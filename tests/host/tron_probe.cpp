// Line-oriented probe around the real TRON review module.
//
// usage: tron_probe.exe <raw_data_hex> <owner_base58>
// Prints the reviewed fields exactly as the trusted display receives them.
// The host harness deliberately stubs secp256k1; the on-device self-test signs
// these same vectors and compares the exact 65 bytes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../TronTransaction.h"
#include "../../base58.h"

using namespace hexwallet;

namespace {

bool hex_decode(const char *text, uint8_t *out, size_t size) {
  if (text == nullptr || strlen(text) != size * 2) return false;
  const auto digit = [](char value) -> int {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
  };
  for (size_t index = 0; index < size; ++index) {
    const int high = digit(text[index * 2]);
    const int low = digit(text[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

void print_hex(const char *label, const uint8_t *data, size_t size) {
  printf("%s=", label);
  for (size_t index = 0; index < size; ++index) printf("%02x", data[index]);
  printf("\n");
}

}  // namespace

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "format") == 0) {
    uint64_t amount = strtoull(argv[2], nullptr, 10);
    TronTransferReview review = {};
    review.kind = TronKind::Native;
    for (size_t i = 0; i < 8; ++i) review.amount[31 - i] = static_cast<uint8_t>(amount >> (8 * i));
    char output[kTronAmountTextSize] = {};
    if (!tron_format_amount(review, output, sizeof(output))) return 2;
    printf("amount=%s\n", output);
    return 0;
  }
  if (argc < 3) {
    printf("error=arguments\n");
    return 2;
  }
  const size_t raw_size = strlen(argv[1]) / 2;
  uint8_t raw[kTronMaxRawData];
  if (raw_size == 0 || raw_size > sizeof(raw) || !hex_decode(argv[1], raw, raw_size)) {
    printf("error=hex\n");
    return 2;
  }
  uint8_t owner[kTronAddressSize];
  size_t owner_size = sizeof(owner);
  if (!b58check_dec(owner, &owner_size, argv[2]) || owner_size != kTronAddressSize) {
    printf("error=address\n");
    return 2;
  }
  TronTransaction transaction;
  const TronError error = tron_review_raw_data(raw, raw_size, owner, &transaction);
  printf("error=%u\n", static_cast<unsigned>(error));
  if (error != TronError::Ok) {
    printf("text=%s\n", tron_error_text(error));
    return 1;
  }
  if (argc == 4) {
    const char *field = argv[3];
    if (strcmp(field, "oversize") == 0) transaction.raw_data_size = kTronMaxRawData + 1;
    else if (strcmp(field, "raw") == 0) transaction.raw_data[0] ^= 1;
    else if (strcmp(field, "kind") == 0) transaction.review.kind = TronKind::Trc1155;
    else if (strcmp(field, "decimals") == 0) transaction.review.token_decimals ^= 1;
    else if (strcmp(field, "fee") == 0) transaction.review.fee_limit_sun ^= 1;
    else if (strcmp(field, "expiration") == 0) transaction.review.expiration_ms ^= 1;
    else if (strcmp(field, "timestamp") == 0) transaction.review.timestamp_ms ^= 1;
    else if (strcmp(field, "id_flag") == 0) transaction.review.has_token_id = true;
    else {
      struct Field { const char *name; void *value; };
      const Field fields[] = {
          {"owner", transaction.review.owner}, {"recipient", transaction.review.recipient},
          {"contract", transaction.review.token_contract}, {"amount", transaction.review.amount},
          {"id", transaction.review.token_id}, {"block", transaction.review.ref_block_hash},
          {"txid", transaction.review.tx_id}, {"owner_text", transaction.review.owner_text},
          {"recipient_text", transaction.review.recipient_text},
          {"contract_text", transaction.review.token_contract_text},
          {"symbol", transaction.review.token_symbol}, {"amount_text", transaction.review.amount_text},
          {"id_text", transaction.review.token_id_text}};
      bool found = false;
      for (const Field &entry : fields) if (strcmp(field, entry.name) == 0) {
        *static_cast<uint8_t *>(entry.value) ^= 1; found = true; break;
      }
      if (!found) return 2;
    }
    uint8_t private_key[32] = {}, signature[65];
    memset(signature, 0xA5, sizeof(signature));
    size_t size = sizeof(signature);
    const TronError signed_error = tron_sign_transaction(transaction, private_key, signature, &size);
    // A mutation must be detected BEFORE the deliberately stubbed curve call.
    bool rejected = signed_error != TronError::Ok && signed_error != TronError::CryptoFailure && size == 0;
    for (uint8_t byte : signature) rejected = rejected && byte == 0xA5;
    printf("tamper_rejected=%u\n", rejected ? 1U : 0U);
    return rejected ? 0 : 1;
  }
  printf("kind=%u\n", static_cast<unsigned>(transaction.review.kind));
  printf("amount=%s\n", transaction.review.amount_text);
  printf("recipient=%s\n", transaction.review.recipient_text);
  printf("token=%s\n", transaction.review.token_symbol);
  printf("contract=%s\n", transaction.review.token_contract_text);
  if (transaction.review.has_token_id) {
    printf("token_id=%s\n", transaction.review.token_id_text);
  }
  if (transaction.review.kind == TronKind::Trc10) {
    printf("asset_id=%s\n", transaction.review.asset_id_text);
    printf("asset_registered=%u\n", transaction.review.asset_registered ? 1U : 0U);
  }
  if (transaction.review.method_text[0] != '\0') {
    printf("method=%s\n", transaction.review.method_text);
  }
  if (transaction.review.has_memo) {
    printf("memo=%s\n", transaction.review.memo_text);
  }
  print_hex("txid", transaction.review.tx_id, sizeof(transaction.review.tx_id));
  return 0;
}
