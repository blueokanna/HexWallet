// Line-oriented probe around the real Cosmos review module.
//
// usage: cosmos_probe.exe <payload_hex> <network> <from_address> <pubkey_hex>
// Prints the reviewed fields and the exact protobuf bytes the device builds.
// The host harness stubs secp256k1; the on-device self-test signs the same
// vectors and compares the complete TxRaw bytes.
#include <stdio.h>
#include <string.h>

#include "../../CosmosTransaction.h"

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
  if (argc != 5) {
    printf("error=arguments\n");
    return 2;
  }
  const size_t payload_size = strlen(argv[1]) / 2;
  uint8_t payload[kCosmosMaxPayload];
  uint8_t public_key[kCompressedPublicKeySize];
  const CosmosChainParams *chain = cosmos_chain_params(argv[2]);
  if (chain == nullptr) {
    printf("error=network\n");
    return 2;
  }
  if (payload_size == 0 || payload_size > sizeof(payload) ||
      !hex_decode(argv[1], payload, payload_size) ||
      !hex_decode(argv[4], public_key, sizeof(public_key))) {
    printf("error=hex\n");
    return 2;
  }
  CosmosTransaction transaction;
  const CosmosError error = cosmos_review_payload(
      payload, payload_size, *chain, argv[3], public_key, &transaction);
  printf("error=%u\n", static_cast<unsigned>(error));
  if (error != CosmosError::Ok) {
    printf("text=%s\n", cosmos_error_text(error));
    return 1;
  }
  printf("from=%s\n", transaction.review.from);
  printf("to=%s\n", transaction.review.to);
  printf("chain_id=%s\n", transaction.review.chain_id);
  printf("account=%llu\n",
         static_cast<unsigned long long>(transaction.review.account_number));
  printf("sequence=%llu\n",
         static_cast<unsigned long long>(transaction.review.sequence));
  printf("amount=%llu\n",
         static_cast<unsigned long long>(transaction.review.amount));
  printf("fee=%llu\n",
         static_cast<unsigned long long>(transaction.review.fee));
  printf("gas=%llu\n",
         static_cast<unsigned long long>(transaction.review.gas_limit));
  printf("amount_text=%s\n", transaction.review.amount_text);
  printf("fee_text=%s\n", transaction.review.fee_text);
  print_hex("body", transaction.review.tx_body,
            transaction.review.tx_body_size);
  print_hex("auth_info", transaction.review.auth_info,
            transaction.review.auth_info_size);
  print_hex("digest", transaction.review.sign_doc_digest,
            sizeof(transaction.review.sign_doc_digest));
  return 0;
}
