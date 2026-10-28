// Line-oriented probe around the real XTZ review/sign module.
//
// usage: tezos_probe.exe <transaction_hex> <seed_hex> <address_index>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../CryptoExtended.h"
#include "../../TezosTransaction.h"
#include "../../WalletEngine.h"

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
  if (argc < 4 || argc > 5) {
    printf("error=arguments\n");
    return 2;
  }
  const size_t transaction_size = strlen(argv[1]) / 2;
  uint8_t transaction[kTezosMaxTransaction];
  uint8_t seed[kSeedSize];
  if (transaction_size > sizeof(transaction) ||
      !hex_decode(argv[1], transaction, transaction_size) ||
      !hex_decode(argv[2], seed, sizeof(seed))) {
    printf("error=hex\n");
    return 2;
  }
  const uint32_t address_index = static_cast<uint32_t>(strtoul(argv[3], nullptr, 10));
  uint8_t child[32], owner[32];
  if (!tezos_derive_key(seed, address_index, child) ||
      !ed25519_public_key(child, owner)) {
    printf("error=derive\n");
    return 2;
  }
  secure_zero(child, sizeof(child));
  TezosTransaction review;
  const TezosError error =
      tezos_review_transaction(transaction, transaction_size, owner, &review);
  printf("error=%u\n", static_cast<unsigned>(error));
  if (error != TezosError::Ok) return 1;
  DerivedAddress derived = {};
  HdPrivateNode master = {};
  const NetworkProfile *network = find_network_profile("xtz");
  if (!network || derive_address(master, seed, *network, 0, 0, address_index, &derived) != WalletError::Ok ||
      strcmp(derived.address, review.review.source)) return 2;
  printf("path=%s\n", derived.path);
  clear_derived_address(&derived);
  printf("signer=%s\n", review.review.source);
  printf("public_key=%s\n", review.review.public_key);
  printf("branch=%s\n", review.review.branch);
  printf("count=%u\n", review.review.operation_count);
  printf("total=%llu\n", static_cast<unsigned long long>(review.review.total));
  printf("fee=%llu\n", static_cast<unsigned long long>(review.review.total_fee));
  printf("storage=%llu\n", static_cast<unsigned long long>(review.review.total_storage_limit));
  for (size_t i = 0; i < review.review.operation_count; ++i) {
    const auto &op = review.review.operations[i];
    printf("op%u=%u,%llu,%llu,%llu,%llu,%llu,%s\n", static_cast<unsigned>(i), op.reveal ? 1U : 0U,
        static_cast<unsigned long long>(op.fee), static_cast<unsigned long long>(op.counter),
        static_cast<unsigned long long>(op.gas_limit), static_cast<unsigned long long>(op.storage_limit),
        static_cast<unsigned long long>(op.amount), op.recipient);
  }
  print_hex("hash", review.signing_hash, sizeof(review.signing_hash));
  review.address_index = address_index;
  if (argc == 5) {
    const char *field = argv[4];
    if (!strcmp(field,"size")) review.transaction_size = kTezosMaxTransaction + 1;
    else if (!strcmp(field,"index")) ++review.address_index;
    else if (!strcmp(field,"raw")) review.transaction[0] ^= 1;
    else if (!strcmp(field,"hash")) review.signing_hash[0] ^= 1;
    else if (!strcmp(field,"source")) review.review.source[0] ^= 1;
    else if (!strcmp(field,"public_key")) review.review.public_key[0] ^= 1;
    else if (!strcmp(field,"branch")) review.review.branch[0] ^= 1;
    else if (!strcmp(field,"count")) ++review.review.operation_count;
    else if (!strcmp(field,"total")) ++review.review.total;
    else if (!strcmp(field,"fee")) ++review.review.total_fee;
    else if (!strcmp(field,"storage")) ++review.review.total_storage_limit;
    else if (!strcmp(field,"reveal")) review.review.operations[0].reveal = !review.review.operations[0].reveal;
    else if (!strcmp(field,"op_fee")) ++review.review.operations[0].fee;
    else if (!strcmp(field,"counter")) ++review.review.operations[0].counter;
    else if (!strcmp(field,"gas")) ++review.review.operations[0].gas_limit;
    else if (!strcmp(field,"op_storage")) ++review.review.operations[0].storage_limit;
    else if (!strcmp(field,"amount")) ++review.review.operations[0].amount;
    else if (!strcmp(field,"recipient")) review.review.operations[0].recipient[0] ^= 1;
    else if (strcmp(field,"small")) return 2;
  }
  uint8_t signed_transaction[kTezosMaxSigned];
  memset(signed_transaction, 0xA5, sizeof(signed_transaction));
  size_t signed_size = argc == 5 && !strcmp(argv[4], "small") ? 1 : sizeof(signed_transaction);
  const TezosError signed_error =
      tezos_sign_transaction(review, seed, signed_transaction, &signed_size);
  if (argc == 5) {
    bool rejected = signed_error != TezosError::Ok && signed_size == 0;
    for (uint8_t byte : signed_transaction) rejected = rejected && byte == 0xA5;
    printf("tamper_rejected=%u\n", rejected ? 1U : 0U);
    secure_zero(seed, sizeof(seed));
    return rejected ? 0 : 1;
  }
  if (signed_error != TezosError::Ok) {
    printf("sign_error=%u\n", static_cast<unsigned>(signed_error));
    return 1;
  }
  print_hex("signed", signed_transaction, signed_size);
  secure_zero(seed, sizeof(seed));
  return 0;
}
