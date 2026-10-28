// Line-oriented probe around the real NEAR review/sign module.
//
// usage: near_probe.exe <transaction_hex> <seed_hex> <address_index>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../CryptoExtended.h"
#include "../../NearTransaction.h"

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
  if (argc != 4) {
    printf("error=arguments\n");
    return 2;
  }
  const size_t transaction_size = strlen(argv[1]) / 2;
  uint8_t transaction[kNearMaxTransaction];
  uint8_t seed[kSeedSize];
  if (transaction_size == 0 || transaction_size > sizeof(transaction) ||
      !hex_decode(argv[1], transaction, transaction_size) ||
      !hex_decode(argv[2], seed, sizeof(seed))) {
    printf("error=hex\n");
    return 2;
  }
  const uint32_t address_index = static_cast<uint32_t>(strtoul(argv[3], nullptr, 10));
  uint8_t child[32], owner[32];
  if (!near_derive_key(seed, address_index, child) ||
      !ed25519_public_key(child, owner)) {
    printf("error=derive\n");
    return 2;
  }
  secure_zero(child, sizeof(child));
  NearTransaction review;
  const NearError error =
      near_review_transaction(transaction, transaction_size, owner, &review);
  printf("error=%u\n", static_cast<unsigned>(error));
  if (error != NearError::Ok) return 1;
  printf("signer=%s\n", review.review.signer);
  printf("receiver=%s\n", review.review.receiver);
  printf("public_key=%s\n", review.review.public_key);
  printf("block_hash=%s\n", review.review.block_hash);
  printf("nonce=%llu\n", static_cast<unsigned long long>(review.review.nonce));
  printf("actions=%u\n", review.review.action_count);
  printf("total_text=%s\n", review.review.total_text);
  print_hex("hash", review.signing_hash, sizeof(review.signing_hash));
  review.address_index = address_index;
  uint8_t signed_transaction[kNearMaxSigned];
  size_t signed_size = sizeof(signed_transaction);
  const NearError signed_error =
      near_sign_transaction(review, seed, signed_transaction, &signed_size);
  if (signed_error != NearError::Ok) {
    printf("sign_error=%u\n", static_cast<unsigned>(signed_error));
    return 1;
  }
  print_hex("signed", signed_transaction, signed_size);
  secure_zero(seed, sizeof(seed));
  return 0;
}
