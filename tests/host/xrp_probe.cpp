// Host review probe for XrpTransaction. Signing is device-only (secp256k1 is
// stubbed in the host harness); the Python test checks the exact unsigned
// bytes and SHA-512Half against xrpl-py.
#include <stdio.h>
#include <string.h>

#include "../../XrpTransaction.h"

using namespace hexwallet;

namespace {
bool hex_decode(const char *text, uint8_t *out, size_t capacity, size_t *size) {
  *size = 0;
  const size_t length = strlen(text);
  if ((length & 1U) != 0 || length / 2 > capacity) return false;
  for (size_t i = 0; i < length; i += 2) {
    unsigned value = 0;
    if (sscanf(text + i, "%2x", &value) != 1) return false;
    out[(*size)++] = static_cast<uint8_t>(value);
  }
  return true;
}
void print_hex(const char *label, const uint8_t *data, size_t size) {
  printf("%s=", label);
  for (size_t i = 0; i < size; ++i) printf("%02x", data[i]);
  printf("\n");
}
}

int main(int argc, char **argv) {
  if (argc != 3) {
    printf("error=arguments\n");
    return 2;
  }
  uint8_t payload[64], public_key[kXrpPublicKeySize];
  size_t payload_size = 0, public_key_size = 0;
  if (!hex_decode(argv[1], payload, sizeof(payload), &payload_size) ||
      !hex_decode(argv[2], public_key, sizeof(public_key), &public_key_size) ||
      public_key_size != kXrpPublicKeySize) {
    printf("error=hex\n");
    return 2;
  }
  XrpTransaction tx = {};
  const XrpError error = xrp_review_payload(payload, payload_size, public_key, &tx);
  printf("error=%u\n", static_cast<unsigned>(error));
  if (error != XrpError::Ok) return 1;
  printf("source=%s\n", tx.review.source_text);
  printf("destination=%s\n", tx.review.destination_text);
  printf("amount=%s\n", tx.review.amount_text);
  printf("fee=%s\n", tx.review.fee_text);
  printf("sequence=%lu\n", static_cast<unsigned long>(tx.review.sequence));
  printf("last=%lu\n", static_cast<unsigned long>(tx.review.last_ledger_sequence));
  printf("tag=%lu\n", static_cast<unsigned long>(tx.review.destination_tag));
  printf("has_tag=%u\n", tx.review.has_destination_tag ? 1U : 0U);
  printf("hash=%s\n", tx.review.hash_text);
  print_hex("unsigned", tx.review.unsigned_tx, tx.review.unsigned_size);
  clear_xrp_transaction(&tx);
  return 0;
}
