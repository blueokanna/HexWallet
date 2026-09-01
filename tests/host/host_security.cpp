// Host-side definitions for the small set of WalletSecurity symbols that the
// tested firmware units reference (secure_zero). The cryptographic bodies live
// in WalletSecurity.cpp and are exercised on-device via run_bip39/run_bip32/
// run_secp256k1_self_tests; they are not needed for the extended primitives.
#include "WalletSecurity.h"

#include <string.h>

namespace hexwallet {

void secure_zero(void *data, size_t length) {
  if (data == nullptr || length == 0) return;
  volatile uint8_t *cursor = static_cast<volatile uint8_t *>(data);
  while (length--) *cursor++ = 0;
}

bool is_ascii(const char *text) {
  if (text == nullptr) return false;
  for (; *text != '\0'; ++text) {
    if (static_cast<unsigned char>(*text) > 0x7f) return false;
  }
  return true;
}

}  // namespace hexwallet
