#ifndef HEXWALLET_CARDANO_DERIVATION_H
#define HEXWALLET_CARDANO_DERIVATION_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Cardano Ledger-style BIP32-Ed25519 (CIP-0003). The input is the 64-byte
// BIP39 seed, matching Ledger's PBKDF2 output. Path elements are raw uint32
// values, with 0x80000000 marking hardened derivation.
struct CardanoKey {
  uint8_t kL[32];
  uint8_t kR[32];
  uint8_t chain_code[32];
  uint8_t public_key[32];
};

bool cardano_derive_path(const uint8_t seed[64], const uint32_t *path,
                         size_t path_size, CardanoKey *out);
bool run_cardano_derivation_self_tests();

}  // namespace hexwallet

#endif
