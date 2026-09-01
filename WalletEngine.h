#ifndef HEXWALLET_ENGINE_H
#define HEXWALLET_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "WalletNetworks.h"
#include "WalletSecurity.h"

namespace hexwallet {

constexpr size_t kDerivationPathTextSize = 48;
// Address text buffer. Cardano base addresses are the longest supported
// format (up to 103 chars + NUL); 128 bytes covers every coin with margin.
constexpr size_t kAddressTextSize = 128;

struct DerivedAddress {
  const NetworkProfile *network;
  char path[kDerivationPathTextSize];
  char address[kAddressTextSize];
  uint8_t private_key[kPrivateKeySize];
};

// Derive an address for a network. `master` is the secp256k1 BIP32 master
// node; `seed` is the 64-byte BIP39 seed required by SLIP-0010 ed25519 and
// EIP-2333 networks (may be nullptr for secp256k1 networks).
WalletError derive_address(const HdPrivateNode &master, const uint8_t *seed,
                           const NetworkProfile &network,
                           uint32_t account, uint32_t change,
                           uint32_t address_index, DerivedAddress *out);
void clear_derived_address(DerivedAddress *address);
bool run_address_self_tests();

}  // namespace hexwallet

#endif
