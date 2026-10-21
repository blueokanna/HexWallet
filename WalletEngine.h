#ifndef HEXWALLET_ENGINE_H
#define HEXWALLET_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "QrlXmss.h"
#include "WalletNetworks.h"
#include "WalletSecurity.h"

namespace hexwallet {

constexpr size_t kDerivationPathTextSize = 48;
constexpr size_t kAddressTextSize = 128;

struct DerivedAddress {
  const NetworkProfile *network;
  char path[kDerivationPathTextSize];
  char address[kAddressTextSize];
  uint8_t private_key[kPrivateKeySize];
};

// Derive an address for a network. `master` is the secp256k1 BIP32 master
// node; `seed` is the 64-byte BIP39 seed required by SLIP-0010 ed25519,
// EIP-2333 and XMSS networks (may be nullptr for secp256k1 networks).
// progress is only used by CPU-heavy schemes (QRL XMSS) so an embedded caller
// can service its watchdog; returning false aborts the derivation.
WalletError derive_address_ex(const HdPrivateNode &master, const uint8_t *seed,
                              const NetworkProfile &network,
                              uint32_t account, uint32_t change,
                              uint32_t address_index, QrlProgressHook progress,
                              void *context, DerivedAddress *out);
WalletError derive_address(const HdPrivateNode &master, const uint8_t *seed,
                           const NetworkProfile &network,
                           uint32_t account, uint32_t change,
                           uint32_t address_index, DerivedAddress *out);
void clear_derived_address(DerivedAddress *address);
bool run_address_self_tests();

}  // namespace hexwallet

#endif
