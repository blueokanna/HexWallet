#ifndef HEXWALLET_ENGINE_H
#define HEXWALLET_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "WalletNetworks.h"
#include "WalletSecurity.h"

namespace hexwallet {

constexpr size_t kDerivationPathTextSize = 48;
constexpr size_t kAddressTextSize = 96;

struct DerivedAddress {
  const NetworkProfile *network;
  char path[kDerivationPathTextSize];
  char address[kAddressTextSize];
  uint8_t private_key[kPrivateKeySize];
};

WalletError derive_address(const HdPrivateNode &master, const NetworkProfile &network,
                           uint32_t account, uint32_t change, uint32_t address_index,
                           DerivedAddress *out);
void clear_derived_address(DerivedAddress *address);
bool run_address_self_tests();

}  // namespace hexwallet

#endif
