#ifndef HEXWALLET_ENGINE_H
#define HEXWALLET_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "QrlXmss.h"
#include "CryptoNoteRingCt.h"
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

WalletError derive_address_ex(const HdPrivateNode &master, const uint8_t *seed,
                              const NetworkProfile &network,
                              uint32_t account, uint32_t change,
                              uint32_t address_index, QrlProgressHook progress,
                              void *context, DerivedAddress *out);
// CryptoNote signing keys for the same BIP32 child that derive_address() uses
// for the address. The address path is built exactly once by build_path_text;
// signing must not fall back to the BIP39 seed or the displayed address and
// the signature keys would disagree.
WalletError derive_cryptonote_keys(const HdPrivateNode &master,
                                   const NetworkProfile &network,
                                   uint32_t account, uint32_t change,
                                   uint32_t address_index,
                                   uint8_t out_spend_key[kCryptoNoteKeySize],
                                   uint8_t out_view_key[kCryptoNoteKeySize]);
WalletError derive_address(const HdPrivateNode &master, const uint8_t *seed,
                           const NetworkProfile &network,
                           uint32_t account, uint32_t change,
                           uint32_t address_index, DerivedAddress *out);
// CryptoNote subaddress address for the same BIP32 child. (0, 0) returns the
// standard address unchanged, so callers can route every request through here.
WalletError derive_cryptonote_subaddress(const HdPrivateNode &master,
                                         const NetworkProfile &network,
                                         uint32_t account, uint32_t change,
                                         uint32_t address_index,
                                         uint32_t subaddress_major,
                                         uint32_t subaddress_minor,
                                         DerivedAddress *out);
void clear_derived_address(DerivedAddress *address);
bool run_address_self_tests();

}  // namespace hexwallet

#endif
