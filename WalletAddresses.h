#ifndef HEXWALLET_ADDRESSES_H
#define HEXWALLET_ADDRESSES_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet {

// BIP13 and BIP173 parameters are data, never literals scattered through the
// address implementation. Add a network profile only after test-vector review.
struct UtxoAddressProfile {
  uint8_t p2pkh_version;
  uint8_t p2sh_version;
  const char *bech32_hrp;
};

constexpr UtxoAddressProfile kBitcoinMainnet = {0x00, 0x05, "bc"};
constexpr UtxoAddressProfile kBitcoinTestnet = {0x6f, 0xc4, "tb"};

WalletError address_p2pkh(const UtxoAddressProfile &profile,
                          const uint8_t public_key[kCompressedPublicKeySize],
                          char *out, size_t *in_out_size);
WalletError address_p2sh_p2wpkh(const UtxoAddressProfile &profile,
                                const uint8_t public_key[kCompressedPublicKeySize],
                                char *out, size_t *in_out_size);
WalletError address_p2wpkh(const UtxoAddressProfile &profile,
                           const uint8_t public_key[kCompressedPublicKeySize],
                           char *out, size_t out_size);

}  // namespace hexwallet

#endif
