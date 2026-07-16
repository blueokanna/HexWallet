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
  bool ripple_alphabet;
};

constexpr UtxoAddressProfile kBitcoinMainnet = {0x00, 0x05, "bc", false};
constexpr UtxoAddressProfile kBitcoinTestnet = {0x6f, 0xc4, "tb", false};

WalletError address_p2pkh(const UtxoAddressProfile &profile,
                          const uint8_t public_key[kCompressedPublicKeySize],
                          char *out, size_t *in_out_size);
WalletError address_p2sh_p2wpkh(const UtxoAddressProfile &profile,
                                const uint8_t public_key[kCompressedPublicKeySize],
                                char *out, size_t *in_out_size);
WalletError address_p2wpkh(const UtxoAddressProfile &profile,
                           const uint8_t public_key[kCompressedPublicKeySize],
                           char *out, size_t out_size);
WalletError address_evm(const uint8_t public_key[kUncompressedPublicKeySize],
                        char *out, size_t out_size);
WalletError address_keccak_base58(uint8_t version,
                                  const uint8_t public_key[kUncompressedPublicKeySize],
                                  char *out, size_t *in_out_size);
WalletError address_from_script(const UtxoAddressProfile &profile,
                                const uint8_t *script, size_t script_size,
                                char *out, size_t out_size);

}  // namespace hexwallet

#endif
