#ifndef HEXWALLET_ADDRESSES_H
#define HEXWALLET_ADDRESSES_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet
{
  struct UtxoAddressProfile
  {
    uint8_t p2pkh_version;
    uint8_t p2sh_version;
    const char *bech32_hrp;
    bool ripple_alphabet;
  };

  constexpr UtxoAddressProfile kBitcoinMainnet = {0x00, 0x05, "bc", false};
  constexpr UtxoAddressProfile kBitcoinTestnet = {0x6f, 0xc4, "tb", false};
  // Groestlcoin mainnet (SLIP-44 17): p2pkh 0x24, p2sh 0x05, bech32 "grs".
  // The base58 checksum is double Groestl-512, so a profile alone is not enough
  // to render an address - see address_from_script_groestl().
  constexpr UtxoAddressProfile kGroestlcoinMainnet = {0x24, 0x05, "grs", false};

  WalletError address_p2pkh(const UtxoAddressProfile &profile,
                            const uint8_t public_key[kCompressedPublicKeySize],
                            char *out, size_t *in_out_size);

  WalletError address_p2pkh_groestl(const UtxoAddressProfile &profile,
                                    const uint8_t public_key[kCompressedPublicKeySize],
                                    char *out, size_t *in_out_size);
  // Pins the Groestlcoin address checksum to a mainnet address.
  bool run_groestl_address_self_tests();
  WalletError address_p2sh_p2wpkh(const UtxoAddressProfile &profile,
                                  const uint8_t public_key[kCompressedPublicKeySize],
                                  char *out, size_t *in_out_size);
  WalletError address_p2wpkh(const UtxoAddressProfile &profile,
                             const uint8_t public_key[kCompressedPublicKeySize],
                             char *out, size_t out_size);
  // taproot (BIP86): bech32m witness v1 over the 32-byte x-only OUTPUT key.
  // The TapTweak step lives in WalletSecurity because it needs the curve; this
  // function only encodes, so the address layer stays free of key maths.
  WalletError address_p2tr_from_output_key(const UtxoAddressProfile &profile,
                                           const uint8_t output_key[32],
                                           char *out, size_t out_size);
  WalletError address_evm(const uint8_t public_key[kUncompressedPublicKeySize],
                          char *out, size_t out_size);
  WalletError address_keccak_base58(uint8_t version,
                                    const uint8_t public_key[kUncompressedPublicKeySize],
                                    char *out, size_t *in_out_size);
  WalletError address_from_script(const UtxoAddressProfile &profile,
                                  const uint8_t *script, size_t script_size,
                                  char *out, size_t out_size);
  // Same, but with Groestlcoin's double-Groestl-512 base58 checksum. The
  // segwit branch is unchanged because bech32 keeps its own checksum.
  WalletError address_from_script_groestl(const UtxoAddressProfile &profile,
                                          const uint8_t *script,
                                          size_t script_size, char *out,
                                          size_t out_size);

}

#endif
