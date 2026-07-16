#ifndef HEXWALLET_CRYPTONOTE_ADDRESS_H
#define HEXWALLET_CRYPTONOTE_ADDRESS_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet {

constexpr size_t kCryptoNoteScalarSize = 32;
constexpr size_t kCryptoNotePublicKeySize = 32;
constexpr size_t kCryptoNoteStandardAddressSize = 96;

struct CryptoNoteAddressProfile {
  uint64_t standard_address_prefix;
};

constexpr CryptoNoteAddressProfile kMoneroMainnet = {18};
constexpr CryptoNoteAddressProfile kMasariMainnet = {28};

WalletError cryptonote_private_keys_from_seed(
    const uint8_t seed[kCryptoNoteScalarSize],
    uint8_t out_spend_key[kCryptoNoteScalarSize],
    uint8_t out_view_key[kCryptoNoteScalarSize]);
WalletError cryptonote_public_key_from_scalar(
    const uint8_t scalar[kCryptoNoteScalarSize],
    uint8_t out_public_key[kCryptoNotePublicKeySize]);
WalletError cryptonote_standard_address(
    const CryptoNoteAddressProfile &profile,
    const uint8_t public_spend_key[kCryptoNotePublicKeySize],
    const uint8_t public_view_key[kCryptoNotePublicKeySize],
    char *out, size_t out_size);
WalletError cryptonote_address_from_seed(
    const CryptoNoteAddressProfile &profile,
    const uint8_t seed[kCryptoNoteScalarSize],
    char *out, size_t out_size,
    uint8_t out_spend_key[kCryptoNoteScalarSize]);

bool run_cryptonote_self_tests();

}  // namespace hexwallet

#endif
