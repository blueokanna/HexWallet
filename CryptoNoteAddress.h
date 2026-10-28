#ifndef HEXWALLET_CRYPTONOTE_ADDRESS_H
#define HEXWALLET_CRYPTONOTE_ADDRESS_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet {

constexpr size_t kCryptoNoteScalarSize = 32;
constexpr size_t kCryptoNotePublicKeySize = 32;
constexpr size_t kCryptoNoteStandardAddressSize = 96;
constexpr size_t kCryptoNoteMaxAddressSize = 112;

struct CryptoNoteAddressProfile {
  uint64_t standard_address_prefix;
  uint64_t integrated_address_prefix;
  uint64_t subaddress_prefix;
};

constexpr CryptoNoteAddressProfile kMoneroMainnet = { 18, 19, 42 };
// Masari mainnet prefixes, from masari-project/masari src/cryptonote_config.h:
// standard 28, integrated 29, subaddress 52.
constexpr CryptoNoteAddressProfile kMasariMainnet = { 28, 29, 52 };

WalletError cryptonote_private_keys_from_seed(
  const uint8_t seed[kCryptoNoteScalarSize],
  uint8_t out_spend_key[kCryptoNoteScalarSize],
  uint8_t out_view_key[kCryptoNoteScalarSize]);
WalletError cryptonote_public_key_from_scalar(
  const uint8_t scalar[kCryptoNoteScalarSize],
  uint8_t out_public_key[kCryptoNotePublicKeySize]);

WalletError cryptonote_subaddress_public_keys(
  const uint8_t public_spend_key[kCryptoNotePublicKeySize],
  const uint8_t view_secret_key[kCryptoNoteScalarSize],
  uint32_t account, uint32_t minor,
  uint8_t out_spend_public[kCryptoNotePublicKeySize],
  uint8_t out_view_public[kCryptoNotePublicKeySize]);

// Subaddress key material derived from the master wallet keys:
//   spend_secret = b + m, spend_public = B + m*G, view_public = a*spend_public
// (major, minor) == (0, 0) returns the master key pair unchanged. The caller
// owns zeroization of every output buffer.
WalletError cryptonote_subaddress_keys(
  const uint8_t master_spend_secret[kCryptoNoteScalarSize],
  const uint8_t master_view_secret[kCryptoNoteScalarSize],
  uint32_t major, uint32_t minor,
  uint8_t out_spend_secret[kCryptoNoteScalarSize],
  uint8_t out_spend_public[kCryptoNotePublicKeySize],
  uint8_t out_view_public[kCryptoNotePublicKeySize]);

WalletError cryptonote_standard_address(
  const CryptoNoteAddressProfile &profile,
  const uint8_t public_spend_key[kCryptoNotePublicKeySize],
  const uint8_t public_view_key[kCryptoNotePublicKeySize],
  char *out, size_t out_size);

WalletError cryptonote_address_from_public_keys(
  uint64_t prefix,
  const uint8_t public_spend_key[kCryptoNotePublicKeySize],
  const uint8_t public_view_key[kCryptoNotePublicKeySize],
  char *out, size_t out_size);

WalletError cryptonote_integrated_address(
  const CryptoNoteAddressProfile &profile,
  const uint8_t public_spend_key[kCryptoNotePublicKeySize],
  const uint8_t public_view_key[kCryptoNotePublicKeySize],
  const uint8_t payment_id[8],
  char *out, size_t out_size);

WalletError cryptonote_subaddress_address(
  const CryptoNoteAddressProfile &profile,
  const uint8_t public_spend_key[kCryptoNotePublicKeySize],
  const uint8_t view_secret_key[kCryptoNoteScalarSize],
  uint32_t account, uint32_t minor,
  char *out, size_t out_size);

WalletError cryptonote_address_from_seed(
  const CryptoNoteAddressProfile &profile,
  const uint8_t seed[kCryptoNoteScalarSize],
  char *out, size_t out_size,
  uint8_t out_spend_key[kCryptoNoteScalarSize]);
  
WalletError cryptonote_address_from_seed_at(
  const CryptoNoteAddressProfile &profile,
  const uint8_t seed[kCryptoNoteScalarSize],
  uint32_t account, uint32_t minor,
  char *out, size_t out_size,
  uint8_t out_spend_key[kCryptoNoteScalarSize]);

bool run_cryptonote_self_tests();

}

#endif
