#ifndef HEXWALLET_CRYPTONOTE_ADDRESS_H
#define HEXWALLET_CRYPTONOTE_ADDRESS_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet {

constexpr size_t kCryptoNoteScalarSize = 32;
constexpr size_t kCryptoNotePublicKeySize = 32;
constexpr size_t kCryptoNoteStandardAddressSize = 96;
// Standard 95 chars, integrated 106 chars, plus NUL.
constexpr size_t kCryptoNoteMaxAddressSize = 112;

struct CryptoNoteAddressProfile {
  uint64_t standard_address_prefix;
  // Zero means the network/version is not implemented for this profile.
  uint64_t integrated_address_prefix;
  uint64_t subaddress_prefix;
};

constexpr CryptoNoteAddressProfile kMoneroMainnet = { 18, 19, 42 };
constexpr CryptoNoteAddressProfile kMasariMainnet = { 28, 0, 0 };

WalletError cryptonote_private_keys_from_seed(
  const uint8_t seed[kCryptoNoteScalarSize],
  uint8_t out_spend_key[kCryptoNoteScalarSize],
  uint8_t out_view_key[kCryptoNoteScalarSize]);
WalletError cryptonote_public_key_from_scalar(
  const uint8_t scalar[kCryptoNoteScalarSize],
  uint8_t out_public_key[kCryptoNotePublicKeySize]);

// Monero subaddress (MRL-0006): m = Hs("SubAddr" || a || major || minor),
// D = B + m*G and C = a*D.  account/minor are little-endian uint32.
WalletError cryptonote_subaddress_public_keys(
  const uint8_t public_spend_key[kCryptoNotePublicKeySize],
  const uint8_t view_secret_key[kCryptoNoteScalarSize],
  uint32_t account, uint32_t minor,
  uint8_t out_spend_public[kCryptoNotePublicKeySize],
  uint8_t out_view_public[kCryptoNotePublicKeySize]);

WalletError cryptonote_standard_address(
  const CryptoNoteAddressProfile &profile,
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

}  // namespace hexwallet

#endif
