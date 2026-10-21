#include "CryptoNoteAddress.h"

#include <string.h>

#include "CryptoExtended.h"
#include "CryptoPrimitives.h"

namespace hexwallet {
namespace {

constexpr char kBase58Alphabet[] =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr size_t kFullBlockSize = 8;
constexpr size_t kFullEncodedBlockSize = 11;
constexpr size_t kChecksumSize = 4;
constexpr size_t kMaximumPrefixSize = 10;
constexpr size_t kPaymentIdSize = 8;
constexpr size_t kAddressPayloadSize =
  kMaximumPrefixSize + 2 * kCryptoNotePublicKeySize + kPaymentIdSize +
  kChecksumSize;
constexpr uint8_t kEncodedBlockSizes[kFullBlockSize + 1] =
  { 0, 2, 3, 5, 6, 7, 9, 10, 11 };
constexpr uint8_t kEd25519BasePoint[kCryptoNotePublicKeySize] = {
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};

bool is_zero_scalar(const uint8_t scalar[kCryptoNoteScalarSize]) {
  uint8_t combined = 0;
  for (size_t index = 0; index < kCryptoNoteScalarSize; ++index) {
    combined |= scalar[index];
  }
  return combined == 0;
}

bool scalar_reduce(const uint8_t input[kCryptoNoteScalarSize],
                   uint8_t out[kCryptoNoteScalarSize]) {
  memcpy(out, input, kCryptoNoteScalarSize);
  ed25519_scalar_reduce_mod_l(out);
  return !is_zero_scalar(out);
}

// Monero: m = Hs("SubAddr" || a || major || minor) with Keccak-256 and
// sc_reduce32 (device_default.cpp get_subaddress_secret_key).
bool subaddress_scalar(uint8_t out[kCryptoNoteScalarSize],
                       const uint8_t view_secret[kCryptoNoteScalarSize],
                       uint32_t account, uint32_t minor) {
  uint8_t data[8 + kCryptoNoteScalarSize + 2 * sizeof(uint32_t)];
  memcpy(data, "SubAddr", 8);  // includes the NUL terminator
  memcpy(data + 8, view_secret, kCryptoNoteScalarSize);
  for (size_t offset = 0; offset < 4; ++offset) {
    data[8 + kCryptoNoteScalarSize + offset] =
      static_cast<uint8_t>(account >> (8 * offset));
    data[8 + kCryptoNoteScalarSize + 4 + offset] =
      static_cast<uint8_t>(minor >> (8 * offset));
  }
  uint8_t digest[kKeccak256Size];
  const bool ok = crypto_keccak256(data, sizeof(data), digest) &&
                  scalar_reduce(digest, out);
  secure_zero(data, sizeof(data));
  secure_zero(digest, sizeof(digest));
  return ok;
}

size_t write_varint(uint64_t value, uint8_t out[kMaximumPrefixSize]) {
  size_t used = 0;
  do {
    uint8_t byte = static_cast<uint8_t>(value & 0x7fU);
    value >>= 7;
    if (value != 0) byte |= 0x80;
    out[used++] = byte;
  } while (value != 0 && used < kMaximumPrefixSize);
  return value == 0 ? used : 0;
}

bool encode_block(const uint8_t *input, size_t input_size, char *out,
                  size_t output_size) {
  if (input == nullptr || out == nullptr || input_size == 0 ||
      input_size > kFullBlockSize || output_size != kEncodedBlockSizes[input_size]) {
    return false;
  }
  uint64_t value = 0;
  for (size_t index = 0; index < input_size; ++index) {
    value = (value << 8) | input[index];
  }
  memset(out, kBase58Alphabet[0], output_size);
  for (size_t position = output_size; value != 0 && position != 0;) {
    const uint64_t quotient = value / 58U;
    out[--position] = kBase58Alphabet[value - quotient * 58U];
    value = quotient;
  }
  return value == 0;
}

bool cryptonote_base58(const uint8_t *input, size_t input_size, char *out,
                       size_t out_size) {
  if (input == nullptr || out == nullptr) return false;
  const size_t full_blocks = input_size / kFullBlockSize;
  const size_t final_size = input_size % kFullBlockSize;
  const size_t encoded_size =
    full_blocks * kFullEncodedBlockSize + kEncodedBlockSizes[final_size];
  if (encoded_size + 1 > out_size) return false;
  size_t input_offset = 0;
  size_t output_offset = 0;
  for (size_t block = 0; block < full_blocks; ++block) {
    if (!encode_block(input + input_offset, kFullBlockSize,
                      out + output_offset, kFullEncodedBlockSize)) {
      return false;
    }
    input_offset += kFullBlockSize;
    output_offset += kFullEncodedBlockSize;
  }
  if (final_size != 0 &&
      !encode_block(input + input_offset, final_size, out + output_offset,
                    kEncodedBlockSizes[final_size])) {
    return false;
  }
  out[encoded_size] = '\0';
  return true;
}

WalletError encode_address(uint64_t prefix, const uint8_t *keys, size_t keys_size,
                           const uint8_t *payment_id, size_t payment_size,
                           char *out, size_t out_size) {
  uint8_t payload[kAddressPayloadSize];
  const size_t prefix_size = write_varint(prefix, payload);
  if (prefix_size == 0 || prefix_size + keys_size + payment_size + kChecksumSize > sizeof(payload)) {
    return WalletError::InvalidArgument;
  }
  if (keys_size != 0) memcpy(payload + prefix_size, keys, keys_size);
  if (payment_size != 0) {
    memcpy(payload + prefix_size + keys_size, payment_id, payment_size);
  }
  const size_t data_size = prefix_size + keys_size + payment_size;
  uint8_t digest[kKeccak256Size];
  if (!crypto_keccak256(payload, data_size, digest)) return WalletError::CryptoFailure;
  memcpy(payload + data_size, digest, kChecksumSize);
  const size_t encoded_data_size = data_size + kChecksumSize;
  const size_t required =
    (encoded_data_size / kFullBlockSize) * kFullEncodedBlockSize +
    kEncodedBlockSizes[encoded_data_size % kFullBlockSize] + 1;
  WalletError result = WalletError::BufferTooSmall;
  if (out_size >= required && cryptonote_base58(payload, encoded_data_size, out, out_size)) {
    result = WalletError::Ok;
  }
  secure_zero(digest, sizeof(digest));
  secure_zero(payload, sizeof(payload));
  return result;
}

}  // namespace

WalletError cryptonote_private_keys_from_seed(
  const uint8_t seed[kCryptoNoteScalarSize],
  uint8_t out_spend_key[kCryptoNoteScalarSize],
  uint8_t out_view_key[kCryptoNoteScalarSize]) {
  if (seed == nullptr || out_spend_key == nullptr || out_view_key == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t digest[kKeccak256Size];
  const bool ok = crypto_keccak256(seed, kCryptoNoteScalarSize, digest) &&
                  scalar_reduce(digest, out_spend_key) &&
                  crypto_keccak256(out_spend_key, kCryptoNoteScalarSize, digest) &&
                  scalar_reduce(digest, out_view_key);
  secure_zero(digest, sizeof(digest));
  if (!ok) {
    secure_zero(out_spend_key, kCryptoNoteScalarSize);
    secure_zero(out_view_key, kCryptoNoteScalarSize);
  }
  return ok ? WalletError::Ok : WalletError::CryptoFailure;
}

WalletError cryptonote_public_key_from_scalar(
  const uint8_t scalar_bytes[kCryptoNoteScalarSize],
  uint8_t out_public_key[kCryptoNotePublicKeySize]) {
  if (scalar_bytes == nullptr || out_public_key == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t scalar[kCryptoNoteScalarSize];
  const bool valid = scalar_reduce(scalar_bytes, scalar);
  const bool ok = valid &&
                  ed25519_point_mul_compressed(kEd25519BasePoint, scalar,
                                               out_public_key);
  secure_zero(scalar, sizeof(scalar));
  if (!ok) secure_zero(out_public_key, kCryptoNotePublicKeySize);
  return ok ? WalletError::Ok : WalletError::InvalidKey;
}

WalletError cryptonote_subaddress_public_keys(
  const uint8_t public_spend_key[kCryptoNotePublicKeySize],
  const uint8_t view_secret_key[kCryptoNoteScalarSize],
  uint32_t account, uint32_t minor,
  uint8_t out_spend_public[kCryptoNotePublicKeySize],
  uint8_t out_view_public[kCryptoNotePublicKeySize]) {
  if (public_spend_key == nullptr || view_secret_key == nullptr ||
      out_spend_public == nullptr || out_view_public == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t m[kCryptoNoteScalarSize];
  uint8_t view_scalar[kCryptoNoteScalarSize];
  uint8_t m_point[kCryptoNotePublicKeySize];
  bool ok = subaddress_scalar(m, view_secret_key, account, minor) &&
            scalar_reduce(view_secret_key, view_scalar) &&
            ed25519_point_mul_compressed(kEd25519BasePoint, m, m_point) &&
            ed25519_point_add_compressed(public_spend_key, m_point,
                                         out_spend_public) &&
            ed25519_point_mul_compressed(out_spend_public, view_scalar,
                                         out_view_public);
  secure_zero(m, sizeof(m));
  secure_zero(view_scalar, sizeof(view_scalar));
  secure_zero(m_point, sizeof(m_point));
  if (!ok) {
    secure_zero(out_spend_public, kCryptoNotePublicKeySize);
    secure_zero(out_view_public, kCryptoNotePublicKeySize);
  }
  return ok ? WalletError::Ok : WalletError::CryptoFailure;
}

WalletError cryptonote_standard_address(
  const CryptoNoteAddressProfile &profile,
  const uint8_t public_spend_key[kCryptoNotePublicKeySize],
  const uint8_t public_view_key[kCryptoNotePublicKeySize],
  char *out, size_t out_size) {
  if (profile.standard_address_prefix == 0 || public_spend_key == nullptr ||
      public_view_key == nullptr || out == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t keys[2 * kCryptoNotePublicKeySize];
  memcpy(keys, public_spend_key, kCryptoNotePublicKeySize);
  memcpy(keys + kCryptoNotePublicKeySize, public_view_key,
         kCryptoNotePublicKeySize);
  const WalletError result = encode_address(profile.standard_address_prefix, keys,
                                            sizeof(keys), nullptr, 0, out,
                                            out_size);
  secure_zero(keys, sizeof(keys));
  return result;
}

WalletError cryptonote_integrated_address(
  const CryptoNoteAddressProfile &profile,
  const uint8_t public_spend_key[kCryptoNotePublicKeySize],
  const uint8_t public_view_key[kCryptoNotePublicKeySize],
  const uint8_t payment_id[kPaymentIdSize],
  char *out, size_t out_size) {
  if (profile.integrated_address_prefix == 0 || public_spend_key == nullptr ||
      public_view_key == nullptr || payment_id == nullptr || out == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t keys[2 * kCryptoNotePublicKeySize];
  memcpy(keys, public_spend_key, kCryptoNotePublicKeySize);
  memcpy(keys + kCryptoNotePublicKeySize, public_view_key,
         kCryptoNotePublicKeySize);
  const WalletError result = encode_address(profile.integrated_address_prefix,
                                            keys, sizeof(keys), payment_id,
                                            kPaymentIdSize, out, out_size);
  secure_zero(keys, sizeof(keys));
  return result;
}

WalletError cryptonote_subaddress_address(
  const CryptoNoteAddressProfile &profile,
  const uint8_t public_spend_key[kCryptoNotePublicKeySize],
  const uint8_t view_secret_key[kCryptoNoteScalarSize],
  uint32_t account, uint32_t minor,
  char *out, size_t out_size) {
  if (profile.subaddress_prefix == 0 || public_spend_key == nullptr ||
      view_secret_key == nullptr || out == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t keys[2 * kCryptoNotePublicKeySize];
  const WalletError derived = cryptonote_subaddress_public_keys(
    public_spend_key, view_secret_key, account, minor, keys,
    keys + kCryptoNotePublicKeySize);
  if (derived != WalletError::Ok) return derived;
  const WalletError result = encode_address(profile.subaddress_prefix, keys,
                                            sizeof(keys), nullptr, 0, out,
                                            out_size);
  secure_zero(keys, sizeof(keys));
  return result;
}

WalletError cryptonote_address_from_seed_at(
  const CryptoNoteAddressProfile &profile,
  const uint8_t seed[kCryptoNoteScalarSize],
  uint32_t account, uint32_t minor,
  char *out, size_t out_size,
  uint8_t out_spend_key[kCryptoNoteScalarSize]) {
  if (seed == nullptr || out == nullptr || out_spend_key == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t view_key[kCryptoNoteScalarSize];
  uint8_t public_spend[kCryptoNotePublicKeySize];
  WalletError result = cryptonote_private_keys_from_seed(seed, out_spend_key,
                                                         view_key);
  if (result == WalletError::Ok) {
    result = cryptonote_public_key_from_scalar(out_spend_key, public_spend);
  }
  if (result == WalletError::Ok) {
    if (account == 0 && minor == 0) {
      uint8_t public_view[kCryptoNotePublicKeySize];
      result = cryptonote_public_key_from_scalar(view_key, public_view);
      if (result == WalletError::Ok) {
        result = cryptonote_standard_address(profile, public_spend, public_view,
                                             out, out_size);
      }
      secure_zero(public_view, sizeof(public_view));
    } else {
      result = cryptonote_subaddress_address(profile, public_spend, view_key,
                                             account, minor, out, out_size);
    }
  }
  secure_zero(view_key, sizeof(view_key));
  secure_zero(public_spend, sizeof(public_spend));
  if (result != WalletError::Ok) secure_zero(out_spend_key, kCryptoNoteScalarSize);
  return result;
}

WalletError cryptonote_address_from_seed(
  const CryptoNoteAddressProfile &profile,
  const uint8_t seed[kCryptoNoteScalarSize],
  char *out, size_t out_size,
  uint8_t out_spend_key[kCryptoNoteScalarSize]) {
  return cryptonote_address_from_seed_at(profile, seed, 0, 0, out, out_size,
                                         out_spend_key);
}

bool run_cryptonote_self_tests() {
  uint8_t seed[kCryptoNoteScalarSize] = {};
  uint8_t spend_key[kCryptoNoteScalarSize];
  uint8_t view_key[kCryptoNoteScalarSize];
  static const uint8_t kExpectedSpendKey[kCryptoNoteScalarSize] = {
    0x9b, 0x15, 0x29, 0xac, 0xb6, 0x38, 0xf4, 0x97,
    0xd0, 0x56, 0x77, 0xd7, 0x50, 0x5d, 0x35, 0x4b,
    0x4b, 0xa6, 0xbc, 0x95, 0x48, 0x40, 0x08, 0xf6,
    0x36, 0x2f, 0x93, 0x16, 0x0e, 0xf3, 0xe5, 0x03,
  };
  static const uint8_t kExpectedViewKey[kCryptoNoteScalarSize] = {
    0x45, 0x2b, 0x39, 0x13, 0x3e, 0x70, 0xf8, 0x03,
    0xf4, 0x88, 0x28, 0x2d, 0x39, 0x7a, 0x87, 0x1a,
    0xe3, 0x9b, 0xeb, 0x30, 0x01, 0x73, 0x0c, 0x43,
    0xea, 0xa1, 0xf2, 0xee, 0xf9, 0xeb, 0x6a, 0x0e,
  };
  static const uint8_t kBasePoint[kCryptoNotePublicKeySize] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  };
  static const uint8_t kExpectedThreeTimesBasePoint[kCryptoNotePublicKeySize] = {
    0xd4, 0xb4, 0xf5, 0x78, 0x48, 0x68, 0xc3, 0x02,
    0x04, 0x03, 0x24, 0x67, 0x17, 0xec, 0x16, 0x9f,
    0xf7, 0x9e, 0x26, 0x60, 0x8e, 0xa1, 0x26, 0xa1,
    0xab, 0x69, 0xee, 0x77, 0xd1, 0xb1, 0x67, 0x12,
  };
  static const char kExpectedAddress[] =
    "44yQXfkWZNmJ8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmJ7suhUXwdrD"
    "J8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmCYrSgjJ";
  static const char kExpectedMasariAddress[] =
    "5jz8fjwSe3wJ8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmJ7suhUXwdrD"
    "J8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmCWb1XQW";
  static const char kExpectedSeedAddress[] =
    "42z7XSCSbPzfRbbKcALdcZev4QXGGuoLh2x36LhaxLSxJ8BhY7tm4LPc4ZvLo1tmZvA1BtagEN9HkhLzmddcK2PxNj5aDL5";
  static const char kExpectedIntegrated[] =
    "4CgnYF1wCfWfRbbKcALdcZev4QXGGuoLh2x36LhaxLSxJ8BhY7tm4LPc4ZvLo1tmZvA1BtagEN9HkhLzmddcK2PxZ7eJCqy6ep5ESLJGDv";
  static const char kExpectedSubaddress01[] =
    "8AGiXjGVUbB7VkUZkmuThePWy9qnC7srpAomAafzkZN4Wka9v2f1b1XDFd1w5fpmkQKrweHLrBa3F3rSdDYbVCgkHkGGn8z";
  static const char kExpectedSubaddress10[] =
    "8AGDdrcnAd7R72C394FdpRjne5MfxnYGpenmLZGZae1fa2bYijnqPmkUr5P1SZW2Z8Chg1ayK3DZYc4asmeajeqrLtEvsd7";
  char address[kCryptoNoteMaxAddressSize];
  uint8_t public_key[kCryptoNotePublicKeySize];
  uint8_t scalar[kCryptoNoteScalarSize] = { 3 };
  bool passed =
    cryptonote_private_keys_from_seed(seed, spend_key, view_key) == WalletError::Ok &&
    crypto_constant_time_equal(spend_key, kExpectedSpendKey, sizeof(spend_key)) &&
    crypto_constant_time_equal(view_key, kExpectedViewKey, sizeof(view_key)) &&
    cryptonote_public_key_from_scalar(scalar, public_key) == WalletError::Ok &&
    crypto_constant_time_equal(public_key, kExpectedThreeTimesBasePoint,
                               sizeof(public_key)) &&
    cryptonote_standard_address(kMoneroMainnet, kBasePoint, kBasePoint, address,
                                sizeof(address)) == WalletError::Ok &&
    strcmp(address, kExpectedAddress) == 0;
  passed = passed &&
    cryptonote_standard_address(kMasariMainnet, kBasePoint, kBasePoint, address,
                                sizeof(address)) == WalletError::Ok &&
    strcmp(address, kExpectedMasariAddress) == 0;

  uint8_t derived_spend[kCryptoNoteScalarSize];
  passed = passed &&
    cryptonote_address_from_seed_at(kMoneroMainnet, seed, 0, 0, address,
                                    sizeof(address),
                                    derived_spend) == WalletError::Ok &&
    strcmp(address, kExpectedSeedAddress) == 0 &&
    crypto_constant_time_equal(derived_spend, kExpectedSpendKey,
                               sizeof(derived_spend));
  passed = passed &&
    cryptonote_address_from_seed_at(kMoneroMainnet, seed, 0, 1, address,
                                    sizeof(address),
                                    derived_spend) == WalletError::Ok &&
    strcmp(address, kExpectedSubaddress01) == 0;
  passed = passed &&
    cryptonote_address_from_seed_at(kMoneroMainnet, seed, 1, 0, address,
                                    sizeof(address),
                                    derived_spend) == WalletError::Ok &&
    strcmp(address, kExpectedSubaddress10) == 0;

  uint8_t public_spend[kCryptoNotePublicKeySize];
  uint8_t public_view[kCryptoNotePublicKeySize];
  static const uint8_t kPaymentId[8] =
    { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
  passed = passed &&
    cryptonote_public_key_from_scalar(spend_key, public_spend) == WalletError::Ok &&
    cryptonote_public_key_from_scalar(view_key, public_view) == WalletError::Ok &&
    cryptonote_integrated_address(kMoneroMainnet, public_spend, public_view,
                                  kPaymentId, address,
                                  sizeof(address)) == WalletError::Ok &&
    strcmp(address, kExpectedIntegrated) == 0;
  passed = passed &&
    cryptonote_subaddress_address(kMasariMainnet, public_spend, view_key, 0, 1,
                                  address,
                                  sizeof(address)) == WalletError::InvalidArgument;
  secure_zero(public_view, sizeof(public_view));
  secure_zero(public_spend, sizeof(public_spend));
  secure_zero(derived_spend, sizeof(derived_spend));
  secure_zero(address, sizeof(address));
  secure_zero(public_key, sizeof(public_key));
  secure_zero(scalar, sizeof(scalar));
  secure_zero(view_key, sizeof(view_key));
  secure_zero(spend_key, sizeof(spend_key));
  secure_zero(seed, sizeof(seed));
  return passed;
}

}  // namespace hexwallet
