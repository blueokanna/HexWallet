#include "CryptoNoteAddress.h"

#include <mbedtls/bignum.h>
#include <string.h>

#include "CryptoPrimitives.h"

namespace hexwallet {
namespace {

constexpr char kBase58Alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr size_t kFullBlockSize = 8;
constexpr size_t kFullEncodedBlockSize = 11;
constexpr size_t kChecksumSize = 4;
constexpr size_t kMaximumPrefixSize = 10;
constexpr size_t kAddressPayloadSize =
    kMaximumPrefixSize + 2 * kCryptoNotePublicKeySize + kChecksumSize;
constexpr uint8_t kEncodedBlockSizes[kFullBlockSize + 1] = {0, 2, 3, 5, 6, 7, 9, 10, 11};

struct EdwardsPoint {
  mbedtls_mpi x;
  mbedtls_mpi y;
  mbedtls_mpi z;
  mbedtls_mpi t;
};

void point_init(EdwardsPoint *point) {
  mbedtls_mpi_init(&point->x);
  mbedtls_mpi_init(&point->y);
  mbedtls_mpi_init(&point->z);
  mbedtls_mpi_init(&point->t);
}

void point_free(EdwardsPoint *point) {
  mbedtls_mpi_free(&point->t);
  mbedtls_mpi_free(&point->z);
  mbedtls_mpi_free(&point->y);
  mbedtls_mpi_free(&point->x);
}

bool read_decimal(mbedtls_mpi *value, const char *text) {
  return mbedtls_mpi_read_string(value, 10, text) == 0;
}

bool field_normalize(mbedtls_mpi *value, const mbedtls_mpi *prime) {
  return mbedtls_mpi_mod_mpi(value, value, prime) == 0;
}

bool field_add(mbedtls_mpi *out, const mbedtls_mpi *left,
               const mbedtls_mpi *right, const mbedtls_mpi *prime) {
  return mbedtls_mpi_add_mpi(out, left, right) == 0 && field_normalize(out, prime);
}

bool field_sub(mbedtls_mpi *out, const mbedtls_mpi *left,
               const mbedtls_mpi *right, const mbedtls_mpi *prime) {
  return mbedtls_mpi_sub_mpi(out, left, right) == 0 && field_normalize(out, prime);
}

bool field_mul(mbedtls_mpi *out, const mbedtls_mpi *left,
               const mbedtls_mpi *right, const mbedtls_mpi *prime) {
  return mbedtls_mpi_mul_mpi(out, left, right) == 0 && field_normalize(out, prime);
}

bool point_copy(EdwardsPoint *out, const EdwardsPoint &source) {
  return mbedtls_mpi_copy(&out->x, &source.x) == 0 &&
         mbedtls_mpi_copy(&out->y, &source.y) == 0 &&
         mbedtls_mpi_copy(&out->z, &source.z) == 0 &&
         mbedtls_mpi_copy(&out->t, &source.t) == 0;
}

bool point_identity(EdwardsPoint *point) {
  return mbedtls_mpi_lset(&point->x, 0) == 0 &&
         mbedtls_mpi_lset(&point->y, 1) == 0 &&
         mbedtls_mpi_lset(&point->z, 1) == 0 &&
         mbedtls_mpi_lset(&point->t, 0) == 0;
}

bool point_base(EdwardsPoint *point, const mbedtls_mpi *prime) {
  if (!read_decimal(&point->x,
      "15112221349535400772501151409588531511454012693041857206046113283949847762202") ||
      !read_decimal(&point->y,
      "46316835694926478169428394003475163141307993866256225615783033603165251855960") ||
      mbedtls_mpi_lset(&point->z, 1) != 0) {
    return false;
  }
  return field_mul(&point->t, &point->x, &point->y, prime);
}

bool point_add(EdwardsPoint *out, const EdwardsPoint &left,
               const EdwardsPoint &right, const mbedtls_mpi *prime,
               const mbedtls_mpi *edwards_d) {
  mbedtls_mpi a, b, c, d, e, f, g, h, first, second;
  mbedtls_mpi_init(&a); mbedtls_mpi_init(&b); mbedtls_mpi_init(&c);
  mbedtls_mpi_init(&d); mbedtls_mpi_init(&e); mbedtls_mpi_init(&f);
  mbedtls_mpi_init(&g); mbedtls_mpi_init(&h); mbedtls_mpi_init(&first);
  mbedtls_mpi_init(&second);
  const bool ok = field_sub(&first, &left.y, &left.x, prime) &&
      field_sub(&second, &right.y, &right.x, prime) &&
      field_mul(&a, &first, &second, prime) &&
      field_add(&first, &left.y, &left.x, prime) &&
      field_add(&second, &right.y, &right.x, prime) &&
      field_mul(&b, &first, &second, prime) &&
      field_mul(&first, &left.t, &right.t, prime) &&
      field_mul(&second, &first, edwards_d, prime) &&
      field_add(&c, &second, &second, prime) &&
      field_mul(&first, &left.z, &right.z, prime) &&
      field_add(&d, &first, &first, prime) &&
      field_sub(&e, &b, &a, prime) && field_sub(&f, &d, &c, prime) &&
      field_add(&g, &d, &c, prime) && field_add(&h, &b, &a, prime) &&
      field_mul(&out->x, &e, &f, prime) && field_mul(&out->y, &g, &h, prime) &&
      field_mul(&out->t, &e, &h, prime) && field_mul(&out->z, &f, &g, prime);
  mbedtls_mpi_free(&second); mbedtls_mpi_free(&first); mbedtls_mpi_free(&h);
  mbedtls_mpi_free(&g); mbedtls_mpi_free(&f); mbedtls_mpi_free(&e);
  mbedtls_mpi_free(&d); mbedtls_mpi_free(&c); mbedtls_mpi_free(&b);
  mbedtls_mpi_free(&a);
  return ok;
}

bool point_double(EdwardsPoint *out, const EdwardsPoint &point,
                  const mbedtls_mpi *prime) {
  mbedtls_mpi a, b, c, d, e, f, g, h, temporary;
  mbedtls_mpi_init(&a); mbedtls_mpi_init(&b); mbedtls_mpi_init(&c);
  mbedtls_mpi_init(&d); mbedtls_mpi_init(&e); mbedtls_mpi_init(&f);
  mbedtls_mpi_init(&g); mbedtls_mpi_init(&h); mbedtls_mpi_init(&temporary);
  const bool ok = field_mul(&a, &point.x, &point.x, prime) &&
      field_mul(&b, &point.y, &point.y, prime) &&
      field_mul(&temporary, &point.z, &point.z, prime) &&
      field_add(&c, &temporary, &temporary, prime) &&
      mbedtls_mpi_sub_mpi(&d, prime, &a) == 0 &&
      field_add(&temporary, &point.x, &point.y, prime) &&
      field_mul(&e, &temporary, &temporary, prime) &&
      field_sub(&e, &e, &a, prime) && field_sub(&e, &e, &b, prime) &&
      field_add(&g, &d, &b, prime) && field_sub(&f, &g, &c, prime) &&
      field_sub(&h, &d, &b, prime) &&
      field_mul(&out->x, &e, &f, prime) && field_mul(&out->y, &g, &h, prime) &&
      field_mul(&out->t, &e, &h, prime) && field_mul(&out->z, &f, &g, prime);
  mbedtls_mpi_free(&temporary); mbedtls_mpi_free(&h); mbedtls_mpi_free(&g);
  mbedtls_mpi_free(&f); mbedtls_mpi_free(&e); mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&c); mbedtls_mpi_free(&b); mbedtls_mpi_free(&a);
  return ok;
}

bool read_little_endian(mbedtls_mpi *out, const uint8_t *input, size_t size) {
  uint8_t reversed[kCryptoNoteScalarSize];
  if (input == nullptr || size > sizeof(reversed)) return false;
  for (size_t index = 0; index < size; ++index) reversed[index] = input[size - 1 - index];
  const bool ok = mbedtls_mpi_read_binary(out, reversed, size) == 0;
  secure_zero(reversed, sizeof(reversed));
  return ok;
}

bool write_little_endian(const mbedtls_mpi *value, uint8_t *out, size_t size) {
  uint8_t big_endian[kCryptoNoteScalarSize];
  if (out == nullptr || size > sizeof(big_endian) ||
      mbedtls_mpi_write_binary(value, big_endian, size) != 0) return false;
  for (size_t index = 0; index < size; ++index) out[index] = big_endian[size - 1 - index];
  secure_zero(big_endian, sizeof(big_endian));
  return true;
}

bool scalar_reduce(const uint8_t input[kCryptoNoteScalarSize],
                   uint8_t out[kCryptoNoteScalarSize]) {
  mbedtls_mpi scalar, order;
  mbedtls_mpi_init(&scalar);
  mbedtls_mpi_init(&order);
  const bool ok = read_little_endian(&scalar, input, kCryptoNoteScalarSize) &&
      read_decimal(&order,
      "7237005577332262213973186563042994240857116359379907606001950938285454250989") &&
      mbedtls_mpi_mod_mpi(&scalar, &scalar, &order) == 0 &&
      mbedtls_mpi_cmp_int(&scalar, 0) != 0 &&
      write_little_endian(&scalar, out, kCryptoNoteScalarSize);
  mbedtls_mpi_free(&order);
  mbedtls_mpi_free(&scalar);
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

bool encode_block(const uint8_t *input, size_t input_size, char *out, size_t output_size) {
  if (input == nullptr || out == nullptr || input_size == 0 || input_size > kFullBlockSize ||
      output_size != kEncodedBlockSizes[input_size]) return false;
  uint64_t value = 0;
  for (size_t index = 0; index < input_size; ++index) value = (value << 8) | input[index];
  memset(out, kBase58Alphabet[0], output_size);
  for (size_t position = output_size; value != 0 && position != 0;) {
    const uint64_t quotient = value / 58U;
    out[--position] = kBase58Alphabet[value - quotient * 58U];
    value = quotient;
  }
  return value == 0;
}

bool cryptonote_base58(const uint8_t *input, size_t input_size, char *out, size_t out_size) {
  if (input == nullptr || out == nullptr) return false;
  const size_t full_blocks = input_size / kFullBlockSize;
  const size_t final_size = input_size % kFullBlockSize;
  const size_t encoded_size = full_blocks * kFullEncodedBlockSize + kEncodedBlockSizes[final_size];
  if (encoded_size + 1 > out_size) return false;
  size_t input_offset = 0;
  size_t output_offset = 0;
  for (size_t block = 0; block < full_blocks; ++block) {
    if (!encode_block(input + input_offset, kFullBlockSize, out + output_offset,
                      kFullEncodedBlockSize)) return false;
    input_offset += kFullBlockSize;
    output_offset += kFullEncodedBlockSize;
  }
  if (final_size != 0 && !encode_block(input + input_offset, final_size,
                                        out + output_offset, kEncodedBlockSizes[final_size])) return false;
  out[encoded_size] = '\0';
  return true;
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
  if (scalar_bytes == nullptr || out_public_key == nullptr) return WalletError::InvalidArgument;
  mbedtls_mpi prime, order, scalar, edwards_d, inverse, affine_x, affine_y;
  mbedtls_mpi_init(&prime); mbedtls_mpi_init(&order); mbedtls_mpi_init(&scalar);
  mbedtls_mpi_init(&edwards_d); mbedtls_mpi_init(&inverse);
  mbedtls_mpi_init(&affine_x); mbedtls_mpi_init(&affine_y);
  EdwardsPoint result, addend, added, doubled;
  point_init(&result); point_init(&addend); point_init(&added); point_init(&doubled);
  bool ok = read_decimal(&prime,
      "57896044618658097711785492504343953926634992332820282019728792003956564819949") &&
      read_decimal(&order,
      "7237005577332262213973186563042994240857116359379907606001950938285454250989") &&
      read_decimal(&edwards_d,
      "37095705934669439343138083508754565189542113879843219016388785533085940283555") &&
      read_little_endian(&scalar, scalar_bytes, kCryptoNoteScalarSize) &&
      mbedtls_mpi_cmp_int(&scalar, 0) > 0 && mbedtls_mpi_cmp_mpi(&scalar, &order) < 0 &&
      point_identity(&result) && point_base(&addend, &prime);
  for (size_t bit = 0; ok && bit < 253; ++bit) {
    ok = point_add(&added, result, addend, &prime, &edwards_d) &&
         point_double(&doubled, addend, &prime);
    if (ok && mbedtls_mpi_get_bit(&scalar, bit) != 0) ok = point_copy(&result, added);
    if (ok) ok = point_copy(&addend, doubled);
  }
  ok = ok && mbedtls_mpi_inv_mod(&inverse, &result.z, &prime) == 0 &&
       field_mul(&affine_x, &result.x, &inverse, &prime) &&
       field_mul(&affine_y, &result.y, &inverse, &prime) &&
       write_little_endian(&affine_y, out_public_key, kCryptoNotePublicKeySize);
  if (ok && mbedtls_mpi_get_bit(&affine_x, 0) != 0) out_public_key[31] |= 0x80;
  point_free(&doubled); point_free(&added); point_free(&addend); point_free(&result);
  mbedtls_mpi_free(&affine_y); mbedtls_mpi_free(&affine_x); mbedtls_mpi_free(&inverse);
  mbedtls_mpi_free(&edwards_d); mbedtls_mpi_free(&scalar);
  mbedtls_mpi_free(&order); mbedtls_mpi_free(&prime);
  if (!ok) secure_zero(out_public_key, kCryptoNotePublicKeySize);
  return ok ? WalletError::Ok : WalletError::InvalidKey;
}

WalletError cryptonote_standard_address(
    const CryptoNoteAddressProfile &profile,
    const uint8_t public_spend_key[kCryptoNotePublicKeySize],
    const uint8_t public_view_key[kCryptoNotePublicKeySize],
    char *out, size_t out_size) {
  if (profile.standard_address_prefix == 0 || public_spend_key == nullptr ||
      public_view_key == nullptr || out == nullptr) return WalletError::InvalidArgument;
  uint8_t payload[kAddressPayloadSize];
  const size_t prefix_size = write_varint(profile.standard_address_prefix, payload);
  if (prefix_size == 0) return WalletError::InvalidArgument;
  memcpy(payload + prefix_size, public_spend_key, kCryptoNotePublicKeySize);
  memcpy(payload + prefix_size + kCryptoNotePublicKeySize,
         public_view_key, kCryptoNotePublicKeySize);
  const size_t data_size = prefix_size + 2 * kCryptoNotePublicKeySize;
  uint8_t digest[kKeccak256Size];
  const bool hashed = crypto_keccak256(payload, data_size, digest);
  if (hashed) memcpy(payload + data_size, digest, kChecksumSize);
  const bool encoded = hashed && cryptonote_base58(payload, data_size + kChecksumSize, out, out_size);
  secure_zero(digest, sizeof(digest));
  secure_zero(payload, sizeof(payload));
  return encoded ? WalletError::Ok : (out_size < kCryptoNoteStandardAddressSize
                                           ? WalletError::BufferTooSmall
                                           : WalletError::CryptoFailure);
}

WalletError cryptonote_address_from_seed(
    const CryptoNoteAddressProfile &profile,
    const uint8_t seed[kCryptoNoteScalarSize],
    char *out, size_t out_size,
    uint8_t out_spend_key[kCryptoNoteScalarSize]) {
  if (seed == nullptr || out == nullptr || out_spend_key == nullptr) return WalletError::InvalidArgument;
  uint8_t view_key[kCryptoNoteScalarSize];
  uint8_t public_spend[kCryptoNotePublicKeySize];
  uint8_t public_view[kCryptoNotePublicKeySize];
  WalletError result = cryptonote_private_keys_from_seed(seed, out_spend_key, view_key);
  if (result == WalletError::Ok) result = cryptonote_public_key_from_scalar(out_spend_key, public_spend);
  if (result == WalletError::Ok) result = cryptonote_public_key_from_scalar(view_key, public_view);
  if (result == WalletError::Ok) {
    result = cryptonote_standard_address(profile, public_spend, public_view, out, out_size);
  }
  secure_zero(view_key, sizeof(view_key));
  secure_zero(public_spend, sizeof(public_spend));
  secure_zero(public_view, sizeof(public_view));
  if (result != WalletError::Ok) secure_zero(out_spend_key, kCryptoNoteScalarSize);
  return result;
}

bool run_cryptonote_self_tests() {
  uint8_t seed[kCryptoNoteScalarSize] = {};
  uint8_t spend_key[kCryptoNoteScalarSize];
  uint8_t view_key[kCryptoNoteScalarSize];
  static const uint8_t kExpectedSpendKey[kCryptoNoteScalarSize] = {
      0x9b,0x15,0x29,0xac,0xb6,0x38,0xf4,0x97,0xd0,0x56,0x77,0xd7,0x50,0x5d,0x35,0x4b,
      0x4b,0xa6,0xbc,0x95,0x48,0x40,0x08,0xf6,0x36,0x2f,0x93,0x16,0x0e,0xf3,0xe5,0x03,
  };
  static const uint8_t kExpectedViewKey[kCryptoNoteScalarSize] = {
      0x45,0x2b,0x39,0x13,0x3e,0x70,0xf8,0x03,0xf4,0x88,0x28,0x2d,0x39,0x7a,0x87,0x1a,
      0xe3,0x9b,0xeb,0x30,0x01,0x73,0x0c,0x43,0xea,0xa1,0xf2,0xee,0xf9,0xeb,0x6a,0x0e,
  };
  uint8_t scalar[kCryptoNoteScalarSize] = {3};
  uint8_t public_key[kCryptoNotePublicKeySize];
  static const uint8_t kBasePoint[kCryptoNotePublicKeySize] = {
      0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
      0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
  };
  static const uint8_t kExpectedThreeTimesBasePoint[kCryptoNotePublicKeySize] = {
      0xd4,0xb4,0xf5,0x78,0x48,0x68,0xc3,0x02,0x04,0x03,0x24,0x67,0x17,0xec,0x16,0x9f,
      0xf7,0x9e,0x26,0x60,0x8e,0xa1,0x26,0xa1,0xab,0x69,0xee,0x77,0xd1,0xb1,0x67,0x12,
  };
  char address[kCryptoNoteStandardAddressSize];
  static const char kExpectedAddress[] =
      "44yQXfkWZNmJ8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmJ7suhUXwdrD"
      "J8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmCYrSgjJ";
  static const char kExpectedMasariAddress[] =
      "5jz8fjwSe3wJ8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmJ7suhUXwdrD"
      "J8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmCWb1XQW";
  bool passed = cryptonote_private_keys_from_seed(seed, spend_key, view_key) == WalletError::Ok &&
      crypto_constant_time_equal(spend_key, kExpectedSpendKey, sizeof(spend_key)) &&
      crypto_constant_time_equal(view_key, kExpectedViewKey, sizeof(view_key)) &&
      cryptonote_public_key_from_scalar(scalar, public_key) == WalletError::Ok &&
      crypto_constant_time_equal(public_key, kExpectedThreeTimesBasePoint, sizeof(public_key)) &&
      cryptonote_standard_address(kMoneroMainnet, kBasePoint, kBasePoint,
                                  address, sizeof(address)) == WalletError::Ok &&
      strcmp(address, kExpectedAddress) == 0;
  passed = passed && cryptonote_standard_address(kMasariMainnet, kBasePoint, kBasePoint,
                                                  address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, kExpectedMasariAddress) == 0;
  secure_zero(address, sizeof(address));
  secure_zero(public_key, sizeof(public_key));
  secure_zero(scalar, sizeof(scalar));
  secure_zero(view_key, sizeof(view_key));
  secure_zero(spend_key, sizeof(spend_key));
  secure_zero(seed, sizeof(seed));
  return passed;
}

}  // namespace hexwallet
