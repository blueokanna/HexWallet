#include "CryptoPrimitives.h"

#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/platform_util.h>
#include <string.h>

#include "keccak256.h"
#include "local_ripemd160.h"

namespace hexwallet {
namespace {

bool digest(mbedtls_md_type_t type, const uint8_t *data, size_t size, uint8_t *out) {
  if (out == nullptr || (data == nullptr && size != 0)) return false;
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(type);
  return info != nullptr && mbedtls_md(info, data, size, out) == 0;
}

bool hmac(mbedtls_md_type_t type, const uint8_t *key, size_t key_size,
          const uint8_t *data, size_t data_size, uint8_t *out) {
  if (key == nullptr || out == nullptr || (data == nullptr && data_size != 0)) return false;
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(type);
  return info != nullptr && mbedtls_md_hmac(info, key, key_size, data, data_size, out) == 0;
}

constexpr size_t kKeccakLanes = 25;
constexpr size_t kMaxKeccakRate = 168;

uint64_t load_le64(const uint8_t *data) {
  uint64_t value = 0;
  for (uint8_t index = 0; index < 8; ++index) {
    value |= static_cast<uint64_t>(data[index]) << (index * 8U);
  }
  return value;
}

void store_le64(uint8_t *out, uint64_t value) {
  for (uint8_t index = 0; index < 8; ++index) {
    out[index] = static_cast<uint8_t>(value >> (index * 8U));
  }
}

// One-shot Keccak sponge shared by Keccak-512 and SHAKE-256.  The rate is a
// multiple of the lane size; domain is 0x01 for legacy Keccak and 0x1F for
// SHAKE.  Output may span several squeeze blocks.
bool keccak_sponge(const uint8_t *data, size_t size, size_t rate, uint8_t domain,
                   uint8_t *out, size_t out_size) {
  if (out == nullptr || (data == nullptr && size != 0) || rate == 0 ||
      rate > kMaxKeccakRate || (rate % sizeof(uint64_t)) != 0) {
    return false;
  }
  uint64_t state[kKeccakLanes] = {};
  while (size >= rate) {
    for (size_t lane = 0; lane < rate / sizeof(uint64_t); ++lane) {
      state[lane] ^= load_le64(data + lane * sizeof(uint64_t));
    }
    keccak_permute(state);
    data += rate;
    size -= rate;
  }
  uint8_t block[kMaxKeccakRate] = {};
  if (size != 0) memcpy(block, data, size);
  block[size] ^= domain;
  block[rate - 1] ^= 0x80;
  for (size_t lane = 0; lane < rate / sizeof(uint64_t); ++lane) {
    state[lane] ^= load_le64(block + lane * sizeof(uint64_t));
  }
  keccak_permute(state);

  size_t produced = 0;
  while (produced != out_size) {
    const size_t take = (out_size - produced) < rate ? (out_size - produced) : rate;
    for (size_t offset = 0; offset < take; offset += sizeof(uint64_t)) {
      uint8_t lane[sizeof(uint64_t)];
      store_le64(lane, state[offset / sizeof(uint64_t)]);
      const size_t chunk = (take - offset) < sizeof(uint64_t) ? (take - offset) : sizeof(uint64_t);
      memcpy(out + produced + offset, lane, chunk);
    }
    produced += take;
    if (produced != out_size) keccak_permute(state);
  }
  mbedtls_platform_zeroize(state, sizeof(state));
  mbedtls_platform_zeroize(block, sizeof(block));
  return true;
}

}  // namespace

bool crypto_sha256(const uint8_t *data, size_t size, uint8_t out[kSha256Size]) {
  return digest(MBEDTLS_MD_SHA256, data, size, out);
}

bool crypto_double_sha256(const uint8_t *data, size_t size, uint8_t out[kSha256Size]) {
  uint8_t first[kSha256Size];
  const bool ok = crypto_sha256(data, size, first) && crypto_sha256(first, sizeof(first), out);
  mbedtls_platform_zeroize(first, sizeof(first));
  return ok;
}

bool crypto_double_sha256_segments(const uint8_t *a, size_t a_size,
                                   const uint8_t *b, size_t b_size,
                                   const uint8_t *c, size_t c_size,
                                   uint8_t out[kSha256Size]) {
  if (out == nullptr || (a == nullptr && a_size != 0) || (b == nullptr && b_size != 0) ||
      (c == nullptr && c_size != 0)) {
    return false;
  }
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info == nullptr) return false;
  uint8_t first[kSha256Size];
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  bool ok = mbedtls_md_setup(&context, info, 0) == 0 && mbedtls_md_starts(&context) == 0;
  if (ok && a_size != 0) ok = mbedtls_md_update(&context, a, a_size) == 0;
  if (ok && b_size != 0) ok = mbedtls_md_update(&context, b, b_size) == 0;
  if (ok && c_size != 0) ok = mbedtls_md_update(&context, c, c_size) == 0;
  if (ok) ok = mbedtls_md_finish(&context, first) == 0;
  mbedtls_md_free(&context);
  if (ok) ok = crypto_sha256(first, sizeof(first), out);
  mbedtls_platform_zeroize(first, sizeof(first));
  return ok;
}

bool crypto_hmac_sha256(const uint8_t *key, size_t key_size, const uint8_t *data,
                        size_t data_size, uint8_t out[kSha256Size]) {
  return hmac(MBEDTLS_MD_SHA256, key, key_size, data, data_size, out);
}

bool crypto_hmac_sha512(const uint8_t *key, size_t key_size, const uint8_t *data,
                        size_t data_size, uint8_t out[kSha512Size]) {
  return hmac(MBEDTLS_MD_SHA512, key, key_size, data, data_size, out);
}

bool crypto_pbkdf2_sha256(const uint8_t *password, size_t password_size,
                          const uint8_t *salt, size_t salt_size, uint32_t iterations,
                          uint8_t *out, size_t out_size) {
  if (password == nullptr || salt == nullptr || out == nullptr || iterations == 0 || out_size == 0 || out_size > UINT32_MAX) {
    return false;
  }
  const int result = mbedtls_pkcs5_pbkdf2_hmac_ext(
    MBEDTLS_MD_SHA256, password, password_size, salt, salt_size,
    iterations, static_cast<uint32_t>(out_size), out);
  return result == 0;
}

bool crypto_hash160(const uint8_t *data, size_t size, uint8_t out[kRipemd160Size]) {
  uint8_t sha[kSha256Size];
  if (!crypto_sha256(data, size, sha)) return false;
  local_ripemd160(sha, sizeof(sha), out);
  mbedtls_platform_zeroize(sha, sizeof(sha));
  return true;
}

bool crypto_keccak256(const uint8_t *data, size_t size, uint8_t out[kKeccak256Size]) {
  SHA3_CTX context;
  keccak_init(&context);
  const bool ok = keccak_update(&context, data, size) && keccak_final(&context, out);
  mbedtls_platform_zeroize(&context, sizeof(context));
  return ok;
}

bool crypto_keccak512(const uint8_t *data, size_t size, uint8_t out[kKeccak512Size]) {
  return keccak_sponge(data, size, 72, 0x01, out, kKeccak512Size);
}

bool crypto_shake256(const uint8_t *data, size_t size, uint8_t *out, size_t out_size) {
  return keccak_sponge(data, size, 136, 0x1F, out, out_size);
}

bool crypto_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t size) {
  if (left == nullptr || right == nullptr) return false;
  uint8_t difference = 0;
  for (size_t index = 0; index < size; ++index) difference |= left[index] ^ right[index];
  return difference == 0;
}

bool run_crypto_self_tests() {
  static const uint8_t kEmptyKeccak[kKeccak256Size] = {
    0xc5,
    0xd2,
    0x46,
    0x01,
    0x86,
    0xf7,
    0x23,
    0x3c,
    0x92,
    0x7e,
    0x7d,
    0xb2,
    0xdc,
    0xc7,
    0x03,
    0xc0,
    0xe5,
    0x00,
    0xb6,
    0x53,
    0xca,
    0x82,
    0x27,
    0x3b,
    0x7b,
    0xfa,
    0xd8,
    0x04,
    0x5d,
    0x85,
    0xa4,
    0x70,
  };
  static const uint8_t kAbcSha[kSha256Size] = {
    0xba,
    0x78,
    0x16,
    0xbf,
    0x8f,
    0x01,
    0xcf,
    0xea,
    0x41,
    0x41,
    0x40,
    0xde,
    0x5d,
    0xae,
    0x22,
    0x23,
    0xb0,
    0x03,
    0x61,
    0xa3,
    0x96,
    0x17,
    0x7a,
    0x9c,
    0xb4,
    0x10,
    0xff,
    0x61,
    0xf2,
    0x00,
    0x15,
    0xad,
  };
  static const uint8_t kEmptyRipemd[kRipemd160Size] = {
    0x9c,
    0x11,
    0x85,
    0xa5,
    0xc5,
    0xe9,
    0xfc,
    0x54,
    0x61,
    0x28,
    0x08,
    0x97,
    0x7e,
    0xe8,
    0xf5,
    0x48,
    0xb2,
    0x25,
    0x8d,
    0x31,
  };
  static const uint8_t kAbc[] = { 'a', 'b', 'c' };
  static const uint8_t kEmptyKeccak512[kKeccak512Size] = {
    0x0e, 0xab, 0x42, 0xde, 0x4c, 0x3c, 0xeb, 0x92, 0x35, 0xfc, 0x91, 0xac, 0xff, 0xe7, 0x46, 0xb2,
    0x9c, 0x29, 0xa8, 0xc3, 0x66, 0xb7, 0xc6, 0x0e, 0x4e, 0x67, 0xc4, 0x66, 0xf3, 0x6a, 0x43, 0x04,
    0xc0, 0x0f, 0xa9, 0xca, 0xf9, 0xd8, 0x79, 0x76, 0xba, 0x46, 0x9b, 0xcb, 0xe0, 0x67, 0x13, 0xb4,
    0x35, 0xf0, 0x91, 0xef, 0x27, 0x69, 0xfb, 0x16, 0x0c, 0xda, 0xb3, 0x3d, 0x36, 0x70, 0x68, 0x0e,
  };
  static const uint8_t kEmptyShake256[kShake256Size] = {
    0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
    0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
  };
  static const uint8_t kAbcShake256[kShake256Size] = {
    0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77, 0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d,
    0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee, 0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39,
  };
  uint8_t actual[kSha256Size];
  bool passed = crypto_sha256(kAbc, sizeof(kAbc), actual) && crypto_constant_time_equal(actual, kAbcSha, sizeof(actual));
  passed = passed && crypto_keccak256(nullptr, 0, actual) && crypto_constant_time_equal(actual, kEmptyKeccak, sizeof(actual));
  uint8_t short_actual[kRipemd160Size];
  local_ripemd160(nullptr, 0, short_actual);
  passed = passed && crypto_constant_time_equal(short_actual, kEmptyRipemd, sizeof(short_actual));
  uint8_t wide[kKeccak512Size];
  passed = passed && crypto_keccak512(nullptr, 0, wide) && crypto_constant_time_equal(wide, kEmptyKeccak512, sizeof(wide));
  passed = passed && crypto_shake256(nullptr, 0, wide, kShake256Size) && crypto_constant_time_equal(wide, kEmptyShake256, kShake256Size);
  passed = passed && crypto_shake256(kAbc, sizeof(kAbc), wide, kShake256Size) && crypto_constant_time_equal(wide, kAbcShake256, kShake256Size);
  mbedtls_platform_zeroize(wide, sizeof(wide));
  mbedtls_platform_zeroize(actual, sizeof(actual));
  mbedtls_platform_zeroize(short_actual, sizeof(short_actual));
  return passed;
}

}  // namespace hexwallet
