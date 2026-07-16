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
  if (password == nullptr || salt == nullptr || out == nullptr || iterations == 0 ||
      out_size == 0 || out_size > UINT32_MAX) {
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

bool crypto_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t size) {
  if (left == nullptr || right == nullptr) return false;
  uint8_t difference = 0;
  for (size_t index = 0; index < size; ++index) difference |= left[index] ^ right[index];
  return difference == 0;
}

bool run_crypto_self_tests() {
  static const uint8_t kEmptyKeccak[kKeccak256Size] = {
      0xc5,0xd2,0x46,0x01,0x86,0xf7,0x23,0x3c,0x92,0x7e,0x7d,0xb2,0xdc,0xc7,0x03,0xc0,
      0xe5,0x00,0xb6,0x53,0xca,0x82,0x27,0x3b,0x7b,0xfa,0xd8,0x04,0x5d,0x85,0xa4,0x70,
  };
  static const uint8_t kAbcSha[kSha256Size] = {
      0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
      0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad,
  };
  static const uint8_t kEmptyRipemd[kRipemd160Size] = {
      0x9c,0x11,0x85,0xa5,0xc5,0xe9,0xfc,0x54,0x61,0x28,0x08,0x97,0x7e,0xe8,0xf5,0x48,
      0xb2,0x25,0x8d,0x31,
  };
  static const uint8_t kAbc[] = {'a','b','c'};
  uint8_t actual[kSha256Size];
  bool passed = crypto_sha256(kAbc, sizeof(kAbc), actual) &&
                crypto_constant_time_equal(actual, kAbcSha, sizeof(actual));
  passed = passed && crypto_keccak256(nullptr, 0, actual) &&
           crypto_constant_time_equal(actual, kEmptyKeccak, sizeof(actual));
  uint8_t short_actual[kRipemd160Size];
  local_ripemd160(nullptr, 0, short_actual);
  passed = passed && crypto_constant_time_equal(short_actual, kEmptyRipemd, sizeof(short_actual));
  mbedtls_platform_zeroize(actual, sizeof(actual));
  mbedtls_platform_zeroize(short_actual, sizeof(short_actual));
  return passed;
}

}  // namespace hexwallet
