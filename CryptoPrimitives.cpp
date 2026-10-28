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

bool crypto_sha224(const uint8_t *data, size_t size, uint8_t out[kSha224Size]) {
  return digest(MBEDTLS_MD_SHA224, data, size, out);
}

bool crypto_sha224_local(const uint8_t *data, size_t size,
                         uint8_t out[kSha224Size]) {
  if (out == nullptr || (data == nullptr && size != 0)) return false;
  static const uint32_t kK[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  uint32_t h[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                   0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};
  auto rotate = [](uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32U - bits));
  };
  auto compress = [&](const uint8_t *block) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) {
      w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
             (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
             (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
             static_cast<uint32_t>(block[i * 4 + 3]);
    }
    for (size_t i = 16; i < 64; ++i) {
      const uint32_t s0 =
          rotate(w[i - 15], 7) ^ rotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const uint32_t s1 =
          rotate(w[i - 2], 17) ^ rotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (size_t i = 0; i < 64; ++i) {
      const uint32_t s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
      const uint32_t ch = (e & f) ^ (~e & g);
      const uint32_t temp1 = hh + s1 + ch + kK[i] + w[i];
      const uint32_t s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temp2 = s0 + maj;
      hh = g; g = f; f = e; e = d + temp1;
      d = c; c = b; b = a; a = temp1 + temp2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  };
  size_t offset = 0;
  while (size - offset >= 64) {
    compress(data + offset);
    offset += 64;
  }
  uint8_t tail[128] = {};
  const size_t remaining = size - offset;
  if (remaining != 0) memcpy(tail, data + offset, remaining);
  tail[remaining] = 0x80;
  const size_t blocks = remaining + 1 + 8 <= 64 ? 1 : 2;
  const uint64_t bits = static_cast<uint64_t>(size) * 8U;
  for (size_t i = 0; i < 8; ++i) {
    tail[blocks * 64 - 1 - i] = static_cast<uint8_t>(bits >> (i * 8U));
  }
  for (size_t block = 0; block < blocks; ++block) compress(tail + block * 64);
  for (size_t i = 0; i < kSha224Size; ++i) {
    out[i] = static_cast<uint8_t>(h[i / 4] >> (24U - 8U * (i % 4)));
  }
  mbedtls_platform_zeroize(tail, sizeof(tail));
  return true;
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
