#include "Blake2b.h"

#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

constexpr size_t kBlockSize = 128;

const uint64_t kIv[8] = {
  UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
  UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
  UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
  UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179),
};

const uint8_t kSigma[12][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
};

inline uint64_t load_le64(const uint8_t *data) {
  uint64_t value = 0;
  for (uint8_t index = 0; index < 8; ++index) {
    value |= static_cast<uint64_t>(data[index]) << (index * 8U);
  }
  return value;
}

inline uint64_t rotate_right64(uint64_t value, unsigned bits) {
  return (value >> bits) | (value << (64U - bits));
}

#define HW_BLAKE2B_G(a, b, c, d, x, y) \
  do { \
    v[a] = v[a] + v[b] + x; \
    v[d] = rotate_right64(v[d] ^ v[a], 32); \
    v[c] = v[c] + v[d]; \
    v[b] = rotate_right64(v[b] ^ v[c], 24); \
    v[a] = v[a] + v[b] + y; \
    v[d] = rotate_right64(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d]; \
    v[b] = rotate_right64(v[b] ^ v[c], 63); \
  } while (0)

void compress(Blake2bState *state, const uint8_t block[kBlockSize],
              bool last_block) {
  uint64_t m[16];
  for (size_t index = 0; index < 16; ++index) {
    m[index] = load_le64(block + index * 8);
  }
  uint64_t v[16];
  memcpy(v, state->h, sizeof(state->h));
  memcpy(v + 8, kIv, sizeof(kIv));
  v[12] ^= state->t0;
  v[13] ^= state->t1;
  if (last_block) v[14] ^= UINT64_MAX;
  for (size_t round = 0; round < 12; ++round) {
    const uint8_t *s = kSigma[round];
    HW_BLAKE2B_G(0, 4, 8, 12, m[s[0]], m[s[1]]);
    HW_BLAKE2B_G(1, 5, 9, 13, m[s[2]], m[s[3]]);
    HW_BLAKE2B_G(2, 6, 10, 14, m[s[4]], m[s[5]]);
    HW_BLAKE2B_G(3, 7, 11, 15, m[s[6]], m[s[7]]);
    HW_BLAKE2B_G(0, 5, 10, 15, m[s[8]], m[s[9]]);
    HW_BLAKE2B_G(1, 6, 11, 12, m[s[10]], m[s[11]]);
    HW_BLAKE2B_G(2, 7, 8, 13, m[s[12]], m[s[13]]);
    HW_BLAKE2B_G(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (size_t index = 0; index < 8; ++index) {
    state->h[index] ^= v[index] ^ v[index + 8];
  }
  secure_zero(v, sizeof(v));
  secure_zero(m, sizeof(m));
}

#undef HW_BLAKE2B_G

}  // namespace

bool blake2b_init(Blake2bState *state, size_t out_size, const uint8_t *key,
                  size_t key_size) {
  if (state == nullptr || out_size == 0 || out_size > 64 || key_size > 64 ||
      (key == nullptr && key_size != 0)) {
    return false;
  }
  memset(state, 0, sizeof(*state));
  memcpy(state->h, kIv, sizeof(state->h));
  // Parameter block word 0: digest length, key length, fanout=1, depth=1.
  state->h[0] ^= UINT64_C(0x01010000) ^
                 (static_cast<uint64_t>(key_size) << 8) ^
                 static_cast<uint64_t>(out_size);
  state->out_size = out_size;
  if (key_size != 0) {
    uint8_t key_block[kBlockSize] = { 0 };
    memcpy(key_block, key, key_size);
    blake2b_update(state, key_block, kBlockSize);
    secure_zero(key_block, sizeof(key_block));
  }
  return true;
}

void blake2b_update(Blake2bState *state, const uint8_t *data, size_t size) {
  if (state == nullptr || data == nullptr || size == 0) return;
  size_t offset = 0;
  // Only flush a full block when more input follows, so the final block is
  // always processed with the last-block flag set.
  while (size - offset > kBlockSize - state->buffer_size) {
    const size_t take = kBlockSize - state->buffer_size;
    memcpy(state->buffer + state->buffer_size, data + offset, take);
    state->buffer_size = kBlockSize;
    state->t0 += kBlockSize;
    if (state->t0 < kBlockSize) ++state->t1;
    compress(state, state->buffer, false);
    state->buffer_size = 0;
    offset += take;
  }
  memcpy(state->buffer + state->buffer_size, data + offset, size - offset);
  state->buffer_size += size - offset;
}

bool blake2b_final(Blake2bState *state, uint8_t *out) {
  if (state == nullptr || out == nullptr) return false;
  state->t0 += state->buffer_size;
  if (state->t0 < state->buffer_size) ++state->t1;
  memset(state->buffer + state->buffer_size, 0, kBlockSize - state->buffer_size);
  compress(state, state->buffer, true);
  for (size_t index = 0; index < state->out_size; ++index) {
    out[index] = static_cast<uint8_t>(state->h[index / 8] >> (8U * (index % 8)));
  }
  secure_zero(state, sizeof(*state));
  return true;
}

bool blake2b_keyed_hash(const uint8_t *key, size_t key_size, const uint8_t *data,
                        size_t size, uint8_t *out, size_t out_size) {
  if ((data == nullptr && size != 0) || out == nullptr) return false;
  Blake2bState state;
  if (!blake2b_init(&state, out_size, key, key_size)) return false;
  blake2b_update(&state, data, size);
  return blake2b_final(&state, out);
}

bool run_blake2b_self_tests() {
  // RFC 7693 appendix A plus the BLAKE2b-256 vectors, and one keyed vector.
  const uint8_t abc[] = { 'a', 'b', 'c' };
  const uint8_t expected256[32] = {
    0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f,
    0xee, 0x98, 0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42,
    0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5, 0x23, 0x19 };
  uint8_t actual[64];
  bool passed = blake2b_keyed_hash(nullptr, 0, abc, sizeof(abc), actual, 32) &&
                crypto_constant_time_equal(actual, expected256, sizeof(expected256));
  // Keyed vector cross-checked against Python hashlib.blake2b and Rust
  // blake2b_simd with the same key: empty message, 32-byte digest.
  static const uint8_t kKey[] = { 'T', 'r', 'a', 'n', 's', 'a', 'c', 't', 'i',
                                  'o', 'n', 'S', 'i', 'g', 'n', 'i', 'n', 'g',
                                  'H', 'a', 's', 'h' };
  const uint8_t expected_keyed[32] = {
    0x34, 0xc7, 0x50, 0x37, 0xad, 0x62, 0x74, 0x0d, 0x4b, 0x32, 0x28, 0xf8,
    0x8f, 0x84, 0x4f, 0x79, 0x01, 0xc0, 0x7b, 0xfa, 0xcd, 0x55, 0xa0, 0x45,
    0xbe, 0x51, 0x8e, 0xab, 0xc1, 0x5e, 0x52, 0xce };
  passed = blake2b_keyed_hash(kKey, sizeof(kKey), nullptr, 0, actual, 32) &&
           crypto_constant_time_equal(actual, expected_keyed, sizeof(expected_keyed)) &&
           passed;
  // A keyed hash must not equal the unkeyed hash of the same message.
  uint8_t unkeyed[32];
  passed = blake2b_keyed_hash(nullptr, 0, nullptr, 0, unkeyed, 32) &&
           !crypto_constant_time_equal(unkeyed, actual, sizeof(unkeyed)) && passed;
  secure_zero(actual, sizeof(actual));
  secure_zero(unkeyed, sizeof(unkeyed));
  return passed;
}

}  // namespace hexwallet
