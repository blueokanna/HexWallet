#include "Blake256.h"

#include <stdio.h>
#include <string.h>

#include "WalletSecurity.h"

namespace hexwallet {
namespace {

constexpr uint32_t kIv[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

constexpr uint32_t kC[16] = {
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
    0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917};

constexpr uint8_t kSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

uint32_t rotate_right(uint32_t value, uint8_t count) {
  return (value >> count) | (value << (32 - count));
}

uint32_t load_be32(const uint8_t *data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) | data[3];
}

void g(uint32_t *v, uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint32_t mx,
       uint32_t my, uint32_t cx, uint32_t cy) {
  v[a] = v[a] + v[b] + (mx ^ cx);
  v[d] = rotate_right(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = rotate_right(v[b] ^ v[c], 12);
  v[a] = v[a] + v[b] + (my ^ cy);
  v[d] = rotate_right(v[d] ^ v[a], 8);
  v[c] = v[c] + v[d];
  v[b] = rotate_right(v[b] ^ v[c], 7);
}

void compress(Blake256State *state, const uint8_t block[64]) {
  uint32_t m[16];
  for (size_t index = 0; index < 16; ++index) {
    m[index] = load_be32(block + index * 4);
  }
  uint32_t v[16] = {};
  for (size_t index = 0; index < 8; ++index) v[index] = state->h[index];
  v[8] = kC[0];
  v[9] = kC[1];
  v[10] = kC[2];
  v[11] = kC[3];
  const uint32_t t0 = static_cast<uint32_t>(state->counter);
  const uint32_t t1 = static_cast<uint32_t>(state->counter >> 32);
  v[12] = t0 ^ kC[4];
  v[13] = t0 ^ kC[5];
  v[14] = t1 ^ kC[6];
  v[15] = t1 ^ kC[7];
  // BLAKE-256 uses 14 rounds; the ten permutations repeat after round 10.
  for (size_t round = 0; round < 14; ++round) {
    const uint8_t *s = kSigma[round % 10];
    // Each G mixes the message word with the adjacent BLAKE constant in the
    // order c[sigma[2i+1]], c[sigma[2i]].
    g(v, 0, 4, 8, 12, m[s[0]], m[s[1]], kC[s[1]], kC[s[0]]);
    g(v, 1, 5, 9, 13, m[s[2]], m[s[3]], kC[s[3]], kC[s[2]]);
    g(v, 2, 6, 10, 14, m[s[4]], m[s[5]], kC[s[5]], kC[s[4]]);
    g(v, 3, 7, 11, 15, m[s[6]], m[s[7]], kC[s[7]], kC[s[6]]);
    g(v, 0, 5, 10, 15, m[s[8]], m[s[9]], kC[s[9]], kC[s[8]]);
    g(v, 1, 6, 11, 12, m[s[10]], m[s[11]], kC[s[11]], kC[s[10]]);
    g(v, 2, 7, 8, 13, m[s[12]], m[s[13]], kC[s[13]], kC[s[12]]);
    g(v, 3, 4, 9, 14, m[s[14]], m[s[15]], kC[s[15]], kC[s[14]]);
  }
  for (size_t index = 0; index < 8; ++index) {
    state->h[index] ^= v[index] ^ v[index + 8];
  }
  secure_zero(v, sizeof(v));
  secure_zero(m, sizeof(m));
}

void process_block(Blake256State *state, const uint8_t block[64]) {
  state->counter += 512;
  compress(state, block);
}

}  // namespace

void blake256_init(Blake256State *state) {
  if (state == nullptr) return;
  memcpy(state->h, kIv, sizeof(kIv));
  state->counter = 0;
  state->buffer_size = 0;
}

void blake256_update(Blake256State *state, const uint8_t *data, size_t size) {
  if (state == nullptr || (size != 0 && data == nullptr)) return;
  for (size_t index = 0; index < size; ++index) {
    state->buffer[state->buffer_size++] = data[index];
    if (state->buffer_size == 64) {
      process_block(state, state->buffer);
      state->buffer_size = 0;
    }
  }
}

bool blake256_final(Blake256State *state, uint8_t out[32]) {
  if (state == nullptr || out == nullptr) return false;
  const uint64_t message_bits =
      state->counter + static_cast<uint64_t>(state->buffer_size) * 8;
  if (state->buffer_size == 55) {
    state->buffer[55] = 0x81;  // padding bit plus the BLAKE-256 preamble bit
    for (size_t index = 0; index < 8; ++index) {
      state->buffer[56 + index] =
          static_cast<uint8_t>(message_bits >> (56 - 8 * index));
    }
    state->counter = message_bits;
    compress(state, state->buffer);
  } else if (state->buffer_size < 55) {
    state->buffer[state->buffer_size] = 0x80;
    for (size_t index = state->buffer_size + 1; index < 55; ++index) {
      state->buffer[index] = 0;
    }
    state->buffer[55] = 0x01;  // BLAKE-256 length preamble bit
    for (size_t index = 0; index < 8; ++index) {
      state->buffer[56 + index] =
          static_cast<uint8_t>(message_bits >> (56 - 8 * index));
    }
    // A padding-only block uses a zero message-bit counter.
    state->counter = state->buffer_size == 0 ? 0 : message_bits;
    compress(state, state->buffer);
  } else {
    state->buffer[state->buffer_size] = 0x80;
    for (size_t index = state->buffer_size + 1; index < 64; ++index) {
      state->buffer[index] = 0;
    }
    state->counter = message_bits;
    compress(state, state->buffer);
    memset(state->buffer, 0, sizeof(state->buffer));
    state->buffer[55] = 0x01;
    for (size_t index = 0; index < 8; ++index) {
      state->buffer[56 + index] =
          static_cast<uint8_t>(message_bits >> (56 - 8 * index));
    }
    state->counter = 0;
    compress(state, state->buffer);
  }
  for (size_t index = 0; index < 8; ++index) {
    out[4 * index] = static_cast<uint8_t>(state->h[index] >> 24);
    out[4 * index + 1] = static_cast<uint8_t>(state->h[index] >> 16);
    out[4 * index + 2] = static_cast<uint8_t>(state->h[index] >> 8);
    out[4 * index + 3] = static_cast<uint8_t>(state->h[index]);
  }
  secure_zero(state, sizeof(*state));
  return true;
}

bool blake256_hash(const uint8_t *data, size_t size, uint8_t out[32]) {
  if (out == nullptr || (data == nullptr && size != 0)) return false;
  Blake256State state;
  blake256_init(&state);
  blake256_update(&state, data, size);
  return blake256_final(&state, out);
}

bool run_blake256_self_tests() {
  // Decred dcrd crypto/blake256 hasher256_test.go vectors. The multi-byte
  // cases deliberately write both LE and BE forms, matching the Go test.
  static const uint8_t kAbc[3] = {'a', 'b', 'c'};
  static const uint8_t kAbcHash[32] = {
      0x18, 0x33, 0xa9, 0xfa, 0x7c, 0xf4, 0x08, 0x6b, 0xd5, 0xfd, 0xa7,
      0x3d, 0xa3, 0x2e, 0x5a, 0x1d, 0x75, 0xb4, 0xc3, 0xf8, 0x9d, 0x5c,
      0x43, 0x63, 0x69, 0xf9, 0xd7, 0x8b, 0xb2, 0xda, 0x5c, 0x28};
  static const uint8_t kByte[1] = {0x0a};
  static const uint8_t kByteHash[32] = {
      0xe8, 0x1d, 0xb4, 0xf0, 0xd7, 0x6e, 0x02, 0x80, 0x51, 0x55, 0x44,
      0x1f, 0x50, 0xc8, 0x61, 0xa8, 0xf8, 0x63, 0x74, 0xf3, 0xae, 0x34,
      0xc7, 0xa3, 0xff, 0x41, 0x11, 0xd3, 0xa6, 0x34, 0xec, 0xb1};
  static const uint8_t kBytes[6] = {0x01, 0x02, 0x03, 0x01, 0x02, 0x03};
  static const uint8_t kBytesHash[32] = {
      0x6d, 0x65, 0xd2, 0x19, 0xf8, 0x2e, 0x93, 0xa3, 0xfe, 0x00, 0x8f,
      0x4e, 0x26, 0xe6, 0x45, 0x0f, 0xdc, 0x97, 0x67, 0x3f, 0x09, 0x07,
      0xb9, 0xf8, 0xbc, 0x98, 0x9e, 0xd1, 0x95, 0x39, 0x70, 0x2f};
  static const uint8_t kU64[16] = {
      0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  static const uint8_t kU64Hash[32] = {
      0x9b, 0x20, 0xfc, 0xbc, 0x30, 0xb6, 0x3a, 0xe0, 0xce, 0x02, 0xac,
      0xef, 0xea, 0x70, 0x98, 0xa8, 0x0b, 0xbd, 0x81, 0x2e, 0x50, 0x20,
      0x84, 0x4e, 0x25, 0x11, 0xc0, 0x8e, 0x54, 0x41, 0x42, 0x7a};
  uint8_t digest[32] = {};
  bool ok = blake256_hash(kAbc, sizeof(kAbc), digest) &&
            memcmp(digest, kAbcHash, 32) == 0;
  ok = ok && blake256_hash(kByte, sizeof(kByte), digest) &&
       memcmp(digest, kByteHash, 32) == 0;
  ok = ok && blake256_hash(kBytes, sizeof(kBytes), digest) &&
       memcmp(digest, kBytesHash, 32) == 0;
  ok = ok && blake256_hash(kU64, sizeof(kU64), digest) &&
       memcmp(digest, kU64Hash, 32) == 0;
  secure_zero(digest, sizeof(digest));
  return ok;
}

}  // namespace hexwallet
