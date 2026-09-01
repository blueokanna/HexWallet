#include "CryptoExtended.h"

#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {
static bool selftest_report(const char *name, bool ok) {
  if (!ok) ::printf("FAIL: %s\n", name);
  return ok;
}

// ===========================================================================
// SHA3-256 (FIPS 202) — Keccak-f[1600] with the 0x06 domain byte.
// ===========================================================================

constexpr size_t kSha3RateBytes = 136;
constexpr size_t kSha3RoundCount = 24;
constexpr uint8_t kSha3DomainSuffix = 0x06;
constexpr uint8_t kSha3FinalBit = 0x80;

constexpr uint64_t kSha3RoundConstants[kSha3RoundCount] = {
  UINT64_C(0x0000000000000001),
  UINT64_C(0x0000000000008082),
  UINT64_C(0x800000000000808a),
  UINT64_C(0x8000000080008000),
  UINT64_C(0x000000000000808b),
  UINT64_C(0x0000000080000001),
  UINT64_C(0x8000000080008081),
  UINT64_C(0x8000000000008009),
  UINT64_C(0x000000000000008a),
  UINT64_C(0x0000000000000088),
  UINT64_C(0x0000000080008009),
  UINT64_C(0x000000008000000a),
  UINT64_C(0x000000008000808b),
  UINT64_C(0x800000000000008b),
  UINT64_C(0x8000000000008089),
  UINT64_C(0x8000000000008003),
  UINT64_C(0x8000000000008002),
  UINT64_C(0x8000000000000080),
  UINT64_C(0x000000000000800a),
  UINT64_C(0x800000008000000a),
  UINT64_C(0x8000000080008081),
  UINT64_C(0x8000000000008080),
  UINT64_C(0x0000000080000001),
  UINT64_C(0x8000000080008008),
};

constexpr uint8_t kSha3Rotation[5][5] = {
  { 0, 36, 3, 41, 18 },
  { 1, 44, 10, 45, 2 },
  { 62, 6, 43, 15, 61 },
  { 28, 55, 25, 21, 56 },
  { 27, 20, 39, 8, 14 },
};

uint64_t rotate_left64(uint64_t value, uint8_t shift) {
  return shift == 0 ? value : (value << shift) | (value >> (64U - shift));
}

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

void store_be64_into(uint8_t *out, uint64_t value) {
  for (uint8_t index = 0; index < 8; ++index) {
    out[index] = static_cast<uint8_t>(value >> (56U - index * 8U));
  }
}

void keccakf1600(uint64_t state[25]) {
  for (size_t round = 0; round < kSha3RoundCount; ++round) {
    uint64_t column[5];
    uint64_t delta[5];
    uint64_t moved[25];

    for (uint8_t x = 0; x < 5; ++x) {
      column[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (uint8_t x = 0; x < 5; ++x) {
      delta[x] = column[(x + 4) % 5] ^ rotate_left64(column[(x + 1) % 5], 1);
    }
    for (uint8_t y = 0; y < 5; ++y) {
      for (uint8_t x = 0; x < 5; ++x) {
        state[x + 5 * y] ^= delta[x];
      }
    }

    for (uint8_t y = 0; y < 5; ++y) {
      for (uint8_t x = 0; x < 5; ++x) {
        moved[y + 5 * ((2 * x + 3 * y) % 5)] =
          rotate_left64(state[x + 5 * y], kSha3Rotation[x][y]);
      }
    }

    for (uint8_t y = 0; y < 5; ++y) {
      for (uint8_t x = 0; x < 5; ++x) {
        state[x + 5 * y] = moved[x + 5 * y] ^ ((~moved[(x + 1) % 5 + 5 * y]) & moved[(x + 2) % 5 + 5 * y]);
      }
    }

    state[0] ^= kSha3RoundConstants[round];
  }
}

bool sha3_256_one_shot(const uint8_t *data, size_t size, uint8_t out[32]) {
  uint64_t state[25] = { 0 };
  uint8_t buffer[kSha3RateBytes] = { 0 };
  size_t position = 0;
  bool ok = true;

  for (size_t index = 0; index < size; ++index) {
    buffer[position++] ^= data[index];
    if (position == kSha3RateBytes) {
      for (size_t lane = 0; lane < kSha3RateBytes / 8; ++lane) {
        state[lane] ^= load_le64(buffer + lane * 8);
      }
      keccakf1600(state);
      position = 0;
    }
  }
  buffer[position] ^= kSha3DomainSuffix;
  buffer[kSha3RateBytes - 1] ^= kSha3FinalBit;
  for (size_t lane = 0; lane < kSha3RateBytes / 8; ++lane) {
    state[lane] ^= load_le64(buffer + lane * 8);
  }
  keccakf1600(state);

  for (size_t index = 0; index < 32; ++index) {
    out[index] = static_cast<uint8_t>(state[index / 8] >> (8U * (index % 8)));
  }
  secure_zero(state, sizeof(state));
  secure_zero(buffer, sizeof(buffer));
  return ok;
}

// ===========================================================================
// SHA-512/256 (FIPS 180-4) — SHA-512 compression with the 512/256 IV.
// ===========================================================================

constexpr uint64_t kSha512K[80] = {
  UINT64_C(0x428a2f98d728ae22),
  UINT64_C(0x7137449123ef65cd),
  UINT64_C(0xb5c0fbcfec4d3b2f),
  UINT64_C(0xe9b5dba58189dbbc),
  UINT64_C(0x3956c25bf348b538),
  UINT64_C(0x59f111f1b605d019),
  UINT64_C(0x923f82a4af194f9b),
  UINT64_C(0xab1c5ed5da6d8118),
  UINT64_C(0xd807aa98a3030242),
  UINT64_C(0x12835b0145706fbe),
  UINT64_C(0x243185be4ee4b28c),
  UINT64_C(0x550c7dc3d5ffb4e2),
  UINT64_C(0x72be5d74f27b896f),
  UINT64_C(0x80deb1fe3b1696b1),
  UINT64_C(0x9bdc06a725c71235),
  UINT64_C(0xc19bf174cf692694),
  UINT64_C(0xe49b69c19ef14ad2),
  UINT64_C(0xefbe4786384f25e3),
  UINT64_C(0x0fc19dc68b8cd5b5),
  UINT64_C(0x240ca1cc77ac9c65),
  UINT64_C(0x2de92c6f592b0275),
  UINT64_C(0x4a7484aa6ea6e483),
  UINT64_C(0x5cb0a9dcbd41fbd4),
  UINT64_C(0x76f988da831153b5),
  UINT64_C(0x983e5152ee66dfab),
  UINT64_C(0xa831c66d2db43210),
  UINT64_C(0xb00327c898fb213f),
  UINT64_C(0xbf597fc7beef0ee4),
  UINT64_C(0xc6e00bf33da88fc2),
  UINT64_C(0xd5a79147930aa725),
  UINT64_C(0x06ca6351e003826f),
  UINT64_C(0x142929670a0e6e70),
  UINT64_C(0x27b70a8546d22ffc),
  UINT64_C(0x2e1b21385c26c926),
  UINT64_C(0x4d2c6dfc5ac42aed),
  UINT64_C(0x53380d139d95b3df),
  UINT64_C(0x650a73548baf63de),
  UINT64_C(0x766a0abb3c77b2a8),
  UINT64_C(0x81c2c92e47edaee6),
  UINT64_C(0x92722c851482353b),
  UINT64_C(0xa2bfe8a14cf10364),
  UINT64_C(0xa81a664bbc423001),
  UINT64_C(0xc24b8b70d0f89791),
  UINT64_C(0xc76c51a30654be30),
  UINT64_C(0xd192e819d6ef5218),
  UINT64_C(0xd69906245565a910),
  UINT64_C(0xf40e35855771202a),
  UINT64_C(0x106aa07032bbd1b8),
  UINT64_C(0x19a4c116b8d2d0c8),
  UINT64_C(0x1e376c085141ab53),
  UINT64_C(0x2748774cdf8eeb99),
  UINT64_C(0x34b0bcb5e19b48a8),
  UINT64_C(0x391c0cb3c5c95a63),
  UINT64_C(0x4ed8aa4ae3418acb),
  UINT64_C(0x5b9cca4f7763e373),
  UINT64_C(0x682e6ff3d6b2b8a3),
  UINT64_C(0x748f82ee5defb2fc),
  UINT64_C(0x78a5636f43172f60),
  UINT64_C(0x84c87814a1f0ab72),
  UINT64_C(0x8cc702081a6439ec),
  UINT64_C(0x90befffa23631e28),
  UINT64_C(0xa4506cebde82bde9),
  UINT64_C(0xbef9a3f7b2c67915),
  UINT64_C(0xc67178f2e372532b),
  UINT64_C(0xca273eceea26619c),
  UINT64_C(0xd186b8c721c0c207),
  UINT64_C(0xeada7dd6cde0eb1e),
  UINT64_C(0xf57d4f7fee6ed178),
  UINT64_C(0x06f067aa72176fba),
  UINT64_C(0x0a637dc5a2c898a6),
  UINT64_C(0x113f9804bef90dae),
  UINT64_C(0x1b710b35131c471b),
  UINT64_C(0x28db77f523047d84),
  UINT64_C(0x32caab7b40c72493),
  UINT64_C(0x3c9ebe0a15c9bebc),
  UINT64_C(0x431d67c49c100d4c),
  UINT64_C(0x4cc5d4becb3e42b6),
  UINT64_C(0x597f299cfc657e2a),
  UINT64_C(0x5fcb6fab3ad6faec),
  UINT64_C(0x6c44198c4a475817),
};

uint64_t rotate_right64(uint64_t value, uint8_t shift) {
  return shift == 0 ? value : (value >> shift) | (value << (64U - shift));
}

uint64_t load_be64(const uint8_t *data) {
  uint64_t value = 0;
  for (uint8_t index = 0; index < 8; ++index) {
    value = (value << 8) | data[index];
  }
  return value;
}

void sha512_compress(uint64_t state[8], const uint8_t block[128]) {
  uint64_t w[80];
  for (uint8_t word = 0; word < 16; ++word) {
    w[word] = load_be64(block + word * 8);
  }
  for (uint8_t word = 16; word < 80; ++word) {
    const uint64_t s0 = rotate_right64(w[word - 15], 1) ^ rotate_right64(w[word - 15], 8) ^ (w[word - 15] >> 7);
    const uint64_t s1 = rotate_right64(w[word - 2], 19) ^ rotate_right64(w[word - 2], 61) ^ (w[word - 2] >> 6);
    w[word] = w[word - 16] + s0 + w[word - 7] + s1;
  }
  uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint64_t e = state[4], f = state[5], g = state[6], h = state[7];
  for (uint8_t word = 0; word < 80; ++word) {
    const uint64_t s1 = rotate_right64(e, 14) ^ rotate_right64(e, 18) ^ rotate_right64(e, 41);
    const uint64_t ch = (e & f) ^ ((~e) & g);
    const uint64_t t1 = h + s1 + ch + kSha512K[word] + w[word];
    const uint64_t s0 = rotate_right64(a, 28) ^ rotate_right64(a, 34) ^ rotate_right64(a, 39);
    const uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
    const uint64_t t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
  secure_zero(w, sizeof(w));
}

void sha512_256_one_shot(const uint8_t *data, size_t size, uint8_t out[32]) {
  // FIPS 180-4 §5.3.6.1 SHA-512/256 initial hash values.
  uint64_t state[8] = {
    UINT64_C(0x22312194fc2bf72c),
    UINT64_C(0x9f555fa3c84c64c2),
    UINT64_C(0x2393b86b6f53b151),
    UINT64_C(0x963877195940eabd),
    UINT64_C(0x96283ee2a88effe3),
    UINT64_C(0xbe5e1e2553863992),
    UINT64_C(0x2b0199fc2c85b8aa),
    UINT64_C(0x0eb72ddc81c52ca2),
  };
  uint64_t total_bits = static_cast<uint64_t>(size) * 8U;
  uint8_t block[128] = { 0 };
  size_t block_used = 0;

  while (size >= 128 - block_used) {
    const size_t take = 128 - block_used;
    memcpy(block + block_used, data, take);
    sha512_compress(state, block);
    data += take;
    size -= take;
    block_used = 0;
  }
  if (size != 0) {
    memcpy(block + block_used, data, size);
    block_used += size;
  }
  block[block_used++] = 0x80;
  if (block_used > 112) {
    memset(block + block_used, 0, 128 - block_used);
    sha512_compress(state, block);
    block_used = 0;
  }
  memset(block + block_used, 0, 112 - block_used);
  store_be64_into(block + 120, total_bits);
  sha512_compress(state, block);

  for (uint8_t index = 0; index < 32; ++index) {
    out[index] = static_cast<uint8_t>(state[index / 8] >> (56U - 8U * (index % 8)));
  }
  secure_zero(state, sizeof(state));
  secure_zero(block, sizeof(block));
}

}  // namespace

// Public one-shot hashes -----------------------------------------------------

bool crypto_sha3_256(const uint8_t *data, size_t size, uint8_t out[32]) {
  if (out == nullptr || (data == nullptr && size != 0))
    return false;
  sha3_256_one_shot(data, size, out);
  return true;
}

bool crypto_sha512_256(const uint8_t *data, size_t size, uint8_t out[32]) {
  if (out == nullptr || (data == nullptr && size != 0))
    return false;
  sha512_256_one_shot(data, size, out);
  return true;
}

bool crypto_blake2b(const uint8_t *data, size_t size, uint8_t *out,
                    size_t out_size) {
  if (out == nullptr || out_size == 0 || out_size > 64 || (data == nullptr && size != 0)) {
    return false;
  }
  static const uint64_t kIv[8] = {
    UINT64_C(0x6a09e667f3bcc908),
    UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b),
    UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1),
    UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b),
    UINT64_C(0x5be0cd19137e2179),
  };
  static const uint8_t kSigma[12][16] = {
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

  uint64_t h[8];
  memcpy(h, kIv, sizeof(h));
  h[0] ^= UINT64_C(0x01010000) ^ static_cast<uint64_t>(out_size);

  constexpr size_t kBlockSize = 128;
  uint64_t t0 = 0;
  uint64_t t1 = 0;
  uint8_t block[kBlockSize] = { 0 };

  size_t remaining = size;
  const uint8_t *cursor = data;
  while (remaining >= kBlockSize) {
    memcpy(block, cursor, kBlockSize);
    t0 += kBlockSize;
    if (t0 < kBlockSize)
      t1 += 1;
    uint64_t m[16];
    for (size_t index = 0; index < 16; ++index) {
      m[index] = load_le64(block + index * 8);
    }
    uint64_t v[16];
    memcpy(v, h, sizeof(h));
    memcpy(v + 8, kIv, sizeof(kIv));
    v[12] ^= t0;
    v[13] ^= t1;
    for (size_t round = 0; round < 12; ++round) {
      const uint8_t *s = kSigma[round];
#define BLAKE2B_G(a, b, c, d, x, y) \
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
      BLAKE2B_G(0, 4, 8, 12, m[s[0]], m[s[1]]);
      BLAKE2B_G(1, 5, 9, 13, m[s[2]], m[s[3]]);
      BLAKE2B_G(2, 6, 10, 14, m[s[4]], m[s[5]]);
      BLAKE2B_G(3, 7, 11, 15, m[s[6]], m[s[7]]);
      BLAKE2B_G(0, 5, 10, 15, m[s[8]], m[s[9]]);
      BLAKE2B_G(1, 6, 11, 12, m[s[10]], m[s[11]]);
      BLAKE2B_G(2, 7, 8, 13, m[s[12]], m[s[13]]);
      BLAKE2B_G(3, 4, 9, 14, m[s[14]], m[s[15]]);
#undef BLAKE2B_G
    }
    for (size_t index = 0; index < 8; ++index) {
      h[index] ^= v[index] ^ v[index + 8];
    }
    cursor += kBlockSize;
    remaining -= kBlockSize;
  }

  // final block (possibly empty)
  memset(block, 0, sizeof(block));
  if (remaining != 0)
    memcpy(block, cursor, remaining);
  t0 += remaining;
  // RFC 7693: last-block flag lives in f0 (v[14] ^= all-ones), the
  // message block itself is zero-padded (no 0x80 marker byte).
  uint64_t m[16];
  for (size_t index = 0; index < 16; ++index) {
    m[index] = load_le64(block + index * 8);
  }
  uint64_t v[16];
  memcpy(v, h, sizeof(h));
  memcpy(v + 8, kIv, sizeof(kIv));
  v[12] ^= t0;
  v[13] ^= t1;
  v[14] ^= UINT64_MAX;  // f0: last block
  for (size_t round = 0; round < 12; ++round) {
    const uint8_t *s = kSigma[round];
#define BLAKE2B_G2(a, b, c, d, x, y) \
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
    BLAKE2B_G2(0, 4, 8, 12, m[s[0]], m[s[1]]);
    BLAKE2B_G2(1, 5, 9, 13, m[s[2]], m[s[3]]);
    BLAKE2B_G2(2, 6, 10, 14, m[s[4]], m[s[5]]);
    BLAKE2B_G2(3, 7, 11, 15, m[s[6]], m[s[7]]);
    BLAKE2B_G2(0, 5, 10, 15, m[s[8]], m[s[9]]);
    BLAKE2B_G2(1, 6, 11, 12, m[s[10]], m[s[11]]);
    BLAKE2B_G2(2, 7, 8, 13, m[s[12]], m[s[13]]);
    BLAKE2B_G2(3, 4, 9, 14, m[s[14]], m[s[15]]);
#undef BLAKE2B_G2
  }
  for (size_t index = 0; index < 8; ++index) {
    h[index] ^= v[index] ^ v[index + 8];
  }

  for (size_t index = 0; index < out_size; ++index) {
    out[index] = static_cast<uint8_t>(h[index / 8] >> (8U * (index % 8)));
  }
  secure_zero(h, sizeof(h));
  secure_zero(block, sizeof(block));
  return true;
}

// Base encodings -------------------------------------------------------------

bool base32_encode(const uint8_t *data, size_t size, char *out, size_t out_size,
                   bool lowercase, bool pad) {
  static const char kUpper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  static const char kLower[] = "abcdefghijklmnopqrstuvwxyz234567";
  const char *alphabet = lowercase ? kLower : kUpper;
  const size_t output_size = ((size + 4) / 5) * 8;
  const size_t needed = pad ? output_size : output_size - ((5 - size % 5) % 5);
  if (out == nullptr || out_size < needed + 1)
    return false;

  size_t written = 0;
  size_t index = 0;
  while (index + 5 <= size) {
    uint64_t value = 0;
    for (size_t offset = 0; offset < 5; ++offset) {
      value = (value << 8) | data[index + offset];
    }
    for (int bit = 7; bit >= 0; --bit) {
      out[written++] = alphabet[(value >> (bit * 5)) & 0x1f];
    }
    index += 5;
  }
  const size_t remaining = size - index;
  if (remaining != 0) {
    uint64_t value = 0;
    for (size_t offset = 0; offset < remaining; ++offset) {
      value = (value << 8) | data[index + offset];
    }
    value <<= (5 - remaining) * 8;
    // Emit only the 5-bit groups that contain real data; trailing
    // all-zero groups are represented by '=' padding below. A group at
    // position `bit` spans bits [5*bit, 5*bit+4]; the data occupies
    // bits [40-8*remaining, 39].
    for (int bit = 7; bit >= 0; --bit) {
      if (static_cast<size_t>(bit) * 5U + 4U + remaining * 8U >= 40U) {
        out[written++] = alphabet[(value >> (bit * 5)) & 0x1f];
      }
    }
  }
  if (pad) {
    while (written < output_size)
      out[written++] = '=';
  }
  out[written] = '\0';
  return true;
}

bool qubic_base26_encode(const uint8_t *digest, size_t digest_size, char *out,
                         size_t out_size) {
  static const char kAlphabet[] = "123456789abcdefghijkmnopqrstuvwxyz";
  if (digest == nullptr || out == nullptr || digest_size == 0)
    return false;
  uint8_t buffer[64];
  if (digest_size > sizeof(buffer))
    return false;
  memcpy(buffer, digest, digest_size);
  // Max base26 length for 32 bytes is 55; use 60 as the spec ceiling.
  char reversed[60];
  size_t length = 0;
  bool any = true;
  while (any && length < sizeof(reversed)) {
    uint16_t remainder = 0;
    any = false;
    for (size_t index = 0; index < digest_size; ++index) {
      const uint16_t current =
        static_cast<uint16_t>((remainder << 8) | buffer[index]);
      buffer[index] = static_cast<uint8_t>(current / 26);
      remainder = static_cast<uint16_t>(current % 26);
      if (buffer[index] != 0)
        any = true;
    }
    reversed[length++] = kAlphabet[remainder];
  }
  if (length == 0)
    reversed[length++] = kAlphabet[0];
  if (out_size < length + 1) {
    secure_zero(buffer, sizeof(buffer));
    return false;
  }
  for (size_t index = 0; index < length; ++index) {
    out[index] = reversed[length - 1 - index];
  }
  out[length] = '\0';
  secure_zero(buffer, sizeof(buffer));
  secure_zero(reversed, sizeof(reversed));
  return true;
}

namespace {

constexpr char kBase32Charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

uint8_t size_bits_for(size_t payload_size) {
  switch (payload_size) {
    case 20:
      return 0;
    case 24:
      return 1;
    case 28:
      return 2;
    case 32:
      return 3;
    case 40:
      return 4;
    case 48:
      return 5;
    case 56:
      return 6;
    case 64:
      return 7;
    default:
      return 0;
  }
}

// Convert 8-bit bytes to 5-bit groups (big-endian bit stream), optionally
// padding the final group with zeros.
size_t convert_8to5(const uint8_t *data, size_t size, uint8_t *out) {
  size_t written = 0;
  uint32_t accumulator = 0;
  uint32_t bits = 0;
  for (size_t index = 0; index < size; ++index) {
    accumulator = (accumulator << 8) | data[index];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out[written++] = static_cast<uint8_t>((accumulator >> bits) & 0x1f);
    }
  }
  if (bits != 0) {
    out[written++] = static_cast<uint8_t>((accumulator << (5 - bits)) & 0x1f);
  }
  return written;
}

uint64_t cashaddr_polymod(const uint8_t *values, size_t size) {
  static const uint64_t kGenerators[5] = {
    UINT64_C(0x98f2bc8e61),
    UINT64_C(0x79b76d99e2),
    UINT64_C(0xf33e5fb3c4),
    UINT64_C(0xae2eabe2a8),
    UINT64_C(0x1e4f43e470),
  };
  uint64_t checksum = 1;
  for (size_t index = 0; index < size; ++index) {
    const uint8_t top = static_cast<uint8_t>(checksum >> 35);
    checksum = ((checksum & UINT64_C(0x07ffffffff)) << 5) ^ values[index];
    for (uint8_t bit = 0; bit < 5; ++bit) {
      if ((top >> bit) & 1)
        checksum ^= kGenerators[bit];
    }
  }
  return checksum ^ 1;
}

}  // namespace

bool cashaddr_encode(const char *prefix, uint8_t type_bits,
                     const uint8_t *payload, size_t payload_size, char *out,
                     size_t out_size) {
  if (prefix == nullptr || payload == nullptr || out == nullptr)
    return false;
  const size_t prefix_size = strlen(prefix);
  uint8_t data[256];
  const size_t payload5_size = convert_8to5(payload, payload_size, data);
  // prefix(5-bit) || 0 || payload5 || checksum(8 groups)
  const size_t total = prefix_size + 1 + payload5_size + 8;
  if (payload5_size > 200 || out_size < total + prefix_size + 1 + 1) {
    return false;
  }
  // Build the polymod input: prefix lower 5 bits, separator 0, version
  // byte, payload, 8 zeros. The version byte MUST be part of the checksum
  // input per the CashAddr spec.
  uint8_t poly_input[512];
  size_t poly_size = 0;
  for (size_t index = 0; index < prefix_size; ++index) {
    poly_input[poly_size++] = static_cast<uint8_t>(prefix[index] & 0x1f);
  }
  poly_input[poly_size++] = 0;
  poly_input[poly_size++] =
    static_cast<uint8_t>(type_bits | size_bits_for(payload_size));
  memcpy(poly_input + poly_size, data, payload5_size);
  poly_size += payload5_size;
  memset(poly_input + poly_size, 0, 8);
  poly_size += 8;
  const uint64_t polymod = cashaddr_polymod(poly_input, poly_size);
  uint8_t checksum[8];
  for (uint8_t index = 0; index < 8; ++index) {
    checksum[index] =
      static_cast<uint8_t>((polymod >> (5 * (7 - index))) & 0x1f);
  }

  size_t written = 0;
  for (size_t index = 0; index < prefix_size; ++index) {
    out[written++] = prefix[index];
  }
  out[written++] = ':';
  // version byte: type_bits (already includes the <<3 shift) | size bits.
  out[written++] = kBase32Charset[type_bits | size_bits_for(payload_size)];
  for (size_t index = 0; index < payload5_size; ++index) {
    out[written++] = kBase32Charset[data[index]];
  }
  for (uint8_t index = 0; index < 8; ++index) {
    out[written++] = kBase32Charset[checksum[index]];
  }
  out[written] = '\0';
  return true;
}

bool bech32_encode(const char *hrp, const uint8_t *payload, size_t payload_size,
                   char *out, size_t out_size, bool bech32m) {
  static const uint32_t kGenerators[5] = {
    0x3b6a57b2,
    0x26508e6d,
    0x1ea119fa,
    0x3d4233dd,
    0x2a1462b3,
  };
  if (hrp == nullptr || payload == nullptr || out == nullptr)
    return false;
  const size_t hrp_size = strlen(hrp);
  uint8_t data[256];
  const size_t data_size = convert_8to5(payload, payload_size, data);
  if (hrp_size == 0 || hrp_size > 83 || data_size > 200 || out_size < hrp_size + 1 + data_size + 6 + 1) {
    return false;
  }
  // BIP-173 polymod over: hrp>>5 groups, 0, hrp&31 groups, data, six zeroes.
  uint32_t checksum = 1;
  auto step = [&](uint32_t value) {
    const uint8_t top = static_cast<uint8_t>(checksum >> 25);
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (uint8_t bit = 0; bit < 5; ++bit) {
      if ((top >> bit) & 1)
        checksum ^= kGenerators[bit];
    }
  };
  for (size_t index = 0; index < hrp_size; ++index) {
    step(static_cast<uint32_t>(hrp[index]) >> 5);
  }
  step(0);
  for (size_t index = 0; index < hrp_size; ++index) {
    step(static_cast<uint32_t>(hrp[index]) & 0x1f);
  }
  for (size_t index = 0; index < data_size; ++index)
    step(data[index]);
  for (uint8_t index = 0; index < 6; ++index)
    step(0);
  checksum ^= bech32m ? 0x2bc830a3U : 1U;

  size_t written = 0;
  for (size_t index = 0; index < hrp_size; ++index) {
    out[written++] = hrp[index];
  }
  out[written++] = '1';
  for (size_t index = 0; index < data_size; ++index) {
    out[written++] = kBase32Charset[data[index]];
  }
  for (uint8_t index = 0; index < 6; ++index) {
    out[written++] =
      kBase32Charset[static_cast<uint8_t>((checksum >> (5 * (5 - index))) & 0x1f)];
  }
  out[written] = '\0';
  return true;
}

bool kaspa_bech32_encode(const char *hrp, uint8_t version,
                         const uint8_t *payload, size_t payload_size, char *out,
                         size_t out_size) {
  if (hrp == nullptr || payload == nullptr || out == nullptr)
    return false;
  const size_t hrp_size = strlen(hrp);
  uint8_t versioned[64];
  versioned[0] = version;
  if (payload_size + 1 > sizeof(versioned))
    return false;
  memcpy(versioned + 1, payload, payload_size);
  uint8_t data[256];
  const size_t data_size = convert_8to5(versioned, payload_size + 1, data);
  if (hrp_size == 0 || out_size < hrp_size + 1 + data_size + 8 + 1) {
    return false;
  }
  uint8_t poly_input[512];
  size_t poly_size = 0;
  for (size_t index = 0; index < hrp_size; ++index) {
    poly_input[poly_size++] = static_cast<uint8_t>(hrp[index] & 0x1f);
  }
  poly_input[poly_size++] = 0;
  memcpy(poly_input + poly_size, data, data_size);
  poly_size += data_size;
  memset(poly_input + poly_size, 0, 8);
  poly_size += 8;
  const uint64_t polymod = cashaddr_polymod(poly_input, poly_size);
  uint8_t checksum[8];
  for (uint8_t index = 0; index < 8; ++index) {
    checksum[index] =
      static_cast<uint8_t>((polymod >> (8 * (7 - index))) & 0xff);
  }
  // Only the last 5 bytes of the 8-byte checksum are used, converted 8->5.
  uint8_t checksum5[8];
  const size_t checksum5_size = convert_8to5(checksum + 3, 5, checksum5);

  size_t written = 0;
  for (size_t index = 0; index < hrp_size; ++index) {
    out[written++] = hrp[index];
  }
  out[written++] = ':';
  for (size_t index = 0; index < data_size; ++index) {
    out[written++] = kBase32Charset[data[index]];
  }
  for (size_t index = 0; index < checksum5_size; ++index) {
    out[written++] = kBase32Charset[checksum5[index]];
  }
  out[written] = '\0';
  secure_zero(versioned, sizeof(versioned));
  return true;
}

bool run_crypto_extended_self_tests() {
  // FIPS 202 SHA3-256 vectors.
  static const uint8_t kSha3Empty[kSha3RateBytes] = { 0 };
  (void)kSha3Empty;
  uint8_t digest[32];
  static const uint8_t kSha3EmptyExpected[32] = {
    0xa7,
    0xff,
    0xc6,
    0xf8,
    0xbf,
    0x1e,
    0xd7,
    0x66,
    0x51,
    0xc1,
    0x47,
    0x56,
    0xa0,
    0x61,
    0xd6,
    0x62,
    0xf5,
    0x80,
    0xff,
    0x4d,
    0xe4,
    0x3b,
    0x49,
    0xfa,
    0x82,
    0xd8,
    0x0a,
    0x4b,
    0x80,
    0xf8,
    0x43,
    0x4a,
  };
  static const uint8_t kSha3AbcExpected[32] = {
    0x3a,
    0x98,
    0x5d,
    0xa7,
    0x4f,
    0xe2,
    0x25,
    0xb2,
    0x04,
    0x5c,
    0x17,
    0x2d,
    0x6b,
    0xd3,
    0x90,
    0xbd,
    0x85,
    0x5f,
    0x08,
    0x6e,
    0x3e,
    0x9d,
    0x52,
    0x5b,
    0x46,
    0xbf,
    0xe2,
    0x45,
    0x11,
    0x43,
    0x15,
    0x32,
  };
  static const uint8_t kAbc[] = { 'a', 'b', 'c' };
  bool passed = selftest_report("sha3 empty", crypto_sha3_256(nullptr, 0, digest) && crypto_constant_time_equal(digest, kSha3EmptyExpected, 32));
  passed = selftest_report("sha3 abc", crypto_sha3_256(kAbc, sizeof(kAbc), digest) && crypto_constant_time_equal(digest, kSha3AbcExpected, 32)) && passed;

  // FIPS 180-4 SHA-512/256 vectors.
  static const uint8_t kSha512256Empty[32] = {
    0xc6,
    0x72,
    0xb8,
    0xd1,
    0xef,
    0x56,
    0xed,
    0x28,
    0xab,
    0x87,
    0xc3,
    0x62,
    0x2c,
    0x51,
    0x14,
    0x06,
    0x9b,
    0xdd,
    0x3a,
    0xd7,
    0xb8,
    0xf9,
    0x73,
    0x74,
    0x98,
    0xd0,
    0xc0,
    0x1e,
    0xce,
    0xf0,
    0x96,
    0x7a,
  };
  static const uint8_t kSha512256Abc[32] = {
    0x53,
    0x04,
    0x8e,
    0x26,
    0x81,
    0x94,
    0x1e,
    0xf9,
    0x9b,
    0x2e,
    0x29,
    0xb7,
    0x6b,
    0x4c,
    0x7d,
    0xab,
    0xe4,
    0xc2,
    0xd0,
    0xc6,
    0x34,
    0xfc,
    0x6d,
    0x46,
    0xe0,
    0xe2,
    0xf1,
    0x31,
    0x07,
    0xe7,
    0xaf,
    0x23,
  };
  passed = selftest_report("sha512/256 empty", crypto_sha512_256(nullptr, 0, digest) && crypto_constant_time_equal(digest, kSha512256Empty, 32)) && passed;
  passed = selftest_report("sha512/256 abc", crypto_sha512_256(kAbc, sizeof(kAbc), digest) && crypto_constant_time_equal(digest, kSha512256Abc, 32)) && passed;

  // RFC 7693 BLAKE2b-512("abc") and BLAKE2b-256("abc").
  static const uint8_t kBlake2b512Abc[64] = {
    0xba,
    0x80,
    0xa5,
    0x3f,
    0x98,
    0x1c,
    0x4d,
    0x0d,
    0x6a,
    0x27,
    0x97,
    0xb6,
    0x9f,
    0x12,
    0xf6,
    0xe9,
    0x4c,
    0x21,
    0x2f,
    0x14,
    0x68,
    0x5a,
    0xc4,
    0xb7,
    0x4b,
    0x12,
    0xbb,
    0x6f,
    0xdb,
    0xff,
    0xa2,
    0xd1,
    0x7d,
    0x87,
    0xc5,
    0x39,
    0x2a,
    0xab,
    0x79,
    0x2d,
    0xc2,
    0x52,
    0xd5,
    0xde,
    0x45,
    0x33,
    0xcc,
    0x95,
    0x18,
    0xd3,
    0x8a,
    0xa8,
    0xdb,
    0xf1,
    0x92,
    0x5a,
    0xb9,
    0x23,
    0x86,
    0xed,
    0xd4,
    0x00,
    0x99,
    0x23,
  };
  uint8_t blake64[64];
  passed = selftest_report("blake2b-512 abc", crypto_blake2b(kAbc, sizeof(kAbc), blake64, sizeof(blake64)) && crypto_constant_time_equal(blake64, kBlake2b512Abc, sizeof(blake64))) && passed;
  static const uint8_t kBlake2b256Abc[32] = {
    0xbd,
    0xdd,
    0x81,
    0x3c,
    0x63,
    0x42,
    0x39,
    0x72,
    0x31,
    0x71,
    0xef,
    0x3f,
    0xee,
    0x98,
    0x57,
    0x9b,
    0x94,
    0x96,
    0x4e,
    0x3b,
    0xb1,
    0xcb,
    0x3e,
    0x42,
    0x72,
    0x62,
    0xc8,
    0xc0,
    0x68,
    0xd5,
    0x23,
    0x19,
  };
  passed = selftest_report("blake2b-256 abc", crypto_blake2b(kAbc, sizeof(kAbc), digest, 32) && crypto_constant_time_equal(digest, kBlake2b256Abc, 32)) && passed;

  // RFC 4648 base32.
  char encoded[128];
  static const uint8_t kBase32Input[] = { 'f', 'o', 'o' };
  passed = selftest_report("base32 foo", base32_encode(kBase32Input, sizeof(kBase32Input), encoded, sizeof(encoded), false, true) && strcmp(encoded, "MZXW6===") == 0) && passed;

  // CashAddr (bitcoin-cash.info spec) official test vector: P2PKH of
  // 76a04053bda0a88bda5177b86a15c3b29f559873.
  static const uint8_t kCashPayload[20] = {
    0x76,
    0xa0,
    0x40,
    0x53,
    0xbd,
    0xa0,
    0xa8,
    0x8b,
    0xda,
    0x51,
    0x77,
    0xb8,
    0x6a,
    0x15,
    0xc3,
    0xb2,
    0x9f,
    0x55,
    0x98,
    0x73,
  };
  char cashaddr[128];
  passed = selftest_report("cashaddr", cashaddr_encode("bitcoincash", 0, kCashPayload, sizeof(kCashPayload), cashaddr, sizeof(cashaddr)) && strcmp(cashaddr, "bitcoincash:qw6syq5aa5z5ghkj3w7ux59wrk204txrnxjeq7f94") == 0) && passed;

  // bech32 with an in-band version byte (Avalanche-style whole-stream
  // 8->5 conversion, the format this encoder serves for CRO/SEI/AVAX).
  static const uint8_t kBech32Payload[20] = {
    0x75,
    0x1e,
    0x76,
    0xe8,
    0x19,
    0x91,
    0x96,
    0xd4,
    0x54,
    0x94,
    0x1c,
    0x45,
    0xd1,
    0xb3,
    0xa3,
    0x23,
    0xf1,
    0x43,
    0x3b,
    0xd6,
  };
  char bech32[128];
  static const uint8_t kBech32Versioned[sizeof(kBech32Payload) + 1] = { 0, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6 };
  passed = selftest_report("bech32", bech32_encode("bc", kBech32Versioned, sizeof(kBech32Versioned), bech32, sizeof(bech32), false) && strcmp(bech32, "bc1qp63uahgrxged4z5jswyt5dn5v3lzsem6c0qqhg8") == 0) && passed;

  // bech32m with an in-band version byte (same whole-stream conversion).
  static const uint8_t kBech32mPayload[32] = {
    0x79,
    0xbe,
    0x66,
    0x7e,
    0xf9,
    0xdc,
    0xbb,
    0xac,
    0x55,
    0xa0,
    0x62,
    0x95,
    0xce,
    0x87,
    0x0b,
    0x07,
    0x02,
    0x9b,
    0xfc,
    0xdb,
    0x2d,
    0xce,
    0x28,
    0xd9,
    0x59,
    0xf2,
    0x81,
    0x5b,
    0x16,
    0xf8,
    0x17,
    0x98,
  };
  char bech32m[256];
  static const uint8_t kBech32mVersioned[sizeof(kBech32mPayload) + 1] = { 1, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98 };
  passed = selftest_report("bech32m", bech32_encode("bc", kBech32mVersioned, sizeof(kBech32mVersioned), bech32m, sizeof(bech32m), true) && strcmp(bech32m, "bc1q9umuen7l8wthtz45p3ftn58pvrs9xlumvkuu2xet8egzkcklqtesq0reqa") == 0) && passed;

  // Kaspa bech32 (kaspa-addresses test vectors).
  uint8_t zeros[32] = { 0 };
  char kaspa[128];
  passed = selftest_report("kaspa zero", kaspa_bech32_encode("kaspa", 0, zeros, sizeof(zeros), kaspa, sizeof(kaspa)) && strcmp(kaspa, "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e") == 0) && passed;
  static const uint8_t kKaspaPayload[32] = {
    0x5f,
    0xff,
    0x3c,
    0x4d,
    0xa1,
    0x8f,
    0x45,
    0xad,
    0xcd,
    0xd4,
    0x99,
    0xe4,
    0x46,
    0x11,
    0xe9,
    0xff,
    0xf1,
    0x48,
    0xba,
    0x69,
    0xdb,
    0x3c,
    0x4e,
    0xa2,
    0xdd,
    0xd9,
    0x55,
    0xfc,
    0x46,
    0xa5,
    0x95,
    0x22,
  };
  passed = selftest_report("kaspa payload", kaspa_bech32_encode("kaspa", 0, kKaspaPayload, sizeof(kKaspaPayload), kaspa, sizeof(kaspa)) && strcmp(kaspa, "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj") == 0) && passed;

  // Qubic base26 of SHA3-256(32 zero bytes).
  uint8_t zero_hash[32];
  passed = passed && crypto_sha3_256(zeros, sizeof(zeros), zero_hash);
  char qubic[64];
  passed = selftest_report("qubic zero-hash", qubic_base26_encode(zero_hash, sizeof(zero_hash), qubic, sizeof(qubic)) && strcmp(qubic, "3mj9k21j99ekmh8bg8k96drkf6m7g84f1j6h833ok47ph13kefajkdb") == 0) && passed;

  // RFC 8032 Ed25519 test vectors 1 and 2.
  static const uint8_t kEdSeed1[32] = {
    0x9d,
    0x61,
    0xb1,
    0x9d,
    0xef,
    0xfd,
    0x5a,
    0x60,
    0xba,
    0x84,
    0x4a,
    0xf4,
    0x92,
    0xec,
    0x2c,
    0xc4,
    0x44,
    0x49,
    0xc5,
    0x69,
    0x7b,
    0x32,
    0x69,
    0x19,
    0x70,
    0x3b,
    0xac,
    0x03,
    0x1c,
    0xae,
    0x7f,
    0x60,
  };
  static const uint8_t kEdPk1[32] = {
    0xd7,
    0x5a,
    0x98,
    0x01,
    0x82,
    0xb1,
    0x0a,
    0xb7,
    0xd5,
    0x4b,
    0xfe,
    0xd3,
    0xc9,
    0x64,
    0x07,
    0x3a,
    0x0e,
    0xe1,
    0x72,
    0xf3,
    0xda,
    0xa6,
    0x23,
    0x25,
    0xaf,
    0x02,
    0x1a,
    0x68,
    0xf7,
    0x07,
    0x51,
    0x1a,
  };
  static const uint8_t kEdSig1[64] = {
    0xe5,
    0x56,
    0x43,
    0x00,
    0xc3,
    0x60,
    0xac,
    0x72,
    0x90,
    0x86,
    0xe2,
    0xcc,
    0x80,
    0x6e,
    0x82,
    0x8a,
    0x84,
    0x87,
    0x7f,
    0x1e,
    0xb8,
    0xe5,
    0xd9,
    0x74,
    0xd8,
    0x73,
    0xe0,
    0x65,
    0x22,
    0x49,
    0x01,
    0x55,
    0x5f,
    0xb8,
    0x82,
    0x15,
    0x90,
    0xa3,
    0x3b,
    0xac,
    0xc6,
    0x1e,
    0x39,
    0x70,
    0x1c,
    0xf9,
    0xb4,
    0x6b,
    0xd2,
    0x5b,
    0xf5,
    0xf0,
    0x59,
    0x5b,
    0xbe,
    0x24,
    0x65,
    0x51,
    0x41,
    0x43,
    0x8e,
    0x7a,
    0x10,
    0x0b,
  };
  uint8_t ed_pk[32];
  uint8_t ed_sig[64];
  passed = selftest_report("ed25519 TC1 pk", ed25519_public_key(kEdSeed1, ed_pk) && crypto_constant_time_equal(ed_pk, kEdPk1, 32)) && passed;
  passed = selftest_report("ed25519 TC1 sig", ed25519_sign(kEdSeed1, nullptr, 0, ed_sig) && crypto_constant_time_equal(ed_sig, kEdSig1, 64)) && passed;

  static const uint8_t kEdSeed2[32] = {
    0x4c,
    0xcd,
    0x08,
    0x9b,
    0x28,
    0xff,
    0x96,
    0xda,
    0x9d,
    0xb6,
    0xc3,
    0x46,
    0xec,
    0x11,
    0x4e,
    0x0f,
    0x5b,
    0x8a,
    0x31,
    0x9f,
    0x35,
    0xab,
    0xa6,
    0x24,
    0xda,
    0x8c,
    0xf6,
    0xed,
    0x4f,
    0xb8,
    0xa6,
    0xfb,
  };
  static const uint8_t kEdPk2[32] = {
    0x3d,
    0x40,
    0x17,
    0xc3,
    0xe8,
    0x43,
    0x89,
    0x5a,
    0x92,
    0xb7,
    0x0a,
    0xa7,
    0x4d,
    0x1b,
    0x7e,
    0xbc,
    0x9c,
    0x98,
    0x2c,
    0xcf,
    0x2e,
    0xc4,
    0x96,
    0x8c,
    0xc0,
    0xcd,
    0x55,
    0xf1,
    0x2a,
    0xf4,
    0x66,
    0x0c,
  };
  static const uint8_t kEdMsg2[1] = { 0x72 };
  static const uint8_t kEdSig2[64] = {
    0x92,
    0xa0,
    0x09,
    0xa9,
    0xf0,
    0xd4,
    0xca,
    0xb8,
    0x72,
    0x0e,
    0x82,
    0x0b,
    0x5f,
    0x64,
    0x25,
    0x40,
    0xa2,
    0xb2,
    0x7b,
    0x54,
    0x16,
    0x50,
    0x3f,
    0x8f,
    0xb3,
    0x76,
    0x22,
    0x23,
    0xeb,
    0xdb,
    0x69,
    0xda,
    0x08,
    0x5a,
    0xc1,
    0xe4,
    0x3e,
    0x15,
    0x99,
    0x6e,
    0x45,
    0x8f,
    0x36,
    0x13,
    0xd0,
    0xf1,
    0x1d,
    0x8c,
    0x38,
    0x7b,
    0x2e,
    0xae,
    0xb4,
    0x30,
    0x2a,
    0xee,
    0xb0,
    0x0d,
    0x29,
    0x16,
    0x12,
    0xbb,
    0x0c,
    0x00,
  };
  passed = selftest_report("ed25519 TC2 pk", ed25519_public_key(kEdSeed2, ed_pk) && crypto_constant_time_equal(ed_pk, kEdPk2, 32)) && passed;
  passed = selftest_report("ed25519 TC2 sig", ed25519_sign(kEdSeed2, kEdMsg2, sizeof(kEdMsg2), ed_sig) && crypto_constant_time_equal(ed_sig, kEdSig2, 64)) && passed;
  secure_zero(ed_pk, sizeof(ed_pk));
  secure_zero(ed_sig, sizeof(ed_sig));

  // SLIP-0010 Ed25519 test vector 1: 16-byte seed 000102...0f, m/0'.
  static const uint8_t kSlipSeed[16] = {
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0a,
    0x0b,
    0x0c,
    0x0d,
    0x0e,
    0x0f,
  };
  static const uint32_t kSlipPath[] = { kHardenedOffset };
  static const uint8_t kSlipChild[32] = {
    0x68,
    0xe0,
    0xfe,
    0x46,
    0xdf,
    0xb6,
    0x7e,
    0x36,
    0x8c,
    0x75,
    0x37,
    0x9a,
    0xce,
    0xc5,
    0x91,
    0xda,
    0xd1,
    0x9d,
    0xf3,
    0xcd,
    0xe2,
    0x6e,
    0x63,
    0xb9,
    0x3a,
    0x8e,
    0x70,
    0x4f,
    0x1d,
    0xad,
    0xe7,
    0xa3,
  };
  uint8_t slip_child[32];
  passed = selftest_report("slip10 child 0'", slip10_ed25519_derive(kSlipSeed, sizeof(kSlipSeed), kSlipPath, 1, slip_child) && crypto_constant_time_equal(slip_child, kSlipChild, 32)) && passed;
  secure_zero(slip_child, sizeof(slip_child));

  // BLS12-381 G1: secret key 1 -> compressed generator.
  static const uint8_t kBlsOne[32] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
  };
  static const uint8_t kBlsGenerator[48] = {
    0x97,
    0xf1,
    0xd3,
    0xa7,
    0x31,
    0x97,
    0xd7,
    0x94,
    0x26,
    0x95,
    0x63,
    0x8c,
    0x4f,
    0xa9,
    0xac,
    0x0f,
    0xc3,
    0x68,
    0x8c,
    0x4f,
    0x97,
    0x74,
    0xb9,
    0x05,
    0xa1,
    0x4e,
    0x3a,
    0x3f,
    0x17,
    0x1b,
    0xac,
    0x58,
    0x6c,
    0x55,
    0xe8,
    0x3f,
    0xf9,
    0x7a,
    0x1a,
    0xef,
    0xfb,
    0x3a,
    0xf0,
    0x0a,
    0xdb,
    0x22,
    0xc6,
    0xbb,
  };
  uint8_t bls_pk[48];
  passed = selftest_report("bls pk(sk=1)", bls12_381_g1_public_key(kBlsOne, bls_pk) && crypto_constant_time_equal(bls_pk, kBlsGenerator, 48)) && passed;
  secure_zero(bls_pk, sizeof(bls_pk));

  // EIP-2333 test case 0.
  static const uint8_t kEipSeed[64] = {
    0xc5,
    0x52,
    0x57,
    0xc3,
    0x60,
    0xc0,
    0x7c,
    0x72,
    0x02,
    0x9a,
    0xeb,
    0xc1,
    0xb5,
    0x3c,
    0x05,
    0xed,
    0x03,
    0x62,
    0xad,
    0xa3,
    0x8e,
    0xad,
    0x3e,
    0x3e,
    0x9e,
    0xfa,
    0x37,
    0x08,
    0xe5,
    0x34,
    0x95,
    0x53,
    0x1f,
    0x09,
    0xa6,
    0x98,
    0x75,
    0x99,
    0xd1,
    0x82,
    0x64,
    0xc1,
    0xe1,
    0xc9,
    0x2f,
    0x2c,
    0xf1,
    0x41,
    0x63,
    0x0c,
    0x7a,
    0x3c,
    0x4a,
    0xb7,
    0xc8,
    0x1b,
    0x2f,
    0x00,
    0x16,
    0x98,
    0xe7,
    0x46,
    0x3b,
    0x04,
  };
  static const uint8_t kEipMaster[32] = {
    0x0d,
    0x73,
    0x59,
    0xd5,
    0x79,
    0x63,
    0xab,
    0x8f,
    0xbb,
    0xde,
    0x18,
    0x52,
    0xdc,
    0xf5,
    0x53,
    0xfe,
    0xdb,
    0xc3,
    0x1f,
    0x46,
    0x4d,
    0x80,
    0xee,
    0x7d,
    0x40,
    0xae,
    0x68,
    0x31,
    0x22,
    0xb4,
    0x50,
    0x70,
  };
  static const uint8_t kEipChild[32] = {
    0x2d,
    0x18,
    0xbd,
    0x6c,
    0x14,
    0xe6,
    0xd1,
    0x5b,
    0xf8,
    0xb5,
    0x08,
    0x5c,
    0x9b,
    0x74,
    0xf3,
    0xda,
    0xae,
    0x3b,
    0x03,
    0xcc,
    0x20,
    0x14,
    0x77,
    0x0a,
    0x59,
    0x9d,
    0x8c,
    0x15,
    0x39,
    0xe5,
    0x0f,
    0x8e,
  };
  uint8_t eip_master[32];
  uint8_t eip_child[32];
  passed = selftest_report("eip2333 master", eip2333_master_key(kEipSeed, sizeof(kEipSeed), eip_master) && crypto_constant_time_equal(eip_master, kEipMaster, 32)) && passed;
  passed = selftest_report("eip2333 child0", eip2333_derive_child(eip_master, 0, eip_child) && crypto_constant_time_equal(eip_child, kEipChild, 32)) && passed;
  secure_zero(eip_master, sizeof(eip_master));
  secure_zero(eip_child, sizeof(eip_child));

  // Chia standard address (EIP-2333 seed -> m/12381/8444/0/0).
  char chia[128];
  passed = selftest_report("chia addr v0", chia_standard_address(kEipSeed, sizeof(kEipSeed), 0, chia, sizeof(chia)) && strcmp(chia, "xch1sqh8a9jwxfvh0rvzza9sslzjgvhjfqcrq47kwf3hq7sx00pfnw2q6pe2gr") == 0) && passed;
  // Chia with a 64-byte 0x01 seed.
  uint8_t ones_seed[64];
  memset(ones_seed, 0x01, sizeof(ones_seed));
  passed = selftest_report("chia addr ones", chia_standard_address(ones_seed, sizeof(ones_seed), 0, chia, sizeof(chia)) && strcmp(chia, "xch1wv0k6nwah2vx6rgplqcey8yhcv3vd2sadwjx6gpa9n9wkcx4p48q6v7n2d") == 0) && passed;
  secure_zero(ones_seed, sizeof(ones_seed));

  secure_zero(digest, sizeof(digest));
  secure_zero(blake64, sizeof(blake64));
  secure_zero(zero_hash, sizeof(zero_hash));
  return passed;
}

}  // namespace hexwallet
