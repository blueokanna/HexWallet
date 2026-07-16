#include "local_ripemd160.h"

#include <string.h>

namespace {

constexpr size_t kBlockSize = 64;
constexpr size_t kDigestWords = 5;
constexpr size_t kRounds = 80;

constexpr uint32_t kInitialState[kDigestWords] = {
    UINT32_C(0x67452301), UINT32_C(0xefcdab89), UINT32_C(0x98badcfe),
    UINT32_C(0x10325476), UINT32_C(0xc3d2e1f0),
};
constexpr uint32_t kLeftConstants[5] = {
    UINT32_C(0x00000000), UINT32_C(0x5a827999), UINT32_C(0x6ed9eba1),
    UINT32_C(0x8f1bbcdc), UINT32_C(0xa953fd4e),
};
constexpr uint32_t kRightConstants[5] = {
    UINT32_C(0x50a28be6), UINT32_C(0x5c4dd124), UINT32_C(0x6d703ef3),
    UINT32_C(0x7a6d76e9), UINT32_C(0x00000000),
};
constexpr uint8_t kLeftIndex[kRounds] = {
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
     7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
     3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
     1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
     4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13,
};
constexpr uint8_t kRightIndex[kRounds] = {
     5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
     6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
    15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
     8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
    12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11,
};
constexpr uint8_t kLeftShift[kRounds] = {
    11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
     7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
    11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
    11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
     9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6,
};
constexpr uint8_t kRightShift[kRounds] = {
     8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
     9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
     9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
    15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
     8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11,
};

uint32_t rotate_left(uint32_t value, uint8_t count) {
  return (value << count) | (value >> (32U - count));
}

uint32_t round_function(uint8_t group, uint32_t x, uint32_t y, uint32_t z) {
  switch (group) {
    case 0: return x ^ y ^ z;
    case 1: return (x & y) | (~x & z);
    case 2: return (x | ~y) ^ z;
    case 3: return (x & z) | (y & ~z);
    default: return x ^ (y | ~z);
  }
}

uint32_t load_le32(const uint8_t *data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) |
         (static_cast<uint32_t>(data[3]) << 24);
}

void store_le32(uint8_t *out, uint32_t value) {
  out[0] = static_cast<uint8_t>(value);
  out[1] = static_cast<uint8_t>(value >> 8);
  out[2] = static_cast<uint8_t>(value >> 16);
  out[3] = static_cast<uint8_t>(value >> 24);
}

void compress(uint32_t state[kDigestWords], const uint8_t block[kBlockSize]) {
  uint32_t words[16];
  for (uint8_t index = 0; index < 16; ++index) {
    words[index] = load_le32(block + index * 4);
  }
  uint32_t al = state[0], bl = state[1], cl = state[2], dl = state[3], el = state[4];
  uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el;
  for (uint8_t round = 0; round < kRounds; ++round) {
    const uint8_t group = round / 16;
    uint32_t next = rotate_left(al + round_function(group, bl, cl, dl) +
                                    words[kLeftIndex[round]] + kLeftConstants[group],
                                kLeftShift[round]) + el;
    al = el; el = dl; dl = rotate_left(cl, 10); cl = bl; bl = next;
    next = rotate_left(ar + round_function(4 - group, br, cr, dr) +
                           words[kRightIndex[round]] + kRightConstants[group],
                       kRightShift[round]) + er;
    ar = er; er = dr; dr = rotate_left(cr, 10); cr = br; br = next;
  }
  const uint32_t temporary = state[1] + cl + dr;
  state[1] = state[2] + dl + er;
  state[2] = state[3] + el + ar;
  state[3] = state[4] + al + br;
  state[4] = state[0] + bl + cr;
  state[0] = temporary;
  memset(words, 0, sizeof(words));
}

}  // namespace

void local_ripemd160(const uint8_t *data, size_t data_size,
                     uint8_t digest[kLocalRipemd160DigestSize]) {
  if (digest == nullptr || (data == nullptr && data_size != 0)) {
    return;
  }
  uint32_t state[kDigestWords];
  memcpy(state, kInitialState, sizeof(state));
  const size_t original_size = data_size;
  while (data_size >= kBlockSize) {
    compress(state, data);
    data += kBlockSize;
    data_size -= kBlockSize;
  }
  uint8_t final_blocks[kBlockSize * 2] = {0};
  memcpy(final_blocks, data, data_size);
  final_blocks[data_size] = 0x80;
  const size_t padded_size = data_size < 56 ? kBlockSize : kBlockSize * 2;
  const uint64_t bit_size = static_cast<uint64_t>(original_size) * 8U;
  for (uint8_t index = 0; index < 8; ++index) {
    final_blocks[padded_size - 8 + index] = static_cast<uint8_t>(bit_size >> (index * 8U));
  }
  compress(state, final_blocks);
  if (padded_size == kBlockSize * 2) {
    compress(state, final_blocks + kBlockSize);
  }
  for (uint8_t index = 0; index < kDigestWords; ++index) {
    store_le32(digest + index * 4, state[index]);
  }
  memset(state, 0, sizeof(state));
  memset(final_blocks, 0, sizeof(final_blocks));
}
