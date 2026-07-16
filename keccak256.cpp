#include "keccak256.h"

#include <string.h>

namespace {

constexpr size_t kLaneCount = kKeccak256StateLanes;
constexpr size_t kRoundCount = 24;
constexpr size_t kRateBytes = kKeccak256RateBytes;
constexpr size_t kDigestBytes = kKeccak256DigestBytes;
constexpr uint8_t kKeccakDomainSuffix = 0x01;
constexpr uint8_t kFinalBit = 0x80;

// Keccak-f[1600] constants from FIPS 202 section 3.2.  They are algorithm
// parameters, kept immutable and isolated from wallet/network policy.
constexpr uint64_t kRoundConstants[kRoundCount] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

constexpr uint8_t kRotation[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14},
};

uint64_t rotate_left(uint64_t value, uint8_t shift) {
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

void permutation(uint64_t state[kLaneCount]) {
  for (size_t round = 0; round < kRoundCount; ++round) {
    uint64_t column[5];
    uint64_t delta[5];
    uint64_t moved[kLaneCount];

    for (uint8_t x = 0; x < 5; ++x) {
      column[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (uint8_t x = 0; x < 5; ++x) {
      delta[x] = column[(x + 4) % 5] ^ rotate_left(column[(x + 1) % 5], 1);
    }
    for (uint8_t y = 0; y < 5; ++y) {
      for (uint8_t x = 0; x < 5; ++x) {
        state[x + 5 * y] ^= delta[x];
      }
    }

    for (uint8_t y = 0; y < 5; ++y) {
      for (uint8_t x = 0; x < 5; ++x) {
        moved[y + 5 * ((2 * x + 3 * y) % 5)] = rotate_left(state[x + 5 * y], kRotation[x][y]);
      }
    }

    for (uint8_t y = 0; y < 5; ++y) {
      for (uint8_t x = 0; x < 5; ++x) {
        state[x + 5 * y] = moved[x + 5 * y] ^
                             ((~moved[(x + 1) % 5 + 5 * y]) & moved[(x + 2) % 5 + 5 * y]);
      }
    }
    state[0] ^= kRoundConstants[round];
  }
}

void absorb_block(SHA3_CTX *context, const uint8_t block[kRateBytes]) {
  for (size_t lane = 0; lane < kRateBytes / sizeof(uint64_t); ++lane) {
    context->state[lane] ^= load_le64(block + lane * sizeof(uint64_t));
  }
  permutation(context->state);
}

}  // namespace

void keccak_init(SHA3_CTX *context) {
  if (context != nullptr) {
    memset(context, 0, sizeof(*context));
  }
}

bool keccak_update(SHA3_CTX *context, const uint8_t *data, size_t size) {
  if (context == nullptr || context->finalized || (data == nullptr && size != 0)) {
    return false;
  }
  while (size != 0) {
    const size_t available = kRateBytes - context->used;
    const size_t take = size < available ? size : available;
    memcpy(context->buffer + context->used, data, take);
    context->used += take;
    data += take;
    size -= take;
    if (context->used == kRateBytes) {
      absorb_block(context, context->buffer);
      memset(context->buffer, 0, sizeof(context->buffer));
      context->used = 0;
    }
  }
  return true;
}

bool keccak_final(SHA3_CTX *context, uint8_t result[kDigestBytes]) {
  if (context == nullptr || result == nullptr || context->finalized) {
    return false;
  }
  memset(context->buffer + context->used, 0, kRateBytes - context->used);
  context->buffer[context->used] ^= kKeccakDomainSuffix;
  context->buffer[kRateBytes - 1] ^= kFinalBit;
  absorb_block(context, context->buffer);
  for (size_t lane = 0; lane < kDigestBytes / sizeof(uint64_t); ++lane) {
    store_le64(result + lane * sizeof(uint64_t), context->state[lane]);
  }
  context->finalized = true;
  memset(context->buffer, 0, sizeof(context->buffer));
  return true;
}
