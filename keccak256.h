#ifndef HEXWALLET_KECCAK256_H
#define HEXWALLET_KECCAK256_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t kKeccak256StateLanes = 25;
constexpr size_t kKeccak256RateBytes = 136;
constexpr size_t kKeccak256DigestBytes = 32;

struct SHA3_CTX {
  uint64_t state[kKeccak256StateLanes];
  uint8_t buffer[kKeccak256RateBytes];
  size_t used;
  bool finalized;
};

void keccak_init(SHA3_CTX *context);
bool keccak_update(SHA3_CTX *context, const uint8_t *data, size_t size);
bool keccak_final(SHA3_CTX *context, uint8_t result[kKeccak256DigestBytes]);

void keccak_permute(uint64_t state[kKeccak256StateLanes]);

#endif
