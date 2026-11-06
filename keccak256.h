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

// Keccak-p[1600, rounds] as defined by the Keccak reference: the last `rounds`
// of the 24 round constants are applied, so rounds == 12 is Keccak-p[1600,12]
// (what KangarooTwelve and TurboSHAKE use) and rounds == 24 is the full
// permutation SHA3 builds on. `rounds` must be 1..24; anything else is a no-op.
void keccak_p1600(uint64_t state[kKeccak256StateLanes], size_t rounds);

#endif
