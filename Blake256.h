#ifndef HEXWALLET_BLAKE256_H
#define HEXWALLET_BLAKE256_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Original BLAKE-256 (not BLAKE2b), used by Decred for transaction IDs,
// signatures hashes and address checksums.
struct Blake256State {
  uint32_t h[8];
  uint64_t counter;
  uint8_t buffer[64];
  size_t buffer_size;
};

void blake256_init(Blake256State *state);
void blake256_update(Blake256State *state, const uint8_t *data, size_t size);
bool blake256_final(Blake256State *state, uint8_t out[32]);
bool blake256_hash(const uint8_t *data, size_t size, uint8_t out[32]);
bool run_blake256_self_tests();

}  // namespace hexwallet

#endif
