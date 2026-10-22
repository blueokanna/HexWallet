#ifndef HEXWALLET_BLAKE2B_H
#define HEXWALLET_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// RFC 7693 BLAKE2b, incremental and keyed. Kaspa's transaction ID and sighash
// both use BLAKE2b-256 with a domain-separation key, and the sighash preimage
// is streamed, so a one-shot helper is not sufficient.
struct Blake2bState {
  uint64_t h[8];
  uint64_t t0;
  uint64_t t1;
  uint8_t buffer[128];
  size_t buffer_size;
  size_t out_size;
};

// out_size must be in [1, 64]; key_size in [0, 64]. A key of zero length is
// equivalent to the unkeyed function.
bool blake2b_init(Blake2bState *state, size_t out_size, const uint8_t *key,
                  size_t key_size);
void blake2b_update(Blake2bState *state, const uint8_t *data, size_t size);
// Wipes the state; out must have room for out_size bytes.
bool blake2b_final(Blake2bState *state, uint8_t *out);

// Convenience wrappers for the two call sites that dominate this codebase.
bool blake2b_keyed_hash(const uint8_t *key, size_t key_size, const uint8_t *data,
                        size_t size, uint8_t *out, size_t out_size);
bool run_blake2b_self_tests();

}  // namespace hexwallet

#endif
