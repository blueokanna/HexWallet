#ifndef HEXWALLET_RANDOM_SOURCE_H
#define HEXWALLET_RANDOM_SOURCE_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// One entropy path for the whole firmware.
//
// The ESP32-P4 hardware RNG (esp_fill_random) is a true random source, but a
// hardware RNG is exactly the component that fails silently: a stuck output, a
// rail that is not up yet, or a clock gated during light sleep all produce
// plausible-looking bytes. So the raw source is never handed to callers:
//
//   raw 32-byte blocks -> continuous health tests -> SP 800-90A HMAC-SHA256
//   DRBG -> caller
//
// Health tests (per raw block, and over the last four blocks):
//   * reject an all-0x00 or all-0xFF block
//   * reject a block with fewer than 64 or more than 192 set bits (>= 8 sigma)
//   * reject three consecutive identical blocks
// A failed test latches `healthy` false for the rest of the boot: there is no
// "try again and hope" path, because a source that produced one stuck block is
// not a source. Key generation refuses to run while it is false.
//
// The DRBG is HMAC-SHA256 (SP 800-90A 10.1.2) with reseed every 2^20 requests
// or on demand. This is a defence-in-depth construction, not a certified
// module; the point is that a single bad entropy read cannot reach a key.

struct RandomStats {
  uint32_t requests;
  uint32_t reseeds;
  uint32_t entropy_failures;
  uint32_t health_failures;
  bool healthy;
};

// Fills `out` with `size` bytes. With a failed health test the buffer is zeroed
// and the caller's key material will fail its own checks; check random_healthy()
// before generating a seed.
void random_fill(void *out, size_t size);

uint32_t random_u32();

// False after the first health-test or entropy failure of this boot.
bool random_healthy();

// Forces a fresh entropy read and DRBG reseed. Call after wake from deep sleep
// and before a long signing session.
bool random_reseed();

const RandomStats &random_stats();

// Health tests, DRBG determinism/separation and fail-closed behaviour.
bool run_random_source_self_tests();

}  // namespace hexwallet

#endif
