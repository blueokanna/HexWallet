#ifndef HEXWALLET_RANDOM_SOURCE_H
#define HEXWALLET_RANDOM_SOURCE_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// One entropy path for the whole firmware.
//
// The offline board enables the SAR ADC entropy source before its peripherals
// start. Only that exclusive boot window supplies physical seed material.
//
//   raw 32-byte blocks -> continuous health tests -> SP 800-90A HMAC-SHA256
//   DRBG -> caller
//
// Health tests (per raw block, against the two previous raw blocks):
//   * reject an all-0x00 or all-0xFF block
//   * reject a block with fewer than 64 or more than 192 set bits (>= 8 sigma)
//   * reject the third consecutive identical block
//   * reject a block equal to the block before the previous one (a source that
//     alternates between two values would otherwise pass a "same as last"
//     check forever)
// A failed test latches `healthy` false for the rest of the boot: there is no
// "try again and hope" path, because a source that produced one stuck block is
// not a source. Key generation refuses to run while it is false.
//
// An offline board requires another boot after 2^20 requests. The host
// backend can obtain additional entropy while running.

struct RandomStats {
  uint32_t requests;
  uint32_t reseeds;
  uint32_t entropy_failures;
  uint32_t health_failures;
  uint32_t oversized_requests;
  bool healthy;
};

// Call from setup before using the ADC or starting wallet services.
bool random_init_at_boot();

// Legacy wrapper. Callers making a signing or key-generation decision should
// check the return value of random_fill_checked for the specific request.
void random_fill(void *out, size_t size);
// Reports success for this request while holding the generator lock.
bool random_fill_checked(void *out, size_t size);

uint32_t random_u32();

// False after the first health-test or entropy failure of this boot.
bool random_healthy();

// Reseed only when a fresh entropy source is available. The offline device
// returns false after setup, when the ADC belongs to the board peripherals.
bool random_reseed();

RandomStats random_stats();

// Health tests, DRBG determinism/separation and fail-closed behaviour.
bool run_random_source_self_tests();

}  // namespace hexwallet

#endif
