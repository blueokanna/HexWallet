#ifndef HEXWALLET_RYO_BULLETPROOF_H
#define HEXWALLET_RYO_BULLETPROOF_H
#include <stddef.h>
#include <stdint.h>

namespace hexwallet {
// Original RingCT Bulletproof (Ryo type 3), not Bulletproofs+. Points V are
// output commitments divided by eight, exactly as restored by the node.
// Borrowed fields must remain valid and immutable for the entire verification.
struct RyoBulletproofView {
  const uint8_t *commitments;
  size_t commitment_count;
  const uint8_t *a_point;
  const uint8_t *s_point;
  const uint8_t *t1_point;
  const uint8_t *t2_point;
  const uint8_t *taux;
  const uint8_t *mu;
  const uint8_t *left;
  const uint8_t *right;
  size_t rounds;
  const uint8_t *a;
  const uint8_t *b;
  const uint8_t *t;
};

// Verifies both equations independently for one proof; no random batch weight
// or heap allocation. Supports 1..16 outputs, with 64-bit range per output.
bool ryo_bulletproof_verify(const RyoBulletproofView &proof);
bool ryo_bulletproof_generator(size_t index, uint8_t out[32]);
}  // namespace hexwallet
#endif
