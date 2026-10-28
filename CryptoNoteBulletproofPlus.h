#ifndef HEXWALLET_CRYPTONOTE_BULLETPROOF_PLUS_H
#define HEXWALLET_CRYPTONOTE_BULLETPROOF_PLUS_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{
  // Zero-copy view of one Bulletproofs+ proof. `v` points at the commitments
  // with 1/8 mod l already applied, as Monero's expand_transaction_1 leaves
  // them; use bulletproof_plus_commitment_to_view() to build that array from
  // on-chain outPk values.
  struct BulletproofPlusView
  {
    const uint8_t *v;
    size_t commitment_count;
    const uint8_t *a;
    const uint8_t *a1;
    const uint8_t *b;
    const uint8_t *r1;
    const uint8_t *s1;
    const uint8_t *d1;
    const uint8_t *l;
    const uint8_t *r;
    size_t rounds;
  };

  // Monero bulletproof_plus_VERIFY for one proof, transcribed from
  // src/ringct/bulletproofs_plus.cc. Returns false for a malformed view, a
  // non-reduced scalar, an undecodable point, a zero transcript value, or a
  // multiexp result other than the identity.
#if defined(HEXWALLET_HOST_TEST)
  using BulletproofPlusTrace = void (*)(const char *, const uint8_t *, size_t);
  bool bulletproof_plus_verify(const BulletproofPlusView &proof,
                               BulletproofPlusTrace trace = nullptr);
#else
  bool bulletproof_plus_verify(const BulletproofPlusView &proof);
#endif

  // Monero's get_exponent(H, index): the indexed generator Gi/Hi. Exposed so a
  // host test can pin the derivation instead of trusting the verifier.
  bool bulletproof_plus_generator(size_t index, uint8_t out[32]);

  // Monero's initial_transcript, the fixed transcript seed derived from the
  // "bulletproof_plus_transcript" domain separator.
  bool bulletproof_plus_initial_transcript(uint8_t out[32]);

  // Rebuilds the V a proof holds from an on-chain output commitment: Monero's
  // expand_transaction_1 multiplies outPk by 1/8 mod l and the verifier
  // multiplies by 8 again. One definition, so the review path and the verifier
  // cannot drift apart.
  bool bulletproof_plus_commitment_to_view(const uint8_t commitment[32],
                                          uint8_t out[32]);

  // Pins the generator derivation, the transcript seed and the rejection paths.
  bool run_bulletproof_plus_self_tests();

#if defined(HEXWALLET_HOST_TEST)
  // Cross-checks every proof and every intermediate transcript value against the
  // pinned Monero reference build (tests/fixtures/monero-bp-plus). Covers the
  // 1/2/3/4/5/8/9/16-output shapes. Host-only: it costs a full multiexp per
  // case, which a device self-test must not spend.
  bool run_bulletproof_plus_reference_vector_self_test();
#endif

  // Reports whether the equation accepts the pinned mainnet proof. Kept apart
  // from the self-tests so the number is visible without being a gate.
  bool run_bulletproof_plus_mainnet_probe();

} // namespace hexwallet

#endif
