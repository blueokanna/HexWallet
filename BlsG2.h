#ifndef HEXWALLET_BLS_G2_H
#define HEXWALLET_BLS_G2_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{
  // BLS12-381 G2 hash-to-curve and signing (RFC 9380 + Chia's augmented scheme).
  //
  // Chia (XCH) keys live in G1 and signatures in G2. `AugSchemeMPL.sign(sk, m)`
  // is `sk * H(compressed_pk || m)` with the DST
  // "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_", so the identity of the
  // signing key is bound into the message.
  constexpr size_t kBlsG2CompressedSize = 96;
  constexpr size_t kBlsG1CompressedSize = 48;

  // Hashes a message into G2 (96-byte compressed output). `dst` is the domain
  // separation tag; it must be the full suite id string.
  bool bls12_381_g2_hash_to_curve(const uint8_t *message, size_t message_size,
                                  const char *dst, uint8_t out[96]);

  // Augmented signing: sig = sk * H(pk || message).
  bool bls12_381_g2_sign_augmented(const uint8_t secret_key[32],
                                   const uint8_t *message, size_t message_size,
                                   uint8_t out[96]);

  // Aggregates compressed G2 signatures (point addition on the signature group).
  bool bls12_381_g2_aggregate(const uint8_t **signatures, size_t count,
                              uint8_t out[96]);

  bool run_bls_g2_self_tests();

} // namespace hexwallet

#endif
