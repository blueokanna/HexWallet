#ifndef HEXWALLET_BLS_BACKEND_H
#define HEXWALLET_BLS_BACKEND_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// BLS12-381 primitives used by Chia (XCH).
//
// This backend exists so the firmware owns the arithmetic it signs with: the
// field, the two groups, the compressed encoding and the RFC 9380
// hash-to-curve suite are implemented here, not linked from a vendored
// library. Only the operations the wallet performs are present - G1 key
// derivation and AGG_SIG_ME signing in G2. There is no pairing and no
// signature verification, because a wallet that only produces Chia
// signatures never needs either.
//
// Scalars are 32-byte big-endian values below the group order r. Points use
// the ZCash compressed encoding (0x80 compressed, 0x40 infinity, 0x20 sort).
// Every input is validated before use: non-canonical scalars, off-curve
// points, wrong-subgroup points and malformed encodings are rejected, never
// silently reduced.

constexpr size_t kBlsScalarSize = 32;
constexpr size_t kBlsG1Size = 48;
constexpr size_t kBlsG2Size = 96;

// Canonical big-endian scalar helpers. Reduction accepts any input of 1..256
// bytes and produces a value in [0, r). Secret addition rejects a
// non-canonical key, a non-canonical offset and a zero result. Input/output
// aliasing is supported. Failure clears the output.
bool bls_scalar_reduce(const uint8_t *input, size_t size, uint8_t out[32]);
bool bls_secret_add(const uint8_t secret[32], const uint8_t offset[32], uint8_t out[32]);
// EIP-2333/HKDF-mod-r key generation as Chia derives it: HKDF-Extract with
// the raw "BLS-SIG-KEYGEN-SALT-" salt, then HKDF-Expand to 48 bytes and a
// reduction mod r. Rejects IKM shorter than 32 bytes, like the reference.
bool bls_keygen_v3(const uint8_t *ikm, size_t ikm_size, uint8_t out_sk[32]);

// RFC 9380 BLS12381G2_XMD:SHA-256_SSWU_RO_ hash-to-curve with an explicit DST.
bool bls_g2_hash_to_curve(const uint8_t *message, size_t message_size,
                                const char *dst, uint8_t out_compressed[96]);
// Augmented signing: sig = sk * H(augmentation || message). Chia passes the
// compressed G1 public key as the augmentation.
bool bls_g2_sign_augmented(const uint8_t secret_key[32],
                                 const uint8_t *augmentation, size_t augmentation_size,
                                 const uint8_t *message, size_t message_size,
                                 const char *dst, uint8_t out_compressed[96]);
// Sum of compressed G2 signatures. Every input must decode to a member of the
// prime-order G2 subgroup. The canonical infinity encoding is the identity.
bool bls_g2_aggregate(const uint8_t **signatures, size_t count,
                            uint8_t out_compressed[96]);

}  // namespace hexwallet
#endif
