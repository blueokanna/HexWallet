#ifndef HEXWALLET_CRYPTONOTE_RINGCT_H
#define HEXWALLET_CRYPTONOTE_RINGCT_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// CryptoNote/RingCT key layer. These are the consensus-critical primitives
// shared by Monero and its forks; transaction construction, CLSAG and
// Bulletproofs build on top of them. Official Monero tests/crypto/tests.txt
// vectors cover the key primitives; CLSAG still needs external transaction vectors.

constexpr size_t kCryptoNoteKeySize = 32;

// Keccak-256 followed by sc_reduce32.
bool cryptonote_hash_to_scalar(const uint8_t *data, size_t size,
                               uint8_t out_scalar[kCryptoNoteKeySize]);

// 8 * (secret * public), matching Monero generate_key_derivation.
bool cryptonote_generate_key_derivation(
    const uint8_t public_key[kCryptoNoteKeySize],
    const uint8_t secret_key[kCryptoNoteKeySize],
    uint8_t out_derivation[kCryptoNoteKeySize]);

// scalar = Hs(derivation || varint(output_index)); base + scalar*G.
bool cryptonote_derive_public_key(
    const uint8_t derivation[kCryptoNoteKeySize], uint64_t output_index,
    const uint8_t base_public[kCryptoNoteKeySize],
    uint8_t out_public[kCryptoNoteKeySize]);

// scalar = Hs(derivation || varint(output_index)); (base + scalar) mod L.
bool cryptonote_derive_secret_key(
    const uint8_t derivation[kCryptoNoteKeySize], uint64_t output_index,
    const uint8_t base_secret[kCryptoNoteKeySize],
    uint8_t out_secret[kCryptoNoteKeySize]);

// Hp(Keccak-256(public_key)) without the cofactor. This intermediate may
// contain torsion; do not use it directly as the serialized CLSAG D.
bool cryptonote_hash_to_point(const uint8_t public_key[kCryptoNoteKeySize],
                              uint8_t out_point[kCryptoNoteKeySize]);
// 8 * Hp(Keccak-256(public_key)), Monero's hash_to_ec generator.
bool cryptonote_key_image_generator(
    const uint8_t public_key[kCryptoNoteKeySize],
    uint8_t out_generator[kCryptoNoteKeySize]);

// I = secret * (8 * Hp(Keccak-256(public_key))), matching Monero
// generate_key_image/hash_to_ec.
bool cryptonote_generate_key_image(
    const uint8_t public_key[kCryptoNoteKeySize],
    const uint8_t secret_key[kCryptoNoteKeySize],
    uint8_t out_key_image[kCryptoNoteKeySize]);

bool cryptonote_derive_view_tag(const uint8_t derivation[kCryptoNoteKeySize],
                                uint64_t output_index, uint8_t *out_tag);

constexpr size_t kCryptoNoteMaxRingSize = 16;

struct CryptoNoteRingMember {
  uint8_t dest[kCryptoNoteKeySize];
  uint8_t mask[kCryptoNoteKeySize];
};

struct CryptoNoteClsag {
  uint8_t s[kCryptoNoteMaxRingSize][kCryptoNoteKeySize];
  uint8_t c1[kCryptoNoteKeySize];
  uint8_t I[kCryptoNoteKeySize];
  uint8_t D[kCryptoNoteKeySize];
  uint8_t ring_size;
};

// CLSAG over a ring of (dest, nonzero commitment) pairs. `index` is the real
// input; `p` is its spend key, `z` the effective commitment mask
// (amount mask minus pseudo-output offset), and `c_offset` the commitment
// offset. `nonce` and `s_nonces` must be fresh randomness; the caller owns
// their generation and zeroization. The signer verifies p*G == ring[index].dest
// and z*G == ring[index].mask - c_offset before producing a signature.
bool cryptonote_clsag_sign(const uint8_t message[kCryptoNoteKeySize],
                           const CryptoNoteRingMember *ring, size_t ring_size,
                           size_t index, const uint8_t p[kCryptoNoteKeySize],
                           const uint8_t z[kCryptoNoteKeySize],
                           const uint8_t nonce[kCryptoNoteKeySize],
                           const uint8_t *s_nonces,
                           const uint8_t c_offset[kCryptoNoteKeySize],
                           CryptoNoteClsag *out_signature);

bool cryptonote_clsag_verify(const uint8_t message[kCryptoNoteKeySize],
                             const CryptoNoteRingMember *ring,
                             size_t ring_size,
                             const uint8_t c_offset[kCryptoNoteKeySize],
                             const CryptoNoteClsag &signature);

bool run_cryptonote_ringct_self_tests();
// Host/CLI diagnostic: deterministic CLSAG sign/verify and tamper rejection.
bool run_cryptonote_clsag_self_test();

}  // namespace hexwallet

#endif
