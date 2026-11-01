#ifndef HEXWALLET_ML_DSA_87_H
#define HEXWALLET_ML_DSA_87_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// FIPS 204 ML-DSA-87 (Dilithium5 parameter set).
//
// The QRL v2 account derives a 32-byte seed with BIP32, expands it here, and
// signs keccak256(RLP transaction).  Signatures are 4627 bytes and public keys
// 2592 bytes; the signer needs roughly 140 KB of working memory, so every
// operation allocates its workspace on the heap and releases it before
// returning.
//
// `message` is the already-formatted M' string of FIPS 204 section 6.2.  QRL
// v2 prefixes it with 00 08 "ZOND" 01 01 00 00; the ACVP vectors use 00 00.
// The caller owns that prefix so the primitive never guesses a protocol.
//
// `rnd` is 32 bytes.  All-zero selects the deterministic variant; the wallet
// passes fresh random bytes for the default hedged variant.
constexpr size_t kMlDsa87SeedSize = 32;
constexpr size_t kMlDsa87PublicKeySize = 2592;
constexpr size_t kMlDsa87SecretKeySize = 4896;
constexpr size_t kMlDsa87SignatureSize = 4627;

bool ml_dsa_87_keypair_from_seed(const uint8_t seed[kMlDsa87SeedSize],
                                 uint8_t public_key[kMlDsa87PublicKeySize],
                                 uint8_t secret_key[kMlDsa87SecretKeySize]);
bool ml_dsa_87_sign(const uint8_t secret_key[kMlDsa87SecretKeySize],
                    const uint8_t *message, size_t message_size,
                    const uint8_t rnd[32],
                    uint8_t signature[kMlDsa87SignatureSize]);
bool ml_dsa_87_verify(const uint8_t public_key[kMlDsa87PublicKeySize],
                      const uint8_t *message, size_t message_size,
                      const uint8_t signature[kMlDsa87SignatureSize]);

bool run_ml_dsa_87_self_tests();

}  // namespace hexwallet

#endif
