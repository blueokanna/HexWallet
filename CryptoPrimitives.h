#ifndef HEXWALLET_CRYPTO_PRIMITIVES_H
#define HEXWALLET_CRYPTO_PRIMITIVES_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

constexpr size_t kSha256Size = 32;
constexpr size_t kSha224Size = 28;
constexpr size_t kSha512Size = 64;
constexpr size_t kRipemd160Size = 20;
constexpr size_t kKeccak256Size = 32;
constexpr size_t kKeccak512Size = 64;
constexpr size_t kShake256Size = 32;

bool crypto_sha256(const uint8_t *data, size_t size, uint8_t out[kSha256Size]);
// SHA-224 (FIPS 180-4), used by the Internet Computer principal derivation.
bool crypto_sha224(const uint8_t *data, size_t size, uint8_t out[kSha224Size]);
// Portable SHA-224 that does not depend on the selected mbedtls digest set.
bool crypto_sha224_local(const uint8_t *data, size_t size,
                         uint8_t out[kSha224Size]);
bool crypto_double_sha256(const uint8_t *data, size_t size, uint8_t out[kSha256Size]);
// Concatenates up to three segments before hashing.  Needed to compute the
// txid of a segwit previous transaction without materialising a stripped copy.
bool crypto_double_sha256_segments(const uint8_t *a, size_t a_size,
                                   const uint8_t *b, size_t b_size,
                                   const uint8_t *c, size_t c_size,
                                   uint8_t out[kSha256Size]);
bool crypto_hmac_sha256(const uint8_t *key, size_t key_size, const uint8_t *data,
                        size_t data_size, uint8_t out[kSha256Size]);
bool crypto_hmac_sha512(const uint8_t *key, size_t key_size, const uint8_t *data,
                        size_t data_size, uint8_t out[kSha512Size]);
bool crypto_pbkdf2_sha256(const uint8_t *password, size_t password_size,
                          const uint8_t *salt, size_t salt_size, uint32_t iterations,
                          uint8_t *out, size_t out_size);
bool crypto_hash160(const uint8_t *data, size_t size, uint8_t out[kRipemd160Size]);
bool crypto_keccak256(const uint8_t *data, size_t size, uint8_t out[kKeccak256Size]);
// Legacy Keccak-512 (0x01 padding), required by CryptoNote subaddresses.
bool crypto_keccak512(const uint8_t *data, size_t size, uint8_t out[kKeccak512Size]);
// FIPS 202 SHAKE-256 (0x1F padding), arbitrary output length.
bool crypto_shake256(const uint8_t *data, size_t size, uint8_t *out, size_t out_size);
bool crypto_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t size);
bool run_crypto_self_tests();

}  // namespace hexwallet

#endif
