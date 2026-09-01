#ifndef HEXWALLET_CRYPTO_EXTENDED_H
#define HEXWALLET_CRYPTO_EXTENDED_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// ---------------------------------------------------------------------------
// Additional one-shot hashes required by the multi-coin address stack.
// Each function is verified against official vectors in run_crypto_extended_self_tests().
// ---------------------------------------------------------------------------

// FIPS 202 SHA3-256 (Keccak with 0x06 domain byte). Distinct from the legacy
// Ethereum Keccak-256 in CryptoPrimitives (0x01 domain byte).
bool crypto_sha3_256(const uint8_t *data, size_t size, uint8_t out[32]);

// SHA-512/256 (FIPS 180-4): SHA-512 compression with the 512/256 initial
// values, truncated to 256 bits. Used by the Algorand address checksum.
bool crypto_sha512_256(const uint8_t *data, size_t size, uint8_t out[32]);

// BLAKE2b (RFC 7693) without key. out_size must be in [1, 64].
bool crypto_blake2b(const uint8_t *data, size_t size, uint8_t *out,
                    size_t out_size);

// ---------------------------------------------------------------------------
// Base encodings.
// ---------------------------------------------------------------------------

// RFC 4648 base32. lowercase selects a..z2..7 (Filecoin), otherwise A..Z2..7
// (Algorand). pad appends '='. Returns false on truncation.
bool base32_encode(const uint8_t *data, size_t size, char *out, size_t out_size,
                   bool lowercase, bool pad);

// Qubic identity: base26 of a big-endian digest with alphabet
// "123456789abcdefghijkmnopqrstuvwxyz" (no 0/l/o). Variable length <= 60.
bool qubic_base26_encode(const uint8_t *digest, size_t digest_size, char *out,
                         size_t out_size);

// CashAddr (bitcoin-cash.info spec): prefix ':' payload with poly-mod checksum.
// type_bits is 0 for P2PKH and 8 for P2SH (also << 3 per the spec layout is NOT
// applied here; type_bits already carries the shifted value, e.g. 0x00/0x08).
bool cashaddr_encode(const char *prefix, uint8_t type_bits,
                     const uint8_t *payload, size_t payload_size, char *out,
                     size_t out_size);

// BIP-173 bech32 or BIP-350 bech32m. payload is a byte string converted 8->5.
bool bech32_encode(const char *hrp, const uint8_t *payload, size_t payload_size,
                   char *out, size_t out_size, bool bech32m);

// Kaspa bech32: CashAddr-style 64-bit poly-mod with Kaspa generator constants,
// 8-byte checksum of which the last 5 bytes are appended (5-bit converted).
bool kaspa_bech32_encode(const char *hrp, uint8_t version,
                         const uint8_t *payload, size_t payload_size, char *out,
                         size_t out_size);

// ---------------------------------------------------------------------------
// Ed25519 (RFC 8032) and SLIP-0010 hardened derivation.
// ---------------------------------------------------------------------------

// Derive the 32-byte Ed25519 public key from a 32-byte seed.
bool ed25519_public_key(const uint8_t seed[32], uint8_t out_public[32]);

// RFC 8032 pure Ed25519 signature (64 bytes) over an arbitrary message.
bool ed25519_sign(const uint8_t seed[32], const uint8_t *message,
                  size_t message_size, uint8_t out_signature[64]);

// SLIP-0010 Ed25519 derivation. seed may be any length (BIP-39 seeds are
// typically 16-64 bytes). path contains hardened values (index | 0x80000000).
bool slip10_ed25519_derive(const uint8_t *seed, size_t seed_size,
                           const uint32_t *path, size_t path_size,
                           uint8_t out_private[32]);

// ---------------------------------------------------------------------------
// BLS12-381 G1 and EIP-2333 (Chia address derivation).
// ---------------------------------------------------------------------------

// Compute the compressed (48-byte) G1 public key for a 32-byte secret key.
bool bls12_381_g1_public_key(const uint8_t secret_key[32],
                             uint8_t out_compressed[48]);

// Add offset*G1 to an existing compressed point (used for synthetic keys).
bool bls12_381_g1_add_generator(const uint8_t point[48],
                                const uint8_t secret_offset[32],
                                uint8_t out_compressed[48]);

// EIP-2333 master key from the BIP39 seed (64 bytes recommended).
bool eip2333_master_key(const uint8_t *seed, size_t seed_size,
                        uint8_t out_sk[32]);

// EIP-2333 hardened child derivation.
bool eip2333_derive_child(const uint8_t parent_sk[32], uint32_t index,
                          uint8_t out_sk[32]);

// Chia standard-coin address at m/12381'/8444'/0'/index'.
bool chia_standard_address(const uint8_t *seed, size_t seed_size,
                           uint32_t address_index, char *out, size_t out_size);

// ---------------------------------------------------------------------------

bool run_crypto_extended_self_tests();

}  // namespace hexwallet

#endif
