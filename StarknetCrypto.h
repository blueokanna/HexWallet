#ifndef HEXWALLET_STARKNET_CRYPTO_H
#define HEXWALLET_STARKNET_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Starknet cryptography, implemented in this repository.
//
// The curve is the Stark curve over
//   p = 2^251 + 17 * 2^192 + 1,
//   y^2 = x^3 + x + beta,
// with the StarkWare generator and group order. Field elements and scalars are
// 32-byte big-endian values; every entry point rejects a value outside its
// range instead of reducing silently.
//
// Covered primitives:
//   * Pedersen hash (the 252-bit StarkWare subset-sum construction)
//   * Poseidon hash (Hades permutation, rate 2 / capacity 1, 8 full + 83
//     partial rounds, cubic S-box, width-3 MDS, StarkWare round constants)
//   * Stark ECDSA (RFC 6979 nonces, the `r`/`w < 2^251` constraints, no low-S
//     normalisation because Starknet accepts both halves)
//   * Account contract address from class hash, salt, constructor calldata and
//     deployer, using the SNIP-5 `STARKNET_CONTRACT_ADDRESS` prefix
//
// The Pedersen and Poseidon inputs here are public data (addresses, calldata,
// transaction fields). Scalar multiplication for signing runs a fixed
// double-and-add-always walk and self-verifies before a signature is released.
constexpr size_t kStarkFeltSize = 32;

bool stark_pedersen(const uint8_t x[kStarkFeltSize],
                    const uint8_t y[kStarkFeltSize],
                    uint8_t out[kStarkFeltSize]);
// Pedersen chain used by Starknet: h = 0; for v: h = pedersen(h, v); then
// h = pedersen(h, count). `values` may be null when count is zero.
bool stark_pedersen_many(const uint8_t (*values)[kStarkFeltSize], size_t count,
                         uint8_t out[kStarkFeltSize]);

bool stark_poseidon(const uint8_t x[kStarkFeltSize],
                    const uint8_t y[kStarkFeltSize],
                    uint8_t out[kStarkFeltSize]);
bool stark_poseidon_many(const uint8_t (*values)[kStarkFeltSize], size_t count,
                         uint8_t out[kStarkFeltSize]);

// x-coordinate of private_key * G. Only the x coordinate is the Stark key; the
// y sign is recovered from the curve when needed.
bool stark_public_key(const uint8_t private_key[kStarkFeltSize],
                      uint8_t out_x[kStarkFeltSize]);

// StarkWare key grinding: SHA-256(seed || counter) rejection-sampled into
// [0, n). `seed` is the 32-byte BIP32 child; the result is the Stark private
// scalar used by `stark_public_key` / `stark_sign`.
bool stark_grind_key(const uint8_t seed[kStarkFeltSize],
                     uint8_t out_private_key[kStarkFeltSize]);

// Signs a Stark message hash (already a field element < 2^251). Returns r and s
// as 32-byte big-endian values and self-verifies the pair before returning.
bool stark_sign(const uint8_t private_key[kStarkFeltSize],
                const uint8_t message_hash[kStarkFeltSize],
                uint8_t out_r[kStarkFeltSize], uint8_t out_s[kStarkFeltSize]);
bool stark_verify(const uint8_t public_key_x[kStarkFeltSize],
                  const uint8_t message_hash[kStarkFeltSize],
                  const uint8_t r[kStarkFeltSize],
                  const uint8_t s[kStarkFeltSize]);

// Resource bounds as they appear in a v3 transaction. `max_price` is a
// 128-bit big-endian integer; `max_amount` is 64-bit.
struct StarkResourceBounds {
  uint64_t max_amount;
  uint8_t max_price[16];
};
struct StarkV3Fees {
  uint64_t tip;
  StarkResourceBounds l1_gas;
  StarkResourceBounds l2_gas;
  StarkResourceBounds l1_data_gas;
};

// Cairo v3 transaction hashes over the Starknet mainnet chain id ("SN_MAIN").
// `calldata` is the account's compiled calldata (the invoke's calls, or the
// constructor calldata for a deployment); the device never hashes JSON.
bool stark_invoke_v3_hash(const uint8_t sender[kStarkFeltSize],
                          uint64_t nonce, const StarkV3Fees &fees,
                          uint8_t nonce_da_mode, uint8_t fee_da_mode,
                          const uint8_t (*calldata)[kStarkFeltSize],
                          size_t calldata_count, uint8_t out[kStarkFeltSize]);
bool stark_deploy_account_v3_hash(
    const uint8_t contract_address[kStarkFeltSize],
    const uint8_t class_hash[kStarkFeltSize],
    const uint8_t salt[kStarkFeltSize],
    const uint8_t (*constructor_calldata)[kStarkFeltSize],
    size_t calldata_count, uint64_t nonce, const StarkV3Fees &fees,
    uint8_t nonce_da_mode, uint8_t fee_da_mode,
    uint8_t out[kStarkFeltSize]);

// SNIP-5 contract address:
//   calldata_hash = pedersen_many(constructor_calldata)
//   address = pedersen_many([PREFIX, deployer, salt, class_hash,
//                            calldata_hash]) mod (2^251 - 256)
bool stark_contract_address(const uint8_t class_hash[kStarkFeltSize],
                            const uint8_t salt[kStarkFeltSize],
                            const uint8_t (*constructor_calldata)[kStarkFeltSize],
                            size_t calldata_count,
                            const uint8_t deployer[kStarkFeltSize],
                            uint8_t out[kStarkFeltSize]);

// Published KATs (StarkWare/@scure vectors) plus address/hash compositions.
bool run_starknet_crypto_self_tests();

}  // namespace hexwallet

#endif
