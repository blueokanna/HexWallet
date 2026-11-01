#ifndef HEXWALLET_STARKNET_TRANSACTION_H
#define HEXWALLET_STARKNET_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet {

// Starknet v3 transactions for single-key accounts.
//
// Starknet has no "address per account index": an account address is a SNIP-5
// contract address derived from the account class hash, a salt and the
// constructor calldata. The device therefore never trusts a host-supplied
// address; it recomputes
//
//   address = pedersen_many([0x535441524b4e45545f434f4e54524143545f41444452455353,
//                            0, salt, class_hash, pedersen_many(ctor)])
//                            mod (2^251 - 256)
//
// from the class hash and salt in the payload and requires ctor == [key], where
// `key` is the x coordinate of grindKey(BIP32 child) * G. Only accounts whose
// constructor takes exactly one public key are admitted; anything else is
// refused rather than signed blind.
//
// Admitted operations (`kind`):
//   0  invoke          account entry point `execute`, 1..4 ERC-20 `transfer`
//                       calls, each reviewed on its own row
//   1  deploy_account  the account above, deployed by itself
// Both are Cairo v3 and pay the fee in STRK through tip plus L1_GAS / L2_GAS /
// L1_DATA resource bounds. The chain id is pinned to SN_MAIN inside the hash, so
// a testnet payload cannot be signed by this build.
//
// Payload "SNV3" (big-endian integers, felts are 32-byte right-aligned):
//    0  "SNV3"
//    4  u8  kind                (0 invoke, 1 deploy_account)
//    5  u8  nonce_da_mode       (0 = L1, 1 = L2)
//    6  u8  fee_da_mode         (0 = L1, 1 = L2)
//    7  u8  ctor_count          (must be 1)
//    8  felt class_hash
//   40  felt salt
//   72  felt ctor[0]            (Stark account public key)
//  104  u64 nonce_be
//  112  u64 tip_be
//  120  u64 l1_gas.max_amount_be
//  128  u128 l1_gas.max_price_be
//  144  u64 l2_gas.max_amount_be
//  152  u128 l2_gas.max_price_be
//  168  u64 l1_data_gas.max_amount_be
//  176  u128 l1_data_gas.max_price_be
//  192  felt entry_point        (invoke only: keccak("execute") & (2^250 - 1))
//  224  u16  calldata_count_be  (invoke only, 2 + 9*N felts for N calls)
//  226  felt calldata[]         (invoke only)
//
// The invoke calldata is the account's compiled `execute` calldata for N
// transfers, N in 1..kStarknetMaxCalls:
//
//   [N,
//    token_0, transfer_selector, 3, recipient_0, amount_low_0, amount_high_0,
//    ...
//    token_N-1, transfer_selector, 3, recipient_N-1, amount_low_N-1, ...,
//    3*N, recipient_0, amount_low_0, amount_high_0, ...]
//
// i.e. the call array followed by the flattened span the account slices. The
// adapter parses both copies, requires them to match felt by felt, and prints
// one row per call, so the destinations it shows are the ones the signed hash
// commits to. Only `transfer` calls are admitted: a call whose effect the device
// cannot print is refused instead of being shown as an opaque digest.
constexpr size_t kStarknetFeltSize = 32;
constexpr size_t kStarknetAddressTextSize = 67;  // "0x" + 64 hex + NUL
constexpr size_t kStarknetCommonHeaderSize = 192;
constexpr size_t kStarknetInvokeHeaderSize = 226;
constexpr size_t kStarknetDeployPayloadSize = kStarknetCommonHeaderSize;
// A v3 invoke may batch several calls. Four is what the review can print in
// full (see ChainReview); a larger batch is refused, never truncated.
constexpr size_t kStarknetMaxCalls = kChainMaxCalls;
constexpr uint8_t kStarknetDecimals = 18;
constexpr uint8_t kStarknetKindInvoke = 0;
constexpr uint8_t kStarknetKindDeploy = 1;
constexpr size_t kStarknetSignatureSize = 2 * kStarknetFeltSize;

// "0x" + 64 lowercase hex digits; leading zeros are preserved so the text is
// always 66 characters and cannot be confused with another felt.
bool starknet_felt_text(const uint8_t felt[kStarknetFeltSize], char *out,
                        size_t capacity);

// Starknet selector: keccak-256(name) with the top six bits cleared.
bool starknet_selector(const char *name, uint8_t out[kStarknetFeltSize]);

// Stark key pair for a BIP32 child: grindKey() maps the child into [1, n) and
// the public key is the x coordinate of that scalar * G.
bool starknet_key_pair(const uint8_t bip32_key[kPrivateKeySize],
                       uint8_t out_private[kStarknetFeltSize],
                       uint8_t out_public[kStarknetFeltSize]);

// SNIP-5 address of the single-key account described by the payload.
bool starknet_account_address(const uint8_t class_hash[kStarknetFeltSize],
                              const uint8_t salt[kStarknetFeltSize],
                              const uint8_t public_key[kStarknetFeltSize],
                              uint8_t out[kStarknetFeltSize]);

// Parses the payload, proves the account belongs to `bip32_key`, and returns the
// v3 transaction hash the host will submit.
ChainError starknet_review_payload(const uint8_t *payload, size_t size,
                                   const uint8_t bip32_key[kPrivateKeySize],
                                   ChainReview *review, uint8_t digest[32]);

// Rebuilds the hash from the payload and returns r || s (2 x 32 bytes).
ChainError starknet_sign_payload(const uint8_t *payload, size_t size,
                                 const uint8_t bip32_key[kPrivateKeySize],
                                 uint8_t *out, size_t *in_out_size);

bool run_starknet_self_tests();

}  // namespace hexwallet

#endif
