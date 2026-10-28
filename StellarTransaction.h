#ifndef HEXWALLET_STELLAR_TRANSACTION_H
#define HEXWALLET_STELLAR_TRANSACTION_H
#include <stddef.h>
#include <stdint.h>
#include "WalletSecurity.h"

namespace hexwallet {
constexpr size_t kStellarMaxOperations = 8;
constexpr size_t kStellarMaxRequest = 1536;
constexpr size_t kStellarMaxEnvelope = kStellarMaxRequest + 40;
constexpr size_t kStellarAddressSize = 57;
constexpr uint64_t kStellarStroops = 10000000;
enum class StellarError : uint8_t {
  Ok, InvalidArgument, Malformed, Unsupported, WrongNetwork, WrongWallet,
  InvalidAmount, FeePolicy, CryptoFailure, BufferTooSmall
};
struct StellarOperation {
  uint32_t type; // CREATE_ACCOUNT=0, PAYMENT=1
  uint64_t amount;
  char destination[kStellarAddressSize];
  char issuer[kStellarAddressSize]; // empty for native XLM
  char asset[13];
  char amount_text[48];
};
struct StellarReview {
  char source[kStellarAddressSize];
  uint32_t fee;
  uint64_t sequence;
  uint64_t min_time;
  uint64_t max_time;
  uint32_t memo_type;
  char memo[65]; // printable ASCII text, decimal ID, or exact hex hash
  uint32_t operation_count;
  StellarOperation operations[kStellarMaxOperations];
};
struct StellarTransaction {
  uint8_t request[kStellarMaxRequest];
  uint16_t request_size;
  uint32_t address_index;
  uint8_t signing_hash[32];
  StellarReview review;
};
// SEP-0005: the link's address_index is the Stellar account index. Generic
// account/change selectors must be zero, so no two UI paths alias one key.
bool stellar_derivation_path(uint32_t index, uint32_t out[3]);
bool stellar_derive_key(const uint8_t seed[kSeedSize], uint32_t index, uint8_t out[32]);
bool stellar_address(const uint8_t public_key[32], char *out, size_t capacity);
// Input: SHA256(public-network passphrase) || unsigned TransactionEnvelope XDR.
// V1, no signatures, ordinary G accounts, bounded time conditions, up to eight
// Payment/CreateAccount operations. Unsupported unions are rejected, not skipped.
StellarError stellar_review_request(const uint8_t *data, size_t size,
    const uint8_t owner[32], StellarTransaction *out);
// Reparse, compare every displayed field and signing hash, then sign Ed25519.
// Returns the complete signed TransactionEnvelope XDR, without the network prefix.
StellarError stellar_sign_transaction(const StellarTransaction &tx,
    const uint8_t seed[kSeedSize], uint8_t *out, size_t *in_out_size);
bool run_stellar_self_tests();
}
#endif
