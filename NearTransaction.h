#ifndef HEXWALLET_NEAR_TRANSACTION_H
#define HEXWALLET_NEAR_TRANSACTION_H
#include <stddef.h>
#include <stdint.h>
#include "WalletSecurity.h"
namespace hexwallet {
constexpr size_t kNearMaxActions = 16;
constexpr size_t kNearMaxTransaction = 512;
constexpr size_t kNearMaxSigned = kNearMaxTransaction + 65;
enum class NearError : uint8_t {
  Ok, InvalidArgument, Malformed, Unsupported, WrongWallet, InvalidAmount,
  CryptoFailure, BufferTooSmall
};
struct NearReview {
  char signer[65];
  char receiver[65];
  char public_key[53]; // ed25519: + base58 + NUL
  char block_hash[45];
  uint64_t nonce;
  uint32_t action_count;
  uint8_t amounts[kNearMaxActions][16]; // unsigned little endian yoctoNEAR
  uint8_t total[16];
  char total_text[72];
};
struct NearTransaction {
  uint8_t transaction[kNearMaxTransaction];
  uint16_t transaction_size;
  uint32_t address_index;
  uint8_t signing_hash[32];
  NearReview review;
};
// near-slip10 default hierarchy, with account index replacing the last zero.
bool near_derivation_path(uint32_t index, uint32_t out[3]);
bool near_derive_key(const uint8_t seed[kSeedSize], uint32_t index, uint8_t out[32]);
bool near_implicit_address(const uint8_t public_key[32], char *out, size_t capacity);
bool near_format_amount(const uint8_t amount[16], char *out, size_t capacity);
// Borsh TransactionV0, Ed25519, 1..16 native Transfer actions. No named-account
// ownership or block-hash network assertion is made without authenticated state.
NearError near_review_transaction(const uint8_t *data, size_t size,
    const uint8_t owner[32], NearTransaction *out);
NearError near_sign_transaction(const NearTransaction &tx, const uint8_t seed[kSeedSize],
    uint8_t *out, size_t *in_out_size);
bool run_near_self_tests();
}
#endif
