#ifndef HEXWALLET_TEZOS_TRANSACTION_H
#define HEXWALLET_TEZOS_TRANSACTION_H
#include <stddef.h>
#include <stdint.h>
#include "WalletSecurity.h"

namespace hexwallet {
constexpr size_t kTezosMaxOperations = 16;
constexpr size_t kTezosMaxTransaction = 1536;
constexpr size_t kTezosMaxSigned = kTezosMaxTransaction + 64;
enum class TezosError : uint8_t {
  Ok, InvalidArgument, Malformed, Unsupported, WrongWallet, InvalidAmount,
  FeePolicy, CryptoFailure, BufferTooSmall
};
struct TezosOperation {
  bool reveal;
  uint64_t fee, counter, gas_limit, storage_limit, amount;
  char recipient[37];
};
struct TezosReview {
  char source[37], public_key[55], branch[52];
  uint8_t operation_count;
  uint64_t total, total_fee, total_storage_limit;
  TezosOperation operations[kTezosMaxOperations];
};
struct TezosTransaction {
  uint8_t transaction[kTezosMaxTransaction];
  uint16_t transaction_size;
  uint32_t address_index;
  uint8_t signing_hash[32];
  TezosReview review;
};
// Preserve the existing wallet hierarchy: m/44'/1729'/account'/change'/index'.
bool tezos_derivation_path(uint32_t account, uint32_t change, uint32_t index, uint32_t out[5]);
bool tezos_derive_key(const uint8_t seed[kSeedSize], uint32_t index, uint8_t out[32]);
bool tezos_format_amount(uint64_t mutez, char *out, size_t capacity);
// Modern manager-operation encoding: optional initial Ed25519 reveal (absent
// proof), then native transfers to implicit tz1/tz2/tz3/tz4 accounts. No Michelson,
// KT1 calls, delegation, tickets or FA tokens. Branch origin is not authenticated.
TezosError tezos_review_transaction(const uint8_t *raw, size_t size,
    const uint8_t public_key[32], TezosTransaction *out);
// Ed25519 over BLAKE2b-256(0x03 || forged operation); returns raw || signature.
TezosError tezos_sign_transaction(const TezosTransaction &tx, const uint8_t seed[kSeedSize],
    uint8_t *out, size_t *in_out_size);
bool run_tezos_self_tests();
}
#endif
