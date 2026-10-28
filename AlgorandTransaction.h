#ifndef HEXWALLET_ALGORAND_TRANSACTION_H
#define HEXWALLET_ALGORAND_TRANSACTION_H
#include <stddef.h>
#include <stdint.h>
#include "WalletSecurity.h"

namespace hexwallet {
constexpr size_t kAlgorandMaxTransaction = 1536;
constexpr size_t kAlgorandMaxSigned = kAlgorandMaxTransaction + 75;
constexpr size_t kAlgorandMaxNote = 1024;
constexpr size_t kAlgorandAddressSize = 59;
enum class AlgorandError : uint8_t {
  Ok, InvalidArgument, Malformed, Unsupported, WrongNetwork, WrongWallet,
  InvalidAmount, FeePolicy, CryptoFailure, BufferTooSmall
};
enum class AlgorandKind : uint8_t { Payment, AssetTransfer, AssetOptIn };
struct AlgorandReview {
  AlgorandKind kind;
  uint64_t amount;
  uint64_t asset_id;
  uint64_t fee;
  uint64_t first_valid;
  uint64_t last_valid;
  char sender[kAlgorandAddressSize];
  char recipient[kAlgorandAddressSize];
  char amount_text[64];
  char note_hex[2 * kAlgorandMaxNote + 1];
  char lease_hex[65];
};
struct AlgorandTransaction {
  uint8_t transaction[kAlgorandMaxTransaction];
  uint16_t transaction_size;
  uint32_t address_index;
  uint8_t transaction_id[32];
  AlgorandReview review;
};
// Preserve this wallet's existing ALGO SLIP-0010 path. This is a wallet key
// policy, not an assertion of Ledger/BIP32-Ed25519 seed compatibility.
bool algorand_derivation_path(uint32_t account, uint32_t change, uint32_t index, uint32_t out[5]);
bool algorand_derive_key(const uint8_t seed[kSeedSize], uint32_t index, uint8_t out[32]);
// Canonical unsigned MessagePack only; mainnet genesis hash is mandatory.
// pay/axfer, no group, rekey, close, clawback, LogicSig or application calls.
AlgorandError algorand_review_transaction(const uint8_t *data, size_t size,
    const uint8_t owner[32], AlgorandTransaction *out);
// Ed25519 signs "TX" || exact canonical transaction, not its transaction ID.
// Output is the complete canonical SignedTxn {sig, txn} MessagePack map.
AlgorandError algorand_sign_transaction(const AlgorandTransaction &tx,
    const uint8_t seed[kSeedSize], uint8_t *out, size_t *in_out_size);
bool run_algorand_self_tests();
}
#endif
