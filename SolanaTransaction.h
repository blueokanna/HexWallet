#ifndef HEXWALLET_SOLANA_TRANSACTION_H
#define HEXWALLET_SOLANA_TRANSACTION_H
#include <stddef.h>
#include <stdint.h>
#include "WalletSecurity.h"

namespace hexwallet
{
  constexpr size_t kSolanaMaxTransaction = 1232;
  constexpr size_t kSolanaMaxMessage = kSolanaMaxTransaction - 65;
  constexpr size_t kSolanaMaxTransfers = 16;
  constexpr uint64_t kSolanaBaseFee = 5000; // offline schedule assumption, not signed
  constexpr size_t kSolanaTokenSymbolSize = 12;

  enum class SolanaError : uint8_t
  {
    Ok,
    InvalidArgument,
    Malformed,
    Unsupported,
    WrongWallet,
    FeePolicy,
    CryptoFailure,
    BufferTooSmall
  };
  enum class SolanaTransferKind : uint8_t
  {
    Native,
    SplToken,
    SplToken2022
  };
  struct SolanaTransfer
  {
    uint8_t recipient[32];
    uint8_t source[32];
    uint8_t mint[32]; // zero for native SOL
    uint64_t amount;  // lamports or integer token base units, never floating point
    uint8_t decimals;
    SolanaTransferKind kind;
    // Labels from the user-declared table. Empty when the mint is unknown;
    // `token_user_declared` means the name/decimals are the owner's claim, not
    // an on-chain verification.
    char token_symbol[kSolanaTokenSymbolSize];
    bool token_user_declared;
  };
  struct SolanaTransaction
  {
    uint8_t message[kSolanaMaxMessage];
    uint16_t message_size;
    uint32_t address_index;
    uint8_t payer[32];
    uint8_t blockhash[32];
    SolanaTransfer transfers[kSolanaMaxTransfers];
    uint8_t transfer_count;
    uint64_t total_lamports;
    uint64_t priority_fee;
    uint64_t estimated_fee;
    bool version0;
  };

  SolanaError solana_review_message(const uint8_t *message, size_t size,
                                    const uint8_t payer[32], SolanaTransaction *out);
  bool solana_derive_key(const uint8_t seed[kSeedSize], uint32_t address_index,
                         uint8_t child[32]);
  bool solana_format_amount(const SolanaTransfer &transfer, char *out, size_t size);
  SolanaError solana_sign_transaction(const SolanaTransaction &reviewed,
                                      const uint8_t seed[kSeedSize], uint8_t *out, size_t *in_out_size);
  // Legacy Transfer/TransferChecked parsing, custom-label lookup, signing and
  // the rejection paths (truncation, foreign payer, changed amount).
  bool run_solana_self_tests();
}
#endif
