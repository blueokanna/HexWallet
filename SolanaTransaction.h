#ifndef HEXWALLET_SOLANA_TRANSACTION_H
#define HEXWALLET_SOLANA_TRANSACTION_H
#include <stddef.h>
#include <stdint.h>
#include "WalletSecurity.h"

namespace hexwallet {
constexpr size_t kSolanaMaxTransaction = 1232;
constexpr size_t kSolanaMaxMessage = kSolanaMaxTransaction - 65;
constexpr size_t kSolanaMaxTransfers = 16;
constexpr uint64_t kSolanaBaseFee = 5000; // offline schedule assumption, not signed

enum class SolanaError : uint8_t {
  Ok, InvalidArgument, Malformed, Unsupported, WrongWallet, FeePolicy,
  CryptoFailure, BufferTooSmall
};
// SplToken2022 is the same TransferChecked instruction executed by the
// Token-2022 program. Mint extensions (transfer fee, transfer hook) cannot be
// inspected offline, so the review always carries an explicit warning and any
// instruction that needs extra hook accounts is refused.
enum class SolanaTransferKind : uint8_t { Native, SplToken, SplToken2022 };
struct SolanaTransfer {
  // For SPL these are token accounts, NOT their wallet owners. No host-supplied
  // account state or token name is trusted by this interface.
  uint8_t recipient[32];
  uint8_t source[32];
  uint8_t mint[32]; // zero for native SOL
  uint64_t amount; // lamports or integer token base units, never floating point
  uint8_t decimals;
  SolanaTransferKind kind;
};
struct SolanaTransaction {
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

// SystemProgram::Transfer and SPL Token / Token-2022 TransferChecked, optionally
// preceded by exactly one CU limit and CU price. One signer/payer. Legacy and
// v0 with no address lookup tables. Account creation is rejected. Never
// consumes a host-provided amount, fee estimate or decoded instruction.
SolanaError solana_review_message(const uint8_t *message, size_t size,
    const uint8_t payer[32], SolanaTransaction *out);
bool solana_derive_key(const uint8_t seed[kSeedSize], uint32_t address_index,
                       uint8_t child[32]);
// Exact, bounded display formatting, including decimals > 19. No token symbols
// from the host. Returns false (and clears output) rather than truncating.
bool solana_format_amount(const SolanaTransfer &transfer, char *out, size_t size);
// Revalidates the message and the reviewed summary before signing. Returns
// shortvec(1) || Ed25519 signature || the exact reviewed message.
SolanaError solana_sign_transaction(const SolanaTransaction &reviewed,
    const uint8_t seed[kSeedSize], uint8_t *out, size_t *in_out_size);
}
#endif
