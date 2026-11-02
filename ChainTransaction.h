#ifndef HEXWALLET_CHAIN_TRANSACTION_H
#define HEXWALLET_CHAIN_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet
{
  constexpr size_t kChainMaxPayload = 2048;
  // Shelley base addresses are 103 chars; QRL v2 is 'Q' + 128 hex digits.
  constexpr size_t kChainMaxAddress = 136;
  constexpr size_t kChainMaxAmount = 64;
  constexpr size_t kChainMaxFee = 64;
  // QRL v2 needs six labelled lines (chain id, nonce, gas, tip, access list,
  // digest); every other adapter stays well below this.
  constexpr size_t kChainMaxExtra = 256;

  enum class ChainFamily : uint8_t
  {
    None = 0,
    VeChain,
    Icon,
    Nem,
    Hive,
    Lisk,
    Sui,
    Flow,
    Filecoin,
    Siacoin,
    Ckb,
    Ton,
    Decred,
    Cardano,
    Polkadot,
    Kusama,
    Ergo,
    Hedera,
    Chia,
    InternetComputer,
    Qrl,
    Aptos,
    QrlV2,
    Starknet,
    Theta,
  };

  enum class ChainError : uint8_t
  {
    Ok = 0,
    InvalidArgument,
    Malformed,
    Unsupported,
    WrongNetwork,
    WrongWallet,
    InvalidAmount,
    FeePolicy,
    CryptoFailure,
    BufferTooSmall,
    StorageUnavailable,
    RuntimeMismatch,
  };

  // Chains whose single transaction carries several independently reviewed
  // destinations (Starknet `execute` batches) fill this list instead of
  // squeezing every call into the free-form `extra` text. A call larger than
  // these bounds is refused rather than truncated: an address the device cannot
  // print in full is an address the user cannot check.
  constexpr size_t kChainMaxCalls = 4;
  constexpr size_t kChainCallAddressSize = 72;  // 0x + 64 hex + NUL
  constexpr size_t kChainCallAmountSize = 48;

  struct ChainCallSummary
  {
    char target[kChainCallAddressSize];    // contract that receives the call
    char recipient[kChainCallAddressSize]; // value destination, if it has one
    char amount[kChainCallAmountSize];     // formatted amount, symbol included
    // The amount used a token record the user added on the device. The signed
    // bytes never depend on it, so the review must say where the label came from.
    bool declared;
  };

  struct ChainReview
  {
    char symbol[8];
    char sender[kChainMaxAddress];
    char recipient[kChainMaxAddress];
    char amount[kChainMaxAmount];
    char fee[kChainMaxFee];
    char extra[kChainMaxExtra];
    uint8_t call_count;
    ChainCallSummary calls[kChainMaxCalls];
  };

  struct ChainTransaction
  {
    ChainFamily family;
    uint32_t address_index;
    uint8_t payload[kChainMaxPayload];
    uint16_t payload_size;
    uint8_t digest[32];
    ChainReview review;
  };

  bool chain_family_for_network(const char *network_id, ChainFamily *out);
  const char *chain_family_network_id(ChainFamily family);
  const char *chain_family_name(ChainFamily family);
  const char *chain_error_text(ChainError error);

  // Derives the wallet address, parses the adapter payload and fills the review.
  // No signing happens here. `seed` is needed by the Ed25519 adapters.
  ChainError chain_review_transaction(ChainFamily family, const uint8_t *payload,
                                      size_t size, const HdPrivateNode &master,
                                      const uint8_t *seed, uint32_t address_index,
                                      ChainTransaction *out);
  // Re-reviews the stored payload, refuses any field mismatch, then signs the
  // canonical digest. The output is adapter specific (signature or signed tx).
  ChainError chain_sign_transaction(const ChainTransaction &transaction,
                                    const HdPrivateNode &master,
                                    const uint8_t *seed, uint8_t *out,
                                    size_t *in_out_size);

  bool run_chain_self_tests();

  // Prints one labelled line per chain family; defined in host builds only.
  void report_chain_self_tests();

} // namespace hexwallet

#endif
