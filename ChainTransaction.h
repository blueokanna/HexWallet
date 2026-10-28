#ifndef HEXWALLET_CHAIN_TRANSACTION_H
#define HEXWALLET_CHAIN_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet {

// Shared envelope for the account-model adapters that do not have a dedicated
// WalletSigningKind. Each adapter keeps its own strict payload parser; this
// structure only stores the reviewed bytes, the signing digest and the fields
// the trusted display is allowed to show.
constexpr size_t kChainMaxPayload = 2048;
constexpr size_t kChainMaxAddress = 128;  // Shelley base addresses have 103 chars.
constexpr size_t kChainMaxAmount = 64;
constexpr size_t kChainMaxFee = 64;
constexpr size_t kChainMaxExtra = 192;

enum class ChainFamily : uint8_t {
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
};

enum class ChainError : uint8_t {
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
};

struct ChainReview {
  char symbol[8];
  char sender[kChainMaxAddress];
  char recipient[kChainMaxAddress];
  char amount[kChainMaxAmount];
  char fee[kChainMaxFee];
  char extra[kChainMaxExtra];
};

struct ChainTransaction {
  ChainFamily family;
  uint32_t address_index;
  uint8_t payload[kChainMaxPayload];
  uint16_t payload_size;
  uint8_t digest[32];
  ChainReview review;
};

// Maps a catalog network id to the adapter that owns it. Firo, Qtum and Flux
// are deliberately absent: they are served by the Bitcoin and Zcash engines.
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

}  // namespace hexwallet

#endif
