#ifndef HEXWALLET_COSMOS_TRANSACTION_H
#define HEXWALLET_COSMOS_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {

// Cosmos SDK `MsgSend` review/sign surface for ATOM, OSMO and TIA. The host
// sends a compact review payload; the device builds the exact `TxBody`,
// `AuthInfo`, `SignDoc` and `TxRaw` protobuf bytes itself, so no host-provided
// transaction structure is ever trusted.
//
// Payload v2 adds the denom being moved and an optional memo. Payload v3 adds
// several `MsgSend`s in one body.
//   * The chain's own denom (and any denom with pinned metadata) renders with
//     its symbol and precision.
//   * Any other denom is displayed verbatim and the amount stays an exact
//     base-unit integer: an issuer-defined precision cannot be verified
//     offline, so a decimal point there would be invented.
//   * The memo is shown in full or refused; it is never signed unseen.
//   * Every message is shown as its own row with its own recipient and amount,
//     and a review that cannot fit all of them is refused rather than truncated.
//
// Deliberately outside this surface: IBC packet/timeout messages,
// authz/feegrant, JSON/amino signing modes, and Any messages other than the
// bank send. Those need review semantics this firmware cannot prove offline.

constexpr size_t kCosmosMaxChainId = 32;
constexpr size_t kCosmosMaxAddress = 90;
// "ibc/" + 64 hex characters is the longest denom a bank send can carry.
constexpr size_t kCosmosMaxDenom = 68;
constexpr size_t kCosmosMaxMemo = 64;
// Bank sends per transaction. Each one costs a full review row, so the trusted
// display (16 rows) stays the hard ceiling.
constexpr size_t kCosmosMaxMessages = 4;
constexpr size_t kCosmosMaxPayload = 1024;
constexpr size_t kCosmosMaxBody = 1024;
constexpr size_t kCosmosMaxAuthInfo = 224;
constexpr size_t kCosmosMaxSignDoc = 1408;
constexpr size_t kCosmosMaxSignedTx = 1664;
constexpr size_t kCosmosAmountTextSize = 96;
constexpr size_t kCosmosSymbolSize = 16;
// A native bank send costs a few thousand base units. 10 tokens is already two
// orders of magnitude above any normal fee; a larger fee is treated as hostile.
constexpr uint64_t kCosmosMaxFee = 10000000ULL;
constexpr uint64_t kCosmosMaxGas = 2000000ULL;

enum class CosmosError : uint8_t {
  Ok = 0,
  InvalidArgument,
  Malformed,
  Unsupported,
  WrongWallet,
  InvalidAmount,
  FeePolicy,
  CryptoFailure,
  BufferTooSmall,
};

struct CosmosChainParams {
  const char *network_id;
  const char *hrp;
  const char *chain_prefix;
  const char *denom;
  const char *symbol;
  uint8_t decimals;
};

const CosmosChainParams *cosmos_chain_params(const char *network_id);

struct CosmosReview {
  const CosmosChainParams *chain;
  // One row per MsgSend. `amount` and `amount_text` are the totals the summary
  // line shows; the per-row strings are what the trusted display lists.
  uint8_t message_count;
  char to[kCosmosMaxMessages][kCosmosMaxAddress];
  uint64_t amounts[kCosmosMaxMessages];
  char amount_texts[kCosmosMaxMessages][kCosmosAmountTextSize];
  char from[kCosmosMaxAddress];
  char chain_id[kCosmosMaxChainId + 1];
  // Denom actually moved by the message, and the memo committed to TxBody.
  char denom[kCosmosMaxDenom + 1];
  char memo[kCosmosMaxMemo + 1];
  bool has_memo;
  // True only when symbol/decimals come from pinned metadata for this denom.
  bool denom_registered;
  char symbol[kCosmosSymbolSize];
  uint8_t decimals;
  uint64_t account_number;
  uint64_t sequence;
  uint64_t amount;  // sum of every message amount
  uint64_t fee;
  uint64_t gas_limit;
  uint8_t public_key[kCompressedPublicKeySize];
  uint8_t tx_body[kCosmosMaxBody];
  uint16_t tx_body_size;
  uint8_t auth_info[kCosmosMaxAuthInfo];
  uint16_t auth_info_size;
  uint8_t sign_doc_digest[kSha256Size];
  char amount_text[kCosmosAmountTextSize];
  char fee_text[kCosmosAmountTextSize];
};

struct CosmosTransaction {
  CosmosReview review;
  uint32_t address_index;
};

// Validates the payload, the chain-id prefix, the recipient bech32 address and
// the wallet's own address/public-key binding, then builds the protobuf
// transaction and its SignDoc digest. Never signs.
CosmosError cosmos_review_payload(
    const uint8_t *payload, size_t size, const CosmosChainParams &chain,
    const char *from_address,
    const uint8_t public_key[kCompressedPublicKeySize], CosmosTransaction *out);

// Recomputes the SignDoc digest from the stored bytes, signs it with low-S
// secp256k1 and emits the complete TxRaw protobuf for broadcast by the phone.
CosmosError cosmos_sign_transaction(const CosmosTransaction &transaction,
                                    const uint8_t private_key[kPrivateKeySize],
                                    uint8_t *out, size_t *in_out_size);

bool cosmos_format_amount(uint64_t amount, uint8_t decimals,
                          const char *symbol, char *out, size_t size);
// Exact base-unit rendering for a denom whose precision is not pinned.
bool cosmos_format_base_units(uint64_t amount, const char *denom, char *out,
                              size_t size);
void clear_cosmos_transaction(CosmosTransaction *transaction);
const char *cosmos_error_text(CosmosError error);
bool run_cosmos_self_tests();
// Signs every pinned Cosmos vector and compares the complete TxRaw bytes, plus
// the wrong-key refusal. Requires real secp256k1: the device and the chain probe
// (which links the firmware crypto) run this; the stubbed host harness does not.
bool run_cosmos_signature_self_test();

}  // namespace hexwallet

#endif
