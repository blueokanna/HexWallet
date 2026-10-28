#ifndef HEXWALLET_COSMOS_TRANSACTION_H
#define HEXWALLET_COSMOS_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {

// Cosmos SDK `MsgSend` review/sign surface for the native denom of ATOM, OSMO
// and TIA. The host sends a compact review payload; the device builds the
// exact `TxBody`, `AuthInfo`, `SignDoc` and `TxRaw` protobuf bytes itself, so
// no host-provided transaction structure is ever trusted.
//
// Deliberately outside this surface: IBC transfers, multiple messages, memo,
// authz/feegrant, Any messages other than the native bank send, and any denom
// other than the chain's native one. Those require review semantics this
// firmware cannot prove offline.

constexpr size_t kCosmosMaxChainId = 32;
constexpr size_t kCosmosMaxAddress = 90;
constexpr size_t kCosmosMaxPayload = 256;
constexpr size_t kCosmosMaxBody = 384;
constexpr size_t kCosmosMaxAuthInfo = 224;
constexpr size_t kCosmosMaxSignDoc = 512;
constexpr size_t kCosmosMaxSignedTx = 768;
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
  char from[kCosmosMaxAddress];
  char to[kCosmosMaxAddress];
  char chain_id[kCosmosMaxChainId + 1];
  uint64_t account_number;
  uint64_t sequence;
  uint64_t amount;
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
void clear_cosmos_transaction(CosmosTransaction *transaction);
const char *cosmos_error_text(CosmosError error);
bool run_cosmos_self_tests();

}  // namespace hexwallet

#endif
