#ifndef HEXWALLET_COSMOS_TRANSACTION_H
#define HEXWALLET_COSMOS_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "WalletEngine.h"

namespace hexwallet {

// Cosmos SDK staking delegation with SIGN_MODE_DIRECT.
//
// The signed artifact is the protobuf SignDoc; the digest is SHA-256 over its
// bytes and the signature is secp256k1 ECDSA (r || s), matching
// cosmos.crypto.secp256k1. Field numbers and the tag order below were verified
// byte-for-byte against a prost encoder using the same message definitions.

constexpr size_t kCosmosMaxTypeUrlSize = 64;
constexpr size_t kCosmosMaxBech32Size = 128;
constexpr size_t kCosmosMaxDenomSize = 32;
constexpr size_t kCosmosMaxAmountTextSize = 32;
constexpr size_t kCosmosMaxSignDocSize = 512;

enum class CosmosError : uint8_t {
  Ok = 0,
  InvalidArgument,
  Unsupported,
  InvalidAddress,
  InvalidAmount,
  BufferTooSmall,
  CryptoFailure,
};

struct CosmosDelegateRequest {
  char chain_id[kCosmosMaxDenomSize];
  char delegator[kCosmosMaxBech32Size];
  char validator[kCosmosMaxBech32Size];
  char denom[kCosmosMaxDenomSize];
  char amount[kCosmosMaxAmountTextSize];
  char fee_denom[kCosmosMaxDenomSize];
  char fee_amount[kCosmosMaxAmountTextSize];
  uint64_t gas_limit;
  uint64_t account_number;
  uint64_t sequence;
  uint8_t public_key[kCompressedPublicKeySize];
};

struct CosmosSignedTransaction {
  uint8_t sign_doc[kCosmosMaxSignDocSize];
  uint16_t sign_doc_size;
  uint8_t digest[kSha256Size];
};

// Assemble the SignDoc for MsgDelegate and hash it. The caller signs `digest`
// with the account key and appends (r || s) inside TxRaw.signatures when
// broadcasting over gRPC.
CosmosError cosmos_delegate_sign_doc(const CosmosDelegateRequest &request,
                                     CosmosSignedTransaction *out);

const char *cosmos_error_text(CosmosError error);
void clear_cosmos_request(CosmosDelegateRequest *request);
bool run_cosmos_self_tests();

}  // namespace hexwallet

#endif
