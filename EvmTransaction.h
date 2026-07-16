#ifndef HEXWALLET_EVM_TRANSACTION_H
#define HEXWALLET_EVM_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "WalletEngine.h"
#include "WalletTokens.h"

namespace hexwallet {

constexpr size_t kEvmAddressSize = 20;
constexpr size_t kEvmUint256Size = 32;
constexpr size_t kEvmMaxDataSize = 68;
constexpr size_t kEvmMaxUnsignedTransactionSize = 256;
constexpr size_t kEvmMaxSignedTransactionSize = 384;
constexpr size_t kEvmAmountTextSize = 96;

enum class EvmTransactionType : uint8_t {
  LegacyEip155,
  Eip1559,
};

enum class EvmTransactionError : uint8_t {
  Ok = 0,
  InvalidArgument,
  Truncated,
  NonCanonical,
  Unsupported,
  WrongNetwork,
  WrongWallet,
  InvalidAmount,
  FeePolicy,
  CryptoFailure,
  BufferTooSmall,
};

struct EvmSigningRequest {
  EvmTransactionType type;
  const NetworkProfile *network;
  const TokenProfile *token;
  uint32_t address_index;
  uint64_t nonce;
  uint64_t gas_limit;
  uint64_t gas_price_or_max_fee;
  uint64_t max_priority_fee;
  uint64_t maximum_fee;
  uint8_t contract[kEvmAddressSize];
  uint8_t recipient[kEvmAddressSize];
  uint8_t amount[kEvmUint256Size];
  uint8_t data[kEvmMaxDataSize];
  uint8_t data_size;
  uint8_t unsigned_transaction[kEvmMaxUnsignedTransactionSize];
  uint16_t unsigned_transaction_size;
  uint8_t signing_hash[kKeccak256Size];
  uint8_t request_hash[kSha256Size];
  char from_address[kAddressTextSize];
  char recipient_address[kAddressTextSize];
  char amount_text[kEvmAmountTextSize];
  char maximum_fee_text[kEvmAmountTextSize];
};

EvmTransactionError evm_parse_transaction(const uint8_t *transaction,
                                          size_t transaction_size,
                                          const NetworkProfile &network,
                                          const HdPrivateNode &master,
                                          uint32_t address_index,
                                          EvmSigningRequest *out);
EvmTransactionError evm_sign_transaction(const EvmSigningRequest &request,
                                         const HdPrivateNode &master,
                                         uint8_t *out_transaction,
                                         size_t *in_out_size);
const char *evm_transaction_error_text(EvmTransactionError error);
void clear_evm_request(EvmSigningRequest *request);
bool run_evm_transaction_self_test();

}  // namespace hexwallet

#endif
