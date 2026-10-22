#ifndef HEXWALLET_EVM_TRANSACTION_H
#define HEXWALLET_EVM_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "TokenCalldata.h"
#include "WalletEngine.h"
#include "WalletTokens.h"

namespace hexwallet {

constexpr size_t kEvmAddressSize = 20;
constexpr size_t kEvmUint256Size = 32;
constexpr size_t kEvmMaxDataSize = kTokenMaxCalldataSize;
constexpr size_t kEvmMaxUnsignedTransactionSize = 768;
constexpr size_t kEvmMaxSignedTransactionSize = 896;
constexpr size_t kEvmAmountTextSize = 96;
constexpr size_t kEvmBytes32TextSize = kTokenBytes32TextSize;

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
  uint16_t data_size;
  // Native value carried by a payable contract call (OFT/ONFT LayerZero fee,
  // ERC-6551 call value). ERC-20/721/1155/3525/4626/777 calls must leave it 0.
  uint8_t native_value[kEvmUint256Size];
  bool has_native_value;
  DecodedTokenCalldata call;
  bool has_call;
  uint8_t unsigned_transaction[kEvmMaxUnsignedTransactionSize];
  uint16_t unsigned_transaction_size;
  uint8_t signing_hash[kKeccak256Size];
  uint8_t request_hash[kSha256Size];
  char from_address[kAddressTextSize];
  char recipient_address[kAddressTextSize];
  char amount_text[kEvmAmountTextSize];
  char token_id_text[kEvmAmountTextSize];
  char value_text[kEvmAmountTextSize];
  char min_amount_text[kEvmAmountTextSize];
  char native_value_text[kEvmAmountTextSize];
  char remote_address_text[kEvmBytes32TextSize];
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
