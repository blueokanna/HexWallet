#ifndef HEXWALLET_EVM_TRANSACTION_H
#define HEXWALLET_EVM_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "TokenCalldata.h"
#include "WalletEngine.h"
#include "WalletTokens.h"

namespace hexwallet
{

  constexpr size_t kEvmAddressSize = 20;
  constexpr size_t kEvmUint256Size = 32;
  constexpr size_t kEvmMaxDataSize = 1024;
  constexpr size_t kEvmMaxUnsignedTransactionSize = 1536;
  constexpr size_t kEvmMaxSignedTransactionSize = 1664;
  constexpr size_t kEvmAmountTextSize = 96;
  constexpr size_t kEvmBytes32TextSize = kTokenBytes32TextSize;
  constexpr size_t kEvmMaxAccessListBytes = 384;
  constexpr size_t kEvmMaxAccessListAddresses = 8;
  constexpr size_t kEvmMaxAccessListKeys = 8;
  constexpr size_t kEvmAccessListTextSize = 1400;
  constexpr size_t kEvmReviewTextSize = 4096;

  enum class EvmTransactionType : uint8_t
  {
    LegacyEip155,
    Eip1559,
    Eip2930,
  };

  enum class EvmTransactionError : uint8_t
  {
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

  struct EvmSigningRequest
  {
    EvmTransactionType type;
    bool opaque;
    bool contract_creation;
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
    // Canonical RLP list payload, without its outer prefix. Preserve order and
    // duplicates: EIP-2930 charges each occurrence and signs the exact list.
    uint8_t access_list[kEvmMaxAccessListBytes];
    uint16_t access_list_size;
    uint8_t access_list_addresses;
    uint8_t access_list_keys;
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
                                            EvmSigningRequest *out,
                                            bool opaque_review = false);
  // Try the registered decoder first; unsupported semantics use a raw-byte
  // review. Malformed envelopes, wrong networks and fee violations never fall back.
  EvmTransactionError evm_parse_for_review(const uint8_t *transaction, size_t size,
                                           const NetworkProfile &network, const HdPrivateNode &master,
                                           uint32_t address_index, EvmSigningRequest *out);
  const char *evm_operation_text(const EvmSigningRequest &request);
  bool evm_review_amount(const EvmSigningRequest &request, const char *asset, char *out, size_t capacity);
  EvmTransactionError evm_sign_transaction(const EvmSigningRequest &request,
                                           const HdPrivateNode &master,
                                           uint8_t *out_transaction,
                                           size_t *in_out_size);
  const char *evm_transaction_error_text(EvmTransactionError error);
  void clear_evm_request(EvmSigningRequest *request);
  bool evm_access_list_details(const EvmSigningRequest &request, char *out, size_t size);
  bool evm_review_details(const EvmSigningRequest &request, char *out, size_t size);
  const char *evm_transaction_type_text(EvmTransactionType type);
  bool run_evm_transaction_self_test();

}

#endif
