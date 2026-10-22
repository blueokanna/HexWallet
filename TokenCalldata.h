#ifndef HEXWALLET_TOKEN_CALLDATA_H
#define HEXWALLET_TOKEN_CALLDATA_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// EVM token calldata whitelist.
//
// Every selector in this table is recomputed at runtime from its canonical
// signature string with the firmware's own Keccak-256 and compared with the
// stored constant, so a typo in either place fails the self-test instead of
// silently signing the wrong function.
//
// A table entry describes an ABI, not permission to sign a transaction.
// Contract identity, chain, review rendering and signing policy are separate.
// Standards that are recognised but deliberately refused are enumerated in
// `EvmTokenStandard` with the reason carried by `evm_token_standard_refusal`,
// because producing calldata for an ABI this code cannot verify would be worse
// than refusing.

constexpr size_t kTokenSelectorSize = 4;
constexpr size_t kTokenWordSize = 32;
// ERC-1155 batch transfers and LayerZero OFT/ONFT carry dynamic tails; 512
// bytes covers four batch pairs plus the ABI head and padding.
constexpr size_t kTokenMaxCalldataSize = 512;
constexpr size_t kTokenMaxBatchItems = 4;
constexpr size_t kTokenMaxTailSize = 128;
constexpr size_t kTokenAddressTextSize = 43;   // 0x + 40 hex + NUL
constexpr size_t kTokenBytes32TextSize = 67;   // 0x + 64 hex + NUL

enum class EvmTokenStandard : uint8_t {
  Erc20 = 0,
  Erc721,
  Erc1155,
  Erc4626,
  Erc777,
  Erc3525,
  Erc6551,
  LayerZeroOft,
  LayerZeroOnft,
  // Recognised but deliberately refused: the ABI cannot be reviewed with the
  // data available on-device, so these never reach the selector table.
  Erc2981,
  Erc4337,
  Erc3643,
  Erc1400,
  Erc1410,
  Erc5528,
  Unknown,
};

enum class TokenFunction : uint8_t {
  Transfer = 0,
  TransferFrom,
  SafeTransferFrom,
  SafeTransferFromWithData,
  SafeBatchTransferFrom,
  SetApprovalForAll,
  Deposit,
  Mint,
  Withdraw,
  Redeem,
  Send777,
  OperatorSend,
  OftSend,
  OnftSendFrom,
  TransferValueToAddress,
  TransferValueToToken,
  Execute,
  Unknown,
};

struct TokenCalldataSelector {
  EvmTokenStandard standard;
  TokenFunction function;
  const char *signature;
  uint32_t selector;
  uint8_t argument_words;  // ABI head words after the selector
};

extern const TokenCalldataSelector kTokenCalldataSelectors[];
extern const size_t kTokenCalldataSelectorCount;

const TokenCalldataSelector *find_token_selector(EvmTokenStandard standard,
                                                 TokenFunction function);
const TokenCalldataSelector *match_token_selector(const uint8_t *data,
                                                  size_t data_size);
const char *evm_token_standard_name(EvmTokenStandard standard);
const char *token_function_name(TokenFunction function);
// Human-readable reason a standard is refused, or nullptr when supported.
const char *evm_token_standard_refusal(EvmTokenStandard standard);

struct DecodedTokenCalldata {
  EvmTokenStandard standard;
  TokenFunction function;
  const TokenCalldataSelector *selector;
  uint8_t recipient[20];        // primary receiver / `to`
  uint8_t secondary[20];        // `from`, owner, or operator depending on ABI
  uint8_t tertiary[20];         // refund address
  uint8_t payment_address[20];  // LayerZero zroPaymentAddress
  uint8_t amount[kTokenWordSize];  // full 256-bit word, big-endian
  bool amount_fits_u64;
  uint64_t amount_u64;
  bool has_token_id;
  uint8_t token_id[kTokenWordSize];
  bool has_destination_token_id;
  uint8_t destination_token_id[kTokenWordSize];
  bool has_value;          // ERC-3525 value, ERC-6551 call value
  uint8_t value[kTokenWordSize];
  bool has_min_amount;     // LayerZero OFT minAmountLD
  uint8_t min_amount[kTokenWordSize];
  bool approval_for_all;
  uint8_t batch_count;
  uint8_t batch_ids[kTokenMaxBatchItems][kTokenWordSize];
  uint8_t batch_amounts[kTokenMaxBatchItems][kTokenWordSize];
  bool has_bytes_tail;
  uint16_t bytes_tail_size;
  bool has_second_bytes_tail;
  uint16_t second_bytes_tail_size;
  // LayerZero fields. `remote_address` is the raw bytes/bytes32 payload; when
  // its leading 12 bytes are zero the peer is an EVM account.
  uint16_t remote_chain_id;
  uint32_t remote_eid;
  uint8_t remote_address[kTokenWordSize];
  uint8_t remote_address_size;
  uint8_t fee_native[kTokenWordSize];
  uint8_t fee_lz_token[kTokenWordSize];
  // ERC-6551 nested call, decoded only when the nested selector is itself on
  // the whitelist. Unreviewable nested calldata is rejected by the decoder.
  bool has_nested_call;
  uint8_t nested_target[20];
  uint8_t nested_value[kTokenWordSize];
  uint8_t nested_selector[kTokenSelectorSize];
  uint16_t nested_data_size;
  bool nested_has_token_id;
  uint8_t nested_token_id[kTokenWordSize];
};

// Build ERC-20 transfer(to, amount) calldata.
bool token_build_erc20_transfer(const uint8_t recipient[20], uint64_t amount,
                                uint8_t *out, size_t out_size);
// Build ERC-721 safeTransferFrom(from, to, tokenId) calldata.
bool token_build_erc721_safe_transfer(const uint8_t from[20], const uint8_t to[20],
                                      const uint8_t token_id[kTokenWordSize],
                                      uint8_t *out, size_t out_size);
// Build ERC-1155 safeTransferFrom(from, to, id, amount, "") calldata.
bool token_build_erc1155_safe_transfer(const uint8_t from[20], const uint8_t to[20],
                                       const uint8_t token_id[kTokenWordSize],
                                       uint64_t amount, uint8_t *out,
                                       size_t out_size);
// Build ERC-4626 deposit(assets, receiver).
bool token_build_erc4626_deposit(const uint8_t receiver[20], uint64_t assets,
                                 uint8_t *out, size_t out_size);

// Decode the implemented ABI subset with canonical, bounds-checked ABI
// traversal. Dynamic tails are accepted up to kTokenMaxTailSize and reported
// to the reviewer; ERC-6551 nested calldata must itself be whitelisted.
// Selectors shared by different standards require the typed overload.
// On failure the result is cleared and marked Unknown.
bool token_decode_calldata(const uint8_t *data, size_t data_size,
                           DecodedTokenCalldata *out);
// Use a standard from a trusted contract registry, never from host input alone.
// The untyped overload rejects selectors shared by different standards.
bool token_decode_calldata(const uint8_t *data, size_t data_size,
                           EvmTokenStandard standard, DecodedTokenCalldata *out);

bool run_token_calldata_self_tests();

}  // namespace hexwallet

#endif
