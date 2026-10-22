#include "TokenCalldata.h"

#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {

// Published selectors, cross-checked against the canonical signature strings by
// run_token_calldata_self_tests(). `argument_words` is the ABI head width after
// the selector, including offset words for dynamic arguments. Dynamic tails and
// arrays are validated separately with canonical offset checks.
const TokenCalldataSelector kTokenCalldataSelectors[] = {
  { EvmTokenStandard::Erc20, TokenFunction::Transfer,
    "transfer(address,uint256)", 0xa9059cbb, 2 },
  { EvmTokenStandard::Erc20, TokenFunction::TransferFrom,
    "transferFrom(address,address,uint256)", 0x23b872dd, 3 },
  { EvmTokenStandard::Erc721, TokenFunction::TransferFrom,
    "transferFrom(address,address,uint256)", 0x23b872dd, 3 },
  { EvmTokenStandard::Erc721, TokenFunction::SafeTransferFrom,
    "safeTransferFrom(address,address,uint256)", 0x42842e0e, 3 },
  { EvmTokenStandard::Erc721, TokenFunction::SafeTransferFromWithData,
    "safeTransferFrom(address,address,uint256,bytes)", 0xb88d4fde, 4 },
  { EvmTokenStandard::Erc721, TokenFunction::SetApprovalForAll,
    "setApprovalForAll(address,bool)", 0xa22cb465, 2 },
  { EvmTokenStandard::Erc1155, TokenFunction::SafeTransferFrom,
    "safeTransferFrom(address,address,uint256,uint256,bytes)", 0xf242432a, 5 },
  { EvmTokenStandard::Erc1155, TokenFunction::SafeBatchTransferFrom,
    "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)", 0x2eb2c2d6, 5 },
  { EvmTokenStandard::Erc4626, TokenFunction::Deposit,
    "deposit(uint256,address)", 0x6e553f65, 2 },
  { EvmTokenStandard::Erc4626, TokenFunction::Mint,
    "mint(uint256,address)", 0x94bf804d, 2 },
  { EvmTokenStandard::Erc4626, TokenFunction::Withdraw,
    "withdraw(uint256,address,address)", 0xb460af94, 3 },
  { EvmTokenStandard::Erc4626, TokenFunction::Redeem,
    "redeem(uint256,address,address)", 0xba087652, 3 },
  { EvmTokenStandard::Erc777, TokenFunction::Send777,
    "send(address,uint256,bytes)", 0x9bd9bbc6, 3 },
  { EvmTokenStandard::Erc777, TokenFunction::OperatorSend,
    "operatorSend(address,address,uint256,bytes,bytes)", 0x62ad1b83, 5 },
  { EvmTokenStandard::Erc3525, TokenFunction::TransferValueToAddress,
    "transferFrom(uint256,address,uint256)", 0x0f485c02, 3 },
  { EvmTokenStandard::Erc3525, TokenFunction::TransferValueToToken,
    "transferFrom(uint256,uint256,uint256)", 0x310ed7f0, 3 },
  { EvmTokenStandard::Erc6551, TokenFunction::Execute,
    "execute(address,uint256,bytes,uint8)", 0x51945447, 4 },
  { EvmTokenStandard::LayerZeroOft, TokenFunction::OftSend,
    "send((uint32,bytes32,uint256,uint256,bytes,bytes,bytes),(uint256,uint256),address)",
    0xc7c7f5b3, 4 },
  { EvmTokenStandard::LayerZeroOft, TokenFunction::OnftSendFrom,
    "sendFrom(address,uint16,bytes,uint256,address,address,bytes)",
    0x51905636, 7 },
  { EvmTokenStandard::LayerZeroOnft, TokenFunction::OnftSendFrom,
    "sendFrom(address,uint16,bytes,uint256,address,address,bytes)",
    0x51905636, 7 },
  { EvmTokenStandard::LayerZeroOnft, TokenFunction::OnftSendFrom,
    "sendFrom(address,uint16,bytes,uint256,uint256,address,address,bytes)",
    0x4db8226a, 8 },
};

const size_t kTokenCalldataSelectorCount =
    sizeof(kTokenCalldataSelectors) / sizeof(kTokenCalldataSelectors[0]);

namespace {

bool store_word(uint8_t *out, const uint8_t value[kTokenWordSize]) {
  memcpy(out, value, kTokenWordSize);
  return true;
}

bool store_u64_word(uint8_t *out, uint64_t value) {
  memset(out, 0, kTokenWordSize);
  for (uint8_t index = 0; index < 8; ++index) {
    out[kTokenWordSize - 1 - index] = static_cast<uint8_t>(value >> (8 * index));
  }
  return true;
}

bool store_address_word(uint8_t *out, const uint8_t address[20]) {
  memset(out, 0, kTokenWordSize);
  memcpy(out + kTokenWordSize - 20, address, 20);
  return true;
}

void store_selector(uint8_t *out, uint32_t selector) {
  out[0] = static_cast<uint8_t>(selector >> 24);
  out[1] = static_cast<uint8_t>(selector >> 16);
  out[2] = static_cast<uint8_t>(selector >> 8);
  out[3] = static_cast<uint8_t>(selector);
}

// An ABI address word must have its top 12 bytes zero, otherwise the calldata
// is not a plain address and must not be displayed as one.
bool read_address_word(const uint8_t *word, uint8_t out[20]) {
  for (uint8_t index = 0; index < 12; ++index) {
    if (word[index] != 0) return false;
  }
  memcpy(out, word + 12, 20);
  return true;
}

bool word_to_u64(const uint8_t word[kTokenWordSize], uint64_t *out) {
  for (uint8_t index = 0; index < 24; ++index) {
    if (word[index] != 0) return false;
  }
  uint64_t value = 0;
  for (uint8_t index = 24; index < 32; ++index) {
    value = (value << 8) | word[index];
  }
  *out = value;
  return true;
}

bool word_to_u32(const uint8_t word[kTokenWordSize], uint32_t *out) {
  uint64_t value = 0;
  if (!word_to_u64(word, &value) || value > 0xffffffffULL) return false;
  *out = static_cast<uint32_t>(value);
  return true;
}

bool is_zero_bytes(const uint8_t *data, size_t size) {
  for (size_t index = 0; index < size; ++index) {
    if (data[index] != 0) return false;
  }
  return true;
}

size_t padded_word_size(size_t size) {
  return (size + kTokenWordSize - 1) & ~(kTokenWordSize - 1);
}

// Read a dynamic `bytes`/array tail whose offset word lives at
// `offset_word_index` in the ABI head. The offset must be the canonical one
// produced by Solidity encoders; non-canonical aliases are rejected instead of
// being silently normalised. `end` is the first byte after the padded tail.
bool read_tail(const uint8_t *arguments, size_t arguments_size,
               size_t offset_word_index, size_t expected_offset,
               size_t maximum_size, const uint8_t **data, size_t *size,
               size_t *end) {
  if (arguments == nullptr || data == nullptr || size == nullptr || end == nullptr ||
      (expected_offset % kTokenWordSize) != 0 ||
      offset_word_index >= expected_offset / kTokenWordSize ||
      expected_offset + kTokenWordSize > arguments_size) {
    return false;
  }
  uint64_t offset = 0;
  uint64_t length = 0;
  if (!word_to_u64(arguments + offset_word_index * kTokenWordSize, &offset) ||
      offset != expected_offset ||
      !word_to_u64(arguments + expected_offset, &length) ||
      length > maximum_size ||
      length > arguments_size - expected_offset - kTokenWordSize) {
    return false;
  }
  const size_t padded = padded_word_size(static_cast<size_t>(length));
  if (padded > arguments_size - expected_offset - kTokenWordSize) return false;
  if (!is_zero_bytes(arguments + expected_offset + kTokenWordSize +
                         static_cast<size_t>(length),
                     padded - static_cast<size_t>(length))) return false;
  *data = arguments + expected_offset + kTokenWordSize;
  *size = static_cast<size_t>(length);
  *end = expected_offset + kTokenWordSize + padded;
  return true;
}

// Read a uint256[] tail. The ABI length word is an element count, not a byte
// count, so it must not be run through the bytes padding logic.
bool read_word_array(const uint8_t *arguments, size_t arguments_size,
                     size_t offset_word_index, size_t expected_offset,
                     size_t maximum_items, const uint8_t **data,
                     size_t *count, size_t *end) {
  if (arguments == nullptr || data == nullptr || count == nullptr || end == nullptr ||
      (expected_offset % kTokenWordSize) != 0 ||
      offset_word_index >= expected_offset / kTokenWordSize ||
      expected_offset + kTokenWordSize > arguments_size) {
    return false;
  }
  uint64_t offset = 0;
  uint64_t items = 0;
  if (!word_to_u64(arguments + offset_word_index * kTokenWordSize, &offset) ||
      offset != expected_offset ||
      !word_to_u64(arguments + expected_offset, &items) ||
      items == 0 || items > maximum_items ||
      items > (arguments_size - expected_offset - kTokenWordSize) / kTokenWordSize) {
    return false;
  }
  *data = arguments + expected_offset + kTokenWordSize;
  *count = static_cast<size_t>(items);
  *end = expected_offset + kTokenWordSize + static_cast<size_t>(items) * kTokenWordSize;
  return true;
}

// A LayerZero peer is a raw bytes/bytes32 value. If it is a left-padded EVM
// address, expose it as one; otherwise keep the full 32-byte payload.
bool store_remote_address(const uint8_t *data, size_t size,
                          DecodedTokenCalldata *out) {
  if (data == nullptr || out == nullptr || size == 0 || size > kTokenWordSize) {
    return false;
  }
  memset(out->remote_address, 0, sizeof(out->remote_address));
  memcpy(out->remote_address + sizeof(out->remote_address) - size, data, size);
  out->remote_address_size = static_cast<uint8_t>(size);
  return true;
}

bool read_remote_address(const uint8_t *word, DecodedTokenCalldata *out) {
  if (out == nullptr) return false;
  memcpy(out->remote_address, word, kTokenWordSize);
  out->remote_address_size = 32;
  return true;
}

// A LayerZero peer may be an ABI-encoded EVM address (either a 20-byte bytes
// value or a left-padded bytes32). Only that shape can populate the EVM
// recipient field used by the review screen.
void set_recipient_from_remote(DecodedTokenCalldata *out) {
  if (out == nullptr) return;
  // store_remote_address() right-aligns short peers into the bytes32 field.
  if (out->remote_address_size == 20 ||
      (out->remote_address_size == kTokenWordSize &&
       is_zero_bytes(out->remote_address, 12))) {
    memcpy(out->recipient, out->remote_address + 12, sizeof(out->recipient));
  }
}

}  // namespace

const TokenCalldataSelector *find_token_selector(EvmTokenStandard standard,
                                                 TokenFunction function) {
  for (size_t index = 0; index < kTokenCalldataSelectorCount; ++index) {
    if (kTokenCalldataSelectors[index].standard == standard &&
        kTokenCalldataSelectors[index].function == function) {
      return &kTokenCalldataSelectors[index];
    }
  }
  return nullptr;
}

const TokenCalldataSelector *match_token_selector(const uint8_t *data,
                                                  size_t data_size) {
  if (data == nullptr || data_size < kTokenSelectorSize) return nullptr;
  const uint32_t selector = (static_cast<uint32_t>(data[0]) << 24) |
                            (static_cast<uint32_t>(data[1]) << 16) |
                            (static_cast<uint32_t>(data[2]) << 8) |
                            static_cast<uint32_t>(data[3]);
  const TokenCalldataSelector *match = nullptr;
  for (size_t index = 0; index < kTokenCalldataSelectorCount; ++index) {
    const TokenCalldataSelector &candidate = kTokenCalldataSelectors[index];
    if (candidate.selector != selector) continue;
    if (match == nullptr) {
      match = &candidate;
      continue;
    }
    // Shared selectors require trusted contract context, even if ABI types match.
    return nullptr;
  }
  return match;
}

const char *evm_token_standard_name(EvmTokenStandard standard) {
  switch (standard) {
    case EvmTokenStandard::Erc20: return "ERC-20";
    case EvmTokenStandard::Erc721: return "ERC-721";
    case EvmTokenStandard::Erc1155: return "ERC-1155";
    case EvmTokenStandard::Erc4626: return "ERC-4626";
    case EvmTokenStandard::Erc777: return "ERC-777";
    case EvmTokenStandard::Erc3525: return "ERC-3525";
    case EvmTokenStandard::Erc6551: return "ERC-6551";
    case EvmTokenStandard::Erc2981: return "ERC-2981";
    case EvmTokenStandard::Erc4337: return "ERC-4337";
    case EvmTokenStandard::Erc3643: return "ERC-3643";
    case EvmTokenStandard::Erc1400: return "ERC-1400";
    case EvmTokenStandard::Erc1410: return "ERC-1410";
    case EvmTokenStandard::Erc5528: return "ERC-5528";
    case EvmTokenStandard::LayerZeroOft: return "LayerZero OFT";
    case EvmTokenStandard::LayerZeroOnft: return "LayerZero ONFT";
    case EvmTokenStandard::Unknown: return "unknown";
  }
  return "unknown";
}

const char *token_function_name(TokenFunction function) {
  switch (function) {
    case TokenFunction::Transfer: return "transfer";
    case TokenFunction::TransferFrom: return "transferFrom";
    case TokenFunction::SafeTransferFrom: return "safeTransferFrom";
    case TokenFunction::SafeTransferFromWithData: return "safeTransferFrom(with-data)";
    case TokenFunction::SafeBatchTransferFrom: return "safeBatchTransferFrom";
    case TokenFunction::SetApprovalForAll: return "setApprovalForAll";
    case TokenFunction::Deposit: return "deposit";
    case TokenFunction::Mint: return "mint";
    case TokenFunction::Withdraw: return "withdraw";
    case TokenFunction::Redeem: return "redeem";
    case TokenFunction::Send777: return "send";
    case TokenFunction::OperatorSend: return "operatorSend";
    case TokenFunction::Execute: return "execute";
    case TokenFunction::TransferValueToAddress: return "transferValueToAddress";
    case TokenFunction::TransferValueToToken: return "transferValueToToken";
    case TokenFunction::OftSend: return "send(OFT)";
    case TokenFunction::OnftSendFrom: return "sendFrom";
    case TokenFunction::Unknown: return "unknown";
  }
  return "unknown";
}

const char *evm_token_standard_refusal(EvmTokenStandard standard) {
  switch (standard) {
    case EvmTokenStandard::Erc20:
    case EvmTokenStandard::Erc721:
    case EvmTokenStandard::Erc1155:
    case EvmTokenStandard::Erc4626:
    case EvmTokenStandard::Erc777:
    case EvmTokenStandard::Erc3525:
    case EvmTokenStandard::Erc6551:
    case EvmTokenStandard::LayerZeroOft:
    case EvmTokenStandard::LayerZeroOnft:
      return nullptr;
    case EvmTokenStandard::Erc2981:
      return "royaltyInfo is a read-only query; no transaction signing policy";
    case EvmTokenStandard::Erc4337:
      return "account-abstraction UserOperation encoding not implemented";
    case EvmTokenStandard::Erc3643:
      return "security-token compliance module ABI not verifiable offline";
    case EvmTokenStandard::Erc1400:
      return "security-token tranche ABI not verifiable offline";
    case EvmTokenStandard::Erc1410:
      return "security-token partition ABI not verifiable offline";
    case EvmTokenStandard::Erc5528:
      return "escrow ABI not verifiable offline";
    case EvmTokenStandard::Unknown:
      return "selector not in the whitelist";
  }
  return "selector not in the whitelist";
}

bool token_build_erc20_transfer(const uint8_t recipient[20], uint64_t amount,
                                uint8_t *out, size_t out_size) {
  if (recipient == nullptr || out == nullptr ||
      out_size < kTokenSelectorSize + 2 * kTokenWordSize) {
    return false;
  }
  store_selector(out, 0xa9059cbb);
  store_address_word(out + kTokenSelectorSize, recipient);
  store_u64_word(out + kTokenSelectorSize + kTokenWordSize, amount);
  return true;
}

bool token_build_erc4626_deposit(const uint8_t receiver[20], uint64_t assets,
                                 uint8_t *out, size_t out_size) {
  if (receiver == nullptr || out == nullptr ||
      out_size < kTokenSelectorSize + 2 * kTokenWordSize) {
    return false;
  }
  store_selector(out, 0x6e553f65);
  store_u64_word(out + kTokenSelectorSize, assets);
  store_address_word(out + kTokenSelectorSize + kTokenWordSize, receiver);
  return true;
}

bool token_build_erc721_safe_transfer(const uint8_t from[20], const uint8_t to[20],
                                      const uint8_t token_id[kTokenWordSize],
                                      uint8_t *out, size_t out_size) {
  if (from == nullptr || to == nullptr || token_id == nullptr || out == nullptr ||
      out_size < kTokenSelectorSize + 3 * kTokenWordSize) {
    return false;
  }
  store_selector(out, 0x42842e0e);
  store_address_word(out + kTokenSelectorSize, from);
  store_address_word(out + kTokenSelectorSize + kTokenWordSize, to);
  store_word(out + kTokenSelectorSize + 2 * kTokenWordSize, token_id);
  return true;
}

bool token_build_erc1155_safe_transfer(const uint8_t from[20], const uint8_t to[20],
                                       const uint8_t token_id[kTokenWordSize],
                                       uint64_t amount, uint8_t *out,
                                       size_t out_size) {
  const size_t required = kTokenSelectorSize + 6 * kTokenWordSize;
  if (from == nullptr || to == nullptr || token_id == nullptr || out == nullptr ||
      out_size < required || required > kTokenMaxCalldataSize) {
    return false;
  }
  store_selector(out, 0xf242432a);
  store_address_word(out + kTokenSelectorSize, from);
  store_address_word(out + kTokenSelectorSize + kTokenWordSize, to);
  store_word(out + kTokenSelectorSize + 2 * kTokenWordSize, token_id);
  store_u64_word(out + kTokenSelectorSize + 3 * kTokenWordSize, amount);
  // bytes data: offset of the empty tail, then a zero length word.
  store_u64_word(out + kTokenSelectorSize + 4 * kTokenWordSize, 5 * kTokenWordSize);
  store_u64_word(out + kTokenSelectorSize + 5 * kTokenWordSize, 0);
  return true;
}

// `depth` bounds ERC-6551 executeCall nesting. One nested level is reviewable;
// deeper recursion would multiply stack use without adding review value.
static bool decode_calldata(const uint8_t *data, size_t data_size,
                           EvmTokenStandard standard, DecodedTokenCalldata *out,
                           uint8_t depth = 0) {
  if (data == nullptr || out == nullptr || data_size < kTokenSelectorSize ||
      depth > 1) {
    return false;
  }
  memset(out, 0, sizeof(*out));
  out->standard = EvmTokenStandard::Unknown;
  out->function = TokenFunction::Unknown;

  const TokenCalldataSelector *selector = nullptr;
  if (standard == EvmTokenStandard::Unknown) {
    selector = match_token_selector(data, data_size);
  } else {
    const uint32_t selector_word = (static_cast<uint32_t>(data[0]) << 24) |
                                   (static_cast<uint32_t>(data[1]) << 16) |
                                   (static_cast<uint32_t>(data[2]) << 8) |
                                   static_cast<uint32_t>(data[3]);
    for (size_t index = 0; index < kTokenCalldataSelectorCount; ++index) {
      const TokenCalldataSelector &entry = kTokenCalldataSelectors[index];
      if (entry.standard == standard && entry.selector == selector_word) {
        selector = &entry;
        break;
      }
    }
  }
  if (selector == nullptr) return false;

  const uint8_t *arguments = data + kTokenSelectorSize;
  const size_t arguments_size = data_size - kTokenSelectorSize;
  const size_t head_size = static_cast<size_t>(selector->argument_words) * kTokenWordSize;
  if (arguments_size < head_size) return false;
  out->selector = selector;
  out->standard = selector->standard;
  out->function = selector->function;

  switch (selector->standard) {
    case EvmTokenStandard::Erc20: {
      if (selector->function == TokenFunction::TransferFrom) {
        if (!read_address_word(arguments, out->secondary) ||
            !read_address_word(arguments + kTokenWordSize, out->recipient)) {
          return false;
        }
        memcpy(out->amount, arguments + 2 * kTokenWordSize, kTokenWordSize);
      } else {
        if (!read_address_word(arguments, out->recipient)) return false;
        memcpy(out->amount, arguments + kTokenWordSize, kTokenWordSize);
      }
      out->amount_fits_u64 = word_to_u64(out->amount, &out->amount_u64);
      return arguments_size == head_size;
    }
    case EvmTokenStandard::Erc721: {
      if (selector->function == TokenFunction::SetApprovalForAll) {
        if (!read_address_word(arguments, out->recipient)) return false;
        uint64_t approval = 0;
        if (!word_to_u64(arguments + kTokenWordSize, &approval) || approval > 1) {
          return false;
        }
        out->approval_for_all = approval == 1;
        return arguments_size == head_size;
      }
      if (!read_address_word(arguments, out->secondary) ||
          !read_address_word(arguments + kTokenWordSize, out->recipient)) {
        return false;
      }
      out->has_token_id = true;
      memcpy(out->token_id, arguments + 2 * kTokenWordSize, kTokenWordSize);
      if (selector->function != TokenFunction::SafeTransferFromWithData) {
        return arguments_size == head_size;
      }
      const uint8_t *tail = nullptr;
      size_t tail_size = 0;
      size_t end = 0;
      if (!read_tail(arguments, arguments_size, 3, 4 * kTokenWordSize,
                     kTokenMaxTailSize, &tail, &tail_size, &end) ||
          end != arguments_size) {
        return false;
      }
      out->has_bytes_tail = true;
      out->bytes_tail_size = static_cast<uint16_t>(tail_size);
      return true;
    }
    case EvmTokenStandard::Erc1155: {
      if (!read_address_word(arguments, out->secondary) ||
          !read_address_word(arguments + kTokenWordSize, out->recipient)) {
        return false;
      }
      if (selector->function == TokenFunction::SafeBatchTransferFrom) {
        const size_t head_words = 5;
        const uint8_t *ids = nullptr;
        const uint8_t *amounts = nullptr;
        const uint8_t *call_data = nullptr;
        size_t ids_count = 0;
        size_t amounts_count = 0;
        size_t call_data_size = 0;
        size_t end_ids = 0;
        size_t end_amounts = 0;
        size_t end_call_data = 0;
        if (!read_word_array(arguments, arguments_size, 2,
                             head_words * kTokenWordSize, kTokenMaxBatchItems,
                             &ids, &ids_count, &end_ids) ||
            !read_word_array(arguments, arguments_size, 3, end_ids,
                             kTokenMaxBatchItems, &amounts, &amounts_count,
                             &end_amounts) ||
            !read_tail(arguments, arguments_size, 4, end_amounts,
                       kTokenMaxTailSize, &call_data, &call_data_size,
                       &end_call_data) ||
            end_call_data != arguments_size || ids_count != amounts_count) {
          return false;
        }
        (void)call_data;  // Reported through bytes_tail_size.
        out->batch_count = static_cast<uint8_t>(ids_count);
        for (size_t index = 0; index < ids_count; ++index) {
          memcpy(out->batch_ids[index], ids + index * kTokenWordSize,
                 kTokenWordSize);
          memcpy(out->batch_amounts[index], amounts + index * kTokenWordSize,
                 kTokenWordSize);
        }
        out->has_bytes_tail = true;
        out->bytes_tail_size = static_cast<uint16_t>(call_data_size);
        return true;
      }
      out->has_token_id = true;
      memcpy(out->token_id, arguments + 2 * kTokenWordSize, kTokenWordSize);
      memcpy(out->amount, arguments + 3 * kTokenWordSize, kTokenWordSize);
      out->amount_fits_u64 = word_to_u64(out->amount, &out->amount_u64);
      const uint8_t *tail = nullptr;
      size_t tail_size = 0;
      size_t end = 0;
      if (!read_tail(arguments, arguments_size, 4, 5 * kTokenWordSize,
                     kTokenMaxTailSize, &tail, &tail_size, &end) ||
          end != arguments_size) {
        return false;
      }
      out->has_bytes_tail = true;
      out->bytes_tail_size = static_cast<uint16_t>(tail_size);
      return true;
    }
    case EvmTokenStandard::Erc4626: {
      memcpy(out->amount, arguments, kTokenWordSize);
      out->amount_fits_u64 = word_to_u64(out->amount, &out->amount_u64);
      if (!read_address_word(arguments + kTokenWordSize, out->recipient)) {
        return false;
      }
      if (selector->function == TokenFunction::Withdraw ||
          selector->function == TokenFunction::Redeem) {
        if (!read_address_word(arguments + 2 * kTokenWordSize, out->secondary)) {
          return false;
        }
      }
      return arguments_size == head_size;
    }
    case EvmTokenStandard::Erc777: {
      if (selector->function == TokenFunction::OperatorSend) {
        if (!read_address_word(arguments, out->secondary) ||
            !read_address_word(arguments + kTokenWordSize, out->recipient)) {
          return false;
        }
        memcpy(out->amount, arguments + 2 * kTokenWordSize, kTokenWordSize);
        out->amount_fits_u64 = word_to_u64(out->amount, &out->amount_u64);
        const uint8_t *tail = nullptr;
        const uint8_t *operator_tail = nullptr;
        size_t tail_size = 0;
        size_t operator_tail_size = 0;
        size_t end = 0;
        size_t operator_end = 0;
        if (!read_tail(arguments, arguments_size, 3, 5 * kTokenWordSize,
                       kTokenMaxTailSize, &tail, &tail_size, &end) ||
            !read_tail(arguments, arguments_size, 4, end, kTokenMaxTailSize,
                       &operator_tail, &operator_tail_size, &operator_end) ||
            operator_end != arguments_size) {
          return false;
        }
        out->has_bytes_tail = true;
        out->bytes_tail_size = static_cast<uint16_t>(tail_size);
        out->has_second_bytes_tail = true;
        out->second_bytes_tail_size = static_cast<uint16_t>(operator_tail_size);
        return true;
      }
      if (!read_address_word(arguments, out->recipient)) return false;
      memcpy(out->amount, arguments + kTokenWordSize, kTokenWordSize);
      out->amount_fits_u64 = word_to_u64(out->amount, &out->amount_u64);
      const uint8_t *tail = nullptr;
      size_t tail_size = 0;
      size_t end = 0;
      if (!read_tail(arguments, arguments_size, 2, 3 * kTokenWordSize,
                     kTokenMaxTailSize, &tail, &tail_size, &end) ||
          end != arguments_size) {
        return false;
      }
      out->has_bytes_tail = true;
      out->bytes_tail_size = static_cast<uint16_t>(tail_size);
      return true;
    }
    case EvmTokenStandard::Erc3525: {
      out->has_token_id = true;
      memcpy(out->token_id, arguments, kTokenWordSize);
      if (selector->function == TokenFunction::TransferValueToAddress) {
        if (!read_address_word(arguments + kTokenWordSize, out->recipient)) return false;
      } else {
        out->has_destination_token_id = true;
        memcpy(out->destination_token_id, arguments + kTokenWordSize, kTokenWordSize);
      }
      out->has_value = true;
      memcpy(out->value, arguments + 2 * kTokenWordSize, kTokenWordSize);
      memcpy(out->amount, out->value, kTokenWordSize);
      out->amount_fits_u64 = word_to_u64(out->amount, &out->amount_u64);
      return arguments_size == head_size;
    }
    case EvmTokenStandard::Erc6551: {
      // IERC6551Executable permits multiple operation types. Only CALL can
      // be represented by this review path; never accept DELEGATECALL/CREATE.
      uint64_t operation = 0;
      if (!word_to_u64(arguments + 3 * kTokenWordSize, &operation) || operation != 0) {
        return false;
      }
      if (!read_address_word(arguments, out->nested_target)) return false;
      memcpy(out->nested_value, arguments + kTokenWordSize, kTokenWordSize);
      const uint8_t *nested = nullptr;
      size_t nested_size = 0;
      size_t end = 0;
      if (!read_tail(arguments, arguments_size, 2, 4 * kTokenWordSize,
                     kTokenMaxTailSize, &nested, &nested_size, &end) ||
          end != arguments_size) {
        return false;
      }
      out->has_nested_call = true;
      out->nested_data_size = static_cast<uint16_t>(nested_size);
      out->has_value = true;
      memcpy(out->value, out->nested_value, sizeof(out->value));
      if (nested_size == 0) {
        memcpy(out->recipient, out->nested_target, sizeof(out->recipient));
        memcpy(out->amount, out->nested_value, sizeof(out->amount));
        out->amount_fits_u64 = word_to_u64(out->amount, &out->amount_u64);
        return true;
      }
      if (nested_size < kTokenSelectorSize) return false;
      const TokenCalldataSelector *nested_selector =
          match_token_selector(nested, nested_size);
      if (nested_selector == nullptr) return false;
      if (nested_selector->standard == EvmTokenStandard::Erc3525 ||
          nested_selector->standard == EvmTokenStandard::Erc6551 ||
          nested_selector->standard == EvmTokenStandard::LayerZeroOft ||
          nested_selector->standard == EvmTokenStandard::LayerZeroOnft) {
        return false;
      }
      memcpy(out->nested_selector, nested, sizeof(out->nested_selector));
      DecodedTokenCalldata inner = {};
      if (!decode_calldata(nested, nested_size, EvmTokenStandard::Unknown, &inner,
                           static_cast<uint8_t>(depth + 1))) {
        return false;
      }
      memcpy(out->recipient, inner.recipient, sizeof(out->recipient));
      memcpy(out->amount, inner.amount, sizeof(out->amount));
      out->amount_fits_u64 = inner.amount_fits_u64;
      out->amount_u64 = inner.amount_u64;
      out->has_token_id = inner.has_token_id;
      memcpy(out->token_id, inner.token_id, sizeof(out->token_id));
      out->nested_has_token_id = inner.has_token_id;
      memcpy(out->nested_token_id, inner.token_id, sizeof(out->nested_token_id));
      // Surface the inner callback flags so the signing policy can refuse an
      // opaque hook hidden behind execute.
      out->has_bytes_tail = inner.has_bytes_tail;
      out->bytes_tail_size = inner.bytes_tail_size;
      out->has_second_bytes_tail = inner.has_second_bytes_tail;
      out->second_bytes_tail_size = inner.second_bytes_tail_size;
      return true;
    }
    case EvmTokenStandard::LayerZeroOft: {
      if (selector->function == TokenFunction::OftSend) {
        uint64_t send_param_offset = 0;
        if (!word_to_u64(arguments, &send_param_offset) ||
            send_param_offset != 4 * kTokenWordSize) {
          return false;
        }
        const uint8_t *send_param = arguments + send_param_offset;
        const size_t send_param_size = arguments_size - send_param_offset;
        if (send_param_size < 7 * kTokenWordSize) return false;
        uint32_t dst_eid = 0;
        if (!word_to_u32(send_param, &dst_eid) ||
            !read_remote_address(send_param + kTokenWordSize, out)) {
          return false;
        }
        out->remote_eid = dst_eid;
        memcpy(out->amount, send_param + 2 * kTokenWordSize, kTokenWordSize);
        out->amount_fits_u64 = word_to_u64(out->amount, &out->amount_u64);
        out->has_min_amount = true;
        memcpy(out->min_amount, send_param + 3 * kTokenWordSize, kTokenWordSize);
        const uint8_t *extra_options = nullptr;
        const uint8_t *compose_msg = nullptr;
        const uint8_t *oft_cmd = nullptr;
        size_t extra_options_size = 0;
        size_t compose_msg_size = 0;
        size_t oft_cmd_size = 0;
        size_t end_options = 0;
        size_t end_compose = 0;
        size_t end_cmd = 0;
        if (!read_tail(send_param, send_param_size, 4, 7 * kTokenWordSize,
                       kTokenMaxTailSize, &extra_options, &extra_options_size,
                       &end_options) ||
            !read_tail(send_param, send_param_size, 5, end_options,
                       kTokenMaxTailSize, &compose_msg, &compose_msg_size,
                       &end_compose) ||
            !read_tail(send_param, send_param_size, 6, end_compose,
                       kTokenMaxTailSize, &oft_cmd, &oft_cmd_size, &end_cmd) ||
            end_cmd != send_param_size || compose_msg_size != 0 ||
            oft_cmd_size != 0) {
          return false;
        }
        memcpy(out->fee_native, arguments + kTokenWordSize, kTokenWordSize);
        memcpy(out->fee_lz_token, arguments + 2 * kTokenWordSize, kTokenWordSize);
        if (!read_address_word(arguments + 3 * kTokenWordSize, out->tertiary)) {
          return false;
        }
        (void)extra_options;
        (void)compose_msg;
        (void)oft_cmd;
        set_recipient_from_remote(out);
        out->has_bytes_tail = true;
        out->bytes_tail_size = static_cast<uint16_t>(extra_options_size);
        return true;
      }
      // LayerZero OFT/ONFT v1 sendFrom(address,uint16,bytes,uint256,...).
      if (selector->function != TokenFunction::OnftSendFrom) return false;
      if (!read_address_word(arguments, out->secondary)) return false;
      uint64_t remote_chain = 0;
      if (!word_to_u64(arguments + kTokenWordSize, &remote_chain) ||
          remote_chain > 0xffffULL) {
        return false;
      }
      out->remote_chain_id = static_cast<uint16_t>(remote_chain);
      const uint8_t *peer = nullptr;
      size_t peer_size = 0;
      size_t peer_end = 0;
      if (!read_tail(arguments, arguments_size, 2, 7 * kTokenWordSize,
                     kTokenWordSize, &peer, &peer_size, &peer_end) ||
          !store_remote_address(peer, peer_size, out)) {
        return false;
      }
      memcpy(out->amount, arguments + 3 * kTokenWordSize, kTokenWordSize);
      out->amount_fits_u64 = word_to_u64(out->amount, &out->amount_u64);
      if (!read_address_word(arguments + 4 * kTokenWordSize, out->tertiary) ||
          !read_address_word(arguments + 5 * kTokenWordSize, out->payment_address)) {
        return false;
      }
      const uint8_t *adapter = nullptr;
      size_t adapter_size = 0;
      size_t adapter_end = 0;
      if (!read_tail(arguments, arguments_size, 6, peer_end, kTokenMaxTailSize,
                     &adapter, &adapter_size, &adapter_end) ||
          adapter_end != arguments_size) {
        return false;
      }
      set_recipient_from_remote(out);
      out->has_bytes_tail = true;
      out->bytes_tail_size = static_cast<uint16_t>(adapter_size);
      return true;
    }
    case EvmTokenStandard::LayerZeroOnft: {
      if (selector->function != TokenFunction::OnftSendFrom) return false;
      if (!read_address_word(arguments, out->secondary)) return false;
      uint64_t remote_chain = 0;
      if (!word_to_u64(arguments + kTokenWordSize, &remote_chain) ||
          remote_chain > 0xffffULL) {
        return false;
      }
      out->remote_chain_id = static_cast<uint16_t>(remote_chain);
      const bool multi = head_size == 8 * kTokenWordSize;
      const uint8_t *peer = nullptr;
      size_t peer_size = 0;
      size_t peer_end = 0;
      if (!read_tail(arguments, arguments_size, 2, head_size, kTokenWordSize,
                     &peer, &peer_size, &peer_end) ||
          !store_remote_address(peer, peer_size, out)) {
        return false;
      }
      out->has_token_id = true;
      memcpy(out->token_id, arguments + 3 * kTokenWordSize, kTokenWordSize);
      const size_t refund_index = multi ? 5 : 4;
      if (multi) {
        memcpy(out->amount, arguments + 4 * kTokenWordSize, kTokenWordSize);
        out->amount_fits_u64 = word_to_u64(out->amount, &out->amount_u64);
      }
      if (!read_address_word(arguments + refund_index * kTokenWordSize,
                             out->tertiary) ||
          !read_address_word(arguments + (refund_index + 1) * kTokenWordSize,
                             out->payment_address)) {
        return false;
      }
      const uint8_t *adapter = nullptr;
      size_t adapter_size = 0;
      size_t adapter_end = 0;
      if (!read_tail(arguments, arguments_size, refund_index + 2, peer_end,
                     kTokenMaxTailSize, &adapter, &adapter_size, &adapter_end) ||
          adapter_end != arguments_size) {
        return false;
      }
      set_recipient_from_remote(out);
      out->has_bytes_tail = true;
      out->bytes_tail_size = static_cast<uint16_t>(adapter_size);
      return true;
    }
    default:
      return false;
  }
}

bool token_decode_calldata(const uint8_t *data, size_t size,
                           EvmTokenStandard standard, DecodedTokenCalldata *out) {
  if (out == nullptr) return false;
  DecodedTokenCalldata decoded = {};
  const bool valid = decode_calldata(data, size, standard, &decoded);
  memset(out, 0, sizeof(*out));
  out->standard = EvmTokenStandard::Unknown;
  out->function = TokenFunction::Unknown;
  if (valid) *out = decoded;
  return valid;
}

bool token_decode_calldata(const uint8_t *data, size_t size,
                           DecodedTokenCalldata *out) {
  return token_decode_calldata(data, size, EvmTokenStandard::Unknown, out);
}

bool run_token_calldata_self_tests() {
  // Recompute every selector from its signature with the firmware's Keccak-256.
  bool passed = true;
  for (size_t index = 0; index < kTokenCalldataSelectorCount; ++index) {
    const TokenCalldataSelector &entry = kTokenCalldataSelectors[index];
    const size_t signature_size = strlen(entry.signature);
    uint8_t digest[kKeccak256Size];
    if (!crypto_keccak256(reinterpret_cast<const uint8_t *>(entry.signature),
                          signature_size, digest)) {
      return false;
    }
    const uint32_t computed = (static_cast<uint32_t>(digest[0]) << 24) |
                              (static_cast<uint32_t>(digest[1]) << 16) |
                              (static_cast<uint32_t>(digest[2]) << 8) |
                              static_cast<uint32_t>(digest[3]);
    if (computed != entry.selector) passed = false;
    secure_zero(digest, sizeof(digest));
    for (size_t other = index + 1; other < kTokenCalldataSelectorCount; ++other) {
      const TokenCalldataSelector &candidate = kTokenCalldataSelectors[other];
      if (candidate.selector == entry.selector &&
          (candidate.standard != entry.standard ||
           candidate.function != entry.function) &&
          strcmp(candidate.signature, entry.signature) != 0) {
        // Two different signatures sharing a selector would make the whitelist
        // ambiguous; that is a hard failure, not a warning.
        passed = false;
      }
    }
  }
  // Supported standards must have selectors; refused standards must not.
  const EvmTokenStandard supported[] = {
    EvmTokenStandard::Erc20, EvmTokenStandard::Erc721, EvmTokenStandard::Erc1155,
    EvmTokenStandard::Erc4626, EvmTokenStandard::Erc777, EvmTokenStandard::Erc3525,
    EvmTokenStandard::Erc6551, EvmTokenStandard::LayerZeroOft,
    EvmTokenStandard::LayerZeroOnft };
  for (EvmTokenStandard standard : supported) {
    if (evm_token_standard_refusal(standard) != nullptr) passed = false;
    bool found = false;
    for (size_t index = 0; index < kTokenCalldataSelectorCount; ++index) {
      if (kTokenCalldataSelectors[index].standard == standard) found = true;
    }
    if (!found) passed = false;
  }
  const EvmTokenStandard refused[] = {
    EvmTokenStandard::Erc2981, EvmTokenStandard::Erc4337, EvmTokenStandard::Erc3643,
    EvmTokenStandard::Erc1400, EvmTokenStandard::Erc1410,
    EvmTokenStandard::Erc5528 };
  for (EvmTokenStandard standard : refused) {
    if (evm_token_standard_refusal(standard) == nullptr) passed = false;
    for (size_t index = 0; index < kTokenCalldataSelectorCount; ++index) {
      if (kTokenCalldataSelectors[index].standard == standard) passed = false;
    }
  }

  uint8_t recipient[20];
  uint8_t sender[20];
  for (uint8_t index = 0; index < 20; ++index) {
    recipient[index] = static_cast<uint8_t>(0x40 + index);
    sender[index] = static_cast<uint8_t>(0x80 + index);
  }
  uint8_t data[kTokenMaxCalldataSize];
  DecodedTokenCalldata decoded;
  uint8_t token_id[kTokenWordSize];
  memset(token_id, 0, sizeof(token_id));
  token_id[kTokenWordSize - 1] = 0x2a;
  token_id[kTokenWordSize - 2] = 0x01;

  // ERC-20 transfer and typed transferFrom.
  passed = token_build_erc20_transfer(recipient, 1000, data, sizeof(data)) &&
           token_decode_calldata(data, kTokenSelectorSize + 2 * kTokenWordSize,
                                 &decoded) &&
           decoded.standard == EvmTokenStandard::Erc20 &&
           decoded.function == TokenFunction::Transfer &&
           crypto_constant_time_equal(decoded.recipient, recipient, 20) &&
           decoded.amount_fits_u64 && decoded.amount_u64 == 1000 && passed;
  store_selector(data, 0x23b872dd);
  store_address_word(data + 4, sender);
  store_address_word(data + 36, recipient);
  store_u64_word(data + 68, 123);
  passed = !token_decode_calldata(data, 100, &decoded) && passed;
  passed = token_decode_calldata(data, 100, EvmTokenStandard::Erc20, &decoded) &&
           memcmp(decoded.secondary, sender, 20) == 0 &&
           memcmp(decoded.recipient, recipient, 20) == 0 &&
           decoded.amount_u64 == 123 && !decoded.has_token_id && passed;
  passed = token_decode_calldata(data, 100, EvmTokenStandard::Erc721, &decoded) &&
           decoded.has_token_id && decoded.token_id[31] == 123 && passed;
  data[36] = 1;
  passed = !token_decode_calldata(data, 100, EvmTokenStandard::Erc20, &decoded) &&
           decoded.standard == EvmTokenStandard::Unknown && decoded.selector == nullptr && passed;
  data[36] = 0;

  // ERC-721 safeTransferFrom with an empty callback tail.
  passed = token_build_erc721_safe_transfer(sender, recipient, token_id, data,
                                            sizeof(data)) &&
           token_decode_calldata(data, kTokenSelectorSize + 3 * kTokenWordSize,
                                 &decoded) &&
           decoded.standard == EvmTokenStandard::Erc721 &&
           decoded.has_token_id &&
           crypto_constant_time_equal(decoded.token_id, token_id, kTokenWordSize) &&
           crypto_constant_time_equal(decoded.recipient, recipient, 20) && passed;
  store_selector(data, 0xb88d4fde);
  store_address_word(data + 4, sender);
  store_address_word(data + 36, recipient);
  memcpy(data + 68, token_id, kTokenWordSize);
  store_u64_word(data + 100, 128);
  store_u64_word(data + 132, 0);
  passed = token_decode_calldata(data, 164, &decoded) && passed;
  for (size_t length = 0; length < 164; ++length) {
    passed = !token_decode_calldata(data, length, &decoded) && passed;
  }
  data[131] = 0;
  passed = !token_decode_calldata(data, 164, &decoded) && passed;
  data[131] = 128;
  data[163] = 1;
  passed = !token_decode_calldata(data, 164, &decoded) && passed;

  // ERC-1155 single transfer.
  const size_t erc1155_size = kTokenSelectorSize + 6 * kTokenWordSize;
  passed = token_build_erc1155_safe_transfer(sender, recipient, token_id, 7, data,
                                             sizeof(data)) &&
           token_decode_calldata(data, erc1155_size, &decoded) &&
           decoded.standard == EvmTokenStandard::Erc1155 &&
           decoded.amount_u64 == 7 &&
           crypto_constant_time_equal(decoded.recipient, recipient, 20) && passed;
  passed = !token_decode_calldata(data, erc1155_size - 1, &decoded) && passed;

  // ERC-1155 batch with one pair.
  store_selector(data, 0x2eb2c2d6);
  store_address_word(data + 4, sender);
  store_address_word(data + 36, recipient);
  store_u64_word(data + 68, 5 * kTokenWordSize);
  store_u64_word(data + 100, 224);
  store_u64_word(data + 132, 288);
  store_u64_word(data + 164, 1);
  memcpy(data + 196, token_id, kTokenWordSize);
  store_u64_word(data + 228, 1);
  store_u64_word(data + 260, 7);
  store_u64_word(data + 292, 0);
  const size_t batch_size = kTokenSelectorSize + 320;
  passed = token_decode_calldata(data, batch_size, &decoded) &&
           decoded.standard == EvmTokenStandard::Erc1155 &&
           decoded.function == TokenFunction::SafeBatchTransferFrom &&
           decoded.batch_count == 1 &&
           crypto_constant_time_equal(decoded.batch_ids[0], token_id, kTokenWordSize) &&
           decoded.batch_amounts[0][kTokenWordSize - 1] == 7 && passed;
  passed = !token_decode_calldata(data, batch_size - 1, &decoded) && passed;
  store_u64_word(data + 164, 5);
  passed = !token_decode_calldata(data, batch_size, &decoded) && passed;
  store_u64_word(data + 164, 1);

  // ERC-4626 deposit.
  passed = token_build_erc4626_deposit(recipient, 1000, data, sizeof(data)) &&
           token_decode_calldata(data, kTokenSelectorSize + 2 * kTokenWordSize,
                                 &decoded) &&
           decoded.standard == EvmTokenStandard::Erc4626 &&
           decoded.function == TokenFunction::Deposit &&
           decoded.amount_u64 == 1000 &&
           crypto_constant_time_equal(decoded.recipient, recipient, 20) && passed;

  // ERC-777 send and operatorSend with non-empty hook data.
  store_selector(data, 0x9bd9bbc6);
  store_address_word(data + 4, recipient);
  store_u64_word(data + 36, 1000);
  store_u64_word(data + 68, 96);
  store_u64_word(data + 100, 0);
  passed = token_decode_calldata(data, 132, &decoded) &&
           decoded.amount_u64 == 1000 && passed;
  passed = !token_decode_calldata(data, 100, &decoded) && passed;
  data[99] = 64;
  passed = !token_decode_calldata(data, 132, &decoded) && passed;
  memset(data, 0, sizeof(data));
  store_selector(data, 0x62ad1b83);
  store_address_word(data + 4, sender);
  store_address_word(data + 36, recipient);
  store_u64_word(data + 68, 55);
  store_u64_word(data + 100, 160);
  store_u64_word(data + 132, 224);
  store_u64_word(data + 164, 1);
  data[196] = 0xaa;
  store_u64_word(data + 228, 0);
  passed = token_decode_calldata(data, 260, &decoded) &&
           decoded.function == TokenFunction::OperatorSend &&
           decoded.amount_u64 == 55 && decoded.bytes_tail_size == 1 &&
           memcmp(decoded.secondary, sender, 20) == 0 &&
           memcmp(decoded.recipient, recipient, 20) == 0 && passed;
  // Nonzero ABI padding and overlapping tails are rejected, with cleared output.
  data[197] = 1;
  passed = !token_decode_calldata(data, 260, &decoded) &&
           decoded.standard == EvmTokenStandard::Unknown && decoded.selector == nullptr && passed;
  data[197] = 0;
  store_u64_word(data + 132, 160);
  passed = !token_decode_calldata(data, 260, &decoded) && passed;
  store_u64_word(data + 132, 224);
  passed = !token_decode_calldata(data, 292, &decoded) && passed;

  // EIP-3525 value transfer overloads: IDs are uint256, not addresses.
  memset(data, 0, sizeof(data));
  store_selector(data, 0x0f485c02);
  memcpy(data + 4, token_id, kTokenWordSize);
  data[4] = 0xff; // Full-width ID must never undergo address validation.
  store_address_word(data + 36, recipient);
  store_u64_word(data + 68, 5);
  passed = token_decode_calldata(data, 100, &decoded) &&
           decoded.standard == EvmTokenStandard::Erc3525 &&
           decoded.token_id[0] == 0xff && decoded.amount_u64 == 5 &&
           !decoded.has_destination_token_id &&
           memcmp(decoded.recipient, recipient, 20) == 0 && passed;
  store_selector(data, 0x310ed7f0);
  memset(data + 36, 0xff, kTokenWordSize);
  passed = token_decode_calldata(data, 100, &decoded) &&
           decoded.has_destination_token_id &&
           decoded.destination_token_id[0] == 0xff && passed;
  store_selector(data, 0xfe99049a);
  passed = !token_decode_calldata(data, 132, EvmTokenStandard::Erc3525, &decoded) && passed;
  store_selector(data, 0xf242432a);
  passed = !token_decode_calldata(data, 196, EvmTokenStandard::Erc3525, &decoded) && passed;

  // ERC-6551 execute(CALL) wrapping an ERC-20 transfer.
  uint8_t nested_erc20[kTokenSelectorSize + 2 * kTokenWordSize];
  passed = token_build_erc20_transfer(recipient, 321, nested_erc20,
                                      sizeof(nested_erc20)) && passed;
  memset(data, 0, sizeof(data));
  store_selector(data, 0x51945447);
  store_address_word(data + 4, sender);
  store_u64_word(data + 36, 0);
  store_u64_word(data + 68, 128);
  store_u64_word(data + 100, 0);
  store_u64_word(data + 132, sizeof(nested_erc20));
  memcpy(data + 164, nested_erc20, sizeof(nested_erc20));
  const size_t execute_call_size =
      kTokenSelectorSize + 160 + padded_word_size(sizeof(nested_erc20));
  passed = token_decode_calldata(data, execute_call_size, &decoded) &&
           decoded.standard == EvmTokenStandard::Erc6551 &&
           decoded.has_nested_call && decoded.nested_data_size == sizeof(nested_erc20) &&
           memcmp(decoded.nested_target, sender, 20) == 0 &&
           memcmp(decoded.recipient, recipient, 20) == 0 &&
           decoded.amount_u64 == 321 && passed;
  store_u64_word(data + 100, 1);
  passed = !token_decode_calldata(data, execute_call_size, &decoded) && passed;
  store_u64_word(data + 100, 256);
  passed = !token_decode_calldata(data, execute_call_size, &decoded) && passed;
  store_u64_word(data + 100, 0);
  data[166] = 0xde;
  data[167] = 0xad;
  data[168] = 0xbe;
  data[169] = 0xef;
  passed = !token_decode_calldata(data, execute_call_size, &decoded) && passed;
  store_selector(data, 0x912ccaa3);
  passed = !token_decode_calldata(data, 100, &decoded) && passed;

  // LayerZero OFT v2 send(SendParam,MessagingFee,address).
  memset(data, 0, sizeof(data));
  store_selector(data, 0xc7c7f5b3);
  store_u64_word(data + 4, 128);
  store_u64_word(data + 36, 1000);
  store_u64_word(data + 68, 0);
  store_address_word(data + 100, sender);
  const size_t send_param = 132;
  store_u64_word(data + send_param, 30101);
  uint8_t remote_word[kTokenWordSize] = {};
  memcpy(remote_word + 12, recipient, 20);
  memcpy(data + send_param + 32, remote_word, kTokenWordSize);
  store_u64_word(data + send_param + 64, 500);
  store_u64_word(data + send_param + 96, 490);
  store_u64_word(data + send_param + 128, 224);
  store_u64_word(data + send_param + 160, 256);
  store_u64_word(data + send_param + 192, 288);
  store_u64_word(data + send_param + 224, 0);
  store_u64_word(data + send_param + 256, 0);
  store_u64_word(data + send_param + 288, 0);
  const size_t oft_size = kTokenSelectorSize + 128 + 320;
  passed = token_decode_calldata(data, oft_size, &decoded) &&
           decoded.standard == EvmTokenStandard::LayerZeroOft &&
           decoded.remote_eid == 30101 && decoded.amount_u64 == 500 &&
           decoded.has_min_amount && decoded.min_amount[kTokenWordSize - 1] == 0xea &&
           decoded.fee_native[kTokenWordSize - 1] == 0xe8 &&
           memcmp(decoded.recipient, recipient, 20) == 0 &&
           memcmp(decoded.tertiary, sender, 20) == 0 && passed;
  store_u64_word(data + send_param + 160, 288);
  passed = !token_decode_calldata(data, oft_size, &decoded) && passed;

  // LayerZero ONFT721 v1 sendFrom.
  memset(data, 0, sizeof(data));
  store_selector(data, 0x51905636);
  store_address_word(data + 4, sender);
  store_u64_word(data + 36, 101);
  store_u64_word(data + 68, 224);
  store_u64_word(data + 100, 42);
  store_address_word(data + 132, recipient);
  store_address_word(data + 164, sender);
  store_u64_word(data + 196, 288);
  store_u64_word(data + 228, 20);
  memcpy(data + 260, recipient, 20);
  store_u64_word(data + 292, 0);
  const size_t onft_size = kTokenSelectorSize + 320;
  passed = token_decode_calldata(data, onft_size, EvmTokenStandard::LayerZeroOnft,
                                 &decoded) &&
           decoded.function == TokenFunction::OnftSendFrom &&
           decoded.remote_chain_id == 101 && decoded.has_token_id &&
           decoded.token_id[kTokenWordSize - 1] == 42 &&
           decoded.remote_address_size == 20 &&
           memcmp(decoded.recipient, recipient, 20) == 0 &&
           memcmp(decoded.tertiary, recipient, 20) == 0 &&
           memcmp(decoded.payment_address, sender, 20) == 0 && passed;

  // LayerZero OFT v1 sendFrom (same selector as ONFT721; registry context).
  memset(data, 0, sizeof(data));
  store_selector(data, 0x51905636);
  store_address_word(data + 4, sender);
  store_u64_word(data + 36, 101);
  store_u64_word(data + 68, 224);
  store_u64_word(data + 100, 500);
  store_address_word(data + 132, recipient);
  store_address_word(data + 164, sender);
  store_u64_word(data + 196, 288);
  store_u64_word(data + 228, 20);
  memcpy(data + 260, recipient, 20);
  store_u64_word(data + 292, 0);
  passed = token_decode_calldata(data, onft_size, EvmTokenStandard::LayerZeroOft,
                                 &decoded) &&
           decoded.amount_u64 == 500 && !decoded.has_token_id && passed;
  passed = !token_decode_calldata(data, onft_size, &decoded) && passed;

  // ERC-721 setApprovalForAll boolean validation.
  store_selector(data, 0xa22cb465);
  store_u64_word(data + 36, 1);
  passed = token_decode_calldata(data, 68, &decoded) && decoded.approval_for_all && passed;
  store_u64_word(data + 36, 0);
  passed = token_decode_calldata(data, 68, &decoded) && !decoded.approval_for_all && passed;
  store_u64_word(data + 36, 2);
  passed = !token_decode_calldata(data, 68, &decoded) && passed;

  uint8_t unknown[36];
  memcpy(unknown, data, sizeof(unknown));
  unknown[0] = 0xde;
  unknown[1] = 0xad;
  unknown[2] = 0xbe;
  unknown[3] = 0xef;
  passed = !token_decode_calldata(unknown, sizeof(unknown), &decoded) &&
           decoded.standard == EvmTokenStandard::Unknown && passed;

  secure_zero(data, sizeof(data));
  secure_zero(nested_erc20, sizeof(nested_erc20));
  secure_zero(remote_word, sizeof(remote_word));
  secure_zero(unknown, sizeof(unknown));
  secure_zero(&decoded, sizeof(decoded));
  return passed;
}

}  // namespace hexwallet
