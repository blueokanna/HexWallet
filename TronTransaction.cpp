#include "TronTransaction.h"

#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletAddresses.h"
#include "WalletTokens.h"
#include "base58.h"
#include "src/BytesText.h"

namespace hexwallet {
namespace {

constexpr uint8_t kTronAddressPrefix = 0x41;
constexpr uint64_t kContractTransfer = 1;
constexpr uint64_t kContractTransferAsset = 2;
constexpr uint64_t kContractTriggerSmart = 31;
constexpr char kTypeUrlTransfer[] = "type.googleapis.com/protocol.TransferContract";
constexpr char kTypeUrlTransferAsset[] =
    "type.googleapis.com/protocol.TransferAssetContract";
constexpr char kTypeUrlTrigger[] = "type.googleapis.com/protocol.TriggerSmartContract";
constexpr uint8_t kTrc20TransferSelector[4] = {0xa9, 0x05, 0x9c, 0xbb};
// Shared by ERC-20/TRC-20 transferFrom and ERC-721 transferFrom. It only
// reaches signing when `from` is the wallet owner and the contract is a
// registered TRC-20; there are no registered TRC-721 contracts.
constexpr uint8_t kTrc20TransferFromSelector[4] = {0x23, 0xb8, 0x72, 0xdd};
constexpr uint8_t kTrc721SafeTransferSelector[4] = {0x42, 0x84, 0x2e, 0x0e};
constexpr uint8_t kTrc1155SafeTransferSelector[4] = {0xf2, 0x42, 0x43, 0x2a};
constexpr size_t kTrc20DataSize = 68;
constexpr size_t kTrc20TransferFromSize = 4 + 3 * kTronWordSize;
constexpr size_t kTrc721SafeTransferSize = 4 + 3 * 32;
constexpr size_t kTrc1155SafeTransferSize = 4 + 5 * 32 + 32;
constexpr size_t kChecksumSize = 4;

// Bounded protobuf reader. Only varint and length-delimited wire types appear
// in the reviewed messages; groups and every other wire type are rejected.
// Varints must be minimally encoded so one transaction has exactly one byte
// sequence that the phone and the device can disagree about.
struct ProtoReader {
  const uint8_t *data;
  size_t size;
  size_t offset;

  bool take(size_t count, const uint8_t **out) {
    if (count > size - offset) return false;
    *out = data + offset;
    offset += count;
    return true;
  }

  bool varint(uint64_t *out) {
    uint64_t value = 0;
    for (unsigned index = 0; index < 10; ++index) {
      if (offset >= size) return false;
      const uint8_t byte = data[offset++];
      if (index == 9 && byte > 1) return false;
      value |= static_cast<uint64_t>(byte & 0x7f) << (7 * index);
      if ((byte & 0x80) == 0) {
        if (index != 0 && byte == 0) return false;
        *out = value;
        return true;
      }
    }
    return false;
  }

  bool length(size_t *out) {
    uint64_t value = 0;
    if (!varint(&value) || value > size - offset) return false;
    *out = static_cast<size_t>(value);
    return true;
  }

  bool tag(uint32_t *field, uint8_t *wire) {
    uint64_t key = 0;
    if (!varint(&key)) return false;
    const uint64_t number = key >> 3;
    // Protobuf field numbers are 29-bit. Truncating a larger number would let
    // one byte sequence mean "contract" here and "unknown field" to a node.
    if (number == 0 || number > 0x1fffffffULL) return false;
    *field = static_cast<uint32_t>(number);
    *wire = static_cast<uint8_t>(key & 7);
    return *wire == 0 || *wire == 2;
  }
};

bool all_zero(const uint8_t *data, size_t size) {
  uint8_t accumulator = 0;
  for (size_t index = 0; index < size; ++index) accumulator |= data[index];
  return accumulator == 0;
}

bool same_review(const TronTransferReview &a, const TronTransferReview &b) {
  return a.kind == b.kind && a.token_decimals == b.token_decimals &&
      a.has_token_id == b.has_token_id && a.fee_limit_sun == b.fee_limit_sun &&
      a.asset_id_size == b.asset_id_size && a.asset_registered == b.asset_registered &&
      a.has_memo == b.has_memo &&
      a.expiration_ms == b.expiration_ms && a.timestamp_ms == b.timestamp_ms &&
      bytes_equal(a.asset_id, b.asset_id, sizeof(a.asset_id)) &&
      memcmp(a.asset_id_text, b.asset_id_text, sizeof(a.asset_id_text)) == 0 &&
      memcmp(a.method_text, b.method_text, sizeof(a.method_text)) == 0 &&
      memcmp(a.memo_text, b.memo_text, sizeof(a.memo_text)) == 0 &&
      bytes_equal(a.owner, b.owner, sizeof(a.owner)) &&
      bytes_equal(a.recipient, b.recipient, sizeof(a.recipient)) &&
      bytes_equal(a.token_contract, b.token_contract, sizeof(a.token_contract)) &&
      bytes_equal(a.amount, b.amount, sizeof(a.amount)) &&
      bytes_equal(a.token_id, b.token_id, sizeof(a.token_id)) &&
      bytes_equal(a.ref_block_hash, b.ref_block_hash, sizeof(a.ref_block_hash)) &&
      bytes_equal(a.tx_id, b.tx_id, sizeof(a.tx_id)) &&
      memcmp(a.owner_text, b.owner_text, sizeof(a.owner_text)) == 0 &&
      memcmp(a.recipient_text, b.recipient_text, sizeof(a.recipient_text)) == 0 &&
      memcmp(a.token_contract_text, b.token_contract_text, sizeof(a.token_contract_text)) == 0 &&
      memcmp(a.token_symbol, b.token_symbol, sizeof(a.token_symbol)) == 0 &&
      memcmp(a.amount_text, b.amount_text, sizeof(a.amount_text)) == 0 &&
      memcmp(a.token_id_text, b.token_id_text, sizeof(a.token_id_text)) == 0;
}

bool word_address(const uint8_t *word, uint8_t out[kTronAddressSize]) {
  if (!all_zero(word, 12)) return false;
  out[0] = kTronAddressPrefix;
  memcpy(out + 1, word + 12, kTronAddressSize - 1);
  return true;
}

bool word_is_owner(const uint8_t *word, const uint8_t owner[kTronAddressSize]) {
  return all_zero(word, 12) &&
         bytes_equal(word + 12, owner + 1, kTronAddressSize - 1);
}

bool word_is_zero(const uint8_t *word) { return all_zero(word, kTronWordSize); }

bool word_is_u64(const uint8_t *word, uint64_t value) {
  if (!all_zero(word, kTronWordSize - 8)) return false;
  uint64_t actual = 0;
  for (size_t index = kTronWordSize - 8; index < kTronWordSize; ++index) {
    actual = (actual << 8) | word[index];
  }
  return actual == value;
}

void store_u64_word(uint64_t value, uint8_t word[kTronWordSize]) {
  memset(word, 0, kTronWordSize);
  for (size_t index = 0; index < 8; ++index) {
    word[kTronWordSize - 1 - index] = static_cast<uint8_t>(value >> (8 * index));
  }
}

bool address_text(const uint8_t address[kTronAddressSize], char *out,
                  size_t size) {
  uint8_t payload[kTronAddressSize + kChecksumSize];
  uint8_t checksum[kSha256Size];
  memcpy(payload, address, kTronAddressSize);
  if (!crypto_double_sha256(address, kTronAddressSize, checksum)) return false;
  memcpy(payload + kTronAddressSize, checksum, kChecksumSize);
  size_t encoded_size = size;
  const bool ok = b58enc(out, &encoded_size, payload, sizeof(payload));
  secure_zero(payload, sizeof(payload));
  secure_zero(checksum, sizeof(checksum));
  return ok && encoded_size <= size;
}

// Decimal rendering of a 256-bit word without floating point. Truncation is an
// error, never a silently shortened amount.
bool format_units(const uint8_t amount[kTronWordSize], uint8_t decimals,
                  char *out, size_t size) {
  if (amount == nullptr || out == nullptr || size == 0 || decimals > 32) {
    return false;
  }
  uint8_t work[kTronWordSize];
  memcpy(work, amount, sizeof(work));
  char reversed[80];
  size_t count = 0;
  bool nonzero = !all_zero(work, sizeof(work));
  if (!nonzero) reversed[count++] = '0';
  while (nonzero) {
    uint32_t remainder = 0;
    nonzero = false;
    for (size_t index = 0; index < sizeof(work); ++index) {
      const uint32_t current = (remainder << 8) | work[index];
      work[index] = static_cast<uint8_t>(current / 10);
      remainder = current % 10;
      if (work[index] != 0) nonzero = true;
    }
    if (count == sizeof(reversed)) {
      secure_zero(work, sizeof(work));
      return false;
    }
    reversed[count++] = static_cast<char>('0' + remainder);
  }
  secure_zero(work, sizeof(work));
  char digits[80];
  for (size_t index = 0; index < count; ++index) {
    digits[index] = reversed[count - 1 - index];
  }
  digits[count] = '\0';
  int written = 0;
  if (decimals == 0) {
    written = snprintf(out, size, "%.*s", static_cast<int>(count), digits);
  } else if (count <= decimals) {
    written = snprintf(out, size, "0.%.*s%.*s",
                       static_cast<int>(decimals - count),
                       "00000000000000000000000000000000",
                       static_cast<int>(count), digits);
  } else {
    written = snprintf(out, size, "%.*s.%s",
                       static_cast<int>(count - decimals), digits,
                       digits + (count - decimals));
  }
  return written > 0 && static_cast<size_t>(written) < size;
}

const TokenProfile *find_trc20(const uint8_t contract[kTronAddressSize]) {
  for (size_t index = 0; index < kTokenProfileCount; ++index) {
    const TokenProfile &token = kTokenProfiles[index];
    if (token.standard != TokenStandard::Trc20 ||
        strcmp(token.network_id, "trx") != 0 || token.contract_or_mint == nullptr) {
      continue;
    }
    uint8_t decoded[kTronAddressSize + kChecksumSize] = {};
    size_t decoded_size = sizeof(decoded);
    if (b58check_dec(decoded, &decoded_size, token.contract_or_mint) &&
        decoded_size == kTronAddressSize &&
        bytes_equal(decoded, contract, kTronAddressSize)) {
      return &token;
    }
  }
  return nullptr;
}

// TRC-10 assets are keyed by their chain-assigned id. The registry never
// matches on the display name: token names are not unique on TRON, and the
// node resolves the transfer by the identifier bytes only.
const TokenProfile *find_trc10(const uint8_t *id, size_t size) {
  if (id == nullptr || size == 0) return nullptr;
  for (size_t index = 0; index < kTokenProfileCount; ++index) {
    const TokenProfile &token = kTokenProfiles[index];
    if (token.standard != TokenStandard::Trc10 ||
        strcmp(token.network_id, "trx") != 0 || token.contract_or_mint == nullptr) {
      continue;
    }
    if (strlen(token.contract_or_mint) == size &&
        memcmp(token.contract_or_mint, id, size) == 0) {
      return &token;
    }
  }
  return nullptr;
}

// Printable ASCII identifiers render verbatim; anything else renders as exact
// bytes so the trusted display cannot substitute one glyph sequence for another.
bool render_asset_id(const uint8_t *id, size_t size, char *out, size_t out_size) {
  if (id == nullptr || out == nullptr || size == 0 || size > kTronAssetIdSize) {
    return false;
  }
  bool printable = true;
  for (size_t index = 0; index < size; ++index) {
    if (id[index] < 0x20 || id[index] > 0x7e) {
      printable = false;
      break;
    }
  }
  if (!printable) {
    if (out_size < 2 + size * 2 + 1) return false;
    out[0] = '0';
    out[1] = 'x';
    for (size_t index = 0; index < size; ++index) {
      const int written = snprintf(out + 2 + index * 2, out_size - (2 + index * 2),
                                   "%02x", id[index]);
      if (written != 2) return false;
    }
    return true;
  }
  const int written = snprintf(out, out_size, "%.*s", static_cast<int>(size),
                               reinterpret_cast<const char *>(id));
  return written == static_cast<int>(size);
}

TronError parse_any(const uint8_t *data, size_t size, const char *type_url,
                    const uint8_t **value, size_t *value_size) {
  ProtoReader reader = {data, size, 0};
  bool has_url = false, has_value = false;
  while (reader.offset < size) {
    uint32_t field = 0;
    uint8_t wire = 0;
    if (!reader.tag(&field, &wire)) return TronError::Malformed;
    if (field == 1) {
      const uint8_t *text = nullptr;
      size_t length = 0;
      if (wire != 2 || has_url || !reader.length(&length) ||
          !reader.take(length, &text)) {
        return TronError::Malformed;
      }
      const size_t expected = strlen(type_url);
      if (length != expected || memcmp(text, type_url, expected) != 0) {
        return TronError::Unsupported;
      }
      has_url = true;
    } else if (field == 2) {
      if (wire != 2 || has_value || !reader.length(value_size) ||
          !reader.take(*value_size, value)) {
        return TronError::Malformed;
      }
      has_value = true;
    } else {
      return TronError::Unsupported;
    }
  }
  return has_url && has_value ? TronError::Ok : TronError::Malformed;
}

TronError parse_transfer_body(const uint8_t *data, size_t size,
                              TronTransferReview *review) {
  ProtoReader reader = {data, size, 0};
  bool has_owner = false, has_recipient = false, has_amount = false;
  uint64_t amount = 0;
  while (reader.offset < size) {
    uint32_t field = 0;
    uint8_t wire = 0;
    const uint8_t *bytes = nullptr;
    size_t length = 0;
    if (!reader.tag(&field, &wire)) return TronError::Malformed;
    switch (field) {
      case 1:
      case 2:
        if (wire != 2 || !reader.length(&length) || !reader.take(length, &bytes) ||
            length != kTronAddressSize) {
          return TronError::Malformed;
        }
        if (field == 1) {
          if (has_owner) return TronError::Malformed;
          memcpy(review->owner, bytes, kTronAddressSize);
          has_owner = true;
        } else {
          if (has_recipient) return TronError::Malformed;
          memcpy(review->recipient, bytes, kTronAddressSize);
          has_recipient = true;
        }
        break;
      case 3:
        if (wire != 0 || has_amount || !reader.varint(&amount) ||
            amount == 0 || amount > static_cast<uint64_t>(INT64_MAX)) {
          return TronError::InvalidAmount;
        }
        has_amount = true;
        break;
      default:
        return TronError::Unsupported;
    }
  }
  if (!has_owner || !has_recipient || !has_amount) return TronError::Malformed;
  store_u64_word(amount, review->amount);
  review->kind = TronKind::Native;
  return TronError::Ok;
}

// TransferAssetContract: asset_name=1, owner=2, to=3, amount=4. The asset
// identifier is the chain lookup key, so it is carried verbatim into the review
// instead of being resolved to a symbol here.
TronError parse_transfer_asset_body(const uint8_t *data, size_t size,
                                    TronTransferReview *review) {
  ProtoReader reader = {data, size, 0};
  bool has_asset = false, has_owner = false, has_recipient = false;
  bool has_amount = false;
  const uint8_t *asset = nullptr;
  size_t asset_length = 0;
  uint64_t amount = 0;
  while (reader.offset < size) {
    uint32_t field = 0;
    uint8_t wire = 0;
    const uint8_t *bytes = nullptr;
    size_t length = 0;
    if (!reader.tag(&field, &wire)) return TronError::Malformed;
    switch (field) {
      case 1:
        if (wire != 2 || has_asset || !reader.length(&length) ||
            !reader.take(length, &bytes) || length == 0 ||
            length > kTronAssetIdSize) {
          return TronError::Malformed;
        }
        memcpy(review->asset_id, bytes, length);
        review->asset_id_size = static_cast<uint8_t>(length);
        asset = review->asset_id;
        asset_length = length;
        has_asset = true;
        break;
      case 2:
      case 3:
        if (wire != 2 || !reader.length(&length) || !reader.take(length, &bytes) ||
            length != kTronAddressSize) {
          return TronError::Malformed;
        }
        if (field == 2) {
          if (has_owner) return TronError::Malformed;
          memcpy(review->owner, bytes, kTronAddressSize);
          has_owner = true;
        } else {
          if (has_recipient) return TronError::Malformed;
          memcpy(review->recipient, bytes, kTronAddressSize);
          has_recipient = true;
        }
        break;
      case 4:
        if (wire != 0 || has_amount || !reader.varint(&amount) ||
            amount == 0 || amount > static_cast<uint64_t>(INT64_MAX)) {
          return TronError::InvalidAmount;
        }
        has_amount = true;
        break;
      default:
        return TronError::Unsupported;
    }
  }
  if (!has_asset || !has_owner || !has_recipient || !has_amount) {
    return TronError::Malformed;
  }
  if (!render_asset_id(asset, asset_length, review->asset_id_text,
                       sizeof(review->asset_id_text))) {
    return TronError::Malformed;
  }
  store_u64_word(amount, review->amount);
  review->kind = TronKind::Trc10;
  return TronError::Ok;
}

TronError parse_trigger_body(const uint8_t *data, size_t size,
                             TronTransferReview *review) {
  ProtoReader reader = {data, size, 0};
  bool has_owner = false, has_contract = false, has_data = false;
  bool has_call_value = false, has_call_token_value = false, has_token_id = false;
  uint64_t call_value = 0, call_token_value = 0, token_id = 0;
  const uint8_t *call_data = nullptr;
  size_t call_data_size = 0;
  while (reader.offset < size) {
    uint32_t field = 0;
    uint8_t wire = 0;
    const uint8_t *bytes = nullptr;
    size_t length = 0;
    if (!reader.tag(&field, &wire)) return TronError::Malformed;
    switch (field) {
      case 1:
      case 2:
        if (wire != 2 || !reader.length(&length) || !reader.take(length, &bytes) ||
            length != kTronAddressSize) {
          return TronError::Malformed;
        }
        if (field == 1) {
          if (has_owner) return TronError::Malformed;
          memcpy(review->owner, bytes, kTronAddressSize);
          has_owner = true;
        } else {
          if (has_contract) return TronError::Malformed;
          memcpy(review->token_contract, bytes, kTronAddressSize);
          has_contract = true;
        }
        break;
      case 3:
        if (wire != 0 || has_call_value || !reader.varint(&call_value)) return TronError::Malformed;
        has_call_value = true;
        break;
      case 4:
        if (wire != 2 || has_data || !reader.length(&call_data_size) ||
            !reader.take(call_data_size, &call_data)) {
          return TronError::Malformed;
        }
        has_data = true;
        break;
      case 5:
        if (wire != 0 || has_call_token_value || !reader.varint(&call_token_value)) return TronError::Malformed;
        has_call_token_value = true;
        break;
      case 6:
        if (wire != 0 || has_token_id || !reader.varint(&token_id)) return TronError::Malformed;
        has_token_id = true;
        break;
      default:
        return TronError::Unsupported;
    }
  }
  if (!has_owner || !has_contract || !has_data) return TronError::Malformed;
  // Attached TRX or TRC-10 token values change what the user pays for and are
  // outside this review; refuse instead of showing only the call data.
  if (call_value != 0 || call_token_value != 0 || token_id != 0) {
    return TronError::Unsupported;
  }
  if (call_data_size == kTrc20DataSize &&
      memcmp(call_data, kTrc20TransferSelector, sizeof(kTrc20TransferSelector)) == 0) {
    const uint8_t *recipient_word = call_data + 4;
    if (!word_address(recipient_word, review->recipient)) return TronError::Malformed;
    memcpy(review->amount, recipient_word + kTronWordSize, kTronWordSize);
    if (word_is_zero(review->amount)) return TronError::InvalidAmount;
    snprintf(review->method_text, sizeof(review->method_text), "transfer");
    review->kind = TronKind::Trc20;
    return TronError::Ok;
  }
  // transferFrom(address from,address to,uint256 value) shares selector
  // 0x23b872dd with ERC-721 transferFrom. It is reviewable only when `from` is
  // this wallet, and the registry lookup that follows rejects any contract that
  // is not a registered TRC-20, so an NFT contract cannot slip through here.
  if (call_data_size == kTrc20TransferFromSize &&
      memcmp(call_data, kTrc20TransferFromSelector,
             sizeof(kTrc20TransferFromSelector)) == 0) {
    const uint8_t *from_word = call_data + 4;
    const uint8_t *to_word = from_word + kTronWordSize;
    const uint8_t *amount_word = to_word + kTronWordSize;
    if (!word_is_owner(from_word, review->owner)) return TronError::WrongWallet;
    if (!word_address(to_word, review->recipient)) return TronError::Malformed;
    memcpy(review->amount, amount_word, kTronWordSize);
    if (word_is_zero(review->amount)) return TronError::InvalidAmount;
    snprintf(review->method_text, sizeof(review->method_text), "transferFrom");
    review->kind = TronKind::Trc20;
    return TronError::Ok;
  }
  if (call_data_size == kTrc721SafeTransferSize &&
      memcmp(call_data, kTrc721SafeTransferSelector,
             sizeof(kTrc721SafeTransferSelector)) == 0) {
    const uint8_t *from_word = call_data + 4;
    const uint8_t *to_word = from_word + kTronWordSize;
    // The calldata `from` is part of the signed payload; a mismatch would
    // transfer someone else's token through this owner's contract call.
    if (!word_is_owner(from_word, review->owner)) return TronError::WrongWallet;
    if (!word_address(to_word, review->recipient)) return TronError::Malformed;
    memcpy(review->token_id, to_word + kTronWordSize, kTronWordSize);
    review->has_token_id = true;
    snprintf(review->method_text, sizeof(review->method_text), "safeTransferFrom");
    review->kind = TronKind::Trc721;
    return TronError::Ok;
  }
  if (call_data_size == kTrc1155SafeTransferSize &&
      memcmp(call_data, kTrc1155SafeTransferSelector,
             sizeof(kTrc1155SafeTransferSelector)) == 0) {
    const uint8_t *from_word = call_data + 4;
    const uint8_t *to_word = from_word + kTronWordSize;
    const uint8_t *id_word = to_word + kTronWordSize;
    const uint8_t *value_word = id_word + kTronWordSize;
    const uint8_t *offset_word = value_word + kTronWordSize;
    const uint8_t *length_word = offset_word + kTronWordSize;
    if (!word_is_owner(from_word, review->owner)) return TronError::WrongWallet;
    if (!word_address(to_word, review->recipient)) return TronError::Malformed;
    // Only the canonical empty-bytes tail is reviewable. A non-empty receiver
    // hook is code execution hidden inside a transfer and is refused.
    if (!word_is_u64(offset_word, 0xa0) || !word_is_zero(length_word)) {
      return TronError::Unsupported;
    }
    memcpy(review->token_id, id_word, kTronWordSize);
    memcpy(review->amount, value_word, kTronWordSize);
    if (word_is_zero(review->amount)) return TronError::InvalidAmount;
    review->has_token_id = true;
    snprintf(review->method_text, sizeof(review->method_text), "safeTransferFrom");
    review->kind = TronKind::Trc1155;
    return TronError::Ok;
  }
  // 0x23b872dd is shared by ERC-20 and ERC-721 transferFrom; without a
  // registered standard it cannot be reviewed as either. Batch transfers and
  // safeTransferFrom with a callback tail are likewise unsupported.
  return TronError::Unsupported;
}

TronError parse_contract(const uint8_t *data, size_t size,
                         TronTransferReview *review) {
  ProtoReader reader = {data, size, 0};
  bool has_type = false, has_any = false, has_permission = false;
  uint64_t type = 0;
  const uint8_t *any = nullptr;
  size_t any_size = 0;
  while (reader.offset < size) {
    uint32_t field = 0;
    uint8_t wire = 0;
    size_t length = 0;
    if (!reader.tag(&field, &wire)) return TronError::Malformed;
    switch (field) {
      case 1:
        if (wire != 0 || has_type || !reader.varint(&type)) return TronError::Malformed;
        has_type = true;
        break;
      case 2:
        if (wire != 2 || has_any || !reader.length(&any_size) ||
            !reader.take(any_size, &any)) {
          return TronError::Malformed;
        }
        has_any = true;
        break;
      case 5: {
        uint64_t permission = 0;
        if (wire != 0 || has_permission || !reader.varint(&permission)) {
          return TronError::Malformed;
        }
        // Only the owner permission (0/absent) is signed by this review.
        if (permission != 0) return TronError::Unsupported;
        has_permission = true;
        break;
      }
      default:
        // provider / ContractName and unknown fields are not reviewable here.
        (void)length;
        return TronError::Unsupported;
    }
  }
  if (!has_type || !has_any) return TronError::Malformed;
  const uint8_t *body = nullptr;
  size_t body_size = 0;
  if (type == kContractTransfer) {
    const TronError error = parse_any(any, any_size, kTypeUrlTransfer, &body, &body_size);
    return error == TronError::Ok ? parse_transfer_body(body, body_size, review) : error;
  }
  if (type == kContractTransferAsset) {
    const TronError error =
        parse_any(any, any_size, kTypeUrlTransferAsset, &body, &body_size);
    return error == TronError::Ok ? parse_transfer_asset_body(body, body_size, review)
                                  : error;
  }
  if (type == kContractTriggerSmart) {
    const TronError error = parse_any(any, any_size, kTypeUrlTrigger, &body, &body_size);
    return error == TronError::Ok ? parse_trigger_body(body, body_size, review) : error;
  }
  return TronError::Unsupported;
}

TronError parse_raw(const uint8_t *data, size_t size, TronTransferReview *review) {
  ProtoReader reader = {data, size, 0};
  bool has_ref_bytes = false, has_ref_hash = false, has_expiration = false;
  bool has_timestamp = false, has_contract = false, has_fee_limit = false;
  bool has_memo_field = false;
  uint64_t expiration = 0, timestamp = 0, fee_limit = 0;
  const uint8_t *contract = nullptr;
  size_t contract_size = 0;
  while (reader.offset < size) {
    uint32_t field = 0;
    uint8_t wire = 0;
    const uint8_t *bytes = nullptr;
    size_t length = 0;
    if (!reader.tag(&field, &wire)) return TronError::Malformed;
    switch (field) {
      case 1:  // ref_block_bytes
        if (wire != 2 || has_ref_bytes || !reader.length(&length) ||
            !reader.take(length, &bytes) || length != 2) {
          return TronError::Malformed;
        }
        has_ref_bytes = true;
        break;
      case 3:  // deprecated ref_block_num is outside the reviewed encoding
        return TronError::Unsupported;
      case 4:  // ref_block_hash
        if (wire != 2 || has_ref_hash || !reader.length(&length) ||
            !reader.take(length, &bytes) || length != sizeof(review->ref_block_hash)) {
          return TronError::Malformed;
        }
        memcpy(review->ref_block_hash, bytes, sizeof(review->ref_block_hash));
        has_ref_hash = true;
        break;
      case 8:  // expiration
        if (wire != 0 || has_expiration || !reader.varint(&expiration) ||
            expiration > static_cast<uint64_t>(INT64_MAX)) {
          return TronError::Malformed;
        }
        has_expiration = true;
        break;
      case 11:  // contract
        if (wire != 2 || has_contract || !reader.length(&contract_size) ||
            !reader.take(contract_size, &contract)) {
          return TronError::Malformed;
        }
        has_contract = true;
        break;
      case 14:  // timestamp
        if (wire != 0 || has_timestamp || !reader.varint(&timestamp) ||
            timestamp > static_cast<uint64_t>(INT64_MAX)) {
          return TronError::Malformed;
        }
        has_timestamp = true;
        break;
      case 18:  // fee_limit
        if (wire != 0 || has_fee_limit || !reader.varint(&fee_limit) ||
            fee_limit > static_cast<uint64_t>(INT64_MAX)) {
          return TronError::Malformed;
        }
        has_fee_limit = true;
        break;
      case 10: {  // data (memo)
        if (wire != 2 || has_memo_field || !reader.length(&length) ||
            !reader.take(length, &bytes) || length > kTronMemoSize) {
          return TronError::Malformed;
        }
        has_memo_field = true;
        if (length == 0) break;
        // The memo is shown in full on the trusted display, so only printable
        // ASCII is reviewable; anything else would be signed unseen.
        for (size_t index = 0; index < length; ++index) {
          if (bytes[index] < 0x20 || bytes[index] > 0x7e) {
            return TronError::Unsupported;
          }
        }
        memcpy(review->memo_text, bytes, length);
        review->memo_text[length] = '\0';
        review->has_memo = true;
        break;
      }
      default:
        // auths (9), memo trailers this review cannot render, and anything
        // newer are not displayed, so signing them would be blind signing.
        return TronError::Unsupported;
    }
  }
  if (!has_ref_bytes || !has_ref_hash || !has_expiration || !has_timestamp ||
      !has_contract) {
    return TronError::Malformed;
  }
  review->expiration_ms = static_cast<int64_t>(expiration);
  review->timestamp_ms = static_cast<int64_t>(timestamp);
  review->fee_limit_sun = fee_limit;
  return parse_contract(contract, contract_size, review);
}

#include "src/generated/TronVectorsTest.inc"

}  // namespace

TronError tron_review_raw_data(const uint8_t *data, size_t size,
                               const uint8_t owner[kTronAddressSize],
                               TronTransaction *out) {
  if (out != nullptr) clear_tron_transaction(out);
  if (data == nullptr || owner == nullptr || out == nullptr || size == 0) {
    return TronError::InvalidArgument;
  }
  if (size > kTronMaxRawData) return TronError::Unsupported;
  TronTransferReview review = {};
  const TronError parsed = parse_raw(data, size, &review);
  if (parsed != TronError::Ok) return parsed;
  if (!bytes_equal(review.owner, owner, kTronAddressSize)) return TronError::WrongWallet;
  if (review.owner[0] != kTronAddressPrefix ||
      review.recipient[0] != kTronAddressPrefix) {
    return TronError::Malformed;
  }
  if (bytes_equal(review.recipient, review.owner, kTronAddressSize) ||
      all_zero(review.recipient + 1, kTronAddressSize - 1)) {
    return TronError::InvalidAmount;
  }
  const int64_t lifetime = review.expiration_ms - review.timestamp_ms;
  if (lifetime <= 0 || lifetime > kTronMaxLifetimeMs) return TronError::Malformed;
  if (review.kind == TronKind::Native) {
    if (review.fee_limit_sun != 0) return TronError::Unsupported;
    review.token_decimals = kTronTrxDecimals;
    snprintf(review.token_symbol, sizeof(review.token_symbol), "TRX");
  } else if (review.kind == TronKind::Trc10) {
    // TransferAssetContract burns bandwidth only; a fee_limit there is a field
    // this review does not model, so it is refused rather than ignored.
    if (review.fee_limit_sun != 0) return TronError::Unsupported;
    const TokenProfile *asset = find_trc10(review.asset_id, review.asset_id_size);
    if (asset != nullptr && asset->symbol != nullptr && asset->symbol[0] != '\0' &&
        asset->decimals <= 32) {
      review.asset_registered = true;
      review.token_decimals = asset->decimals;
      snprintf(review.token_symbol, sizeof(review.token_symbol), "%s", asset->symbol);
    } else {
      // Unregistered asset: the identifier is displayed verbatim and the amount
      // stays in exact base units. No precision is invented.
      review.asset_registered = false;
      review.token_decimals = 0;
      snprintf(review.token_symbol, sizeof(review.token_symbol), "TRC10");
    }
  } else if (review.kind == TronKind::Trc20) {
    if (review.fee_limit_sun == 0 || review.fee_limit_sun > kTronMaxFeeLimitSun) {
      return TronError::FeePolicy;
    }
    const TokenProfile *token = find_trc20(review.token_contract);
    if (token == nullptr || token->symbol == nullptr || token->symbol[0] == '\0' ||
        token->decimals > 32) {
      return TronError::UnknownToken;
    }
    review.token_decimals = token->decimals;
    snprintf(review.token_symbol, sizeof(review.token_symbol), "%s", token->symbol);
  } else {
    // There are no verified TRC-721/1155 contract registrations yet. Parsing
    // the ABI is insufficient evidence of the contract's effects.
    return TronError::UnknownToken;
  }
  if (!address_text(review.owner, review.owner_text, sizeof(review.owner_text)) ||
      !address_text(review.recipient, review.recipient_text,
                    sizeof(review.recipient_text)) ||
      !tron_format_amount(review, review.amount_text, sizeof(review.amount_text))) {
    return TronError::CryptoFailure;
  }
  if (review.kind != TronKind::Native && review.kind != TronKind::Trc10 &&
      !address_text(review.token_contract, review.token_contract_text,
                    sizeof(review.token_contract_text))) {
    return TronError::CryptoFailure;
  }
  if (!crypto_sha256(data, size, review.tx_id)) return TronError::CryptoFailure;
  memcpy(out->raw_data, data, size);
  out->raw_data_size = static_cast<uint16_t>(size);
  out->review = review;
  return TronError::Ok;
}

TronError tron_sign_transaction(const TronTransaction &reviewed,
                                const uint8_t private_key[kPrivateKeySize],
                                uint8_t *out_signature, size_t *in_out_size) {
  const size_t capacity = in_out_size == nullptr ? 0 : *in_out_size;
  if (in_out_size != nullptr) *in_out_size = 0;
  if (private_key == nullptr || out_signature == nullptr || in_out_size == nullptr ||
      reviewed.raw_data_size == 0 || reviewed.raw_data_size > kTronMaxRawData) {
    return TronError::InvalidArgument;
  }
  if (capacity < kTronSignatureSize) {
    return TronError::BufferTooSmall;
  }
  TronTransaction verified = {};
  TronError error = tron_review_raw_data(reviewed.raw_data, reviewed.raw_data_size,
                                        reviewed.review.owner, &verified);
  if (error == TronError::Ok && !same_review(verified.review, reviewed.review)) {
    error = TronError::Malformed;
  }
  uint8_t owner[kTronAddressSize] = {};
  if (error == TronError::Ok) error = tron_owner_from_private(private_key, owner);
  if (error == TronError::Ok && !bytes_equal(owner, verified.review.owner, sizeof(owner))) {
    error = TronError::WrongWallet;
  }
  secure_zero(owner, sizeof(owner));
  if (error != TronError::Ok) {
    clear_tron_transaction(&verified);
    return error;
  }
  RecoverableSignature signature = {};
  const WalletError signed_error = secp256k1_sign_digest_recoverable(
      private_key, verified.review.tx_id, &signature);
  clear_tron_transaction(&verified);
  if (signed_error != WalletError::Ok) {
    secure_zero(&signature, sizeof(signature));
    return TronError::CryptoFailure;
  }
  size_t encoded_size = capacity;
  const TronError encoded = tron_encode_signature(signature, out_signature, &encoded_size);
  if (encoded == TronError::Ok) *in_out_size = encoded_size;
  secure_zero(&signature, sizeof(signature));
  return encoded;
}

TronError tron_encode_signature(const RecoverableSignature &signature,
                                uint8_t *out_signature, size_t *in_out_size) {
  if (out_signature == nullptr || in_out_size == nullptr ||
      signature.y_parity > 1) {
    return TronError::InvalidArgument;
  }
  if (*in_out_size < kTronSignatureSize) {
    *in_out_size = kTronSignatureSize;
    return TronError::BufferTooSmall;
  }
  memcpy(out_signature, signature.r, sizeof(signature.r));
  memcpy(out_signature + sizeof(signature.r), signature.s, sizeof(signature.s));
  out_signature[64] = static_cast<uint8_t>(27 + signature.y_parity);
  *in_out_size = kTronSignatureSize;
  return TronError::Ok;
}

bool tron_format_amount(const TronTransferReview &review, char *out, size_t size) {
  if (out == nullptr || size == 0) return false;
  if (review.kind == TronKind::Trc721) {
    const int written = snprintf(out, size, "1 NFT");
    return written > 0 && static_cast<size_t>(written) < size;
  }
  if (review.kind == TronKind::Trc10 && !review.asset_registered) {
    // Base units are what the chain moves; without the issuer's precision any
    // decimal point would be an invention.
    char units[kTronAmountTextSize];
    if (!format_units(review.amount, 0, units, sizeof(units))) return false;
    const int written = snprintf(out, size, "%s base units", units);
    return written > 0 && static_cast<size_t>(written) < size;
  }
  const uint8_t decimals =
      review.kind == TronKind::Native ? kTronTrxDecimals
      : review.kind == TronKind::Trc1155 ? 0
                                          : review.token_decimals;
  const char *symbol =
      review.kind == TronKind::Native ? "TRX" : review.token_symbol;
  char units[kTronAmountTextSize];
  if (!format_units(review.amount, decimals, units, sizeof(units))) return false;
  const int written = snprintf(out, size, "%s %s", units, symbol);
  return written > 0 && static_cast<size_t>(written) < size;
}

TronError tron_owner_from_private(const uint8_t private_key[kPrivateKeySize],
                                  uint8_t out_owner[kTronAddressSize]) {
  if (private_key == nullptr || out_owner == nullptr) return TronError::InvalidArgument;
  uint8_t public_key[kUncompressedPublicKeySize];
  if (uncompressed_public_key_from_private(private_key, public_key) != WalletError::Ok) {
    return TronError::CryptoFailure;
  }
  uint8_t digest[kKeccak256Size];
  const bool hashed =
      crypto_keccak256(public_key + 1, kUncompressedPublicKeySize - 1, digest);
  secure_zero(public_key, sizeof(public_key));
  if (!hashed) {
    secure_zero(digest, sizeof(digest));
    return TronError::CryptoFailure;
  }
  out_owner[0] = kTronAddressPrefix;
  memcpy(out_owner + 1, digest + kKeccak256Size - 20, 20);
  secure_zero(digest, sizeof(digest));
  return TronError::Ok;
}

void clear_tron_transaction(TronTransaction *transaction) {
  if (transaction != nullptr) secure_zero(transaction, sizeof(*transaction));
}

const char *tron_error_text(TronError error) {
  switch (error) {
    case TronError::Ok: return "ok";
    case TronError::InvalidArgument: return "invalid-argument";
    case TronError::Malformed: return "malformed-transaction";
    case TronError::Unsupported: return "unsupported-transaction";
    case TronError::WrongWallet: return "wrong-wallet";
    case TronError::InvalidAmount: return "invalid-amount";
    case TronError::FeePolicy: return "fee-policy";
    case TronError::UnknownToken: return "unknown-token";
    case TronError::CryptoFailure: return "crypto-failure";
    case TronError::BufferTooSmall: return "buffer-too-small";
  }
  return "unknown";
}

bool run_tron_self_tests() {
  uint8_t private_key[kPrivateKeySize];
  uint8_t owner[kTronAddressSize];
  size_t owner_size = sizeof(owner);
  bool passed = hex_decode_exact(kTronVectorPrivateKeyHex, private_key, sizeof(private_key)) &&
                b58check_dec(owner, &owner_size, kTronVectorAddress) &&
                owner_size == kTronAddressSize;
  // The host harness stubs secp256k1 on purpose; the on-device self-test
  // recomputes the address from the same reference key.
#if !defined(HEXWALLET_HOST_TEST)
  uint8_t derived_owner[kTronAddressSize] = {};
  passed = passed &&
           tron_owner_from_private(private_key, derived_owner) == TronError::Ok &&
           bytes_equal(derived_owner, owner, kTronAddressSize);
  secure_zero(derived_owner, sizeof(derived_owner));
#endif

  uint8_t foreign_owner[kTronAddressSize];
  memcpy(foreign_owner, owner, sizeof(foreign_owner));
  foreign_owner[20] ^= 1;

  for (const TronVectorCase &vector : kTronVectorCases) {
    if (!passed) break;
    uint8_t raw[kTronMaxRawData];
    const size_t raw_size = vector.raw_hex == nullptr ? 0 : strlen(vector.raw_hex) / 2;
    uint8_t expected_txid[kTronTxIdSize];
    uint8_t expected_signature[kTronSignatureSize] = {};
    const bool has_signature = vector.signature_hex != nullptr;
    const bool owned_by_fixture = vector.owner_base58 == nullptr;
    uint8_t case_owner[kTronAddressSize];
    memcpy(case_owner, owner, sizeof(case_owner));
    passed = raw_size > 0 && raw_size <= sizeof(raw) &&
             hex_decode_exact(vector.raw_hex, raw, raw_size) &&
             hex_decode_exact(vector.txid_hex, expected_txid, sizeof(expected_txid));
    if (passed && has_signature) {
      passed = hex_decode_exact(vector.signature_hex, expected_signature,
                          sizeof(expected_signature));
    }
    if (passed && !owned_by_fixture) {
      size_t case_owner_size = sizeof(case_owner);
      passed = b58check_dec(case_owner, &case_owner_size, vector.owner_base58) &&
               case_owner_size == kTronAddressSize;
    }
    if (!passed) break;

    TronTransaction transaction;
    const TronError reviewed =
        tron_review_raw_data(raw, raw_size, case_owner, &transaction);
    passed = reviewed == TronError::Ok &&
             transaction.review.kind == vector.expected_kind &&
             bytes_equal(transaction.review.tx_id, expected_txid, kTronTxIdSize) &&
             tron_format_amount(transaction.review, transaction.review.amount_text,
                                sizeof(transaction.review.amount_text));
    if (passed && vector.expected_amount_text != nullptr) {
      passed =
          strcmp(transaction.review.amount_text, vector.expected_amount_text) == 0;
    }
    if (passed && vector.expected_method != nullptr) {
      passed = strcmp(transaction.review.method_text, vector.expected_method) == 0;
    }
    if (passed && vector.expected_memo != nullptr) {
      passed = transaction.review.has_memo &&
               strcmp(transaction.review.memo_text, vector.expected_memo) == 0;
    }
    if (passed && has_signature) {
      // The envelope is checked on every build; the curve itself is stubbed in
      // the host harness, so the exact signature is compared on-device below.
      // Mainnet carries both the raw recovery id and the 27-offset form in byte
      // 64, so that byte is accepted in either convention while r||s must match
      // the canonical encoding exactly.
      const uint8_t chain_v = expected_signature[64];
      const uint8_t parity =
          chain_v >= 27 ? static_cast<uint8_t>(chain_v - 27) : chain_v;
      RecoverableSignature envelope = {};
      memcpy(envelope.r, expected_signature, sizeof(envelope.r));
      memcpy(envelope.s, expected_signature + 32, sizeof(envelope.s));
      envelope.y_parity = parity;
      uint8_t encoded[kTronSignatureSize];
      size_t encoded_size = sizeof(encoded);
      passed = parity <= 1 &&
               tron_encode_signature(envelope, encoded, &encoded_size) == TronError::Ok &&
               encoded_size == kTronSignatureSize &&
               bytes_equal(encoded, expected_signature, 64) &&
               (chain_v == encoded[64] || chain_v == parity);
      secure_zero(&envelope, sizeof(envelope));
      secure_zero(encoded, sizeof(encoded));
    }
#if !defined(HEXWALLET_HOST_TEST)
    if (passed && owned_by_fixture) {
      // Chain vectors signed by other accounts still prove parse, txid and the
      // displayed amount; only this wallet's key can be reproduced here.
      uint8_t signature[kTronSignatureSize + 8];
      size_t signature_size = sizeof(signature);
      passed = tron_sign_transaction(transaction, private_key, signature,
                                     &signature_size) == TronError::Ok &&
               signature_size == kTronSignatureSize &&
               (!has_signature ||
                bytes_equal(signature, expected_signature, kTronSignatureSize));
      secure_zero(signature, sizeof(signature));
    }
#endif
    // Re-hashing must bind the signature to the reviewed bytes.
#if !defined(HEXWALLET_HOST_TEST)
    if (passed && owned_by_fixture) {
      TronTransaction tampered = transaction;
      tampered.review.tx_id[0] ^= 1;
      uint8_t signature[kTronSignatureSize];
      size_t signature_size = sizeof(signature) - 1;
      passed = tron_sign_transaction(tampered, private_key, signature, &signature_size) ==
               TronError::BufferTooSmall;
      signature_size = sizeof(signature);
      passed = passed && tron_sign_transaction(tampered, private_key, signature,
                                               &signature_size) == TronError::Malformed;
      secure_zero(signature, sizeof(signature));
      clear_tron_transaction(&tampered);
    }
#endif
    // A different wallet must never be able to sign this raw_data.
    if (passed) {
      TronTransaction other;
      passed = tron_review_raw_data(raw, raw_size, foreign_owner, &other) ==
               TronError::WrongWallet;
      clear_tron_transaction(&other);
    }
    // Every truncated prefix must be refused. The one exception is a prefix
    // that cuts only trailing optional data (the memo): that prefix is a
    // different, still-valid transaction and must then review without a memo
    // rather than inherit the one from the bytes it dropped.
    for (size_t end = 1; end < raw_size && passed; ++end) {
      TronTransaction probe;
      const TronError prefix_error = tron_review_raw_data(raw, end, case_owner, &probe);
      if (prefix_error == TronError::Ok) {
        passed = vector.expected_memo != nullptr && !probe.review.has_memo;
      }
      clear_tron_transaction(&probe);
    }
    clear_tron_transaction(&transaction);
  }

  // Rejection cases that only make sense against the account that signed them.
  for (const TronRejectedDetailCase &vector : kTronRejectedDetailCases) {
    if (!passed) break;
    uint8_t raw[kTronMaxRawData];
    const size_t raw_size = vector.raw_hex == nullptr ? 0 : strlen(vector.raw_hex) / 2;
    uint8_t case_owner[kTronAddressSize];
    size_t case_owner_size = sizeof(case_owner);
    passed = raw_size > 0 && raw_size <= sizeof(raw) &&
             hex_decode_exact(vector.raw_hex, raw, raw_size) &&
             b58check_dec(case_owner, &case_owner_size, vector.owner_base58) &&
             case_owner_size == kTronAddressSize;
    if (!passed) break;
    TronTransaction transaction;
    passed = tron_review_raw_data(raw, raw_size, case_owner, &transaction) ==
             vector.expected_error;
    clear_tron_transaction(&transaction);
  }

  for (const TronRejectedCase &vector : kTronRejectedCases) {
    if (!passed) break;
    uint8_t raw[kTronMaxRawData];
    const size_t raw_size = vector.raw_hex == nullptr ? 0 : strlen(vector.raw_hex) / 2;
    passed = raw_size <= sizeof(raw) && hex_decode_exact(vector.raw_hex, raw, raw_size);
    if (!passed) break;
    TronTransaction transaction;
    passed = tron_review_raw_data(raw, raw_size, owner, &transaction) != TronError::Ok;
    clear_tron_transaction(&transaction);
  }

  if (passed) {
    TronTransferReview review = {};
    review.kind = TronKind::Native;
    review.amount[29] = 0x16;
    review.amount[30] = 0xe3;
    review.amount[31] = 0x60;  // 1_500_000 sun
    char text[kTronAmountTextSize];
    passed = tron_format_amount(review, text, sizeof(text)) &&
             strcmp(text, "1.500000 TRX") == 0;
  }
  if (passed) {
    // An unregistered TRC-10 asset has no verifiable precision, so the amount
    // must stay an exact base-unit integer instead of gaining a decimal point.
    TronTransferReview review = {};
    review.kind = TronKind::Trc10;
    review.asset_registered = false;
    snprintf(review.token_symbol, sizeof(review.token_symbol), "TRC10");
    review.amount[31] = 7;
    char text[kTronAmountTextSize];
    passed = tron_format_amount(review, text, sizeof(text)) &&
             strcmp(text, "7 base units") == 0;
  }
  secure_zero(private_key, sizeof(private_key));
  secure_zero(owner, sizeof(owner));
  secure_zero(foreign_owner, sizeof(foreign_owner));
  return passed;
}

}  // namespace hexwallet
