#include "TronTransaction.h"

#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletAddresses.h"
#include "WalletTokens.h"
#include "base58.h"

namespace hexwallet {
namespace {

constexpr uint8_t kTronAddressPrefix = 0x41;
constexpr uint64_t kContractTransfer = 1;
constexpr uint64_t kContractTriggerSmart = 31;
constexpr char kTypeUrlTransfer[] = "type.googleapis.com/protocol.TransferContract";
constexpr char kTypeUrlTrigger[] = "type.googleapis.com/protocol.TriggerSmartContract";
constexpr uint8_t kTrc20TransferSelector[4] = {0xa9, 0x05, 0x9c, 0xbb};
constexpr uint8_t kTrc721SafeTransferSelector[4] = {0x42, 0x84, 0x2e, 0x0e};
constexpr uint8_t kTrc1155SafeTransferSelector[4] = {0xf2, 0x42, 0x43, 0x2a};
constexpr size_t kTrc20DataSize = 68;
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

bool equal(const uint8_t *left, const uint8_t *right, size_t size) {
  return crypto_constant_time_equal(left, right, size);
}

bool all_zero(const uint8_t *data, size_t size) {
  uint8_t accumulator = 0;
  for (size_t index = 0; index < size; ++index) accumulator |= data[index];
  return accumulator == 0;
}

bool same_review(const TronTransferReview &a, const TronTransferReview &b) {
  return a.kind == b.kind && a.token_decimals == b.token_decimals &&
      a.has_token_id == b.has_token_id && a.fee_limit_sun == b.fee_limit_sun &&
      a.expiration_ms == b.expiration_ms && a.timestamp_ms == b.timestamp_ms &&
      equal(a.owner, b.owner, sizeof(a.owner)) &&
      equal(a.recipient, b.recipient, sizeof(a.recipient)) &&
      equal(a.token_contract, b.token_contract, sizeof(a.token_contract)) &&
      equal(a.amount, b.amount, sizeof(a.amount)) &&
      equal(a.token_id, b.token_id, sizeof(a.token_id)) &&
      equal(a.ref_block_hash, b.ref_block_hash, sizeof(a.ref_block_hash)) &&
      equal(a.tx_id, b.tx_id, sizeof(a.tx_id)) &&
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
         equal(word + 12, owner + 1, kTronAddressSize - 1);
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
        equal(decoded, contract, kTronAddressSize)) {
      return &token;
    }
  }
  return nullptr;
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
  memset(review->amount, 0, kTronWordSize);
  for (size_t index = 0; index < 8; ++index) {
    review->amount[kTronWordSize - 1 - index] =
        static_cast<uint8_t>(amount >> (8 * index));
  }
  review->kind = TronKind::Native;
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
      default:
        // Memo / data (10), auths (9) and anything newer are not displayed by
        // this review, so signing them would be blind signing.
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

bool hex_decode(const char *text, uint8_t *out, size_t size) {
  if (text == nullptr || out == nullptr || strlen(text) != size * 2) return false;
  const auto digit = [](char value) -> int {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
  };
  for (size_t index = 0; index < size; ++index) {
    const int high = digit(text[index * 2]);
    const int low = digit(text[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

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
  if (!equal(review.owner, owner, kTronAddressSize)) return TronError::WrongWallet;
  if (review.owner[0] != kTronAddressPrefix ||
      review.recipient[0] != kTronAddressPrefix) {
    return TronError::Malformed;
  }
  if (equal(review.recipient, review.owner, kTronAddressSize) ||
      all_zero(review.recipient + 1, kTronAddressSize - 1)) {
    return TronError::InvalidAmount;
  }
  const int64_t lifetime = review.expiration_ms - review.timestamp_ms;
  if (lifetime <= 0 || lifetime > kTronMaxLifetimeMs) return TronError::Malformed;
  if (review.kind == TronKind::Native) {
    if (review.fee_limit_sun != 0) return TronError::Unsupported;
    review.token_decimals = kTronTrxDecimals;
    snprintf(review.token_symbol, sizeof(review.token_symbol), "TRX");
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
  if (review.kind != TronKind::Native &&
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
  if (error == TronError::Ok && !equal(owner, verified.review.owner, sizeof(owner))) {
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
  bool passed = hex_decode(kTronVectorPrivateKeyHex, private_key, sizeof(private_key)) &&
                b58check_dec(owner, &owner_size, kTronVectorAddress) &&
                owner_size == kTronAddressSize;
  // The host harness stubs secp256k1 on purpose; the on-device self-test
  // recomputes the address from the same reference key.
#if !defined(HEXWALLET_HOST_TEST)
  uint8_t derived_owner[kTronAddressSize] = {};
  passed = passed &&
           tron_owner_from_private(private_key, derived_owner) == TronError::Ok &&
           equal(derived_owner, owner, kTronAddressSize);
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
    uint8_t expected_signature[kTronSignatureSize];
    passed = raw_size <= sizeof(raw) &&
             hex_decode(vector.raw_hex, raw, raw_size) &&
             hex_decode(vector.txid_hex, expected_txid, sizeof(expected_txid)) &&
             hex_decode(vector.signature_hex, expected_signature,
                        sizeof(expected_signature));
    if (!passed) break;

    TronTransaction transaction;
    const TronError reviewed = tron_review_raw_data(raw, raw_size, owner, &transaction);
    passed = reviewed == TronError::Ok &&
             equal(transaction.review.tx_id, expected_txid, kTronTxIdSize) &&
             tron_format_amount(transaction.review, transaction.review.amount_text,
                                sizeof(transaction.review.amount_text));
    if (passed) {
      // The envelope is checked on every build; the curve itself is stubbed in
      // the host harness, so the exact signature is compared on-device below.
      RecoverableSignature envelope = {};
      memcpy(envelope.r, expected_signature, sizeof(envelope.r));
      memcpy(envelope.s, expected_signature + 32, sizeof(envelope.s));
      envelope.y_parity = static_cast<uint8_t>(expected_signature[64] - 27);
      uint8_t encoded[kTronSignatureSize];
      size_t encoded_size = sizeof(encoded);
      passed = tron_encode_signature(envelope, encoded, &encoded_size) == TronError::Ok &&
               encoded_size == kTronSignatureSize &&
               equal(encoded, expected_signature, kTronSignatureSize);
      secure_zero(&envelope, sizeof(envelope));
      secure_zero(encoded, sizeof(encoded));
    }
#if !defined(HEXWALLET_HOST_TEST)
    if (passed) {
      uint8_t signature[kTronSignatureSize + 8];
      size_t signature_size = sizeof(signature);
      passed = tron_sign_transaction(transaction, private_key, signature,
                                     &signature_size) == TronError::Ok &&
               signature_size == kTronSignatureSize &&
               equal(signature, expected_signature, kTronSignatureSize);
      secure_zero(signature, sizeof(signature));
    }
#endif
    // Re-hashing must bind the signature to the reviewed bytes.
#if !defined(HEXWALLET_HOST_TEST)
    if (passed) {
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
    // Every truncated prefix must be refused.
    for (size_t end = 1; end < raw_size && passed; ++end) {
      TronTransaction probe;
      passed = tron_review_raw_data(raw, end, owner, &probe) != TronError::Ok;
      clear_tron_transaction(&probe);
    }
    clear_tron_transaction(&transaction);
  }

  for (const TronRejectedCase &vector : kTronRejectedCases) {
    if (!passed) break;
    uint8_t raw[kTronMaxRawData];
    const size_t raw_size = vector.raw_hex == nullptr ? 0 : strlen(vector.raw_hex) / 2;
    passed = raw_size <= sizeof(raw) && hex_decode(vector.raw_hex, raw, raw_size);
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
  secure_zero(private_key, sizeof(private_key));
  secure_zero(owner, sizeof(owner));
  secure_zero(foreign_owner, sizeof(foreign_owner));
  return passed;
}

}  // namespace hexwallet
