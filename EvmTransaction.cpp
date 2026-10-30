#include "EvmTransaction.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "WalletConfig.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

constexpr uint8_t kEip2930Type = 0x01;
constexpr uint8_t kEip1559Type = 0x02;
constexpr uint8_t kErc20TransferSelector[4] = {0xa9, 0x05, 0x9c, 0xbb};
constexpr uint64_t kMinimumTransferGas = 21000;
constexpr uint64_t kMaximumTransferGas = 30000000;

struct Cursor {
  const uint8_t *data;
  size_t size;
  size_t position;
};

struct RlpItem {
  const uint8_t *data;
  size_t size;
  bool list;
};

struct Writer {
  uint8_t *data;
  size_t capacity;
  size_t position;
};

bool write_bytes(Writer *writer, const uint8_t *data, size_t size) {
  if (writer == nullptr || writer->position > writer->capacity ||
      size > writer->capacity - writer->position || (data == nullptr && size != 0)) return false;
  if (size != 0) memcpy(writer->data + writer->position, data, size);
  writer->position += size;
  return true;
}

bool write_byte(Writer *writer, uint8_t value) {
  return write_bytes(writer, &value, 1);
}

bool read_rlp_length(Cursor *cursor, size_t length_of_length, size_t *out) {
  if (length_of_length == 0 || length_of_length > sizeof(size_t) ||
      cursor->position + length_of_length > cursor->size ||
      cursor->data[cursor->position] == 0) return false;
  size_t value = 0;
  for (size_t index = 0; index < length_of_length; ++index) {
    if (value > (SIZE_MAX >> 8)) return false;
    value = (value << 8) | cursor->data[cursor->position++];
  }
  *out = value;
  return true;
}

EvmTransactionError read_rlp_item(Cursor *cursor, RlpItem *out) {
  if (cursor == nullptr || out == nullptr || cursor->position >= cursor->size) {
    return EvmTransactionError::Truncated;
  }
  const uint8_t prefix = cursor->data[cursor->position++];
  size_t payload_size = 0;
  bool list = false;
  if (prefix <= 0x7f) {
    out->data = cursor->data + cursor->position - 1;
    out->size = 1;
    out->list = false;
    return EvmTransactionError::Ok;
  } else if (prefix <= 0xb7) {
    payload_size = prefix - 0x80;
  } else if (prefix <= 0xbf) {
    const size_t length_size = prefix - 0xb7;
    if (!read_rlp_length(cursor, length_size, &payload_size)) return EvmTransactionError::NonCanonical;
    if (payload_size < 56) return EvmTransactionError::NonCanonical;
  } else if (prefix <= 0xf7) {
    payload_size = prefix - 0xc0;
    list = true;
  } else {
    const size_t length_size = prefix - 0xf7;
    if (!read_rlp_length(cursor, length_size, &payload_size)) return EvmTransactionError::NonCanonical;
    if (payload_size < 56) return EvmTransactionError::NonCanonical;
    list = true;
  }
  if (payload_size > cursor->size - cursor->position) return EvmTransactionError::Truncated;
  if (!list && payload_size == 1 && cursor->data[cursor->position] < 0x80) {
    return EvmTransactionError::NonCanonical;
  }
  out->data = cursor->data + cursor->position;
  out->size = payload_size;
  out->list = list;
  cursor->position += payload_size;
  return EvmTransactionError::Ok;
}

EvmTransactionError read_integer(const RlpItem &item, uint8_t *out, size_t out_size) {
  if (item.list || item.size > out_size || (item.size != 0 && item.data[0] == 0)) {
    return EvmTransactionError::NonCanonical;
  }
  memset(out, 0, out_size);
  if (item.size != 0) memcpy(out + out_size - item.size, item.data, item.size);
  return EvmTransactionError::Ok;
}

EvmTransactionError validate_access_list(const RlpItem &list, uint8_t *addresses,
                                         uint8_t *keys) {
  *addresses = 0;
  *keys = 0;
  if (!list.list) return EvmTransactionError::NonCanonical;
  if (list.size > kEvmMaxAccessListBytes) return EvmTransactionError::Unsupported;
  Cursor rows{list.data, list.size, 0};
  while (rows.position < rows.size) {
    RlpItem row{}, address{}, slots{};
    EvmTransactionError error = read_rlp_item(&rows, &row);
    if (error != EvmTransactionError::Ok) return error;
    if (!row.list) return EvmTransactionError::NonCanonical;
    Cursor fields{row.data, row.size, 0};
    error = read_rlp_item(&fields, &address);
    if (error == EvmTransactionError::Ok) error = read_rlp_item(&fields, &slots);
    if (error != EvmTransactionError::Ok) return error;
    if (fields.position != fields.size || address.list || address.size != 20 || !slots.list)
      return EvmTransactionError::NonCanonical;
    if (++*addresses > kEvmMaxAccessListAddresses) return EvmTransactionError::Unsupported;
    Cursor storage{slots.data, slots.size, 0};
    while (storage.position < storage.size) {
      RlpItem key{};
      error = read_rlp_item(&storage, &key);
      if (error != EvmTransactionError::Ok) return error;
      if (key.list || key.size != 32) return EvmTransactionError::NonCanonical;
      if (++*keys > kEvmMaxAccessListKeys) return EvmTransactionError::Unsupported;
    }
  }
  return EvmTransactionError::Ok;
}

EvmTransactionError read_u64(const RlpItem &item, uint64_t *out) {
  uint8_t bytes[8];
  const EvmTransactionError error = read_integer(item, bytes, sizeof(bytes));
  if (error != EvmTransactionError::Ok) return error;
  uint64_t value = 0;
  for (uint8_t byte : bytes) value = (value << 8) | byte;
  *out = value;
  return EvmTransactionError::Ok;
}

bool is_zero(const uint8_t *data, size_t size) {
  uint8_t value = 0;
  for (size_t index = 0; index < size; ++index) value |= data[index];
  return value == 0;
}

bool write_rlp_prefix(Writer *writer, size_t size, bool list) {
  const uint8_t short_base = list ? 0xc0 : 0x80;
  const uint8_t long_base = list ? 0xf7 : 0xb7;
  if (size <= 55) return write_byte(writer, static_cast<uint8_t>(short_base + size));
  uint8_t length[sizeof(size_t)];
  size_t used = 0;
  size_t value = size;
  while (value != 0) {
    length[sizeof(length) - 1 - used++] = static_cast<uint8_t>(value);
    value >>= 8;
  }
  return write_byte(writer, static_cast<uint8_t>(long_base + used)) &&
         write_bytes(writer, length + sizeof(length) - used, used);
}

bool write_rlp_bytes(Writer *writer, const uint8_t *data, size_t size) {
  if (size == 1 && data != nullptr && data[0] < 0x80) return write_byte(writer, data[0]);
  return write_rlp_prefix(writer, size, false) && write_bytes(writer, data, size);
}

bool write_rlp_u64(Writer *writer, uint64_t value) {
  if (value == 0) return write_rlp_bytes(writer, nullptr, 0);
  uint8_t bytes[8];
  size_t first = sizeof(bytes);
  while (value != 0) {
    bytes[--first] = static_cast<uint8_t>(value);
    value >>= 8;
  }
  return write_rlp_bytes(writer, bytes + first, sizeof(bytes) - first);
}

bool write_rlp_uint256(Writer *writer, const uint8_t value[kEvmUint256Size]) {
  size_t first = 0;
  while (first < kEvmUint256Size && value[first] == 0) ++first;
  return write_rlp_bytes(writer, value + first, kEvmUint256Size - first);
}

bool wrap_rlp_list(const uint8_t *payload, size_t payload_size,
                   uint8_t type, uint8_t *out, size_t capacity, size_t *out_size) {
  Writer writer = {out, capacity, 0};
  if (type != 0 && !write_byte(&writer, type)) return false;
  if (!write_rlp_prefix(&writer, payload_size, true) ||
      !write_bytes(&writer, payload, payload_size)) return false;
  *out_size = writer.position;
  return true;
}

bool serialize_transaction(const EvmSigningRequest &request,
                           const RecoverableSignature *signature,
                           uint8_t *out, size_t capacity, size_t *out_size) {
  uint8_t payload[kEvmMaxSignedTransactionSize];
  Writer writer = {payload, sizeof(payload), 0};
  const bool contract_call = request.has_call || request.token != nullptr;
  const uint8_t *native_value = contract_call ? request.native_value : request.amount;
  const bool dynamic_fee = request.type == EvmTransactionType::Eip1559;
  const bool typed = dynamic_fee || request.type == EvmTransactionType::Eip2930;
  if (!typed && request.type != EvmTransactionType::LegacyEip155) return false;
  bool ok;
  if (typed) {
    ok = write_rlp_u64(&writer, request.network->evm_chain_id) &&
         write_rlp_u64(&writer, request.nonce) &&
         (!dynamic_fee || write_rlp_u64(&writer, request.max_priority_fee)) &&
         write_rlp_u64(&writer, request.gas_price_or_max_fee) &&
         write_rlp_u64(&writer, request.gas_limit) &&
         write_rlp_bytes(&writer, request.contract, sizeof(request.contract)) &&
         write_rlp_uint256(&writer, native_value) &&
         write_rlp_bytes(&writer, request.data, request.data_size) &&
         write_rlp_prefix(&writer, request.access_list_size, true) &&
         write_bytes(&writer, request.access_list, request.access_list_size);
    if (ok && signature != nullptr) {
      ok = write_rlp_u64(&writer, signature->y_parity) &&
           write_rlp_uint256(&writer, signature->r) &&
           write_rlp_uint256(&writer, signature->s);
    }
  } else {
    ok = write_rlp_u64(&writer, request.nonce) &&
         write_rlp_u64(&writer, request.gas_price_or_max_fee) &&
         write_rlp_u64(&writer, request.gas_limit) &&
         write_rlp_bytes(&writer, request.contract, sizeof(request.contract)) &&
         write_rlp_uint256(&writer, native_value) &&
         write_rlp_bytes(&writer, request.data, request.data_size);
    if (ok && signature == nullptr) {
      ok = write_rlp_u64(&writer, request.network->evm_chain_id) &&
           write_rlp_u64(&writer, 0) && write_rlp_u64(&writer, 0);
    } else if (ok) {
      const uint64_t v = static_cast<uint64_t>(request.network->evm_chain_id) * 2U +
                         35U + signature->y_parity;
      ok = write_rlp_u64(&writer, v) && write_rlp_uint256(&writer, signature->r) &&
           write_rlp_uint256(&writer, signature->s);
    }
  }
  size_t serialized_size = 0;
  if (ok) ok = wrap_rlp_list(payload, writer.position,
                             dynamic_fee ? kEip1559Type : (typed ? kEip2930Type : 0),
                             out, capacity, &serialized_size);
  if (ok) *out_size = serialized_size;
  secure_zero(payload, sizeof(payload));
  return ok;
}

void address_text(const uint8_t address[kEvmAddressSize], char out[kAddressTextSize]) {
  static constexpr char kHex[] = "0123456789abcdef";
  out[0] = '0'; out[1] = 'x';
  for (size_t index = 0; index < kEvmAddressSize; ++index) {
    out[2 + index * 2] = kHex[address[index] >> 4];
    out[3 + index * 2] = kHex[address[index] & 0x0f];
  }
  out[42] = '\0';
}

int hex_nibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

bool decode_contract(const char *text, uint8_t out[kEvmAddressSize]) {
  if (text == nullptr || strlen(text) != 42 || text[0] != '0' || text[1] != 'x') return false;
  for (size_t index = 0; index < kEvmAddressSize; ++index) {
    const int high = hex_nibble(text[2 + index * 2]);
    const int low = hex_nibble(text[3 + index * 2]);
    if (high < 0 || low < 0) return false;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

const TokenProfile *find_token(const NetworkProfile &network,
                               const uint8_t contract[kEvmAddressSize]) {
  uint8_t candidate[kEvmAddressSize];
  for (size_t index = 0; index < kTokenProfileCount; ++index) {
    const TokenProfile &token = kTokenProfiles[index];
    if (strcmp(token.network_id, network.id) == 0 && token_supports_transfer_signing(token) &&
        decode_contract(token.contract_or_mint, candidate) &&
        crypto_constant_time_equal(candidate, contract, sizeof(candidate))) {
      secure_zero(candidate, sizeof(candidate));
      return &token;
    }
  }
  secure_zero(candidate, sizeof(candidate));
  return nullptr;
}

int compare_uint256(const uint8_t left[kEvmUint256Size],
                    const uint8_t right[kEvmUint256Size]) {
  for (size_t index = 0; index < kEvmUint256Size; ++index) {
    if (left[index] != right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

bool call_requires_wallet_sender(const DecodedTokenCalldata &call) {
  switch (call.standard) {
    case EvmTokenStandard::Erc20:
      return call.function == TokenFunction::TransferFrom;
    case EvmTokenStandard::Erc721:
    case EvmTokenStandard::Erc1155:
      return call.function == TokenFunction::TransferFrom ||
             call.function == TokenFunction::SafeTransferFrom ||
             call.function == TokenFunction::SafeTransferFromWithData ||
             call.function == TokenFunction::SafeBatchTransferFrom;
    case EvmTokenStandard::Erc4626:
      return call.function == TokenFunction::Withdraw ||
             call.function == TokenFunction::Redeem;
    case EvmTokenStandard::Erc777:
      return call.function == TokenFunction::OperatorSend;
    case EvmTokenStandard::LayerZeroOft:
      // OFT v2 send() has no from field; v1 sendFrom() does.
      return call.function == TokenFunction::OnftSendFrom;
    case EvmTokenStandard::LayerZeroOnft:
      return true;
    default:
      return false;
  }
}

void bytes32_text(const uint8_t value[kEvmUint256Size], char out[kEvmBytes32TextSize]) {
  static constexpr char kHex[] = "0123456789abcdef";
  out[0] = '0';
  out[1] = 'x';
  for (size_t index = 0; index < kEvmUint256Size; ++index) {
    out[2 + index * 2] = kHex[value[index] >> 4];
    out[3 + index * 2] = kHex[value[index] & 0x0f];
  }
  out[kEvmBytes32TextSize - 1] = '\0';
}

bool uint256_to_text(const uint8_t value[kEvmUint256Size], uint8_t decimals,
                     char out[kEvmAmountTextSize]) {
  uint8_t work[kEvmUint256Size];
  memcpy(work, value, sizeof(work));
  char reversed[80];
  size_t digits = 0;
  do {
    uint16_t remainder = 0;
    for (size_t index = 0; index < sizeof(work); ++index) {
      const uint16_t current = static_cast<uint16_t>((remainder << 8) | work[index]);
      work[index] = static_cast<uint8_t>(current / 10);
      remainder = current % 10;
    }
    reversed[digits++] = static_cast<char>('0' + remainder);
  } while (!is_zero(work, sizeof(work)) && digits < sizeof(reversed));
  secure_zero(work, sizeof(work));
  if (digits == sizeof(reversed)) return false;
  char plain[80];
  for (size_t index = 0; index < digits; ++index) plain[index] = reversed[digits - 1 - index];
  size_t position = 0;
  bool has_decimal = false;
  if (decimals == 0) {
    if (digits + 1 > kEvmAmountTextSize) return false;
    memcpy(out, plain, digits);
    position = digits;
  } else if (digits <= decimals) {
    const size_t zeroes = decimals - digits;
    if (2 + zeroes + digits + 1 > kEvmAmountTextSize) return false;
    out[position++] = '0'; out[position++] = '.';
    has_decimal = true;
    memset(out + position, '0', zeroes); position += zeroes;
    memcpy(out + position, plain, digits); position += digits;
  } else {
    if (digits + 2 > kEvmAmountTextSize) return false;
    const size_t integer_digits = digits - decimals;
    memcpy(out, plain, integer_digits); position += integer_digits;
    out[position++] = '.';
    has_decimal = true;
    memcpy(out + position, plain + integer_digits, decimals); position += decimals;
  }
  while (position > 0 && out[position - 1] == '0' && has_decimal) --position;
  if (position > 0 && out[position - 1] == '.') --position;
  out[position] = '\0';
  secure_zero(reversed, sizeof(reversed));
  secure_zero(plain, sizeof(plain));
  return true;
}

void uint64_to_uint256(uint64_t value, uint8_t out[kEvmUint256Size]) {
  memset(out, 0, kEvmUint256Size);
  for (size_t index = 0; index < 8; ++index) {
    out[kEvmUint256Size - 1 - index] = static_cast<uint8_t>(value);
    value >>= 8;
  }
}

bool decode_hex_string(const char *text, uint8_t *out, size_t capacity, size_t *out_size) {
  if (text == nullptr || out == nullptr || out_size == nullptr) return false;
  const size_t length = strlen(text);
  if ((length & 1U) != 0 || length / 2 > capacity) return false;
  for (size_t index = 0; index < length / 2; ++index) {
    const int high = hex_nibble(text[index * 2]);
    const int low = hex_nibble(text[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  *out_size = length / 2;
  return true;
}

}  // namespace

EvmTransactionError evm_parse_transaction(const uint8_t *transaction,
                                          size_t transaction_size,
                                          const NetworkProfile &network,
                                          const HdPrivateNode &master,
                                          uint32_t address_index,
                                          EvmSigningRequest *out) {
  if (out != nullptr) clear_evm_request(out);
  if (transaction == nullptr || out == nullptr || transaction_size == 0 ||
      transaction_size > kEvmMaxUnsignedTransactionSize ||
      network.encoding != AddressEncoding::Evm || network.evm_chain_id == 0 ||
      address_index >= kHardenedOffset) return EvmTransactionError::InvalidArgument;
  EvmSigningRequest parsed = {};
  parsed.network = &network;
  parsed.address_index = address_index;
  Cursor cursor = {transaction, transaction_size, 0};
  if (transaction[0] == kEip1559Type || transaction[0] == kEip2930Type) {
    parsed.type = transaction[0] == kEip1559Type ? EvmTransactionType::Eip1559
                                              : EvmTransactionType::Eip2930;
    cursor.position = 1;
    if (parsed.type == EvmTransactionType::Eip1559
            ? !network_supports_eip1559(network)
            : !network_supports_eip2930(network)) {
      return EvmTransactionError::Unsupported;
    }
  } else {
    // Reserved typed envelopes must never be interpreted as legacy RLP.
    if (transaction[0] < 0xc0) return EvmTransactionError::Unsupported;
    parsed.type = EvmTransactionType::LegacyEip155;
  }
  RlpItem outer;
  EvmTransactionError error = read_rlp_item(&cursor, &outer);
  if (error != EvmTransactionError::Ok) return error;
  if (!outer.list || cursor.position != cursor.size) return EvmTransactionError::NonCanonical;
  Cursor fields_cursor = {outer.data, outer.size, 0};
  RlpItem fields[9]{};
  const size_t field_count = parsed.type == EvmTransactionType::Eip2930 ? 8 : 9;
  for (size_t i = 0; i < field_count; ++i) {
    error = read_rlp_item(&fields_cursor, &fields[i]);
    if (error != EvmTransactionError::Ok) return error;
  }
  if (fields_cursor.position != fields_cursor.size) return EvmTransactionError::Unsupported;

  uint64_t chain_id = 0;
  uint8_t native_value[kEvmUint256Size];
  const RlpItem *to = nullptr;
  const RlpItem *value = nullptr;
  const RlpItem *data = nullptr;
  if (parsed.type != EvmTransactionType::LegacyEip155) {
    const bool dynamic_fee = parsed.type == EvmTransactionType::Eip1559;
    const size_t fee_index = dynamic_fee ? 3 : 2;
    error = read_u64(fields[0], &chain_id);
    if (error == EvmTransactionError::Ok) error = read_u64(fields[1], &parsed.nonce);
    if (error == EvmTransactionError::Ok && dynamic_fee)
      error = read_u64(fields[2], &parsed.max_priority_fee);
    if (error == EvmTransactionError::Ok)
      error = read_u64(fields[fee_index], &parsed.gas_price_or_max_fee);
    if (error == EvmTransactionError::Ok)
      error = read_u64(fields[fee_index + 1], &parsed.gas_limit);
    if (error != EvmTransactionError::Ok) return error;
    const RlpItem &access_list = fields[fee_index + 5];
    error = validate_access_list(access_list, &parsed.access_list_addresses,
                                 &parsed.access_list_keys);
    if (error != EvmTransactionError::Ok) return error;
    parsed.access_list_size = static_cast<uint16_t>(access_list.size);
    if (access_list.size != 0) memcpy(parsed.access_list, access_list.data, access_list.size);
    to = &fields[fee_index + 2]; value = &fields[fee_index + 3]; data = &fields[fee_index + 4];
    if (parsed.max_priority_fee > parsed.gas_price_or_max_fee) return EvmTransactionError::FeePolicy;
  } else {
    error = read_u64(fields[0], &parsed.nonce);
    if (error == EvmTransactionError::Ok) error = read_u64(fields[1], &parsed.gas_price_or_max_fee);
    if (error == EvmTransactionError::Ok) error = read_u64(fields[2], &parsed.gas_limit);
    if (error == EvmTransactionError::Ok) error = read_u64(fields[6], &chain_id);
    if (error != EvmTransactionError::Ok) return error;
    if (fields[7].list || fields[7].size != 0 || fields[8].list || fields[8].size != 0) {
      return EvmTransactionError::NonCanonical;
    }
    to = &fields[3]; value = &fields[4]; data = &fields[5];
  }
  if (chain_id != network.evm_chain_id) return EvmTransactionError::WrongNetwork;
  if (to->list || to->size != kEvmAddressSize || data->list || data->size > kEvmMaxDataSize) {
    return EvmTransactionError::Unsupported;
  }
  error = read_integer(*value, native_value, sizeof(native_value));
  if (error != EvmTransactionError::Ok) return error;
  uint64_t intrinsic_gas = kMinimumTransferGas +
      2400ULL * parsed.access_list_addresses + 1900ULL * parsed.access_list_keys;
  for (size_t i = 0; i < data->size; ++i) intrinsic_gas += data->data[i] == 0 ? 4 : 16;
  if (parsed.gas_limit < intrinsic_gas || parsed.gas_limit > kMaximumTransferGas ||
      parsed.gas_price_or_max_fee == 0 ||
      parsed.gas_limit > HEXWALLET_MAX_EVM_FEE_WEI / parsed.gas_price_or_max_fee) {
    secure_zero(native_value, sizeof(native_value));
    return EvmTransactionError::FeePolicy;
  }
  parsed.maximum_fee = parsed.gas_limit * parsed.gas_price_or_max_fee;
  memcpy(parsed.contract, to->data, sizeof(parsed.contract));
  parsed.data_size = static_cast<uint16_t>(data->size);
  if (data->size != 0) memcpy(parsed.data, data->data, data->size);

  if (data->size == 0) {
    if (is_zero(native_value, sizeof(native_value))) {
      secure_zero(native_value, sizeof(native_value));
      return EvmTransactionError::InvalidAmount;
    }
    memcpy(parsed.recipient, parsed.contract, sizeof(parsed.recipient));
    memcpy(parsed.amount, native_value, sizeof(parsed.amount));
  } else {
    parsed.token = find_token(network, parsed.contract);
    EvmTokenStandard standard = parsed.token != nullptr
                                    ? token_evm_standard(parsed.token->standard)
                                    : EvmTokenStandard::Unknown;
    // A selector describes an ABI shape, not the implementation at an address.
    // Never infer trusted transfer semantics from an unregistered contract.
    if (standard == EvmTokenStandard::Unknown) {
      secure_zero(native_value, sizeof(native_value));
      return EvmTransactionError::Unsupported;
    }
    DecodedTokenCalldata decoded = {};
    if (!token_decode_calldata(data->data, data->size, standard, &decoded)) {
      secure_zero(native_value, sizeof(native_value));
      return EvmTransactionError::Unsupported;
    }
    // Fungible amounts need the registered symbol and decimals; an unknown
    // ERC-20 selector is not reviewable as a token transfer.
    if (decoded.standard == EvmTokenStandard::Erc20 && parsed.token == nullptr) {
      secure_zero(native_value, sizeof(native_value));
      return EvmTransactionError::Unsupported;
    }
    // The trusted display cannot itemise an arbitrary ERC-1155 batch, and an
    // opaque receiver hook is code execution hidden inside a transfer. Both
    // are refused rather than displayed as something they are not.
    const bool batch_transfer =
        decoded.function == TokenFunction::SafeBatchTransferFrom;
    const bool opaque_transfer_tail =
        (decoded.standard == EvmTokenStandard::Erc721 ||
         decoded.standard == EvmTokenStandard::Erc1155 ||
         decoded.standard == EvmTokenStandard::Erc3525 ||
         decoded.standard == EvmTokenStandard::Erc777 ||
         decoded.standard == EvmTokenStandard::Erc6551) &&
        ((decoded.has_bytes_tail && decoded.bytes_tail_size != 0) ||
         (decoded.has_second_bytes_tail && decoded.second_bytes_tail_size != 0));
    // Token-ID destinations need their own review fields and trusted owner
    // resolution. Never display them as the zero address.
    if (batch_transfer || opaque_transfer_tail || decoded.has_destination_token_id) {
      secure_zero(native_value, sizeof(native_value));
      return EvmTransactionError::Unsupported;
    }
    const bool payable_call =
        decoded.standard == EvmTokenStandard::LayerZeroOft ||
        decoded.standard == EvmTokenStandard::LayerZeroOnft ||
        decoded.standard == EvmTokenStandard::Erc6551;
    if (!is_zero(native_value, sizeof(native_value))) {
      if (!payable_call) {
        secure_zero(native_value, sizeof(native_value));
        return EvmTransactionError::Unsupported;
      }
      memcpy(parsed.native_value, native_value, sizeof(parsed.native_value));
      parsed.has_native_value = true;
    }
    if (decoded.standard == EvmTokenStandard::LayerZeroOft) {
      // Only native-fee settlement is supported; LZ-token payment changes the
      // fee asset and is deliberately out of scope.
      if (!is_zero(decoded.fee_lz_token, sizeof(decoded.fee_lz_token)) ||
          compare_uint256(native_value, decoded.fee_native) < 0) {
        secure_zero(native_value, sizeof(native_value));
        return EvmTransactionError::FeePolicy;
      }
    }
    parsed.call = decoded;
    parsed.has_call = true;
    memcpy(parsed.recipient, decoded.recipient, sizeof(parsed.recipient));
    if (decoded.has_token_id) {
      if (!uint256_to_text(decoded.token_id, 0, parsed.token_id_text)) {
        secure_zero(native_value, sizeof(native_value));
        return EvmTransactionError::InvalidAmount;
      }
      if (decoded.standard == EvmTokenStandard::Erc1155 ||
          decoded.standard == EvmTokenStandard::Erc3525 ||
          (decoded.standard == EvmTokenStandard::LayerZeroOnft &&
           decoded.amount_fits_u64)) {
        memcpy(parsed.amount, decoded.amount, sizeof(parsed.amount));
      } else {
        memset(parsed.amount, 0, sizeof(parsed.amount));
        parsed.amount[kEvmUint256Size - 1] = 1;
      }
    } else {
      memcpy(parsed.amount, decoded.amount, sizeof(parsed.amount));
    }
    if ((decoded.standard == EvmTokenStandard::Erc20 ||
         decoded.standard == EvmTokenStandard::LayerZeroOft ||
         decoded.standard == EvmTokenStandard::LayerZeroOnft) &&
        is_zero(parsed.amount, sizeof(parsed.amount))) {
      secure_zero(native_value, sizeof(native_value));
      return EvmTransactionError::InvalidAmount;
    }
  }
  secure_zero(native_value, sizeof(native_value));

  address_text(parsed.recipient, parsed.recipient_address);
  const uint8_t decimals = !parsed.has_call ? 18 : (parsed.token == nullptr ? 0 : parsed.token->decimals);
  if (!uint256_to_text(parsed.amount, decimals, parsed.amount_text)) {
    return EvmTransactionError::InvalidAmount;
  }
  if (parsed.has_native_value &&
      !uint256_to_text(parsed.native_value, 18, parsed.native_value_text)) {
    return EvmTransactionError::InvalidAmount;
  }
  if (parsed.has_call && parsed.call.has_value &&
      !uint256_to_text(parsed.call.value,
                       parsed.call.standard == EvmTokenStandard::Erc6551 ? 18 : 0,
                       parsed.value_text)) {
    return EvmTransactionError::InvalidAmount;
  }
  if (parsed.has_call && parsed.call.has_min_amount &&
      !uint256_to_text(parsed.call.min_amount, 0, parsed.min_amount_text)) {
    return EvmTransactionError::InvalidAmount;
  }
  if (parsed.has_call &&
      (parsed.call.standard == EvmTokenStandard::LayerZeroOft ||
       parsed.call.standard == EvmTokenStandard::LayerZeroOnft)) {
    bytes32_text(parsed.call.remote_address, parsed.remote_address_text);
  }
  uint8_t maximum_fee[kEvmUint256Size];
  uint64_to_uint256(parsed.maximum_fee, maximum_fee);
  const bool fee_text_ok = uint256_to_text(maximum_fee, 18, parsed.maximum_fee_text);
  secure_zero(maximum_fee, sizeof(maximum_fee));
  if (!fee_text_ok) return EvmTransactionError::InvalidAmount;

  uint8_t canonical[kEvmMaxUnsignedTransactionSize];
  size_t canonical_size = 0;
  if (!serialize_transaction(parsed, nullptr, canonical, sizeof(canonical), &canonical_size) ||
      canonical_size != transaction_size || memcmp(canonical, transaction, transaction_size) != 0) {
    secure_zero(canonical, sizeof(canonical));
    return EvmTransactionError::NonCanonical;
  }
  secure_zero(canonical, sizeof(canonical));
  memcpy(parsed.unsigned_transaction, transaction, transaction_size);
  parsed.unsigned_transaction_size = static_cast<uint16_t>(transaction_size);
  if (!crypto_keccak256(transaction, transaction_size, parsed.signing_hash)) {
    clear_evm_request(&parsed);
    return EvmTransactionError::CryptoFailure;
  }
  DerivedAddress derived;
  const WalletError address_error =
      derive_address(master, nullptr, network, 0, 0, address_index, &derived);
  if (address_error != WalletError::Ok) {
    clear_evm_request(&parsed);
    return EvmTransactionError::WrongWallet;
  }
  memcpy(parsed.from_address, derived.address, sizeof(parsed.from_address));
  uint8_t binding[kKeccak256Size + kEvmAddressSize + 4];
  memcpy(binding, parsed.signing_hash, kKeccak256Size);
  uint8_t public_key[kUncompressedPublicKeySize];
  // Bind the request to the same network-specific account shown during review.
  if (uncompressed_public_key_from_private(derived.private_key, public_key) != WalletError::Ok) {
    secure_zero(binding, sizeof(binding)); secure_zero(public_key, sizeof(public_key));
    clear_derived_address(&derived); clear_evm_request(&parsed);
    return EvmTransactionError::WrongWallet;
  }
  uint8_t public_hash[kKeccak256Size];
  const bool public_hashed = crypto_keccak256(public_key + 1, kUncompressedPublicKeySize - 1, public_hash);
  secure_zero(public_key, sizeof(public_key)); clear_derived_address(&derived);
  if (!public_hashed) {
    secure_zero(binding, sizeof(binding)); secure_zero(public_hash, sizeof(public_hash));
    clear_evm_request(&parsed); return EvmTransactionError::CryptoFailure;
  }
  // A caller-supplied `from`/`owner` must be this wallet. Otherwise the review
  // would describe an allowance-driven transfer of somebody else's asset.
  if (parsed.has_call && call_requires_wallet_sender(parsed.call)) {
    const bool sender_matches = crypto_constant_time_equal(
        parsed.call.secondary, public_hash + 12, kEvmAddressSize);
    // ERC-777's operator is msg.sender, not a calldata argument.
    if (!sender_matches) {
      secure_zero(binding, sizeof(binding));
      secure_zero(public_hash, sizeof(public_hash));
      clear_evm_request(&parsed);
      return EvmTransactionError::WrongWallet;
    }
  }
  memcpy(binding + kKeccak256Size, public_hash + 12, kEvmAddressSize);
  binding[kKeccak256Size + kEvmAddressSize] = static_cast<uint8_t>(address_index >> 24);
  binding[kKeccak256Size + kEvmAddressSize + 1] = static_cast<uint8_t>(address_index >> 16);
  binding[kKeccak256Size + kEvmAddressSize + 2] = static_cast<uint8_t>(address_index >> 8);
  binding[kKeccak256Size + kEvmAddressSize + 3] = static_cast<uint8_t>(address_index);
  const bool bound = crypto_sha256(binding, sizeof(binding), parsed.request_hash);
  secure_zero(binding, sizeof(binding)); secure_zero(public_hash, sizeof(public_hash));
  if (!bound) { clear_evm_request(&parsed); return EvmTransactionError::CryptoFailure; }
  *out = parsed;
  return EvmTransactionError::Ok;
}

namespace {

template <typename T, size_t N>
bool same_array(const T (&left)[N], const T (&right)[N]) {
  // Fixed bounds also reject unterminated, corrupted review strings without
  // reading past the request. All parsed fields start with zero-filled tails.
  return memcmp(left, right, sizeof(left)) == 0;
}

bool same_decoded_call(const DecodedTokenCalldata &a, const DecodedTokenCalldata &b) {
  return a.standard == b.standard && a.function == b.function && a.selector == b.selector &&
      a.amount_fits_u64 == b.amount_fits_u64 && a.amount_u64 == b.amount_u64 &&
      a.has_token_id == b.has_token_id && a.has_destination_token_id == b.has_destination_token_id &&
      a.has_value == b.has_value && a.has_min_amount == b.has_min_amount &&
      a.approval_for_all == b.approval_for_all && a.batch_count == b.batch_count &&
      a.has_bytes_tail == b.has_bytes_tail && a.bytes_tail_size == b.bytes_tail_size &&
      a.has_second_bytes_tail == b.has_second_bytes_tail &&
      a.second_bytes_tail_size == b.second_bytes_tail_size &&
      a.remote_chain_id == b.remote_chain_id && a.remote_eid == b.remote_eid &&
      a.remote_address_size == b.remote_address_size && a.has_nested_call == b.has_nested_call &&
      a.nested_data_size == b.nested_data_size && a.nested_has_token_id == b.nested_has_token_id &&
      same_array(a.recipient, b.recipient) && same_array(a.secondary, b.secondary) &&
      same_array(a.tertiary, b.tertiary) && same_array(a.payment_address, b.payment_address) &&
      same_array(a.amount, b.amount) && same_array(a.token_id, b.token_id) &&
      same_array(a.destination_token_id, b.destination_token_id) && same_array(a.value, b.value) &&
      same_array(a.min_amount, b.min_amount) && same_array(a.batch_ids, b.batch_ids) &&
      same_array(a.batch_amounts, b.batch_amounts) && same_array(a.remote_address, b.remote_address) &&
      same_array(a.fee_native, b.fee_native) && same_array(a.fee_lz_token, b.fee_lz_token) &&
      same_array(a.nested_target, b.nested_target) && same_array(a.nested_value, b.nested_value) &&
      same_array(a.nested_selector, b.nested_selector) && same_array(a.nested_token_id, b.nested_token_id);
}

// The two hashes bind the exact unsigned bytes, but a second parse must also
// agree with everything the trusted display showed. Comparing the reviewed
// fields explicitly catches a future parser that derives different display
// data from the same bytes (for example a registry or formatting change).
bool evm_same_review(const EvmSigningRequest &reviewed,
                     const EvmSigningRequest &request) {
  return reviewed.type == request.type &&
         reviewed.network == request.network &&
         reviewed.token == request.token &&
         reviewed.address_index == request.address_index &&
         reviewed.nonce == request.nonce &&
         reviewed.gas_limit == request.gas_limit &&
         reviewed.gas_price_or_max_fee == request.gas_price_or_max_fee &&
         reviewed.max_priority_fee == request.max_priority_fee &&
         reviewed.maximum_fee == request.maximum_fee &&
         reviewed.has_native_value == request.has_native_value &&
         reviewed.has_call == request.has_call &&
         reviewed.data_size == request.data_size &&
         reviewed.access_list_size == request.access_list_size &&
         reviewed.access_list_addresses == request.access_list_addresses &&
         reviewed.access_list_keys == request.access_list_keys &&
         crypto_constant_time_equal(reviewed.access_list, request.access_list,
                                    reviewed.access_list_size) &&
         same_decoded_call(reviewed.call, request.call) &&
         crypto_constant_time_equal(reviewed.contract, request.contract,
                                    kEvmAddressSize) &&
         crypto_constant_time_equal(reviewed.recipient, request.recipient,
                                    kEvmAddressSize) &&
         crypto_constant_time_equal(reviewed.amount, request.amount,
                                    kEvmUint256Size) &&
         crypto_constant_time_equal(reviewed.native_value,
                                    request.native_value, kEvmUint256Size) &&
         crypto_constant_time_equal(reviewed.data, request.data,
                                    reviewed.data_size) &&
         same_array(reviewed.from_address, request.from_address) &&
         same_array(reviewed.recipient_address, request.recipient_address) &&
         same_array(reviewed.amount_text, request.amount_text) &&
         same_array(reviewed.token_id_text, request.token_id_text) &&
         same_array(reviewed.value_text, request.value_text) &&
         same_array(reviewed.min_amount_text, request.min_amount_text) &&
         same_array(reviewed.native_value_text, request.native_value_text) &&
         same_array(reviewed.remote_address_text, request.remote_address_text) &&
         same_array(reviewed.maximum_fee_text, request.maximum_fee_text);
}

}  // namespace

EvmTransactionError evm_sign_transaction(const EvmSigningRequest &request,
                                         const HdPrivateNode &master,
                                         uint8_t *out_transaction,
                                         size_t *in_out_size) {
  if (in_out_size == nullptr) return EvmTransactionError::InvalidArgument;
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  if (out_transaction != nullptr) secure_zero(out_transaction, capacity);
  if (out_transaction == nullptr || in_out_size == nullptr || request.network == nullptr ||
      request.unsigned_transaction_size == 0 || request.address_index >= kHardenedOffset) {
    return EvmTransactionError::InvalidArgument;
  }
  EvmSigningRequest validated;
  EvmTransactionError error = evm_parse_transaction(
      request.unsigned_transaction, request.unsigned_transaction_size,
      *request.network, master, request.address_index, &validated);
  if (error != EvmTransactionError::Ok) return error;
  const bool same_request = crypto_constant_time_equal(validated.request_hash, request.request_hash,
                                                        sizeof(request.request_hash)) &&
      crypto_constant_time_equal(validated.signing_hash, request.signing_hash,
                                 sizeof(request.signing_hash)) && evm_same_review(validated, request);
  if (!same_request) {
    clear_evm_request(&validated);
    return EvmTransactionError::WrongWallet;
  }
  DerivedAddress derived;
  if (derive_address(master, nullptr, *validated.network, 0, 0,
                     validated.address_index, &derived) != WalletError::Ok) {
    clear_evm_request(&validated);
    return EvmTransactionError::WrongWallet;
  }
  RecoverableSignature signature;
  const WalletError sign_error = secp256k1_sign_digest_recoverable(
      derived.private_key, validated.signing_hash, &signature);
  clear_derived_address(&derived);
  if (sign_error != WalletError::Ok) {
    secure_zero(&signature, sizeof(signature));
    clear_evm_request(&validated);
    return EvmTransactionError::CryptoFailure;
  }
  size_t signed_size = 0;
  const bool serialized = serialize_transaction(validated, &signature, out_transaction,
                                                capacity, &signed_size);
  secure_zero(&signature, sizeof(signature));
  clear_evm_request(&validated);
  if (!serialized) {
    secure_zero(out_transaction, capacity);
    return EvmTransactionError::BufferTooSmall;
  }
  *in_out_size = signed_size;
  return EvmTransactionError::Ok;
}

const char *evm_transaction_error_text(EvmTransactionError error) {
  switch (error) {
    case EvmTransactionError::Ok: return "ok";
    case EvmTransactionError::InvalidArgument: return "invalid-argument";
    case EvmTransactionError::Truncated: return "truncated";
    case EvmTransactionError::NonCanonical: return "non-canonical-rlp";
    case EvmTransactionError::Unsupported: return "unsupported-call-or-field";
    case EvmTransactionError::WrongNetwork: return "wrong-network";
    case EvmTransactionError::WrongWallet: return "wrong-wallet-or-review";
    case EvmTransactionError::InvalidAmount: return "invalid-amount";
    case EvmTransactionError::FeePolicy: return "fee-policy";
    case EvmTransactionError::CryptoFailure: return "crypto-failure";
    case EvmTransactionError::BufferTooSmall: return "buffer-too-small";
  }
  return "unknown";
}

void clear_evm_request(EvmSigningRequest *request) {
  if (request != nullptr) secure_zero(request, sizeof(*request));
}

bool evm_access_list_details(const EvmSigningRequest &request, char *out, size_t size) {
  if (out == nullptr || size == 0) return false;
  out[0] = '\0';
  uint8_t addresses = 0, keys = 0;
  const RlpItem list{request.access_list, request.access_list_size, true};
  if (validate_access_list(list, &addresses, &keys) != EvmTransactionError::Ok ||
      addresses != request.access_list_addresses || keys != request.access_list_keys)
    return false;
  if (addresses == 0) return true;
  Writer writer{reinterpret_cast<uint8_t *>(out), size - 1, 0};
  const char heading[] = "ACCESS LIST (gas scheduling)\n";
  bool ok = write_bytes(&writer, reinterpret_cast<const uint8_t *>(heading), sizeof(heading) - 1);
  const auto append_hex = [&writer](const uint8_t *bytes, size_t length) {
    static const char hex[] = "0123456789abcdef";
    if (!write_byte(&writer, '0') || !write_byte(&writer, 'x')) return false;
    for (size_t i = 0; i < length; ++i) {
      if (!write_byte(&writer, hex[bytes[i] >> 4]) ||
          !write_byte(&writer, hex[bytes[i] & 15])) return false;
    }
    return write_byte(&writer, '\n');
  };
  Cursor rows{list.data, list.size, 0};
  while (ok && rows.position < rows.size) {
    RlpItem row{}, address{}, slots{};
    ok = read_rlp_item(&rows, &row) == EvmTransactionError::Ok;
    Cursor fields{row.data, row.size, 0};
    ok = ok && read_rlp_item(&fields, &address) == EvmTransactionError::Ok &&
         read_rlp_item(&fields, &slots) == EvmTransactionError::Ok;
    if (!ok) break;
    ok = append_hex(address.data, address.size);
    Cursor storage{slots.data, slots.size, 0};
    while (ok && storage.position < storage.size) {
      RlpItem key{};
      ok = read_rlp_item(&storage, &key) == EvmTransactionError::Ok &&
           write_byte(&writer, ' ') && write_byte(&writer, ' ') && append_hex(key.data, key.size);
    }
  }
  if (!ok) { secure_zero(out, size); return false; }
  out[writer.position] = '\0';
  return true;
}

const char *evm_transaction_type_text(EvmTransactionType type) {
  switch (type) {
    case EvmTransactionType::LegacyEip155: return "EIP-155";
    case EvmTransactionType::Eip2930: return "EIP-2930";
    case EvmTransactionType::Eip1559: return "EIP-1559";
  }
  return "UNSUPPORTED";
}

bool evm_review_details(const EvmSigningRequest &request, char *out, size_t size) {
  if (out == nullptr || size == 0) return false;
  secure_zero(out, size);
  if (request.network == nullptr ||
      memchr(request.from_address, '\0', sizeof(request.from_address)) == nullptr ||
      memchr(request.native_value_text, '\0', sizeof(request.native_value_text)) == nullptr ||
      memchr(request.value_text, '\0', sizeof(request.value_text)) == nullptr ||
      memchr(request.min_amount_text, '\0', sizeof(request.min_amount_text)) == nullptr)
    return false;
  size_t used = 0;
  bool ok = true;
  const auto append = [&](const char *format, ...) {
    if (!ok) return;
    va_list args;
    va_start(args, format);
    const int written = vsnprintf(out + used, size - used, format, args);
    va_end(args);
    if (written < 0 || static_cast<size_t>(written) >= size - used) { ok = false; return; }
    used += static_cast<size_t>(written);
  };
  append("%s\nCHAIN ID %lu\nFROM\n%s\nNONCE %llu\nGAS LIMIT %llu\n%s %llu WEI\n",
      evm_transaction_type_text(request.type),
      static_cast<unsigned long>(request.network->evm_chain_id), request.from_address,
      static_cast<unsigned long long>(request.nonce),
      static_cast<unsigned long long>(request.gas_limit),
      request.type == EvmTransactionType::Eip1559 ? "MAX GAS PRICE" : "GAS PRICE",
      static_cast<unsigned long long>(request.gas_price_or_max_fee));
  if (request.type == EvmTransactionType::Eip1559)
    append("MAX PRIORITY %llu WEI\n", static_cast<unsigned long long>(request.max_priority_fee));
  if (request.has_call) {
    char address[kTokenAddressTextSize];
    address_text(request.contract, address);
    append("CONTRACT\n%s\nCALL\n%s.%s\n", address,
        evm_token_standard_name(request.call.standard), token_function_name(request.call.function));
    const auto address_field = [&](const char *label, const uint8_t *bytes) {
      if (!is_zero(bytes, kEvmAddressSize)) {
        address_text(bytes, address);
        append("%s\n%s\n", label, address);
      }
    };
    address_field("SOURCE / OWNER", request.call.secondary);
    address_field("REFUND ADDRESS", request.call.tertiary);
    address_field("FEE PAYMENT ADDRESS", request.call.payment_address);
    if (request.has_native_value) append("NATIVE CALL VALUE %s\n", request.native_value_text);
    if (request.call.has_value) append("CALL VALUE %s\n", request.value_text);
    if (request.call.has_min_amount) append("MINIMUM BASE UNITS %s\n", request.min_amount_text);
    if (request.call.remote_eid != 0)
      append("DESTINATION EID %lu\n", static_cast<unsigned long>(request.call.remote_eid));
    if (request.call.remote_chain_id != 0) append("REMOTE CHAIN %u\n", request.call.remote_chain_id);
    if (request.call.has_nested_call) {
      address_field("NESTED TARGET", request.call.nested_target);
      append("NESTED SELECTOR 0x%02x%02x%02x%02x\nNESTED DATA BYTES %u\n",
          request.call.nested_selector[0], request.call.nested_selector[1],
          request.call.nested_selector[2], request.call.nested_selector[3], request.call.nested_data_size);
    }
  }
  if (!ok || !evm_access_list_details(request, out + used, size - used)) {
    secure_zero(out, size);
    return false;
  }
  return true;
}

bool run_evm_transaction_self_test() {
  static const char kUnsignedHex[] =
      "ec098504a817c800825208943535353535353535353535353535353535353535"
      "880de0b6b3a764000080018080";
  static const char kDigestHex[] =
      "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";
  static const char kSignedHex[] =
      "f86c098504a817c800825208943535353535353535353535353535353535353535"
      "880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c"
      "71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc"
      "64214b297fb1966a3b6d83";
  const NetworkProfile *ethereum = find_network_profile("eth");
  if (ethereum == nullptr) return false;
  uint8_t unsigned_transaction[kEvmMaxUnsignedTransactionSize];
  uint8_t expected_signed[kEvmMaxSignedTransactionSize];
  uint8_t actual[kEvmMaxSignedTransactionSize];
  uint8_t expected_digest[kKeccak256Size];
  size_t unsigned_size = 0, expected_signed_size = 0, digest_size = 0;
  bool passed = decode_hex_string(kUnsignedHex, unsigned_transaction,
                                  sizeof(unsigned_transaction), &unsigned_size) &&
      decode_hex_string(kSignedHex, expected_signed, sizeof(expected_signed),
                        &expected_signed_size) &&
      decode_hex_string(kDigestHex, expected_digest, sizeof(expected_digest), &digest_size) &&
      digest_size == sizeof(expected_digest);
  EvmSigningRequest request = {};
  request.type = EvmTransactionType::LegacyEip155;
  request.network = ethereum;
  request.nonce = 9;
  request.gas_limit = 21000;
  request.gas_price_or_max_fee = 20000000000ULL;
  request.maximum_fee = request.gas_limit * request.gas_price_or_max_fee;
  memset(request.contract, 0x35, sizeof(request.contract));
  const uint8_t value[] = {0x0d,0xe0,0xb6,0xb3,0xa7,0x64,0x00,0x00};
  memcpy(request.amount + sizeof(request.amount) - sizeof(value), value, sizeof(value));
  size_t actual_size = 0;
  passed = passed && serialize_transaction(request, nullptr, actual, sizeof(actual), &actual_size) &&
      actual_size == unsigned_size && memcmp(actual, unsigned_transaction, unsigned_size) == 0;
  uint8_t digest[kKeccak256Size];
  passed = passed && crypto_keccak256(actual, actual_size, digest) &&
      crypto_constant_time_equal(digest, expected_digest, sizeof(digest));
  uint8_t private_key[kPrivateKeySize];
  memset(private_key, 0x46, sizeof(private_key));
  RecoverableSignature signature;
  passed = passed && secp256k1_sign_digest_recoverable(private_key, digest, &signature) ==
                         WalletError::Ok && signature.y_parity == 0;
  actual_size = 0;
  passed = passed && serialize_transaction(request, &signature, actual, sizeof(actual), &actual_size) &&
      actual_size == expected_signed_size && memcmp(actual, expected_signed, actual_size) == 0;

  const uint8_t master_seed[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  HdPrivateNode master;
  EvmSigningRequest parsed;
  passed = passed && hd_private_from_seed(master_seed, sizeof(master_seed), &master) == WalletError::Ok &&
      evm_parse_transaction(unsigned_transaction, unsigned_size, *ethereum, master, 0, &parsed) ==
          EvmTransactionError::Ok && parsed.nonce == 9 && parsed.gas_limit == 21000 &&
      parsed.token == nullptr &&
      crypto_constant_time_equal(parsed.signing_hash, expected_digest, sizeof(expected_digest));
  clear_evm_request(&parsed);

  EvmSigningRequest type_two = {};
  type_two.type = EvmTransactionType::Eip1559;
  type_two.network = ethereum;
  type_two.nonce = 1;
  type_two.max_priority_fee = 1000000000ULL;
  type_two.gas_price_or_max_fee = 2000000000ULL;
  type_two.gas_limit = 21000;
  memset(type_two.contract, 0x35, sizeof(type_two.contract));
  type_two.amount[kEvmUint256Size - 1] = 1;
  actual_size = 0;
  passed = passed && serialize_transaction(type_two, nullptr, actual, sizeof(actual), &actual_size) &&
      evm_parse_transaction(actual, actual_size, *ethereum, master, 0, &parsed) ==
          EvmTransactionError::Ok && parsed.type == EvmTransactionType::Eip1559 &&
      parsed.max_priority_fee == 1000000000ULL && parsed.amount[kEvmUint256Size - 1] == 1;
  clear_evm_request(&parsed);

  // Independent ethers 6.15.0 envelope/hash vector (full signature fixtures
  // also run through the native chain probe). Type 1 omits the priority fee
  // field, and its signed digest includes the 0x01 envelope byte.
  static const char kTypeOneUnsignedHex[] =
      "01e20101847735940082fde89435353535353535353535353535353535353535350180c0";
  static const char kTypeOneDigestHex[] =
      "ca4083b58c1f3fc38ae7001862fb98f2aef42f88c483f7382de0e3fb7abfa5ff";
  type_two.type = EvmTransactionType::Eip2930;
  type_two.gas_limit = 65000;
  passed = passed &&
      decode_hex_string(kTypeOneUnsignedHex, expected_signed, sizeof(expected_signed), &expected_signed_size) &&
      decode_hex_string(kTypeOneDigestHex, expected_digest, sizeof(expected_digest), &digest_size) &&
      serialize_transaction(type_two, nullptr, actual, sizeof(actual), &actual_size) &&
      actual_size == expected_signed_size && memcmp(actual, expected_signed, actual_size) == 0 &&
      evm_parse_transaction(actual, actual_size, *ethereum, master, 0, &parsed) ==
          EvmTransactionError::Ok && parsed.type == EvmTransactionType::Eip2930 &&
      parsed.max_priority_fee == 0 && same_array(parsed.signing_hash, expected_digest);
  clear_evm_request(&parsed);
  type_two.type = EvmTransactionType::Eip1559;
  type_two.gas_limit = 21000;

  const TokenProfile *usdc = find_token_profile("eth-usdc");
  EvmSigningRequest token_transfer = type_two;
  token_transfer.token = usdc;
  token_transfer.gas_limit = 65000;
  memset(token_transfer.amount, 0, sizeof(token_transfer.amount));
  token_transfer.amount[29] = 0x0f;
  token_transfer.amount[30] = 0x42;
  token_transfer.amount[31] = 0x40;
  if (usdc != nullptr) decode_contract(usdc->contract_or_mint, token_transfer.contract);
  token_transfer.data_size = kTokenSelectorSize + 2 * kTokenWordSize;
  memcpy(token_transfer.data, kErc20TransferSelector, sizeof(kErc20TransferSelector));
  memset(token_transfer.data + 16, 0x11, kEvmAddressSize);
  memcpy(token_transfer.data + 36, token_transfer.amount, kEvmUint256Size);
  actual_size = 0;
  passed = passed && usdc != nullptr &&
      serialize_transaction(token_transfer, nullptr, actual, sizeof(actual), &actual_size) &&
      evm_parse_transaction(actual, actual_size, *ethereum, master, 0, &parsed) ==
          EvmTransactionError::Ok && parsed.token == usdc && strcmp(parsed.amount_text, "1") == 0;
  clear_evm_request(&parsed);

  // A syntactically valid ERC-721 call to an unregistered contract is refused.
  DerivedAddress nft_wallet;
  uint8_t nft_from[kEvmAddressSize] = {};
  uint8_t nft_to[kEvmAddressSize];
  uint8_t nft_id[kEvmUint256Size] = {};
  char expected_nft_recipient[kAddressTextSize];
  memset(nft_to, 0x22, sizeof(nft_to));
  nft_id[kEvmUint256Size - 1] = 7;
  address_text(nft_to, expected_nft_recipient);
  const bool nft_derived =
      derive_address(master, nullptr, *ethereum, 0, 0, 0, &nft_wallet) == WalletError::Ok &&
      decode_contract(nft_wallet.address, nft_from);
  clear_derived_address(&nft_wallet);
  EvmSigningRequest nft_transfer = type_two;
  nft_transfer.token = nullptr;
  nft_transfer.gas_limit = 65000;
  memset(nft_transfer.amount, 0, sizeof(nft_transfer.amount));
  memset(nft_transfer.contract, 0x33, sizeof(nft_transfer.contract));
  const bool nft_built =
      token_build_erc721_safe_transfer(nft_from, nft_to, nft_id,
                                       nft_transfer.data,
                                       sizeof(nft_transfer.data));
  nft_transfer.data_size = kTokenSelectorSize + 3 * kTokenWordSize;
  actual_size = 0;
  passed = passed && nft_derived && nft_built &&
      serialize_transaction(nft_transfer, nullptr, actual, sizeof(actual), &actual_size) &&
      evm_parse_transaction(actual, actual_size, *ethereum, master, 0, &parsed) ==
          EvmTransactionError::Unsupported;
  clear_evm_request(&parsed);
  secure_zero(&nft_transfer, sizeof(nft_transfer));
  secure_zero(nft_from, sizeof(nft_from));
  secure_zero(nft_to, sizeof(nft_to));
  secure_zero(nft_id, sizeof(nft_id));
  secure_zero(expected_nft_recipient, sizeof(expected_nft_recipient));

  // Ethereum Classic uses derivation coin type 61. Compare against a signature
  // produced directly by that derived key to prevent a hard-coded type-60 path.
  const NetworkProfile *ethereum_classic = find_network_profile("etc");
  EvmSigningRequest etc_transaction = request;
  etc_transaction.network = ethereum_classic;
  actual_size = 0;
  passed = passed && ethereum_classic != nullptr &&
      serialize_transaction(etc_transaction, nullptr, actual, sizeof(actual), &actual_size) &&
      evm_parse_transaction(actual, actual_size, *ethereum_classic, master, 0, &parsed) ==
          EvmTransactionError::Ok;
  DerivedAddress etc_derived;
  RecoverableSignature etc_signature;
  size_t expected_etc_size = 0;
  if (passed) {
    passed = derive_address(master, nullptr, *ethereum_classic, 0, 0, 0, &etc_derived) ==
        WalletError::Ok &&
        strcmp(parsed.from_address, etc_derived.address) == 0 &&
        secp256k1_sign_digest_recoverable(etc_derived.private_key, parsed.signing_hash,
                                          &etc_signature) == WalletError::Ok &&
        serialize_transaction(parsed, &etc_signature, expected_signed, sizeof(expected_signed),
                              &expected_etc_size);
  }
  actual_size = sizeof(actual);
  passed = passed && evm_sign_transaction(parsed, master, actual, &actual_size) ==
                         EvmTransactionError::Ok &&
      actual_size == expected_etc_size && memcmp(actual, expected_signed, actual_size) == 0;
  clear_derived_address(&etc_derived);
  secure_zero(&etc_signature, sizeof(etc_signature));
  clear_evm_request(&parsed);
  secure_zero(&etc_transaction, sizeof(etc_transaction));
  secure_zero(&token_transfer, sizeof(token_transfer));
  secure_zero(&type_two, sizeof(type_two));
  secure_zero(&master, sizeof(master));
  secure_zero(&signature, sizeof(signature)); secure_zero(private_key, sizeof(private_key));
  secure_zero(digest, sizeof(digest)); secure_zero(&request, sizeof(request));
  secure_zero(expected_digest, sizeof(expected_digest)); secure_zero(actual, sizeof(actual));
  secure_zero(expected_signed, sizeof(expected_signed));
  secure_zero(unsigned_transaction, sizeof(unsigned_transaction));
  return passed && run_secp256k1_self_test();
}

}  // namespace hexwallet
