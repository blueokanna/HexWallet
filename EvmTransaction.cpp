#include "EvmTransaction.h"

#include <stdio.h>
#include <string.h>

#include "WalletConfig.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

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
                   bool typed, uint8_t *out, size_t capacity, size_t *out_size) {
  Writer writer = {out, capacity, 0};
  if (typed && !write_byte(&writer, kEip1559Type)) return false;
  if (!write_rlp_prefix(&writer, payload_size, true) ||
      !write_bytes(&writer, payload, payload_size)) return false;
  *out_size = writer.position;
  return true;
}

bool serialize_transaction(const EvmSigningRequest &request,
                           const RecoverableSignature *signature,
                           uint8_t *out, size_t capacity, size_t *out_size) {
  uint8_t payload[kEvmMaxSignedTransactionSize];
  uint8_t zero_value[kEvmUint256Size] = {};
  Writer writer = {payload, sizeof(payload), 0};
  const uint8_t *native_value = request.token == nullptr ? request.amount : zero_value;
  bool ok;
  if (request.type == EvmTransactionType::Eip1559) {
    ok = write_rlp_u64(&writer, request.network->evm_chain_id) &&
         write_rlp_u64(&writer, request.nonce) &&
         write_rlp_u64(&writer, request.max_priority_fee) &&
         write_rlp_u64(&writer, request.gas_price_or_max_fee) &&
         write_rlp_u64(&writer, request.gas_limit) &&
         write_rlp_bytes(&writer, request.contract, sizeof(request.contract)) &&
         write_rlp_uint256(&writer, native_value) &&
         write_rlp_bytes(&writer, request.data, request.data_size) &&
         write_byte(&writer, 0xc0);
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
                             request.type == EvmTransactionType::Eip1559,
                             out, capacity, &serialized_size);
  if (ok) *out_size = serialized_size;
  secure_zero(zero_value, sizeof(zero_value));
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
  if (transaction == nullptr || out == nullptr || transaction_size == 0 ||
      transaction_size > kEvmMaxUnsignedTransactionSize ||
      network.encoding != AddressEncoding::Evm || network.evm_chain_id == 0 ||
      address_index >= kHardenedOffset) return EvmTransactionError::InvalidArgument;
  EvmSigningRequest parsed = {};
  parsed.network = &network;
  parsed.address_index = address_index;
  Cursor cursor = {transaction, transaction_size, 0};
  if (transaction[0] == kEip1559Type) {
    parsed.type = EvmTransactionType::Eip1559;
    cursor.position = 1;
  } else {
    parsed.type = EvmTransactionType::LegacyEip155;
  }
  RlpItem outer;
  EvmTransactionError error = read_rlp_item(&cursor, &outer);
  if (error != EvmTransactionError::Ok) return error;
  if (!outer.list || cursor.position != cursor.size) return EvmTransactionError::NonCanonical;
  Cursor fields_cursor = {outer.data, outer.size, 0};
  RlpItem fields[9];
  for (RlpItem &field : fields) {
    error = read_rlp_item(&fields_cursor, &field);
    if (error != EvmTransactionError::Ok) return error;
  }
  if (fields_cursor.position != fields_cursor.size) return EvmTransactionError::Unsupported;

  uint64_t chain_id = 0;
  uint8_t native_value[kEvmUint256Size];
  const RlpItem *to = nullptr;
  const RlpItem *value = nullptr;
  const RlpItem *data = nullptr;
  if (parsed.type == EvmTransactionType::Eip1559) {
    error = read_u64(fields[0], &chain_id);
    if (error == EvmTransactionError::Ok) error = read_u64(fields[1], &parsed.nonce);
    if (error == EvmTransactionError::Ok) error = read_u64(fields[2], &parsed.max_priority_fee);
    if (error == EvmTransactionError::Ok) error = read_u64(fields[3], &parsed.gas_price_or_max_fee);
    if (error == EvmTransactionError::Ok) error = read_u64(fields[4], &parsed.gas_limit);
    if (error != EvmTransactionError::Ok) return error;
    if (!fields[8].list || fields[8].size != 0) return EvmTransactionError::Unsupported;
    to = &fields[5]; value = &fields[6]; data = &fields[7];
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
  if (parsed.gas_limit < kMinimumTransferGas || parsed.gas_limit > kMaximumTransferGas ||
      parsed.gas_price_or_max_fee == 0 ||
      parsed.gas_limit > HEXWALLET_MAX_EVM_FEE_WEI / parsed.gas_price_or_max_fee) {
    secure_zero(native_value, sizeof(native_value));
    return EvmTransactionError::FeePolicy;
  }
  parsed.maximum_fee = parsed.gas_limit * parsed.gas_price_or_max_fee;
  memcpy(parsed.contract, to->data, sizeof(parsed.contract));
  parsed.data_size = static_cast<uint8_t>(data->size);
  if (data->size != 0) memcpy(parsed.data, data->data, data->size);

  if (data->size == 0) {
    if (is_zero(native_value, sizeof(native_value))) {
      secure_zero(native_value, sizeof(native_value));
      return EvmTransactionError::InvalidAmount;
    }
    memcpy(parsed.recipient, parsed.contract, sizeof(parsed.recipient));
    memcpy(parsed.amount, native_value, sizeof(parsed.amount));
  } else {
    if (data->size != kEvmMaxDataSize ||
        memcmp(data->data, kErc20TransferSelector, sizeof(kErc20TransferSelector)) != 0 ||
        !is_zero(data->data + 4, 12) || !is_zero(native_value, sizeof(native_value))) {
      secure_zero(native_value, sizeof(native_value));
      return EvmTransactionError::Unsupported;
    }
    parsed.token = find_token(network, parsed.contract);
    if (parsed.token == nullptr) {
      secure_zero(native_value, sizeof(native_value));
      return EvmTransactionError::Unsupported;
    }
    memcpy(parsed.recipient, data->data + 16, sizeof(parsed.recipient));
    memcpy(parsed.amount, data->data + 36, sizeof(parsed.amount));
    if (is_zero(parsed.amount, sizeof(parsed.amount))) {
      secure_zero(native_value, sizeof(native_value));
      return EvmTransactionError::InvalidAmount;
    }
  }
  secure_zero(native_value, sizeof(native_value));

  address_text(parsed.recipient, parsed.recipient_address);
  if (!uint256_to_text(parsed.amount, parsed.token == nullptr ? 18 : parsed.token->decimals,
                       parsed.amount_text)) return EvmTransactionError::InvalidAmount;
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
  const WalletError address_error = derive_address(master, network, 0, 0, address_index, &derived);
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

EvmTransactionError evm_sign_transaction(const EvmSigningRequest &request,
                                         const HdPrivateNode &master,
                                         uint8_t *out_transaction,
                                         size_t *in_out_size) {
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
                                 sizeof(request.signing_hash));
  if (!same_request) {
    clear_evm_request(&validated);
    return EvmTransactionError::WrongWallet;
  }
  DerivedAddress derived;
  if (derive_address(master, *validated.network, 0, 0, validated.address_index, &derived) !=
      WalletError::Ok) {
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
                                                *in_out_size, &signed_size);
  secure_zero(&signature, sizeof(signature));
  clear_evm_request(&validated);
  if (!serialized) return EvmTransactionError::BufferTooSmall;
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

  const TokenProfile *usdc = find_token_profile("eth-usdc");
  EvmSigningRequest token_transfer = type_two;
  token_transfer.token = usdc;
  token_transfer.gas_limit = 65000;
  memset(token_transfer.amount, 0, sizeof(token_transfer.amount));
  token_transfer.amount[29] = 0x0f;
  token_transfer.amount[30] = 0x42;
  token_transfer.amount[31] = 0x40;
  if (usdc != nullptr) decode_contract(usdc->contract_or_mint, token_transfer.contract);
  token_transfer.data_size = kEvmMaxDataSize;
  memcpy(token_transfer.data, kErc20TransferSelector, sizeof(kErc20TransferSelector));
  memset(token_transfer.data + 16, 0x11, kEvmAddressSize);
  memcpy(token_transfer.data + 36, token_transfer.amount, kEvmUint256Size);
  actual_size = 0;
  passed = passed && usdc != nullptr &&
      serialize_transaction(token_transfer, nullptr, actual, sizeof(actual), &actual_size) &&
      evm_parse_transaction(actual, actual_size, *ethereum, master, 0, &parsed) ==
          EvmTransactionError::Ok && parsed.token == usdc && strcmp(parsed.amount_text, "1") == 0;
  clear_evm_request(&parsed);

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
    passed = derive_address(master, *ethereum_classic, 0, 0, 0, &etc_derived) == WalletError::Ok &&
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
