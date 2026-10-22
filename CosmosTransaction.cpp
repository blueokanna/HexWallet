#include "CosmosTransaction.h"

#include <string.h>

#include "WalletSecurity.h"

namespace hexwallet {
namespace {

constexpr char kMsgDelegateTypeUrl[] = "/cosmos.staking.v1beta1.MsgDelegate";
constexpr char kSecp256k1PubKeyTypeUrl[] = "/cosmos.crypto.secp256k1.PubKey";
constexpr uint32_t kSignModeDirect = 1;

struct Writer {
  uint8_t *data;
  size_t capacity;
  size_t position;
  bool ok;
};

bool write_bytes(Writer *writer, const void *data, size_t size) {
  if (!writer->ok) return false;
  if (writer->position + size > writer->capacity) {
    writer->ok = false;
    return false;
  }
  memcpy(writer->data + writer->position, data, size);
  writer->position += size;
  return true;
}

bool write_varint(Writer *writer, uint64_t value) {
  do {
    uint8_t byte = static_cast<uint8_t>(value & 0x7f);
    value >>= 7;
    if (value != 0) byte |= 0x80;
    if (!write_bytes(writer, &byte, 1)) return false;
  } while (value != 0);
  return true;
}

bool write_tag(Writer *writer, uint32_t field, uint32_t wire_type) {
  return write_varint(writer, (static_cast<uint64_t>(field) << 3) | wire_type);
}

bool write_length_delimited(Writer *writer, uint32_t field, const void *data,
                            size_t size) {
  return write_tag(writer, field, 2) && write_varint(writer, size) &&
         write_bytes(writer, data, size);
}

// proto3 omits scalars at their default value; string and bytes fields are
// omitted when empty, which is what prost emits.
bool write_uint_field(Writer *writer, uint32_t field, uint64_t value) {
  if (value == 0) return true;
  return write_tag(writer, field, 0) && write_varint(writer, value);
}

bool write_string_field(Writer *writer, uint32_t field, const char *value) {
  const size_t size = strlen(value);
  if (size == 0) return true;
  return write_length_delimited(writer, field, value, size);
}

bool write_message_field(Writer *writer, uint32_t field, const uint8_t *data,
                         size_t size) {
  return write_length_delimited(writer, field, data, size);
}

// Bech32 bodies are [hrp]1[data]; the delegator must carry the "cosmos" prefix
// and the validator the "cosmosvaloper" one. A validator address pasted as a
// delegator (or the reverse) is rejected before any bytes are built.
bool bech32_has_prefix(const char *value, const char *prefix) {
  const size_t prefix_size = strlen(prefix);
  return strlen(value) > prefix_size + 1 &&
         strncmp(value, prefix, prefix_size) == 0 && value[prefix_size] == '1';
}

// Cosmos amounts are decimal strings; keep them canonical (no sign, no leading
// zeros, no overflow) so the fee cannot be reinterpreted by the node.
bool valid_decimal_amount(const char *value) {
  const size_t size = strlen(value);
  if (size == 0 || size > 20) return false;
  if (value[0] == '0' && size > 1) return false;
  for (size_t index = 0; index < size; ++index) {
    if (value[index] < '0' || value[index] > '9') return false;
  }
  return true;
}

}  // namespace

CosmosError cosmos_delegate_sign_doc(const CosmosDelegateRequest &request,
                                     CosmosSignedTransaction *out) {
  if (out == nullptr) return CosmosError::InvalidArgument;
  memset(out, 0, sizeof(*out));
  if (!bech32_has_prefix(request.delegator, "cosmos")) {
    return CosmosError::InvalidAddress;
  }
  if (!bech32_has_prefix(request.validator, "cosmosvaloper")) {
    return CosmosError::InvalidAddress;
  }
  if (request.chain_id[0] == '\0' || request.denom[0] == '\0' ||
      request.fee_denom[0] == '\0') {
    return CosmosError::InvalidArgument;
  }
  if (!valid_decimal_amount(request.amount) ||
      !valid_decimal_amount(request.fee_amount)) {
    return CosmosError::InvalidAmount;
  }
  if (request.gas_limit == 0) return CosmosError::InvalidArgument;

  // MsgDelegate { string delegator = 1; string validator = 2; Coin amount = 3; }
  uint8_t msg[256];
  Writer msg_writer = { msg, sizeof(msg), 0, true };
  write_string_field(&msg_writer, 1, request.delegator);
  write_string_field(&msg_writer, 2, request.validator);
  uint8_t coin[128];
  Writer coin_writer = { coin, sizeof(coin), 0, true };
  write_string_field(&coin_writer, 1, request.denom);
  write_string_field(&coin_writer, 2, request.amount);
  if (!coin_writer.ok || coin_writer.position == 0) return CosmosError::BufferTooSmall;
  write_message_field(&msg_writer, 3, coin, coin_writer.position);
  if (!msg_writer.ok) return CosmosError::BufferTooSmall;

  // Any { string type_url = 1; bytes value = 2; }
  uint8_t any[320];
  Writer any_writer = { any, sizeof(any), 0, true };
  write_string_field(&any_writer, 1, kMsgDelegateTypeUrl);
  write_message_field(&any_writer, 2, msg, msg_writer.position);
  if (!any_writer.ok) return CosmosError::BufferTooSmall;

  // TxBody { repeated Any messages = 1; string memo = 2; uint64 timeout = 3; }
  uint8_t body[384];
  Writer body_writer = { body, sizeof(body), 0, true };
  write_message_field(&body_writer, 1, any, any_writer.position);
  if (!body_writer.ok) return CosmosError::BufferTooSmall;

  // PubKey { bytes key = 1; } wrapped in Any.
  uint8_t pubkey[40];
  Writer pubkey_writer = { pubkey, sizeof(pubkey), 0, true };
  write_message_field(&pubkey_writer, 1, request.public_key, kCompressedPublicKeySize);
  if (!pubkey_writer.ok) return CosmosError::BufferTooSmall;
  uint8_t pubkey_any[96];
  Writer pubkey_any_writer = { pubkey_any, sizeof(pubkey_any), 0, true };
  write_string_field(&pubkey_any_writer, 1, kSecp256k1PubKeyTypeUrl);
  write_message_field(&pubkey_any_writer, 2, pubkey, pubkey_writer.position);
  if (!pubkey_any_writer.ok) return CosmosError::BufferTooSmall;

  // ModeInfo { Single single = 1; } / Single { SignMode mode = 1; }
  uint8_t single[8];
  Writer single_writer = { single, sizeof(single), 0, true };
  write_uint_field(&single_writer, 1, kSignModeDirect);
  uint8_t mode_info[16];
  Writer mode_writer = { mode_info, sizeof(mode_info), 0, true };
  write_message_field(&mode_writer, 1, single, single_writer.position);
  if (!mode_writer.ok) return CosmosError::BufferTooSmall;

  // SignerInfo { Any public_key = 1; ModeInfo mode_info = 2; uint64 sequence = 3; }
  uint8_t signer[192];
  Writer signer_writer = { signer, sizeof(signer), 0, true };
  write_message_field(&signer_writer, 1, pubkey_any, pubkey_any_writer.position);
  write_message_field(&signer_writer, 2, mode_info, mode_writer.position);
  write_uint_field(&signer_writer, 3, request.sequence);
  if (!signer_writer.ok) return CosmosError::BufferTooSmall;

  // Fee { repeated Coin amount = 1; uint64 gas_limit = 2; }
  uint8_t fee_coin[128];
  Writer fee_coin_writer = { fee_coin, sizeof(fee_coin), 0, true };
  write_string_field(&fee_coin_writer, 1, request.fee_denom);
  write_string_field(&fee_coin_writer, 2, request.fee_amount);
  if (!fee_coin_writer.ok) return CosmosError::BufferTooSmall;
  uint8_t fee[192];
  Writer fee_writer = { fee, sizeof(fee), 0, true };
  write_message_field(&fee_writer, 1, fee_coin, fee_coin_writer.position);
  write_uint_field(&fee_writer, 2, request.gas_limit);
  if (!fee_writer.ok) return CosmosError::BufferTooSmall;

  // AuthInfo { repeated SignerInfo signer_infos = 1; Fee fee = 2; }
  uint8_t auth_info[256];
  Writer auth_writer = { auth_info, sizeof(auth_info), 0, true };
  write_message_field(&auth_writer, 1, signer, signer_writer.position);
  write_message_field(&auth_writer, 2, fee, fee_writer.position);
  if (!auth_writer.ok) return CosmosError::BufferTooSmall;

  // SignDoc { bytes body_bytes = 1; bytes auth_info_bytes = 2;
  //           string chain_id = 3; uint64 account_number = 4; }
  Writer doc = { out->sign_doc, sizeof(out->sign_doc), 0, true };
  write_message_field(&doc, 1, body, body_writer.position);
  write_message_field(&doc, 2, auth_info, auth_writer.position);
  write_string_field(&doc, 3, request.chain_id);
  write_uint_field(&doc, 4, request.account_number);
  if (!doc.ok) return CosmosError::BufferTooSmall;
  out->sign_doc_size = static_cast<uint16_t>(doc.position);
  const bool hashed = crypto_sha256(out->sign_doc, doc.position, out->digest);
  secure_zero(msg, sizeof(msg));
  secure_zero(coin, sizeof(coin));
  secure_zero(any, sizeof(any));
  secure_zero(body, sizeof(body));
  secure_zero(pubkey, sizeof(pubkey));
  secure_zero(pubkey_any, sizeof(pubkey_any));
  secure_zero(signer, sizeof(signer));
  secure_zero(fee, sizeof(fee));
  secure_zero(fee_coin, sizeof(fee_coin));
  secure_zero(auth_info, sizeof(auth_info));
  secure_zero(mode_info, sizeof(mode_info));
  secure_zero(single, sizeof(single));
  return hashed ? CosmosError::Ok : CosmosError::CryptoFailure;
}

const char *cosmos_error_text(CosmosError error) {
  switch (error) {
    case CosmosError::Ok: return "ok";
    case CosmosError::InvalidArgument: return "invalid-argument";
    case CosmosError::Unsupported: return "unsupported";
    case CosmosError::InvalidAddress: return "invalid-bech32-prefix";
    case CosmosError::InvalidAmount: return "invalid-decimal-amount";
    case CosmosError::BufferTooSmall: return "buffer-too-small";
    case CosmosError::CryptoFailure: return "crypto-failure";
  }
  return "unknown";
}

void clear_cosmos_request(CosmosDelegateRequest *request) {
  if (request != nullptr) secure_zero(request, sizeof(*request));
}

bool run_cosmos_self_tests() {
  // Expected bytes produced by prost 0.13 from the same message definitions,
  // for chain cosmoshub-4, account 42, sequence 7, 1234567 uatom delegated and
  // a 5000 uatom / 200000 gas fee.
  static const uint8_t kExpectedSignDoc[] = {
    0x0a, 0xa1, 0x01, 0x0a, 0x9e, 0x01, 0x0a, 0x23, 0x2f, 0x63, 0x6f, 0x73,
    0x6d, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x2e,
    0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x4d, 0x73, 0x67, 0x44,
    0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x65, 0x12, 0x77, 0x0a, 0x2d, 0x63,
    0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x31, 0x77, 0x35, 0x30, 0x38, 0x64, 0x36,
    0x71, 0x65, 0x6a, 0x78, 0x74, 0x64, 0x67, 0x34, 0x79, 0x35, 0x72, 0x33,
    0x7a, 0x61, 0x72, 0x76, 0x61, 0x72, 0x79, 0x30, 0x63, 0x35, 0x78, 0x77,
    0x37, 0x6b, 0x36, 0x61, 0x68, 0x36, 0x30, 0x63, 0x12, 0x34, 0x63, 0x6f,
    0x73, 0x6d, 0x6f, 0x73, 0x76, 0x61, 0x6c, 0x6f, 0x70, 0x65, 0x72, 0x31,
    0x77, 0x35, 0x30, 0x38, 0x64, 0x36, 0x71, 0x65, 0x6a, 0x78, 0x74, 0x64,
    0x67, 0x34, 0x79, 0x35, 0x72, 0x33, 0x7a, 0x61, 0x72, 0x76, 0x61, 0x72,
    0x79, 0x30, 0x63, 0x35, 0x78, 0x77, 0x37, 0x6b, 0x6c, 0x66, 0x72, 0x30,
    0x72, 0x74, 0x1a, 0x10, 0x0a, 0x05, 0x75, 0x61, 0x74, 0x6f, 0x6d, 0x12,
    0x07, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x12, 0x67, 0x0a, 0x50,
    0x0a, 0x46, 0x0a, 0x1f, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e,
    0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x73, 0x65, 0x63, 0x70, 0x32,
    0x35, 0x36, 0x6b, 0x31, 0x2e, 0x50, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x12,
    0x23, 0x0a, 0x21, 0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb,
    0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    0x12, 0x04, 0x0a, 0x02, 0x08, 0x01, 0x18, 0x07, 0x12, 0x13, 0x0a, 0x0d,
    0x0a, 0x05, 0x75, 0x61, 0x74, 0x6f, 0x6d, 0x12, 0x04, 0x35, 0x30, 0x30,
    0x30, 0x10, 0xc0, 0x9a, 0x0c, 0x1a, 0x0b, 0x63, 0x6f, 0x73, 0x6d, 0x6f,
    0x73, 0x68, 0x75, 0x62, 0x2d, 0x34, 0x20, 0x2a };
  static const uint8_t kExpectedDigest[kSha256Size] = {
    0x21, 0x96, 0x51, 0x9d, 0xf1, 0xe5, 0x0f, 0x4c, 0x96, 0x26, 0x40, 0x26,
    0x78, 0x08, 0xba, 0x98, 0x6c, 0xb5, 0x90, 0x43, 0x08, 0xf9, 0x39, 0x8d,
    0x6a, 0xb1, 0xc3, 0xbd, 0xc1, 0xb1, 0xbc, 0x81 };
  CosmosDelegateRequest request;
  memset(&request, 0, sizeof(request));
  strcpy(request.chain_id, "cosmoshub-4");
  strcpy(request.delegator, "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c");
  strcpy(request.validator, "cosmosvaloper1w508d6qejxtdg4y5r3zarvary0c5xw7klfr0rt");
  strcpy(request.denom, "uatom");
  strcpy(request.amount, "1234567");
  strcpy(request.fee_denom, "uatom");
  strcpy(request.fee_amount, "5000");
  request.gas_limit = 200000;
  request.account_number = 42;
  request.sequence = 7;
  const uint8_t kPublicKey[kCompressedPublicKeySize] = {
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
    0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
    0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98 };
  memcpy(request.public_key, kPublicKey, sizeof(kPublicKey));

  CosmosSignedTransaction signed_doc;
  bool passed = cosmos_delegate_sign_doc(request, &signed_doc) == CosmosError::Ok &&
                signed_doc.sign_doc_size == sizeof(kExpectedSignDoc) &&
                crypto_constant_time_equal(signed_doc.sign_doc, kExpectedSignDoc,
                                           sizeof(kExpectedSignDoc)) &&
                crypto_constant_time_equal(signed_doc.digest, kExpectedDigest,
                                           sizeof(kExpectedDigest));
  // A validator address pasted into the delegator field must be refused.
  CosmosDelegateRequest wrong = request;
  strcpy(wrong.delegator, request.validator);
  passed = passed && cosmos_delegate_sign_doc(wrong, &signed_doc) ==
                          CosmosError::InvalidAddress;
  // Non-canonical decimal amounts must be refused.
  CosmosDelegateRequest bad_amount = request;
  strcpy(bad_amount.fee_amount, "05000");
  passed = passed && cosmos_delegate_sign_doc(bad_amount, &signed_doc) ==
                          CosmosError::InvalidAmount;
  clear_cosmos_request(&request);
  clear_cosmos_request(&wrong);
  clear_cosmos_request(&bad_amount);
  secure_zero(&signed_doc, sizeof(signed_doc));
  return passed;
}

}  // namespace hexwallet
