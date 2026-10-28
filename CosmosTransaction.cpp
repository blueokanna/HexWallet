#include "CosmosTransaction.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "local_bech32.h"

namespace hexwallet {
namespace {

constexpr char kMsgSendTypeUrl[] = "/cosmos.bank.v1beta1.MsgSend";
constexpr char kPubKeyTypeUrl[] = "/cosmos.crypto.secp256k1.PubKey";
constexpr uint64_t kSignModeDirect = 1;
constexpr size_t kAddressBytes = 20;

constexpr CosmosChainParams kCosmosChains[] = {
    {"atom", "cosmos", "cosmoshub-", "uatom", "ATOM", 6},
    {"osmo", "osmo", "osmosis-", "uosmo", "OSMO", 6},
    {"tia", "celestia", "celestia", "utia", "TIA", 6},
};

bool equal(const uint8_t *left, const uint8_t *right, size_t size) {
  return crypto_constant_time_equal(left, right, size);
}

struct PayloadReader {
  const uint8_t *data;
  size_t size;
  size_t offset;

  bool u8(uint8_t *out) {
    if (offset >= size) return false;
    *out = data[offset++];
    return true;
  }

  bool u64(uint64_t *out) {
    if (size - offset < 8) return false;
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
      value = (value << 8) | data[offset++];
    }
    *out = value;
    return true;
  }

  bool bytes(char *out, size_t capacity, size_t *out_size) {
    uint8_t length = 0;
    if (!u8(&length) || length > capacity || length > size - offset) {
      return false;
    }
    memcpy(out, data + offset, length);
    out[length] = '\0';
    offset += length;
    *out_size = length;
    return true;
  }
};

// Bounded, canonical protobuf writer. Every field is written in ascending field
// order with default values omitted, matching gogoproto encoding.
struct ProtoWriter {
  uint8_t *data;
  size_t capacity;
  size_t size;
  bool ok;

  ProtoWriter(uint8_t *buffer, size_t buffer_capacity)
      : data(buffer), capacity(buffer_capacity), size(0), ok(buffer != nullptr) {}

  bool put(uint8_t value) {
    if (!ok || size >= capacity) {
      ok = false;
      return false;
    }
    data[size++] = value;
    return true;
  }

  bool raw(const void *source, size_t length) {
    if (!ok || length > capacity - size) {
      ok = false;
      return false;
    }
    memcpy(data + size, source, length);
    size += length;
    return true;
  }

  bool varint(uint64_t value) {
    do {
      uint8_t byte = static_cast<uint8_t>(value & 0x7f);
      value >>= 7;
      if (value != 0) byte |= 0x80;
      if (!put(byte)) return false;
    } while (value != 0);
    return true;
  }

  bool tag(uint32_t field, uint8_t wire) {
    return varint((static_cast<uint64_t>(field) << 3) | wire);
  }

  bool bytes(uint32_t field, const void *source, size_t length) {
    return tag(field, 2) && varint(length) && raw(source, length);
  }

  bool string(uint32_t field, const char *text) {
    return bytes(field, text, strlen(text));
  }

  bool uint64(uint32_t field, uint64_t value) {
    return tag(field, 0) && varint(value);
  }
};

bool lowercase_only(const char *text) {
  for (const char *cursor = text; *cursor != '\0'; ++cursor) {
    if (*cursor >= 'A' && *cursor <= 'Z') return false;
  }
  return true;
}

bool convert_5_to_8(const std::vector<uint8_t> &input, uint8_t *out,
                    size_t capacity, size_t *out_size) {
  uint32_t accumulator = 0;
  unsigned bits = 0;
  size_t count = 0;
  for (const uint8_t value : input) {
    if (value > 31) return false;
    accumulator = (accumulator << 5) | value;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      if (count >= capacity) return false;
      out[count++] = static_cast<uint8_t>((accumulator >> bits) & 0xff);
    }
  }
  if (bits >= 5) return false;
  if ((accumulator & ((1U << bits) - 1)) != 0) return false;
  *out_size = count;
  return true;
}

// Strict canonical bech32 account address: lowercase, correct HRP, BECH32
// (not BECH32M) checksum, exactly 20 payload bytes, and an identical re-encode.
bool decode_account_address(const char *hrp, const char *address,
                            uint8_t out[kAddressBytes]) {
  if (hrp == nullptr || address == nullptr) return false;
  const size_t length = strlen(address);
  if (length == 0 || length > kCosmosMaxAddress - 1 || !lowercase_only(address)) {
    return false;
  }
  const bech32::DecodeResult decoded = bech32::decode(address);
  if (decoded.encoding != bech32::Encoding::BECH32 || decoded.hrp != hrp) {
    return false;
  }
  size_t payload_size = 0;
  uint8_t payload[64];
  if (!convert_5_to_8(decoded.data, payload, sizeof(payload), &payload_size) ||
      payload_size != kAddressBytes) {
    return false;
  }
  char canonical[kCosmosMaxAddress];
  if (!bech32_encode(hrp, payload, payload_size, canonical, sizeof(canonical),
                     false) ||
      strcmp(canonical, address) != 0) {
    return false;
  }
  memcpy(out, payload, kAddressBytes);
  return true;
}

bool address_matches_public_key(const char *hrp, const char *address,
                                const uint8_t public_key[kCompressedPublicKeySize]) {
  uint8_t expected[kAddressBytes];
  uint8_t actual[kAddressBytes];
  if (!crypto_hash160(public_key, kCompressedPublicKeySize, expected) ||
      !decode_account_address(hrp, address, actual)) {
    return false;
  }
  return equal(expected, actual, kAddressBytes);
}

void decimal_text(uint64_t value, char *out, size_t size) {
  char reversed[24];
  size_t count = 0;
  do {
    reversed[count++] = static_cast<char>('0' + (value % 10));
    value /= 10;
  } while (value != 0 && count < sizeof(reversed));
  size_t written = 0;
  while (count > 0 && written + 1 < size) {
    out[written++] = reversed[--count];
  }
  out[written] = '\0';
}

bool build_coin(uint8_t *out, size_t capacity, size_t *size, const char *denom,
                uint64_t amount) {
  char text[24];
  decimal_text(amount, text, sizeof(text));
  ProtoWriter writer(out, capacity);
  writer.string(1, denom);
  writer.string(2, text);
  *size = writer.size;
  return writer.ok;
}

bool build_tx_body(uint8_t *out, size_t capacity, size_t *size,
                   const char *from, const char *to, const char *denom,
                   uint64_t amount) {
  uint8_t coin[64];
  size_t coin_size = 0;
  if (!build_coin(coin, sizeof(coin), &coin_size, denom, amount)) return false;
  uint8_t message[192];
  ProtoWriter msg(message, sizeof(message));
  msg.string(1, from);
  msg.string(2, to);
  msg.bytes(3, coin, coin_size);
  if (!msg.ok) return false;
  uint8_t any[kCosmosMaxBody];
  ProtoWriter any_writer(any, sizeof(any));
  any_writer.string(1, kMsgSendTypeUrl);
  any_writer.bytes(2, message, msg.size);
  if (!any_writer.ok) return false;
  ProtoWriter writer(out, capacity);
  writer.bytes(1, any, any_writer.size);
  *size = writer.size;
  return writer.ok;
}

bool build_auth_info(uint8_t *out, size_t capacity, size_t *size,
                     const uint8_t public_key[kCompressedPublicKeySize],
                     const char *denom, uint64_t fee, uint64_t gas_limit,
                     uint64_t sequence) {
  uint8_t pubkey_message[40];
  ProtoWriter pubkey_message_writer(pubkey_message, sizeof(pubkey_message));
  pubkey_message_writer.bytes(1, public_key, kCompressedPublicKeySize);
  if (!pubkey_message_writer.ok) return false;
  uint8_t pubkey_any[80];
  ProtoWriter pubkey_any_writer(pubkey_any, sizeof(pubkey_any));
  pubkey_any_writer.string(1, kPubKeyTypeUrl);
  pubkey_any_writer.bytes(2, pubkey_message, pubkey_message_writer.size);
  if (!pubkey_any_writer.ok) return false;
  uint8_t single[8];
  ProtoWriter single_writer(single, sizeof(single));
  single_writer.uint64(1, kSignModeDirect);
  if (!single_writer.ok) return false;
  uint8_t mode_info[16];
  ProtoWriter mode_writer(mode_info, sizeof(mode_info));
  mode_writer.bytes(1, single, single_writer.size);
  if (!mode_writer.ok) return false;
  uint8_t signer_info[128];
  ProtoWriter signer_writer(signer_info, sizeof(signer_info));
  signer_writer.bytes(1, pubkey_any, pubkey_any_writer.size);
  signer_writer.bytes(2, mode_info, mode_writer.size);
  signer_writer.uint64(3, sequence);
  if (!signer_writer.ok) return false;
  uint8_t fee_coin[64];
  size_t fee_coin_size = 0;
  if (!build_coin(fee_coin, sizeof(fee_coin), &fee_coin_size, denom, fee)) {
    return false;
  }
  uint8_t fee_message[96];
  ProtoWriter fee_writer(fee_message, sizeof(fee_message));
  fee_writer.bytes(1, fee_coin, fee_coin_size);
  fee_writer.uint64(2, gas_limit);
  if (!fee_writer.ok) return false;
  ProtoWriter writer(out, capacity);
  writer.bytes(1, signer_info, signer_writer.size);
  writer.bytes(2, fee_message, fee_writer.size);
  *size = writer.size;
  return writer.ok;
}

bool build_sign_doc(uint8_t *out, size_t capacity, size_t *size,
                    const uint8_t *body, size_t body_size,
                    const uint8_t *auth_info, size_t auth_info_size,
                    const char *chain_id, uint64_t account_number) {
  ProtoWriter writer(out, capacity);
  writer.bytes(1, body, body_size);
  writer.bytes(2, auth_info, auth_info_size);
  writer.string(3, chain_id);
  writer.uint64(4, account_number);
  *size = writer.size;
  return writer.ok;
}

bool build_tx_raw(uint8_t *out, size_t capacity, size_t *size,
                  const uint8_t *body, size_t body_size,
                  const uint8_t *auth_info, size_t auth_info_size,
                  const uint8_t signature[64]) {
  ProtoWriter writer(out, capacity);
  writer.bytes(1, body, body_size);
  writer.bytes(2, auth_info, auth_info_size);
  writer.bytes(3, signature, 64);
  *size = writer.size;
  return writer.ok;
}

bool valid_chain_id_char(char value) {
  return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
         (value >= '0' && value <= '9') || value == '-' || value == '.' ||
         value == '_';
}

bool chain_id_allowed(const CosmosChainParams &chain, const char *chain_id) {
  const size_t prefix = strlen(chain.chain_prefix);
  if (strncmp(chain_id, chain.chain_prefix, prefix) != 0) return false;
  for (const char *cursor = chain_id; *cursor != '\0'; ++cursor) {
    if (!valid_chain_id_char(*cursor)) return false;
  }
  return true;
}

#include "src/generated/CosmosVectorsTest.inc"

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

bool hex_equals(const uint8_t *data, size_t size, const char *text) {
  if (text == nullptr || strlen(text) != size * 2) return false;
  uint8_t expected[kCosmosMaxSignedTx];
  if (size > sizeof(expected) || !hex_decode(text, expected, size)) return false;
  return equal(data, expected, size);
}

}  // namespace

const CosmosChainParams *cosmos_chain_params(const char *network_id) {
  if (network_id == nullptr) return nullptr;
  for (const CosmosChainParams &chain : kCosmosChains) {
    if (strcmp(chain.network_id, network_id) == 0) return &chain;
  }
  return nullptr;
}

bool cosmos_format_amount(uint64_t amount, uint8_t decimals,
                          const char *symbol, char *out, size_t size) {
  if (symbol == nullptr || out == nullptr || size == 0 || decimals > 19) {
    return false;
  }
  uint64_t divisor = 1;
  for (uint8_t index = 0; index < decimals; ++index) divisor *= 10;
  int written = 0;
  if (decimals == 0) {
    written = snprintf(out, size, "%llu %s",
                       static_cast<unsigned long long>(amount), symbol);
  } else {
    written = snprintf(out, size, "%llu.%0*llu %s",
                       static_cast<unsigned long long>(amount / divisor),
                       static_cast<int>(decimals),
                       static_cast<unsigned long long>(amount % divisor), symbol);
  }
  return written > 0 && static_cast<size_t>(written) < size;
}

CosmosError cosmos_review_payload(
    const uint8_t *payload, size_t size, const CosmosChainParams &chain,
    const char *from_address,
    const uint8_t public_key[kCompressedPublicKeySize], CosmosTransaction *out) {
  if (payload == nullptr || from_address == nullptr || public_key == nullptr ||
      out == nullptr || size == 0) {
    return CosmosError::InvalidArgument;
  }
  if (size > kCosmosMaxPayload) return CosmosError::Unsupported;
  clear_cosmos_transaction(out);

  PayloadReader reader = {payload, size, 0};
  uint8_t version = 0;
  char chain_id[kCosmosMaxChainId + 1] = {};
  char to[kCosmosMaxAddress] = {};
  char memo[2] = {};
  size_t chain_length = 0, to_length = 0, memo_length = 0;
  uint64_t account_number = 0, sequence = 0, amount = 0, fee = 0, gas = 0;
  if (!reader.u8(&version) || version != 1 ||
      !reader.bytes(chain_id, kCosmosMaxChainId, &chain_length) ||
      chain_length == 0 || !reader.u64(&account_number) ||
      !reader.u64(&sequence) || !reader.u64(&amount) || !reader.u64(&fee) ||
      !reader.u64(&gas) ||
      !reader.bytes(to, kCosmosMaxAddress - 1, &to_length) || to_length == 0 ||
      !reader.bytes(memo, 1, &memo_length) || reader.offset != size) {
    return CosmosError::Malformed;
  }
  if (memo_length != 0) return CosmosError::Unsupported;
  if (!chain_id_allowed(chain, chain_id)) return CosmosError::Unsupported;
  if (amount == 0) return CosmosError::InvalidAmount;
  if (fee > kCosmosMaxFee) return CosmosError::FeePolicy;
  if (gas == 0 || gas > kCosmosMaxGas) return CosmosError::FeePolicy;

  uint8_t recipient[kAddressBytes];
  if (!decode_account_address(chain.hrp, to, recipient)) {
    return CosmosError::Malformed;
  }
  if (strcmp(to, from_address) == 0) return CosmosError::InvalidAmount;
  if (!address_matches_public_key(chain.hrp, from_address, public_key)) {
    return CosmosError::WrongWallet;
  }
  uint8_t sender[kAddressBytes];
  if (!decode_account_address(chain.hrp, from_address, sender)) {
    return CosmosError::WrongWallet;
  }
  if (equal(sender, recipient, kAddressBytes)) return CosmosError::InvalidAmount;

  CosmosReview review = {};
  review.chain = &chain;
  snprintf(review.from, sizeof(review.from), "%s", from_address);
  snprintf(review.to, sizeof(review.to), "%s", to);
  snprintf(review.chain_id, sizeof(review.chain_id), "%s", chain_id);
  review.account_number = account_number;
  review.sequence = sequence;
  review.amount = amount;
  review.fee = fee;
  review.gas_limit = gas;
  memcpy(review.public_key, public_key, kCompressedPublicKeySize);
  if (!cosmos_format_amount(amount, chain.decimals, chain.symbol,
                            review.amount_text, sizeof(review.amount_text)) ||
      !cosmos_format_amount(fee, chain.decimals, chain.symbol, review.fee_text,
                            sizeof(review.fee_text))) {
    return CosmosError::BufferTooSmall;
  }

  size_t body_size = 0, auth_size = 0, sign_doc_size = 0;
  if (!build_tx_body(review.tx_body, sizeof(review.tx_body), &body_size,
                     review.from, review.to, chain.denom, amount) ||
      body_size > UINT16_MAX) {
    return CosmosError::BufferTooSmall;
  }
  if (!build_auth_info(review.auth_info, sizeof(review.auth_info), &auth_size,
                       public_key, chain.denom, fee, gas, sequence) ||
      auth_size > UINT16_MAX) {
    return CosmosError::BufferTooSmall;
  }
  review.tx_body_size = static_cast<uint16_t>(body_size);
  review.auth_info_size = static_cast<uint16_t>(auth_size);

  uint8_t sign_doc[kCosmosMaxSignDoc];
  if (!build_sign_doc(sign_doc, sizeof(sign_doc), &sign_doc_size,
                      review.tx_body, review.tx_body_size, review.auth_info,
                      review.auth_info_size, review.chain_id, account_number) ||
      !crypto_sha256(sign_doc, sign_doc_size, review.sign_doc_digest)) {
    secure_zero(sign_doc, sizeof(sign_doc));
    return CosmosError::CryptoFailure;
  }
  secure_zero(sign_doc, sizeof(sign_doc));
  out->review = review;
  return CosmosError::Ok;
}

CosmosError cosmos_sign_transaction(const CosmosTransaction &transaction,
                                    const uint8_t private_key[kPrivateKeySize],
                                    uint8_t *out, size_t *in_out_size) {
  if (private_key == nullptr || out == nullptr || in_out_size == nullptr) {
    return CosmosError::InvalidArgument;
  }
  const CosmosReview &review = transaction.review;
  if (review.chain == nullptr || review.tx_body_size == 0 ||
      review.auth_info_size == 0) {
    return CosmosError::InvalidArgument;
  }
  uint8_t public_key[kCompressedPublicKeySize];
  if (public_key_from_private(private_key, public_key) != WalletError::Ok) {
    return CosmosError::CryptoFailure;
  }
  if (!equal(public_key, review.public_key, sizeof(public_key))) {
    secure_zero(public_key, sizeof(public_key));
    return CosmosError::WrongWallet;
  }
  uint8_t sign_doc[kCosmosMaxSignDoc];
  size_t sign_doc_size = 0;
  uint8_t digest[kSha256Size];
  const bool built =
      build_sign_doc(sign_doc, sizeof(sign_doc), &sign_doc_size, review.tx_body,
                     review.tx_body_size, review.auth_info,
                     review.auth_info_size, review.chain_id,
                     review.account_number) &&
      crypto_sha256(sign_doc, sign_doc_size, digest);
  secure_zero(sign_doc, sizeof(sign_doc));
  if (!built || !equal(digest, review.sign_doc_digest, sizeof(digest))) {
    secure_zero(public_key, sizeof(public_key));
    secure_zero(digest, sizeof(digest));
    return CosmosError::Malformed;
  }
  RecoverableSignature signature = {};
  const WalletError signed_error =
      secp256k1_sign_digest_recoverable(private_key, digest, &signature);
  secure_zero(digest, sizeof(digest));
  secure_zero(public_key, sizeof(public_key));
  if (signed_error != WalletError::Ok) {
    secure_zero(&signature, sizeof(signature));
    return CosmosError::CryptoFailure;
  }
  uint8_t compact[64];
  memcpy(compact, signature.r, 32);
  memcpy(compact + 32, signature.s, 32);
  secure_zero(&signature, sizeof(signature));

  uint8_t raw[kCosmosMaxSignedTx];
  size_t raw_size = 0;
  const bool raw_ok =
      build_tx_raw(raw, sizeof(raw), &raw_size, review.tx_body,
                   review.tx_body_size, review.auth_info,
                   review.auth_info_size, compact);
  secure_zero(compact, sizeof(compact));
  if (!raw_ok) {
    secure_zero(raw, sizeof(raw));
    return CosmosError::BufferTooSmall;
  }
  if (*in_out_size < raw_size) {
    *in_out_size = raw_size;
    secure_zero(raw, sizeof(raw));
    return CosmosError::BufferTooSmall;
  }
  memcpy(out, raw, raw_size);
  *in_out_size = raw_size;
  secure_zero(raw, sizeof(raw));
  return CosmosError::Ok;
}

void clear_cosmos_transaction(CosmosTransaction *transaction) {
  if (transaction != nullptr) secure_zero(transaction, sizeof(*transaction));
}

const char *cosmos_error_text(CosmosError error) {
  switch (error) {
    case CosmosError::Ok: return "ok";
    case CosmosError::InvalidArgument: return "invalid-argument";
    case CosmosError::Malformed: return "malformed-payload";
    case CosmosError::Unsupported: return "unsupported-transaction";
    case CosmosError::WrongWallet: return "wrong-wallet";
    case CosmosError::InvalidAmount: return "invalid-amount";
    case CosmosError::FeePolicy: return "fee-policy";
    case CosmosError::CryptoFailure: return "crypto-failure";
    case CosmosError::BufferTooSmall: return "buffer-too-small";
  }
  return "unknown";
}

bool run_cosmos_self_tests() {
  uint8_t private_key[kPrivateKeySize];
  uint8_t public_key[kCompressedPublicKeySize];
  bool passed = hex_decode(kCosmosVectorPrivateKeyHex, private_key,
                           sizeof(private_key)) &&
                hex_decode(kCosmosVectorPublicKeyHex, public_key,
                           sizeof(public_key));
  for (const CosmosVectorCase &vector : kCosmosVectorCases) {
    if (!passed) break;
    const CosmosChainParams *chain = cosmos_chain_params(vector.network);
    uint8_t payload[kCosmosMaxPayload];
    const size_t payload_size =
        vector.payload_hex == nullptr ? 0 : strlen(vector.payload_hex) / 2;
    passed = chain != nullptr && payload_size > 0 &&
             payload_size <= sizeof(payload) &&
             hex_decode(vector.payload_hex, payload, payload_size);
    if (!passed) break;
    CosmosTransaction transaction;
    const CosmosError reviewed = cosmos_review_payload(
        payload, payload_size, *chain, vector.from_address, public_key,
        &transaction);
    passed = reviewed == CosmosError::Ok &&
             strcmp(transaction.review.to, vector.to_address) == 0 &&
             strcmp(transaction.review.chain_id, vector.chain_id) == 0 &&
             transaction.review.account_number == strtoull(vector.account, nullptr, 10) &&
             transaction.review.sequence == strtoull(vector.sequence, nullptr, 10) &&
             transaction.review.amount == strtoull(vector.amount, nullptr, 10) &&
             transaction.review.fee == strtoull(vector.fee, nullptr, 10) &&
             transaction.review.gas_limit == strtoull(vector.gas, nullptr, 10) &&
             strcmp(transaction.review.amount_text, vector.amount_text) == 0 &&
             strcmp(transaction.review.fee_text, vector.fee_text) == 0 &&
             hex_equals(transaction.review.tx_body, transaction.review.tx_body_size,
                        vector.body_hex) &&
             hex_equals(transaction.review.auth_info,
                        transaction.review.auth_info_size, vector.auth_info_hex) &&
             hex_equals(transaction.review.sign_doc_digest, kSha256Size,
                        vector.digest_hex);
    if (passed) {
      uint8_t expected_signature[64];
      passed = hex_decode(vector.signature_hex, expected_signature,
                          sizeof(expected_signature));
      secure_zero(expected_signature, sizeof(expected_signature));
    }
#if !defined(HEXWALLET_HOST_TEST)
    if (passed) {
      uint8_t signed_tx[kCosmosMaxSignedTx + 8];
      size_t signed_size = sizeof(signed_tx);
      passed = cosmos_sign_transaction(transaction, private_key, signed_tx,
                                       &signed_size) == CosmosError::Ok &&
               hex_equals(signed_tx, signed_size, vector.tx_raw_hex);
      secure_zero(signed_tx, sizeof(signed_tx));
    }
#endif
    for (size_t end = 1; end < payload_size && passed; ++end) {
      CosmosTransaction probe;
      passed = cosmos_review_payload(payload, end, *chain, vector.from_address,
                                     public_key, &probe) != CosmosError::Ok;
      clear_cosmos_transaction(&probe);
    }
    clear_cosmos_transaction(&transaction);
  }
  for (const CosmosRejectedCase &vector : kCosmosRejectedCases) {
    if (!passed) break;
    const CosmosChainParams *chain = cosmos_chain_params(vector.network);
    uint8_t payload[kCosmosMaxPayload];
    const size_t payload_size =
        vector.payload_hex == nullptr ? 0 : strlen(vector.payload_hex) / 2;
    passed = chain != nullptr && payload_size > 0 &&
             payload_size <= sizeof(payload) &&
             hex_decode(vector.payload_hex, payload, payload_size);
    if (!passed) break;
    CosmosTransaction transaction;
    passed = cosmos_review_payload(payload, payload_size, *chain,
                                   kCosmosVectorCases[0].from_address,
                                   public_key, &transaction) != CosmosError::Ok;
    clear_cosmos_transaction(&transaction);
  }
  if (passed) {
    char text[kCosmosAmountTextSize];
    passed = cosmos_format_amount(1500000, 6, "ATOM", text, sizeof(text)) &&
             strcmp(text, "1.500000 ATOM") == 0;
  }
  (void)private_key;
  secure_zero(private_key, sizeof(private_key));
  secure_zero(public_key, sizeof(public_key));
  return passed;
}

}  // namespace hexwallet
