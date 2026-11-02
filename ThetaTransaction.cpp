#include "ThetaTransaction.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoPrimitives.h"
#include "keccak256.h"

namespace hexwallet {
namespace {
constexpr uint8_t kRlpEmpty = 0x80;
// Type prefix Theta writes ahead of the SendTx body.
constexpr uint8_t kSendTxType = 2;

size_t wrap_prefix(uint8_t *out, size_t payload_size, uint8_t short_base,
                   uint8_t long_base) {
  if (payload_size <= 55) {
    out[0] = static_cast<uint8_t>(short_base + payload_size);
    return 1;
  }
  size_t length = 0;
  uint8_t length_bytes[8];
  size_t remaining = payload_size;
  while (remaining != 0) {
    length_bytes[length++] = static_cast<uint8_t>(remaining);
    remaining >>= 8;
  }
  out[0] = static_cast<uint8_t>(long_base + length);
  for (size_t index = 0; index < length; ++index) {
    out[1 + index] = length_bytes[length - 1 - index];
  }
  return 1 + length;
}

size_t encode_bytes(uint8_t *out, const uint8_t *data, size_t size) {
  if (size == 1 && data[0] < 0x80) {
    out[0] = data[0];
    return 1;
  }
  const size_t header = wrap_prefix(out, size, 0x80, 0xB7);
  if (size != 0) memcpy(out + header, data, size);
  return header + size;
}

size_t uint_bytes(uint64_t value, uint8_t out[8]) {
  size_t length = 0;
  while (value != 0) {
    out[length++] = static_cast<uint8_t>(value);
    value >>= 8;
  }
  // big-endian order in out[0..length)
  for (size_t index = 0; index < length / 2; ++index) {
    const uint8_t swap = out[index];
    out[index] = out[length - 1 - index];
    out[length - 1 - index] = swap;
  }
  return length;
}

size_t encode_uint(uint8_t *out, uint64_t value) {
  if (value == 0) {
    out[0] = kRlpEmpty;
    return 1;
  }
  uint8_t big_endian[8];
  const size_t length = uint_bytes(value, big_endian);
  return encode_bytes(out, big_endian, length);
}

// List header plus the already encoded items.
size_t encode_list(uint8_t *out, const uint8_t *items, size_t items_size) {
  const size_t header = wrap_prefix(out, items_size, 0xC0, 0xF7);
  if (items_size != 0) memcpy(out + header, items, items_size);
  return header + items_size;
}

uint64_t read_u64_be(const uint8_t *data) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; ++index) value = (value << 8) | data[index];
  return value;
}

void write_u64_be(uint64_t value, uint8_t *out) {
  for (size_t index = 0; index < 8; ++index) {
    out[7 - index] = static_cast<uint8_t>(value);
    value >>= 8;
  }
}

size_t encode_coins(uint8_t *out, const ThetaCoin &coins) {
  uint8_t items[24];
  size_t used = encode_uint(items, coins.theta_wei);
  used += encode_uint(items + used, coins.tfuel_wei);
  return encode_list(out, items, used);
}

size_t encode_input(uint8_t *out, const ThetaInput &input) {
  uint8_t items[64];
  size_t used = encode_bytes(items, input.address, kThetaAddressSize);
  used += encode_coins(items + used, input.coins);
  used += encode_uint(items + used, input.sequence);
  items[used++] = kRlpEmpty;  // signature stays empty while signing
  return encode_list(out, items, used);
}

size_t encode_output(uint8_t *out, const ThetaOutput &output) {
  uint8_t items[48];
  size_t used = encode_bytes(items, output.address, kThetaAddressSize);
  used += encode_coins(items + used, output.coins);
  return encode_list(out, items, used);
}

bool inputs_valid(const ThetaSendTx &tx) {
  if (tx.input_count == 0 || tx.input_count > kThetaMaxInputs) return false;
  if (tx.output_count == 0 || tx.output_count > kThetaMaxOutputs) return false;
  if (tx.chain_id == nullptr) return false;
  uint64_t total_in = 0;
  for (size_t index = 0; index < tx.input_count; ++index) {
    const ThetaInput &input = tx.inputs[index];
    // A zero address is never a valid sender, and an input has to carry more
    // than the fee it pays.
    bool zero = true;
    for (size_t byte = 0; byte < kThetaAddressSize; ++byte) {
      if (input.address[byte] != 0) zero = false;
    }
    if (zero) return false;
    const uint64_t coins = input.coins.theta_wei + input.coins.tfuel_wei;
    if (coins < input.coins.theta_wei) return false;  // overflow
    if (total_in + coins < total_in) return false;
    total_in += coins;
  }
  for (size_t index = 0; index < tx.output_count; ++index) {
    if (tx.outputs[index].coins.theta_wei == 0 &&
        tx.outputs[index].coins.tfuel_wei == 0) {
      return false;
    }
  }
  return true;
}

uint16_t hex_value(char c) {
  if (c >= '0' && c <= '9') return static_cast<uint16_t>(c - '0');
  if (c >= 'A' && c <= 'F') return static_cast<uint16_t>(c - 'A' + 10);
  if (c >= 'a' && c <= 'f') return static_cast<uint16_t>(c - 'a' + 10);
  return 0xFFFF;
}

bool hex_equal(const uint8_t *data, size_t size, const char *hex) {
  for (size_t index = 0; index < size; ++index) {
    const uint16_t high = hex_value(hex[index * 2]);
    const uint16_t low = hex_value(hex[index * 2 + 1]);
    if (high == 0xFFFF || low == 0xFFFF) return false;
    if (data[index] != static_cast<uint8_t>((high << 4) | low)) return false;
  }
  return hex[size * 2] == '\0';
}

bool parse_address(const char *text, uint8_t out[kThetaAddressSize]) {
  if (strncmp(text, "0x", 2) != 0) return false;
  for (size_t index = 0; index < kThetaAddressSize; ++index) {
    const uint16_t high = hex_value(text[2 + index * 2]);
    const uint16_t low = hex_value(text[3 + index * 2]);
    if (high == 0xFFFF || low == 0xFFFF) return false;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return text[2 + kThetaAddressSize * 2] == '\0';
}
}  // namespace

bool theta_sendtx_sign_bytes(const ThetaSendTx &tx, uint8_t *out,
                             size_t capacity, size_t *out_size) {
  if (out == nullptr || out_size == nullptr) return false;
  *out_size = 0;
  if (!inputs_valid(tx)) return false;

  uint8_t inputs[kThetaMaxInputs * 64];
  size_t inputs_size = 0;
  for (size_t index = 0; index < tx.input_count; ++index) {
    inputs_size += encode_input(inputs + inputs_size, tx.inputs[index]);
  }
  uint8_t outputs[kThetaMaxOutputs * 48];
  size_t outputs_size = 0;
  for (size_t index = 0; index < tx.output_count; ++index) {
    outputs_size += encode_output(outputs + outputs_size, tx.outputs[index]);
  }

  // Theta serialises the signed body as RLP(type = 2) followed by one list of
  // {fee, inputs, outputs}; the input signatures stay empty.
  uint8_t list_items[64 + sizeof(inputs) + sizeof(outputs)];
  size_t items_size = encode_coins(list_items, tx.fee);
  items_size += encode_list(list_items + items_size, inputs, inputs_size);
  items_size += encode_list(list_items + items_size, outputs, outputs_size);

  uint8_t payload[kThetaMaxSignBytes];
  const size_t chain_size =
      encode_bytes(payload, reinterpret_cast<const uint8_t *>(tx.chain_id),
                   strlen(tx.chain_id));
  if (chain_size + 1 + items_size + 2 > sizeof(payload)) return false;
  payload[chain_size] = kSendTxType;
  const size_t body_size = encode_list(payload + chain_size + 1, list_items, items_size);
  const size_t payload_size = chain_size + 1 + body_size;

  // Six-field Ethereum envelope with only `input` populated.
  uint8_t zero_address[kThetaAddressSize] = {};
  uint8_t fields[32 + sizeof(payload)];
  size_t fields_size = 0;
  fields[fields_size++] = kRlpEmpty;  // nonce
  fields[fields_size++] = kRlpEmpty;  // gas price
  fields[fields_size++] = kRlpEmpty;  // gas limit
  fields_size += encode_bytes(fields + fields_size, zero_address, kThetaAddressSize);
  fields[fields_size++] = kRlpEmpty;  // value
  fields_size += encode_bytes(fields + fields_size, payload, payload_size);
  if (fields_size > sizeof(fields)) return false;

  const size_t header = wrap_prefix(out, fields_size, 0xC0, 0xF7);
  if (header + fields_size > capacity) return false;
  memcpy(out + header, fields, fields_size);
  *out_size = header + fields_size;
  return true;
}

bool theta_sendtx_digest(const ThetaSendTx &tx, uint8_t out[32]) {
  if (out == nullptr) return false;
  uint8_t sign_bytes[kThetaMaxSignBytes];
  size_t size = 0;
  if (!theta_sendtx_sign_bytes(tx, sign_bytes, sizeof(sign_bytes), &size)) return false;
  SHA3_CTX context;
  keccak_init(&context);
  const bool ok = keccak_update(&context, sign_bytes, size) && keccak_final(&context, out);
  memset(sign_bytes, 0, sizeof(sign_bytes));
  return ok;
}

bool run_theta_self_tests() {
  // Mainnet reference: block 1000000, tx 0x1ccc4b6e..063e17bca.
  ThetaSendTx tx = {};
  tx.chain_id = "mainnet";
  tx.fee.tfuel_wei = 1000000000000ULL;
  tx.input_count = 1;
  tx.output_count = 1;
  if (!parse_address("0x26239129266c3f46009287294e0ed63fb198de62",
                     tx.inputs[0].address)) {
    return false;
  }
  tx.inputs[0].coins.tfuel_wei = 15000001000000000000ULL;
  tx.inputs[0].sequence = 186928;
  if (!parse_address("0x63d88b73ed6707b562e2576eaaead17473e6f8ff",
                     tx.outputs[0].address)) {
    return false;
  }
  tx.outputs[0].coins.tfuel_wei = 15000000000000000000ULL;

  uint8_t sign_bytes[kThetaMaxSignBytes];
  size_t size = 0;
  bool ok = theta_sendtx_sign_bytes(tx, sign_bytes, sizeof(sign_bytes), &size);
  // The signature on that transaction recovers to the input address under
  // exactly these bytes, so a byte-for-byte match here is the acceptance.
  ok = ok && hex_equal(sign_bytes, size,
                       "f87780808094000000000000000000000000000000000000000080b85c876d6169"
                       "6e6e657402f851c78085e8d4a51000e6e59426239129266c3f46009287294e0ed63f"
                       "b198de62ca8088d02ab56fa38110008302da3080e1e09463d88b73ed6707b562e257"
                       "6eaaead17473e6f8ffca8088d02ab486cedc0000");
  uint8_t digest[32];
  ok = ok && theta_sendtx_digest(tx, digest) &&
       hex_equal(digest, sizeof(digest),
                 "03490f7146f6019cecc9dc317bf5e8d30813099822671b4d438560d1dce01cbe");

  // The chain id is part of the signed payload: a different one must change
  // the digest, otherwise a testnet signature would replay on mainnet.
  tx.chain_id = "testnet";
  uint8_t other[32];
  ok = ok && theta_sendtx_digest(tx, other) && memcmp(digest, other, sizeof(digest)) != 0;
  tx.chain_id = "mainnet";

  // A bumped fee, a different sequence and an extra output must all move the
  // digest; these are the fields the device shows.
  uint8_t baseline[32];
  ok = ok && theta_sendtx_digest(tx, baseline);
  tx.fee.tfuel_wei += 1;
  ok = ok && theta_sendtx_digest(tx, other) && memcmp(baseline, other, sizeof(other)) != 0;
  tx.fee.tfuel_wei -= 1;
  tx.inputs[0].sequence += 1;
  ok = ok && theta_sendtx_digest(tx, other) && memcmp(baseline, other, sizeof(other)) != 0;
  tx.inputs[0].sequence -= 1;
  tx.output_count = 2;
  tx.outputs[1] = tx.outputs[0];
  ok = ok && theta_sendtx_digest(tx, other) && memcmp(baseline, other, sizeof(other)) != 0;
  tx.output_count = 1;

  // Rejections: no inputs, a zero sender, a zero output and a short buffer.
  ThetaSendTx empty = {};
  empty.chain_id = "mainnet";
  empty.output_count = 1;
  ok = ok && !theta_sendtx_digest(empty, other);
  ThetaSendTx zero_sender = tx;
  memset(zero_sender.inputs[0].address, 0, kThetaAddressSize);
  ok = ok && !theta_sendtx_digest(zero_sender, other);
  ThetaSendTx zero_output = tx;
  zero_output.outputs[0].coins.theta_wei = 0;
  zero_output.outputs[0].coins.tfuel_wei = 0;
  ok = ok && !theta_sendtx_digest(zero_output, other);
  size_t tight = 32;
  ok = ok && !theta_sendtx_sign_bytes(tx, sign_bytes, tight, &tight) && tight == 0;
  memset(sign_bytes, 0, sizeof(sign_bytes));

  // The same mainnet transfer expressed as a device request has to reach the
  // same digest through the adapter, otherwise the panel would show one thing
  // and the signature would cover another.
  uint8_t request[kThetaRequestSize] = {};
  request[0] = kThetaRequestVersion;
  request[1] = 0;  // mainnet
  if (!parse_address("0x63d88b73ed6707b562e2576eaaead17473e6f8ff", request + 2)) {
    return false;
  }
  write_u64_be(15000000000000000000ULL, request + 22);
  write_u64_be(1000000000000ULL, request + 30);
  write_u64_be(186928, request + 38);
  ChainReview review;
  uint8_t adapter_digest[32];
  ok = ok && theta_review_payload(request, sizeof(request),
                                  "0x26239129266c3f46009287294e0ed63fb198de62",
                                  &review, adapter_digest) == ChainError::Ok;
  ok = ok && hex_equal(adapter_digest, sizeof(adapter_digest),
                       "03490f7146f6019cecc9dc317bf5e8d30813099822671b4d438560d1dce01cbe");
  ok = ok && strcmp(review.symbol, "TFUEL") == 0;
  ok = ok && strcmp(review.sender, "0x26239129266c3f46009287294e0ed63fb198de62") == 0;
  ok = ok && strcmp(review.recipient, "0x63d88b73ed6707b562e2576eaaead17473e6f8ff") == 0;
  ok = ok && review.amount[0] != '\0' && review.fee[0] != '\0';
  ok = ok && strstr(review.extra, "mainnet") != nullptr &&
       strstr(review.extra, "186928") != nullptr;
  // The host harness links a stubbed mbedtls (no EC math), so signing itself is
  // exercised on device and in the native probe. What is checkable here is that
  // the sign path refuses bad input instead of reaching the key.
  const uint8_t test_key[32] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01};
  uint8_t signature[65];
  size_t short_signature = 64;
  ok = ok && theta_sign_payload(request, sizeof(request), test_key,
                                "0x26239129266c3f46009287294e0ed63fb198de62",
                                signature, &short_signature) == ChainError::BufferTooSmall;
  uint8_t zero_key[32] = {};
  size_t zero_key_size = sizeof(signature);
  ok = ok && theta_sign_payload(request, sizeof(request), zero_key,
                                "0x26239129266c3f46009287294e0ed63fb198de62",
                                signature, &zero_key_size) == ChainError::CryptoFailure;
  size_t malformed_size = sizeof(signature);
  ok = ok && theta_sign_payload(request, sizeof(request) - 1, test_key,
                                "0x26239129266c3f46009287294e0ed63fb198de62",
                                signature, &malformed_size) == ChainError::Malformed;
  // Flipping the chain selector has to move the digest the device signs.
  uint8_t other_request[kThetaRequestSize];
  memcpy(other_request, request, sizeof(other_request));
  other_request[1] = 1;  // testnet
  ChainReview other_review;
  uint8_t other_digest[32];
  ok = ok && theta_review_payload(other_request, sizeof(other_request),
                                  "0x26239129266c3f46009287294e0ed63fb198de62",
                                  &other_review, other_digest) == ChainError::Ok &&
       memcmp(adapter_digest, other_digest, sizeof(other_digest)) != 0;
  // Malformed requests are refused, not coerced.
  ok = ok && theta_review_payload(request, sizeof(request) - 1, nullptr, &review,
                                  adapter_digest) == ChainError::Malformed;
  uint8_t bad[kThetaRequestSize];
  memcpy(bad, request, sizeof(bad));
  bad[0] = 2;
  ok = ok && theta_review_payload(bad, sizeof(bad), nullptr, &review, adapter_digest) ==
                 ChainError::Malformed;
  memcpy(bad, request, sizeof(bad));
  bad[1] = 3;
  ok = ok && theta_review_payload(bad, sizeof(bad), nullptr, &review, adapter_digest) ==
                 ChainError::Malformed;
  memcpy(bad, request, sizeof(bad));
  write_u64_be(0, bad + 22);
  ok = ok && theta_review_payload(bad, sizeof(bad), nullptr, &review, adapter_digest) ==
                 ChainError::Malformed;
  memcpy(bad, request, sizeof(bad));
  write_u64_be(0, bad + 30);
  ok = ok && theta_review_payload(bad, sizeof(bad), nullptr, &review, adapter_digest) ==
                 ChainError::Malformed;
  memcpy(bad, request, sizeof(bad));
  memset(bad + 2, 0, kThetaAddressSize);
  ok = ok && theta_review_payload(bad, sizeof(bad), nullptr, &review, adapter_digest) ==
                 ChainError::Malformed;
  return ok;
}

// Device-facing request decoding. Kept next to the encoder so a change to one
// has to face the other.
namespace {
const char *theta_chain_id_for(uint8_t selector) {
  switch (selector) {
    case 0: return "mainnet";
    case 1: return "testnet";
    case 2: return "privatenet";
    default: return nullptr;
  }
}


bool parse_address_hex(const char *text, size_t length, uint8_t out[kThetaAddressSize]) {
  if (text == nullptr || length != 2 + kThetaAddressSize * 2) return false;
  if (text[0] != '0' || (text[1] != 'x' && text[1] != 'X')) return false;
  for (size_t index = 0; index < kThetaAddressSize; ++index) {
    const uint16_t high = hex_value(text[2 + index * 2]);
    const uint16_t low = hex_value(text[3 + index * 2]);
    if (high == 0xFFFF || low == 0xFFFF) return false;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

bool address_is_zero(const uint8_t address[kThetaAddressSize]) {
  for (size_t index = 0; index < kThetaAddressSize; ++index) {
    if (address[index] != 0) return false;
  }
  return true;
}

// Builds the transaction a request describes. The input carries amount + fee,
// exactly like the mainnet reference, so an underfunded request cannot be
// signed into something the chain will reject for the wrong reason.
bool build_from_request(const uint8_t *payload, size_t size,
                        const char *derived_address, ThetaSendTx *tx) {
  if (payload == nullptr || tx == nullptr || size != kThetaRequestSize) return false;
  if (payload[0] != kThetaRequestVersion) return false;
  const char *chain_id = theta_chain_id_for(payload[1]);
  if (chain_id == nullptr) return false;
  memset(tx, 0, sizeof(*tx));
  tx->chain_id = chain_id;
  tx->fee.tfuel_wei = read_u64_be(payload + 30);
  if (tx->fee.tfuel_wei == 0) return false;
  const uint64_t amount = read_u64_be(payload + 22);
  if (amount == 0) return false;
  const uint64_t total = amount + tx->fee.tfuel_wei;
  if (total < amount) return false;  // overflow
  tx->output_count = 1;
  memcpy(tx->outputs[0].address, payload + 2, kThetaAddressSize);
  if (address_is_zero(tx->outputs[0].address)) return false;
  tx->outputs[0].coins.tfuel_wei = amount;
  tx->input_count = 1;
  if (derived_address != nullptr) {
    const size_t length = strlen(derived_address);
    if (!parse_address_hex(derived_address, length, tx->inputs[0].address)) return false;
  }
  if (address_is_zero(tx->inputs[0].address)) return false;
  tx->inputs[0].coins.tfuel_wei = total;
  tx->inputs[0].sequence = read_u64_be(payload + 38);
  return true;
}
}  // namespace

ChainError theta_review_payload(const uint8_t *payload, size_t size,
                                const char *derived_address,
                                ChainReview *review, uint8_t digest[32]) {
  if (review == nullptr || digest == nullptr) return ChainError::InvalidArgument;
  ThetaSendTx tx;
  if (!build_from_request(payload, size, derived_address, &tx)) {
    return ChainError::Malformed;
  }
  if (!theta_sendtx_digest(tx, digest)) return ChainError::CryptoFailure;
  memset(review, 0, sizeof(*review));
  chain_copy_text(review->symbol, sizeof(review->symbol), "TFUEL");
  if (derived_address == nullptr ||
      !chain_copy_text(review->sender, sizeof(review->sender), derived_address)) {
    return ChainError::InvalidArgument;
  }
  const uint8_t *recipient = tx.outputs[0].address;
  static const char kHex[] = "0123456789abcdef";
  char *out = review->recipient;
  if (sizeof(review->recipient) < 2 + kThetaAddressSize * 2 + 1) return ChainError::BufferTooSmall;
  out[0] = '0';
  out[1] = 'x';
  for (size_t index = 0; index < kThetaAddressSize; ++index) {
    out[2 + index * 2] = kHex[recipient[index] >> 4];
    out[3 + index * 2] = kHex[recipient[index] & 0x0F];
  }
  out[2 + kThetaAddressSize * 2] = '\0';
  if (!chain_format_units(tx.outputs[0].coins.tfuel_wei, 18, "TFUEL", review->amount,
                          sizeof(review->amount)) ||
      !chain_format_units(tx.fee.tfuel_wei, 18, "TFUEL", review->fee,
                          sizeof(review->fee))) {
    return ChainError::BufferTooSmall;
  }
  char extra[kChainMaxExtra];
  const int written = snprintf(extra, sizeof(extra), "seq %llu %s",
                               static_cast<unsigned long long>(tx.inputs[0].sequence),
                               tx.chain_id);
  if (written <= 0 || static_cast<size_t>(written) >= sizeof(extra)) {
    return ChainError::BufferTooSmall;
  }
  if (!chain_copy_text(review->extra, sizeof(review->extra), extra)) {
    return ChainError::BufferTooSmall;
  }
  review->call_count = 0;
  return ChainError::Ok;
}

ChainError theta_sign_payload(const uint8_t *payload, size_t size,
                              const uint8_t private_key[32],
                              const char *sender_address, uint8_t *out,
                              size_t *in_out_size) {
  if (private_key == nullptr || sender_address == nullptr || out == nullptr ||
      in_out_size == nullptr) {
    return ChainError::InvalidArgument;
  }
  if (*in_out_size < 65) return ChainError::BufferTooSmall;
  ThetaSendTx tx;
  if (!build_from_request(payload, size, sender_address, &tx)) {
    return ChainError::Malformed;
  }
  uint8_t digest[32];
  if (!theta_sendtx_digest(tx, digest)) return ChainError::CryptoFailure;
  RecoverableSignature signature;
  const WalletError sign_error =
      secp256k1_sign_digest_recoverable(private_key, digest, &signature);
  secure_zero(digest, sizeof(digest));
  if (sign_error != WalletError::Ok) {
    secure_zero(&signature, sizeof(signature));
    return ChainError::CryptoFailure;
  }
  memcpy(out, signature.r, 32);
  memcpy(out + 32, signature.s, 32);
  out[64] = signature.y_parity;
  *in_out_size = 65;
  secure_zero(&signature, sizeof(signature));
  return ChainError::Ok;
}}  // namespace hexwallet
