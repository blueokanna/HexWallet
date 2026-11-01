#include "QrlV2Transaction.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoPrimitives.h"
#include "RandomSource.h"
#include "WalletEngine.h"
#include "WalletNetworks.h"

namespace hexwallet {
namespace {

constexpr uint8_t kQrlV2Descriptor[3] = {0x01, 0x00, 0x00};
constexpr uint8_t kQrlV2SigningContext[8] = {'Z', 'O', 'N', 'D',
                                             0x01, 0x01, 0x00, 0x00};
constexpr size_t kQrlV2FieldCount = 11;
constexpr size_t kQrlV2MessageSize =
    2 + sizeof(kQrlV2SigningContext) + kKeccak256Size;

struct RlpField {
  const uint8_t *data;
  size_t size;
  bool list;
};

// Strict RLP reader: canonical integer/byte-string forms only, no trailing
// bytes inside a list and no length that does not fit in the remaining input.
bool rlp_next(const uint8_t **cursor, const uint8_t *end, RlpField *field) {
  if (cursor == nullptr || *cursor == nullptr || end == nullptr ||
      field == nullptr || *cursor >= end) {
    return false;
  }
  const uint8_t *start = *cursor;
  const uint8_t *p = start;
  const uint8_t prefix = *p++;
  if (prefix <= 0x7f) {
    field->data = start;
    field->size = 1;
    field->list = false;
    *cursor = p;
    return true;
  }
  const bool list = prefix >= 0xc0;
  size_t length = 0;
  if (!list && prefix <= 0xb7) {
    length = prefix - 0x80;
  } else if (list && prefix <= 0xf7) {
    length = prefix - 0xc0;
  } else {
    const size_t length_bytes = list ? prefix - 0xf7 : prefix - 0xb7;
    if ((size_t)(end - p) < length_bytes || length_bytes > sizeof(size_t) ||
        p[0] == 0) {
      return false;
    }
    for (size_t index = 0; index < length_bytes; ++index) {
      if (length > (SIZE_MAX >> 8)) return false;
      length = (length << 8) | *p++;
    }
    if (length <= 55) return false;
  }
  if (length > static_cast<size_t>(end - p)) return false;
  if (!list && length == 1 && p[0] < 0x80) return false;
  field->data = p;
  field->size = length;
  field->list = list;
  *cursor = p + length;
  return true;
}

bool rlp_uint(const RlpField &field, size_t max_bytes, const uint8_t **data,
              size_t *size) {
  if (field.list || field.size > max_bytes) return false;
  if (field.size != 0 && field.data[0] == 0) return false;
  *data = field.data;
  *size = field.size;
  return true;
}

bool rlp_u64(const RlpField &field, size_t max_bytes, uint64_t *out) {
  const uint8_t *data = nullptr;
  size_t size = 0;
  if (!rlp_uint(field, max_bytes, &data, &size)) return false;
  uint64_t value = 0;
  for (size_t index = 0; index < size; ++index) {
    value = (value << 8) | data[index];
  }
  *out = value;
  return true;
}

int compare_uint(const uint8_t *left, size_t left_size, const uint8_t *right,
                 size_t right_size) {
  if (left_size != right_size) return left_size < right_size ? -1 : 1;
  const int order = left_size == 0 ? 0 : memcmp(left, right, left_size);
  return order < 0 ? -1 : (order > 0 ? 1 : 0);
}

void build_message(const uint8_t digest[kKeccak256Size], uint8_t *out) {
  out[0] = 0x00;
  out[1] = static_cast<uint8_t>(sizeof(kQrlV2SigningContext));
  memcpy(out + 2, kQrlV2SigningContext, sizeof(kQrlV2SigningContext));
  memcpy(out + 2 + sizeof(kQrlV2SigningContext), digest, kKeccak256Size);
}

bool format_checksummed(const uint8_t address[kQrlV2AddressSize], char *out,
                        size_t out_size) {
  if (address == nullptr || out == nullptr ||
      out_size < kQrlV2AddressTextSize) {
    return false;
  }
  static const char kHex[] = "0123456789abcdef";
  char *body = out + 1;
  for (size_t index = 0; index < kQrlV2AddressSize; ++index) {
    body[2 * index] = kHex[address[index] >> 4];
    body[2 * index + 1] = kHex[address[index] & 0x0f];
  }
  body[2 * kQrlV2AddressSize] = '\0';
  uint8_t mask[kQrlV2AddressSize] = {};
  if (crypto_shake256(reinterpret_cast<const uint8_t *>(body),
                      2 * kQrlV2AddressSize, mask, sizeof(mask))) {
    for (size_t index = 0; index < 2 * kQrlV2AddressSize; ++index) {
      const uint8_t nibble = index % 2 == 0 ? mask[index / 2] >> 4
                                            : mask[index / 2] & 0x0f;
      if (body[index] >= 'a' && body[index] <= 'f' && nibble >= 8) {
        body[index] = static_cast<char>(body[index] - 'a' + 'A');
      }
    }
  }
  out[0] = 'Q';
  return true;
}

int hex_value(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

void load_be_limbs(const uint8_t value[32], uint32_t limbs[8]) {
  for (size_t index = 0; index < 8; ++index) {
    const uint8_t *part = value + (7 - index) * 4;
    limbs[index] = (static_cast<uint32_t>(part[0]) << 24) |
                   (static_cast<uint32_t>(part[1]) << 16) |
                   (static_cast<uint32_t>(part[2]) << 8) |
                   static_cast<uint32_t>(part[3]);
  }
}

void add_limb(uint32_t *accumulator, size_t position, uint32_t value) {
  size_t index = position;
  uint64_t carry = value;
  while (carry != 0 && index < 12) {
    const uint64_t sum = static_cast<uint64_t>(accumulator[index]) + carry;
    accumulator[index] = static_cast<uint32_t>(sum);
    carry = sum >> 32;
    ++index;
  }
}

// max_fee = gas * fee_cap. Rejects a product that does not fit in 256 bits;
// QRL supply makes that unreachable for a valid fee cap.
bool fee_from_gas(const uint8_t fee_cap[32], uint64_t gas, uint8_t fee[32]) {
  const uint32_t factor_low = static_cast<uint32_t>(gas);
  const uint32_t factor_high = static_cast<uint32_t>(gas >> 32);
  uint32_t limbs[8];
  load_be_limbs(fee_cap, limbs);
  uint32_t accumulator[12] = {};
  for (size_t index = 0; index < 8; ++index) {
    const uint64_t low = static_cast<uint64_t>(limbs[index]) * factor_low;
    add_limb(accumulator, index, static_cast<uint32_t>(low));
    add_limb(accumulator, index + 1, static_cast<uint32_t>(low >> 32));
    const uint64_t high = static_cast<uint64_t>(limbs[index]) * factor_high;
    add_limb(accumulator, index + 1, static_cast<uint32_t>(high));
    add_limb(accumulator, index + 2, static_cast<uint32_t>(high >> 32));
  }
  if (accumulator[8] != 0 || accumulator[9] != 0 || accumulator[10] != 0 ||
      accumulator[11] != 0) {
    return false;
  }
  for (size_t index = 0; index < 8; ++index) {
    const uint32_t value = accumulator[7 - index];
    fee[index * 4] = static_cast<uint8_t>(value >> 24);
    fee[index * 4 + 1] = static_cast<uint8_t>(value >> 16);
    fee[index * 4 + 2] = static_cast<uint8_t>(value >> 8);
    fee[index * 4 + 3] = static_cast<uint8_t>(value);
  }
  return true;
}

struct Request {
  uint32_t chain_id;
  uint64_t nonce;
  uint64_t gas;
  const uint8_t *tip_cap;
  size_t tip_cap_size;
  const uint8_t *fee_cap;
  size_t fee_cap_size;
  const uint8_t *to;
  size_t to_size;
  const uint8_t *value;
  size_t value_size;
  size_t data_size;
  size_t access_list_entries;
};

ChainError parse_preimage(const uint8_t *payload, size_t size,
                          Request *request) {
  if (payload == nullptr || request == nullptr || size < 2 ||
      size > kQrlV2MaxPreimageSize || payload[0] != 0x02) {
    return ChainError::Malformed;
  }
  const uint8_t *cursor = payload + 1;
  const uint8_t *end = payload + size;
  RlpField outer;
  if (!rlp_next(&cursor, end, &outer) || !outer.list || cursor != end) {
    return ChainError::Malformed;
  }
  RlpField fields[kQrlV2FieldCount];
  const uint8_t *inner = outer.data;
  const uint8_t *inner_end = outer.data + outer.size;
  size_t count = 0;
  while (inner < inner_end) {
    if (count == kQrlV2FieldCount || !rlp_next(&inner, inner_end, &fields[count])) {
      return ChainError::Malformed;
    }
    ++count;
  }
  if (count != kQrlV2FieldCount) return ChainError::Malformed;

  const uint8_t *chain_data = nullptr;
  size_t chain_size = 0;
  if (!rlp_uint(fields[0], 4, &chain_data, &chain_size) || chain_size == 0) {
    return ChainError::Malformed;
  }
  uint32_t chain_id = 0;
  for (size_t index = 0; index < chain_size; ++index) {
    chain_id = (chain_id << 8) | chain_data[index];
  }
  if (chain_id != kQrlV2MainnetChainId) return ChainError::WrongNetwork;

  Request parsed = {};
  parsed.chain_id = chain_id;
  if (!rlp_u64(fields[1], 8, &parsed.nonce) ||
      !rlp_u64(fields[4], 8, &parsed.gas)) {
    return ChainError::Malformed;
  }
  if (!rlp_uint(fields[2], 32, &parsed.tip_cap, &parsed.tip_cap_size) ||
      !rlp_uint(fields[3], 32, &parsed.fee_cap, &parsed.fee_cap_size)) {
    return ChainError::Malformed;
  }
  if (fields[5].list || (fields[5].size != 0 &&
                         fields[5].size != kQrlV2AddressSize)) {
    return ChainError::Malformed;
  }
  parsed.to = fields[5].data;
  parsed.to_size = fields[5].size;
  if (!rlp_uint(fields[6], 32, &parsed.value, &parsed.value_size)) {
    return ChainError::Malformed;
  }
  if (fields[7].list) return ChainError::Malformed;
  parsed.data_size = fields[7].size;
  if (!fields[8].list) return ChainError::Malformed;
  const uint8_t *entry = fields[8].data;
  const uint8_t *entry_end = fields[8].data + fields[8].size;
  while (entry < entry_end) {
    // Each entry must be a well-formed RLP list. The inner key layout is left
    // opaque on purpose: the envelope hashes these bytes, and inventing a
    // shape the protocol has not fixed would reject valid access lists.
    RlpField access;
    if (!rlp_next(&entry, entry_end, &access) || !access.list) {
      return ChainError::Malformed;
    }
    const uint8_t *part = access.data;
    const uint8_t *part_end = access.data + access.size;
    while (part < part_end) {
      RlpField item;
      if (!rlp_next(&part, part_end, &item)) return ChainError::Malformed;
    }
    ++parsed.access_list_entries;
  }
  if (fields[9].list || fields[9].size != sizeof(kQrlV2Descriptor) ||
      memcmp(fields[9].data, kQrlV2Descriptor, sizeof(kQrlV2Descriptor)) != 0) {
    return ChainError::Malformed;
  }
  if (fields[10].list || fields[10].size != 0) return ChainError::Malformed;

  if (parsed.gas == 0 || parsed.fee_cap_size == 0) {
    return ChainError::FeePolicy;
  }
  if (compare_uint(parsed.tip_cap, parsed.tip_cap_size, parsed.fee_cap,
                   parsed.fee_cap_size) > 0) {
    return ChainError::FeePolicy;
  }
  *request = parsed;
  return ChainError::Ok;
}

struct HeapBlock {
  explicit HeapBlock(size_t bytes)
      : data(static_cast<uint8_t *>(malloc(bytes))), size(bytes) {
    if (data != nullptr) memset(data, 0, size);
  }
  ~HeapBlock() {
    if (data != nullptr) {
      secure_zero(data, size);
      free(data);
    }
  }
  HeapBlock(const HeapBlock &) = delete;
  HeapBlock &operator=(const HeapBlock &) = delete;
  bool ok() const { return data != nullptr; }
  uint8_t *data;
  size_t size;
};

bool address_for_seed(const uint8_t seed[kMlDsa87SeedSize], HeapBlock &public_key,
                      HeapBlock &secret_key, char *out, size_t out_size) {
  return ml_dsa_87_keypair_from_seed(seed, public_key.data, secret_key.data) &&
         qrl_v2_address_from_public_key(public_key.data, out, out_size);
}

}  // namespace

WalletError qrl_v2_address_from_seed(const uint8_t seed[kMlDsa87SeedSize],
                                     char *out, size_t out_size) {
  if (seed == nullptr || out == nullptr || out_size < kQrlV2AddressTextSize) {
    return WalletError::InvalidArgument;
  }
  HeapBlock public_key(kQrlV2PublicKeySize);
  HeapBlock secret_key(kMlDsa87SecretKeySize);
  if (!public_key.ok() || !secret_key.ok()) return WalletError::CryptoFailure;
  if (!address_for_seed(seed, public_key, secret_key, out, out_size)) {
    return WalletError::CryptoFailure;
  }
  return WalletError::Ok;
}

bool qrl_v2_address_from_public_key(
    const uint8_t public_key[kQrlV2PublicKeySize], char *out, size_t out_size) {
  if (public_key == nullptr || out == nullptr ||
      out_size < kQrlV2AddressTextSize) {
    return false;
  }
  // The descriptor and key are hashed as one buffer; keep it on the heap so a
  // firmware task with a small stack can still derive an address.
  HeapBlock material(sizeof(kQrlV2Descriptor) + kQrlV2PublicKeySize);
  if (!material.ok()) return false;
  memcpy(material.data, kQrlV2Descriptor, sizeof(kQrlV2Descriptor));
  memcpy(material.data + sizeof(kQrlV2Descriptor), public_key,
         kQrlV2PublicKeySize);
  uint8_t address[kQrlV2AddressSize] = {};
  const bool hashed = crypto_shake256(material.data, material.size, address,
                                      sizeof(address));
  if (!hashed) return false;
  const bool formatted = format_checksummed(address, out, out_size);
  secure_zero(address, sizeof(address));
  return formatted;
}

bool qrl_v2_address_decode(const char *text, uint8_t out[kQrlV2AddressSize]) {
  if (text == nullptr || out == nullptr ||
      strlen(text) != kQrlV2AddressTextSize - 1 || text[0] != 'Q') {
    return false;
  }
  uint8_t address[kQrlV2AddressSize];
  for (size_t index = 0; index < kQrlV2AddressSize; ++index) {
    const int high = hex_value(text[1 + 2 * index]);
    const int low = hex_value(text[2 + 2 * index]);
    if (high < 0 || low < 0) return false;
    address[index] = static_cast<uint8_t>((high << 4) | low);
  }
  char expected[kQrlV2AddressTextSize];
  if (!format_checksummed(address, expected, sizeof(expected)) ||
      !chain_constant_time_equal(reinterpret_cast<const uint8_t *>(expected),
                                 reinterpret_cast<const uint8_t *>(text),
                                 kQrlV2AddressTextSize - 1)) {
    secure_zero(address, sizeof(address));
    return false;
  }
  memcpy(out, address, sizeof(address));
  secure_zero(address, sizeof(address));
  return true;
}

ChainError qrl_v2_review_payload(const uint8_t *payload, size_t size,
                                 const char *sender, ChainReview *review,
                                 uint8_t digest[32]) {
  if (sender == nullptr || review == nullptr || digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  uint8_t sender_account[kQrlV2AddressSize];
  if (!qrl_v2_address_decode(sender, sender_account)) {
    return ChainError::WrongWallet;
  }
  secure_zero(sender_account, sizeof(sender_account));
  Request request = {};
  const ChainError parsed = parse_preimage(payload, size, &request);
  if (parsed != ChainError::Ok) return parsed;
  if (!crypto_keccak256(payload, size, digest)) return ChainError::CryptoFailure;

  uint8_t fee_cap[32] = {};
  memcpy(fee_cap + (sizeof(fee_cap) - request.fee_cap_size), request.fee_cap,
         request.fee_cap_size);
  uint8_t fee[32] = {};
  if (!fee_from_gas(fee_cap, request.gas, fee)) {
    secure_zero(fee_cap, sizeof(fee_cap));
    return ChainError::FeePolicy;
  }
  secure_zero(fee_cap, sizeof(fee_cap));
  memset(review, 0, sizeof(*review));
  if (!chain_copy_text(review->symbol, sizeof(review->symbol), "QRL") ||
      !chain_copy_text(review->sender, sizeof(review->sender), sender)) {
    return ChainError::BufferTooSmall;
  }
  if (request.to_size == 0) {
    if (!chain_copy_text(review->recipient, sizeof(review->recipient),
                         "CONTRACT CREATE")) {
      return ChainError::BufferTooSmall;
    }
  } else {
    char body[kQrlV2AddressTextSize];
    if (!format_checksummed(request.to, body, sizeof(body)) ||
        !chain_copy_text(review->recipient, sizeof(review->recipient), body)) {
      return ChainError::BufferTooSmall;
    }
  }
  uint8_t value[32] = {};
  memcpy(value + (sizeof(value) - request.value_size), request.value,
         request.value_size);
  if (!chain_format_units256(value, kQrlV2Decimals, "QRL", review->amount,
                       sizeof(review->amount)) ||
      !chain_format_units256(fee, kQrlV2Decimals, "QRL MAX", review->fee,
                       sizeof(review->fee))) {
    return ChainError::BufferTooSmall;
  }
  char tip[64] = "0";
  if (request.tip_cap_size != 0) {
    uint8_t tip_value[32] = {};
    memcpy(tip_value + (sizeof(tip_value) - request.tip_cap_size),
           request.tip_cap, request.tip_cap_size);
    if (!chain_format_units256(tip_value, kQrlV2Decimals, "QRL", tip, sizeof(tip))) {
      return ChainError::BufferTooSmall;
    }
  }
  char digest_text[kKeccak256Size * 2 + 1];
  chain_hex(digest, kKeccak256Size, digest_text, sizeof(digest_text));
  const int written = snprintf(
      review->extra, sizeof(review->extra),
      "CHAIN %u\nNONCE %llu\nGAS %llu\nTIP %s\nACCESS %u DATA %u B\nDIGEST %s",
      static_cast<unsigned>(request.chain_id),
      static_cast<unsigned long long>(request.nonce),
      static_cast<unsigned long long>(request.gas),
      tip,
      static_cast<unsigned>(request.access_list_entries),
      static_cast<unsigned>(request.data_size), digest_text);
  if (written < 0 || static_cast<size_t>(written) >= sizeof(review->extra)) {
    return ChainError::BufferTooSmall;
  }
  return ChainError::Ok;
}

namespace {

// Signs with the account seed that was already derived for the reviewed path.
// Keeping this separate from qrl_v2_sign_payload lets the host self-test cover
// review, signing and self-verification even when the host build has no BIP32
// body of its own.
ChainError sign_with_seed(const uint8_t seed[kMlDsa87SeedSize],
                          const uint8_t *payload, size_t size,
                          const char *sender, uint8_t *out,
                          size_t *in_out_size) {
  if (in_out_size == nullptr) return ChainError::InvalidArgument;
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  if (seed == nullptr || payload == nullptr || sender == nullptr ||
      out == nullptr) {
    return ChainError::InvalidArgument;
  }
  if (capacity < kQrlV2SignedSize) return ChainError::BufferTooSmall;
  ChainReview review;
  uint8_t digest[kKeccak256Size];
  const ChainError reviewed =
      qrl_v2_review_payload(payload, size, sender, &review, digest);
  if (reviewed != ChainError::Ok) return reviewed;

  HeapBlock public_key(kQrlV2PublicKeySize);
  HeapBlock secret_key(kMlDsa87SecretKeySize);
  HeapBlock signature(kQrlV2SignatureSize);
  bool ok = public_key.ok() && secret_key.ok() && signature.ok();
  char derived_text[kQrlV2AddressTextSize];
  ok = ok && address_for_seed(seed, public_key, secret_key, derived_text,
                              sizeof(derived_text));
  uint8_t derived_account[kQrlV2AddressSize];
  uint8_t sender_account[kQrlV2AddressSize];
  bool matches = false;
  if (ok && qrl_v2_address_decode(derived_text, derived_account) &&
      qrl_v2_address_decode(sender, sender_account)) {
    matches = chain_constant_time_equal(derived_account, sender_account,
                                        sizeof(derived_account));
  }
  secure_zero(derived_account, sizeof(derived_account));
  secure_zero(sender_account, sizeof(sender_account));
  if (!ok) return ChainError::CryptoFailure;
  if (!matches) return ChainError::WrongWallet;

  uint8_t message[kQrlV2MessageSize];
  uint8_t rnd[32];
  build_message(digest, message);
  random_fill(rnd, sizeof(rnd));
  // random_fill zeroes on a health failure; deterministic ML-DSA would still
  // verify, so refuse explicitly instead of masking a dead entropy source.
  if (!random_healthy()) {
    secure_zero(rnd, sizeof(rnd));
    secure_zero(message, sizeof(message));
    return ChainError::CryptoFailure;
  }
  ok = ml_dsa_87_sign(secret_key.data, message, sizeof(message), rnd,
                      signature.data) &&
       ml_dsa_87_verify(public_key.data, message, sizeof(message),
                        signature.data);
  secure_zero(rnd, sizeof(rnd));
  secure_zero(message, sizeof(message));
  if (!ok) return ChainError::CryptoFailure;
  memcpy(out, signature.data, kQrlV2SignatureSize);
  memcpy(out + kQrlV2SignatureSize, public_key.data, kQrlV2PublicKeySize);
  *in_out_size = kQrlV2SignedSize;
  return ChainError::Ok;
}

}  // namespace

ChainError qrl_v2_sign_payload(const uint8_t *payload, size_t size,
                               const char *sender, const HdPrivateNode &master,
                               uint32_t address_index, uint8_t *out,
                               size_t *in_out_size) {
  if (in_out_size == nullptr) return ChainError::InvalidArgument;
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  if (payload == nullptr || sender == nullptr || out == nullptr) {
    return ChainError::InvalidArgument;
  }
  if (capacity < kQrlV2SignedSize) return ChainError::BufferTooSmall;
  if (address_index >= kHardenedOffset) return ChainError::InvalidArgument;
  char path[48];
  const int written = snprintf(path, sizeof(path), "m/44'/238'/0'/0/%lu",
                               static_cast<unsigned long>(address_index));
  if (written < 0 || static_cast<size_t>(written) >= sizeof(path)) {
    return ChainError::InvalidArgument;
  }
  HdPrivateNode child;
  if (hd_private_derive_path(&master, path, &child) != WalletError::Ok) {
    secure_zero(&child, sizeof(child));
    return ChainError::CryptoFailure;
  }
  *in_out_size = capacity;
  const ChainError result =
      sign_with_seed(child.private_key, payload, size, sender, out, in_out_size);
  secure_zero(&child, sizeof(child));
  return result;
}

bool run_qrl_v2_self_tests() {
  // Checksum vectors generated with an independent Python SHAKE-256
  // implementation: 64 x 0xAB and the byte counter 0..63.
  static const char kAllAb[] =
      "QabaBABabaBAbAbAbABaBABaBabaBabaBAbabaBABABAbAbabababAbaBaBABABabABaBaBABABaBabaBA"
      "BaBabABAbABabaBAbABAbABAbaBabABababAbaBaBabaBAB";
  static const char kCounter[] =
      "Q000102030405060708090a0B0C0D0e0f101112131415161718191A1B1C1D1e1F202122232425262728"
      "292a2B2c2d2E2f303132333435363738393A3B3C3d3e3f";
  uint8_t address[kQrlV2AddressSize];
  memset(address, 0xab, sizeof(address));
  char text[kQrlV2AddressTextSize];
  bool ok = format_checksummed(address, text, sizeof(text)) &&
            strcmp(text, kAllAb) == 0;
  for (size_t index = 0; index < sizeof(address); ++index) {
    address[index] = static_cast<uint8_t>(index);
  }
  ok = ok && format_checksummed(address, text, sizeof(text)) &&
       strcmp(text, kCounter) == 0;
  ok = ok && qrl_v2_address_decode(kCounter, address);
  char corrupted[kQrlV2AddressTextSize];
  memcpy(corrupted, kCounter, sizeof(corrupted));
  corrupted[10] = corrupted[10] == 'A' ? 'a' : 'A';
  ok = ok && !qrl_v2_address_decode(corrupted, address);

#if !defined(HEXWALLET_HOST_TEST)
  return ok;
#else
  uint8_t account_seed[kMlDsa87SeedSize];
  for (size_t index = 0; index < sizeof(account_seed); ++index) {
    account_seed[index] = static_cast<uint8_t>(index);
  }
  char sender[kQrlV2AddressTextSize];
  ok = ok && qrl_v2_address_from_seed(account_seed, sender, sizeof(sender)) ==
                 WalletError::Ok &&
       qrl_v2_address_decode(sender, address);

  uint8_t to[kQrlV2AddressSize];
  for (size_t index = 0; index < sizeof(to); ++index) {
    to[index] = static_cast<uint8_t>(0x40 + index);
  }
  uint8_t preimage[kQrlV2MaxPreimageSize];
  size_t preimage_size = 0;
  const uint8_t empty_access_list[1] = {0xc0};
  auto build = [&](uint8_t chain_id, const uint8_t descriptor[3],
                   bool reversed_fee, const uint8_t *extra, size_t extra_size,
                   const uint8_t *access, size_t access_size, uint8_t *out,
                   size_t capacity, size_t *out_size) {
    uint8_t fields[512];
    RlpWriter writer(fields, sizeof(fields));
    const uint8_t chain[1] = {chain_id};
    const uint8_t nonce[1] = {0x03};
    const uint8_t tip[4] = {0x3b, 0x9a, 0xca, 0x00};
    const uint8_t fee[5] = {0x04, 0xa8, 0x17, 0xc8, 0x00};
    const uint8_t gas[2] = {0x52, 0x08};
    const uint8_t value[8] = {0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00};
    bool built = writer.integer(chain, sizeof(chain)) &&
                 writer.integer(nonce, sizeof(nonce));
    if (reversed_fee) {
      built = built && writer.integer(fee, sizeof(fee)) &&
              writer.integer(tip, sizeof(tip));
    } else {
      built = built && writer.integer(tip, sizeof(tip)) &&
              writer.integer(fee, sizeof(fee));
    }
    built = built && writer.integer(gas, sizeof(gas)) &&
            writer.integer(to, sizeof(to)) &&
            writer.integer(value, sizeof(value)) &&
            writer.bytes(nullptr, 0) && writer.raw(access, access_size) &&
            writer.bytes(descriptor, 3) && writer.bytes(extra, extra_size);
    uint8_t list[512];
    size_t list_size = 0;
    built = built && rlp_wrap_list(fields, writer.size(), list, sizeof(list),
                                   &list_size) &&
            list_size + 1 <= capacity;
    if (built) {
      out[0] = 0x02;
      memcpy(out + 1, list, list_size);
      *out_size = list_size + 1;
    }
    return built;
  };
  const size_t capacity = sizeof(preimage);
  preimage_size = capacity;
  const uint8_t descriptor[3] = {0x01, 0x00, 0x00};
  ok = ok && build(1, descriptor, false, nullptr, 0, empty_access_list,
                   sizeof(empty_access_list), preimage, capacity,
                   &preimage_size);

  ChainReview review;
  uint8_t digest[kKeccak256Size];
  const ChainError review_error =
      qrl_v2_review_payload(preimage, preimage_size, sender, &review, digest);
  if (review_error != ChainError::Ok) {
    fprintf(stderr, "qrlv2 review=%d\n", (int)review_error);
  }
  ok = ok && review_error == ChainError::Ok;
  char expected_recipient[kQrlV2AddressTextSize];
  format_checksummed(to, expected_recipient, sizeof(expected_recipient));
  const bool review_fields =
      strcmp(review.symbol, "QRL") == 0 &&
      strcmp(review.sender, sender) == 0 &&
      strcmp(review.recipient, expected_recipient) == 0 &&
      strcmp(review.amount, "1.0 QRL") == 0 &&
      strcmp(review.fee, "0.00042 QRL MAX") == 0 &&
      strstr(review.extra, "NONCE 3") != nullptr &&
      strstr(review.extra, "GAS 21000") != nullptr &&
      strstr(review.extra, "ACCESS 0 DATA 0 B") != nullptr;
  if (!review_fields) {
    fprintf(stderr,
            "qrlv2 fields symbol=%s sender=%s recipient=%s amount=%s fee=%s "
            "extra=%s expected=%s\n",
            review.symbol, review.sender, review.recipient, review.amount,
            review.fee, review.extra, expected_recipient);
  }
  ok = ok && review_fields;

  auto check = [&](bool value, const char *label) {
    if (!value) fprintf(stderr, "qrlv2 check failed: %s\n", label);
    ok = ok && value;
  };
  uint8_t signed_payload[kQrlV2SignedSize];
  size_t signed_size = sizeof(signed_payload);
  const ChainError sign_error =
      sign_with_seed(account_seed, preimage, preimage_size, sender,
                     signed_payload, &signed_size);
  check(sign_error == ChainError::Ok, "sign");
  check(signed_size == kQrlV2SignedSize, "sign-size");
  uint8_t message[kQrlV2MessageSize];
  build_message(digest, message);
  check(ml_dsa_87_verify(signed_payload + kQrlV2SignatureSize, message,
                         sizeof(message), signed_payload),
        "verify");
  signed_payload[100] ^= 0x01;
  check(!ml_dsa_87_verify(signed_payload + kQrlV2SignatureSize, message,
                          sizeof(message), signed_payload),
        "tamper");
  signed_payload[100] ^= 0x01;

  ChainReview rejected;
  auto rejected_with = [&](uint8_t chain_id, const uint8_t *desc,
                           bool reversed_fee, const uint8_t *extra_data,
                           size_t extra_data_size, ChainError expected) {
    size_t length = capacity;
    const bool built =
        build(chain_id, desc, reversed_fee, extra_data, extra_data_size,
              empty_access_list, sizeof(empty_access_list), preimage, capacity,
              &length);
    const ChainError actual =
        built ? qrl_v2_review_payload(preimage, length, sender, &rejected,
                                      digest)
              : ChainError::Malformed;
    return built && actual == expected;
  };
  check(rejected_with(2, descriptor, false, nullptr, 0,
                      ChainError::WrongNetwork), "wrong-network");
  const uint8_t wrong_descriptor[3] = {0x01, 0x00, 0x01};
  check(rejected_with(1, wrong_descriptor, false, nullptr, 0,
                      ChainError::Malformed), "descriptor");
  const uint8_t extra[1] = {0x01};
  check(rejected_with(1, descriptor, false, extra, sizeof(extra),
                      ChainError::Malformed), "extra");
  check(rejected_with(1, descriptor, true, nullptr, 0, ChainError::FeePolicy),
        "fee-order");

  // A non-empty access list is opaque but must still be a well-formed list and
  // its entry count must reach the screen.
  uint8_t access_payload[256];
  RlpWriter access_writer(access_payload, sizeof(access_payload));
  const uint8_t storage_key[32] = {0x11, 0x22, 0x33, 0x44};
  bool access_built = access_writer.bytes(to, sizeof(to)) &&
                      access_writer.bytes(storage_key, sizeof(storage_key));
  uint8_t access_entry[256];
  size_t access_entry_size = 0;
  access_built = access_built &&
                 rlp_wrap_list(access_payload, access_writer.size(),
                               access_entry, sizeof(access_entry),
                               &access_entry_size);
  uint8_t access_outer_payload[256];
  RlpWriter outer_writer(access_outer_payload, sizeof(access_outer_payload));
  access_built = access_built &&
                 outer_writer.raw(access_entry, access_entry_size);
  uint8_t access_outer[256];
  size_t access_outer_size = 0;
  access_built = access_built &&
                 rlp_wrap_list(access_outer_payload, outer_writer.size(),
                               access_outer, sizeof(access_outer),
                               &access_outer_size);
  preimage_size = capacity;
  check(access_built &&
            build(1, descriptor, false, nullptr, 0, access_outer,
                  access_outer_size, preimage, capacity, &preimage_size),
        "access-build");
  check(qrl_v2_review_payload(preimage, preimage_size, sender, &rejected,
                              digest) == ChainError::Ok,
        "access-review");
  check(strstr(rejected.extra, "ACCESS 1") != nullptr, "access-count");

  preimage_size = capacity;
  ok = ok && build(1, descriptor, false, nullptr, 0, empty_access_list,
                   sizeof(empty_access_list), preimage, capacity,
                   &preimage_size);
  uint8_t stranger_account[kQrlV2AddressSize];
  for (size_t index = 0; index < sizeof(stranger_account); ++index) {
    stranger_account[index] = static_cast<uint8_t>(index);
  }
  char stranger[kQrlV2AddressTextSize];
  check(format_checksummed(stranger_account, stranger, sizeof(stranger)),
        "stranger-format");
  signed_size = sizeof(signed_payload);
  check(sign_with_seed(account_seed, preimage, preimage_size, stranger,
                       signed_payload, &signed_size) == ChainError::WrongWallet,
        "stranger");
  check(signed_size == 0, "stranger-size");

  // The MSVC host build intentionally links no BIP32 body
  // (tests/host/host_security.cpp), so the derivation leg only runs where a
  // real one exists: the chain-native probe and the firmware.
  HdPrivateNode master;
  HdPrivateNode child;
  const WalletError bip32 = hd_private_from_seed(account_seed,
                                                 sizeof(account_seed), &master);
  if (bip32 == WalletError::Ok) {
    char path[48] = "m/44'/238'/0'/0/0";
    char bip32_sender[kQrlV2AddressTextSize];
    size_t bip32_size = sizeof(signed_payload);
    check(hd_private_derive_path(&master, path, &child) == WalletError::Ok,
          "bip32-path");
    check(qrl_v2_address_from_seed(child.private_key, bip32_sender,
                                   sizeof(bip32_sender)) == WalletError::Ok,
          "bip32-address");
    check(qrl_v2_sign_payload(preimage, preimage_size, bip32_sender, master, 0,
                              signed_payload, &bip32_size) == ChainError::Ok,
          "bip32-sign");
    check(bip32_size == kQrlV2SignedSize, "bip32-size");
    const NetworkProfile *profile = find_network_profile("qrl2");
    DerivedAddress derived;
    const bool derived_ok =
        profile != nullptr &&
        derive_address(master, nullptr, *profile, 0, 0, 0, &derived) ==
            WalletError::Ok;
    check(derived_ok, "engine-derive");
    if (derived_ok) {
      check(strcmp(derived.address, bip32_sender) == 0, "engine-address");
      check(chain_constant_time_equal(derived.private_key, child.private_key,
                                      kPrivateKeySize),
            "engine-seed");
    }
  } else {
    check(bip32 == WalletError::CryptoFailure, "bip32-unexpected");
  }
  secure_zero(&master, sizeof(master));
  secure_zero(&child, sizeof(child));
  secure_zero(account_seed, sizeof(account_seed));
  return ok;
#endif
}

}  // namespace hexwallet
