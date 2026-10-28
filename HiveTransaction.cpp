#include "HiveTransaction.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

// Hive mainnet chain id (HF24 replaced the inherited Steem zero chain id).
constexpr uint8_t kHiveChainId[32] = {
    0xbe, 0xea, 0xb0, 0xde, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
constexpr size_t kHiveDigestSize = 32;
constexpr size_t kHiveSignatureSize = 65;
constexpr size_t kHiveSerializedMax = 320;

struct HiveTransfer {
  uint16_t ref_block_num;
  uint32_t ref_block_prefix;
  uint32_t expiration;
  char from[kHiveMaxNameSize + 1];
  char to[kHiveMaxNameSize + 1];
  char amount[kHiveMaxAmountSize + 1];
  char memo[kHiveMaxMemoSize + 1];
  uint8_t from_size;
  uint8_t to_size;
  uint8_t amount_size;
  uint8_t memo_size;
};

bool valid_account_name(const char *name, size_t size) {
  if (size < 3 || size > kHiveMaxNameSize) return false;
  size_t part_start = 0;
  for (size_t i = 0; i < size; ++i) {
    const char c = name[i];
    const bool lower = c >= 'a' && c <= 'z';
    const bool digit = c >= '0' && c <= '9';
    if (i == part_start && !lower) return false;
    if (c == '.') {
      if (i - part_start < 3 || name[i - 1] == '-') return false;
      part_start = i + 1;
    } else if (!lower && !digit && c != '-') return false;
  }
  return size - part_start >= 3 && name[size - 1] != '-';
}

// "N.NNN HIVE" or "N.NNN HBD": exactly three decimals, non-zero integer part.
bool valid_amount(const char *text, size_t size) {
  size_t dot = size;
  for (size_t i = 0; i < size; ++i) {
    if (text[i] == '.') {
      dot = i;
      break;
    }
  }
  if (dot == size || dot == 0) return false;
  if (size != dot + 9 && size != dot + 8) return false;
  if (dot > 1 && text[0] == '0') return false;
  uint64_t whole = 0;
  for (size_t i = 0; i < dot; ++i) {
    if (text[i] < '0' || text[i] > '9') return false;
    whole = whole * 10 + static_cast<uint64_t>(text[i] - '0');
    if (whole > 1000000000000ULL) return false;
  }
  uint64_t fraction = 0;
  for (size_t i = dot + 1; i < dot + 4; ++i) {
    if (text[i] < '0' || text[i] > '9') return false;
    fraction = fraction * 10 + static_cast<uint64_t>(text[i] - '0');
  }
  if (text[dot + 4] != ' ') return false;
  const bool hive = size == dot + 9 && memcmp(text + dot + 5, "HIVE", 4) == 0;
  const bool hbd = size == dot + 8 && memcmp(text + dot + 5, "HBD", 3) == 0;
  if (!hive && !hbd) return false;
  return whole != 0 || fraction != 0;
}

bool parse_payload(const uint8_t *payload, size_t size, HiveTransfer *out) {
  if (payload == nullptr || out == nullptr || size < 4 + 10 + 3 * 4 ||
      size > kHivePayloadSize || memcmp(payload, "HIV1", 4) != 0) {
    return false;
  }
  size_t offset = 4;
  HiveTransfer parsed = {};
  parsed.ref_block_num = static_cast<uint16_t>(payload[offset] |
                                               (payload[offset + 1] << 8));
  offset += 2;
  parsed.ref_block_prefix = static_cast<uint32_t>(
      payload[offset] | (payload[offset + 1] << 8) |
      (payload[offset + 2] << 16) |
      (static_cast<uint32_t>(payload[offset + 3]) << 24));
  offset += 4;
  parsed.expiration = static_cast<uint32_t>(
      payload[offset] | (payload[offset + 1] << 8) |
      (payload[offset + 2] << 16) |
      (static_cast<uint32_t>(payload[offset + 3]) << 24));
  offset += 4;

  struct Field {
    char *text;
    uint8_t *size_out;
    size_t limit;
  } fields[4] = {
      {parsed.from, &parsed.from_size, kHiveMaxNameSize},
      {parsed.to, &parsed.to_size, kHiveMaxNameSize},
      {parsed.amount, &parsed.amount_size, kHiveMaxAmountSize},
      {parsed.memo, &parsed.memo_size, kHiveMaxMemoSize},
  };
  for (size_t i = 0; i < 4; ++i) {
    if (offset >= size) return false;
    const uint8_t length = payload[offset++];
    if (length > fields[i].limit || offset + length > size) return false;
    memcpy(fields[i].text, payload + offset, length);
    fields[i].text[length] = '\0';
    *fields[i].size_out = length;
    offset += length;
  }
  if (offset != size) return false;
  if (!valid_account_name(parsed.from, parsed.from_size) ||
      !valid_account_name(parsed.to, parsed.to_size) ||
      !valid_amount(parsed.amount, parsed.amount_size)) {
    return false;
  }
  if (parsed.from_size == parsed.to_size &&
      memcmp(parsed.from, parsed.to, parsed.from_size) == 0) {
    return false;
  }
  // Encrypted memos ("#base64") cannot be shown to the user, so they are not
  // admitted: the device never signs content it cannot display.
  if (parsed.memo_size != 0 && parsed.memo[0] == '#') return false;
  for (size_t i = 0; i < parsed.memo_size; ++i)
    if (static_cast<uint8_t>(parsed.memo[i]) < 0x20 ||
        static_cast<uint8_t>(parsed.memo[i]) > 0x7e) return false;
  *out = parsed;
  return true;
}

size_t write_varint(uint32_t value, uint8_t *out) {
  size_t size = 0;
  while (value >= 0x80) {
    out[size++] = static_cast<uint8_t>((value & 0x7f) | 0x80);
    value >>= 7;
  }
  out[size++] = static_cast<uint8_t>(value);
  return size;
}

size_t write_string(const char *text, uint8_t size, uint8_t *out) {
  const size_t prefix = write_varint(size, out);
  memcpy(out + prefix, text, size);
  return prefix + size;
}

size_t serialize_transfer(const HiveTransfer &tx, uint8_t *out) {
  out[0] = static_cast<uint8_t>(tx.ref_block_num);
  out[1] = static_cast<uint8_t>(tx.ref_block_num >> 8);
  chain_write_u32_le(tx.ref_block_prefix, out + 2);
  chain_write_u32_le(tx.expiration, out + 6);
  size_t offset = 10;
  out[offset++] = 1;  // one operation
  out[offset++] = 2;  // transfer_operation, not vote_operation (0)
  offset += write_string(tx.from, tx.from_size, out + offset);
  offset += write_string(tx.to, tx.to_size, out + offset);
  uint64_t amount = 0;
  const char *cursor = tx.amount;
  while (*cursor && *cursor != ' ') {
    if (*cursor != '.') amount = amount * 10 + static_cast<unsigned>(*cursor - '0');
    ++cursor;
  }
  chain_write_u64_le(amount, out + offset); offset += 8;
  out[offset++] = 3;
  // Legacy wire symbols remain STEEM/SBD after Hive's fork; JSON uses HIVE/HBD.
  memset(out + offset, 0, 7);
  memcpy(out + offset, strstr(tx.amount, "HBD") ? "SBD" : "STEEM",
         strstr(tx.amount, "HBD") ? 3 : 5);
  offset += 7;
  offset += write_string(tx.memo, tx.memo_size, out + offset);
  out[offset++] = 0;  // signed_transaction extensions
  return offset;
}

bool hive_digest(const HiveTransfer &tx, uint8_t digest[32]) {
  uint8_t serialized[kHiveSerializedMax] = {};
  const size_t size = serialize_transfer(tx, serialized);
  uint8_t preimage[32 + kHiveSerializedMax] = {};
  memcpy(preimage, kHiveChainId, 32);
  memcpy(preimage + 32, serialized, size);
  const bool ok = crypto_sha256(preimage, 32 + size, digest);
  secure_zero(serialized, sizeof(serialized));
  secure_zero(preimage, sizeof(preimage));
  return ok;
}

ChainError review_transfer(const HiveTransfer &tx, const char *sender_key,
                           ChainReview *review, uint8_t digest[32]) {
  ChainReview built = {};
  memcpy(built.symbol, "HIVE", 5);
  if (strlen(sender_key) >= sizeof(built.sender) ||
      strlen(tx.to) >= sizeof(built.recipient)) {
    return ChainError::InvalidArgument;
  }
  strcpy(built.sender, sender_key);
  strcpy(built.recipient, tx.to);
  if (strlen(tx.amount) >= sizeof(built.amount)) return ChainError::InvalidAmount;
  strcpy(built.amount, tx.amount);
  strcpy(built.fee, "0 HIVE (resource credits required)");
  const int written = snprintf(
      built.extra, sizeof(built.extra),
      "FROM %s; verify active key on node\nref %u/%08x exp %u\n%s%s",
      tx.from, static_cast<unsigned>(tx.ref_block_num),
      static_cast<unsigned>(tx.ref_block_prefix),
      static_cast<unsigned>(tx.expiration), tx.memo_size ? "memo: " : "no memo",
      tx.memo_size ? tx.memo : "");
  if (written < 0 || static_cast<size_t>(written) >= sizeof(built.extra)) {
    return ChainError::BufferTooSmall;
  }
  if (!hive_digest(tx, digest)) return ChainError::CryptoFailure;
  *review = built;
  return ChainError::Ok;
}

}  // namespace

ChainError hive_review_payload(const uint8_t *payload, size_t size,
                               const char *sender_key, ChainReview *review,
                               uint8_t digest[32]) {
  if (sender_key == nullptr || review == nullptr || digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  HiveTransfer tx = {};
  if (!parse_payload(payload, size, &tx)) return ChainError::Malformed;
  return review_transfer(tx, sender_key, review, digest);
}

ChainError hive_sign_payload(const uint8_t *payload, size_t size,
                             const uint8_t private_key[32], uint8_t *out,
                             size_t *in_out_size) {
  if (private_key == nullptr || out == nullptr || in_out_size == nullptr) {
    return ChainError::InvalidArgument;
  }
  if (*in_out_size < kHiveSignatureSize) return ChainError::BufferTooSmall;
  *in_out_size = 0;
  HiveTransfer tx = {};
  if (!parse_payload(payload, size, &tx)) return ChainError::Malformed;
  uint8_t digest[kHiveDigestSize] = {};
  if (!hive_digest(tx, digest)) return ChainError::CryptoFailure;
  uint8_t der[72] = {};
  size_t der_size = sizeof(der);
  uint8_t recovery = 0;
  const bool signed_ok = chain_secp256k1_sign_der_canonical(
      private_key, digest, der, &der_size, &recovery);
  if (!signed_ok) {
    secure_zero(digest, sizeof(digest));
    return ChainError::CryptoFailure;
  }
  // Graphene compact signature: header || r(32) || s(32).
  uint8_t r[32] = {};
  uint8_t s[32] = {};
  bool parsed = false;
  if (der_size >= 8 && der[0] == 0x30 && der[1] == der_size - 2 &&
      der[2] == 0x02) {
    const size_t r_size = der[3];
    if (r_size > 0 && r_size <= 32 && der_size >= 6 + r_size &&
        der[4 + r_size] == 0x02) {
      const size_t s_size = der[5 + r_size];
      if (s_size > 0 && s_size <= 32 && der_size == 6 + r_size + s_size) {
        memcpy(r + (32 - r_size), der + 4, r_size);
        memcpy(s + (32 - s_size), der + 6 + r_size, s_size);
        parsed = true;
      }
    }
  }
  if (parsed) {
    out[0] = static_cast<uint8_t>(kHiveCollateral + recovery);
    memcpy(out + 1, r, 32);
    memcpy(out + 33, s, 32);
    *in_out_size = kHiveSignatureSize;
  }
  secure_zero(digest, sizeof(digest));
  secure_zero(der, sizeof(der));
  secure_zero(r, sizeof(r));
  secure_zero(s, sizeof(s));
  return parsed ? ChainError::Ok : ChainError::CryptoFailure;
}

bool run_hive_self_tests() {
  // Hive mainnet graphene signed_transaction serialization, chain id beeab0de... .
  // Pinned by @hiveio/dhive 1.3.6. Transfer has no extensions field;
  // only the transaction's empty extensions vector belongs in the preimage.
  static const uint8_t kPayload[] = {
      0x48,0x49,0x56,0x31,0x34,0x12,0xef,0xcd,0xab,0x89,0xc0,0xdc,0xde,0x6a,0x0e,0x74,
      0x65,0x73,0x74,0x2d,0x61,0x63,0x63,0x6f,0x75,0x6e,0x74,0x2d,0x31,0x06,0x68,0x69,
      0x76,0x65,0x69,0x6f,0x0a,0x31,0x2e,0x32,0x33,0x34,0x20,0x48,0x49,0x56,0x45,0x05,
      0x68,0x65,0x6c,0x6c,0x6f};
  static const uint8_t kExpectedDigest[32] = {
      0xd0,0x10,0x95,0x2b,0x9a,0x49,0xfe,0x0e,0xd2,0x99,0x78,0x0a,0xa2,0xdc,0xb3,0x01,
      0xa3,0x15,0xbf,0x29,0x34,0x4b,0x82,0xd6,0x79,0x41,0x3c,0x14,0x9f,0xee,0x47,0xaa};
  static const uint8_t kPrivateKey[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 1};
  HiveTransfer tx = {};
  bool ok = parse_payload(kPayload, sizeof(kPayload), &tx);
  uint8_t digest[32] = {};
  ok = ok && hive_digest(tx, digest);
  if (!ok) return false;
  // The digest must match the independent SDK computation for this frame.
  ok = chain_constant_time_equal(digest, kExpectedDigest, sizeof(kExpectedDigest));
  if (!ok) {
    ::printf("hive digest ");
    for (size_t i = 0; i < 32; ++i) ::printf("%02x", digest[i]);
    ::printf("\n");
  }
  // The host unit-test shim stubs mbedtls_ecp_mul, so the ECDSA step is only
  // exercised where a real Mbed TLS is linked (device build and the native
  // tests/host/chain probe).
#if !defined(HEXWALLET_HOST_TEST) || defined(HEXWALLET_REAL_MBEDTLS)
  uint8_t signature[kHiveSignatureSize] = {};
  size_t signature_size = sizeof(signature);
  const ChainError sign_error = hive_sign_payload(
      kPayload, sizeof(kPayload), kPrivateKey, signature, &signature_size);
  if (sign_error != ChainError::Ok) {
    ::printf("hive sign error %u\n", static_cast<unsigned>(sign_error));
  } else if (signature_size != kHiveSignatureSize ||
             signature[0] < kHiveCollateral ||
             signature[0] > kHiveCollateral + 3) {
    ::printf("hive sig meta size=%u id=%u\n",
             static_cast<unsigned>(signature_size),
             static_cast<unsigned>(signature[0]));
  }
  ok = ok && sign_error == ChainError::Ok &&
       signature_size == kHiveSignatureSize &&
       signature[0] >= kHiveCollateral && signature[0] <= kHiveCollateral + 3;
  secure_zero(signature, sizeof(signature));
#endif
  secure_zero(&tx, sizeof(tx));
  return ok;
}

}  // namespace hexwallet
