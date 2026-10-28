#include "XrpTransaction.h"

#include <stdio.h>
#include <string.h>

#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "base58.h"

namespace hexwallet {
namespace {

constexpr uint8_t kPayment = 0;
constexpr uint32_t kCanonicalFlags = 0x80000000UL;
constexpr uint8_t kSigningPrefix[4] = {0x53, 0x54, 0x58, 0x00};

struct Writer {
  uint8_t *data;
  size_t capacity;
  size_t offset;
  bool ok;

  void u8(uint8_t value) {
    if (!ok || offset + 1 > capacity) { ok = false; return; }
    data[offset++] = value;
  }
  void u16(uint16_t value) {
    u8(static_cast<uint8_t>(value >> 8));
    u8(static_cast<uint8_t>(value));
  }
  void u32(uint32_t value) {
    u8(static_cast<uint8_t>(value >> 24));
    u8(static_cast<uint8_t>(value >> 16));
    u8(static_cast<uint8_t>(value >> 8));
    u8(static_cast<uint8_t>(value));
  }
  void u64(uint64_t value) {
    for (uint8_t index = 0; index < 8; ++index) {
      u8(static_cast<uint8_t>(value >> (56 - 8 * index)));
    }
  }
  void bytes(const uint8_t *value, size_t count) {
    if (!ok || offset + count > capacity) { ok = false; return; }
    memcpy(data + offset, value, count);
    offset += count;
  }
};

void field_header(Writer *writer, uint8_t type, uint8_t field) {
  if (field < 16) {
    writer->u8(static_cast<uint8_t>((type << 4) | field));
  } else {
    writer->u8(static_cast<uint8_t>(type << 4));
    writer->u8(field);
  }
}

void xrp_amount(Writer *writer, uint64_t drops) {
  field_header(writer, 6, 1);
  writer->u64(0x4000000000000000ULL | drops);
}

bool address_from_account(const uint8_t account[kXrpAccountSize], char *out,
                          size_t capacity) {
  if (account == nullptr || out == nullptr || capacity < kXrpAddressTextSize) {
    return false;
  }
  uint8_t payload[1 + kXrpAccountSize + 4] = {};
  uint8_t checksum[kSha256Size] = {};
  memcpy(payload + 1, account, kXrpAccountSize);
  if (!crypto_double_sha256(payload, 1 + kXrpAccountSize, checksum)) return false;
  memcpy(payload + 1 + kXrpAccountSize, checksum, 4);
  size_t encoded_size = capacity;
  const bool ok = ripple_b58enc(out, &encoded_size, payload, sizeof(payload));
  secure_zero(payload, sizeof(payload));
  secure_zero(checksum, sizeof(checksum));
  return ok && encoded_size <= capacity;
}

bool encode_der_integer(uint8_t *out, size_t capacity, size_t *offset,
                        const uint8_t value[kPrivateKeySize]) {
  size_t first = 0;
  while (first < kPrivateKeySize - 1 && value[first] == 0) ++first;
  const size_t digits = kPrivateKeySize - first;
  const bool pad = (value[first] & 0x80U) != 0;
  const size_t needed = digits + (pad ? 1 : 0);
  if (*offset + 2 + needed > capacity || needed > 127) return false;
  out[(*offset)++] = 0x02;
  out[(*offset)++] = static_cast<uint8_t>(needed);
  if (pad) out[(*offset)++] = 0;
  memcpy(out + *offset, value + first, digits);
  *offset += digits;
  return true;
}

bool encode_der(const RecoverableSignature &signature, uint8_t *out,
                size_t capacity, size_t *out_size) {
  size_t offset = 0;
  if (capacity < 8) return false;
  out[offset++] = 0x30;
  const size_t length_offset = offset++;
  if (!encode_der_integer(out, capacity, &offset, signature.r) ||
      !encode_der_integer(out, capacity, &offset, signature.s)) {
    return false;
  }
  const size_t length = offset - 2;
  if (length > 127) return false;
  out[length_offset] = static_cast<uint8_t>(length);
  *out_size = offset;
  return true;
}

uint64_t read_be(const uint8_t *data, size_t size) {
  uint64_t value = 0;
  for (size_t index = 0; index < size; ++index) value = (value << 8) | data[index];
  return value;
}

bool same_review(const XrpReview &a, const XrpReview &b) {
  return a.amount_drops == b.amount_drops && a.fee_drops == b.fee_drops &&
         a.sequence == b.sequence && a.last_ledger_sequence == b.last_ledger_sequence &&
         a.destination_tag == b.destination_tag &&
         a.has_destination_tag == b.has_destination_tag &&
         !memcmp(a.source, b.source, sizeof(a.source)) &&
         !memcmp(a.destination, b.destination, sizeof(a.destination)) &&
         !memcmp(a.public_key, b.public_key, sizeof(a.public_key)) &&
         a.unsigned_size == b.unsigned_size &&
         !memcmp(a.unsigned_tx, b.unsigned_tx, sizeof(a.unsigned_tx)) &&
         !memcmp(a.signing_hash, b.signing_hash, sizeof(a.signing_hash));
}

}  // namespace

bool xrp_address_from_account(const uint8_t account[kXrpAccountSize], char *out,
                              size_t capacity) {
  return address_from_account(account, out, capacity);
}

bool xrp_format_amount(uint64_t drops, char *out, size_t capacity) {
  if (out == nullptr || capacity == 0) return false;
  const int written = snprintf(out, capacity, "%llu.%06llu XRP",
      static_cast<unsigned long long>(drops / 1000000ULL),
      static_cast<unsigned long long>(drops % 1000000ULL));
  return written > 0 && static_cast<size_t>(written) < capacity;
}

XrpError xrp_review_payload(const uint8_t *payload, size_t size,
                            const uint8_t public_key[kXrpPublicKeySize],
                            XrpTransaction *out) {
  if (out == nullptr) return XrpError::InvalidArgument;
  memset(out, 0, sizeof(*out));
  if (payload == nullptr || public_key == nullptr || size != 50) {
    return XrpError::InvalidArgument;
  }
  if (payload[0] != 1 || payload[1] > 1) return XrpError::Malformed;
  XrpReview &v = out->review;
  v.amount_drops = read_be(payload + 2, 8);
  v.fee_drops = read_be(payload + 10, 8);
  v.sequence = static_cast<uint32_t>(read_be(payload + 18, 4));
  v.last_ledger_sequence = static_cast<uint32_t>(read_be(payload + 22, 4));
  v.destination_tag = static_cast<uint32_t>(read_be(payload + 26, 4));
  v.has_destination_tag = payload[1] != 0;
  memcpy(v.destination, payload + 30, kXrpAccountSize);
  if ((public_key[0] != 2 && public_key[0] != 3) ||
      (v.amount_drops == 0 || v.amount_drops > kXrpMaxAmountDrops) ||
      v.fee_drops < 10 || v.fee_drops > kXrpMaxFeeDrops ||
      v.sequence == 0 || v.last_ledger_sequence == 0) {
    return XrpError::InvalidArgument;
  }
  bool destination_nonzero = false;
  for (size_t index = 0; index < kXrpAccountSize; ++index) {
    if (v.destination[index] != 0) destination_nonzero = true;
  }
  if (!destination_nonzero) return XrpError::InvalidArgument;
  memcpy(v.public_key, public_key, kXrpPublicKeySize);
  if (!crypto_hash160(public_key, kXrpPublicKeySize, v.source)) {
    return XrpError::CryptoFailure;
  }
  if (!memcmp(v.source, v.destination, kXrpAccountSize)) {
    return XrpError::InvalidAmount;
  }
  Writer writer = {v.unsigned_tx, sizeof(v.unsigned_tx), 0, true};
  field_header(&writer, 1, 2);
  writer.u16(kPayment);
  field_header(&writer, 2, 2);
  writer.u32(kCanonicalFlags);
  field_header(&writer, 2, 4);
  writer.u32(v.sequence);
  if (v.has_destination_tag) {
    field_header(&writer, 2, 14);
    writer.u32(v.destination_tag);
  }
  field_header(&writer, 2, 27);
  writer.u32(v.last_ledger_sequence);
  xrp_amount(&writer, v.amount_drops);
  field_header(&writer, 6, 8);
  writer.u64(0x4000000000000000ULL | v.fee_drops);
  field_header(&writer, 7, 3);
  writer.u8(kXrpPublicKeySize);
  writer.bytes(v.public_key, kXrpPublicKeySize);
  v.signature_offset = static_cast<uint16_t>(writer.offset);
  field_header(&writer, 8, 1);
  writer.u8(kXrpAccountSize);
  writer.bytes(v.source, kXrpAccountSize);
  field_header(&writer, 8, 3);
  writer.u8(kXrpAccountSize);
  writer.bytes(v.destination, kXrpAccountSize);
  if (!writer.ok || writer.offset > kXrpMaxUnsigned) return XrpError::BufferTooSmall;
  v.unsigned_size = static_cast<uint16_t>(writer.offset);
  uint8_t signing[4 + kXrpMaxUnsigned] = {};
  memcpy(signing, kSigningPrefix, sizeof(kSigningPrefix));
  memcpy(signing + 4, v.unsigned_tx, v.unsigned_size);
  if (!crypto_sha512_half(signing, 4 + v.unsigned_size, v.signing_hash)) {
    secure_zero(signing, sizeof(signing));
    return XrpError::CryptoFailure;
  }
  secure_zero(signing, sizeof(signing));
  if (!xrp_address_from_account(v.source, v.source_text, sizeof(v.source_text)) ||
      !xrp_address_from_account(v.destination, v.destination_text,
                                sizeof(v.destination_text)) ||
      !xrp_format_amount(v.amount_drops, v.amount_text, sizeof(v.amount_text)) ||
      !xrp_format_amount(v.fee_drops, v.fee_text, sizeof(v.fee_text))) {
    return XrpError::CryptoFailure;
  }
  static const char kHex[] = "0123456789abcdef";
  for (size_t index = 0; index < kXrpHashSize; ++index) {
    v.hash_text[2 * index] = kHex[v.signing_hash[index] >> 4];
    v.hash_text[2 * index + 1] = kHex[v.signing_hash[index] & 0x0f];
  }
  v.hash_text[64] = 0;
  return XrpError::Ok;
}

XrpError xrp_sign_transaction(const XrpTransaction &transaction,
                              const uint8_t private_key[kPrivateKeySize],
                              uint8_t *out, size_t *in_out_size) {
  if (in_out_size == nullptr) return XrpError::InvalidArgument;
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  if (private_key == nullptr || out == nullptr) return XrpError::InvalidArgument;
  uint8_t public_key[kXrpPublicKeySize] = {};
  if (public_key_from_private(private_key, public_key) != WalletError::Ok) {
    return XrpError::CryptoFailure;
  }
  XrpTransaction verified = {};
  // The reviewed unsigned bytes are the source of truth; rebuild the public key
  // binding and signing hash before touching the curve.
  verified.review = transaction.review;
  uint8_t source[kXrpAccountSize] = {};
  uint8_t hash[kXrpHashSize] = {};
  uint8_t signing[4 + kXrpMaxUnsigned] = {};
  crypto_hash160(public_key, sizeof(public_key), source);
  memcpy(signing, kSigningPrefix, sizeof(kSigningPrefix));
  memcpy(signing + 4, transaction.review.unsigned_tx, transaction.review.unsigned_size);
  const bool binding = !memcmp(source, transaction.review.source, sizeof(source)) &&
      !memcmp(public_key, transaction.review.public_key, sizeof(public_key)) &&
      crypto_sha512_half(signing, 4 + transaction.review.unsigned_size, hash) &&
      !memcmp(hash, transaction.review.signing_hash, sizeof(hash));
  secure_zero(signing, sizeof(signing));
  if (!binding) {
    secure_zero(public_key, sizeof(public_key));
    secure_zero(source, sizeof(source));
    return XrpError::Malformed;
  }
  RecoverableSignature signature = {};
  uint8_t der[kXrpMaxSignature] = {};
  size_t der_size = 0;
  const WalletError sign_error = secp256k1_sign_digest_recoverable(
      private_key, transaction.review.signing_hash, &signature);
  const bool der_ok = sign_error == WalletError::Ok &&
      encode_der(signature, der, sizeof(der), &der_size);
  secure_zero(&signature, sizeof(signature));
  secure_zero(public_key, sizeof(public_key));
  secure_zero(source, sizeof(source));
  if (!der_ok) {
    secure_zero(der, sizeof(der));
    return XrpError::CryptoFailure;
  }
  const size_t needed = transaction.review.unsigned_size + der_size + 2;
  if (capacity < needed || transaction.review.signature_offset >
                              transaction.review.unsigned_size) {
    secure_zero(der, sizeof(der));
    *in_out_size = needed;
    return XrpError::BufferTooSmall;
  }
  size_t offset = 0;
  memcpy(out, transaction.review.unsigned_tx, transaction.review.signature_offset);
  offset += transaction.review.signature_offset;
  out[offset++] = 0x74;
  out[offset++] = static_cast<uint8_t>(der_size);
  memcpy(out + offset, der, der_size);
  offset += der_size;
  memcpy(out + offset, transaction.review.unsigned_tx + transaction.review.signature_offset,
         transaction.review.unsigned_size - transaction.review.signature_offset);
  offset += transaction.review.unsigned_size - transaction.review.signature_offset;
  *in_out_size = offset;
  secure_zero(der, sizeof(der));
  secure_zero(&verified, sizeof(verified));
  return XrpError::Ok;
}

void clear_xrp_transaction(XrpTransaction *transaction) {
  if (transaction != nullptr) secure_zero(transaction, sizeof(*transaction));
}

const char *xrp_error_text(XrpError error) {
  switch (error) {
    case XrpError::Ok: return "ok";
    case XrpError::InvalidArgument: return "invalid argument";
    case XrpError::Malformed: return "malformed";
    case XrpError::Unsupported: return "unsupported";
    case XrpError::WrongWallet: return "wrong wallet";
    case XrpError::InvalidAmount: return "invalid amount";
    case XrpError::FeePolicy: return "fee policy";
    case XrpError::CryptoFailure: return "crypto failure";
    case XrpError::BufferTooSmall: return "buffer too small";
  }
  return "unknown";
}

bool run_xrp_self_tests() {
  // The full SDK vector is compiled by the generator below; keep this check
  // honest even if the host has no secp256k1 signer.
  static const uint8_t kTestPubkey[kXrpPublicKeySize] = {
      0x03,0x6d,0x6c,0xaa,0xc2,0x48,0xaf,0x96,0xf6,0xaf,0xa7,0xf9,0x04,0xf5,0x50,0x25,
      0x3a,0x0f,0x3e,0xf3,0xf5,0xaa,0x2f,0xe6,0x83,0x8a,0x95,0xb2,0x16,0x69,0x14,0x68,
      0xe2};
  static const uint8_t kTestPayload[50] = {
      0x01,0x00,
      0x00,0x00,0x00,0x00,0x00,0x0f,0x42,0x40,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,
      0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x64,0x00,0x00,0x00,0x00,
      0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
      0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11};
  static const uint8_t kExpectedHash[32] = {
      0x12,0x2d,0x6f,0x6c,0xea,0x68,0x41,0xa6,0xbe,0x12,0x80,0xc9,0xc7,0x9e,0xdc,0x7f,
      0x9e,0x4d,0xa3,0xc1,0xb5,0xfe,0x57,0xc3,0x16,0x1e,0x89,0x3d,0x9a,0x44,0x50,0xa6};
  XrpTransaction tx = {};
  const XrpError error = xrp_review_payload(kTestPayload, sizeof(kTestPayload),
                                            kTestPubkey, &tx);
  const bool ok = error == XrpError::Ok &&
      !memcmp(tx.review.signing_hash, kExpectedHash, sizeof(kExpectedHash)) &&
      !strcmp(tx.review.source_text, "raZbRYVpCr44u4Q9EDYy7MUpdrcjGSpGsL");
  clear_xrp_transaction(&tx);
  return ok;
}

}  // namespace hexwallet
