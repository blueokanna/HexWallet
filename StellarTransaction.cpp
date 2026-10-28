#include "StellarTransaction.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include <stdio.h>
#include <string.h>

namespace hexwallet {
namespace {
constexpr char kPublicNetwork[] = "Public Global Stellar Network ; September 2015";
// Device spending policy, not a claim about the network's dynamic minimum fee.
constexpr uint32_t kMaximumFee = 10000000; // one XLM per transaction
#include "src/generated/StellarVectorsTest.inc"
class XdrReader {
 public:
  XdrReader(const uint8_t *data, size_t size) : data_(data), size_(size) {}
  bool bytes(void *out, size_t count) {
    if (count > size_ - offset_) { ok_ = false; return false; }
    memcpy(out, data_ + offset_, count); offset_ += count; return true;
  }
  uint32_t u32() {
    uint8_t b[4] = {}; bytes(b, sizeof(b));
    return (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) |
           (uint32_t(b[2]) << 8) | b[3];
  }
  uint64_t u64() { const uint64_t hi = u32(); return (hi << 32) | u32(); }
  bool done() const { return ok_ && offset_ == size_; }
  bool ok() const { return ok_; }
 private:
  const uint8_t *data_; size_t size_; size_t offset_ = 0; bool ok_ = true;
};
void hex_text(const uint8_t *bytes, size_t count, char *out) {
  constexpr char alphabet[] = "0123456789abcdef";
  for (size_t i = 0; i < count; ++i) {
    out[2*i] = alphabet[bytes[i] >> 4]; out[2*i+1] = alphabet[bytes[i] & 15];
  }
  out[2*count] = 0;
}
bool read_account(XdrReader &r, uint8_t key[32], char *text) {
  // Muxed accounts need a distinct M-address review; never discard their ID.
  return r.u32() == 0 && r.bytes(key, 32) && stellar_address(key, text, kStellarAddressSize);
}
StellarError parse(const uint8_t *data, size_t size, const uint8_t owner[32],
                   StellarTransaction *out) {
  uint8_t network[32];
  if (!crypto_sha256(reinterpret_cast<const uint8_t *>(kPublicNetwork),
                     sizeof(kPublicNetwork)-1, network)) return StellarError::CryptoFailure;
  if (memcmp(data, network, 32)) return StellarError::WrongNetwork;
  XdrReader r(data + 32, size - 32);
  if (r.u32() != 2) return StellarError::Unsupported;
  StellarReview &v = out->review;
  uint8_t key[32];
  if (!read_account(r, key, v.source)) return StellarError::Unsupported;
  if (memcmp(key, owner, 32)) return StellarError::WrongWallet;
  v.fee = r.u32(); v.sequence = r.u64();
  if (v.sequence == 0 || v.sequence > INT64_MAX) return StellarError::Malformed;
  // Require an explicit finite time window. No dependence on an unauthenticated
  // phone clock: signed Unix bounds are displayed, ledger enforces expiration.
  if (r.u32() != 1) return StellarError::Unsupported;
  v.min_time = r.u64(); v.max_time = r.u64();
  if (v.max_time == 0 || v.max_time <= v.min_time) return StellarError::Malformed;
  v.memo_type = r.u32();
  switch (v.memo_type) {
    case 0: strcpy(v.memo, "NONE"); break;
    case 1: {
      const uint32_t length = r.u32();
      if (length > 28 || !r.bytes(v.memo, length)) return StellarError::Malformed;
      for (size_t i = 0; i < length; ++i) {
        // No embedded NUL, control characters, bidi controls or invalid UTF-8.
        if (v.memo[i] < 0x20 || v.memo[i] > 0x7e) return StellarError::Unsupported;
      }
      uint8_t pad[3] = {};
      const size_t padding = (4 - length % 4) % 4;
      if (!r.bytes(pad, padding)) return StellarError::Malformed;
      for (size_t i = 0; i < padding; ++i) if (pad[i]) return StellarError::Malformed;
      break;
    }
    case 2: snprintf(v.memo, sizeof(v.memo), "%llu", static_cast<unsigned long long>(r.u64())); break;
    case 3: case 4: {
      uint8_t hash[32];
      if (!r.bytes(hash, sizeof(hash))) return StellarError::Malformed;
      hex_text(hash, sizeof(hash), v.memo); break;
    }
    default: return StellarError::Unsupported;
  }
  v.operation_count = r.u32();
  if (v.operation_count == 0 || v.operation_count > kStellarMaxOperations)
    return StellarError::Unsupported;
  if (v.fee < 100 * v.operation_count || v.fee > kMaximumFee) return StellarError::FeePolicy;
  for (size_t i = 0; i < v.operation_count; ++i) {
    StellarOperation &op = v.operations[i];
    // An explicit operation source is accepted only if it is our ordinary key.
    const uint32_t has_source = r.u32();
    if (has_source > 1) return StellarError::Malformed;
    if (has_source) {
      char source[kStellarAddressSize];
      if (!read_account(r, key, source)) return StellarError::Unsupported;
      if (memcmp(key, owner, 32)) return StellarError::WrongWallet;
    }
    op.type = r.u32();
    if (op.type > 1) return StellarError::Unsupported;
    if (!read_account(r, key, op.destination)) return StellarError::Unsupported;
    uint32_t asset_type = op.type == 1 ? r.u32() : 0;
    if (asset_type == 0) strcpy(op.asset, "XLM");
    else if (asset_type == 1 || asset_type == 2) {
      const size_t width = asset_type == 1 ? 4 : 12;
      if (!r.bytes(op.asset, width)) return StellarError::Malformed;
      size_t length = 0;
      while (length < width && op.asset[length]) {
        const char c = op.asset[length++];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
          return StellarError::Unsupported;
      }
      if (length == 0 || (asset_type == 2 && length <= 4)) return StellarError::Malformed;
      for (size_t j = length; j < width; ++j) if (op.asset[j]) return StellarError::Malformed;
      if (!read_account(r, key, op.issuer)) return StellarError::Unsupported;
    } else return StellarError::Unsupported;
    op.amount = r.u64();
    if (op.amount == 0 || op.amount > INT64_MAX) return StellarError::InvalidAmount;
    const int count = snprintf(op.amount_text, sizeof(op.amount_text), "%llu.%07llu %s",
        static_cast<unsigned long long>(op.amount / kStellarStroops),
        static_cast<unsigned long long>(op.amount % kStellarStroops), op.asset);
    if (count < 0 || static_cast<size_t>(count) >= sizeof(op.amount_text)) return StellarError::Malformed;
  }
  if (!r.ok() || r.u32() != 0 || r.u32() != 0 || !r.done()) return StellarError::Malformed;
  // The network prefix and envelope discriminant are exactly the signature
  // payload; only the final empty signatures vector is excluded.
  if (!crypto_sha256(data, size - 4, out->signing_hash)) return StellarError::CryptoFailure;
  memcpy(out->request, data, size); out->request_size = static_cast<uint16_t>(size);
  return StellarError::Ok;
}
bool same_review(const StellarReview &a, const StellarReview &b) {
  if (memcmp(a.source, b.source, sizeof(a.source)) || a.fee != b.fee ||
      a.sequence != b.sequence || a.min_time != b.min_time || a.max_time != b.max_time ||
      a.memo_type != b.memo_type || memcmp(a.memo, b.memo, sizeof(a.memo)) ||
      a.operation_count != b.operation_count) return false;
  for (size_t i = 0; i < a.operation_count; ++i) {
    const auto &x = a.operations[i]; const auto &y = b.operations[i];
    if (x.type != y.type || x.amount != y.amount ||
        memcmp(x.destination, y.destination, sizeof(x.destination)) ||
        memcmp(x.issuer, y.issuer, sizeof(x.issuer)) ||
        memcmp(x.asset, y.asset, sizeof(x.asset)) ||
        memcmp(x.amount_text, y.amount_text, sizeof(x.amount_text))) return false;
  }
  return true;
}
}

bool stellar_derivation_path(uint32_t index, uint32_t out[3]) {
  if (!out || index >= 0x80000000UL) return false;
  out[0] = 0x8000002c; out[1] = 0x80000094; out[2] = 0x80000000UL | index;
  return true;
}
bool stellar_derive_key(const uint8_t seed[kSeedSize], uint32_t index, uint8_t out[32]) {
  uint32_t path[3];
  if (!out) return false;
  if (seed && stellar_derivation_path(index, path) && slip10_ed25519_derive(seed, kSeedSize, path, 3, out)) return true;
  secure_zero(out, 32); return false;
}
bool stellar_address(const uint8_t public_key[32], char *out, size_t capacity) {
  if (out && capacity) out[0] = 0;
  if (!public_key || !out || capacity < kStellarAddressSize) return false;
  uint8_t payload[35] = {6 << 3};
  memcpy(payload + 1, public_key, 32);
  uint16_t crc = 0; // CRC16-XModem, little endian in StrKey
  for (size_t i = 0; i < 33; ++i) {
    crc ^= static_cast<uint16_t>(payload[i]) << 8;
    for (unsigned bit = 0; bit < 8; ++bit)
      crc = static_cast<uint16_t>((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0));
  }
  payload[33] = static_cast<uint8_t>(crc); payload[34] = static_cast<uint8_t>(crc >> 8);
  return base32_encode(payload, sizeof(payload), out, capacity, false, false);
}
StellarError stellar_review_request(const uint8_t *data, size_t size,
    const uint8_t owner[32], StellarTransaction *out) {
  if (!out) return StellarError::InvalidArgument;
  memset(out, 0, sizeof(*out));
  if (!data || !owner || size < 36 || size > kStellarMaxRequest) return StellarError::InvalidArgument;
  const StellarError error = parse(data, size, owner, out);
  if (error != StellarError::Ok) secure_zero(out, sizeof(*out));
  return error;
}
StellarError stellar_sign_transaction(const StellarTransaction &tx,
    const uint8_t seed[kSeedSize], uint8_t *out, size_t *in_out_size) {
  if (!in_out_size) return StellarError::InvalidArgument;
  const size_t capacity = *in_out_size; *in_out_size = 0;
  if (!out || !seed) return StellarError::InvalidArgument;
  uint8_t child[32] = {}, owner[32] = {}, signature[64] = {};
  StellarTransaction verified = {};
  StellarError error = StellarError::CryptoFailure;
  if (stellar_derive_key(seed, tx.address_index, child) && ed25519_public_key(child, owner)) {
    error = stellar_review_request(tx.request, tx.request_size, owner, &verified);
    if (error == StellarError::Ok && (!same_review(tx.review, verified.review) ||
        memcmp(tx.signing_hash, verified.signing_hash, 32))) error = StellarError::Malformed;
    if (error == StellarError::Ok) {
      const size_t size = verified.request_size - 32 + 72;
      if (capacity < size) error = StellarError::BufferTooSmall;
      else if (!ed25519_sign(child, verified.signing_hash, 32, signature) ||
               !ed25519_verify(owner, verified.signing_hash, 32, signature)) error = StellarError::CryptoFailure;
      else {
        const size_t body_size = verified.request_size - 36;
        memcpy(out, verified.request + 32, body_size);
        const uint8_t count[4] = {0,0,0,1}, length[4] = {0,0,0,64};
        memcpy(out + body_size, count, 4);
        memcpy(out + body_size + 4, owner + 28, 4);
        memcpy(out + body_size + 8, length, 4);
        memcpy(out + body_size + 12, signature, 64); *in_out_size = size;
      }
    }
  }
  secure_zero(child, sizeof(child)); secure_zero(owner, sizeof(owner));
  secure_zero(signature, sizeof(signature)); secure_zero(&verified, sizeof(verified));
  return error;
}
bool run_stellar_self_tests() {
  // SEP-0005, test 1 primary key. Independent public reference.
  const uint8_t seed[64] = {
    0xe4,0xa5,0xa6,0x32,0xe7,0x09,0x43,0xae,0x7f,0x07,0x65,0x9d,0xf1,0x33,0x21,0x60,
    0x93,0x7f,0xad,0x82,0x58,0x72,0x16,0xa4,0xc6,0x43,0x15,0xa0,0xfb,0x39,0x49,0x7e,
    0xe4,0xa0,0x1f,0x76,0xdd,0xab,0x4c,0xba,0x68,0x14,0x79,0x77,0xf3,0xa1,0x47,0xb6,
    0xad,0x58,0x4c,0x41,0x80,0x8e,0x82,0x38,0xa0,0x7f,0x6c,0xc4,0xb5,0x82,0xf1,0x86};
  uint8_t child[32], public_key[32]; char address[kStellarAddressSize];
  bool ok = stellar_derive_key(seed, 0, child) && ed25519_public_key(child, public_key) &&
      stellar_address(public_key, address, sizeof(address)) &&
      !strcmp(address, "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6");
  secure_zero(child, sizeof(child));
  StellarTransaction tx = {};
  uint8_t envelope[kStellarMaxEnvelope];
  size_t envelope_size = sizeof(envelope);
  ok = ok && stellar_review_request(kStellarTestRequest, sizeof(kStellarTestRequest), public_key, &tx) == StellarError::Ok &&
      stellar_sign_transaction(tx, seed, envelope, &envelope_size) == StellarError::Ok &&
      envelope_size == sizeof(kStellarTestEnvelope) &&
      memcmp(envelope, kStellarTestEnvelope, envelope_size) == 0;
  secure_zero(&tx, sizeof(tx)); secure_zero(envelope, sizeof(envelope));
  return ok;
}
}
