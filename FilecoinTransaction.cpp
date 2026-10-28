#include "FilecoinTransaction.h"
#include <stdio.h>
#include <string.h>
#include "ChainCommon.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "WalletAltAddresses.h"

namespace hexwallet {
namespace {
class Cbor {
 public:
  Cbor(const uint8_t *data, size_t size) : data_(data), size_(size) {}
  bool head(uint8_t major, uint64_t *v) {
    if (pos_ == size_) return false;
    const uint8_t b = data_[pos_++], ai = b & 31;
    if ((b >> 5) != major || ai > 27) return false;
    if (ai < 24) { *v = ai; return true; }
    const size_t n = size_t(1) << (ai - 24);
    if (n > size_ - pos_) return false;
    *v = 0; for (size_t i = 0; i < n; ++i) *v = (*v << 8) | data_[pos_++];
    return *v >= (n == 1 ? 24ULL : (1ULL << (4 * n)));
  }
  bool literal(uint8_t b) { return pos_ < size_ && data_[pos_++] == b; }
  const uint8_t *bytes(size_t *n) {
    uint64_t len = 0;
    if (!head(2, &len) || len > size_ - pos_) return nullptr;
    const uint8_t *p = data_ + pos_; *n = static_cast<size_t>(len); pos_ += *n; return p;
  }
  bool done() const { return pos_ == size_; }
 private:
  const uint8_t *data_; size_t size_, pos_ = 0;
};
bool bigint(Cbor &r, uint8_t out[16]) {
  size_t n = 0; const uint8_t *p = r.bytes(&n); memset(out, 0, 16);
  if (!p || n > 17 || n == 1 || (n && (p[0] != 0 || p[1] == 0))) return false;
  if (n) memcpy(out + 17 - n, p + 1, n - 1);
  return true;
}
bool address(const uint8_t *p, size_t n, char *out, size_t cap) {
  if (!p || !n) return false;
  if (p[0] == 0) {
    // ID addresses carry a minimal unsigned LEB128 actor ID.
    if (n < 2 || n > 11) return false;
    uint64_t id = 0;
    for (size_t i = 1; i < n; ++i) {
      if (i == 10 && p[i] > 1) return false;
      if (((p[i] & 128) != 0) != (i + 1 != n)) return false;
      if (i > 1 && i + 1 == n && p[i] == 0) return false;
      id |= uint64_t(p[i] & 127) << (7 * (i - 1));
    }
    // Built-in actors must not be presented as ordinary account transfers.
    if (id < 100) return false;
    const int len = snprintf(out, cap, "f0%llu", static_cast<unsigned long long>(id));
    return len > 0 && static_cast<size_t>(len) < cap;
  }
  if (!((p[0] == 1 && n == 21) || (p[0] == 3 && n == 49)) || cap < 3) return false;
  uint8_t checked[52] = {}; memcpy(checked, p + 1, n - 1);
  if (!crypto_blake2b(p, n, checked + n - 1, 4)) return false;
  out[0] = 'f'; out[1] = char('0' + p[0]);
  return base32_encode(checked, n + 3, out + 2, cap - 2, true, false);
}
// Exact u128 multiplication by a small positive gas limit; detects overflow.
bool multiply(const uint8_t in[16], uint64_t factor, uint8_t out[16]) {
  uint64_t carry = 0;
  for (size_t i = 16; i-- > 0;) {
    const uint64_t v = uint64_t(in[i]) * factor + carry;
    out[i] = uint8_t(v); carry = v >> 8;
  }
  return carry == 0;
}
}

ChainError filecoin_review_payload(const uint8_t *data, size_t size,
                                   const char *sender, ChainReview *review,
                                   uint8_t digest[32]) {
  if (!data || !sender || !review || !digest || !size || size > kChainMaxPayload)
    return ChainError::InvalidArgument;
  memset(review, 0, sizeof(*review)); Cbor r(data, size);
  if (!r.literal(0x8a) || !r.literal(0)) return ChainError::Unsupported;
  size_t to_size = 0, from_size = 0;
  const uint8_t *to = r.bytes(&to_size), *from = r.bytes(&from_size);
  if (!address(to, to_size, review->recipient, sizeof(review->recipient)) ||
      !from || from_size != 21 || from[0] != 1 ||
      !address(from, from_size, review->sender, sizeof(review->sender)))
    return ChainError::Malformed;
  if (strcmp(sender, review->sender)) return ChainError::WrongWallet;
  uint64_t nonce = 0, gas = 0;
  uint8_t value[16] = {}, cap[16] = {}, premium[16] = {}, fee[16] = {};
  if (!r.head(0, &nonce) || !bigint(r, value) || !r.head(0, &gas) ||
      !bigint(r, cap) || !bigint(r, premium)) return ChainError::Malformed;
  if (!r.literal(0) || !r.literal(0x40) || !r.done()) return ChainError::Unsupported;
  if (chain_u128_is_zero(value)) return ChainError::InvalidAmount;
  if (!gas || gas > 10000000000ULL || chain_u128_is_zero(cap) ||
      memcmp(premium, cap, 16) > 0 || !multiply(cap, gas, fee)) return ChainError::FeePolicy;
  unsigned carry = 0;
  for (size_t i = 16; i-- > 0;) carry = (unsigned(value[i]) + fee[i] + carry) >> 8;
  if (carry) return ChainError::InvalidAmount;
  strcpy(review->symbol, "FIL");
  if (!chain_format_units128(value, 18, "FIL", review->amount, sizeof(review->amount)) ||
      !chain_format_units128(fee, 18, "FIL MAX", review->fee, sizeof(review->fee)))
    return ChainError::BufferTooSmall;
  snprintf(review->extra, sizeof(review->extra),
           "METHOD SEND\nNONCE %llu\nGAS LIMIT %llu\nNO CHAIN ID IN MESSAGE",
           static_cast<unsigned long long>(nonce), static_cast<unsigned long long>(gas));
  // Signing bytes are the binary CID, not the raw message or its bare hash:
  // CIDv1 / dag-cbor / blake2b-256 (multihash varint 0xb220) / 32-byte digest.
  uint8_t cid[38] = {1, 0x71, 0xa0, 0xe4, 2, 0x20};
  if (!crypto_blake2b(data, size, cid + 6, 32) || !crypto_blake2b(cid, sizeof(cid), digest, 32))
    return ChainError::CryptoFailure;
  return ChainError::Ok;
}

ChainError filecoin_sign_payload(const uint8_t *data, size_t size,
                                 const uint8_t private_key[32], uint8_t *out,
                                 size_t *in_out_size) {
  if (!in_out_size) return ChainError::InvalidArgument;
  const size_t capacity = *in_out_size; *in_out_size = 0;
  if (!private_key || !out || !data || size > kChainMaxPayload) return ChainError::InvalidArgument;
  if (capacity < size + 69) return ChainError::BufferTooSmall;
  uint8_t pub[65] = {}, digest[32] = {}; char sender[96] = {}; ChainReview review = {};
  if (uncompressed_public_key_from_private(private_key, pub) != WalletError::Ok ||
      address_filecoin(pub, sender, sizeof(sender)) != WalletError::Ok)
    return ChainError::CryptoFailure;
  ChainError error = filecoin_review_payload(data, size, sender, &review, digest);
  if (error != ChainError::Ok) return error;
  RecoverableSignature signature = {};
  if (secp256k1_sign_digest_recoverable(private_key, digest, &signature) != WalletError::Ok ||
      signature.y_parity > 1) {
    secure_zero(&signature, sizeof(signature)); return ChainError::CryptoFailure;
  }
  out[0] = 0x82; memcpy(out + 1, data, size);
  out[size + 1] = 0x58; out[size + 2] = 66; out[size + 3] = 1;
  memcpy(out + size + 4, signature.r, 32); memcpy(out + size + 36, signature.s, 32);
  out[size + 68] = signature.y_parity; *in_out_size = size + 69;
  secure_zero(&signature, sizeof(signature)); return ChainError::Ok;
}
bool run_filecoin_self_tests() {
#include "src/generated/FilecoinVectorsTest.inc"
  ChainReview review = {}; uint8_t digest[32] = {};
  return filecoin_review_payload(kPayload, sizeof(kPayload), kAddress, &review, digest) == ChainError::Ok &&
      !memcmp(digest, kExpectedDigest, 32) && !strcmp(review.recipient, kRecipient) &&
      !strcmp(review.amount, kAmount) && !strcmp(review.fee, kFee);
}
} // namespace hexwallet
