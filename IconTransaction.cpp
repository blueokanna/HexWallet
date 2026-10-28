#include "IconTransaction.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoExtended.h"

namespace hexwallet {
namespace {

struct IconRequest {
  uint32_t nid;
  uint64_t nonce;
  uint64_t step_limit;
  uint64_t timestamp_us;
  uint8_t value_be[kChainUint128Size];
  uint8_t recipient[20];
};

ChainError parse_payload(const uint8_t *payload, size_t size,
                         IconRequest *request) {
  if (payload == nullptr || request == nullptr || size != kIconPayloadSize) {
    return ChainError::InvalidArgument;
  }
  if (memcmp(payload, "ICX1", 4) != 0) return ChainError::Malformed;
  size_t offset = 4;
  request->nid = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  request->nonce = chain_read_u64_le(payload + offset);
  offset += 8;
  request->step_limit = chain_read_u64_le(payload + offset);
  offset += 8;
  request->timestamp_us = chain_read_u64_le(payload + offset);
  offset += 8;
  memcpy(request->value_be, payload + offset, kChainUint128Size);
  offset += kChainUint128Size;
  const uint8_t recipient_size = payload[offset++];
  if (recipient_size != 20) return ChainError::Malformed;
  memcpy(request->recipient, payload + offset, 20);
  offset += 20;
  if (offset != size) return ChainError::Malformed;
  if (request->nid != kIconMainnetNid) return ChainError::WrongNetwork;
  if (request->nonce == 0 || request->timestamp_us == 0) {
    return ChainError::Malformed;
  }
  if (request->step_limit < 10000 || request->step_limit > 10000000) {
    return ChainError::FeePolicy;
  }
  if (chain_u128_is_zero(request->value_be)) {
    return ChainError::InvalidAmount;
  }
  uint8_t zero_address[20] = {};
  if (chain_constant_time_equal(request->recipient, zero_address, 20)) {
    return ChainError::InvalidAmount;
  }
  return ChainError::Ok;
}

}  // namespace

ChainError icon_serialize_payload(const uint8_t *payload, size_t size,
                                  const char *sender, char *out,
                                  size_t out_size) {
  if (sender == nullptr || out == nullptr || out_size == 0) {
    return ChainError::InvalidArgument;
  }
  IconRequest request;
  ChainError error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;
  // Only the two address forms and lowercase hex numbers appear here; no
  // escape sequences are possible, so the canonical concatenation is exact.
  if (strncmp(sender, "hx", 2) != 0 || strlen(sender) != 42) {
    return ChainError::WrongWallet;
  }
  char recipient[43] = {};
  char recipient_hex[41] = {};
  char value_hex[33] = {};
  chain_hex(request.recipient, 20, recipient_hex, sizeof(recipient_hex));
  snprintf(recipient, sizeof(recipient), "hx%s", recipient_hex);
  if (!chain_u128_hex(request.value_be, value_hex, sizeof(value_hex))) {
    return ChainError::BufferTooSmall;
  }
  const int written = snprintf(
      out, out_size,
      "icx_sendTransaction.from.%s.nid.0x%x.nonce.0x%llx.stepLimit.0x%llx."
      "timestamp.0x%llx.to.%s.value.0x%s.version.0x3",
      sender, static_cast<unsigned>(request.nid),
      static_cast<unsigned long long>(request.nonce),
      static_cast<unsigned long long>(request.step_limit),
      static_cast<unsigned long long>(request.timestamp_us), recipient,
      value_hex);
  if (written <= 0 || static_cast<size_t>(written) >= out_size) {
    return ChainError::BufferTooSmall;
  }
  return ChainError::Ok;
}

ChainError icon_review_payload(const uint8_t *payload, size_t size,
                               const char *sender, ChainReview *review,
                               uint8_t digest[32]) {
  if (sender == nullptr || review == nullptr || digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  memset(review, 0, sizeof(*review));
  char serialized[kIconMaxSerialized] = {};
  ChainError error = icon_serialize_payload(payload, size, sender, serialized,
                                            sizeof(serialized));
  if (error != ChainError::Ok) return error;
  if (!crypto_sha3_256(reinterpret_cast<const uint8_t *>(serialized),
                       strlen(serialized), digest)) {
    return ChainError::CryptoFailure;
  }
  IconRequest request;
  error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;
  strncpy(review->symbol, "ICX", sizeof(review->symbol) - 1);
  strncpy(review->sender, sender, sizeof(review->sender) - 1);
  char recipient_hex[41] = {};
  chain_hex(request.recipient, 20, recipient_hex, sizeof(recipient_hex));
  snprintf(review->recipient, sizeof(review->recipient), "hx%s", recipient_hex);
  if (!chain_format_units128(request.value_be, 18, "ICX", review->amount,
                             sizeof(review->amount))) {
    return ChainError::BufferTooSmall;
  }
  snprintf(review->fee, sizeof(review->fee), "STEP LIMIT %llu",
           static_cast<unsigned long long>(request.step_limit));
  snprintf(review->extra, sizeof(review->extra),
           "NID 0x%x\nNONCE 0x%llx\nTIMESTAMP 0x%llx",
           static_cast<unsigned>(request.nid),
           static_cast<unsigned long long>(request.nonce),
           static_cast<unsigned long long>(request.timestamp_us));
  secure_zero(serialized, sizeof(serialized));
  return ChainError::Ok;
}

ChainError icon_sign_payload(const uint8_t *payload, size_t size,
                             const uint8_t private_key[32], const char *sender,
                             uint8_t *out, size_t *in_out_size) {
  if (private_key == nullptr || sender == nullptr || out == nullptr ||
      in_out_size == nullptr) {
    return ChainError::InvalidArgument;
  }
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  if (capacity < 65) return ChainError::BufferTooSmall;
  char serialized[kIconMaxSerialized] = {};
  ChainError error = icon_serialize_payload(payload, size, sender, serialized,
                                            sizeof(serialized));
  if (error != ChainError::Ok) {
    secure_zero(serialized, sizeof(serialized));
    return error;
  }
  uint8_t digest[32] = {};
  if (!crypto_sha3_256(reinterpret_cast<const uint8_t *>(serialized),
                       strlen(serialized), digest)) {
    secure_zero(serialized, sizeof(serialized));
    return ChainError::CryptoFailure;
  }
  RecoverableSignature signature;
  const WalletError sign_error =
      secp256k1_sign_digest_recoverable(private_key, digest, &signature);
  secure_zero(serialized, sizeof(serialized));
  if (sign_error != WalletError::Ok || signature.y_parity > 1) {
    secure_zero(&signature, sizeof(signature));
    return ChainError::CryptoFailure;
  }
  memcpy(out, signature.r, 32);
  memcpy(out + 32, signature.s, 32);
  out[64] = signature.y_parity;
  *in_out_size = 65;
  secure_zero(&signature, sizeof(signature));
  return ChainError::Ok;
}

bool run_icon_self_tests() {
  // iconsdk / coincurve vector for private key 1.
  static const uint8_t kPayload[kIconPayloadSize] = {
      'I', 'C', 'X', '1',
      0x01, 0x00, 0x00, 0x00,
      0x15, 0xcd, 0x5b, 0x07, 0x00, 0x00, 0x00, 0x00,
      0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x40, 0x1e, 0x18, 0x24, 0x0a, 0x06, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x11, 0x22, 0x10, 0xf4, 0x7d, 0xe9, 0x81, 0x15,
      0x14,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11};
  static const char kExpectedText[] =
      "icx_sendTransaction.from.hx0502987e630ea7ebb2bf1d84a65a727109385bcf."
      "nid.0x1.nonce.0x75bcd15.stepLimit.0x186a0.timestamp.0x60a24181e4000."
      "to.hx1111111111111111111111111111111111111111."
      "value.0x112210f47de98115.version.0x3";
  static const uint8_t kExpectedDigest[32] = {
      0xa1, 0xfb, 0x01, 0x1a, 0x25, 0x4c, 0xc1, 0x0d, 0x25, 0x0d, 0xba,
      0xf9, 0xa2, 0xa3, 0xfd, 0x04, 0x76, 0x1d, 0xcd, 0x6a, 0x76, 0xf0,
      0x40, 0x2a, 0x21, 0xe8, 0x49, 0x3b, 0xda, 0xe3, 0xd0, 0x16};
  char serialized[kIconMaxSerialized] = {};
  ChainReview review;
  uint8_t digest[32] = {};
  const ChainError serialize_error = icon_serialize_payload(
      kPayload, sizeof(kPayload),
      "hx0502987e630ea7ebb2bf1d84a65a727109385bcf", serialized,
      sizeof(serialized));
  const ChainError review_error = icon_review_payload(
      kPayload, sizeof(kPayload),
      "hx0502987e630ea7ebb2bf1d84a65a727109385bcf", &review, digest);
  bool ok = serialize_error == ChainError::Ok &&
            strcmp(serialized, kExpectedText) == 0 &&
            review_error == ChainError::Ok &&
            chain_constant_time_equal(digest, kExpectedDigest, 32) &&
            !strcmp(review.amount, "1.234567890123456789 ICX") &&
            !strcmp(review.recipient,
                    "hx1111111111111111111111111111111111111111");
  uint8_t wrong_nid[sizeof(kPayload)] = {};
  memcpy(wrong_nid, kPayload, sizeof(kPayload));
  wrong_nid[4] = 0x02;
  ok = ok && icon_review_payload(wrong_nid, sizeof(wrong_nid),
                                 "hx0502987e630ea7ebb2bf1d84a65a727109385bcf",
                                 &review, digest) ==
                 ChainError::WrongNetwork;
  secure_zero(serialized, sizeof(serialized));
  return ok;
}

}  // namespace hexwallet
