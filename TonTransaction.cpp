#include "TonTransaction.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoExtended.h"
#include "TonCell.h"

namespace hexwallet {
namespace {

struct TonRequest {
  uint32_t wallet_id;
  uint32_t valid_until;
  uint32_t seqno;
  uint8_t send_mode;
  uint8_t bounce;
  uint8_t recipient[32];
  uint8_t amount_be[kChainUint128Size];
};

ChainError parse_payload(const uint8_t *payload, size_t size,
                         TonRequest *request) {
  if (payload == nullptr || request == nullptr || size != kTonPayloadSize) {
    return ChainError::InvalidArgument;
  }
  if (memcmp(payload, "TON1", 4) != 0) return ChainError::Malformed;
  size_t offset = 4;
  request->wallet_id = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  request->valid_until = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  request->seqno = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  request->send_mode = payload[offset++];
  request->bounce = payload[offset++];
  memcpy(request->recipient, payload + offset, 32);
  offset += 32;
  memcpy(request->amount_be, payload + offset, kChainUint128Size);
  offset += kChainUint128Size;
  if (offset != size) return ChainError::Malformed;
  if (request->wallet_id != kTonDefaultWalletId) {
    return ChainError::WrongWallet;
  }
  if (request->valid_until == 0) return ChainError::Malformed;
  if (request->send_mode != kTonSendMode) return ChainError::FeePolicy;
  if (request->bounce > 1) return ChainError::Malformed;
  if (chain_u128_is_zero(request->amount_be)) {
    return ChainError::InvalidAmount;
  }
  uint8_t zero[32] = {};
  if (chain_constant_time_equal(request->recipient, zero, 32)) {
    return ChainError::InvalidAmount;
  }
  return ChainError::Ok;
}

bool build_internal_message(const TonRequest &request, TonCell *out) {
  if (out == nullptr) return false;
  ton_cell_init(out);
  TonBitWriter writer = {out, true};
  // int_msg_info$0, ihr_disabled, bounce, bounced, src=addr_none
  if (!ton_write_bits(&writer, 0, 1) ||
      !ton_write_bits(&writer, 1, 1) ||
      !ton_write_bits(&writer, request.bounce, 1) ||
      !ton_write_bits(&writer, 0, 1) ||
      !ton_write_bits(&writer, 0, 2)) {
    return false;
  }
  // dest = addr_std, no anycast, workchain 0, 32-byte hash.
  if (!ton_write_bits(&writer, 2, 2) ||
      !ton_write_bits(&writer, 0, 1) ||
      !ton_write_bits(&writer, 0, 8) ||
      !ton_write_bytes(&writer, request.recipient, 32)) {
    return false;
  }
  if (!ton_write_var_uint(&writer, request.amount_be, kChainUint128Size) ||
      !ton_write_bits(&writer, 0, 1) ||
      !ton_write_var_uint(&writer, nullptr, 0) ||
      !ton_write_var_uint(&writer, nullptr, 0) ||
      !ton_write_bits(&writer, 0, 64) ||
      !ton_write_bits(&writer, 0, 32) ||
      !ton_write_bits(&writer, 0, 1) ||
      !ton_write_bits(&writer, 0, 1)) {
    return false;
  }
  return writer.ok;
}

bool build_signing_message(const TonRequest &request, TonCell *out,
                           uint8_t *out_hash, uint16_t *out_depth) {
  if (out == nullptr || out_hash == nullptr) return false;
  TonCell message;
  uint8_t message_hash[32] = {};
  if (!build_internal_message(request, &message) ||
      !ton_cell_hash(&message, message_hash, nullptr)) {
    return false;
  }
  ton_cell_init(out);
  TonBitWriter writer = {out, true};
  if (!ton_write_bits(&writer, request.wallet_id, 32) ||
      !ton_write_bits(&writer, request.valid_until, 32) ||
      !ton_write_bits(&writer, request.seqno, 32) ||
      !ton_write_bits(&writer, 0, 8) ||
      !ton_write_bits(&writer, request.send_mode, 8) ||
      !ton_add_ref(&writer, message_hash, 0) || !writer.ok) {
    return false;
  }
  return ton_cell_hash(out, out_hash, out_depth);
}

}  // namespace

ChainError ton_review_payload(const uint8_t *payload, size_t size,
                              const char *sender, ChainReview *review,
                              uint8_t digest[32]) {
  if (sender == nullptr || review == nullptr || digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  memset(review, 0, sizeof(*review));
  TonRequest request;
  ChainError error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;
  TonCell signing_message;
  uint16_t depth = 0;
  if (!build_signing_message(request, &signing_message, digest, &depth)) {
    return ChainError::CryptoFailure;
  }
  char recipient[64] = {};
  if (!ton_user_friendly_address(
          request.bounce ? kTonBounceable : kTonNonBounceable, 0,
          request.recipient, recipient, sizeof(recipient))) {
    return ChainError::CryptoFailure;
  }
  strncpy(review->symbol, "TON", sizeof(review->symbol) - 1);
  strncpy(review->sender, sender, sizeof(review->sender) - 1);
  strncpy(review->recipient, recipient, sizeof(review->recipient) - 1);
  if (!ton_format_nanotons(request.amount_be, review->amount,
                           sizeof(review->amount))) {
    return ChainError::BufferTooSmall;
  }
  strncpy(review->fee, "SEND MODE 3", sizeof(review->fee) - 1);
  snprintf(review->extra, sizeof(review->extra),
           "WALLET ID %lu\nSEQNO %lu\nVALID UNTIL %lu\nBOUNCE %s",
           static_cast<unsigned long>(request.wallet_id),
           static_cast<unsigned long>(request.seqno),
           static_cast<unsigned long>(request.valid_until),
           request.bounce ? "YES" : "NO");
  secure_zero(&signing_message, sizeof(signing_message));
  return ChainError::Ok;
}

ChainError ton_sign_payload(const uint8_t *payload, size_t size,
                            const uint8_t seed[32], uint8_t *out,
                            size_t *in_out_size) {
  if (seed == nullptr || out == nullptr || in_out_size == nullptr) {
    return ChainError::InvalidArgument;
  }
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  if (capacity < kTonSignedSize) return ChainError::BufferTooSmall;
  TonRequest request;
  ChainError error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;
  TonCell signing_message;
  uint8_t digest[32] = {};
  uint16_t depth = 0;
  if (!build_signing_message(request, &signing_message, digest, &depth)) {
    return ChainError::CryptoFailure;
  }
  uint8_t signature[64] = {};
  if (!ed25519_sign(seed, digest, sizeof(digest), signature)) {
    secure_zero(&signing_message, sizeof(signing_message));
    return ChainError::CryptoFailure;
  }
  memcpy(out, signature, sizeof(signature));
  memcpy(out + sizeof(signature), digest, sizeof(digest));
  *in_out_size = kTonSignedSize;
  secure_zero(&signing_message, sizeof(signing_message));
  secure_zero(signature, sizeof(signature));
  return ChainError::Ok;
}

bool run_ton_self_tests() {
  static const uint8_t kSeed[32] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  static const uint8_t kPayload[kTonPayloadSize] = {
      'T', 'O', 'N', '1',
      0x17, 0xa3, 0xa9, 0x29,  // wallet id 698983191
      0x00, 0xf1, 0x53, 0x65,  // valid until 1700000000
      0x07, 0x00, 0x00, 0x00,  // seqno 7
      0x03, 0x00,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x07, 0x5b, 0xcd, 0x15};
  static const uint8_t kExpectedDigest[32] = {
      0x29, 0x4f, 0x1f, 0xda, 0xfb, 0x26, 0xb5, 0x17, 0x66, 0xf9, 0x23,
      0x78, 0x13, 0x59, 0xfe, 0xee, 0x4c, 0x3b, 0x9f, 0x24, 0x2d, 0xc2,
      0x77, 0xe1, 0x21, 0xa0, 0xf8, 0x92, 0xab, 0x7a, 0x10, 0x4f};
  static const uint8_t kExpectedSignature[64] = {
      0x4c, 0xd9, 0xa4, 0x47, 0x9d, 0x1f, 0x0f, 0x2a, 0x3f, 0xf3, 0x82,
      0x3c, 0xbc, 0x88, 0x61, 0x31, 0x52, 0xe3, 0x2c, 0xb6, 0xf5, 0x8b,
      0xae, 0xb5, 0x76, 0xf0, 0xd9, 0xbe, 0x83, 0xa1, 0x97, 0xac, 0x47,
      0x4c, 0xe1, 0x8f, 0xab, 0x83, 0xa2, 0x11, 0x2c, 0xa5, 0xc6, 0x48,
      0xda, 0x16, 0x72, 0xd4, 0x59, 0x2c, 0xf5, 0xc1, 0xe1, 0x7f, 0x7d,
      0x16, 0x63, 0x04, 0x72, 0xe7, 0x65, 0x0d, 0xc5, 0x0d};
  ChainReview review;
  uint8_t digest[32] = {};
  const ChainError review_error = ton_review_payload(
      kPayload, sizeof(kPayload),
      "UQDTcUOcJvwtMx4R6Vbb+uYCtJELCzAAvdD439fc2Y0UNpjM", &review, digest);
  if (review_error != ChainError::Ok) printf("ton review error=%u\n", static_cast<unsigned>(review_error));
  if (!chain_constant_time_equal(digest, kExpectedDigest, 32)) {
    printf("ton digest: ");
    for (size_t index = 0; index < 32; ++index) printf("%02x", digest[index]);
    printf("\n");
  }
  if (strcmp(review.recipient, "UQAiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIsAH")) printf("ton recipient='%s'\n", review.recipient);
  if (strcmp(review.amount, "0.123456789 TON")) printf("ton amount='%s'\n", review.amount);
  bool ok = review_error == ChainError::Ok &&
            chain_constant_time_equal(digest, kExpectedDigest, 32) &&
            !strcmp(review.recipient,
                    "UQAiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIsAH") &&
            !strcmp(review.amount, "0.123456789 TON");
  uint8_t signed_data[kTonSignedSize] = {};
  size_t signed_size = sizeof(signed_data);
  const ChainError sign_error = ton_sign_payload(
      kPayload, sizeof(kPayload), kSeed, signed_data, &signed_size);
  if (sign_error != ChainError::Ok) printf("ton sign error=%u\n", static_cast<unsigned>(sign_error));
  if (signed_size != kTonSignedSize) printf("ton signed size=%u\n", static_cast<unsigned>(signed_size));
  if (sign_error == ChainError::Ok && signed_size == kTonSignedSize &&
      !chain_constant_time_equal(signed_data, kExpectedSignature, 64)) {
    printf("ton signature: ");
    for (size_t index = 0; index < 64; ++index) printf("%02x", signed_data[index]);
    printf("\n");
  }
  if (sign_error == ChainError::Ok && signed_size == kTonSignedSize &&
      !chain_constant_time_equal(signed_data + 64, kExpectedDigest, 32)) {
    printf("ton signed digest: ");
    for (size_t index = 0; index < 32; ++index) printf("%02x", signed_data[64 + index]);
    printf("\n");
  }
  ok = ok && sign_error == ChainError::Ok &&
       signed_size == kTonSignedSize &&
       chain_constant_time_equal(signed_data, kExpectedSignature, 64) &&
       chain_constant_time_equal(signed_data + 64, kExpectedDigest, 32);
  return ok;
}

}  // namespace hexwallet
