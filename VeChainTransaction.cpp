#include "VeChainTransaction.h"

#include <stdio.h>
#include <string.h>

#include "Blake2b.h"
#include "ChainCommon.h"
#include "CryptoPrimitives.h"

namespace hexwallet {
namespace {

struct VeChainRequest {
  uint32_t chain_tag;
  uint8_t block_ref[8];
  uint32_t expiration;
  uint32_t gas_price_coef;
  uint64_t gas;
  uint8_t recipient[20];
  uint8_t value_be[kChainUint128Size];
  uint64_t nonce;
};

void write_u32_be(uint32_t value, uint8_t out[4]) {
  out[0] = static_cast<uint8_t>(value >> 24);
  out[1] = static_cast<uint8_t>(value >> 16);
  out[2] = static_cast<uint8_t>(value >> 8);
  out[3] = static_cast<uint8_t>(value);
}

void write_u64_be(uint64_t value, uint8_t out[8]) {
  for (size_t index = 0; index < 8; ++index) {
    out[index] = static_cast<uint8_t>(value >> (8 * (7 - index)));
  }
}

ChainError parse_payload(const uint8_t *payload, size_t size,
                         VeChainRequest *request) {
  if (payload == nullptr || request == nullptr || size != kVeChainPayloadSize) {
    return ChainError::InvalidArgument;
  }
  if (memcmp(payload, "VET1", 4) != 0) return ChainError::Malformed;
  size_t offset = 4;
  request->chain_tag = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  memcpy(request->block_ref, payload + offset, 8);
  offset += 8;
  request->expiration = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  request->gas_price_coef = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  request->gas = chain_read_u64_le(payload + offset);
  offset += 8;
  const uint8_t clause_count = payload[offset++];
  if (clause_count != 1) return ChainError::Unsupported;
  const uint8_t recipient_size = payload[offset++];
  if (recipient_size != 20) return ChainError::Malformed;
  memcpy(request->recipient, payload + offset, 20);
  offset += 20;
  memcpy(request->value_be, payload + offset, kChainUint128Size);
  offset += kChainUint128Size;
  const uint16_t data_size = static_cast<uint16_t>(
      (static_cast<uint16_t>(payload[offset]) << 8) | payload[offset + 1]);
  offset += 2;
  if (data_size != 0) return ChainError::Unsupported;
  request->nonce = chain_read_u64_le(payload + offset);
  offset += 8;
  if (offset != size) return ChainError::Malformed;
  if (request->chain_tag != kVeChainMainnetTag) return ChainError::WrongNetwork;
  if (request->gas_price_coef > 255) return ChainError::Malformed;
  if (request->expiration == 0 || request->expiration > 86400) {
    return ChainError::FeePolicy;
  }
  if (request->gas < 21000 || request->gas > 10000000) {
    return ChainError::FeePolicy;
  }
  if (chain_u128_is_zero(request->value_be)) {
    return ChainError::InvalidAmount;
  }
  if (request->nonce == 0) return ChainError::Malformed;
  uint8_t zero_address[20] = {};
  if (chain_constant_time_equal(request->recipient, zero_address, 20)) {
    return ChainError::InvalidAmount;
  }
  return ChainError::Ok;
}

bool encode_clause(const VeChainRequest &request, uint8_t *out,
                   size_t capacity, size_t *out_size) {
  uint8_t payload[64] = {};
  RlpWriter writer(payload, sizeof(payload));
  const uint8_t *value = nullptr;
  size_t value_size = 0;
  chain_u128_minimal(request.value_be, &value, &value_size);
  writer.bytes(request.recipient, 20);
  writer.integer(value, value_size);
  writer.bytes(nullptr, 0);
  return writer.ok() &&
         rlp_wrap_list(payload, writer.size(), out, capacity, out_size);
}

// Builds the concatenated top-level items, without the outer list header.
bool encode_unsigned_payload(const VeChainRequest &request, uint8_t *out,
                             size_t capacity, size_t *out_size) {
  uint8_t clause[64] = {};
  size_t clause_size = 0;
  if (!encode_clause(request, clause, sizeof(clause), &clause_size)) return false;
  uint8_t clauses_payload[96] = {};
  RlpWriter clauses_writer(clauses_payload, sizeof(clauses_payload));
  clauses_writer.raw(clause, clause_size);
  uint8_t clauses[112] = {};
  size_t clauses_size = 0;
  if (!clauses_writer.ok() ||
      !rlp_wrap_list(clauses_payload, clauses_writer.size(), clauses,
                     sizeof(clauses), &clauses_size)) {
    return false;
  }

  RlpWriter writer(out, capacity);
  uint8_t be[8] = {};
  write_u32_be(request.chain_tag, be);
  writer.integer(be, 4);
  size_t block_ref_offset = 0;
  while (block_ref_offset < 8 && request.block_ref[block_ref_offset] == 0) {
    ++block_ref_offset;
  }
  writer.bytes(request.block_ref + block_ref_offset, 8 - block_ref_offset);
  write_u32_be(request.expiration, be);
  writer.integer(be, 4);
  writer.raw(clauses, clauses_size);
  write_u32_be(request.gas_price_coef, be);
  writer.integer(be, 4);
  write_u64_be(request.gas, be);
  writer.integer(be, 8);
  writer.bytes(nullptr, 0);
  write_u64_be(request.nonce, be);
  writer.integer(be, 8);
  uint8_t empty_list[1] = {};
  size_t empty_list_size = 0;
  if (!rlp_wrap_list(empty_list, 0, empty_list, sizeof(empty_list),
                     &empty_list_size)) {
    return false;
  }
  writer.raw(empty_list, empty_list_size);
  if (!writer.ok()) return false;
  *out_size = writer.size();
  return true;
}

bool encode_unsigned(const VeChainRequest &request, uint8_t *out,
                     size_t capacity, size_t *out_size) {
  uint8_t payload[192] = {};
  size_t payload_size = 0;
  return encode_unsigned_payload(request, payload, sizeof(payload),
                                 &payload_size) &&
         rlp_wrap_list(payload, payload_size, out, capacity, out_size);
}

ChainError compute_digest(const uint8_t *payload, size_t size,
                          VeChainRequest *request, uint8_t unsigned_tx[192],
                          size_t *unsigned_size, uint8_t digest[32]) {
  ChainError error = parse_payload(payload, size, request);
  if (error != ChainError::Ok) return error;
  if (!encode_unsigned(*request, unsigned_tx, 192, unsigned_size)) {
    return ChainError::BufferTooSmall;
  }
  if (!blake2b_keyed_hash(nullptr, 0, unsigned_tx, *unsigned_size, digest, 32)) {
    return ChainError::CryptoFailure;
  }
  return ChainError::Ok;
}

}  // namespace

ChainError vechain_build_unsigned(const uint8_t *payload, size_t size,
                                  uint8_t *out, size_t *in_out_size) {
  if (out == nullptr || in_out_size == nullptr) {
    return ChainError::InvalidArgument;
  }
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  VeChainRequest request;
  const ChainError error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;
  if (!encode_unsigned(request, out, capacity, in_out_size)) {
    return ChainError::BufferTooSmall;
  }
  return ChainError::Ok;
}

ChainError vechain_review_payload(const uint8_t *payload, size_t size,
                                  const char *sender, ChainReview *review,
                                  uint8_t digest[32]) {
  if (sender == nullptr || review == nullptr || digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  memset(review, 0, sizeof(*review));
  VeChainRequest request;
  uint8_t unsigned_tx[kVeChainMaxUnsigned] = {};
  size_t unsigned_size = 0;
  const ChainError error =
      compute_digest(payload, size, &request, unsigned_tx, &unsigned_size, digest);
  secure_zero(unsigned_tx, sizeof(unsigned_tx));
  if (error != ChainError::Ok) return error;
  strncpy(review->symbol, "VET", sizeof(review->symbol) - 1);
  strncpy(review->sender, sender, sizeof(review->sender) - 1);
  char recipient_hex[41] = {};
  chain_hex(request.recipient, 20, recipient_hex, sizeof(recipient_hex));
  snprintf(review->recipient, sizeof(review->recipient), "0x%s", recipient_hex);
  if (!chain_format_units128(request.value_be, 18, "VET", review->amount,
                             sizeof(review->amount))) {
    return ChainError::BufferTooSmall;
  }
  snprintf(review->fee, sizeof(review->fee), "GAS %llu / COEF %u",
           static_cast<unsigned long long>(request.gas),
           static_cast<unsigned>(request.gas_price_coef));
  snprintf(review->extra, sizeof(review->extra),
           "CHAIN TAG 0x%02x\nEXPIRATION %lu BLOCKS\nNONCE %llu",
           static_cast<unsigned>(request.chain_tag),
           static_cast<unsigned long>(request.expiration),
           static_cast<unsigned long long>(request.nonce));
  return ChainError::Ok;
}

ChainError vechain_sign_payload(const uint8_t *payload, size_t size,
                                const uint8_t private_key[32], uint8_t *out,
                                size_t *in_out_size) {
  if (private_key == nullptr || out == nullptr || in_out_size == nullptr) {
    return ChainError::InvalidArgument;
  }
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  VeChainRequest request;
  uint8_t unsigned_payload[192] = {};
  size_t unsigned_payload_size = 0;
  uint8_t digest[32] = {};
  ChainError error = parse_payload(payload, size, &request);
  if (error == ChainError::Ok &&
      !encode_unsigned_payload(request, unsigned_payload,
                               sizeof(unsigned_payload),
                               &unsigned_payload_size)) {
    error = ChainError::BufferTooSmall;
  }
  if (error != ChainError::Ok) {
    secure_zero(unsigned_payload, sizeof(unsigned_payload));
    return error;
  }
  uint8_t unsigned_tx[kVeChainMaxUnsigned] = {};
  size_t unsigned_size = 0;
  if (!rlp_wrap_list(unsigned_payload, unsigned_payload_size, unsigned_tx,
                     sizeof(unsigned_tx), &unsigned_size) ||
      !blake2b_keyed_hash(nullptr, 0, unsigned_tx, unsigned_size, digest, 32)) {
    secure_zero(unsigned_payload, sizeof(unsigned_payload));
    return ChainError::CryptoFailure;
  }
  secure_zero(unsigned_tx, sizeof(unsigned_tx));
  RecoverableSignature signature;
  const WalletError sign_error =
      secp256k1_sign_digest_recoverable(private_key, digest, &signature);
  if (sign_error != WalletError::Ok || signature.y_parity > 1) {
    secure_zero(unsigned_payload, sizeof(unsigned_payload));
    secure_zero(&signature, sizeof(signature));
    return ChainError::CryptoFailure;
  }

  uint8_t signature_bytes[65] = {};
  memcpy(signature_bytes, signature.r, 32);
  memcpy(signature_bytes + 32, signature.s, 32);
  signature_bytes[64] = signature.y_parity;

  uint8_t combined[256] = {};
  memcpy(combined, unsigned_payload, unsigned_payload_size);
  RlpWriter tail(combined + unsigned_payload_size,
                 sizeof(combined) - unsigned_payload_size);
  tail.bytes(signature_bytes, sizeof(signature_bytes));
  const size_t combined_size =
      unsigned_payload_size + (tail.ok() ? tail.size() : 0);
  if (!tail.ok() ||
      !rlp_wrap_list(combined, combined_size, out, capacity, in_out_size)) {
    secure_zero(unsigned_payload, sizeof(unsigned_payload));
    secure_zero(&signature, sizeof(signature));
    secure_zero(signature_bytes, sizeof(signature_bytes));
    secure_zero(combined, sizeof(combined));
    return ChainError::BufferTooSmall;
  }
  secure_zero(unsigned_payload, sizeof(unsigned_payload));
  secure_zero(&signature, sizeof(signature));
  secure_zero(signature_bytes, sizeof(signature_bytes));
  secure_zero(combined, sizeof(combined));
  return ChainError::Ok;
}

bool run_vechain_self_tests() {
  // thor-devkit 1.0.14 vector for private key 1.
  static const uint8_t kPayload[kVeChainPayloadSize] = {
      0x56, 0x45, 0x54, 0x31, 0x27, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xa1, 0xb2, 0xc3, 0xd4,
      0xd0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x08, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x01, 0x14,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x11, 0x22, 0x10, 0xf4, 0x7d, 0xe9, 0x81, 0x15,
      0x00, 0x00,
      0x15, 0xcd, 0x5b, 0x07, 0x00, 0x00, 0x00, 0x00};
  static const uint8_t kExpectedDigest[32] = {
      0x90, 0x3a, 0xfb, 0xc4, 0xae, 0x9b, 0x95, 0x9f, 0x2b, 0xfb, 0xc8,
      0x73, 0xaf, 0x93, 0xe7, 0x36, 0xab, 0x94, 0xc7, 0x15, 0x7b, 0xe2,
      0x16, 0x5a, 0x8b, 0xcd, 0x7c, 0xd4, 0xf8, 0x73, 0x40, 0xfd};
  static const uint8_t kExpectedUnsigned[] = {
      0xf5, 0x27, 0x84, 0xa1, 0xb2, 0xc3, 0xd4, 0x82, 0x02, 0xd0, 0xe0,
      0xdf, 0x94, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x88, 0x11, 0x22, 0x10, 0xf4, 0x7d, 0xe9, 0x81, 0x15, 0x80, 0x80,
      0x82, 0x52, 0x08, 0x80, 0x84, 0x07, 0x5b, 0xcd, 0x15, 0xc0};
  ChainReview review;
  uint8_t digest[32] = {};
  const ChainError review_error = vechain_review_payload(
      kPayload, sizeof(kPayload),
      "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", &review, digest);
  bool ok = review_error == ChainError::Ok &&
            chain_constant_time_equal(digest, kExpectedDigest, 32) &&
            !strcmp(review.amount, "1.234567890123456789 VET") &&
            !strcmp(review.recipient,
                    "0x1111111111111111111111111111111111111111");
  uint8_t unsigned_tx[kVeChainMaxUnsigned] = {};
  size_t unsigned_size = sizeof(unsigned_tx);
  ok = ok &&
       vechain_build_unsigned(kPayload, sizeof(kPayload), unsigned_tx,
                              &unsigned_size) == ChainError::Ok &&
       unsigned_size == sizeof(kExpectedUnsigned) &&
       chain_constant_time_equal(unsigned_tx, kExpectedUnsigned,
                                 sizeof(kExpectedUnsigned));
  ok = ok && vechain_review_payload(kPayload, sizeof(kPayload) - 1,
                                    "0x0", &review, digest) != ChainError::Ok;
  uint8_t wrong_tag[sizeof(kPayload)] = {};
  memcpy(wrong_tag, kPayload, sizeof(kPayload));
  wrong_tag[4] = 0x28;
  ok = ok && vechain_review_payload(wrong_tag, sizeof(wrong_tag), "0x0",
                                    &review, digest) ==
                 ChainError::WrongNetwork;
  secure_zero(unsigned_tx, sizeof(unsigned_tx));
  return ok;
}

}  // namespace hexwallet
