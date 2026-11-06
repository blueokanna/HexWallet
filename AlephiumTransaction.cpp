#include "AlephiumTransaction.h"
#include <cstdio>
#include <cstring>
#include "Blake2b.h"
#include "ChainCommon.h"
#include "base58.h"

namespace hexwallet {
namespace {
struct Reader {
  const uint8_t *p, *end;
  const uint8_t *take(size_t n) {
    if (n > size_t(end - p))
      return nullptr;
    const uint8_t *start = p;
    p += n;
    return start;
  }
  // Positive I32 (gas and array lengths) and U256 share the length prefixes.
  bool compact(bool signed_count, uint8_t (&out)[32]) {
    memset(out, 0, sizeof(out));
    const uint8_t *header = take(1);
    if (!header)
      return false;
    const uint8_t mode = *header >> 6;
    const uint8_t boundary = signed_count ? 32 : 64;
    if (mode < 3) {
      const size_t width = size_t(1) << mode;
      const uint8_t *tail = take(width - 1);
      if (!tail || (signed_count && (*header & 0x20)))
        return false;
      out[32 - width] = *header & 63;
      memcpy(out + 33 - width, tail, width - 1);
      if (mode == 1 && !out[30] && out[31] < boundary)
        return false;
      return mode != 2 || out[28] || out[29] || out[30] >= boundary;
    }
    const size_t width = 4 + (*header & 63);
    if (width > 32 || (signed_count && width != 4))
      return false;
    const auto *body = take(width);
    if (!body || !body[0] || (signed_count && (body[0] & 128)) || (width == 4 && body[0] < boundary))
      return false;
    memcpy(out + 32 - width, body, width);
    return true;
  }
  bool integer(bool signed_count, uint64_t &value) {
    uint8_t bytes[32], zero[24]{};
    if (!compact(signed_count, bytes) || memcmp(bytes, zero, 24))
      return false;
    value = 0;
    for (size_t i = 24; i < 32; ++i)
      value = (value << 8) | bytes[i];
    return true;
  }
};
} // namespace

ChainError alephium_review(const uint8_t *wire, size_t size, const uint8_t public_key[33], const char *sender,
                           ChainReview &review, uint8_t digest[32]) {
  if (!wire || size < 4 || !public_key || !sender || !digest)
    return ChainError::InvalidArgument;
  if (wire[1] != 0)
    return ChainError::WrongNetwork;
  if (wire[0] || wire[2])
    return ChainError::Unsupported;
  Reader r{wire + 3, wire + size};
  uint64_t gas, price, inputs, outputs;
  if (!r.integer(true, gas) || !r.integer(false, price) || !r.integer(true, inputs) || !inputs || inputs > 16)
    return ChainError::Malformed;
  // Local maximum fee of one ALPH bounds multiplication before formatting.
  if (gas < 20000 || price < 100000000000ULL || price > 1000000000000000000ULL / gas)
    return ChainError::FeePolicy;
  uint8_t owner[32];
  if (!blake2b_keyed_hash(nullptr, 0, public_key, 33, owner, 32))
    return ChainError::CryptoFailure;
  uint32_t hint = 5381;
  for (uint8_t b : owner)
    hint = hint * 33 + b;
  hint |= 1;
  const uint8_t *refs[16]{};
  for (size_t i = 0; i < inputs; ++i) {
    const auto *ref = r.take(36);
    const auto *unlock = r.take(1);
    if (!ref || !unlock)
      return ChainError::Malformed;
    const uint32_t h = (uint32_t(ref[0]) << 24) | (uint32_t(ref[1]) << 16) | (uint32_t(ref[2]) << 8) | ref[3];
    if (h != hint)
      return ChainError::WrongWallet;
    for (size_t j = 0; j < i; ++j)
      if (!memcmp(ref + 4, refs[j] + 4, 32))
        return ChainError::Malformed;
    refs[i] = ref;
    if (*unlock == 3 && i)
      continue;
    if (*unlock != 0)
      return ChainError::Unsupported;
    const auto *pk = r.take(33);
    if (!pk || memcmp(pk, public_key, 33))
      return ChainError::WrongWallet;
  }
  if (!r.integer(true, outputs) || !outputs || outputs > 2)
    return ChainError::Unsupported;
  bool recipient_seen = false, change_seen = false;
  char change[kChainMaxAmount]{};
  for (size_t i = 0; i < outputs; ++i) {
    uint8_t amount[32], zero[32]{};
    if (!r.compact(false, amount) || !memcmp(amount, zero, 32))
      return ChainError::InvalidAmount;
    const auto *script = r.take(33);
    const auto *lock = r.take(8);
    uint64_t tokens, message;
    if (!script || script[0] || !lock || memcmp(lock, zero, 8) || !r.integer(true, tokens) || tokens ||
        !r.integer(true, message) || message)
      return ChainError::Unsupported;
    if (!memcmp(script + 1, owner, 32)) {
      if (change_seen || !chain_format_units256(amount, 18, "ALPH", change, sizeof(change)))
        return ChainError::Unsupported;
      change_seen = true;
    } else {
      size_t capacity = sizeof(review.recipient);
      if (recipient_seen || !b58enc(review.recipient, &capacity, script, 33) ||
          !chain_format_units256(amount, 18, "ALPH", review.amount, sizeof(review.amount)))
        return ChainError::Unsupported;
      recipient_seen = true;
    }
  }
  if (r.p != r.end || !recipient_seen)
    return ChainError::Malformed;
  if (!chain_copy_text(review.sender, sizeof(review.sender), sender) ||
      !chain_copy_text(review.symbol, sizeof(review.symbol), "ALPH") ||
      !chain_format_units(gas * price, 18, "ALPH", review.fee, sizeof(review.fee)) ||
      !blake2b_keyed_hash(nullptr, 0, wire, size, digest, 32))
    return ChainError::CryptoFailure;
  snprintf(review.extra, sizeof(review.extra), "Inputs %u | Gas %llu | Change %s", unsigned(inputs),
           (unsigned long long)gas, change_seen ? change : "0 ALPH");
  return ChainError::Ok;
}
} // namespace hexwallet
