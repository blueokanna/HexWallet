#include "CardanoTransaction.h"

#include <stdio.h>
#include <string.h>

#include "CardanoDerivation.h"
#include "ChainCommon.h"
#include "CryptoExtended.h"
#include "WalletAltAddresses.h"

namespace hexwallet {
namespace {
constexpr uint64_t kMaxLovelace = UINT64_C(45000000000000000);
constexpr uint64_t kMaxFee = 10000000;  // local policy, not a network fee estimate

// Only definite-length CBOR with shortest integer/length encodings is admitted.
// No generic recursive skip: every accepted field is understood and displayed.
struct Reader {
  const uint8_t *p;
  size_t left;
  bool head(uint8_t major, uint64_t *value) {
    if (!left || (*p >> 5) != major) return false;
    const uint8_t ai = *p++ & 31;
    --left;
    if (ai < 24) { *value = ai; return true; }
    if (ai > 27) return false;
    const size_t n = size_t(1) << (ai - 24);
    if (n > left) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | *p++;
    left -= n;
    if (v < 24 || (n > 1 && v <= (UINT64_MAX >> (64 - 8 * (n / 2)))))
      return false;
    *value = v;
    return true;
  }
  bool exact(uint8_t major, uint64_t expected) {
    uint64_t v = 0;
    return head(major, &v) && v == expected;
  }
  bool bytes(const uint8_t **data, size_t *size) {
    uint64_t n = 0;
    if (!head(2, &n) || n > left) return false;
    *data = p; *size = static_cast<size_t>(n);
    p += *size; left -= *size;
    return true;
  }
};

struct Parsed {
  uint64_t amount, change, fee, ttl, start, inputs;
  bool tagged;
  char recipient[kChainMaxAddress];
};

ChainError parse(const uint8_t *body, size_t size, const char *sender, Parsed *v) {
  if (!body || !sender || !v || !size || size > kChainMaxPayload)
    return ChainError::InvalidArgument;
  memset(v, 0, sizeof(*v));
  Reader r{body, size};
  uint64_t fields = 0;
  if (!r.head(5, &fields) || fields < 4 || fields > 6 || !r.exact(0, 0))
    return ChainError::Malformed;
  if (r.left && (*r.p >> 5) == 6) {
    if (!r.exact(6, 258)) return ChainError::Unsupported;
    v->tagged = true;
  }
  if (!r.head(4, &v->inputs) || !v->inputs || v->inputs > 8)
    return ChainError::Unsupported;
  const uint8_t *previous = nullptr;
  uint64_t previous_index = 0;
  for (uint64_t i = 0; i < v->inputs; ++i) {
    const uint8_t *id = nullptr;
    size_t id_size = 0;
    uint64_t index = 0;
    if (!r.exact(4, 2) || !r.bytes(&id, &id_size) || id_size != 32 ||
        !r.head(0, &index) || index > UINT16_MAX) return ChainError::Malformed;
    // Canonical sorted set: no duplicate outpoints or hidden repeated inputs.
    if (previous) {
      const int cmp = memcmp(previous, id, 32);
      if (cmp > 0 || (cmp == 0 && index <= previous_index))
        return ChainError::Malformed;
    }
    previous = id; previous_index = index;
  }
  uint64_t outputs = 0;
  if (!r.exact(0, 1) || !r.head(4, &outputs) || !outputs || outputs > 2)
    return ChainError::Unsupported;
  for (uint64_t i = 0; i < outputs; ++i) {
    const bool map = r.left && (*r.p >> 5) == 5;
    if (!r.exact(map ? 5 : 4, 2) || (map && !r.exact(0, 0)))
      return ChainError::Unsupported;
    const uint8_t *address = nullptr;
    size_t address_size = 0;
    uint64_t amount = 0;
    if (!r.bytes(&address, &address_size) || !address_size)
      return ChainError::Malformed;
    if ((address[0] & 15) != 1) return ChainError::WrongNetwork;
    // Only key-credential base/enterprise destinations, no script/pointer/Byron.
    if (!((address[0] == 0x01 && address_size == 57) ||
          (address[0] == 0x61 && address_size == 29)))
      return ChainError::Unsupported;
    if ((map && !r.exact(0, 1)) || !r.head(0, &amount))
      return ChainError::Unsupported;  // rejects multiasset and datum/script fields
    if (!amount || amount > kMaxLovelace) return ChainError::InvalidAmount;
    char text[kChainMaxAddress] = {};
    if (!bech32_encode("addr", address, address_size, text, sizeof(text), false))
      return ChainError::CryptoFailure;
    if (!i) {
      v->amount = amount;
      memcpy(v->recipient, text, sizeof(text));
    } else {
      if (strcmp(text, sender)) return ChainError::WrongWallet;
      v->change = amount;
    }
  }
  if (!r.exact(0, 2) || !r.head(0, &v->fee) || !v->fee || v->fee > kMaxFee)
    return ChainError::FeePolicy;
  if (!r.exact(0, 3) || !r.head(0, &v->ttl) || !v->ttl)
    return ChainError::Malformed;
  uint64_t last_key = 3;
  for (uint64_t i = 4; i < fields; ++i) {
    uint64_t key = 0;
    if (!r.head(0, &key) || key <= last_key) return ChainError::Malformed;
    last_key = key;
    if (key == 8) {
      if (!r.head(0, &v->start) || v->start >= v->ttl) return ChainError::Malformed;
    } else if (key == 15) {
      if (!r.exact(0, 1)) return ChainError::WrongNetwork;
    } else {
      return ChainError::Unsupported;
    }
  }
  if (r.left) return ChainError::Malformed;
  if (v->amount > kMaxLovelace - v->change ||
      v->amount + v->change > kMaxLovelace - v->fee)
    return ChainError::InvalidAmount;
  return ChainError::Ok;
}
}  // namespace

ChainError cardano_review_payload(const uint8_t *body, size_t size,
                                  const char *sender, ChainReview *review,
                                  uint8_t digest[32]) {
  if (!review || !digest || !sender || strlen(sender) >= sizeof(review->sender))
    return ChainError::InvalidArgument;
  memset(review, 0, sizeof(*review));
  memset(digest, 0, 32);
  Parsed p{};
  ChainError error = parse(body, size, sender, &p);
  if (error != ChainError::Ok) return error;
  strcpy(review->symbol, "ADA");
  strcpy(review->sender, sender);
  strcpy(review->recipient, p.recipient);
  char change[64] = {};
  if (!chain_format_units(p.amount, 6, "ADA", review->amount, sizeof(review->amount)) ||
      !chain_format_units(p.fee, 6, "ADA", review->fee, sizeof(review->fee)) ||
      !chain_format_units(p.change, 6, "ADA", change, sizeof(change)))
    return ChainError::BufferTooSmall;
  const int n = snprintf(review->extra, sizeof(review->extra),
      "Mainnet; %llu inputs\nSlots %llu..%llu\nChange %s to FROM address\n"
      "ADA only; input ownership/balance checked by node",
      static_cast<unsigned long long>(p.inputs),
      static_cast<unsigned long long>(p.start),
      static_cast<unsigned long long>(p.ttl), change);
  if (n < 0 || static_cast<size_t>(n) >= sizeof(review->extra))
    return ChainError::BufferTooSmall;
  return crypto_blake2b(body, size, digest, 32) ? ChainError::Ok : ChainError::CryptoFailure;
}

ChainError cardano_sign_payload(const uint8_t *body, size_t size,
                                const uint8_t seed[64], uint32_t index,
                                uint8_t *out, size_t *in_out_size) {
  if (!in_out_size) return ChainError::InvalidArgument;
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  if (out) secure_zero(out, capacity);
  if (!out || !seed || index >= 0x80000000UL) return ChainError::InvalidArgument;
  const uint32_t payment_path[] = {0x8000073c, 0x80000717, 0x80000000, 0, index};
  const uint32_t stake_path[] = {0x8000073c, 0x80000717, 0x80000000, 2, 0};
  CardanoKey payment{}, stake{};
  ChainError error = ChainError::CryptoFailure;
  char sender[kChainMaxAddress] = {};
  Parsed p{};
  uint8_t digest[32] = {}, signature[64] = {};
  if (cardano_derive_path(seed, payment_path, 5, &payment) &&
      cardano_derive_path(seed, stake_path, 5, &stake) &&
      address_cardano_base(payment.public_key, stake.public_key, sender,
                           sizeof(sender)) == WalletError::Ok) {
    error = parse(body, size, sender, &p);
    // [body, {0: set< [vkey, signature] >}, true, null]
    const size_t required = size + 107 + (p.tagged ? 3 : 0);
    if (error == ChainError::Ok && capacity < required) error = ChainError::BufferTooSmall;
    if (error == ChainError::Ok &&
        (!crypto_blake2b(body, size, digest, 32) ||
         !ed25519_sign_expanded(payment.kL, payment.kR, digest, 32, signature) ||
         !ed25519_verify(payment.public_key, digest, 32, signature)))
      error = ChainError::CryptoFailure;
    if (error == ChainError::Ok) {
      size_t n = 0;
      out[n++] = 0x84;
      memcpy(out + n, body, size); n += size;
      out[n++] = 0xa1; out[n++] = 0x00;
      if (p.tagged) { out[n++] = 0xd9; out[n++] = 0x01; out[n++] = 0x02; }
      out[n++] = 0x81; out[n++] = 0x82;
      out[n++] = 0x58; out[n++] = 0x20;
      memcpy(out + n, payment.public_key, 32); n += 32;
      out[n++] = 0x58; out[n++] = 0x40;
      memcpy(out + n, signature, 64); n += 64;
      out[n++] = 0xf5; out[n++] = 0xf6;
      *in_out_size = n;
    }
  }
  secure_zero(&payment, sizeof(payment)); secure_zero(&stake, sizeof(stake));
  secure_zero(signature, sizeof(signature)); secure_zero(digest, sizeof(digest));
  return error;
}

bool run_cardano_transaction_self_tests() {
  return run_cardano_derivation_self_tests();
}
}  // namespace hexwallet
