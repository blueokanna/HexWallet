#ifndef HEXWALLET_PRIVACY_RING_OPS_H
#define HEXWALLET_PRIVACY_RING_OPS_H

#include <string.h>
#include "CryptoExtended.h"
#include "CryptoNoteRingCt.h"
#include "CryptoPrimitives.h"
#include "SensitiveValue.h"
#include "keccak256.h"

// Internal arithmetic shared by the Ryo and Zano signing backends. No wire
// decoding or wallet policy belongs here. Public multiscalar routines must
// never receive private scalars or nonce material.
namespace hexwallet { namespace privacy {
constexpr uint8_t kZero[32] = {};
constexpr uint8_t kOne[32] = {1};
constexpr uint8_t kZanoX[32] = {
    0x3a,0x25,0xbc,0xdb,0x43,0xf5,0xd2,0xc9,0xdd,0x06,0x3d,0xc3,0x9a,0x9e,0x09,0x87,
    0xba,0xfc,0x6f,0xcf,0x2d,0xf1,0xbc,0x76,0x32,0x2d,0x75,0x88,0x4a,0x4a,0x38,0x20};
constexpr uint8_t kG[32] = {
    0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66};
constexpr uint8_t kOrder[32] = {
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
constexpr uint8_t kInv8[32] = {
    0x79,0x2f,0xdc,0xe2,0x29,0xe5,0x06,0x61,0xd0,0xda,0x1c,0x7d,0xb3,0x9d,0xd3,0x07,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x06};

inline bool equal(const uint8_t *a, const uint8_t *b) {
  return crypto_constant_time_equal(a, b, 32);
}
inline bool scalar(const uint8_t *s, bool allow_zero = true) {
  if (!s) return false;
  SensitiveValue<uint8_t[32]> reduced;
  memcpy(reduced.get(), s, 32);
  ed25519_scalar_reduce_mod_l(reduced.get());
  return equal(s, reduced.get()) && (allow_zero || !equal(s, kZero));
}
inline bool point(const uint8_t *p, bool allow_identity = false) {
  uint8_t check[32];
  return p && (allow_identity || !equal(p, kOne)) &&
      ed25519_point_mul_compressed(p, kOrder, check) && equal(check, kOne);
}
inline bool mul(const uint8_t *p, const uint8_t *s, uint8_t *out) {
  return ed25519_point_mul_compressed(p, s, out);
}
inline void smul(const uint8_t *a, const uint8_t *b, uint8_t *out) {
  ed25519_scalar_muladd(out, a, b, kZero);
}

class Transcript {
 public:
  Transcript() { keccak_init(&ctx_); }
  bool add(const uint8_t *p, size_t n = 32) {
    ok_ = ok_ && p && keccak_update(&ctx_, p, n);
    return ok_;
  }
  bool hash(uint8_t *out) { return ok_ && keccak_final(&ctx_, out); }
  bool challenge(uint8_t *out) {
    if (!hash(out)) return false;
    ed25519_scalar_reduce_mod_l(out);
    return true;
  }
 private:
  SHA3_CTX ctx_{};
  bool ok_ = true;
};

// Hedge device entropy with the private witnesses and the complete public
// transcript. Repeating entropy across different rings/messages cannot repeat
// the real nonce. Role and position use fixed-width, little-endian encoding.
class Nonces {
 public:
  bool init(const char *domain, const uint8_t *witnesses, size_t size,
            const uint8_t binding[32], const uint8_t entropy[32], size_t index) {
    if (!domain || !witnesses || !entropy || index > UINT32_MAX) return false;
    SensitiveValue<uint8_t[128]> input;
    const size_t n = strlen(domain);
    if (n > 59) return false;
    memcpy(input.get(), domain, n);
    memcpy(input.get() + 60, binding, 32);
    memcpy(input.get() + 92, entropy, 32);
    for (size_t i = 0; i < 4; ++i)
      input.get()[124 + i] = static_cast<uint8_t>(index >> (8 * i));
    return crypto_hmac_sha512(witnesses, size, input.get(), 128, key_.get());
  }
  bool get(uint8_t role, size_t index, uint8_t out[32]) const {
    if (index > UINT32_MAX) return false;
    uint8_t input[5] = {role};
    for (size_t i = 0; i < 4; ++i)
      input[1 + i] = static_cast<uint8_t>(index >> (8 * i));
    SensitiveValue<uint8_t[64]> wide;
    if (!crypto_hmac_sha512(key_.get(), 64, input, sizeof(input), wide.get()))
      return false;
    ed25519_scalar_reduce_wide(wide.get(), out);
    return !equal(out, kZero);
  }
 private:
  SensitiveValue<uint8_t[64]> key_;
};

// Constant-time products also for decoy responses: before publication, those
// responses are private nonce material. Public verification can use Shamir.
inline bool combination(const uint8_t *p, const uint8_t *a,
                        const uint8_t *q, const uint8_t *b, uint8_t *out,
                        bool signing) {
  if (!signing) return ed25519_double_scalar_mul(p, a, q, b, out);
  uint8_t pa[32], qb[32];
  return mul(p, a, pa) && mul(q, b, qb) &&
      ed25519_point_add_compressed(pa, qb, out);
}
}}  // namespace hexwallet::privacy
#endif
