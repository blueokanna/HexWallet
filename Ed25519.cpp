#include "CryptoExtended.h"

#include <mbedtls/md.h>
#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

typedef int64_t fe[10];

uint64_t load_le64_word(const uint8_t *data);

// ---------------------------------------------------------------------------
// Field arithmetic mod 2^255 - 19 (25.5-bit limbs).
// ---------------------------------------------------------------------------

void fe_0(fe out) {
  for (int index = 0; index < 10; ++index) out[index] = 0;
}

void fe_1(fe out) {
  fe_0(out);
  out[0] = 1;
}

void fe_copy(fe out, const fe value) {
  for (int index = 0; index < 10; ++index) out[index] = value[index];
}

void fe_add(fe out, const fe left, const fe right) {
  for (int index = 0; index < 10; ++index) out[index] = left[index] + right[index];
}

void fe_sub(fe out, const fe left, const fe right) {
  for (int index = 0; index < 10; ++index) out[index] = left[index] - right[index];
}

int64_t load_26(const uint8_t *data) {
  return static_cast<int64_t>(data[0]) | (static_cast<int64_t>(data[1]) << 8) | (static_cast<int64_t>(data[2]) << 16) | (static_cast<int64_t>(data[3]) << 24) | (static_cast<int64_t>(data[4]) << 32);
}

int64_t load_25(const uint8_t *data) {
  return static_cast<int64_t>(data[0]) | (static_cast<int64_t>(data[1]) << 8) | (static_cast<int64_t>(data[2]) << 16) | (static_cast<int64_t>(data[3]) << 24);
}

int64_t load_3(const uint8_t *data) {
  return static_cast<int64_t>(data[0]) | (static_cast<int64_t>(data[1]) << 8) | (static_cast<int64_t>(data[2]) << 16);
}

int64_t load_4(const uint8_t *data) {
  return static_cast<int64_t>(data[0]) | (static_cast<int64_t>(data[1]) << 8) | (static_cast<int64_t>(data[2]) << 16) | (static_cast<int64_t>(data[3]) << 24);
}

void store_26(uint8_t *out, int64_t value) {
  const uint32_t v = static_cast<uint32_t>(value);
  out[0] = static_cast<uint8_t>(v);
  out[1] = static_cast<uint8_t>(v >> 8);
  out[2] = static_cast<uint8_t>(v >> 16);
  out[3] = static_cast<uint8_t>(v >> 24);
  out[4] = 0;  // 26-bit value never occupies byte 4
}

void store_25(uint8_t *out, int64_t value) {
  const uint32_t v = static_cast<uint32_t>(value);
  out[0] = static_cast<uint8_t>(v);
  out[1] = static_cast<uint8_t>(v >> 8);
  out[2] = static_cast<uint8_t>(v >> 16);
  out[3] = static_cast<uint8_t>(v >> 24);
}

// Decode a canonical little-endian 32-byte field element (sign bit ignored).
// The 256-bit value is split into four 64-bit words and each limb is extracted
// by its exact bit range (ref10 layout: 26/25/26/25/26/25/26/25/26/25). This
// avoids the subtle rounding carries of the classic ref10 decoder and yields a
// canonical representation directly.
void fe_frombytes(fe out, const uint8_t *data) {
  uint64_t v[4];
  for (int i = 0; i < 4; ++i) v[i] = load_le64_word(data + i * 8);
  v[3] &= UINT64_C(0x7fffffffffffffff);  // ignore the sign bit (bit 255)

  static const int kOffsets[10] = { 0, 26, 51, 77, 102, 128, 153, 179, 204, 230 };
  static const int kSizes[10] = { 26, 25, 26, 25, 26, 25, 26, 25, 26, 25 };
  for (int limb = 0; limb < 10; ++limb) {
    const int start = kOffsets[limb];
    const int count = kSizes[limb];
    uint64_t result = 0;
    for (int bit = 0; bit < count; ++bit) {
      const int position = start + bit;
      result |= ((v[position / 64] >> (position % 64)) & 1) << bit;
    }
    out[limb] = static_cast<int64_t>(result);
  }
}

// Canonical little-endian encoding with the top bit left for the x sign.
void fe_tobytes(uint8_t *out, const fe value) {
  int64_t h0 = value[0], h1 = value[1], h2 = value[2], h3 = value[3], h4 = value[4];
  int64_t h5 = value[5], h6 = value[6], h7 = value[7], h8 = value[8], h9 = value[9];

  int64_t q = (19 * h9 + (INT64_C(1) << 24)) >> 25;
  q = (h0 + q) >> 26;
  q = (h1 + q) >> 25;
  q = (h2 + q) >> 26;
  q = (h3 + q) >> 25;
  q = (h4 + q) >> 26;
  q = (h5 + q) >> 25;
  q = (h6 + q) >> 26;
  q = (h7 + q) >> 25;
  q = (h8 + q) >> 26;
  q = (h9 + q) >> 25;

  h0 += 19 * q;
  // NOTE: carry limbs can be negative (fe_sub produces negative limbs), and
  // left-shifting a negative value is UB in C++17 (MSVC happens to keep the
  // 2's-complement result, clang optimizes assuming it cannot happen). Use
  // multiplication by a positive power of two instead, which is equivalent
  // and fully defined.
  int64_t carry0 = h0 >> 26;
  h1 += carry0;
  h0 -= carry0 * (INT64_C(1) << 26);
  int64_t carry1 = h1 >> 25;
  h2 += carry1;
  h1 -= carry1 * (INT64_C(1) << 25);
  int64_t carry2 = h2 >> 26;
  h3 += carry2;
  h2 -= carry2 * (INT64_C(1) << 26);
  int64_t carry3 = h3 >> 25;
  h4 += carry3;
  h3 -= carry3 * (INT64_C(1) << 25);
  int64_t carry4 = h4 >> 26;
  h5 += carry4;
  h4 -= carry4 * (INT64_C(1) << 26);
  int64_t carry5 = h5 >> 25;
  h6 += carry5;
  h5 -= carry5 * (INT64_C(1) << 25);
  int64_t carry6 = h6 >> 26;
  h7 += carry6;
  h6 -= carry6 * (INT64_C(1) << 26);
  int64_t carry7 = h7 >> 25;
  h8 += carry7;
  h7 -= carry7 * (INT64_C(1) << 25);
  int64_t carry8 = h8 >> 26;
  h9 += carry8;
  h8 -= carry8 * (INT64_C(1) << 26);
  int64_t carry9 = h9 >> 25;
  h9 -= carry9 * (INT64_C(1) << 25);

  // ref10 bit packing: limbs sit on 25.5-bit boundaries. Each byte carries
  // the tail of one limb and the head of the next, except where a limb ends
  // exactly on a byte boundary (h4 ends at bit 127).
  out[0] = (uint8_t)h0;
  out[1] = (uint8_t)(h0 >> 8);
  out[2] = (uint8_t)(h0 >> 16);
  out[3] = (uint8_t)((h0 >> 24) | ((int64_t)h1 << 2));
  out[4] = (uint8_t)(h1 >> 6);
  out[5] = (uint8_t)(h1 >> 14);
  out[6] = (uint8_t)((h1 >> 22) | ((int64_t)h2 << 3));
  out[7] = (uint8_t)(h2 >> 5);
  out[8] = (uint8_t)(h2 >> 13);
  out[9] = (uint8_t)((h2 >> 21) | ((int64_t)h3 << 5));
  out[10] = (uint8_t)(h3 >> 3);
  out[11] = (uint8_t)(h3 >> 11);
  out[12] = (uint8_t)((h3 >> 19) | ((int64_t)h4 << 6));
  out[13] = (uint8_t)(h4 >> 2);
  out[14] = (uint8_t)(h4 >> 10);
  out[15] = (uint8_t)(h4 >> 18);
  out[16] = (uint8_t)h5;  // h4 ends at bit 127; byte 16 starts h5.
  out[17] = (uint8_t)(h5 >> 8);
  out[18] = (uint8_t)(h5 >> 16);
  out[19] = (uint8_t)((h5 >> 24) | ((int64_t)h6 << 1));
  out[20] = (uint8_t)(h6 >> 7);
  out[21] = (uint8_t)(h6 >> 15);
  out[22] = (uint8_t)((h6 >> 23) | ((int64_t)h7 << 3));
  out[23] = (uint8_t)(h7 >> 5);
  out[24] = (uint8_t)(h7 >> 13);
  out[25] = (uint8_t)((h7 >> 21) | ((int64_t)h8 << 4));
  out[26] = (uint8_t)(h8 >> 4);
  out[27] = (uint8_t)(h8 >> 12);
  out[28] = (uint8_t)((h8 >> 20) | ((int64_t)h9 << 6));
  out[29] = (uint8_t)(h9 >> 2);
  out[30] = (uint8_t)(h9 >> 10);
  out[31] = (uint8_t)(h9 >> 18);
}

// fe_mul: weighted limb convolution on the 25.5-bit layout. The 38/2/19
// coefficients come from the exact exponent arithmetic of the offsets
// (0,26,51,77,102,128,153,179,204,230); a plain all-19 schoolbook form is
// WRONG here because cross terms land at 255 vs 256 (19 vs 38) exponents.
void fe_mul(fe out, const fe left, const fe right) {
  const int64_t f0 = left[0], f1 = left[1], f2 = left[2], f3 = left[3], f4 = left[4];
  const int64_t f5 = left[5], f6 = left[6], f7 = left[7], f8 = left[8], f9 = left[9];
  const int64_t g0 = right[0], g1 = right[1], g2 = right[2], g3 = right[3], g4 = right[4];
  const int64_t g5 = right[5], g6 = right[6], g7 = right[7], g8 = right[8], g9 = right[9];

  int64_t h0 = f0 * g0 + 38 * f1 * g9 + 19 * f2 * g8 + 38 * f3 * g7 + 19 * f4 * g6 + 38 * f5 * g5 + 19 * f6 * g4 + 38 * f7 * g3 + 19 * f8 * g2 + 38 * f9 * g1;
  int64_t h1 = f0 * g1 + f1 * g0 + 19 * f2 * g9 + 19 * f3 * g8 + 19 * f4 * g7 + 19 * f5 * g6 + 19 * f6 * g5 + 19 * f7 * g4 + 19 * f8 * g3 + 19 * f9 * g2;
  int64_t h2 = f0 * g2 + 2 * f1 * g1 + f2 * g0 + 38 * f3 * g9 + 19 * f4 * g8 + 38 * f5 * g7 + 19 * f6 * g6 + 38 * f7 * g5 + 19 * f8 * g4 + 38 * f9 * g3;
  int64_t h3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + 19 * f4 * g9 + 19 * f5 * g8 + 19 * f6 * g7 + 19 * f7 * g6 + 19 * f8 * g5 + 19 * f9 * g4;
  int64_t h4 = f0 * g4 + 2 * f1 * g3 + f2 * g2 + 2 * f3 * g1 + f4 * g0 + 38 * f5 * g9 + 19 * f6 * g8 + 38 * f7 * g7 + 19 * f8 * g6 + 38 * f9 * g5;
  int64_t h5 = f0 * g5 + f1 * g4 + f2 * g3 + f3 * g2 + f4 * g1 + f5 * g0 + 19 * f6 * g9 + 19 * f7 * g8 + 19 * f8 * g7 + 19 * f9 * g6;
  int64_t h6 = f0 * g6 + 2 * f1 * g5 + f2 * g4 + 2 * f3 * g3 + f4 * g2 + 2 * f5 * g1 + f6 * g0 + 38 * f7 * g9 + 19 * f8 * g8 + 38 * f9 * g7;
  int64_t h7 = f0 * g7 + f1 * g6 + f2 * g5 + f3 * g4 + f4 * g3 + f5 * g2 + f6 * g1 + f7 * g0 + 19 * f8 * g9 + 19 * f9 * g8;
  int64_t h8 = f0 * g8 + 2 * f1 * g7 + f2 * g6 + 2 * f3 * g5 + f4 * g4 + 2 * f5 * g3 + f6 * g2 + 2 * f7 * g1 + f8 * g0 + 38 * f9 * g9;
  int64_t h9 = f0 * g9 + f1 * g8 + f2 * g7 + f3 * g6 + f4 * g5 + f5 * g4 + f6 * g3 + f7 * g2 + f8 * g1 + f9 * g0;

  static const int kSizes[10] = { 26, 25, 26, 25, 26, 25, 26, 25, 26, 25 };
  // Full reduction: propagate carries limb by limb, then fold h9's top with
  // the 2^255 == 19 rule. Repeat until stable (three passes suffice for the
  // bounded products below). Negative carry limbs are possible (fe_sub), so
  // scale with multiplication, never a left shift of a negative value (UB).
  for (int pass = 0; pass < 3; ++pass) {
    int64_t h[10] = { h0, h1, h2, h3, h4, h5, h6, h7, h8, h9 };
    int64_t c = 0;
    for (int i = 0; i < 9; ++i) {
      c = h[i] >> kSizes[i];
      h[i + 1] += c;
      h[i] -= c * (INT64_C(1) << kSizes[i]);
    }
    c = h[9] >> kSizes[9];
    h[9] -= c * (INT64_C(1) << kSizes[9]);
    h[0] += 19 * c;
    h0 = h[0];
    h1 = h[1];
    h2 = h[2];
    h3 = h[3];
    h4 = h[4];
    h5 = h[5];
    h6 = h[6];
    h7 = h[7];
    h8 = h[8];
    h9 = h[9];
  }

  out[0] = h0;
  out[1] = h1;
  out[2] = h2;
  out[3] = h3;
  out[4] = h4;
  out[5] = h5;
  out[6] = h6;
  out[7] = h7;
  out[8] = h8;
  out[9] = h9;
}

void fe_sq(fe out, const fe value) {
  fe_mul(out, value, value);
}

void fe_invert(fe out, const fe value) {
  fe t0, t1, t2, t3;
  fe_sq(t0, value);
  fe_sq(t1, t0);
  fe_sq(t1, t1);
  fe_mul(t1, value, t1);
  fe_mul(t0, t0, t1);
  fe_sq(t2, t0);
  fe_mul(t1, t1, t2);
  fe_sq(t2, t1);
  for (int index = 1; index < 5; ++index) fe_sq(t2, t2);
  fe_mul(t1, t2, t1);
  fe_sq(t2, t1);
  for (int index = 1; index < 10; ++index) fe_sq(t2, t2);
  fe_mul(t2, t2, t1);
  fe_sq(t3, t2);
  for (int index = 1; index < 20; ++index) fe_sq(t3, t3);
  fe_mul(t2, t3, t2);
  fe_sq(t2, t2);
  for (int index = 1; index < 10; ++index) fe_sq(t2, t2);
  fe_mul(t1, t2, t1);
  fe_sq(t2, t1);
  for (int index = 1; index < 50; ++index) fe_sq(t2, t2);
  fe_mul(t2, t2, t1);
  fe_sq(t3, t2);
  for (int index = 1; index < 100; ++index) fe_sq(t3, t3);
  fe_mul(t2, t3, t2);
  fe_sq(t2, t2);
  for (int index = 1; index < 50; ++index) fe_sq(t2, t2);
  fe_mul(t1, t2, t1);
  fe_sq(t1, t1);
  for (int index = 1; index < 5; ++index) fe_sq(t1, t1);
  fe_mul(out, t1, t0);
  secure_zero(t0, sizeof(t0));
  secure_zero(t1, sizeof(t1));
  secure_zero(t2, sizeof(t2));
  secure_zero(t3, sizeof(t3));
}

// ---------------------------------------------------------------------------
// Scalar arithmetic mod L = 2^252 + 27742317777372353535851937790883648493.
// ---------------------------------------------------------------------------

uint64_t load_le64_word(const uint8_t *data) {
  uint64_t value = 0;
  for (int index = 0; index < 8; ++index) {
    value |= static_cast<uint64_t>(data[index]) << (index * 8);
  }
  return value;
}

void store_le64_word(uint8_t *out, uint64_t value) {
  for (int index = 0; index < 8; ++index) {
    out[index] = static_cast<uint8_t>(value >> (index * 8));
  }
}

// 256-bit little-endian comparison as big-endian integers.
bool ge_ge_words(const uint64_t left[4], const uint64_t right[4]) {
  for (int index = 3; index >= 0; --index) {
    if (left[index] > right[index]) return true;
    if (left[index] < right[index]) return false;
  }
  return true;
}

void sub_words(uint64_t out[4], const uint64_t right[4], const uint64_t left[4]) {
  uint64_t borrow = 0;
  for (int index = 0; index < 4; ++index) {
    const uint64_t subtrahend = right[index] + borrow;
    out[index] = left[index] - subtrahend;
    borrow = left[index] < subtrahend ? 1 : 0;
  }
}

// out = value mod L by binary long division. acc is kept below L at every
// step, so the running remainder after consuming every bit is the answer.
void reduce_mod_l(uint64_t *value, size_t word_count, uint8_t out[32]) {
  static const uint64_t kL[4] = {
    UINT64_C(0x5812631a5cf5d3ed),
    UINT64_C(0x14def9dea2f79cd6),
    UINT64_C(0x0000000000000000),
    UINT64_C(0x1000000000000000),
  };
  uint64_t acc[4] = { 0, 0, 0, 0 };

  const size_t total_bits = word_count * 64;
  for (size_t bit = total_bits; bit-- > 0;) {
    const uint64_t incoming = (value[bit / 64] >> (bit % 64)) & 1;
    for (int index = 3; index > 0; --index) {
      acc[index] = (acc[index] << 1) | (acc[index - 1] >> 63);
    }
    acc[0] = (acc[0] << 1) | incoming;
    if (ge_ge_words(acc, kL)) {
      uint64_t tmp[4];
      sub_words(tmp, kL, acc);
      memcpy(acc, tmp, sizeof(acc));
    }
  }
  for (int index = 0; index < 4; ++index) {
    store_le64_word(out + index * 8, acc[index]);
  }
  secure_zero(acc, sizeof(acc));
}

void sc_reduce_32(uint8_t scalar[32]) {
  uint64_t words[4];
  for (int index = 0; index < 4; ++index) {
    words[index] = load_le64_word(scalar + index * 8);
  }
  reduce_mod_l(words, 4, scalar);
  secure_zero(words, sizeof(words));
}

// Reduce a full 64-byte (512-bit) little-endian digest mod L, writing the
// 32-byte result. RFC 8032 section 5.1.6 requires interpreting the WHOLE
// 64-octet SHA-512 digest as the integer r (and k), not just its low 256
// bits; reducing only the low half produces wrong signatures.
void sc_reduce_64(const uint8_t digest[64], uint8_t out[32]) {
  uint64_t words[8];
  for (int index = 0; index < 8; ++index) {
    words[index] = load_le64_word(digest + index * 8);
  }
  reduce_mod_l(words, 8, out);
  secure_zero(words, sizeof(words));
}

// Portable 64-bit add/mul with carry (MSVC has no __int128).
static uint64_t add64_carry(uint64_t a, uint64_t b, uint64_t carry_in,
                            uint64_t *carry_out) {
  uint64_t s = a + b;
  uint64_t c = (s < a) ? 1 : 0;
  uint64_t s2 = s + carry_in;
  *carry_out = c | ((s2 < s) ? 1 : 0);
  return s2;
}

static uint64_t mul64_hi(uint64_t a, uint64_t b) {
  uint64_t a_lo = a & 0xFFFFFFFFULL, a_hi = a >> 32;
  uint64_t b_lo = b & 0xFFFFFFFFULL, b_hi = b >> 32;
  uint64_t ll = a_lo * b_lo;
  uint64_t lh = a_lo * b_hi;
  uint64_t hl = a_hi * b_lo;
  uint64_t hh = a_hi * b_hi;
  uint64_t mid = (ll >> 32) + (lh & 0xFFFFFFFFULL) + (hl & 0xFFFFFFFFULL);
  return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

static uint64_t mul64_add_carry(uint64_t a, uint64_t b, uint64_t add,
                                uint64_t carry_in, uint64_t *carry_out) {
  uint64_t lo = a * b;
  uint64_t hi = mul64_hi(a, b);
  uint64_t s1 = lo + add;
  hi += (s1 < lo) ? 1 : 0;
  uint64_t s2 = s1 + carry_in;
  hi += (s2 < s1) ? 1 : 0;
  *carry_out = hi;
  return s2;
}

// out = (a * b + c) mod L, all 32-byte little-endian.
void sc_muladd(uint8_t out[32], const uint8_t *a, const uint8_t *b,
               const uint8_t *c) {
  uint64_t aw[4], bw[4], cw[4];
  for (int index = 0; index < 4; ++index) {
    aw[index] = load_le64_word(a + index * 8);
    bw[index] = load_le64_word(b + index * 8);
    cw[index] = load_le64_word(c + index * 8);
  }
  uint64_t wide[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
  for (int i = 0; i < 4; ++i) {
    uint64_t carry = 0;
    for (int j = 0; j < 4; ++j) {
      wide[i + j] = mul64_add_carry(aw[i], bw[j], wide[i + j], carry, &carry);
    }
    /* Column i + 4 is zero here (row i-1 reaches only column i + 3). */
    wide[i + 4] = carry;
  }
  uint64_t carry = 0;
  for (int index = 0; index < 4; ++index) {
    wide[index] = add64_carry(wide[index], cw[index], carry, &carry);
  }
  for (int index = 4; index < 8 && carry; ++index) {
    uint64_t next = 0;
    wide[index] = add64_carry(wide[index], 0, carry, &next);
    carry = next;
  }
  reduce_mod_l(wide, 8, out);
  secure_zero(aw, sizeof(aw));
  secure_zero(bw, sizeof(bw));
  secure_zero(cw, sizeof(cw));
  secure_zero(wide, sizeof(wide));
}

// ---------------------------------------------------------------------------
// Ed25519 curve group (affine formulas from RFC 8032).
// ---------------------------------------------------------------------------

// d = -121665/121666 mod 2^255-19 (RFC 8032).
const uint8_t kEdwardsD[32] = {
  0xa3,
  0x78,
  0x59,
  0x13,
  0xca,
  0x4d,
  0xeb,
  0x75,
  0xab,
  0xd8,
  0x41,
  0x41,
  0x4d,
  0x0a,
  0x70,
  0x00,
  0x98,
  0xe8,
  0x79,
  0x77,
  0x79,
  0x40,
  0xc7,
  0x8c,
  0x73,
  0xfe,
  0x6f,
  0x2b,
  0xee,
  0x6c,
  0x03,
  0x52,
};

// Base point: y = 4/5, x = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a.
const uint8_t kBaseY[32] = {
  0x58,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
  0x66,
};
const uint8_t kBaseX[32] = {
  0x1a,
  0xd5,
  0x25,
  0x8f,
  0x60,
  0x2d,
  0x56,
  0xc9,
  0xb2,
  0xa7,
  0x25,
  0x95,
  0x60,
  0xc7,
  0x2c,
  0x69,
  0x5c,
  0xdc,
  0xd6,
  0xfd,
  0x31,
  0xe2,
  0xa4,
  0xc0,
  0xfe,
  0x53,
  0x6e,
  0xcd,
  0xd3,
  0x36,
  0x69,
  0x21,
};

// (x3, y3) = (x1, y1) + (x2, y2) on edwards25519 (RFC 8032 formulas).
void edwards_add(fe x3, fe y3, const fe x1, const fe y1, const fe x2,
                 const fe y2) {
  fe d_fe;
  fe_frombytes(d_fe, kEdwardsD);
  fe t0, t1, t2, t3, t4;
  fe_mul(t0, x1, x2);    // x1*x2
  fe_mul(t1, y1, y2);    // y1*y2
  fe_mul(t2, t0, t1);    // x1*x2*y1*y2
  fe_mul(t3, d_fe, t2);  // d * x1*x2*y1*y2
  fe_1(t4);
  fe_add(t4, t4, t3);  // 1 + d*...
  fe_invert(t4, t4);
  // x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
  fe_mul(x3, x1, y2);
  fe_mul(t2, x2, y1);
  fe_add(x3, x3, t2);
  fe_mul(x3, x3, t4);
  // y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
  fe_1(t4);
  fe_sub(t4, t4, t3);
  fe_invert(t4, t4);
  fe_add(y3, t1, t0);  // y1*y2 + x1*x2
  fe_mul(y3, y3, t4);
  secure_zero(d_fe, sizeof(d_fe));
  secure_zero(t0, sizeof(t0));
  secure_zero(t1, sizeof(t1));
  secure_zero(t2, sizeof(t2));
  secure_zero(t3, sizeof(t3));
  secure_zero(t4, sizeof(t4));
}

// Multiply the base point by a 32-byte little-endian scalar (MSB-first walk).
void scalarmult_base(fe rx, fe ry, const uint8_t *scalar) {
  fe bx, by, tx, ty, dbl_x, dbl_y;
  fe_frombytes(bx, kBaseX);
  fe_frombytes(by, kBaseY);
  fe_0(rx);
  fe_1(ry);  // identity (0, 1)
  for (int bit = 255; bit >= 0; --bit) {
    edwards_add(dbl_x, dbl_y, rx, ry, rx, ry);
    fe_copy(rx, dbl_x);
    fe_copy(ry, dbl_y);
    if ((scalar[bit / 8] >> (bit % 8)) & 1) {
      edwards_add(tx, ty, rx, ry, bx, by);
      fe_copy(rx, tx);
      fe_copy(ry, ty);
    }
  }
  secure_zero(bx, sizeof(bx));
  secure_zero(by, sizeof(by));
  secure_zero(tx, sizeof(tx));
  secure_zero(ty, sizeof(ty));
  secure_zero(dbl_x, sizeof(dbl_x));
  secure_zero(dbl_y, sizeof(dbl_y));
}

void encode_point(uint8_t out[32], const fe x, const fe y) {
  fe_tobytes(out, y);
  const uint8_t sign = static_cast<uint8_t>(x[0] & 1);
  out[31] ^= static_cast<uint8_t>(sign << 7);
}

bool sha512(const uint8_t *data, size_t size, uint8_t out[64]) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  return info != nullptr && mbedtls_md(info, data, size, out) == 0;
}

}  // namespace

bool ed25519_public_key(const uint8_t seed[32], uint8_t out_public[32]) {
  if (seed == nullptr || out_public == nullptr) return false;
  uint8_t hash[64];
  if (!sha512(seed, 32, hash)) return false;
  hash[0] &= 248;
  hash[31] &= 127;
  hash[31] |= 64;
  fe rx, ry;
  scalarmult_base(rx, ry, hash);
  encode_point(out_public, rx, ry);
  secure_zero(hash, sizeof(hash));
  secure_zero(rx, sizeof(rx));
  secure_zero(ry, sizeof(ry));
  return true;
}

bool ed25519_sign(const uint8_t seed[32], const uint8_t *message,
                  size_t message_size, uint8_t out_signature[64]) {
  if (seed == nullptr || out_signature == nullptr || (message == nullptr && message_size != 0)) {
    return false;
  }
  uint8_t hash[64];
  uint8_t public_key[32];
  uint8_t r_digest[64];
  uint8_t r_scalar[32];
  uint8_t k_bytes[64];
  if (!sha512(seed, 32, hash)) return false;
  hash[0] &= 248;
  hash[31] &= 127;
  hash[31] |= 64;

  fe rx, ry;
  scalarmult_base(rx, ry, hash);
  encode_point(public_key, rx, ry);

  // r = SHA512(hash[32..64] || M); reduce the FULL 64-octet digest mod L
  // (RFC 8032 5.1.6: "Interpret the 64-octet digest as a little-endian
  // integer r"). Reducing only the low 32 bytes gives wrong signatures.
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  bool ok = info != nullptr;
  if (ok) ok = mbedtls_md_setup(&context, info, 0) == 0;
  if (ok) ok = mbedtls_md_starts(&context) == 0;
  if (ok) ok = mbedtls_md_update(&context, hash + 32, 32) == 0;
  if (ok && message_size != 0) ok = mbedtls_md_update(&context, message, message_size) == 0;
  if (ok) ok = mbedtls_md_finish(&context, r_digest) == 0;
  mbedtls_md_free(&context);
  if (!ok) {
    secure_zero(hash, sizeof(hash));
    secure_zero(r_digest, sizeof(r_digest));
    secure_zero(k_bytes, sizeof(k_bytes));
    return false;
  }
  sc_reduce_64(r_digest, r_scalar);

  // R = [r]B
  scalarmult_base(rx, ry, r_scalar);
  uint8_t r_encoded[32];
  encode_point(r_encoded, rx, ry);

  // k = SHA512(R || A || M); reduce the FULL 64-octet digest mod L.
  mbedtls_md_init(&context);
  ok = mbedtls_md_setup(&context, info, 0) == 0;
  if (ok) ok = mbedtls_md_starts(&context) == 0;
  if (ok) ok = mbedtls_md_update(&context, r_encoded, 32) == 0;
  if (ok) ok = mbedtls_md_update(&context, public_key, 32) == 0;
  if (ok && message_size != 0) ok = mbedtls_md_update(&context, message, message_size) == 0;
  if (ok) ok = mbedtls_md_finish(&context, k_bytes) == 0;
  mbedtls_md_free(&context);
  if (!ok) {
    secure_zero(hash, sizeof(hash));
    secure_zero(r_digest, sizeof(r_digest));
    secure_zero(r_scalar, sizeof(r_scalar));
    secure_zero(k_bytes, sizeof(k_bytes));
    secure_zero(r_encoded, sizeof(r_encoded));
    return false;
  }
  uint8_t k_scalar[32];
  sc_reduce_64(k_bytes, k_scalar);

  // S = (r + k*a) mod L
  uint8_t s_scalar[32];
  sc_muladd(s_scalar, k_scalar, hash, r_scalar);

  memcpy(out_signature, r_encoded, 32);
  memcpy(out_signature + 32, s_scalar, 32);

  secure_zero(hash, sizeof(hash));
  secure_zero(public_key, sizeof(public_key));
  secure_zero(r_digest, sizeof(r_digest));
  secure_zero(r_scalar, sizeof(r_scalar));
  secure_zero(k_bytes, sizeof(k_bytes));
  secure_zero(k_scalar, sizeof(k_scalar));
  secure_zero(r_encoded, sizeof(r_encoded));
  secure_zero(s_scalar, sizeof(s_scalar));
  secure_zero(rx, sizeof(rx));
  secure_zero(ry, sizeof(ry));
  return true;
}

bool slip10_ed25519_derive(const uint8_t *seed, size_t seed_size,
                           const uint32_t *path, size_t path_size,
                           uint8_t out_private[32]) {
  if (seed == nullptr || seed_size == 0 || out_private == nullptr || (path == nullptr && path_size != 0)) {
    return false;
  }
  static const uint8_t kSlip10Key[] = "ed25519 seed";
  uint8_t i[64];
  uint8_t private_key[32];
  uint8_t chain_code[32];
  if (!crypto_hmac_sha512(kSlip10Key, sizeof(kSlip10Key) - 1, seed, seed_size, i)) {
    return false;
  }
  memcpy(private_key, i, 32);
  memcpy(chain_code, i + 32, 32);
  secure_zero(i, sizeof(i));

  for (size_t depth = 0; depth < path_size; ++depth) {
    uint8_t data[1 + 32 + 4];
    data[0] = 0x00;
    memcpy(data + 1, private_key, 32);
    const uint32_t index = path[depth] | kHardenedOffset;
    data[33] = static_cast<uint8_t>(index >> 24);
    data[34] = static_cast<uint8_t>(index >> 16);
    data[35] = static_cast<uint8_t>(index >> 8);
    data[36] = static_cast<uint8_t>(index);
    if (!crypto_hmac_sha512(chain_code, 32, data, sizeof(data), i)) {
      secure_zero(private_key, sizeof(private_key));
      secure_zero(chain_code, sizeof(chain_code));
      secure_zero(data, sizeof(data));
      return false;
    }
    memcpy(private_key, i, 32);
    memcpy(chain_code, i + 32, 32);
    secure_zero(data, sizeof(data));
    secure_zero(i, sizeof(i));
  }
  memcpy(out_private, private_key, 32);
  secure_zero(private_key, sizeof(private_key));
  secure_zero(chain_code, sizeof(chain_code));
  return true;
}

}  // namespace hexwallet
