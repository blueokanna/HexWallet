#include "CryptoExtended.h"

#include <mbedtls/md.h>
#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

typedef int64_t fe[10];

void fe_cmov(fe out, const fe a, const fe b, int flag);

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

// Full 32-byte field decode used by CryptoNote's ge_fromfe_frombytes_vartime.
// Unlike fe_frombytes(), bit 255 is part of the value, not an x sign bit.
void fe_frombytes_full(fe out, const uint8_t *data) {
  int64_t h0 = static_cast<int64_t>(data[0]) |
               (static_cast<int64_t>(data[1]) << 8) |
               (static_cast<int64_t>(data[2]) << 16) |
               (static_cast<int64_t>(data[3]) << 24);
  int64_t h1 = (static_cast<int64_t>(data[4]) |
                (static_cast<int64_t>(data[5]) << 8) |
                (static_cast<int64_t>(data[6]) << 16)) << 6;
  int64_t h2 = (static_cast<int64_t>(data[7]) |
                (static_cast<int64_t>(data[8]) << 8) |
                (static_cast<int64_t>(data[9]) << 16)) << 5;
  int64_t h3 = (static_cast<int64_t>(data[10]) |
                (static_cast<int64_t>(data[11]) << 8) |
                (static_cast<int64_t>(data[12]) << 16)) << 3;
  int64_t h4 = (static_cast<int64_t>(data[13]) |
                (static_cast<int64_t>(data[14]) << 8) |
                (static_cast<int64_t>(data[15]) << 16)) << 2;
  int64_t h5 = static_cast<int64_t>(data[16]) |
               (static_cast<int64_t>(data[17]) << 8) |
               (static_cast<int64_t>(data[18]) << 16) |
               (static_cast<int64_t>(data[19]) << 24);
  int64_t h6 = (static_cast<int64_t>(data[20]) |
                (static_cast<int64_t>(data[21]) << 8) |
                (static_cast<int64_t>(data[22]) << 16)) << 7;
  int64_t h7 = (static_cast<int64_t>(data[23]) |
                (static_cast<int64_t>(data[24]) << 8) |
                (static_cast<int64_t>(data[25]) << 16)) << 5;
  int64_t h8 = (static_cast<int64_t>(data[26]) |
                (static_cast<int64_t>(data[27]) << 8) |
                (static_cast<int64_t>(data[28]) << 16)) << 4;
  int64_t h9 = (static_cast<int64_t>(data[29]) |
                (static_cast<int64_t>(data[30]) << 8) |
                (static_cast<int64_t>(data[31]) << 16)) << 2;

  const int64_t carry9 = (h9 + (INT64_C(1) << 24)) >> 25;
  h0 += carry9 * 19;
  h9 -= carry9 * (INT64_C(1) << 25);
  const int64_t carry1 = (h1 + (INT64_C(1) << 24)) >> 25;
  h2 += carry1;
  h1 -= carry1 * (INT64_C(1) << 25);
  const int64_t carry3 = (h3 + (INT64_C(1) << 24)) >> 25;
  h4 += carry3;
  h3 -= carry3 * (INT64_C(1) << 25);
  const int64_t carry5 = (h5 + (INT64_C(1) << 24)) >> 25;
  h6 += carry5;
  h5 -= carry5 * (INT64_C(1) << 25);
  const int64_t carry7 = (h7 + (INT64_C(1) << 24)) >> 25;
  h8 += carry7;
  h7 -= carry7 * (INT64_C(1) << 25);

  const int64_t carry0 = (h0 + (INT64_C(1) << 25)) >> 26;
  h1 += carry0;
  h0 -= carry0 * (INT64_C(1) << 26);
  const int64_t carry2 = (h2 + (INT64_C(1) << 25)) >> 26;
  h3 += carry2;
  h2 -= carry2 * (INT64_C(1) << 26);
  const int64_t carry4 = (h4 + (INT64_C(1) << 25)) >> 26;
  h5 += carry4;
  h4 -= carry4 * (INT64_C(1) << 26);
  const int64_t carry6 = (h6 + (INT64_C(1) << 25)) >> 26;
  h7 += carry6;
  h6 -= carry6 * (INT64_C(1) << 26);
  const int64_t carry8 = (h8 + (INT64_C(1) << 25)) >> 26;
  h9 += carry8;
  h8 -= carry8 * (INT64_C(1) << 26);

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

bool fe_isnonzero(const fe value) {
  uint8_t encoded[32];
  fe_tobytes(encoded, value);
  uint8_t any = 0;
  for (size_t index = 0; index < sizeof(encoded); ++index) {
    any |= encoded[index];
  }
  return any != 0;
}

int fe_isnegative(const fe value) {
  uint8_t encoded[32];
  fe_tobytes(encoded, value);
  return encoded[0] & 1;
}

void fe_sq2(fe out, const fe value) {
  fe squared;
  fe_sq(squared, value);
  fe_add(out, squared, squared);
}

// x^((p-5)/8), used by the CryptoNote hash-to-point map.
void fe_pow22523(fe out, const fe value) {
  fe t0, t1, t2;
  fe_sq(t0, value);
  fe_sq(t1, t0);
  fe_sq(t1, t1);
  fe_mul(t1, value, t1);
  fe_mul(t0, t0, t1);
  fe_sq(t0, t0);
  fe_mul(t0, t1, t0);
  fe_sq(t1, t0);
  for (int index = 0; index < 4; ++index) fe_sq(t1, t1);
  fe_mul(t0, t1, t0);
  fe_sq(t1, t0);
  for (int index = 0; index < 9; ++index) fe_sq(t1, t1);
  fe_mul(t1, t1, t0);
  fe_sq(t2, t1);
  for (int index = 0; index < 19; ++index) fe_sq(t2, t2);
  fe_mul(t1, t2, t1);
  for (int index = 0; index < 10; ++index) fe_sq(t1, t1);
  fe_mul(t0, t1, t0);
  fe_sq(t1, t0);
  for (int index = 0; index < 49; ++index) fe_sq(t1, t1);
  fe_mul(t1, t1, t0);
  fe_sq(t2, t1);
  for (int index = 0; index < 99; ++index) fe_sq(t2, t2);
  fe_mul(t1, t2, t1);
  for (int index = 0; index < 50; ++index) fe_sq(t1, t1);
  fe_mul(t0, t1, t0);
  fe_sq(t0, t0);
  fe_sq(t0, t0);
  fe_mul(out, t0, value);
  secure_zero(t0, sizeof(t0));
  secure_zero(t1, sizeof(t1));
  secure_zero(t2, sizeof(t2));
}

void fe_divpowm1(fe out, const fe u, const fe v) {
  fe v3, uv7, t0, t1, t2;
  fe_sq(v3, v);
  fe_mul(v3, v3, v);          // v^3
  fe_sq(uv7, v3);
  fe_mul(uv7, uv7, v);
  fe_mul(uv7, uv7, u);        // u * v^7
  fe_pow22523(t0, uv7);
  fe_mul(t0, t0, v3);
  fe_mul(out, t0, u);
  secure_zero(v3, sizeof(v3));
  secure_zero(uv7, sizeof(uv7));
  secure_zero(t0, sizeof(t0));
  secure_zero(t1, sizeof(t1));
  secure_zero(t2, sizeof(t2));
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

const uint64_t kScalarOrder[4] = {
  UINT64_C(0x5812631a5cf5d3ed),
  UINT64_C(0x14def9dea2f79cd6),
  UINT64_C(0x0000000000000000),
  UINT64_C(0x1000000000000000),
};

// out = (c - a * b) mod L.
void sc_mulsub(uint8_t out[32], const uint8_t *a, const uint8_t *b,
               const uint8_t *c) {
  uint8_t product[32];
  const uint8_t zero[32] = { 0 };
  sc_muladd(product, a, b, zero);
  uint64_t cw[4], pw[4], diff[4];
  for (int index = 0; index < 4; ++index) {
    cw[index] = load_le64_word(c + index * 8);
    pw[index] = load_le64_word(product + index * 8);
  }
  uint64_t borrow = 0;
  for (int index = 0; index < 4; ++index) {
    const uint64_t partial = cw[index] - pw[index];
    const uint64_t borrow1 = cw[index] < pw[index];
    diff[index] = partial - borrow;
    const uint64_t borrow2 = partial < borrow;
    borrow = borrow1 | borrow2;
  }
  if (borrow != 0) {
    uint64_t carry = 0;
    for (int index = 0; index < 4; ++index) {
      const uint64_t sum1 = diff[index] + kScalarOrder[index];
      const uint64_t carry1 = sum1 < diff[index];
      const uint64_t sum2 = sum1 + carry;
      const uint64_t carry2 = sum2 < sum1;
      diff[index] = sum2;
      carry = carry1 | carry2;
    }
  }
  for (int index = 0; index < 4; ++index) {
    store_le64_word(out + index * 8, diff[index]);
  }
  secure_zero(product, sizeof(product));
  secure_zero(cw, sizeof(cw));
  secure_zero(pw, sizeof(pw));
  secure_zero(diff, sizeof(diff));
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

// Constants from Monero's crypto-ops-data.c, same 25.5-bit limb layout.
const fe kFeMa2 = { -12721188, -3529, 0, 0, 0, 0, 0, 0, 0, 0 };
const fe kFeMa = { -486662, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
const fe kFeSqrtM1 = { -32595792, -7943725, 9377950, 3500415, 12389472,
                       -272473, -25146209, -2005654, 326686, 11406482 };
const fe kFeFffb1 = { -31702527, -2466483, -26106795, -12203692, -12169197,
                      -321052, 14850977, -10296299, -16929438, -407568 };
const fe kFeFffb2 = { 8166131, -6741800, -17040804, 3154616, 21461005,
                      1466302, -30876704, -6368709, 10503587, -13363080 };
const fe kFeFffb3 = { -13620103, 14639558, 4532995, 7679154, 16815101,
                      -15883539, -22863840, -14813421, 13716513, -6477756 };
const fe kFeFffb4 = { -21786234, -12173074, 21573800, 4524538, -4645904,
                      16204591, 8012863, -8444712, 3212926, 6885324 };

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

// Complete extended Edwards addition (RFC 8032, section 5.1.4).
// Keeping Z and T avoids field inversions inside the scalar multiplication.
using ExtendedPoint = Ed25519ExtendedPoint;

void extended_add(ExtendedPoint &out, const ExtendedPoint &p,
                  const ExtendedPoint &q, const fe twice_d) {
  fe a,b,c,d,e,f,g,h,u,v;
  fe_sub(u,p.y,p.x); fe_sub(v,q.y,q.x); fe_mul(a,u,v);
  fe_add(u,p.y,p.x); fe_add(v,q.y,q.x); fe_mul(b,u,v);
  fe_mul(u,p.t,q.t); fe_mul(c,u,twice_d);
  fe_mul(u,p.z,q.z); fe_add(d,u,u);
  fe_sub(e,b,a); fe_sub(f,d,c); fe_add(g,d,c); fe_add(h,b,a);
  fe_mul(out.x,e,f); fe_mul(out.y,g,h);
  fe_mul(out.t,e,h); fe_mul(out.z,f,g);
  secure_zero(a,sizeof(a)); secure_zero(b,sizeof(b));
  secure_zero(c,sizeof(c)); secure_zero(d,sizeof(d));
  secure_zero(e,sizeof(e)); secure_zero(f,sizeof(f));
  secure_zero(g,sizeof(g)); secure_zero(h,sizeof(h));
  secure_zero(u,sizeof(u)); secure_zero(v,sizeof(v));
}

// Fixed 256-bit walk, two complete additions and a masked selection per bit.
// Only one inversion is needed when converting the final result to affine.
void scalarmult_point(fe rx, fe ry, const fe px, const fe py,
                      const uint8_t *scalar) {
  ExtendedPoint base, acc, doubled, candidate;
  fe twice_d, inverse_z;
  fe_frombytes(twice_d,kEdwardsD); fe_add(twice_d,twice_d,twice_d);
  fe_copy(base.x,px); fe_copy(base.y,py); fe_1(base.z); fe_mul(base.t,px,py);
  fe_0(acc.x); fe_1(acc.y); fe_1(acc.z); fe_0(acc.t);
  for (int bit = 255; bit >= 0; --bit) {
    extended_add(doubled,acc,acc,twice_d);
    extended_add(candidate,doubled,base,twice_d);
    const int bit_value = (scalar[bit / 8] >> (bit % 8)) & 1;
    fe_cmov(acc.x,doubled.x,candidate.x,bit_value);
    fe_cmov(acc.y,doubled.y,candidate.y,bit_value);
    fe_cmov(acc.z,doubled.z,candidate.z,bit_value);
    fe_cmov(acc.t,doubled.t,candidate.t,bit_value);
  }
  fe_invert(inverse_z,acc.z);
  fe_mul(rx,acc.x,inverse_z); fe_mul(ry,acc.y,inverse_z);
  secure_zero(&base,sizeof(base)); secure_zero(&acc,sizeof(acc));
  secure_zero(&doubled,sizeof(doubled)); secure_zero(&candidate,sizeof(candidate));
  secure_zero(twice_d,sizeof(twice_d)); secure_zero(inverse_z,sizeof(inverse_z));
}

void scalarmult_base(fe rx, fe ry, const uint8_t *scalar) {
  fe bx, by;
  fe_frombytes(bx, kBaseX);
  fe_frombytes(by, kBaseY);
  scalarmult_point(rx, ry, bx, by, scalar);
  secure_zero(bx, sizeof(bx));
  secure_zero(by, sizeof(by));
}

void fe_neg(fe out, const fe value) {
  fe zero;
  fe_0(zero);
  fe_sub(out, zero, value);
}

// CryptoNote hash-to-point: Monero ge_fromfe_frombytes_vartime().
bool hash_to_point_compressed(const uint8_t hash[32], uint8_t out[32]) {
  fe u, v, w, x, y, z, rx, denominator, numerator, inverse, affine_y;
  fe_frombytes_full(u, hash);
  fe_sq2(v, u);
  fe_1(w);
  fe_add(w, v, w);
  fe_sq(x, w);
  fe_mul(y, kFeMa2, v);
  fe_add(x, x, y);
  fe_divpowm1(rx, w, x);
  fe_sq(y, rx);
  fe_mul(x, y, x);
  fe_sub(y, w, x);
  fe_copy(z, kFeMa);
  int sign;
  if (fe_isnonzero(y)) {
    fe_add(y, w, x);
    if (fe_isnonzero(y)) {
      fe_mul(x, x, kFeSqrtM1);
      fe_sub(y, w, x);
      if (fe_isnonzero(y)) {
        fe_add(y, w, x);
        fe_mul(rx, rx, kFeFffb3);
      } else {
        fe_mul(rx, rx, kFeFffb4);
      }
      sign = 1;
    } else {
      fe_mul(rx, rx, kFeFffb1);
      fe_mul(rx, rx, u);
      fe_mul(z, z, v);
      sign = 0;
    }
  } else {
    fe_mul(rx, rx, kFeFffb2);
    fe_mul(rx, rx, u);
    fe_mul(z, z, v);
    sign = 0;
  }
  if (fe_isnegative(rx) != sign) fe_neg(rx, rx);
  fe_add(denominator, z, w);
  fe_sub(numerator, z, w);
  if (!fe_isnonzero(denominator)) return false;
  fe_invert(inverse, denominator);
  fe_mul(affine_y, numerator, inverse);
  fe_tobytes(out, affine_y);
  out[31] ^= static_cast<uint8_t>(fe_isnegative(rx) << 7);
  secure_zero(u, sizeof(u));
  secure_zero(v, sizeof(v));
  secure_zero(w, sizeof(w));
  secure_zero(x, sizeof(x));
  secure_zero(y, sizeof(y));
  secure_zero(z, sizeof(z));
  secure_zero(rx, sizeof(rx));
  secure_zero(denominator, sizeof(denominator));
  secure_zero(numerator, sizeof(numerator));
  secure_zero(inverse, sizeof(inverse));
  secure_zero(affine_y, sizeof(affine_y));
  return true;
}

// Constant-time select: out = flag ? b : a.  flag must be 0 or 1.
void fe_cmov(fe out, const fe a, const fe b, int flag) {
  const int64_t mask = -static_cast<int64_t>(flag != 0);
  for (int index = 0; index < 10; ++index) {
    out[index] = (a[index] & ~mask) | (b[index] & mask);
  }
}

bool fe_iszero(const fe value) {
  uint8_t encoded[32];
  fe_tobytes(encoded, value);
  uint8_t combined = 0;
  for (size_t index = 0; index < sizeof(encoded); ++index) combined |= encoded[index];
  secure_zero(encoded, sizeof(encoded));
  return combined == 0;
}

// out = base^exponent with a 32-byte little-endian exponent.
void fe_pow(fe out, const fe base, const uint8_t exponent[32]) {
  fe result, factor;
  fe_1(result);
  fe_copy(factor, base);
  for (int bit = 255; bit >= 0; --bit) {
    fe_sq(result, result);
    if ((exponent[bit / 8] >> (bit % 8)) & 1) fe_mul(result, result, factor);
  }
  fe_copy(out, result);
  secure_zero(result, sizeof(result));
  secure_zero(factor, sizeof(factor));
}

bool edwards_decompress(fe x, fe y, const uint8_t point[32]) {
  const bool sign = (point[31] & 0x80) != 0;
  fe y2, u, v, v3, v7, t, check, one, two, d, sqrt_m1;
  fe_frombytes(y, point);
  uint8_t canonical[32];
  fe_tobytes(canonical, y);
  uint8_t expected[32];
  memcpy(expected, point, sizeof(expected));
  expected[31] &= 0x7f;
  const bool canonical_y = memcmp(canonical, expected, sizeof(expected)) == 0;
  secure_zero(canonical, sizeof(canonical));
  secure_zero(expected, sizeof(expected));
  if (!canonical_y) return false;
  fe_1(one);
  fe_sq(y2, y);
  fe_sub(u, y2, one);
  fe_frombytes(d, kEdwardsD);
  fe_mul(v, d, y2);
  fe_add(v, v, one);
  if (fe_iszero(v)) return false;
  fe_sq(v3, v);
  fe_mul(v3, v3, v);
  fe_sq(v7, v3);
  fe_mul(v7, v7, v);
  fe_mul(t, u, v7);

  uint8_t exponent[32];
  memset(exponent, 0xff, sizeof(exponent));
  exponent[0] = 0xfd;  // (p-5)/8 = 2^252 - 3
  exponent[31] = 0x0f;
  fe_pow(t, t, exponent);
  fe_mul(x, t, u);
  fe_mul(x, x, v3);

  fe_sq(check, x);
  fe_mul(check, check, v);
  fe_sub(check, check, u);
  if (!fe_iszero(check)) {
    memset(exponent, 0xff, sizeof(exponent));
    exponent[0] = 0xfb;  // (p-1)/4 = 2^253 - 5
    exponent[31] = 0x1f;
    fe_1(two);
    fe_add(two, two, two);
    fe_pow(sqrt_m1, two, exponent);
    fe_mul(x, x, sqrt_m1);
    fe_sq(check, x);
    fe_mul(check, check, v);
    fe_sub(check, check, u);
    if (!fe_iszero(check)) return false;
  }
  uint8_t encoded[32];
  fe_tobytes(encoded, x);
  const bool odd = (encoded[0] & 1) != 0;
  secure_zero(encoded, sizeof(encoded));
  if (!odd && sign && fe_iszero(x)) return false;
  if (odd != sign) fe_neg(x, x);
  return true;
}

void encode_point(uint8_t out[32], const fe x, const fe y) {
  fe_tobytes(out, y);
  // Limbs may represent x + p, whose parity differs from canonical x.
  // The sign bit must come from the reduced field encoding (including x=0).
  const uint8_t sign = static_cast<uint8_t>(fe_isnegative(x));
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

bool ed25519_public_key_expanded(const uint8_t scalar[32],
                                 uint8_t out_public[32]) {
  if (scalar == nullptr || out_public == nullptr) return false;
  fe rx, ry;
  scalarmult_base(rx, ry, scalar);
  encode_point(out_public, rx, ry);
  secure_zero(rx, sizeof(rx));
  secure_zero(ry, sizeof(ry));
  return true;
}

bool ed25519_sign(const uint8_t seed[32], const uint8_t *message,
                  size_t message_size, uint8_t out_signature[64]) {
  if (seed == nullptr || out_signature == nullptr || (message == nullptr && message_size != 0)) {
    return false;
  }
  uint8_t hash[64] = {};
  bool ok = sha512(seed, 32, hash);
  if (ok) {
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    ok = ed25519_sign_expanded(hash, hash + 32, message, message_size,
                               out_signature);
  }
  secure_zero(hash, sizeof(hash));
  if (!ok) secure_zero(out_signature, 64);
  return ok;
}

bool ed25519_sign_expanded(const uint8_t kL[32], const uint8_t kR[32],
                           const uint8_t *message, size_t message_size,
                           uint8_t out_signature[64]) {
  if (out_signature == nullptr) return false;
  secure_zero(out_signature, 64);
  if (kL == nullptr || kR == nullptr ||
      (message == nullptr && message_size != 0)) return false;
  uint8_t hash[64];
  memcpy(hash, kL, 32);
  memcpy(hash + 32, kR, 32);
  uint8_t public_key[32];
  uint8_t r_digest[64];
  uint8_t r_scalar[32];
  uint8_t k_bytes[64];
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

bool ed25519_verify(const uint8_t public_key[32], const uint8_t *message,
                    size_t message_size, const uint8_t signature[64]) {
  if (public_key == nullptr || signature == nullptr ||
      (message == nullptr && message_size != 0)) {
    return false;
  }

  // S must be a canonical scalar. A non-canonical S is a malleable signature
  // and must not be accepted by the link handshake.
  uint64_t s_words[4];
  for (int index = 0; index < 4; ++index) {
    s_words[index] = load_le64_word(signature + 32 + index * 8);
  }
  if (ge_ge_words(s_words, kScalarOrder)) return false;

  fe ax, ay, rx, ry;
  if (!edwards_decompress(ax, ay, public_key) ||
      !edwards_decompress(rx, ry, signature)) {
    return false;
  }

  // Reject public keys and R values whose order divides 8. Without this
  // check the identity public key would let anyone forge a "valid" signature.
  static const uint8_t kCofactor[32] = { 8 };
  fe cx, cy;
  scalarmult_point(cx, cy, ax, ay, kCofactor);
  uint8_t cofactored_public[32];
  encode_point(cofactored_public, cx, cy);
  static const uint8_t kIdentity[32] = { 1 };
  if (crypto_constant_time_equal(cofactored_public, kIdentity, 32)) return false;
  scalarmult_point(cx, cy, rx, ry, kCofactor);
  uint8_t cofactored_r[32];
  encode_point(cofactored_r, cx, cy);
  if (crypto_constant_time_equal(cofactored_r, kIdentity, 32)) return false;

  // k = SHA-512(R || A || M) mod L.
  uint8_t digest[64];
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  bool ok = info != nullptr;
  if (ok) ok = mbedtls_md_setup(&context, info, 0) == 0;
  if (ok) ok = mbedtls_md_starts(&context) == 0;
  if (ok) ok = mbedtls_md_update(&context, signature, 32) == 0;
  if (ok) ok = mbedtls_md_update(&context, public_key, 32) == 0;
  if (ok && message_size != 0) ok = mbedtls_md_update(&context, message, message_size) == 0;
  if (ok) ok = mbedtls_md_finish(&context, digest) == 0;
  mbedtls_md_free(&context);
  if (!ok) {
    secure_zero(digest, sizeof(digest));
    return false;
  }

  uint8_t k_scalar[32];
  sc_reduce_64(digest, k_scalar);

  // [S]B == R + [k]A.
  fe sbx, sby, kax, kay, sumx, sumy;
  scalarmult_base(sbx, sby, signature + 32);
  scalarmult_point(kax, kay, ax, ay, k_scalar);
  edwards_add(sumx, sumy, rx, ry, kax, kay);
  uint8_t left[32];
  uint8_t right[32];
  encode_point(left, sbx, sby);
  encode_point(right, sumx, sumy);
  ok = crypto_constant_time_equal(left, right, sizeof(left));

  secure_zero(digest, sizeof(digest));
  secure_zero(k_scalar, sizeof(k_scalar));
  secure_zero(s_words, sizeof(s_words));
  secure_zero(left, sizeof(left));
  secure_zero(right, sizeof(right));
  secure_zero(cofactored_public, sizeof(cofactored_public));
  secure_zero(cofactored_r, sizeof(cofactored_r));
  secure_zero(cx, sizeof(cx));
  secure_zero(cy, sizeof(cy));
  secure_zero(ax, sizeof(ax));
  secure_zero(ay, sizeof(ay));
  secure_zero(rx, sizeof(rx));
  secure_zero(ry, sizeof(ry));
  secure_zero(sbx, sizeof(sbx));
  secure_zero(sby, sizeof(sby));
  secure_zero(kax, sizeof(kax));
  secure_zero(kay, sizeof(kay));
  secure_zero(sumx, sizeof(sumx));
  secure_zero(sumy, sizeof(sumy));
  return ok;
}

bool ed25519_ecdh(const uint8_t seed[32], const uint8_t peer_public[32],
                  uint8_t out_shared[32]) {
  if (seed == nullptr || peer_public == nullptr || out_shared == nullptr) {
    return false;
  }
  uint8_t hash[64];
  if (!sha512(seed, 32, hash)) {
    secure_zero(hash, sizeof(hash));
    return false;
  }
  hash[0] &= 248;
  hash[31] &= 127;
  hash[31] |= 64;

  fe px, py, sx, sy;
  bool ok = edwards_decompress(px, py, peer_public);
  if (ok) scalarmult_point(sx, sy, px, py, hash);
  uint8_t shared[32];
  if (ok) {
    encode_point(shared, sx, sy);
    static const uint8_t kIdentity[32] = { 1 };
    ok = !crypto_constant_time_equal(shared, kIdentity, sizeof(shared));
  }
  if (ok) memcpy(out_shared, shared, sizeof(shared));
  else memset(out_shared, 0, 32);

  secure_zero(hash, sizeof(hash));
  secure_zero(shared, sizeof(shared));
  secure_zero(px, sizeof(px));
  secure_zero(py, sizeof(py));
  secure_zero(sx, sizeof(sx));
  secure_zero(sy, sizeof(sy));
  return ok;
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

bool ed25519_point_add_compressed(const uint8_t left[32],
                                  const uint8_t right[32],
                                  uint8_t out[32]) {
  if (left == nullptr || right == nullptr || out == nullptr) return false;
  fe x1, y1, x2, y2, x3, y3;
  if (!edwards_decompress(x1, y1, left) ||
      !edwards_decompress(x2, y2, right)) {
    return false;
  }
  edwards_add(x3, y3, x1, y1, x2, y2);
  encode_point(out, x3, y3);
  secure_zero(x1, sizeof(x1));
  secure_zero(y1, sizeof(y1));
  secure_zero(x2, sizeof(x2));
  secure_zero(y2, sizeof(y2));
  secure_zero(x3, sizeof(x3));
  secure_zero(y3, sizeof(y3));
  return true;
}

bool ed25519_point_mul_compressed(const uint8_t point[32],
                                  const uint8_t scalar[32],
                                  uint8_t out[32]) {
  if (point == nullptr || scalar == nullptr || out == nullptr) return false;
  fe px, py, rx, ry;
  if (!edwards_decompress(px, py, point)) return false;
  scalarmult_point(rx, ry, px, py, scalar);
  encode_point(out, rx, ry);
  secure_zero(px, sizeof(px));
  secure_zero(py, sizeof(py));
  secure_zero(rx, sizeof(rx));
  secure_zero(ry, sizeof(ry));
  return true;
}

// Variable-time Shamir double-scalar multiplication. The operands are public
// (verification equations), so skipping zero-bit additions is safe here and
// roughly halves the point additions of two separate scalar multiplications.
bool ed25519_double_scalar_mul(const uint8_t p1[32], const uint8_t s1[32],
                               const uint8_t p2[32], const uint8_t s2[32],
                               uint8_t out[32]) {
  if (p1 == nullptr || s1 == nullptr || p2 == nullptr || s2 == nullptr ||
      out == nullptr)
    return false;
  fe x1, y1, x2, y2, twice_d, inverse_z, rx, ry;
  if (!edwards_decompress(x1, y1, p1) || !edwards_decompress(x2, y2, p2))
    return false;
  fe_frombytes(twice_d, kEdwardsD);
  fe_add(twice_d, twice_d, twice_d);

  ExtendedPoint a, b, both, acc, scratch;
  fe_copy(a.x, x1); fe_copy(a.y, y1); fe_1(a.z); fe_mul(a.t, x1, y1);
  fe_copy(b.x, x2); fe_copy(b.y, y2); fe_1(b.z); fe_mul(b.t, x2, y2);
  extended_add(both, a, b, twice_d);
  fe_0(acc.x); fe_1(acc.y); fe_1(acc.z); fe_0(acc.t);

  for (int bit = 255; bit >= 0; --bit) {
    extended_add(scratch, acc, acc, twice_d);
    acc = scratch;
    const int first = (s1[bit / 8] >> (bit % 8)) & 1;
    const int second = (s2[bit / 8] >> (bit % 8)) & 1;
    if (first && second) {
      extended_add(scratch, acc, both, twice_d);
      acc = scratch;
    } else if (first) {
      extended_add(scratch, acc, a, twice_d);
      acc = scratch;
    } else if (second) {
      extended_add(scratch, acc, b, twice_d);
      acc = scratch;
    }
  }
  fe_invert(inverse_z, acc.z);
  fe_mul(rx, acc.x, inverse_z);
  fe_mul(ry, acc.y, inverse_z);
  encode_point(out, rx, ry);
  secure_zero(&a, sizeof(a));
  secure_zero(&b, sizeof(b));
  secure_zero(&both, sizeof(both));
  secure_zero(&acc, sizeof(acc));
  secure_zero(&scratch, sizeof(scratch));
  secure_zero(x1, sizeof(x1)); secure_zero(y1, sizeof(y1));
  secure_zero(x2, sizeof(x2)); secure_zero(y2, sizeof(y2));
  secure_zero(twice_d, sizeof(twice_d));
  secure_zero(inverse_z, sizeof(inverse_z));
  secure_zero(rx, sizeof(rx)); secure_zero(ry, sizeof(ry));
  return true;
}

void ed25519_scalar_reduce_mod_l(uint8_t scalar[32]) {
  if (scalar != nullptr) sc_reduce_32(scalar);
}

// Cofactor clearing for Monero's scalarmult8. Doing the three doublings in
// extended coordinates costs one field inversion instead of five, which is the
// difference between a usable and an unusable Bulletproofs+ verification on an
// MCU: the verifier derives 2*padded_outputs generators per proof.
bool ed25519_point_mul8_compressed(const uint8_t in[32], uint8_t out[32]) {
  if (in == nullptr || out == nullptr) return false;
  fe x, y, twice_d;
  if (!edwards_decompress(x, y, in)) return false;
  ExtendedPoint point, scratch, doubled;
  fe_copy(point.x, x);
  fe_copy(point.y, y);
  fe_1(point.z);
  fe_mul(point.t, x, y);
  fe_frombytes(twice_d, kEdwardsD);
  fe_add(twice_d, twice_d, twice_d);
  extended_add(scratch, point, point, twice_d);   // 2P
  extended_add(doubled, scratch, scratch, twice_d); // 4P
  extended_add(scratch, doubled, doubled, twice_d); // 8P
  fe inverse_z, rx, ry;
  fe_invert(inverse_z, scratch.z);
  fe_mul(rx, scratch.x, inverse_z);
  fe_mul(ry, scratch.y, inverse_z);
  encode_point(out, rx, ry);
  secure_zero(x, sizeof(x)); secure_zero(y, sizeof(y));
  secure_zero(&point, sizeof(point)); secure_zero(&scratch, sizeof(scratch));
  secure_zero(&doubled, sizeof(doubled));
  secure_zero(twice_d, sizeof(twice_d));
  secure_zero(inverse_z, sizeof(inverse_z));
  secure_zero(rx, sizeof(rx)); secure_zero(ry, sizeof(ry));
  return true;
}

void ed25519_extended_identity(Ed25519ExtendedPoint *point) {
  if (point == nullptr) return;
  fe_0(point->x); fe_1(point->y); fe_1(point->z); fe_0(point->t);
}

// acc += point * scalar for public verification operands. The window keeps one
// decompression, one precomputation and no per-term inversion; the accumulator
// stays in extended coordinates until the caller converts it once. A 3-bit
// window (8 precomputed multiples) keeps the table at 2.5 KiB so the verifier
// still fits the caller's stack.
bool ed25519_extended_add_scaled(Ed25519ExtendedPoint *acc,
                                 const uint8_t point[32],
                                 const uint8_t scalar[32]) {
  if (acc == nullptr || point == nullptr || scalar == nullptr) return false;
  fe px, py, twice_d;
  if (!edwards_decompress(px, py, point)) return false;
  fe_frombytes(twice_d, kEdwardsD);
  fe_add(twice_d, twice_d, twice_d);

  constexpr int kDigits = 86; // ceil(256 / 3)
  ExtendedPoint table[8];
  fe_copy(table[0].x, px);
  fe_copy(table[0].y, py);
  fe_1(table[0].z);
  fe_mul(table[0].t, px, py);
  for (int index = 1; index < 8; ++index)
    extended_add(table[index], table[index - 1], table[0], twice_d);

  ExtendedPoint sum, doubled, added;
  ed25519_extended_identity(&sum);
  for (int digit_index = kDigits - 1; digit_index >= 0; --digit_index) {
    for (int times = 0; times < 3; ++times) {
      extended_add(doubled, sum, sum, twice_d);
      sum = doubled;
    }
    const int shift = 3 * digit_index;
    uint32_t window_value = scalar[shift / 8];
    if (shift % 8 > 5 && shift / 8 + 1 < 32)
      window_value |= static_cast<uint32_t>(scalar[shift / 8 + 1]) << 8;
    const uint8_t digit =
        static_cast<uint8_t>((window_value >> (shift % 8)) & 0x07);
    if (digit != 0) {
      extended_add(added, sum, table[digit - 1], twice_d);
      sum = added;
    }
  }
  extended_add(added, *acc, sum, twice_d);
  *acc = added;
  secure_zero(px, sizeof(px)); secure_zero(py, sizeof(py));
  secure_zero(twice_d, sizeof(twice_d));
  secure_zero(table, sizeof(table));
  secure_zero(&sum, sizeof(sum));
  secure_zero(&doubled, sizeof(doubled));
  secure_zero(&added, sizeof(added));
  return true;
}

bool ed25519_extended_to_compressed(const Ed25519ExtendedPoint *point,
                                    uint8_t out[32]) {
  if (point == nullptr || out == nullptr) return false;
  fe inverse_z, rx, ry;
  fe_invert(inverse_z, point->z);
  fe_mul(rx, point->x, inverse_z);
  fe_mul(ry, point->y, inverse_z);
  encode_point(out, rx, ry);
  secure_zero(inverse_z, sizeof(inverse_z));
  secure_zero(rx, sizeof(rx)); secure_zero(ry, sizeof(ry));
  return true;
}

void ed25519_scalar_reduce_wide(const uint8_t digest[64], uint8_t out[32]) {
  if (digest != nullptr && out != nullptr) sc_reduce_64(digest, out);
}

void ed25519_scalar_muladd(uint8_t out[32], const uint8_t a[32],
                           const uint8_t b[32], const uint8_t c[32]) {
  if (out == nullptr || a == nullptr || b == nullptr || c == nullptr) return;
  sc_muladd(out, a, b, c);
}

void ed25519_scalar_mulsub(uint8_t out[32], const uint8_t a[32],
                           const uint8_t b[32], const uint8_t c[32]) {
  if (out == nullptr || a == nullptr || b == nullptr || c == nullptr) return;
  sc_mulsub(out, a, b, c);
}

bool ed25519_point_sub_compressed(const uint8_t left[32],
                                  const uint8_t right[32],
                                  uint8_t out[32]) {
  if (left == nullptr || right == nullptr || out == nullptr) return false;
  fe x1, y1, x2, y2, x3, y3;
  if (!edwards_decompress(x1, y1, left) ||
      !edwards_decompress(x2, y2, right)) {
    return false;
  }
  fe_neg(x2, x2);
  edwards_add(x3, y3, x1, y1, x2, y2);
  encode_point(out, x3, y3);
  secure_zero(x1, sizeof(x1));
  secure_zero(y1, sizeof(y1));
  secure_zero(x2, sizeof(x2));
  secure_zero(y2, sizeof(y2));
  secure_zero(x3, sizeof(x3));
  secure_zero(y3, sizeof(y3));
  return true;
}

bool ed25519_hash_to_point(const uint8_t hash[32], uint8_t out_point[32]) {
  if (hash == nullptr || out_point == nullptr) return false;
  return hash_to_point_compressed(hash, out_point);
}

}  // namespace hexwallet
