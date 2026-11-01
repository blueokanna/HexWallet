#include "StarknetCrypto.h"

#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"

namespace hexwallet {
namespace {

// ---------------------------------------------------------------------------
// 256-bit little-endian integers and Montgomery arithmetic.
//
// The Stark field p and the curve order n are both 252-bit, so eight 32-bit
// limbs hold either modulus with room for a carry bit. Every multiplication is
// a fixed CIOS loop: no branch depends on a limb value.
// ---------------------------------------------------------------------------
constexpr size_t kLimbs = 8;
constexpr size_t kBytes = 32;

struct Num {
  uint32_t v[kLimbs];
};

constexpr Num kPrime = {{0x00000001u, 0x00000000u, 0x00000000u, 0x00000000u,
                         0x00000000u, 0x00000000u, 0x00000011u, 0x08000000u}};
constexpr Num kOrder = {{0xadc64d2fu, 0x1e66a241u, 0xcae7b232u, 0xb781126du,
                         0xffffffffu, 0xffffffffu, 0x00000010u, 0x08000000u}};
constexpr Num kFieldR2 = {{0x7e000401u, 0xfffffd73u, 0x330fffffu, 0x00000001u,
                           0xff6f8000u, 0xffffffffu, 0x5e008810u, 0x07ffd4abu}};
constexpr Num kOrderR2 = {{0xea1c688du, 0x6021b3f1u, 0x14ce60b9u, 0x509cf64du,
                           0xf78bbabbu, 0xbaf0ab4cu, 0x2333766eu, 0x07d9e57cu}};
constexpr uint32_t kFieldN0 = 0xffffffffu;
constexpr uint32_t kOrderN0 = 0xe8bde631u;

// 2^251 - 256: the largest value StarkWare treats as a signature/message
// element (MAX_STORAGE_ITEM_SIZE is 256).
constexpr Num kMaxValue = {{0xffffff00u, 0xffffffffu, 0xffffffffu, 0xffffffffu,
                            0xffffffffu, 0xffffffffu, 0xffffffffu, 0x07ffffffu}};
constexpr Num kOne = {{1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};

constexpr Num kCurveBeta = {{0x9cee9e89u, 0xf4cdfcb9u, 0x15c915c1u, 0x609ad26cu,
                             0x72f7a8c5u, 0x150e596du, 0xefbe40deu, 0x06f21413u}};

constexpr Num kGx = {{0xc943cfcau, 0x3d723d8bu, 0x0d1819e0u, 0xdeacfd9bu,
                      0x5a40f0c7u, 0x7beced41u, 0x8599971bu, 0x01ef15c1u}};
constexpr Num kGy = {{0x36e8dc1fu, 0x2873000cu, 0x1abe43a3u, 0xde53ecd1u,
                      0xdf46ec62u, 0xb7be4801u, 0x0aa49730u, 0x00566806u}};

constexpr Num kShiftX = {{0x50ca6804u, 0x551fde40u, 0x22947733u, 0x716b0b10u,
                          0xeb599f16u, 0x00ee1b87u, 0xa8c16007u, 0x049ee3ebu}};
constexpr Num kShiftY = {{0x6e10268au, 0xd0405d26u, 0xc0e056c1u, 0x4e621062u,
                          0x06ea0ed3u, 0xf346d49du, 0x4b3bc6ddu, 0x03ca0cfeu}};
constexpr Num kP0X = {{0x57ebe47bu, 0x1080d179u, 0x6d56eb0cu, 0x8fa8120bu,
                       0x55fca9e5u, 0x969c7486u, 0xcbaffe7fu, 0x0234287du}};
constexpr Num kP0Y = {{0xe89e5615u, 0x6ed0268eu, 0x7a6c94ccu, 0x940135ddu,
                       0xd41f4e39u, 0x1e889527u, 0x00f96fb2u, 0x03b056f1u}};
constexpr Num kP1X = {{0xba8aa378u, 0xb7a6932du, 0xde5e3018u, 0x99099ec1u,
                       0x56558f33u, 0x3f9dab26u, 0x76c83db3u, 0x04fa56f3u}};
constexpr Num kP1Y = {{0x0ff5b54du, 0x5168f4e8u, 0x2a7a23b4u, 0x562761f9u,
                       0xe47e4401u, 0x8113e0c0u, 0xc931c9e3u, 0x03fa0984u}};
constexpr Num kP2X = {{0xbd2d6997u, 0x3aa372f0u, 0x4709e90fu, 0x40c690c7u,
                       0x5b45f74bu, 0x764910f7u, 0x66be8decu, 0x04ba4cc1u}};
constexpr Num kP2Y = {{0xb24b219cu, 0x48151f27u, 0x5ce5ae7cu, 0xcac5c59au,
                       0xc4ede85fu, 0x4b971e46u, 0xf5c1751fu, 0x0040301cu}};
constexpr Num kP3X = {{0x49a58202u, 0xd36ff12cu, 0xd53fb325u, 0x2ca65048u,
                       0xf61a63bbu, 0x6e44cca8u, 0xb0e6cc1cu, 0x054302dcu}};
constexpr Num kP3Y = {{0xe99c2426u, 0x879dcc77u, 0x3c25561au, 0xce98ad78u,
                       0x68d8ae25u, 0xb3480462u, 0x37d13504u, 0x01b77b3eu}};

bool is_zero(const Num &a) {
  uint32_t aggregate = 0;
  for (size_t i = 0; i < kLimbs; ++i) aggregate |= a.v[i];
  return aggregate == 0;
}

bool equal(const Num &a, const Num &b) {
  uint32_t difference = 0;
  for (size_t i = 0; i < kLimbs; ++i) difference |= a.v[i] ^ b.v[i];
  return difference == 0;
}

int compare(const Num &a, const Num &b) {
  for (size_t i = kLimbs; i-- > 0;) {
    if (a.v[i] != b.v[i]) return a.v[i] < b.v[i] ? -1 : 1;
  }
  return 0;
}

uint32_t add_raw(const Num &a, const Num &b, Num *out) {
  uint64_t carry = 0;
  for (size_t i = 0; i < kLimbs; ++i) {
    const uint64_t sum = static_cast<uint64_t>(a.v[i]) + b.v[i] + carry;
    out->v[i] = static_cast<uint32_t>(sum);
    carry = sum >> 32;
  }
  return static_cast<uint32_t>(carry);
}

uint32_t sub_raw(const Num &a, const Num &b, Num *out) {
  uint64_t borrow = 0;
  for (size_t i = 0; i < kLimbs; ++i) {
    const uint64_t left = static_cast<uint64_t>(a.v[i]) - b.v[i] - borrow;
    out->v[i] = static_cast<uint32_t>(left);
    borrow = (left >> 32) & 1u;
  }
  return static_cast<uint32_t>(borrow);
}

Num select_num(const Num &a, const Num &b, uint32_t bit) {
  const uint32_t mask = 0u - (bit & 1u);
  Num out;
  for (size_t i = 0; i < kLimbs; ++i) {
    out.v[i] = (a.v[i] & ~mask) | (b.v[i] & mask);
  }
  return out;
}

Num cond_sub(const Num &value, const Num &modulus, uint32_t enable) {
  Num difference;
  const uint32_t borrow = sub_raw(value, modulus, &difference);
  return select_num(value, difference, enable & (borrow ^ 1u));
}

// value + modulus when the subtraction borrowed (used by sub_mod).
Num cond_add(const Num &value, const Num &modulus, uint32_t enable) {
  Num sum;
  add_raw(value, modulus, &sum);
  return select_num(value, sum, enable);
}

Num add_mod(const Num &a, const Num &b, const Num &modulus) {
  Num sum;
  const uint32_t carry = add_raw(a, b, &sum);
  Num difference;
  const uint32_t borrow = sub_raw(sum, modulus, &difference);
  // sum - modulus is correct when the addition carried or the sum is large.
  return select_num(sum, difference, (carry | (borrow ^ 1u)) & 1u);
}

Num sub_mod(const Num &a, const Num &b, const Num &modulus) {
  Num difference;
  const uint32_t borrow = sub_raw(a, b, &difference);
  return cond_add(difference, modulus, borrow);
}

// CIOS Montgomery multiplication. `modulus` must be odd and `n0` must equal
// -modulus^-1 mod 2^32.
Num mont_mul(const Num &a, const Num &b, const Num &modulus, uint32_t n0) {
  uint32_t t[10] = {};
  for (size_t i = 0; i < kLimbs; ++i) {
    uint64_t carry = 0;
    for (size_t j = 0; j < kLimbs; ++j) {
      const uint64_t sum =
          static_cast<uint64_t>(a.v[j]) * b.v[i] + t[j] + carry;
      t[j] = static_cast<uint32_t>(sum);
      carry = sum >> 32;
    }
    uint64_t sum = static_cast<uint64_t>(t[kLimbs]) + carry;
    t[kLimbs] = static_cast<uint32_t>(sum);
    t[kLimbs + 1] = static_cast<uint32_t>(sum >> 32);

    const uint32_t m = t[0] * n0;
    carry = 0;
    for (size_t j = 0; j < kLimbs; ++j) {
      const uint64_t reduced =
          static_cast<uint64_t>(m) * modulus.v[j] + t[j] + carry;
      t[j] = static_cast<uint32_t>(reduced);
      carry = reduced >> 32;
    }
    sum = static_cast<uint64_t>(t[kLimbs]) + carry;
    t[kLimbs] = static_cast<uint32_t>(sum);
    t[kLimbs + 1] += static_cast<uint32_t>(sum >> 32);
    for (size_t j = 0; j < kLimbs; ++j) {
      t[j] = t[j + 1];
    }
    t[kLimbs] = t[kLimbs + 1];
    t[kLimbs + 1] = 0;
  }
  Num result;
  for (size_t i = 0; i < kLimbs; ++i) result.v[i] = t[i];
  Num difference;
  const uint32_t borrow = sub_raw(result, modulus, &difference);
  return select_num(result, difference,
                    ((t[kLimbs] | (borrow ^ 1u)) & 1u));
}

Num to_mont(const Num &value, const Num &r2, const Num &modulus,
            uint32_t n0) {
  return mont_mul(value, r2, modulus, n0);
}

Num from_mont(const Num &value, const Num &modulus, uint32_t n0) {
  return mont_mul(value, kOne, modulus, n0);
}

Num field_mul(const Num &a, const Num &b) {
  return mont_mul(a, b, kPrime, kFieldN0);
}

Num scalar_mul(const Num &a, const Num &b) {
  return mont_mul(a, b, kOrder, kOrderN0);
}

// Reduces an arbitrary 256-bit value modulo p. The bound is 2^256 < 32 * p.
Num reduce_field(const Num &value) {
  Num current = value;
  for (size_t i = 0; i < 32; ++i) {
    current = cond_sub(current, kPrime, 1);
  }
  return current;
}

Num from_bytes(const uint8_t *bytes) {
  Num out = {};
  for (size_t i = 0; i < kBytes; ++i) {
    const size_t limb = (kBytes - 1 - i) / 4;
    const size_t shift = ((kBytes - 1 - i) % 4) * 8;
    out.v[limb] |= static_cast<uint32_t>(bytes[i]) << shift;
  }
  return out;
}

void to_bytes(const Num &value, uint8_t *out) {
  for (size_t i = 0; i < kBytes; ++i) {
    const size_t limb = (kBytes - 1 - i) / 4;
    const size_t shift = ((kBytes - 1 - i) % 4) * 8;
    out[i] = static_cast<uint8_t>(value.v[limb] >> shift);
  }
}

bool parse_felt(const uint8_t bytes[kBytes], Num *out) {
  const Num value = from_bytes(bytes);
  if (compare(value, kPrime) >= 0) return false;
  *out = value;
  return true;
}

bool parse_scalar(const uint8_t bytes[kBytes], Num *out) {
  const Num value = from_bytes(bytes);
  if (is_zero(value) || compare(value, kOrder) >= 0) return false;
  *out = value;
  return true;
}

Num shr_bits(const Num &value, size_t bits) {
  Num out = {};
  if (bits >= 256) return out;
  const size_t limb_shift = bits / 32;
  const size_t bit_shift = bits % 32;
  for (size_t i = 0; i + limb_shift < kLimbs; ++i) {
    uint64_t part = value.v[i + limb_shift];
    if (bit_shift != 0 && i + limb_shift + 1 < kLimbs) {
      part |= static_cast<uint64_t>(value.v[i + limb_shift + 1]) << 32;
    }
    out.v[i] = static_cast<uint32_t>(part >> bit_shift);
  }
  return out;
}

Num mod_pow(const Num &base, const Num &exponent, const Num &modulus,
            const Num &r2, uint32_t n0) {
  // `base` is already in Montgomery form for `modulus`.
  Num result = to_mont(kOne, r2, modulus, n0);
  for (size_t i = 256; i-- > 0;) {
    result = mont_mul(result, result, modulus, n0);
    const uint32_t bit = (exponent.v[i / 32] >> (i % 32)) & 1u;
    const Num product = mont_mul(result, base, modulus, n0);
    result = select_num(result, product, bit);
  }
  return result;
}

Num inv_field(const Num &value) {
  const Num exponent = sub_mod(kPrime, Num{{2u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}},
                               kPrime);
  return mod_pow(value, exponent, kPrime, kFieldR2, kFieldN0);
}

Num inv_scalar(const Num &value) {
  const Num exponent = sub_mod(kOrder, Num{{2u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}},
                               kOrder);
  return mod_pow(value, exponent, kOrder, kOrderR2, kOrderN0);
}

// ---------------------------------------------------------------------------
// Affine points in Montgomery form.
// ---------------------------------------------------------------------------
struct Point {
  Num x;
  Num y;
  bool infinity;
};

Point point_infinity() {
  return Point{Num{}, Num{}, true};
}

Point point_from_affine(const Num &x, const Num &y) {
  return Point{to_mont(x, kFieldR2, kPrime, kFieldN0),
               to_mont(y, kFieldR2, kPrime, kFieldN0), false};
}

bool point_on_curve_mont(const Point &p) {
  if (p.infinity) return true;
  const Num y2 = field_mul(p.y, p.y);
  const Num x2 = field_mul(p.x, p.x);
  const Num x3 = field_mul(x2, p.x);
  const Num rhs = add_mod(add_mod(x3, p.x, kPrime),
                          to_mont(kCurveBeta, kFieldR2, kPrime, kFieldN0),
                          kPrime);
  return equal(y2, rhs);
}

Point point_double(const Point &p) {
  if (p.infinity || is_zero(p.y)) return point_infinity();
  const Num x2 = field_mul(p.x, p.x);
  const Num three_x2 = add_mod(add_mod(x2, x2, kPrime), x2, kPrime);
  const Num numerator = add_mod(three_x2, to_mont(kOne, kFieldR2, kPrime, kFieldN0),
                                kPrime);  // a = 1
  const Num denominator = add_mod(p.y, p.y, kPrime);
  const Num lambda = field_mul(numerator, inv_field(denominator));
  const Num lambda2 = field_mul(lambda, lambda);
  const Num x3 = sub_mod(sub_mod(lambda2, p.x, kPrime), p.x, kPrime);
  const Num y3 = sub_mod(field_mul(lambda, sub_mod(p.x, x3, kPrime)),
                         p.y, kPrime);
  return Point{x3, y3, false};
}

Point point_add(const Point &p, const Point &q) {
  if (p.infinity) return q;
  if (q.infinity) return p;
  if (equal(p.x, q.x)) {
    if (equal(p.y, q.y)) return point_double(p);
    return point_infinity();
  }
  const Num lambda =
      field_mul(sub_mod(q.y, p.y, kPrime), inv_field(sub_mod(q.x, p.x, kPrime)));
  const Num lambda2 = field_mul(lambda, lambda);
  const Num x3 = sub_mod(sub_mod(lambda2, p.x, kPrime), q.x, kPrime);
  const Num y3 = sub_mod(field_mul(lambda, sub_mod(p.x, x3, kPrime)),
                         p.y, kPrime);
  return Point{x3, y3, false};
}

Point point_select(const Point &a, const Point &b, uint32_t bit) {
  Point out;
  out.x = select_num(a.x, b.x, bit);
  out.y = select_num(a.y, b.y, bit);
  out.infinity = bit != 0 ? b.infinity : a.infinity;
  return out;
}

Point point_mul_ct(const Num &scalar, const Point &base) {
  Point accumulator = point_infinity();
  for (size_t i = 252; i-- > 0;) {
    accumulator = point_double(accumulator);
    const Point sum = point_add(accumulator, base);
    const uint32_t bit = (scalar.v[i / 32] >> (i % 32)) & 1u;
    accumulator = point_select(accumulator, sum, bit);
  }
  return accumulator;
}

Point point_mul_vartime(const Num &scalar, const Point &base) {
  Point accumulator = point_infinity();
  for (size_t i = 252; i-- > 0;) {
    accumulator = point_double(accumulator);
    if (((scalar.v[i / 32] >> (i % 32)) & 1u) != 0) {
      accumulator = point_add(accumulator, base);
    }
  }
  return accumulator;
}

// Tonelli-Shanks for p - 1 = (2^59 + 17) * 2^192.
bool field_sqrt(const Num &value, Num *out) {
  if (is_zero(value)) {
    *out = value;
    return true;
  }
  const Num one_mont = to_mont(kOne, kFieldR2, kPrime, kFieldN0);
  const Num value_mont = to_mont(value, kFieldR2, kPrime, kFieldN0);
  const Num exponent = shr_bits(sub_mod(kPrime, kOne, kPrime), 1);
  const Num legendre =
      from_mont(mod_pow(value_mont, exponent, kPrime, kFieldR2, kFieldN0),
                kPrime, kFieldN0);
  if (!equal(legendre, kOne)) return false;
  Num q = {{17u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
  q.v[1] = 0x08000000u;
  Num z = {{2u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
  for (size_t attempt = 0; attempt < 32; ++attempt) {
    const Num z_mont = to_mont(z, kFieldR2, kPrime, kFieldN0);
    const Num check =
        from_mont(mod_pow(z_mont, exponent, kPrime, kFieldR2, kFieldN0),
                  kPrime, kFieldN0);
    if (!equal(check, kOne)) break;
    z.v[0] += 1;
  }
  Num c = mod_pow(to_mont(z, kFieldR2, kPrime, kFieldN0), q, kPrime, kFieldR2,
                  kFieldN0);
  Num t = mod_pow(value_mont, q, kPrime, kFieldR2, kFieldN0);
  const Num r_exp = shr_bits(add_mod(q, kOne, kPrime), 1);
  Num result = mod_pow(value_mont, r_exp, kPrime, kFieldR2, kFieldN0);
  size_t m = 192;
  while (!equal(t, one_mont)) {
    Num power = t;
    size_t i = 0;
    while (i < m && !equal(power, one_mont)) {
      power = field_mul(power, power);
      ++i;
    }
    if (i == m) return false;
    Num b = c;
    for (size_t step = 0; step + i + 1 < m; ++step) {
      b = field_mul(b, b);
    }
    m = i;
    c = field_mul(b, b);
    t = field_mul(field_mul(t, b), b);
    result = field_mul(result, b);
  }
  if (!equal(field_mul(result, result), value_mont)) return false;
  *out = from_mont(result, kPrime, kFieldN0);
  return true;
}

Point point_from_x(const Num &x_normal) {
  const Num x = to_mont(x_normal, kFieldR2, kPrime, kFieldN0);
  const Num x3 = field_mul(field_mul(x, x), x);
  const Num beta = to_mont(kCurveBeta, kFieldR2, kPrime, kFieldN0);
  const Num rhs = add_mod(add_mod(x3, x, kPrime), beta, kPrime);
  const Num rhs_normal = from_mont(rhs, kPrime, kFieldN0);
  Num y_normal;
  if (!field_sqrt(rhs_normal, &y_normal)) return point_infinity();
  return Point{x, to_mont(y_normal, kFieldR2, kPrime, kFieldN0), false};
}

// ---------------------------------------------------------------------------
// Pedersen hash.
// ---------------------------------------------------------------------------
Point pedersen_base(uint32_t index) {
  switch (index) {
    case 0: return point_from_affine(kShiftX, kShiftY);
    case 1: return point_from_affine(kP0X, kP0Y);
    case 2: return point_from_affine(kP1X, kP1Y);
    case 3: return point_from_affine(kP2X, kP2Y);
    default: return point_from_affine(kP3X, kP3Y);
  }
}

Num pedersen_combine(const Num &x, const Num &y) {
  const Point shift = pedersen_base(0);
  const Point p0 = pedersen_base(1);
  const Point p1 = pedersen_base(2);
  const Point p2 = pedersen_base(3);
  const Point p3 = pedersen_base(4);
  Num low_x = x;
  low_x.v[7] &= 0x00ffffffu;
  Num high_x = {{x.v[7] >> 24, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
  Num low_y = y;
  low_y.v[7] &= 0x00ffffffu;
  Num high_y = {{y.v[7] >> 24, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
  Point result = shift;
  result = point_add(result, point_mul_vartime(low_x, p0));
  result = point_add(result, point_mul_vartime(high_x, p1));
  result = point_add(result, point_mul_vartime(low_y, p2));
  result = point_add(result, point_mul_vartime(high_y, p3));
  return from_mont(result.x, kPrime, kFieldN0);
}

// ---------------------------------------------------------------------------
// Poseidon hash.
// ---------------------------------------------------------------------------
Num poseidon_round_constant(size_t index) {
  char label[24];
  const int written = snprintf(label, sizeof(label), "Hades%zu", index);
  uint8_t digest[kSha256Size];
  if (written <= 0 ||
      !crypto_sha256(reinterpret_cast<const uint8_t *>(label),
                     static_cast<size_t>(written), digest)) {
    return Num{};
  }
  return reduce_field(from_bytes(digest));
}

void poseidon_sbox(Num *value) {
  const Num square = field_mul(*value, *value);
  *value = field_mul(square, *value);
}

void poseidon_mix(Num state[3]) {
  const Num a = field_mul(state[0], to_mont(Num{{3u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}},
                                           kFieldR2, kPrime, kFieldN0));
  const Num t0 = add_mod(add_mod(a, state[1], kPrime), state[2], kPrime);
  const Num t1 = add_mod(add_mod(state[0], state[2], kPrime),
                         sub_mod(kPrime, state[1], kPrime), kPrime);
  const Num two_s2 =
      add_mod(state[2], state[2], kPrime);
  const Num t2 = sub_mod(add_mod(state[0], state[1], kPrime), two_s2, kPrime);
  state[0] = t0;
  state[1] = t1;
  state[2] = t2;
}

void poseidon_permute(Num state[3]) {
  size_t round = 0;
  for (; round < 4; ++round) {
    for (size_t lane = 0; lane < 3; ++lane) {
      state[lane] = add_mod(
          state[lane],
          to_mont(poseidon_round_constant(round * 3 + lane), kFieldR2, kPrime,
                  kFieldN0),
          kPrime);
    }
    poseidon_sbox(&state[0]);
    poseidon_sbox(&state[1]);
    poseidon_sbox(&state[2]);
    poseidon_mix(state);
  }
  for (size_t partial = 0; partial < 83; ++partial, ++round) {
    for (size_t lane = 0; lane < 3; ++lane) {
      state[lane] = add_mod(
          state[lane],
          to_mont(poseidon_round_constant(round * 3 + lane), kFieldR2, kPrime,
                  kFieldN0),
          kPrime);
    }
    poseidon_sbox(&state[2]);
    poseidon_mix(state);
  }
  for (; round < 91; ++round) {
    for (size_t lane = 0; lane < 3; ++lane) {
      state[lane] = add_mod(
          state[lane],
          to_mont(poseidon_round_constant(round * 3 + lane), kFieldR2, kPrime,
                  kFieldN0),
          kPrime);
    }
    poseidon_sbox(&state[0]);
    poseidon_sbox(&state[1]);
    poseidon_sbox(&state[2]);
    poseidon_mix(state);
  }
}

// ---------------------------------------------------------------------------
// RFC 6979 nonces.
// ---------------------------------------------------------------------------
void hmac_sha256(const uint8_t *key, size_t key_size, const uint8_t *data,
                 size_t data_size, uint8_t out[32]) {
  if (!crypto_hmac_sha256(key, key_size, data, data_size, out)) {
    memset(out, 0, 32);
  }
}

Num bits2int_mod_order(const uint8_t hash[kBytes]) {
  Num value = from_bytes(hash);
  size_t bits = 0;
  for (size_t i = kLimbs; i-- > 0;) {
    if (value.v[i] != 0) {
      uint32_t top = value.v[i];
      size_t significant = 0;
      while (top != 0) {
        top >>= 1;
        ++significant;
      }
      bits = i * 32 + significant;
      break;
    }
  }
  const size_t digits = (bits + 3) / 4;
  // StarkWare pads a 63-hex-digit hash by one nibble before bits2int; the
  // subsequent 252-bit truncation cancels that shift, so such a value is used
  // as-is. A full 64-digit value is truncated to its top 252 bits.
  if (digits == 64) {
    value = shr_bits(value, 4);
  }
  if (compare(value, kOrder) >= 0) {
    value = sub_mod(value, kOrder, kOrder);
  }
  return value;
}

bool next_nonce(uint8_t V[32], uint8_t K[32], Num *out) {
  for (size_t attempt = 0; attempt < 64; ++attempt) {
    uint8_t message[32];
    hmac_sha256(K, 32, V, 32, message);
    memcpy(V, message, 32);
    Num candidate = shr_bits(from_bytes(V), 4);
    if (!is_zero(candidate) && compare(candidate, kOrder) < 0) {
      *out = candidate;
      return true;
    }
    uint8_t block[33];
    memcpy(block, V, 32);
    block[32] = 0;
    hmac_sha256(K, 32, block, sizeof(block), message);
    memcpy(K, message, 32);
    hmac_sha256(K, 32, V, 32, message);
    memcpy(V, message, 32);
  }
  return false;
}

bool derive_nonce_state(const Num &private_key, const uint8_t hash[kBytes],
                        uint8_t V[32], uint8_t K[32]) {
  uint8_t seed[64];
  to_bytes(private_key, seed);
  to_bytes(bits2int_mod_order(hash), seed + 32);
  memset(V, 0x01, 32);
  memset(K, 0x00, 32);
  uint8_t block[97];
  memcpy(block, V, 32);
  block[32] = 0;
  memcpy(block + 33, seed, sizeof(seed));
  hmac_sha256(K, 32, block, 33 + sizeof(seed), K);
  hmac_sha256(K, 32, V, 32, V);
  memcpy(block, V, 32);
  block[32] = 1;
  memcpy(block + 33, seed, sizeof(seed));
  hmac_sha256(K, 32, block, 33 + sizeof(seed), K);
  hmac_sha256(K, 32, V, 32, V);
  return true;
}

bool stark_verify_point(const Point &public_key, const Num &hash,
                        const Num &r, const Num &s) {
  Num w = inv_scalar(to_mont(s, kOrderR2, kOrder, kOrderN0));
  w = from_mont(w, kOrder, kOrderN0);
  if (is_zero(w) || compare(w, kMaxValue) >= 0) return false;
  const Point generator = point_from_affine(kGx, kGy);
  const Num u1 = scalar_mul(to_mont(hash, kOrderR2, kOrder, kOrderN0),
                            to_mont(w, kOrderR2, kOrder, kOrderN0));
  const Num u2 = scalar_mul(to_mont(r, kOrderR2, kOrder, kOrderN0),
                            to_mont(w, kOrderR2, kOrder, kOrderN0));
  const Point p1 = point_mul_ct(from_mont(u1, kOrder, kOrderN0), generator);
  const Point p2 = point_mul_ct(from_mont(u2, kOrder, kOrderN0), public_key);
  const Point sum = point_add(p1, p2);
  if (sum.infinity) return false;
  const Num x = from_mont(sum.x, kPrime, kFieldN0);
  return equal(x, r);
}

}  // namespace

bool stark_pedersen(const uint8_t x[kStarkFeltSize],
                    const uint8_t y[kStarkFeltSize],
                    uint8_t out[kStarkFeltSize]) {
  Num x_value;
  Num y_value;
  if (!parse_felt(x, &x_value) || !parse_felt(y, &y_value)) return false;
  to_bytes(pedersen_combine(x_value, y_value), out);
  return true;
}

bool stark_pedersen_many(const uint8_t (*values)[kStarkFeltSize], size_t count,
                         uint8_t out[kStarkFeltSize]) {
  if (count != 0 && values == nullptr) return false;
  Num accumulator = {};
  for (size_t i = 0; i < count; ++i) {
    Num value;
    if (!parse_felt(values[i], &value)) return false;
    accumulator = pedersen_combine(accumulator, value);
  }
  Num length = {};
  length.v[0] = static_cast<uint32_t>(count);
  to_bytes(pedersen_combine(accumulator, length), out);
  return true;
}

bool stark_poseidon(const uint8_t x[kStarkFeltSize],
                    const uint8_t y[kStarkFeltSize],
                    uint8_t out[kStarkFeltSize]) {
  Num x_value;
  Num y_value;
  if (!parse_felt(x, &x_value) || !parse_felt(y, &y_value)) return false;
  Num state[3] = {to_mont(x_value, kFieldR2, kPrime, kFieldN0),
                  to_mont(y_value, kFieldR2, kPrime, kFieldN0),
                  to_mont(Num{{2u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}}, kFieldR2,
                          kPrime, kFieldN0)};
  poseidon_permute(state);
  to_bytes(from_mont(state[0], kPrime, kFieldN0), out);
  return true;
}

bool stark_poseidon_many(const uint8_t (*values)[kStarkFeltSize], size_t count,
                         uint8_t out[kStarkFeltSize]) {
  if (count != 0 && values == nullptr) return false;
  // Sponge padding: append 1, then zeros to a multiple of the rate (2).
  const size_t padded = count + 1;
  const size_t total = padded + (padded & 1);
  Num state[3] = {};
  for (size_t index = 0; index < total; index += 2) {
    Num pair[2];
    for (size_t lane = 0; lane < 2; ++lane) {
      const size_t position = index + lane;
      if (position < count) {
        pair[lane] = from_bytes(values[position]);
        if (compare(pair[lane], kPrime) >= 0) return false;
      } else if (position == count) {
        pair[lane] = Num{{1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
      } else {
        pair[lane] = Num{};
      }
    }
    state[0] = add_mod(state[0],
                       to_mont(pair[0], kFieldR2, kPrime, kFieldN0), kPrime);
    state[1] = add_mod(state[1],
                       to_mont(pair[1], kFieldR2, kPrime, kFieldN0), kPrime);
    poseidon_permute(state);
  }
  to_bytes(from_mont(state[0], kPrime, kFieldN0), out);
  return true;
}

bool stark_grind_key(const uint8_t seed[kStarkFeltSize],
                     uint8_t out_private_key[kStarkFeltSize]) {
  if (seed == nullptr || out_private_key == nullptr) return false;
  // 2^256 mod n; key_max = 2^256 - remainder.
  const Num remainder = {{0xf4fca74fu, 0x51925a0bu, 0x6df16beeu, 0xc75ec4b4u,
                          0x00000008u, 0x00000000u, 0xfffffdf1u, 0x07ffffffu}};
  // 2^256 - remainder is not representable in 256 bits as a plain Num, so the
  // rejection test is expressed as `candidate + remainder` not overflowing.
  uint8_t candidate_bytes[kBytes];
  for (uint32_t counter = 0; counter < 0xFFFFFFFFu; ++counter) {
    uint8_t input[kBytes + 4];
    memcpy(input, seed, kBytes);
    size_t length = kBytes;
    // Minimal big-endian counter, at least one byte.
    uint8_t counter_bytes[4];
    size_t counter_length = 0;
    for (uint32_t value = counter; value != 0; value >>= 8) {
      counter_bytes[counter_length++] = static_cast<uint8_t>(value & 0xFF);
    }
    if (counter_length == 0) counter_bytes[counter_length++] = 0;
    for (size_t i = 0; i < counter_length; ++i) {
      input[length++] = counter_bytes[counter_length - 1 - i];
    }
    if (!crypto_sha256(input, length, candidate_bytes)) return false;
    const Num candidate = from_bytes(candidate_bytes);
    Num sum;
    const uint32_t carry = add_raw(candidate, remainder, &sum);
    if (carry != 0) continue;  // candidate >= 2^256 - remainder
    // candidate % n: at most 31 subtractions because candidate < 32n.
    Num reduced = candidate;
    for (size_t i = 0; i < 32; ++i) {
      reduced = cond_sub(reduced, kOrder, 1);
    }
    if (is_zero(reduced)) continue;
    to_bytes(reduced, out_private_key);
    return true;
  }
  return false;
}

bool stark_public_key(const uint8_t private_key[kStarkFeltSize],
                      uint8_t out_x[kStarkFeltSize]) {
  Num scalar;
  if (!parse_scalar(private_key, &scalar) || out_x == nullptr) return false;
  const Point point = point_mul_ct(scalar, point_from_affine(kGx, kGy));
  if (point.infinity) return false;
  to_bytes(from_mont(point.x, kPrime, kFieldN0), out_x);
  return true;
}

bool stark_sign(const uint8_t private_key[kStarkFeltSize],
                const uint8_t message_hash[kStarkFeltSize],
                uint8_t out_r[kStarkFeltSize], uint8_t out_s[kStarkFeltSize]) {
  Num private_scalar;
  if (out_r == nullptr || out_s == nullptr ||
      !parse_scalar(private_key, &private_scalar)) {
    return false;
  }
  const Num hash_value = from_bytes(message_hash);
  if (compare(hash_value, kMaxValue) >= 0) return false;
  const Point generator = point_from_affine(kGx, kGy);
  const Point public_point = point_mul_ct(private_scalar, generator);
  if (public_point.infinity) return false;

  const Num d_mont = to_mont(private_scalar, kOrderR2, kOrder, kOrderN0);
  const Num h_mont = to_mont(hash_value, kOrderR2, kOrder, kOrderN0);
  uint8_t V[32];
  uint8_t K[32];
  derive_nonce_state(private_scalar, message_hash, V, K);
  for (size_t attempt = 0; attempt < 128; ++attempt) {
    Num k;
    if (!next_nonce(V, K, &k)) return false;
    const Point point = point_mul_ct(k, generator);
    if (point.infinity) continue;
    const Num r = from_mont(point.x, kPrime, kFieldN0);
    if (is_zero(r) || compare(r, kMaxValue) >= 0) continue;
    const Num r_mont = to_mont(r, kOrderR2, kOrder, kOrderN0);
    const Num denominator = add_mod(
        h_mont, scalar_mul(r_mont, d_mont), kOrder);
    if (is_zero(denominator)) continue;
    const Num k_mont = to_mont(k, kOrderR2, kOrder, kOrderN0);
    const Num w = scalar_mul(k_mont, inv_scalar(denominator));
    const Num w_normal = from_mont(w, kOrder, kOrderN0);
    if (is_zero(w_normal) || compare(w_normal, kMaxValue) >= 0) continue;
    const Num s = from_mont(inv_scalar(w), kOrder, kOrderN0);
    if (is_zero(s) || compare(s, kOrder) >= 0) continue;
    if (!stark_verify_point(public_point, hash_value, r, s)) continue;
    to_bytes(r, out_r);
    to_bytes(s, out_s);
    return true;
  }
  return false;
}

bool stark_verify(const uint8_t public_key_x[kStarkFeltSize],
                  const uint8_t message_hash[kStarkFeltSize],
                  const uint8_t r_bytes[kStarkFeltSize],
                  const uint8_t s_bytes[kStarkFeltSize]) {
  Num x_normal;
  Num r;
  Num s;
  if (!parse_felt(public_key_x, &x_normal) || !parse_scalar(r_bytes, &r) ||
      !parse_scalar(s_bytes, &s)) {
    return false;
  }
  if (compare(r, kMaxValue) >= 0) return false;
  const Num hash_value = from_bytes(message_hash);
  if (compare(hash_value, kMaxValue) >= 0) return false;
  Point public_point = point_from_x(x_normal);
  if (public_point.infinity) return false;
  if (stark_verify_point(public_point, hash_value, r, s)) return true;
  public_point.y = sub_mod(Num{}, public_point.y, kPrime);
  return stark_verify_point(public_point, hash_value, r, s);
}

namespace {

void felt_from_u64(uint64_t value, uint8_t out[kStarkFeltSize]) {
  memset(out, 0, kStarkFeltSize);
  for (size_t i = 0; i < 8; ++i) {
    out[kStarkFeltSize - 1 - i] = static_cast<uint8_t>(value >> (8 * i));
  }
}

void felt_short_string(const char *text, uint8_t out[kStarkFeltSize]) {
  memset(out, 0, kStarkFeltSize);
  const size_t length = strlen(text);
  if (length > kStarkFeltSize) return;
  memcpy(out + kStarkFeltSize - length, text, length);
}

void felt_resource_bounds(const StarkResourceBounds &bounds, const char *name,
                          uint8_t out[kStarkFeltSize]) {
  memset(out, 0, kStarkFeltSize);
  const size_t length = strlen(name);
  memcpy(out + 8 - length, name, length);
  for (size_t i = 0; i < 8; ++i) {
    out[8 + i] = static_cast<uint8_t>(bounds.max_amount >> (8 * (7 - i)));
  }
  memcpy(out + 16, bounds.max_price, 16);
}

bool compute_fee_hash(const StarkV3Fees &fees, uint8_t out[kStarkFeltSize]) {
  uint8_t fields[4][kStarkFeltSize];
  felt_from_u64(fees.tip, fields[0]);
  felt_resource_bounds(fees.l1_gas, "L1_GAS", fields[1]);
  felt_resource_bounds(fees.l2_gas, "L2_GAS", fields[2]);
  felt_resource_bounds(fees.l1_data_gas, "L1_DATA", fields[3]);
  return stark_poseidon_many(fields, 4, out);
}

bool common_v3_hash(const char *prefix, const uint8_t sender[kStarkFeltSize],
                    uint64_t nonce, const StarkV3Fees &fees,
                    uint8_t nonce_da_mode, uint8_t fee_da_mode,
                    const uint8_t (*additional)[kStarkFeltSize],
                    size_t additional_count, uint8_t out[kStarkFeltSize]) {
  if (sender == nullptr || out == nullptr) return false;
  uint8_t fee_hash[kStarkFeltSize];
  if (!compute_fee_hash(fees, fee_hash)) return false;
  uint8_t paymaster[kStarkFeltSize];
  if (!stark_poseidon_many(nullptr, 0, paymaster)) return false;
  if (additional_count > 3) return false;
  uint8_t elements[11][kStarkFeltSize];
  felt_short_string(prefix, elements[0]);
  felt_from_u64(3, elements[1]);
  memcpy(elements[2], sender, kStarkFeltSize);
  memcpy(elements[3], fee_hash, kStarkFeltSize);
  memcpy(elements[4], paymaster, kStarkFeltSize);
  felt_short_string("SN_MAIN", elements[5]);
  felt_from_u64(nonce, elements[6]);
  uint8_t da_mode[kStarkFeltSize] = {};
  da_mode[kStarkFeltSize - 5] = nonce_da_mode;
  da_mode[kStarkFeltSize - 1] = fee_da_mode;
  memcpy(elements[7], da_mode, kStarkFeltSize);
  for (size_t i = 0; i < additional_count; ++i) {
    memcpy(elements[8 + i], additional[i], kStarkFeltSize);
  }
  return stark_poseidon_many(elements, 8 + additional_count, out);
}

}  // namespace

bool stark_invoke_v3_hash(const uint8_t sender[kStarkFeltSize],
                          uint64_t nonce, const StarkV3Fees &fees,
                          uint8_t nonce_da_mode, uint8_t fee_da_mode,
                          const uint8_t (*calldata)[kStarkFeltSize],
                          size_t calldata_count, uint8_t out[kStarkFeltSize]) {
  if (calldata_count != 0 && calldata == nullptr) return false;
  uint8_t additional[2][kStarkFeltSize];
  if (!stark_poseidon_many(nullptr, 0, additional[0]) ||
      !stark_poseidon_many(calldata, calldata_count, additional[1])) {
    return false;
  }
  return common_v3_hash("invoke", sender, nonce, fees, nonce_da_mode,
                        fee_da_mode, additional, 2, out);
}

bool stark_deploy_account_v3_hash(
    const uint8_t contract_address[kStarkFeltSize],
    const uint8_t class_hash[kStarkFeltSize],
    const uint8_t salt[kStarkFeltSize],
    const uint8_t (*constructor_calldata)[kStarkFeltSize],
    size_t calldata_count, uint64_t nonce, const StarkV3Fees &fees,
    uint8_t nonce_da_mode, uint8_t fee_da_mode, uint8_t out[kStarkFeltSize]) {
  if (contract_address == nullptr || class_hash == nullptr || salt == nullptr ||
      (calldata_count != 0 && constructor_calldata == nullptr)) {
    return false;
  }
  uint8_t additional[3][kStarkFeltSize];
  if (!stark_poseidon_many(constructor_calldata, calldata_count,
                           additional[0])) {
    return false;
  }
  memcpy(additional[1], class_hash, kStarkFeltSize);
  memcpy(additional[2], salt, kStarkFeltSize);
  return common_v3_hash("deploy_account", contract_address, nonce, fees,
                        nonce_da_mode, fee_da_mode, additional, 3, out);
}

bool stark_contract_address(const uint8_t class_hash[kStarkFeltSize],
                            const uint8_t salt[kStarkFeltSize],
                            const uint8_t (*constructor_calldata)[kStarkFeltSize],
                            size_t calldata_count,
                            const uint8_t deployer[kStarkFeltSize],
                            uint8_t out[kStarkFeltSize]) {
  if (out == nullptr || deployer == nullptr ||
      (calldata_count != 0 && constructor_calldata == nullptr)) {
    return false;
  }
  Num class_value;
  Num salt_value;
  Num deployer_value;
  if (!parse_felt(class_hash, &class_value) ||
      !parse_felt(salt, &salt_value) ||
      !parse_felt(deployer, &deployer_value)) {
    return false;
  }
  static const char kPrefix[] = "STARKNET_CONTRACT_ADDRESS";
  Num prefix = {};
  for (size_t i = 0; i < sizeof(kPrefix) - 1; ++i) {
    // The prefix is shorter than 32 bytes, so shift left one byte at a time.
    for (size_t j = kLimbs; j-- > 0;) {
      const uint32_t carry =
          j == 0 ? 0 : prefix.v[j - 1] >> 24;
      prefix.v[j] = (prefix.v[j] << 8) | carry;
    }
    prefix.v[0] |= static_cast<uint32_t>(kPrefix[i]);
  }
  Num calldata_hash = {};
  for (size_t i = 0; i < calldata_count; ++i) {
    Num value;
    if (!parse_felt(constructor_calldata[i], &value)) return false;
    calldata_hash = pedersen_combine(calldata_hash, value);
  }
  Num calldata_length = {};
  calldata_length.v[0] = static_cast<uint32_t>(calldata_count);
  calldata_hash = pedersen_combine(calldata_hash, calldata_length);
  const Num elements[5] = {prefix, deployer_value, salt_value, class_value,
                           calldata_hash};
  Num accumulator = {};
  for (size_t i = 0; i < 5; ++i) {
    accumulator = pedersen_combine(accumulator, elements[i]);
  }
  accumulator = pedersen_combine(accumulator,
                                 Num{{5u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}});
  const Num bound = kMaxValue;
  while (compare(accumulator, bound) >= 0) {
    Num difference;
    sub_raw(accumulator, bound, &difference);
    accumulator = difference;
  }
  to_bytes(accumulator, out);
  return true;
}

bool run_starknet_crypto_self_tests() {
#if !defined(HEXWALLET_HOST_TEST)
  return true;
#else
#include "tests/fixtures/StarknetVectors.inc"
  auto decode = [](const char *text, uint8_t out[kStarkFeltSize]) {
    if (text == nullptr) return false;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;
    const size_t length = strlen(text);
    if (length == 0 || length > 2 * kStarkFeltSize) return false;
    memset(out, 0, kStarkFeltSize);
    const size_t offset = 2 * kStarkFeltSize - length;
    for (size_t i = 0; i < length; ++i) {
      const char c = text[i];
      uint8_t digit = 0;
      if (c >= '0' && c <= '9') digit = static_cast<uint8_t>(c - '0');
      else if (c >= 'a' && c <= 'f') digit = static_cast<uint8_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') digit = static_cast<uint8_t>(c - 'A' + 10);
      else return false;
      const size_t position = offset + i;
      if ((position & 1) == 0) {
        out[position / 2] |= static_cast<uint8_t>(digit << 4);
      } else {
        out[position / 2] |= digit;
      }
    }
    return true;
  };
  bool ok = true;
  auto check = [&](bool value, const char *label) {
    if (!value) {
      printf("starknet KAT failed: %s\n", label);
      ok = false;
    }
  };

  uint8_t a[kStarkFeltSize], b[kStarkFeltSize], expected[kStarkFeltSize],
      actual[kStarkFeltSize];
  check(decode(STARK_MUL_A, a) && decode(STARK_MUL_B, b) &&
            decode(STARK_MUL_OUT, expected),
        "mul-decode");
  Num am, bm;
  check(parse_felt(a, &am) && parse_felt(b, &bm), "mul-parse");
  to_bytes(from_mont(field_mul(to_mont(am, kFieldR2, kPrime, kFieldN0),
                               to_mont(bm, kFieldR2, kPrime, kFieldN0)),
                     kPrime, kFieldN0),
           actual);
  check(memcmp(actual, expected, kStarkFeltSize) == 0, "mul");

  check(decode(STARK_INV_A, a) && decode(STARK_INV_OUT, expected),
        "inv-decode");
  parse_felt(a, &am);
  to_bytes(from_mont(inv_field(to_mont(am, kFieldR2, kPrime, kFieldN0)),
                     kPrime, kFieldN0),
           actual);
  check(memcmp(actual, expected, kStarkFeltSize) == 0, "inv");

  check(decode(STARK_PEDERSEN_X, a) && decode(STARK_PEDERSEN_Y, b) &&
            decode(STARK_PEDERSEN_OUT, expected),
        "pedersen-decode");
  check(stark_pedersen(a, b, actual) &&
            memcmp(actual, expected, kStarkFeltSize) == 0,
        "pedersen");

  uint8_t many[3][kStarkFeltSize] = {};
  many[0][kStarkFeltSize - 1] = 1;
  many[1][kStarkFeltSize - 1] = 2;
  many[2][kStarkFeltSize - 1] = 3;
  check(decode(STARK_PEDERSEN_MANY_OUT, expected), "pedersen-many-decode");
  check(stark_pedersen_many(many, 3, actual) &&
            memcmp(actual, expected, kStarkFeltSize) == 0,
        "pedersen-many");

  check(decode(STARK_POSEIDON_X, a) && decode(STARK_POSEIDON_Y, b) &&
            decode(STARK_POSEIDON_OUT, expected),
        "poseidon-decode");
  check(stark_poseidon(a, b, actual) &&
            memcmp(actual, expected, kStarkFeltSize) == 0,
        "poseidon");

  check(decode(STARK_POSEIDON_SINGLE_IN, a) &&
            decode(STARK_POSEIDON_SINGLE_OUT, expected),
        "poseidon-single-decode");
  Num single_x;
  parse_felt(a, &single_x);
  Num state[3] = {to_mont(single_x, kFieldR2, kPrime, kFieldN0),
                  to_mont(Num{}, kFieldR2, kPrime, kFieldN0),
                  to_mont(Num{{1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}}, kFieldR2,
                          kPrime, kFieldN0)};
  poseidon_permute(state);
  to_bytes(from_mont(state[0], kPrime, kFieldN0), actual);
  check(memcmp(actual, expected, kStarkFeltSize) == 0, "poseidon-single");

  check(decode(STARK_POSEIDON_MANY_OUT, expected), "poseidon-many-decode");
  check(stark_poseidon_many(many, 3, actual) &&
            memcmp(actual, expected, kStarkFeltSize) == 0,
        "poseidon-many");

  uint8_t public_key[kStarkFeltSize];
  check(decode(STARK_KEY_PRIV, a) && decode(STARK_KEY_OUT, public_key),
        "stark-key-decode");
  check(stark_public_key(a, actual) &&
            memcmp(actual, public_key, kStarkFeltSize) == 0,
        "stark-key");

  check(decode(STARK_GRIND_SEED, a) && decode(STARK_GRIND_OUT, expected),
        "grind-decode");
  check(stark_grind_key(a, actual) &&
            memcmp(actual, expected, kStarkFeltSize) == 0,
        "grind");

  check(decode(STARK_SIGN_PRIV, a) && decode(STARK_SIGN_HASH, b) &&
            decode(STARK_SIGN_R, expected),
        "sign-decode");
  uint8_t r[kStarkFeltSize], s[kStarkFeltSize], expected_s[kStarkFeltSize];
  check(decode(STARK_SIGN_S, expected_s), "sign-s-decode");
  check(stark_sign(a, b, r, s) && memcmp(r, expected, kStarkFeltSize) == 0 &&
            memcmp(s, expected_s, kStarkFeltSize) == 0,
        "sign");
  // The signature vector belongs to STARK_SIGN_PRIV, not to STARK_KEY_PRIV.
  check(stark_public_key(a, public_key), "sign-public-key");
  check(stark_verify(public_key, b, r, s), "verify");

  check(decode(STARK_ADDRESS_CLASS_HASH, a) && decode(STARK_ADDRESS_SALT, b) &&
            decode(STARK_ADDRESS_CALLDATA0, many[0]) &&
            decode(STARK_ADDRESS_OUT, expected),
        "address-decode");
  uint8_t zero[kStarkFeltSize] = {};
  uint8_t address_fixture[kStarkFeltSize];
  memcpy(address_fixture, expected, kStarkFeltSize);
  check(stark_contract_address(a, b, many, 1, zero, actual) &&
            memcmp(actual, address_fixture, kStarkFeltSize) == 0,
        "address");

  StarkV3Fees fees = {};
  fees.tip = 9;
  fees.l1_gas.max_amount = 1000;
  fees.l1_gas.max_price[15] = 0xd0;
  fees.l1_gas.max_price[14] = 0x07;
  fees.l2_gas.max_amount = 3000;
  fees.l2_gas.max_price[15] = 0xa0;
  fees.l2_gas.max_price[14] = 0x0f;
  fees.l1_data_gas.max_amount = 500;
  fees.l1_data_gas.max_price[15] = 0x58;
  fees.l1_data_gas.max_price[14] = 0x02;
  uint8_t calldata[3][kStarkFeltSize] = {};
  for (size_t i = 0; i < 3; ++i)
    calldata[i][kStarkFeltSize - 1] = static_cast<uint8_t>(i + 1);
  check(decode(STARK_INVOKE_HASH, expected), "invoke-hash-decode");
  check(stark_invoke_v3_hash(address_fixture, 7, fees, 0, 0, calldata, 3,
                             actual),
        "invoke-hash-run");
  check(memcmp(actual, expected, kStarkFeltSize) == 0, "invoke-hash");

  check(decode(STARK_INVOKE_R, r) && decode(STARK_INVOKE_S, s) &&
            decode(STARK_SIGN_PRIV, a),
        "invoke-signature-decode");
  uint8_t invoke_hash[kStarkFeltSize];
  memcpy(invoke_hash, expected, kStarkFeltSize);
  check(stark_sign(a, invoke_hash, actual, b) &&
            memcmp(actual, r, kStarkFeltSize) == 0 &&
            memcmp(b, s, kStarkFeltSize) == 0,
        "invoke-signature");

  uint8_t class_hash[kStarkFeltSize], salt[kStarkFeltSize];
  memset(class_hash, 0, sizeof(class_hash));
  memset(salt, 0, sizeof(salt));
  class_hash[kStarkFeltSize - 2] = 0x0a;
  class_hash[kStarkFeltSize - 1] = 0xbc;
  salt[kStarkFeltSize - 2] = 0x0d;
  salt[kStarkFeltSize - 1] = 0xef;
  fees.tip = 10;
  check(decode(STARK_DEPLOY_HASH, expected), "deploy-hash-decode");
  check(stark_deploy_account_v3_hash(address_fixture, class_hash, salt, many, 1,
                                     8, fees, 0, 0, actual),
        "deploy-hash-run");
  check(memcmp(actual, expected, kStarkFeltSize) == 0, "deploy-hash");

  return ok;
#endif
}

}  // namespace hexwallet
