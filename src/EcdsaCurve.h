#ifndef HEXWALLET_ECDSA_CURVE_H
#define HEXWALLET_ECDSA_CURVE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet
{

  // One ECDSA engine for the two 256-bit prime curves a hardware wallet has to
  // cover, instead of one implementation per curve.
  //
  // secp256k1 already signs through mbedtls, but on the host the linked mbedtls
  // is a stub that refuses every operation - so no host test had ever verified
  // a produced signature, and verification of on-chain signatures was
  // impossible off-device. secp256r1 lives in P256Sign.h; that file proves
  // itself against RFC 6979 A.2.5 but only knows one curve.
  //
  // This engine is the shared implementation: field arithmetic over
  // p = 2^256 - ... in 8x32-bit limbs, Montgomery multiplication (full product
  // followed by REDC), Jacobian point arithmetic with the `a` coefficient as a
  // curve parameter, RFC 6979 section 3.2 nonces with HMAC-SHA-256, low-S
  // normalisation, strict DER, and a verifier that every signature passes
  // before it is returned.
  //
  // The two magic constants that are easiest to transcribe wrongly - the
  // Montgomery factor n0 = -p^-1 mod 2^32 and R^2 = 2^512 mod p - are computed
  // from the modulus at first use rather than copied from a table. Everything
  // else (p, n, b, G) is pinned by run_ecdsa_curve_self_tests(), which checks
  // G is on the curve, that n*G is the point at infinity, and that published
  // RFC 6979 answers are reproduced byte for byte.

  enum class EcdsaCurve : uint8_t
  {
    Secp256k1 = 0,
    Secp256r1 = 1,
  };

  constexpr size_t kEcdsaScalarSize = 32;
  constexpr size_t kEcdsaDigestSize = 32;
  constexpr size_t kEcdsaPointSize = 64;
  constexpr size_t kEcdsaCompressedPointSize = 33;
  constexpr size_t kEcdsaUncompressedPointSize = 65;
  constexpr size_t kEcdsaSignatureSize = 64;
  constexpr size_t kEcdsaDerMaxSize = 72;

  namespace ecdsa_detail
  {

    constexpr size_t kLimbs = 8;
    constexpr size_t kBytes = 32;

    struct Num
    {
      uint32_t v[kLimbs];
    };

    // Curve constants, in little-endian 32-bit limbs.
    struct CurveConstants
    {
      Num prime;
      Num order;
      Num curve_b;
      Num gx;
      Num gy;
      // P-256 uses a = -3 and secp256k1 uses a = 0. Those are the only two
      // shapes this engine supports; anything else is a compile-time choice
      // here rather than a silent wrong answer at signing time.
      bool a_is_minus_three;
    };

    // Constants plus the Montgomery factors derived from the modulus.
    struct Curve
    {
      Num prime;
      Num order;
      Num curve_b;
      Num gx;
      Num gy;
      uint32_t field_n0;
      uint32_t order_n0;
      Num field_r2;
      Num order_r2;
      bool a_is_minus_three;
    };

    constexpr Num kSecp256k1Prime = {
        {0xfffffc2fu, 0xfffffffeu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
         0xffffffffu, 0xffffffffu, 0xffffffffu}};
    constexpr Num kSecp256k1Order = {
        {0xd0364141u, 0xbfd25e8cu, 0xaf48a03bu, 0xbaaedce6u, 0xfffffffeu,
         0xffffffffu, 0xffffffffu, 0xffffffffu}};
    constexpr Num kSecp256k1B = {{7u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
    constexpr Num kSecp256k1Gx = {
        {0x16f81798u, 0x59f2815bu, 0x2dce28d9u, 0x029bfcdbu, 0xce870b07u,
         0x55a06295u, 0xf9dcbbacu, 0x79be667eu}};
    constexpr Num kSecp256k1Gy = {
        {0xfb10d4b8u, 0x9c47d08fu, 0xa6855419u, 0xfd17b448u, 0x0e1108a8u,
         0x5da4fbfcu, 0x26a3c465u, 0x483ada77u}};

    // Same constants P256Sign.h already validates against RFC 6979 A.2.5.
    constexpr Num kP256Prime = {{0xffffffffu, 0xffffffffu, 0xffffffffu,
                                 0x00000000u, 0x00000000u, 0x00000000u,
                                 0x00000001u, 0xffffffffu}};
    constexpr Num kP256Order = {{0xfc632551u, 0xf3b9cac2u, 0xa7179e84u,
                                 0xbce6faadu, 0xffffffffu, 0xffffffffu,
                                 0x00000000u, 0xffffffffu}};
    constexpr Num kP256B = {{0x27d2604bu, 0x3bce3c3eu, 0xcc53b0f6u,
                             0x651d06b0u, 0x769886bcu, 0xb3ebbd55u,
                             0xaa3a93e7u, 0x5ac635d8u}};
    constexpr Num kP256Gx = {{0xd898c296u, 0xf4a13945u, 0x2deb33a0u,
                              0x77037d81u, 0x63a440f2u, 0xf8bce6e5u,
                              0xe12c4247u, 0x6b17d1f2u}};
    constexpr Num kP256Gy = {{0x37bf51f5u, 0xcbb64068u, 0x6b315eceu,
                              0x2bce3357u, 0x7c0f9e16u, 0x8ee7eb4au,
                              0xfe1a7f9bu, 0x4fe342e2u}};

    inline constexpr Num zero()
    {
      return Num{{0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
    }

    inline constexpr Num one()
    {
      return Num{{1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
    }

    inline bool is_zero(const Num &a)
    {
      uint32_t acc = 0;
      for (size_t i = 0; i < kLimbs; ++i)
        acc |= a.v[i];
      return acc == 0;
    }

    inline int compare(const Num &a, const Num &b)
    {
      for (size_t i = kLimbs; i-- > 0;)
      {
        if (a.v[i] != b.v[i])
          return a.v[i] < b.v[i] ? -1 : 1;
      }
      return 0;
    }

    inline uint32_t add_raw(const Num &a, const Num &b, Num *out)
    {
      uint64_t carry = 0;
      for (size_t i = 0; i < kLimbs; ++i)
      {
        const uint64_t sum = static_cast<uint64_t>(a.v[i]) + b.v[i] + carry;
        out->v[i] = static_cast<uint32_t>(sum);
        carry = sum >> 32;
      }
      return static_cast<uint32_t>(carry);
    }

    inline uint32_t sub_raw(const Num &a, const Num &b, Num *out)
    {
      uint64_t borrow = 0;
      for (size_t i = 0; i < kLimbs; ++i)
      {
        const uint64_t left = static_cast<uint64_t>(a.v[i]) - b.v[i] - borrow;
        out->v[i] = static_cast<uint32_t>(left);
        borrow = (left >> 63) & 1u;
      }
      return static_cast<uint32_t>(borrow);
    }

    // 2^256 - modulus, i.e. the two's complement of the modulus over k limbs.
    inline Num complement_modulus(const Num &modulus)
    {
      Num result;
      uint32_t carry = 1;
      for (size_t i = 0; i < kLimbs; ++i)
      {
        const uint32_t inverted = ~modulus.v[i];
        const uint32_t sum = inverted + carry;
        result.v[i] = sum;
        carry = sum < inverted ? 1u : 0u;
      }
      return result;
    }

    // Subtracts the modulus once when `subtract` is set - the post-condition of
    // a Montgomery product and of a modular addition.
    inline Num cond_sub(const Num &a, const Num &modulus, uint32_t subtract)
    {
      Num diff;
      const uint32_t borrow = sub_raw(a, modulus, &diff);
      const uint32_t take = subtract & (borrow ^ 1u);
      Num result;
      for (size_t i = 0; i < kLimbs; ++i)
      {
        result.v[i] = take != 0 ? diff.v[i] : a.v[i];
      }
      return result;
    }

    inline Num add_mod(const Num &a, const Num &b, const Num &modulus)
    {
      Num sum;
      const uint32_t carry = add_raw(a, b, &sum);
      if (carry == 0)
        return cond_sub(sum, modulus, 1);
      // The sum wrapped past 2^256, so the true value is 2^256 + sum and the
      // reduction becomes sum + (2^256 - modulus) with the carry dropped.
      Num reduced;
      add_raw(sum, complement_modulus(modulus), &reduced);
      return cond_sub(reduced, modulus, 1);
    }

    inline Num sub_mod(const Num &a, const Num &b, const Num &modulus)
    {
      Num diff;
      const uint32_t borrow = sub_raw(a, b, &diff);
      if (borrow == 0)
        return diff;
      Num sum;
      add_raw(diff, modulus, &sum);
      return sum;
    }

    // Montgomery product: full 2k-limb product followed by REDC, ported from
    // the P-256 implementation that RFC 6979 A.2.5 already pins. `n0` is
    // -modulus^-1 mod 2^32.
    inline Num mont_mul(const Num &a, const Num &b, const Num &modulus,
                        uint32_t n0)
    {
      uint32_t t[2 * kLimbs + 1] = {};
      for (size_t i = 0; i < kLimbs; ++i)
      {
        uint64_t carry = 0;
        for (size_t j = 0; j < kLimbs; ++j)
        {
          const uint64_t sum =
              static_cast<uint64_t>(a.v[i]) * b.v[j] + t[i + j] + carry;
          t[i + j] = static_cast<uint32_t>(sum);
          carry = sum >> 32;
        }
        size_t index = i + kLimbs;
        while (carry != 0 && index < 2 * kLimbs + 1)
        {
          const uint64_t sum = static_cast<uint64_t>(t[index]) + carry;
          t[index] = static_cast<uint32_t>(sum);
          carry = sum >> 32;
          ++index;
        }
      }
      for (size_t i = 0; i < kLimbs; ++i)
      {
        const uint32_t factor = t[i] * n0;
        uint64_t carry = 0;
        for (size_t j = 0; j < kLimbs; ++j)
        {
          const uint64_t sum =
              static_cast<uint64_t>(factor) * modulus.v[j] + t[i + j] + carry;
          t[i + j] = static_cast<uint32_t>(sum);
          carry = sum >> 32;
        }
        size_t index = i + kLimbs;
        while (carry != 0 && index < 2 * kLimbs + 1)
        {
          const uint64_t sum = static_cast<uint64_t>(t[index]) + carry;
          t[index] = static_cast<uint32_t>(sum);
          carry = sum >> 32;
          ++index;
        }
      }
      Num result;
      for (size_t i = 0; i < kLimbs; ++i)
        result.v[i] = t[i + kLimbs];
      if (t[2 * kLimbs] != 0)
        return add_mod(result, complement_modulus(modulus), modulus);
      return cond_sub(result, modulus, 1);
    }

    // -modulus^-1 mod 2^32 by Newton iteration. Starting from 1 (correct modulo
    // 2, because the modulus is odd) each step doubles the number of correct
    // low bits, so five steps reach 32.
    inline uint32_t derive_n0(const Num &modulus)
    {
      uint32_t inverse = 1u;
      for (int step = 0; step < 5; ++step)
      {
        inverse *= 2u - modulus.v[0] * inverse;
      }
      return 0u - inverse;
    }

    // R^2 = 2^512 mod p, by 512 modular doublings of one. Cheap, and it removes
    // the one table whose transcription error would only show up as a wrong
    // signature.
    inline Num derive_r2(const Num &modulus)
    {
      Num value = one();
      for (size_t step = 0; step < 512; ++step)
      {
        value = add_mod(value, value, modulus);
      }
      return value;
    }

    inline Curve build_curve(const CurveConstants &constants)
    {
      Curve curve;
      curve.prime = constants.prime;
      curve.order = constants.order;
      curve.curve_b = constants.curve_b;
      curve.gx = constants.gx;
      curve.gy = constants.gy;
      curve.a_is_minus_three = constants.a_is_minus_three;
      curve.field_n0 = derive_n0(constants.prime);
      curve.order_n0 = derive_n0(constants.order);
      curve.field_r2 = derive_r2(constants.prime);
      curve.order_r2 = derive_r2(constants.order);
      return curve;
    }

    // Function-local statics are initialised exactly once even under
    // concurrent first use, so signing on the crypto worker and verifying on
    // the loop task cannot race here.
    inline const Curve &secp256k1_curve()
    {
      static const Curve curve = build_curve(
          CurveConstants{kSecp256k1Prime, kSecp256k1Order, kSecp256k1B,
                         kSecp256k1Gx, kSecp256k1Gy, false});
      return curve;
    }

    inline const Curve &secp256r1_curve()
    {
      static const Curve curve = build_curve(
          CurveConstants{kP256Prime, kP256Order, kP256B, kP256Gx, kP256Gy,
                         true});
      return curve;
    }

    inline const Curve *curve_for(EcdsaCurve curve)
    {
      switch (curve)
      {
      case EcdsaCurve::Secp256k1:
        return &secp256k1_curve();
      case EcdsaCurve::Secp256r1:
        return &secp256r1_curve();
      }
      return nullptr;
    }

    inline Num to_mont(const Num &a, const Curve &curve)
    {
      return mont_mul(a, curve.field_r2, curve.prime, curve.field_n0);
    }

    inline Num from_mont(const Num &a, const Curve &curve)
    {
      return mont_mul(a, one(), curve.prime, curve.field_n0);
    }

    inline Num field_mul(const Num &a, const Num &b, const Curve &curve)
    {
      return mont_mul(a, b, curve.prime, curve.field_n0);
    }

    inline Num field_add(const Num &a, const Num &b, const Curve &curve)
    {
      return add_mod(a, b, curve.prime);
    }

    inline Num field_sub(const Num &a, const Num &b, const Curve &curve)
    {
      return sub_mod(a, b, curve.prime);
    }

    inline Num field_square(const Num &a, const Curve &curve)
    {
      return field_mul(a, a, curve);
    }

    inline size_t bit_length(const Num &a)
    {
      for (size_t i = kLimbs; i-- > 0;)
      {
        if (a.v[i] == 0)
          continue;
        for (size_t bit = 32; bit-- > 0;)
        {
          if (((a.v[i] >> bit) & 1u) != 0)
            return i * 32 + bit + 1;
        }
      }
      return 0;
    }

    inline bool bit_at(const Num &a, size_t index)
    {
      return ((a.v[index / 32] >> (index % 32)) & 1u) != 0;
    }

    // Square-and-multiply over a public exponent: the operation sequence is a
    // function of the exponent, never of the base.
    inline Num mod_pow(const Num &base, const Num &exponent, const Curve &curve,
                       bool scalar_side)
    {
      const Num &modulus = scalar_side ? curve.order : curve.prime;
      const Num &r2 = scalar_side ? curve.order_r2 : curve.field_r2;
      const uint32_t n0 = scalar_side ? curve.order_n0 : curve.field_n0;
      const size_t bits = bit_length(exponent);
      Num result = mont_mul(one(), r2, modulus, n0);
      for (size_t bit = bits; bit-- > 0;)
      {
        result = mont_mul(result, result, modulus, n0);
        if (bit_at(exponent, bit))
        {
          result = mont_mul(result, base, modulus, n0);
        }
      }
      return result;
    }

    inline Num field_inv(const Num &a, const Curve &curve)
    {
      Num exponent;
      sub_raw(curve.prime, Num{{2u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}}, &exponent);
      return mod_pow(a, exponent, curve, false);
    }

    // Only valid when p = 3 (mod 4), which holds for both supported curves.
    // sqrt(a) = a^((p+1)/4); (p+1) overflows 256 bits, so it is written as
    // (p-3)/4 + 1.
    inline bool field_sqrt(const Num &a, const Curve &curve, Num *out)
    {
      Num exponent;
      sub_raw(curve.prime, Num{{3u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}}, &exponent);
      uint32_t carry = 0;
      for (size_t i = kLimbs; i-- > 0;)
      {
        const uint32_t next = exponent.v[i] & 3u;
        exponent.v[i] = (exponent.v[i] >> 2) | (carry << 30);
        carry = next;
      }
      add_raw(exponent, one(), &exponent);
      const Num candidate = mod_pow(a, exponent, curve, false);
      // `a` is already the Montgomery representation, so the check compares
      // against it directly rather than converting it a second time.
      const Num check = field_square(candidate, curve);
      if (compare(check, a) != 0)
        return false;
      *out = candidate;
      return true;
    }

    inline Num scalar_mul(const Num &a, const Num &b, const Curve &curve)
    {
      return mont_mul(a, b, curve.order, curve.order_n0);
    }

    inline Num scalar_add(const Num &a, const Num &b, const Curve &curve)
    {
      return add_mod(a, b, curve.order);
    }

    inline Num scalar_sub(const Num &a, const Num &b, const Curve &curve)
    {
      return sub_mod(a, b, curve.order);
    }

    inline Num scalar_to_mont(const Num &a, const Curve &curve)
    {
      return mont_mul(a, curve.order_r2, curve.order, curve.order_n0);
    }

    inline Num scalar_from_mont(const Num &a, const Curve &curve)
    {
      return mont_mul(a, one(), curve.order, curve.order_n0);
    }

    inline Num scalar_inv(const Num &a, const Curve &curve)
    {
      Num exponent;
      sub_raw(curve.order, Num{{2u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}}, &exponent);
      return mod_pow(a, exponent, curve, true);
    }

    // (n - 1) / 2, the low-S boundary.
    inline Num order_half(const Curve &curve)
    {
      Num value;
      sub_raw(curve.order, one(), &value);
      uint32_t carry = 0;
      for (size_t i = kLimbs; i-- > 0;)
      {
        const uint32_t next = value.v[i] & 1u;
        value.v[i] = (value.v[i] >> 1) | (carry << 31);
        carry = next;
      }
      return value;
    }

    // Jacobian point; Z == 0 encodes infinity.
    struct Point
    {
      Num x;
      Num y;
      Num z;
    };

    inline Num to_field(const Num &a, const Curve &curve)
    {
      return to_mont(a, curve);
    }

    inline Num from_field(const Num &a, const Curve &curve)
    {
      return from_mont(a, curve);
    }

    inline Point generator(const Curve &curve)
    {
      return Point{to_field(curve.gx, curve), to_field(curve.gy, curve),
                   to_field(one(), curve)};
    }

    inline bool point_is_infinity(const Point &p) { return is_zero(p.z); }

    inline bool point_on_curve(const Num &x, const Num &y, const Curve &curve)
    {
      const Num x2 = field_square(x, curve);
      const Num x3 = field_mul(x2, x, curve);
      Num right = field_add(x3, to_field(curve.curve_b, curve), curve);
      if (curve.a_is_minus_three)
      {
        const Num three_x =
            field_add(field_add(x, x, curve), x, curve);
        right = field_sub(right, three_x, curve);
      }
      return compare(field_square(y, curve), right) == 0;
    }

    inline Point point_double(const Point &p, const Curve &curve)
    {
      if (point_is_infinity(p))
        return p;
      const Num delta = field_square(p.z, curve);
      const Num gamma = field_square(p.y, curve);
      const Num beta = field_mul(p.x, gamma, curve);
      // a = -3 collapses the general 3X^2 + aZ^4 term into 3(X-Z^2)(X+Z^2);
      // a = 0 leaves only 3X^2.
      const Num alpha = curve.a_is_minus_three
                            ? field_mul(field_sub(p.x, delta, curve),
                                        field_add(p.x, delta, curve), curve)
                            : field_square(p.x, curve);
      const Num alpha3 = field_add(field_add(alpha, alpha, curve), alpha, curve);
      const Num two_beta = field_add(beta, beta, curve);
      const Num four_beta = field_add(two_beta, two_beta, curve);
      const Num eight_beta = field_add(four_beta, four_beta, curve);
      const Num x3 = field_sub(field_square(alpha3, curve), eight_beta, curve);
      const Num yz = field_add(p.y, p.z, curve);
      const Num z3 =
          field_sub(field_sub(field_square(yz, curve), gamma, curve), delta,
                    curve);
      const Num gamma2 = field_square(gamma, curve);
      const Num two_gamma2 = field_add(gamma2, gamma2, curve);
      const Num four_gamma2 = field_add(two_gamma2, two_gamma2, curve);
      const Num eight_gamma2 = field_add(four_gamma2, four_gamma2, curve);
      const Num y3 = field_sub(
          field_mul(alpha3, field_sub(four_beta, x3, curve), curve),
          eight_gamma2, curve);
      return Point{x3, y3, z3};
    }

    // add-2007-bl.
    inline Point point_add(const Point &p, const Point &q, const Curve &curve)
    {
      if (point_is_infinity(p))
        return q;
      if (point_is_infinity(q))
        return p;
      const Num z1z1 = field_square(p.z, curve);
      const Num z2z2 = field_square(q.z, curve);
      const Num u1 = field_mul(p.x, z2z2, curve);
      const Num u2 = field_mul(q.x, z1z1, curve);
      const Num s1 = field_mul(field_mul(p.y, q.z, curve), z2z2, curve);
      const Num s2 = field_mul(field_mul(q.y, p.z, curve), z1z1, curve);
      if (compare(u1, u2) == 0)
      {
        if (compare(s1, s2) != 0)
          return Point{};
        return point_double(p, curve);
      }
      const Num h = field_sub(u2, u1, curve);
      const Num two_h = field_add(h, h, curve);
      const Num i = field_square(two_h, curve);
      const Num j = field_mul(h, i, curve);
      const Num r = field_add(field_sub(s2, s1, curve),
                              field_sub(s2, s1, curve), curve);
      const Num v = field_mul(u1, i, curve);
      const Num x3 = field_sub(field_sub(field_square(r, curve), j, curve),
                               field_add(v, v, curve), curve);
      const Num s1j = field_mul(s1, j, curve);
      const Num y3 = field_sub(
          field_mul(r, field_sub(v, x3, curve), curve),
          field_add(s1j, s1j, curve), curve);
      const Num zs = field_add(p.z, q.z, curve);
      const Num z3 = field_mul(
          field_sub(field_sub(field_square(zs, curve), z1z1, curve), z2z2,
                    curve),
          h, curve);
      return Point{x3, y3, z3};
    }

    // Double-and-add-always over 256 bits; both branches perform the same work,
    // so a secret scalar does not steer the instruction stream.
    inline Point point_mul(const Num &scalar, const Point &base,
                           const Curve &curve)
    {
      Point accumulator = {};
      for (size_t bit = 256; bit-- > 0;)
      {
        accumulator = point_double(accumulator, curve);
        const Point sum = point_add(accumulator, base, curve);
        accumulator = bit_at(scalar, bit) ? sum : accumulator;
      }
      return accumulator;
    }

    inline bool point_to_affine(const Point &p, const Curve &curve, Num *x,
                                Num *y)
    {
      if (point_is_infinity(p))
        return false;
      const Num z_inv = field_inv(p.z, curve);
      const Num z_inv2 = field_square(z_inv, curve);
      const Num z_inv3 = field_mul(z_inv2, z_inv, curve);
      *x = from_field(field_mul(p.x, z_inv2, curve), curve);
      *y = from_field(field_mul(p.y, z_inv3, curve), curve);
      return true;
    }

    inline void parse_num(const uint8_t bytes[kBytes], Num *out)
    {
      for (size_t i = 0; i < kLimbs; ++i)
      {
        const size_t offset = kBytes - 4 * (i + 1);
        out->v[i] = (static_cast<uint32_t>(bytes[offset]) << 24) |
                    (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
                    (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
                    static_cast<uint32_t>(bytes[offset + 3]);
      }
    }

    inline void write_num(const Num &value, uint8_t out[kBytes])
    {
      for (size_t i = 0; i < kLimbs; ++i)
      {
        const uint32_t limb = value.v[kLimbs - 1 - i];
        out[i * 4] = static_cast<uint8_t>(limb >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(limb >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(limb >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(limb);
      }
    }

    // Both orders exceed 2^255, so a 256-bit value is below 2n and one
    // conditional subtraction reduces it.
    inline Num reduce_scalar(const Num &value, const Curve &curve)
    {
      if (compare(value, curve.order) < 0)
        return value;
      Num reduced;
      sub_raw(value, curve.order, &reduced);
      return reduced;
    }

    // RFC 6979 section 3.2, HMAC-SHA-256, qlen = 256.
    struct NonceState
    {
      uint8_t k[32];
      uint8_t v[32];
    };

    inline void derive_nonce_state(const Num &private_key,
                                   const uint8_t digest[kBytes],
                                   NonceState *state)
    {
      uint8_t secret[32];
      write_num(private_key, secret);
      memset(state->v, 0x01, sizeof(state->v));
      memset(state->k, 0x00, sizeof(state->k));
      uint8_t buffer[32 + 1 + 32 + 32];
      memcpy(buffer, state->v, 32);
      buffer[32] = 0x00;
      memcpy(buffer + 33, secret, 32);
      memcpy(buffer + 65, digest, 32);
      (void)crypto_hmac_sha256(state->k, sizeof(state->k), buffer,
                               sizeof(buffer), state->k);
      (void)crypto_hmac_sha256(state->k, sizeof(state->k), state->v, 32,
                               state->v);
      memcpy(buffer, state->v, 32);
      buffer[32] = 0x01;
      (void)crypto_hmac_sha256(state->k, sizeof(state->k), buffer,
                               sizeof(buffer), state->k);
      (void)crypto_hmac_sha256(state->k, sizeof(state->k), state->v, 32,
                               state->v);
      secure_zero(secret, sizeof(secret));
      secure_zero(buffer, sizeof(buffer));
    }

    inline bool next_nonce(NonceState *state, const Curve &curve, Num *out)
    {
      for (size_t attempt = 0; attempt < 64; ++attempt)
      {
        (void)crypto_hmac_sha256(state->k, sizeof(state->k), state->v, 32,
                                 state->v);
        Num candidate;
        parse_num(state->v, &candidate);
        if (!is_zero(candidate) && compare(candidate, curve.order) < 0)
        {
          *out = candidate;
          return true;
        }
        uint8_t buffer[33];
        memcpy(buffer, state->v, 32);
        buffer[32] = 0x00;
        (void)crypto_hmac_sha256(state->k, sizeof(state->k), buffer,
                                 sizeof(buffer), state->k);
        (void)crypto_hmac_sha256(state->k, sizeof(state->k), state->v, 32,
                                 state->v);
      }
      return false;
    }

    inline bool verify_rs(const EcdsaCurve curve_id, const uint8_t public_key[64],
                          const uint8_t digest[kBytes], const Num &r,
                          const Num &s)
    {
      const Curve *curve_ptr = curve_for(curve_id);
      if (curve_ptr == nullptr)
        return false;
      const Curve &curve = *curve_ptr;
      if (is_zero(r) || is_zero(s) || compare(r, curve.order) >= 0 ||
          compare(s, curve.order) >= 0)
      {
        return false;
      }
      Num hash_value;
      parse_num(digest, &hash_value);
      hash_value = reduce_scalar(hash_value, curve);
      const Num w = scalar_inv(scalar_to_mont(s, curve), curve);
      const Num u1 =
          scalar_from_mont(scalar_mul(scalar_to_mont(hash_value, curve), w, curve),
                           curve);
      const Num u2 =
          scalar_from_mont(scalar_mul(scalar_to_mont(r, curve), w, curve), curve);
      Num qx;
      Num qy;
      parse_num(public_key, &qx);
      parse_num(public_key + 32, &qy);
      if (compare(qx, curve.prime) >= 0 || compare(qy, curve.prime) >= 0)
        return false;
      const Num field_x = to_field(qx, curve);
      const Num field_y = to_field(qy, curve);
      if (!point_on_curve(field_x, field_y, curve))
        return false;
      const Point public_point = Point{field_x, field_y, to_field(one(), curve)};
      const Point sum = point_add(point_mul(u1, generator(curve), curve),
                                  point_mul(u2, public_point, curve), curve);
      Num x;
      Num y;
      if (!point_to_affine(sum, curve, &x, &y))
        return false;
      return compare(reduce_scalar(x, curve), r) == 0;
    }

    // Writes r and s as two 32-byte big-endian integers inside a DER SEQUENCE.
    inline bool encode_der(const Num &r, const Num &s, uint8_t *der,
                           size_t *der_size)
    {
      if (der == nullptr || der_size == nullptr || *der_size < 8)
        return false;
      const Num values[2] = {r, s};
      size_t offset = 2;
      der[0] = 0x30;
      for (size_t index = 0; index < 2; ++index)
      {
        uint8_t raw[32];
        write_num(values[index], raw);
        size_t first = 0;
        while (first + 1 < sizeof(raw) && raw[first] == 0)
          ++first;
        const bool prefix = (raw[first] & 0x80u) != 0;
        const size_t length = sizeof(raw) - first + (prefix ? 1 : 0);
        if (offset + 2 + length > kEcdsaDerMaxSize || offset + 2 + length > *der_size)
        {
          secure_zero(raw, sizeof(raw));
          return false;
        }
        der[offset++] = 0x02;
        der[offset++] = static_cast<uint8_t>(length);
        if (prefix)
          der[offset++] = 0x00;
        memcpy(der + offset, raw + first, sizeof(raw) - first);
        offset += sizeof(raw) - first;
        secure_zero(raw, sizeof(raw));
      }
      der[1] = static_cast<uint8_t>(offset - 2);
      *der_size = offset;
      return true;
    }

    // Strict DER: definite minimal lengths, positive integers, no padding
    // beyond the single 0x00 a high bit requires, no trailing bytes.
    inline bool decode_der(const uint8_t *der, size_t der_size, Num *r, Num *s)
    {
      if (der == nullptr || r == nullptr || s == nullptr)
        return false;
      if (der_size < 8 || der_size > kEcdsaDerMaxSize || der[0] != 0x30)
        return false;
      if (static_cast<size_t>(der[1]) != der_size - 2)
        return false;
      size_t offset = 2;
      Num *targets[2] = {r, s};
      for (size_t index = 0; index < 2; ++index)
      {
        if (offset + 2 > der_size || der[offset] != 0x02)
          return false;
        const size_t length = der[offset + 1];
        offset += 2;
        if (length == 0 || offset + length > der_size)
          return false;
        const uint8_t *value = der + offset;
        if ((value[0] & 0x80u) != 0)
          return false;
        if (length > 1 && value[0] == 0x00 && (value[1] & 0x80u) == 0)
          return false;
        size_t first = 0;
        while (first + 1 < length && value[first] == 0x00)
          ++first;
        const size_t magnitude = length - first;
        if (magnitude > kBytes)
          return false;
        uint8_t padded[kBytes] = {};
        memcpy(padded + (kBytes - magnitude), value + first, magnitude);
        parse_num(padded, targets[index]);
        secure_zero(padded, sizeof(padded));
        offset += length;
      }
      return offset == der_size;
    }

  } // namespace ecdsa_detail

  // X || Y of private_key * G. Rejects 0 and any value >= n.
  inline bool ecdsa_public_key(EcdsaCurve curve_id,
                               const uint8_t private_key[kEcdsaScalarSize],
                               uint8_t public_key[kEcdsaPointSize])
  {
    using namespace ecdsa_detail;
    if (private_key == nullptr || public_key == nullptr)
      return false;
    const Curve *curve = curve_for(curve_id);
    if (curve == nullptr)
      return false;
    Num scalar;
    parse_num(private_key, &scalar);
    if (is_zero(scalar) || compare(scalar, curve->order) >= 0)
      return false;
    Num x;
    Num y;
    if (!point_to_affine(point_mul(scalar, generator(*curve), *curve), *curve,
                         &x, &y))
      return false;
    write_num(x, public_key);
    write_num(y, public_key + 32);
    return true;
  }

  // SEC1 compressed form: 0x02/0x03 for the y parity, then X big endian.
  inline bool ecdsa_encode_compressed(EcdsaCurve curve_id,
                                      const uint8_t point[kEcdsaPointSize],
                                      uint8_t out[kEcdsaCompressedPointSize])
  {
    using namespace ecdsa_detail;
    const Curve *curve = curve_for(curve_id);
    if (curve == nullptr || point == nullptr || out == nullptr)
      return false;
    Num x;
    Num y;
    parse_num(point, &x);
    parse_num(point + 32, &y);
    if (compare(x, curve->prime) >= 0 || compare(y, curve->prime) >= 0)
      return false;
    if (!point_on_curve(to_field(x, *curve), to_field(y, *curve), *curve))
      return false;
    out[0] = static_cast<uint8_t>((y.v[0] & 1u) != 0 ? 0x03 : 0x02);
    write_num(x, out + 1);
    return true;
  }

  // SEC1 compressed form: 0x02/0x03 for the y parity, then X big endian.
  inline bool ecdsa_public_key_compressed(
      EcdsaCurve curve_id, const uint8_t private_key[kEcdsaScalarSize],
      uint8_t public_key[kEcdsaCompressedPointSize])
  {
    if (public_key == nullptr)
      return false;
    uint8_t uncompressed[kEcdsaPointSize];
    if (!ecdsa_public_key(curve_id, private_key, uncompressed))
      return false;
    public_key[0] = static_cast<uint8_t>((uncompressed[63] & 1u) != 0 ? 0x03 : 0x02);
    memcpy(public_key + 1, uncompressed, 32);
    secure_zero(uncompressed, sizeof(uncompressed));
    return true;
  }

  // Accepts SEC1 compressed (33) or uncompressed (65) keys and writes X || Y.
  inline bool ecdsa_parse_public_key(EcdsaCurve curve_id, const uint8_t *encoded,
                                     size_t encoded_size,
                                     uint8_t public_key[kEcdsaPointSize])
  {
    using namespace ecdsa_detail;
    if (encoded == nullptr || public_key == nullptr)
      return false;
    const Curve *curve = curve_for(curve_id);
    if (curve == nullptr)
      return false;
    if (encoded_size == kEcdsaPointSize)
    {
      // Raw X || Y, the form the rest of this firmware already passes around.
      Num x;
      Num y;
      parse_num(encoded, &x);
      parse_num(encoded + 32, &y);
      if (compare(x, curve->prime) >= 0 || compare(y, curve->prime) >= 0)
        return false;
      if (!point_on_curve(to_field(x, *curve), to_field(y, *curve), *curve))
        return false;
      memcpy(public_key, encoded, kEcdsaPointSize);
      return true;
    }
    if (encoded_size == kEcdsaUncompressedPointSize && encoded[0] == 0x04)
    {
      Num x;
      Num y;
      parse_num(encoded + 1, &x);
      parse_num(encoded + 33, &y);
      if (compare(x, curve->prime) >= 0 || compare(y, curve->prime) >= 0)
        return false;
      if (!point_on_curve(to_field(x, *curve), to_field(y, *curve), *curve))
        return false;
      memcpy(public_key, encoded + 1, kEcdsaPointSize);
      return true;
    }
    if (encoded_size != kEcdsaCompressedPointSize ||
        (encoded[0] != 0x02 && encoded[0] != 0x03))
    {
      return false;
    }
    Num x;
    parse_num(encoded + 1, &x);
    if (compare(x, curve->prime) >= 0)
      return false;
    // rhs = x^3 + a*x + b
    const Num field_x = to_field(x, *curve);
    Num rhs = field_add(field_mul(field_square(field_x, *curve), field_x, *curve),
                        to_field(curve->curve_b, *curve), *curve);
    if (curve->a_is_minus_three)
    {
      rhs = field_sub(rhs, field_add(field_add(field_x, field_x, *curve), field_x, *curve),
                      *curve);
    }
    Num field_y;
    if (!field_sqrt(rhs, *curve, &field_y))
      return false;
    Num y = from_field(field_y, *curve);
    const bool odd = (encoded[0] == 0x03);
    if (((y.v[0] & 1u) != 0) != odd)
    {
      Num negated;
      sub_raw(curve->prime, y, &negated);
      if (!is_zero(y))
        y = negated;
    }
    if (!point_on_curve(field_x, to_field(y, *curve), *curve))
      return false;
    write_num(x, public_key);
    write_num(y, public_key + 32);
    return true;
  }

  // RFC 6979 deterministic signature, low-S normalised, then verified against
  // the derived public key before it is returned.
  inline bool ecdsa_sign_digest(EcdsaCurve curve_id,
                                const uint8_t private_key[kEcdsaScalarSize],
                                const uint8_t digest[kEcdsaDigestSize],
                                uint8_t signature[kEcdsaSignatureSize])
  {
    using namespace ecdsa_detail;
    if (private_key == nullptr || digest == nullptr || signature == nullptr)
      return false;
    const Curve *curve = curve_for(curve_id);
    if (curve == nullptr)
      return false;
    Num private_scalar;
    parse_num(private_key, &private_scalar);
    if (is_zero(private_scalar) || compare(private_scalar, curve->order) >= 0)
      return false;
    Num hash_value;
    parse_num(digest, &hash_value);
    hash_value = reduce_scalar(hash_value, *curve);

    uint8_t public_key[kEcdsaPointSize];
    if (!ecdsa_public_key(curve_id, private_key, public_key))
      return false;

    const Num d_mont = scalar_to_mont(private_scalar, *curve);
    const Num h_mont = scalar_to_mont(hash_value, *curve);
    const Num half = order_half(*curve);
    NonceState state;
    derive_nonce_state(private_scalar, digest, &state);
    bool signed_ok = false;
    for (size_t attempt = 0; attempt < 64 && !signed_ok; ++attempt)
    {
      Num nonce;
      if (!next_nonce(&state, *curve, &nonce))
        break;
      Num rx;
      Num ry;
      if (!point_to_affine(point_mul(nonce, generator(*curve), *curve), *curve,
                           &rx, &ry))
      {
        continue;
      }
      const Num r = reduce_scalar(rx, *curve);
      if (is_zero(r))
        continue;
      const Num denominator =
          scalar_add(h_mont, scalar_mul(scalar_to_mont(r, *curve), d_mont, *curve),
                     *curve);
      if (is_zero(denominator))
        continue;
      Num s = scalar_from_mont(
          scalar_mul(scalar_inv(scalar_to_mont(nonce, *curve), *curve),
                     denominator, *curve),
          *curve);
      if (is_zero(s))
        continue;
      if (compare(s, half) > 0)
      {
        s = scalar_sub(zero(), s, *curve);
      }
      if (!verify_rs(curve_id, public_key, digest, r, s))
        continue;
      write_num(r, signature);
      write_num(s, signature + 32);
      signed_ok = true;
    }
    secure_zero(&state, sizeof(state));
    secure_zero(public_key, sizeof(public_key));
    return signed_ok;
  }

  inline bool ecdsa_sign_digest_der(EcdsaCurve curve_id,
                                    const uint8_t private_key[kEcdsaScalarSize],
                                    const uint8_t digest[kEcdsaDigestSize],
                                    uint8_t *der, size_t *der_size)
  {
    using namespace ecdsa_detail;
    if (der == nullptr || der_size == nullptr)
      return false;
    uint8_t signature[kEcdsaSignatureSize];
    if (!ecdsa_sign_digest(curve_id, private_key, digest, signature))
    {
      secure_zero(signature, sizeof(signature));
      return false;
    }
    Num r;
    Num s;
    parse_num(signature, &r);
    parse_num(signature + 32, &s);
    const bool ok = encode_der(r, s, der, der_size);
    secure_zero(signature, sizeof(signature));
    return ok;
  }

  inline bool ecdsa_verify_digest(EcdsaCurve curve_id,
                                  const uint8_t public_key[kEcdsaPointSize],
                                  const uint8_t digest[kEcdsaDigestSize],
                                  const uint8_t signature[kEcdsaSignatureSize])
  {
    using namespace ecdsa_detail;
    if (public_key == nullptr || digest == nullptr || signature == nullptr)
      return false;
    Num r;
    Num s;
    parse_num(signature, &r);
    parse_num(signature + 32, &s);
    return verify_rs(curve_id, public_key, digest, r, s);
  }

  // `public_key` may be SEC1 compressed or uncompressed. High-S is accepted
  // here on purpose: consensus verifiers do not reject it, and a verification
  // helper that did would report valid historical signatures as broken.
  inline bool ecdsa_verify_der(EcdsaCurve curve_id, const uint8_t *public_key,
                               size_t public_key_size,
                               const uint8_t digest[kEcdsaDigestSize],
                               const uint8_t *der, size_t der_size)
  {
    using namespace ecdsa_detail;
    uint8_t point[kEcdsaPointSize];
    if (!ecdsa_parse_public_key(curve_id, public_key, public_key_size, point))
      return false;
    Num r;
    Num s;
    const bool parsed = decode_der(der, der_size, &r, &s);
    const bool ok = parsed && verify_rs(curve_id, point, digest, r, s);
    secure_zero(point, sizeof(point));
    return ok;
  }

  // Exposed so an adapter can refuse a non-canonical signature before parsing.
  inline bool ecdsa_parse_der(const uint8_t *der, size_t der_size,
                              uint8_t signature[kEcdsaSignatureSize])  {
    using namespace ecdsa_detail;
    if (signature == nullptr)
      return false;
    Num r;
    Num s;
    if (!decode_der(der, der_size, &r, &s))
      return false;
    write_num(r, signature);
    write_num(s, signature + 32);
    return true;
  }

  // ---------------------------------------------------------------------------
  // Scalar and point helpers for the schemes built on top of ECDSA. They are
  // what BIP32 public derivation and BIP340 need, and keeping them here means
  // WalletSecurity does not have to carry a second curve implementation.
  // Points are X || Y, the form the rest of the firmware already passes around.
  // ---------------------------------------------------------------------------

  // True when 0 < scalar < n, i.e. a usable private key or offset.
  inline bool ecdsa_scalar_is_valid(EcdsaCurve curve_id,
                                    const uint8_t scalar[kEcdsaScalarSize])
  {
    using namespace ecdsa_detail;
    const Curve *curve = curve_for(curve_id);
    if (curve == nullptr || scalar == nullptr)
      return false;
    Num value;
    parse_num(scalar, &value);
    return !is_zero(value) && compare(value, curve->order) < 0;
  }

  // (a + b) mod n. Returns false when the sum is zero, which is the BIP32
  // "invalid child" condition and must not be silently treated as a key.
  inline bool ecdsa_scalar_add(EcdsaCurve curve_id,
                               const uint8_t a[kEcdsaScalarSize],
                               const uint8_t b[kEcdsaScalarSize],
                               uint8_t out[kEcdsaScalarSize])
  {
    using namespace ecdsa_detail;
    const Curve *curve = curve_for(curve_id);
    if (curve == nullptr || a == nullptr || b == nullptr || out == nullptr)
      return false;
    Num left;
    Num right;
    parse_num(a, &left);
    parse_num(b, &right);
    if (compare(left, curve->order) >= 0 || compare(right, curve->order) >= 0)
      return false;
    const Num sum = scalar_add(left, right, *curve);
    if (is_zero(sum))
      return false;
    write_num(sum, out);
    return true;
  }

  // a * P for a public point. The scalar is public data here (BIP32 offsets,
  // verification operands), so variable-time is acceptable; secret scalars must
  // go through ecdsa_public_key().
  inline bool ecdsa_point_mul(EcdsaCurve curve_id, const uint8_t point[64],
                              const uint8_t scalar[kEcdsaScalarSize],
                              uint8_t out[64])
  {
    using namespace ecdsa_detail;
    const Curve *curve = curve_for(curve_id);
    if (curve == nullptr || point == nullptr || scalar == nullptr || out == nullptr)
      return false;
    Num x;
    Num y;
    parse_num(point, &x);
    parse_num(point + 32, &y);
    if (compare(x, curve->prime) >= 0 || compare(y, curve->prime) >= 0)
      return false;
    const Num field_x = to_field(x, *curve);
    const Num field_y = to_field(y, *curve);
    if (!point_on_curve(field_x, field_y, *curve))
      return false;
    Num k;
    parse_num(scalar, &k);
    if (compare(k, curve->order) >= 0)
      return false;
    Num rx;
    Num ry;
    if (!point_to_affine(
            point_mul(k, Point{field_x, field_y, to_field(one(), *curve)}, *curve),
            *curve, &rx, &ry))
    {
      return false;
    }
    write_num(rx, out);
    write_num(ry, out + 32);
    return true;
  }

  // A + B on the curve.
  inline bool ecdsa_point_add(EcdsaCurve curve_id, const uint8_t a[64],
                              const uint8_t b[64], uint8_t out[64])
  {
    using namespace ecdsa_detail;
    const Curve *curve = curve_for(curve_id);
    if (curve == nullptr || a == nullptr || b == nullptr || out == nullptr)
      return false;
    Num ax;
    Num ay;
    Num bx;
    Num by;
    parse_num(a, &ax);
    parse_num(a + 32, &ay);
    parse_num(b, &bx);
    parse_num(b + 32, &by);
    if (compare(ax, curve->prime) >= 0 || compare(ay, curve->prime) >= 0 ||
        compare(bx, curve->prime) >= 0 || compare(by, curve->prime) >= 0)
    {
      return false;
    }
    const Num field_ax = to_field(ax, *curve);
    const Num field_ay = to_field(ay, *curve);
    const Num field_bx = to_field(bx, *curve);
    const Num field_by = to_field(by, *curve);
    if (!point_on_curve(field_ax, field_ay, *curve) ||
        !point_on_curve(field_bx, field_by, *curve))
    {
      return false;
    }
    const Point sum =
        point_add(Point{field_ax, field_ay, to_field(one(), *curve)},
                  Point{field_bx, field_by, to_field(one(), *curve)}, *curve);
    Num rx;
    Num ry;
    if (!point_to_affine(sum, *curve, &rx, &ry))
      return false;
    write_num(rx, out);
    write_num(ry, out + 32);
    return true;
  }

  // ---------------------------------------------------------------------------
  // Recoverable ECDSA (Ethereum/Tron style): r || s plus the recovery id a
  // verifier needs to rebuild the public key. recid bit 0 is the parity of R.y,
  // bit 1 is set when R.x overflowed the group order.
  // ---------------------------------------------------------------------------
  struct EcdsaRecoverableSignature
  {
    uint8_t signature[kEcdsaSignatureSize]; // r || s, low-S
    uint8_t recovery_id;                    // 0..3
  };

  inline bool ecdsa_sign_digest_recoverable(
      EcdsaCurve curve_id, const uint8_t private_key[kEcdsaScalarSize],
      const uint8_t digest[kEcdsaDigestSize],
      EcdsaRecoverableSignature *out_signature)
  {
    using namespace ecdsa_detail;
    if (private_key == nullptr || digest == nullptr || out_signature == nullptr)
      return false;
    const Curve *curve = curve_for(curve_id);
    if (curve == nullptr)
      return false;
    Num private_scalar;
    parse_num(private_key, &private_scalar);
    if (is_zero(private_scalar) || compare(private_scalar, curve->order) >= 0)
      return false;
    Num hash_value;
    parse_num(digest, &hash_value);
    hash_value = reduce_scalar(hash_value, *curve);

    uint8_t public_key[kEcdsaPointSize];
    if (!ecdsa_public_key(curve_id, private_key, public_key))
      return false;

    const Num d_mont = scalar_to_mont(private_scalar, *curve);
    const Num h_mont = scalar_to_mont(hash_value, *curve);
    const Num half = order_half(*curve);
    NonceState state;
    derive_nonce_state(private_scalar, digest, &state);
    bool signed_ok = false;
    for (size_t attempt = 0; attempt < 64 && !signed_ok; ++attempt)
    {
      Num nonce;
      if (!next_nonce(&state, *curve, &nonce))
        break;
      Num rx;
      Num ry;
      if (!point_to_affine(point_mul(nonce, generator(*curve), *curve), *curve,
                           &rx, &ry))
      {
        continue;
      }
      const Num r = reduce_scalar(rx, *curve);
      if (is_zero(r))
        continue;
      const Num denominator =
          scalar_add(h_mont, scalar_mul(scalar_to_mont(r, *curve), d_mont, *curve),
                     *curve);
      if (is_zero(denominator))
        continue;
      Num s = scalar_from_mont(
          scalar_mul(scalar_inv(scalar_to_mont(nonce, *curve), *curve),
                     denominator, *curve),
          *curve);
      if (is_zero(s))
        continue;
      uint8_t recovery = static_cast<uint8_t>((ry.v[0] & 1u) != 0 ? 1 : 0);
      if (compare(rx, curve->order) >= 0)
        recovery = static_cast<uint8_t>(recovery | 2);
      if (compare(s, half) > 0)
      {
        // Normalising to low-S negates s, which is the same as using -R: the
        // recovery bit has to follow, or a recovering verifier lands on the
        // wrong public key.
        s = scalar_sub(zero(), s, *curve);
        recovery = static_cast<uint8_t>(recovery ^ 1);
      }
      if (!verify_rs(curve_id, public_key, digest, r, s))
        continue;
      write_num(r, out_signature->signature);
      write_num(s, out_signature->signature + 32);
      out_signature->recovery_id = recovery;
      signed_ok = true;
    }
    secure_zero(&state, sizeof(state));
    secure_zero(public_key, sizeof(public_key));
    return signed_ok;
  }

  // ---------------------------------------------------------------------------
  // BIP340 Schnorr over secp256k1. Lives here because it is the same curve and
  // the same scalar field; keeping a second copy of secp256k1 elsewhere is how
  // the two drift apart.
  // ---------------------------------------------------------------------------
  namespace secp256k1_schnorr_detail
  {

    // tagged_hash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)
    inline bool tagged_hash(const char *tag, const uint8_t *data, size_t size,
                            uint8_t out[32])
    {
      uint8_t prefix[64];
      if (tag == nullptr || !crypto_sha256(reinterpret_cast<const uint8_t *>(tag),
                                           strlen(tag), prefix) ||
          size > 96)
      {
        secure_zero(prefix, sizeof(prefix));
        return false;
      }
      // The tag hash appears twice, byte for byte; it is not hashed twice.
      memcpy(prefix + 32, prefix, 32);
      uint8_t buffer[64 + 96];
      memcpy(buffer, prefix, sizeof(prefix));
      if (data != nullptr && size != 0)
        memcpy(buffer + sizeof(prefix), data, size);
      const bool ok = crypto_sha256(buffer, sizeof(prefix) + size, out);
      secure_zero(prefix, sizeof(prefix));
      secure_zero(buffer, sizeof(buffer));
      return ok;
    }

    inline bool reduce_hash(const uint8_t hash[32], const ecdsa_detail::Curve &curve,
                            ecdsa_detail::Num *out)
    {
      using namespace ecdsa_detail;
      Num value;
      parse_num(hash, &value);
      *out = reduce_scalar(value, curve);
      return true;
    }

    inline ecdsa_detail::Num scalar_mul_plain(const ecdsa_detail::Num &a,
                                              const ecdsa_detail::Num &b,
                                              const ecdsa_detail::Curve &curve)
    {
      using namespace ecdsa_detail;
      return scalar_from_mont(
          scalar_mul(scalar_to_mont(a, curve), scalar_to_mont(b, curve), curve),
          curve);
    }

  } // namespace secp256k1_schnorr_detail

  // x-only public key (BIP340). `out_parity` receives the parity of Y, which is
  // what the signer has to negate the secret for.
  inline bool ecdsa_xonly_public_key(EcdsaCurve curve_id,
                                     const uint8_t private_key[kEcdsaScalarSize],
                                     uint8_t out_xonly[32], uint8_t *out_parity);

  inline bool ecdsa_bip340_verify(EcdsaCurve curve_id,
                                  const uint8_t xonly_public_key[32],
                                  const uint8_t message[32],
                                  const uint8_t signature[64]);

  // BIP340 signing. `aux_rand` is the only entropy input: 32 zero bytes gives
  // the deterministic form the specification's vectors use, anything else keeps
  // the nonce unpredictable to an attacker who does not know the secret. The
  // signature is verified before it is returned.
  inline bool ecdsa_bip340_sign(EcdsaCurve curve_id,
                                const uint8_t private_key[kEcdsaScalarSize],
                                const uint8_t message[32],
                                const uint8_t aux_rand[32],
                                uint8_t out_signature[64])
  {
    using namespace ecdsa_detail;
    using namespace secp256k1_schnorr_detail;
    if (curve_id != EcdsaCurve::Secp256k1)
      return false;
    if (private_key == nullptr || message == nullptr || aux_rand == nullptr ||
        out_signature == nullptr)
    {
      return false;
    }
    memset(out_signature, 0, 64);
    const Curve &curve = secp256k1_curve();
    Num d0;
    parse_num(private_key, &d0);
    if (is_zero(d0) || compare(d0, curve.order) >= 0)
      return false;
    Num px;
    Num py;
    if (!point_to_affine(point_mul(d0, generator(curve), curve), curve, &px, &py))
      return false;
    // P must have an even Y; if it does not, the signer works with n - d0, whose
    // point is -P and whose Y is therefore even.
    const Num d = (py.v[0] & 1u) != 0 ? scalar_sub(zero(), d0, curve) : d0;
    uint8_t px_bytes[32];
    write_num(px, px_bytes);

    // t = d XOR tagged_hash("BIP0340/aux", aux)
    uint8_t aux_hash[32];
    if (!tagged_hash("BIP0340/aux", aux_rand, 32, aux_hash))
      return false;
    uint8_t d_bytes[32];
    write_num(d, d_bytes);
    for (size_t index = 0; index < 32; ++index)
      d_bytes[index] = static_cast<uint8_t>(d_bytes[index] ^ aux_hash[index]);

    // k' = int(tagged_hash("BIP0340/nonce", t || P.x || m)) mod n
    uint8_t nonce_input[96];
    memcpy(nonce_input, d_bytes, 32);
    memcpy(nonce_input + 32, px_bytes, 32);
    memcpy(nonce_input + 64, message, 32);
    secure_zero(d_bytes, sizeof(d_bytes));
    uint8_t nonce_hash[32];
    bool ok = tagged_hash("BIP0340/nonce", nonce_input, sizeof(nonce_input),
                          nonce_hash);
    secure_zero(nonce_input, sizeof(nonce_input));
    if (!ok)
      return false;
    Num k0;
    reduce_hash(nonce_hash, curve, &k0);
    if (is_zero(k0))
      return false;
    Num rx;
    Num ry;
    if (!point_to_affine(point_mul(k0, generator(curve), curve), curve, &rx, &ry))
      return false;
    const Num k = (ry.v[0] & 1u) != 0 ? scalar_sub(zero(), k0, curve) : k0;

    // e = int(tagged_hash("BIP0340/challenge", R.x || P.x || m)) mod n
    uint8_t challenge_input[96];
    write_num(rx, challenge_input);
    memcpy(challenge_input + 32, px_bytes, 32);
    memcpy(challenge_input + 64, message, 32);
    uint8_t challenge_hash[32];
    ok = tagged_hash("BIP0340/challenge", challenge_input,
                     sizeof(challenge_input), challenge_hash);
    secure_zero(challenge_input, sizeof(challenge_input));
    if (!ok)
      return false;
    Num e;
    reduce_hash(challenge_hash, curve, &e);

    const Num s = scalar_add(k, scalar_mul_plain(e, d, curve), curve);
    write_num(rx, out_signature);
    write_num(s, out_signature + 32);
    if (!ecdsa_bip340_verify(EcdsaCurve::Secp256k1, px_bytes, message,
                             out_signature))
    {
      memset(out_signature, 0, 64);
      return false;
    }
    return true;
  }

  inline bool ecdsa_bip340_verify(EcdsaCurve curve_id,
                                  const uint8_t xonly_public_key[32],
                                  const uint8_t message[32],
                                  const uint8_t signature[64])
  {
    if (curve_id != EcdsaCurve::Secp256k1)
      return false;
    using namespace ecdsa_detail;
    using namespace secp256k1_schnorr_detail;
    if (xonly_public_key == nullptr || message == nullptr || signature == nullptr)
      return false;
    const Curve &curve = secp256k1_curve();
    Num px;
    parse_num(xonly_public_key, &px);
    if (compare(px, curve.prime) >= 0)
      return false;
    // lift_x: y^2 = x^3 + 7, take the even root.
    const Num field_x = to_field(px, curve);
    const Num x3 = field_mul(field_square(field_x, curve), field_x, curve);
    const Num rhs = field_add(x3, to_field(curve.curve_b, curve), curve);
    Num field_y;
    if (!field_sqrt(rhs, curve, &field_y))
      return false;
    Num py = from_field(field_y, curve);
    if ((py.v[0] & 1u) != 0)
      py = sub_mod(curve.prime, py, curve.prime);
    const Point public_point{field_x, to_field(py, curve), to_field(one(), curve)};
    Num r;
    Num s;
    parse_num(signature, &r);
    parse_num(signature + 32, &s);
    if (compare(r, curve.prime) >= 0 || compare(s, curve.order) >= 0)
      return false;
    uint8_t challenge_input[96];
    memcpy(challenge_input, signature, 32);
    memcpy(challenge_input + 32, xonly_public_key, 32);
    memcpy(challenge_input + 64, message, 32);
    uint8_t challenge_hash[32];
    const bool hashed = tagged_hash("BIP0340/challenge", challenge_input,
                                    sizeof(challenge_input), challenge_hash);
    secure_zero(challenge_input, sizeof(challenge_input));
    if (!hashed)
      return false;
    Num e;
    reduce_hash(challenge_hash, curve, &e);
    const Num negated_e = scalar_sub(zero(), e, curve);
    const Point sum = point_add(point_mul(s, generator(curve), curve),
                                point_mul(negated_e, public_point, curve), curve);
    Num result_x;
    Num result_y;
    if (!point_to_affine(sum, curve, &result_x, &result_y))
      return false;
    if ((result_y.v[0] & 1u) != 0)
      return false;
    return compare(result_x, r) == 0;
  }

  inline bool ecdsa_xonly_public_key(EcdsaCurve curve_id,
                                     const uint8_t private_key[kEcdsaScalarSize],
                                     uint8_t out_xonly[32], uint8_t *out_parity)
  {
    if (curve_id != EcdsaCurve::Secp256k1)
      return false;
    using namespace ecdsa_detail;
    if (private_key == nullptr || out_xonly == nullptr)
      return false;
    const Curve &curve = secp256k1_curve();
    Num scalar;
    parse_num(private_key, &scalar);
    if (is_zero(scalar) || compare(scalar, curve.order) >= 0)
      return false;
    Num x;
    Num y;
    if (!point_to_affine(point_mul(scalar, generator(curve), curve), curve, &x,
                         &y))
      return false;
    write_num(x, out_xonly);
    if (out_parity != nullptr)
      *out_parity = static_cast<uint8_t>((y.v[0] & 1u) != 0 ? 1 : 0);
    return true;
  }

  // Pins both curves against material that does not come from this code:
  //   * the group law, by checking G is on the curve and that n * G is the
  //     point at infinity;
  //   * RFC 6979 A.2.5 for P-256, whose r is unique to the published nonce;
  //   * the same RFC 6979 key and message on secp256k1, with r and s taken from
  //     libsecp256k1 and from python-ecdsa, which agree with each other;
  //   * a real Groestlcoin mainnet spend, whose DER signature is verified
  //     against the compressed public key in the same scriptSig.
  inline bool run_ecdsa_curve_self_tests()
  {
    using namespace ecdsa_detail;
    static const EcdsaCurve kCurves[2] = {EcdsaCurve::Secp256k1,
                                          EcdsaCurve::Secp256r1};
    // RFC 6979 A.2.5/A.2.6 private key.
    static const uint8_t kKey[32] = {
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
        0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
        0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};
    bool passed = true;

    for (size_t index = 0; index < 2; ++index)
    {
      const Curve &curve = *curve_for(kCurves[index]);
      passed = passed && point_on_curve(to_field(curve.gx, curve),
                                        to_field(curve.gy, curve), curve);
      passed = passed && point_is_infinity(
                             point_mul(curve.order, generator(curve), curve));
      // (n - 1) * G has G's x coordinate and the negated y.
      Num x;
      Num y;
      Num order_minus_one;
      sub_raw(curve.order, one(), &order_minus_one);
      passed = passed &&
               point_to_affine(point_mul(order_minus_one, generator(curve), curve),
                               curve, &x, &y) &&
               compare(x, curve.gx) == 0;
      Num negated_y;
      sub_raw(curve.prime, curve.gy, &negated_y);
      passed = passed && compare(y, negated_y) == 0;
      Num ignored_x;
      Num ignored_y;
      passed = passed &&
               !point_to_affine(Point{}, curve, &ignored_x, &ignored_y);
    }

    uint8_t digest[32];
    uint8_t signature[64];
    passed = passed &&
             crypto_sha256(reinterpret_cast<const uint8_t *>("sample"), 6,
                           digest);

    // RFC 6979 A.2.5 (P-256, SHA-256, "sample"). The published s is the high
    // half, so the expected value here is n - s.
    static const uint8_t kP256R[32] = {
        0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd,
        0x9c, 0xd4, 0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa,
        0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16};
    static const uint8_t kP256SPublished[32] = {
        0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7,
        0xa1, 0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf,
        0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8};
    static const uint8_t kP256Point[64] = {
        0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb,
        0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61,
        0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79,
        0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9,
        0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f,
        0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
    uint8_t point[64];
    passed = passed &&
             ecdsa_public_key(EcdsaCurve::Secp256r1, kKey, point) &&
             crypto_constant_time_equal(point, kP256Point, sizeof(point));
    passed = passed &&
             ecdsa_sign_digest(EcdsaCurve::Secp256r1, kKey, digest, signature) &&
             crypto_constant_time_equal(signature, kP256R, 32);
    Num published_s;
    parse_num(kP256SPublished, &published_s);
    const Num expected_s =
        scalar_sub(zero(), published_s, *curve_for(EcdsaCurve::Secp256r1));
    uint8_t expected_s_bytes[32];
    write_num(expected_s, expected_s_bytes);
    passed = passed &&
             crypto_constant_time_equal(signature + 32, expected_s_bytes, 32);

    // Same key and message on secp256k1. Neither r nor s below was produced by
    // this engine.
    static const uint8_t kSecp256k1R[32] = {
        0x43, 0x23, 0x10, 0xe3, 0x2c, 0xb8, 0x0e, 0xb6, 0x50, 0x3a, 0x26,
        0xce, 0x83, 0xcc, 0x16, 0x5c, 0x78, 0x3b, 0x87, 0x08, 0x45, 0xfb,
        0x8a, 0xad, 0x6d, 0x97, 0x08, 0x89, 0xfc, 0xd7, 0xa6, 0xc8};
    static const uint8_t kSecp256k1S[32] = {
        0x53, 0x01, 0x28, 0xb6, 0xb8, 0x1c, 0x54, 0x88, 0x74, 0xa6, 0x30,
        0x5d, 0x93, 0xed, 0x07, 0x1c, 0xa6, 0xe0, 0x50, 0x74, 0xd8, 0x58,
        0x63, 0xd4, 0x05, 0x6c, 0xe8, 0x9b, 0x02, 0xbf, 0xab, 0x69};
    uint8_t secp_point[64];
    passed = passed &&
             ecdsa_public_key(EcdsaCurve::Secp256k1, kKey, secp_point) &&
             ecdsa_sign_digest(EcdsaCurve::Secp256k1, kKey, digest, signature) &&
             crypto_constant_time_equal(signature, kSecp256k1R, 32) &&
             crypto_constant_time_equal(signature + 32, kSecp256k1S, 32) &&
             ecdsa_verify_digest(EcdsaCurve::Secp256k1, secp_point, digest,
                                 signature);
    uint8_t repeat[64];
    passed = passed &&
             ecdsa_sign_digest(EcdsaCurve::Secp256k1, kKey, digest, repeat) &&
             crypto_constant_time_equal(repeat, signature, 64);

    // --- SEC1 compressed round trip, and a compressed key that is not on the
    // curve.
    uint8_t compressed[33];
    uint8_t decoded[64];
    passed = passed &&
             ecdsa_public_key_compressed(EcdsaCurve::Secp256r1, kKey,
                                         compressed) &&
             ecdsa_parse_public_key(EcdsaCurve::Secp256r1, compressed,
                                    sizeof(compressed), decoded) &&
             crypto_constant_time_equal(decoded, kP256Point, sizeof(decoded));
    uint8_t off_curve[33];
    memcpy(off_curve, compressed, sizeof(off_curve));
    off_curve[1] ^= 0x01;
    for (size_t index = 2; index < sizeof(off_curve); ++index)
    {
      off_curve[index] = static_cast<uint8_t>(off_curve[index] ^ 0x5a);
    }
    passed = passed &&
             !ecdsa_parse_public_key(EcdsaCurve::Secp256r1, off_curve,
                                     sizeof(off_curve), decoded);

    // --- real Groestlcoin mainnet spend (block 6324419,
    // tx b566ddf7ae1374d13081bc01ddee3d5a1f2390773c6c910b4414063ba95f6c92).
    // The digest is single SHA-256 of the Bitcoin legacy sighash preimage; the
    // signature and public key are the ones in that transaction's scriptSig.
    static const uint8_t kGroestlDigest[32] = {
        0xdf, 0x00, 0xbd, 0xc1, 0x26, 0x40, 0x2d, 0xef, 0xa7, 0xe9, 0x27,
        0x77, 0x2d, 0x1b, 0xaf, 0x20, 0xf6, 0xf5, 0x0a, 0x02, 0xb3, 0x75,
        0xab, 0xe4, 0xbd, 0x32, 0xe9, 0x4f, 0xa1, 0x11, 0xb3, 0xbe};
    static const uint8_t kGroestlPublicKey[33] = {
        0x03, 0xf4, 0xb9, 0xdd, 0xd6, 0x6b, 0x30, 0x46, 0xde, 0x57, 0x50,
        0x59, 0x9a, 0x09, 0xe3, 0xf2, 0x15, 0x04, 0xd0, 0xbb, 0x03, 0xb8,
        0xad, 0x75, 0x58, 0x8d, 0xd3, 0x5a, 0x93, 0xe6, 0xf1, 0x88, 0xf1};
    static const uint8_t kGroestlSignature[70] = {
        0x30, 0x44, 0x02, 0x20, 0x44, 0x0c, 0x79, 0x0f, 0xc6, 0x95, 0x9e,
        0x0f, 0xd2, 0xb3, 0x80, 0xdb, 0x0b, 0x83, 0x65, 0x4a, 0x3e, 0xe8,
        0xe1, 0x86, 0x0e, 0x52, 0xa2, 0x99, 0x69, 0x4c, 0xd0, 0xd5, 0x1a,
        0x93, 0x6e, 0x8b, 0x02, 0x20, 0x37, 0x56, 0x10, 0x03, 0x42, 0x79,
        0x31, 0xc8, 0xfe, 0x4e, 0x01, 0x15, 0x3c, 0xe3, 0x84, 0x55, 0x93,
        0xd7, 0x4b, 0x5c, 0xcb, 0xa3, 0x73, 0x73, 0x45, 0x1f, 0x20, 0x2f,
        0x75, 0x28, 0x07, 0x6e};
    passed = passed &&
             ecdsa_verify_der(EcdsaCurve::Secp256k1, kGroestlPublicKey,
                              sizeof(kGroestlPublicKey), kGroestlDigest,
                              kGroestlSignature, sizeof(kGroestlSignature));
    // The double-SHA256 of the same digest is not what that chain signs, so the
    // same signature must fail against it. This is the assumption the previous
    // round got wrong.
    uint8_t double_digest[32];
    passed = passed &&
             crypto_sha256(kGroestlDigest, sizeof(kGroestlDigest),
                           double_digest) &&
             !ecdsa_verify_der(EcdsaCurve::Secp256k1, kGroestlPublicKey,
                               sizeof(kGroestlPublicKey), double_digest,
                               kGroestlSignature, sizeof(kGroestlSignature));

    // --- rejection paths: tampering, zero r/s, wrong digest, key bounds.
    uint8_t tampered[64];
    memcpy(tampered, signature, sizeof(tampered));
    tampered[5] ^= 0x40;
    passed = passed &&
             !ecdsa_verify_digest(EcdsaCurve::Secp256k1, secp_point, digest,
                                  tampered);
    uint8_t zeros[64] = {};
    passed = passed && !ecdsa_verify_digest(EcdsaCurve::Secp256k1, secp_point,
                                            digest, zeros);
    uint8_t other_digest[32];
    passed = passed &&
             crypto_sha256(reinterpret_cast<const uint8_t *>("Sample"), 6,
                           other_digest) &&
             !ecdsa_verify_digest(EcdsaCurve::Secp256k1, secp_point,
                                  other_digest, signature);
    uint8_t zero_key[32] = {};
    passed = passed &&
             !ecdsa_sign_digest(EcdsaCurve::Secp256k1, zero_key, digest,
                                signature);
    uint8_t order_key[32];
    write_num(curve_for(EcdsaCurve::Secp256k1)->order, order_key);
    passed = passed &&
             !ecdsa_sign_digest(EcdsaCurve::Secp256k1, order_key, digest,
                                signature);
    // A public key with a coordinate equal to p is not a point.
    uint8_t bad_point[64];
    memcpy(bad_point, secp_point, sizeof(bad_point));
    write_num(curve_for(EcdsaCurve::Secp256k1)->prime, bad_point);
    passed = passed && !ecdsa_verify_digest(EcdsaCurve::Secp256k1, bad_point,
                                            digest, repeat);

    // --- DER: round trip, strictness, and verification through it.
    uint8_t der[80];
    size_t der_size = sizeof(der);
    uint8_t parsed[64];
    const bool der_written =
        ecdsa_sign_digest_der(EcdsaCurve::Secp256r1, kKey, digest, der,
                              &der_size) &&
        der_size + 2 <= sizeof(der);
    passed = passed && der_written &&
             ecdsa_parse_der(der, der_size, parsed) &&
             ecdsa_verify_der(EcdsaCurve::Secp256r1, kP256Point,
                              sizeof(kP256Point), digest, der, der_size);
    if (der_written)
    {
      // Truncated, extended, and non-minimal forms are all refused.
      passed = passed && !ecdsa_parse_der(der, der_size - 1, parsed);
      uint8_t extended[82];
      memcpy(extended, der, der_size);
      extended[der_size] = 0x00;
      passed = passed && !ecdsa_parse_der(extended, der_size + 1, parsed);
      // The same SEQUENCE with one 0x00 of padding inside the r INTEGER.
      uint8_t padded[82];
      memcpy(padded, der, der_size);
      memmove(padded + 4, padded + 3, der_size - 3);
      padded[3] = static_cast<uint8_t>(padded[3] + 1);
      padded[4] = 0x00;
      padded[1] = static_cast<uint8_t>(padded[1] + 1);
      passed = passed && !ecdsa_parse_der(padded, der_size + 1, parsed);
      secure_zero(extended, sizeof(extended));
      secure_zero(padded, sizeof(padded));
    }

    secure_zero(der, sizeof(der));
    secure_zero(signature, sizeof(signature));
    secure_zero(repeat, sizeof(repeat));
    secure_zero(parsed, sizeof(parsed));
    secure_zero(secp_point, sizeof(secp_point));
    secure_zero(point, sizeof(point));
    secure_zero(decoded, sizeof(decoded));
    secure_zero(expected_s_bytes, sizeof(expected_s_bytes));
    return passed;
  }

} // namespace hexwallet

#endif
