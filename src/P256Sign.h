#ifndef HEXWALLET_P256_SIGN_H
#define HEXWALLET_P256_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet
{

  // NIST P-256 ECDSA, implemented here instead of going through mbedtls.
  //
  // FIDO2/CTAP2 credentials must be ES256: that is what platform authenticators
  // and relying parties actually accept. mbedtls is linked into this firmware,
  // but the host shim only carries secp256k1, so a signature produced through
  // mbedtls could never be exercised off-device. Same reasoning that put the Stark
  // curve and ML-DSA-87 in this tree: one implementation, byte-identical on host
  // and MCU, pinned to published vectors.
  //
  // What is here: field arithmetic over p = 2^256 - 2^224 + 2^192 + 2^96 - 1 in
  // Montgomery form (8 x 32-bit limbs, CIOS), Jacobian point arithmetic for
  // a = -3, RFC 6979 deterministic nonces with SHA-256, low-S normalisation,
  // strict DER, and a verifier that every signature passes before it is returned.
  // Scalar multiplication runs a fixed double-and-add-always sequence, so the
  // secret scalar does not steer branches.
  //
  // Costs, honestly: one ES256 signature is about 512 point operations plus two
  // Fermat inversions. Milliseconds on the P4, and not on any hot path - a FIDO
  // assertion is a user-initiated, once-per-login event.

  namespace p256_detail
  {

    constexpr size_t kLimbs = 8;
    constexpr size_t kBytes = 32;
    constexpr size_t kScalarSize = 32;

    struct Num
    {
      uint32_t v[kLimbs];
    };

    // p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
    constexpr Num kPrime = {{0xffffffffu, 0xffffffffu, 0xffffffffu, 0x00000000u,
                             0x00000000u, 0x00000000u, 0x00000001u, 0xffffffffu}};
    // n, the group order.
    constexpr Num kOrder = {{0xfc632551u, 0xf3b9cac2u, 0xa7179e84u, 0xbce6faadu,
                             0xffffffffu, 0xffffffffu, 0x00000000u, 0xffffffffu}};
    constexpr uint32_t kFieldN0 = 0x00000001u;
    constexpr uint32_t kOrderN0 = 0xee00bc4fu;
    constexpr Num kFieldR2 = {{0x00000003u, 0x00000000u, 0xffffffffu, 0xfffffffbu,
                               0xfffffffeu, 0xffffffffu, 0xfffffffdu, 0x00000004u}};
    constexpr Num kOrderR2 = {{0xbe79eea2u, 0x83244c95u, 0x49bd6fa6u, 0x4699799cu,
                               0x2b6bec59u, 0x2845b239u, 0xf3d95620u, 0x66e12d94u}};
    // y^2 = x^3 - 3x + b.
    constexpr Num kCurveB = {{0x27d2604bu, 0x3bce3c3eu, 0xcc53b0f6u, 0x651d06b0u,
                              0x769886bcu, 0xb3ebbd55u, 0xaa3a93e7u, 0x5ac635d8u}};
    constexpr Num kGx = {{0xd898c296u, 0xf4a13945u, 0x2deb33a0u, 0x77037d81u,
                          0x63a440f2u, 0xf8bce6e5u, 0xe12c4247u, 0x6b17d1f2u}};
    constexpr Num kGy = {{0x37bf51f5u, 0xcbb64068u, 0x6b315eceu, 0x2bce3357u,
                          0x7c0f9e16u, 0x8ee7eb4au, 0xfe1a7f9bu, 0x4fe342e2u}};

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

    inline Num complement_modulus(const Num &modulus);

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

    // Subtracts the modulus once when `subtract` is set - exactly the post-condition
    // of a Montgomery product and of a modular addition.
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
      // The sum wrapped past 2^k limbs, so the true value is 2^256 + sum and the
      // reduction becomes sum + (2^256 - modulus) with the carry dropped again.
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
      // diff wrapped: adding the modulus back lands in range and drops the carry.
      Num sum;
      add_raw(diff, modulus, &sum);
      return sum;
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

    // Montgomery product: full 2k-limb product followed by REDC. Slower than CIOS
    // (2x the multiplies) but the carry handling is local and provable, which is
    // what matters for a curve primitive nobody can step through on paper.
    // `n0` is -modulus^-1 mod 2^32.
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
      // REDC leaves a value below 2 * modulus. When the borrow word is set the true
      // value is 2^256 + result, which is congruent to result + (2^256 - modulus);
      // otherwise one conditional subtraction finishes the reduction.
      if (t[2 * kLimbs] != 0)
      {
        return add_mod(result, complement_modulus(modulus), modulus);
      }
      return cond_sub(result, modulus, 1);
    }

    inline Num to_mont(const Num &a, const Num &r2, const Num &modulus,
                       uint32_t n0)
    {
      return mont_mul(a, r2, modulus, n0);
    }

    inline Num from_mont(const Num &a, const Num &modulus, uint32_t n0)
    {
      const Num one = {{1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
      return mont_mul(a, one, modulus, n0);
    }

    inline Num field_mul(const Num &a, const Num &b)
    {
      return mont_mul(a, b, kPrime, kFieldN0);
    }
    inline Num field_add(const Num &a, const Num &b) { return add_mod(a, b, kPrime); }
    inline Num field_sub(const Num &a, const Num &b) { return sub_mod(a, b, kPrime); }
    inline Num field_square(const Num &a) { return field_mul(a, a); }

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

    // Square-and-multiply over the (public) exponent: the operation sequence is a
    // function of the exponent, never of the base.
    inline Num mod_pow(const Num &base, const Num &exponent, const Num &modulus,
                       const Num &r2, uint32_t n0)
    {
      const size_t bits = bit_length(exponent);
      Num result = to_mont(Num{{1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}}, r2, modulus, n0);
      if (bits == 0)
        return result;
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

    inline Num field_inv(const Num &a)
    {
      const Num two = {{2u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
      Num exponent;
      sub_raw(kPrime, two, &exponent); // p - 2
      return mod_pow(a, exponent, kPrime, kFieldR2, kFieldN0);
    }

    inline Num scalar_mul(const Num &a, const Num &b)
    {
      return mont_mul(a, b, kOrder, kOrderN0);
    }
    inline Num scalar_add(const Num &a, const Num &b)
    {
      return add_mod(a, b, kOrder);
    }
    inline Num scalar_sub(const Num &a, const Num &b)
    {
      return sub_mod(a, b, kOrder);
    }
    inline Num scalar_to_mont(const Num &a)
    {
      return to_mont(a, kOrderR2, kOrder, kOrderN0);
    }
    inline Num scalar_from_mont(const Num &a)
    {
      return from_mont(a, kOrder, kOrderN0);
    }
    inline Num scalar_inv(const Num &a)
    {
      const Num two = {{2u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
      Num exponent;
      sub_raw(kOrder, two, &exponent); // n - 2
      return mod_pow(a, exponent, kOrder, kOrderR2, kOrderN0);
    }

    // (n - 1) / 2, the low-S boundary.
    inline Num order_half()
    {
      const Num one = {{1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
      Num value;
      sub_raw(kOrder, one, &value);
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

    inline Num to_field(const Num &a) { return to_mont(a, kFieldR2, kPrime, kFieldN0); }
    inline Num from_field(const Num &a) { return from_mont(a, kPrime, kFieldN0); }

    inline Point generator()
    {
      return Point{to_field(kGx), to_field(kGy),
                   to_field(Num{{1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}})};
    }

    inline bool point_is_infinity(const Point &p) { return is_zero(p.z); }
    inline bool point_on_curve(const Num &x, const Num &y)
    {
      const Num x2 = field_square(x);
      const Num x3 = field_mul(x2, x);
      const Num three_x = field_add(field_add(x, x), x);
      const Num right = field_add(field_sub(x3, three_x), to_field(kCurveB));
      return compare(field_square(y), right) == 0;
    }

    inline Point point_double(const Point &p)
    {
      if (point_is_infinity(p))
        return p;
      const Num delta = field_square(p.z);
      const Num gamma = field_square(p.y);
      const Num beta = field_mul(p.x, gamma);
      const Num alpha = field_mul(field_sub(p.x, delta), field_add(p.x, delta));
      const Num alpha3 = field_add(field_add(alpha, alpha), alpha);
      const Num two_beta = field_add(beta, beta);
      const Num four_beta = field_add(two_beta, two_beta);
      const Num eight_beta = field_add(four_beta, four_beta);
      const Num x3 = field_sub(field_square(alpha3), eight_beta);
      const Num yz = field_add(p.y, p.z);
      const Num z3 = field_sub(field_sub(field_square(yz), gamma), delta);
      const Num gamma2 = field_square(gamma);
      const Num two_gamma2 = field_add(gamma2, gamma2);
      const Num four_gamma2 = field_add(two_gamma2, two_gamma2);
      const Num eight_gamma2 = field_add(four_gamma2, four_gamma2);
      const Num y3 =
          field_sub(field_mul(alpha3, field_sub(four_beta, x3)), eight_gamma2);
      return Point{x3, y3, z3};
    }

    // add-2007-bl.
    inline Point point_add(const Point &p, const Point &q)
    {
      if (point_is_infinity(p))
        return q;
      if (point_is_infinity(q))
        return p;
      const Num z1z1 = field_square(p.z);
      const Num z2z2 = field_square(q.z);
      const Num u1 = field_mul(p.x, z2z2);
      const Num u2 = field_mul(q.x, z1z1);
      const Num s1 = field_mul(field_mul(p.y, q.z), z2z2);
      const Num s2 = field_mul(field_mul(q.y, p.z), z1z1);
      if (compare(u1, u2) == 0)
      {
        if (compare(s1, s2) != 0)
          return Point{}; // P + (-P)
        return point_double(p);
      }
      const Num h = field_sub(u2, u1);
      const Num two_h = field_add(h, h);
      const Num i = field_square(two_h);
      const Num j = field_mul(h, i);
      const Num r = field_add(field_sub(s2, s1), field_sub(s2, s1));
      const Num v = field_mul(u1, i);
      const Num x3 = field_sub(field_sub(field_square(r), j), field_add(v, v));
      const Num s1j = field_mul(s1, j);
      const Num y3 =
          field_sub(field_mul(r, field_sub(v, x3)), field_add(s1j, s1j));
      const Num zs = field_add(p.z, q.z);
      const Num z3 =
          field_mul(field_sub(field_sub(field_square(zs), z1z1), z2z2), h);
      return Point{x3, y3, z3};
    }

    // Double-and-add-always over 256 bits; both branches perform the same work.
    inline Point point_mul(const Num &scalar, const Point &base)
    {
      Point accumulator = {};
      for (size_t bit = 256; bit-- > 0;)
      {
        accumulator = point_double(accumulator);
        const Point sum = point_add(accumulator, base);
        accumulator = bit_at(scalar, bit) ? sum : accumulator;
      }
      return accumulator;
    }

    inline bool point_to_affine(const Point &p, Num *x, Num *y)
    {
      if (point_is_infinity(p))
        return false;
      const Num z_inv = field_inv(p.z);
      const Num z_inv2 = field_square(z_inv);
      const Num z_inv3 = field_mul(z_inv2, z_inv);
      *x = from_field(field_mul(p.x, z_inv2));
      *y = from_field(field_mul(p.y, z_inv3));
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

    // A 256-bit value is below 2n, so one conditional subtraction reduces it.
    inline Num reduce_scalar(const Num &value)
    {
      if (compare(value, kOrder) < 0)
        return value;
      Num reduced;
      sub_raw(value, kOrder, &reduced);
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
      (void)crypto_hmac_sha256(state->k, sizeof(state->k), buffer, sizeof(buffer),
                               state->k);
      (void)crypto_hmac_sha256(state->k, sizeof(state->k), state->v, 32, state->v);
      memcpy(buffer, state->v, 32);
      buffer[32] = 0x01;
      (void)crypto_hmac_sha256(state->k, sizeof(state->k), buffer, sizeof(buffer),
                               state->k);
      (void)crypto_hmac_sha256(state->k, sizeof(state->k), state->v, 32, state->v);
      secure_zero(secret, sizeof(secret));
      secure_zero(buffer, sizeof(buffer));
    }

    inline bool next_nonce(NonceState *state, Num *out)
    {
      for (size_t attempt = 0; attempt < 64; ++attempt)
      {
        (void)crypto_hmac_sha256(state->k, sizeof(state->k), state->v, 32,
                                 state->v);
        Num candidate;
        parse_num(state->v, &candidate);
        if (!is_zero(candidate) && compare(candidate, kOrder) < 0)
        {
          *out = candidate;
          return true;
        }
        uint8_t buffer[33];
        memcpy(buffer, state->v, 32);
        buffer[32] = 0x00;
        (void)crypto_hmac_sha256(state->k, sizeof(state->k), buffer, sizeof(buffer),
                                 state->k);
        (void)crypto_hmac_sha256(state->k, sizeof(state->k), state->v, 32,
                                 state->v);
      }
      return false;
    }

    inline bool verify_rs(const uint8_t public_key[64],
                          const uint8_t digest[kBytes], const Num &r, const Num &s)
    {
      if (is_zero(r) || is_zero(s) || compare(r, kOrder) >= 0 ||
          compare(s, kOrder) >= 0)
      {
        return false;
      }
      Num hash_value;
      parse_num(digest, &hash_value);
      hash_value = reduce_scalar(hash_value);
      const Num w = scalar_inv(scalar_to_mont(s));
      const Num u1 = scalar_from_mont(scalar_mul(scalar_to_mont(hash_value), w));
      const Num u2 = scalar_from_mont(scalar_mul(scalar_to_mont(r), w));
      Num qx;
      Num qy;
      parse_num(public_key, &qx);
      parse_num(public_key + 32, &qy);
      if (compare(qx, kPrime) >= 0 || compare(qy, kPrime) >= 0)
        return false;
      const Num field_x = to_field(qx);
      const Num field_y = to_field(qy);
      if (!point_on_curve(field_x, field_y))
        return false;
      const Point public_point =
          Point{field_x, field_y, to_field(Num{{1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}})};
      const Point sum =
          point_add(point_mul(u1, generator()), point_mul(u2, public_point));
      Num x;
      Num y;
      if (!point_to_affine(sum, &x, &y))
        return false;
      return compare(reduce_scalar(x), r) == 0;
    }

  }

  // X || Y of private_key * G.
  inline bool p256_public_key(const uint8_t private_key[p256_detail::kScalarSize],
                              uint8_t public_key[64])
  {
    using namespace p256_detail;
    if (private_key == nullptr || public_key == nullptr)
      return false;
    Num scalar;
    parse_num(private_key, &scalar);
    if (is_zero(scalar) || compare(scalar, kOrder) >= 0)
      return false;
    Num x;
    Num y;
    if (!point_to_affine(point_mul(scalar, generator()), &x, &y))
      return false;
    write_num(x, public_key);
    write_num(y, public_key + 32);
    return true;
  }

  inline bool p256_sign_digest(const uint8_t private_key[p256_detail::kScalarSize],
                               const uint8_t digest[p256_detail::kBytes],
                               uint8_t signature[64])
  {
    using namespace p256_detail;
    if (private_key == nullptr || digest == nullptr || signature == nullptr)
    {
      return false;
    }
    Num private_scalar;
    parse_num(private_key, &private_scalar);
    if (is_zero(private_scalar) || compare(private_scalar, kOrder) >= 0)
    {
      return false;
    }
    Num hash_value;
    parse_num(digest, &hash_value);
    hash_value = reduce_scalar(hash_value);

    uint8_t public_key[64];
    if (!p256_public_key(private_key, public_key))
      return false;

    const Num d_mont = scalar_to_mont(private_scalar);
    const Num h_mont = scalar_to_mont(hash_value);
    const Num half = order_half();
    NonceState state;
    derive_nonce_state(private_scalar, digest, &state);
    for (size_t attempt = 0; attempt < 64; ++attempt)
    {
      Num nonce;
      if (!next_nonce(&state, &nonce))
        break;
      Num rx;
      Num ry;
      if (!point_to_affine(point_mul(nonce, generator()), &rx, &ry))
        continue;
      const Num r = reduce_scalar(rx);
      if (is_zero(r))
        continue;
      const Num denominator =
          scalar_add(h_mont, scalar_mul(scalar_to_mont(r), d_mont));
      if (is_zero(denominator))
        continue;
      Num s = scalar_from_mont(scalar_mul(
          scalar_inv(scalar_to_mont(nonce)), denominator));
      if (is_zero(s))
        continue;
      if (compare(s, half) > 0)
      {
        s = scalar_sub(Num{{0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}}, s);
      }
      if (!verify_rs(public_key, digest, r, s))
        continue;
      write_num(r, signature);
      write_num(s, signature + 32);
      secure_zero(&state, sizeof(state));
      secure_zero(public_key, sizeof(public_key));
      return true;
    }
    secure_zero(&state, sizeof(state));
    secure_zero(public_key, sizeof(public_key));
    return false;
  }

  // DER SEQUENCE(r, s); at most 72 bytes.
  inline bool p256_sign_der(const uint8_t private_key[p256_detail::kScalarSize],
                            const uint8_t digest[p256_detail::kBytes],
                            uint8_t *der, size_t *der_size)
  {
    using namespace p256_detail;
    if (der == nullptr || der_size == nullptr)
      return false;
    uint8_t signature[64];
    if (!p256_sign_digest(private_key, digest, signature))
    {
      secure_zero(signature, sizeof(signature));
      return false;
    }
    Num values[2];
    parse_num(signature, &values[0]);
    parse_num(signature + 32, &values[1]);
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
      if (offset + 2 + length > 72)
      {
        secure_zero(signature, sizeof(signature));
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
    secure_zero(signature, sizeof(signature));
    return true;
  }

  inline bool p256_verify_digest(const uint8_t public_key[64],
                                 const uint8_t digest[p256_detail::kBytes],
                                 const uint8_t signature[64])
  {
    using namespace p256_detail;
    if (public_key == nullptr || digest == nullptr || signature == nullptr)
    {
      return false;
    }
    Num r;
    Num s;
    parse_num(signature, &r);
    parse_num(signature + 32, &s);
    return verify_rs(public_key, digest, r, s);
  }


  // Published KAT: RFC 6979 A.2.5 (P-256, SHA-256, message "sample") pins the
  // nonce and r byte for byte. The example's own s is high-S while this signer
  // normalises, so s is compared against n - s and both halves are verified.
  inline bool run_p256_self_tests()
  {
    using namespace p256_detail;
    static const uint8_t kPrivateKey[32] = {
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57,
        0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
        0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};
    static const uint8_t kPublicKey[64] = {
        0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74,
        0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c,
        0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10,
        0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
        0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94,
        0xd4, 0x46, 0x22, 0x99};
    static const uint8_t kExpectedR[32] = {
        0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c,
        0xd4, 0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91,
        0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16};
    static const uint8_t kExpectedS[32] = {
        0x08, 0x34, 0xe3, 0x6a, 0xd2, 0x9a, 0x83, 0xbf, 0x2b, 0xc9, 0x38, 0x5e,
        0x49, 0x1d, 0x60, 0x99, 0xc8, 0xfd, 0xf9, 0xd1, 0xed, 0x67, 0xaa, 0x7e,
        0xa5, 0xf5, 0x1f, 0x93, 0x78, 0x28, 0x57, 0xa9};

    uint8_t digest[32];
    if (!crypto_sha256(reinterpret_cast<const uint8_t *>("sample"), 6, digest))
      return false;

    uint8_t public_key[64];
    bool passed = p256_public_key(kPrivateKey, public_key) &&
                  crypto_constant_time_equal(public_key, kPublicKey, 64);

    uint8_t signature[64];
    passed = passed && p256_sign_digest(kPrivateKey, digest, signature);
    passed = passed && crypto_constant_time_equal(signature, kExpectedR, 32);
    passed = passed &&
             crypto_constant_time_equal(signature + 32, kExpectedS, 32);
    passed = passed && p256_verify_digest(public_key, digest, signature);

    // The RFC example's own s is high-S; the verifier must accept it as well.
    uint8_t high_s[64];
    memcpy(high_s, signature, 32);
    Num halves[2];
    parse_num(signature, &halves[0]);
    parse_num(signature + 32, &halves[1]);
    const Num negated = scalar_sub(Num{}, halves[1]);
    write_num(negated, high_s + 32);
    passed = passed && p256_verify_digest(public_key, digest, high_s);

    // DER must be a well-formed SEQUENCE of two minimally encoded INTEGERs.
    uint8_t der[72];
    size_t der_size = 0;
    passed = passed && p256_sign_der(kPrivateKey, digest, der, &der_size);
    passed = passed && der_size >= 8 && der[0] == 0x30 &&
              der[1] == static_cast<uint8_t>(der_size - 2);
    size_t cursor = 2;
    for (size_t integer = 0; passed && integer < 2; ++integer)
    {
      if (cursor + 2 > der_size || der[cursor] != 0x02)
      {
        passed = false;
        break;
      }
      const size_t length = der[cursor + 1];
      if (length == 0 || length > 33 || cursor + 2 + length > der_size)
      {
        passed = false;
        break;
      }
      const uint8_t *content = der + cursor + 2;
      if (content[0] == 0x00 && (length == 1 || (content[1] & 0x80u) == 0))
        passed = false;
      cursor += 2 + length;
    }
    passed = passed && cursor == der_size;

    // Refusals: tampered signature, wrong digest, zero key and key == n.
    uint8_t tampered[64];
    memcpy(tampered, signature, sizeof(tampered));
    tampered[8] ^= 0x01;
    passed = passed && !p256_verify_digest(public_key, digest, tampered);
    // r == 0 and s == 0 must be rejected outright.
    uint8_t zero_signature[64] = {};
    passed = passed && !p256_verify_digest(public_key, digest, zero_signature);

    uint8_t other_digest[32];
    memcpy(other_digest, digest, sizeof(other_digest));
    other_digest[0] ^= 0x80;
    passed = passed && !p256_verify_digest(public_key, other_digest, signature);

    // A public key that is not on the curve must be refused, not multiplied.
    uint8_t off_curve[64];
    memcpy(off_curve, kPublicKey, sizeof(off_curve));
    off_curve[63] ^= 0x01;
    passed = passed && !p256_verify_digest(off_curve, digest, signature);

    const uint8_t zero_key[32] = {};
    passed = passed && !p256_sign_digest(zero_key, digest, signature);
    uint8_t order_key[32];
    write_num(kOrder, order_key);
    passed = passed && !p256_sign_digest(order_key, digest, signature);

    secure_zero(public_key, sizeof(public_key));
    secure_zero(signature, sizeof(signature));
    secure_zero(high_s, sizeof(high_s));
    secure_zero(der, sizeof(der));
    secure_zero(other_digest, sizeof(other_digest));
    secure_zero(off_curve, sizeof(off_curve));
    secure_zero(order_key, sizeof(order_key));
    return passed;
  }

} // namespace hexwallet

#endif
