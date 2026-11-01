#include "BlsBackend.h"

#include <stdlib.h>
#include <string.h>

#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {

    struct Fp
    {
      uint32_t v[12];
    };

    struct Fp2
    {
      Fp c0;
      Fp c1;
    };

    // p = 0x1a0111ea...ffffaaab, little-endian limbs.
    constexpr uint32_t kP[12] = {
        0xffffaaab, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0,
        0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea};
    constexpr uint32_t kPm2[12] = {
        0xffffaaa9, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0,
        0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea};
    // R^2 mod p, with R = 2^384.
    constexpr uint32_t kR2[12] = {
        0x1c341746, 0xf4df1f34, 0x09d104f1, 0x0a76e6a6, 0x4c95b6d5, 0x8de5476c,
        0x939d83c0, 0x67eb88a9, 0xb519952d, 0x9a793e85, 0x92cae3aa, 0x11988fe5};
    // R mod p, i.e. one in Montgomery form.
    constexpr uint32_t kOne[12] = {
        0x0002fffd, 0x76090000, 0xc40c0002, 0xebf4000b, 0x53c758ba, 0x5f489857,
        0x70525745, 0x77ce5853, 0xa256ec6d, 0x5c071a97, 0xfa80e493, 0x15f65ec3};
    // (p + 1) / 4, the square-root exponent because p == 3 (mod 4).
    constexpr uint32_t kSqrtExp[12] = {
        0xffffeaab, 0xee7fbfff, 0xac54ffff, 0x07aaffff, 0x3dac3d89, 0xd9cc34a8,
        0x3ce144af, 0xd91dd2e1, 0x90d2eb35, 0x92c6e9ed, 0x8e5ff9a6, 0x0680447a};
    // -p^-1 mod 2^32.
    constexpr uint32_t kMontgomeryN0 = 0xfffcfffd;

    // Group order r and the G2 effective cofactor (RFC 9380 section 8.8.2).
    constexpr uint32_t kR[8] = {0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402,
                                0x09a1d805, 0x3339d808, 0x299d7d48, 0x73eda753};
    constexpr uint32_t kHeff[20] = {
        0xaaa95551, 0xe8020005, 0xdebbf6b4, 0x59894c0a, 0x6689f6a3, 0xe954cbc0,
        0xd7477c1a, 0x2ec0ec69, 0x5d1212b0, 0x6d82bf01, 0x8731db95, 0x329c2f17,
        0x1508ffe1, 0x9986ff03, 0x145ad768, 0x88e2a8e9, 0xa91b3528, 0x584c6a0e,
        0xf2ee75b3, 0x0bc69f08};
    constexpr size_t kHeffBits = 636;

    // G1 generator (x, y).
    constexpr uint32_t kG1x[12] = {
        0xdb22c6bb, 0xfb3af00a, 0xf97a1aef, 0x6c55e83f, 0x171bac58, 0xa14e3a3f,
        0x9774b905, 0xc3688c4f, 0x4fa9ac0f, 0x2695638c, 0x3197d794, 0x17f1d3a7};
    constexpr uint32_t kG1y[12] = {
        0x46c5e7e1, 0x0caa2329, 0xa2888ae4, 0xd03cc744, 0x2c04b3ed, 0x00db18cb,
        0xd5d00af6, 0xfcf5e095, 0x741d8ae4, 0xa09e30ed, 0xe3aaa0f1, 0x08b3f481};

    // 3-isogeny map constants (RFC 9380 appendix E.3), each an Fp2 pair
    // (real, imaginary). Order: k(1,0)..k(1,3), k(2,0)..k(2,1),
    // k(3,0)..k(3,3), k(4,0)..k(4,2).
    constexpr uint32_t kIsoReal[13][12] = {
        {0xaaaa97d6, 0x6238aaaa, 0x43d9c71c, 0x5c2638e3, 0xc50ae15d, 0x88b58423,
         0xfd3a042a, 0x32c52d39, 0x47d7ed85, 0xbb5b7a9a, 0x7e8e333e, 0x05c75950},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xffffc71e, 0x26a9ffff, 0xcb8d5555, 0x1472aaa9, 0x4f20a418, 0x9a208c6b,
         0xf7ae0c7f, 0x984f87ad, 0xd787c88f, 0x32126fce, 0x7baa99bc, 0x11560bf1},
        {0xaaaa5ed1, 0x88e2aaaa, 0x0f671c71, 0x7098e38d, 0x142b8575, 0x22d6108f,
         0xf4e810aa, 0xcb14b4e7, 0x1f5fb614, 0xed6dea69, 0xfa38ccfa, 0x171d6541},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x0000000c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x71c6d706, 0x12cfc71c, 0xf8c92f68, 0xfc8c25eb, 0x7d27e500, 0xf54439d8,
         0xa07f649b, 0x0f7da5d4, 0x076d1193, 0x59a4c18b, 0x7ab4113b, 0x1530477c},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xffffc71c, 0x26a9ffff, 0xcb8d5555, 0x1472aaa9, 0x4f20a418, 0x9a208c6b,
         0xf7ae0c7f, 0x984f87ad, 0xd787c88f, 0x32126fce, 0x7baa99bc, 0x11560bf1},
        {0x1c718b10, 0xe1b371c7, 0x56dc4bd9, 0x4e79097a, 0x9aa27452, 0xb0e977c6,
         0xa1e26286, 0x761b0f37, 0xe3811ad0, 0xfbf7043d, 0x3b6cf79b, 0x124c9ad4},
        {0xffffa8fb, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0,
         0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x00000012, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    };
    constexpr uint32_t kIsoImag[13][12] = {
        {0xaaaa97d6, 0x6238aaaa, 0x43d9c71c, 0x5c2638e3, 0xc50ae15d, 0x88b58423,
         0xfd3a042a, 0x32c52d39, 0x47d7ed85, 0xbb5b7a9a, 0x7e8e333e, 0x05c75950},
        {0xffffc71a, 0x26a9ffff, 0xcb8d5555, 0x1472aaa9, 0x4f20a418, 0x9a208c6b,
         0xf7ae0c7f, 0x984f87ad, 0xd787c88f, 0x32126fce, 0x7baa99bc, 0x11560bf1},
        {0xffffe38d, 0x9354ffff, 0xe5c6aaaa, 0x0a395554, 0xa790520c, 0xcd104635,
         0xfbd7063f, 0xcc27c3d6, 0x6bc3e447, 0x190937e7, 0xbdd54cde, 0x08ab05f8},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xffffaa63, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0,
         0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea},
        {0xffffaa9f, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0,
         0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea},
        {0x71c6d706, 0x12cfc71c, 0xf8c92f68, 0xfc8c25eb, 0x7d27e500, 0xf54439d8,
         0xa07f649b, 0x0f7da5d4, 0x076d1193, 0x59a4c18b, 0x7ab4113b, 0x1530477c},
        {0xaaaa97be, 0x6238aaaa, 0x43d9c71c, 0x5c2638e3, 0xc50ae15d, 0x88b58423,
         0xfd3a042a, 0x32c52d39, 0x47d7ed85, 0xbb5b7a9a, 0x7e8e333e, 0x05c75950},
        {0xffffe38f, 0x9354ffff, 0xe5c6aaaa, 0x0a395554, 0xa790520c, 0xcd104635,
         0xfbd7063f, 0xcc27c3d6, 0x6bc3e447, 0x190937e7, 0xbdd54cde, 0x08ab05f8},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xffffa8fb, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0,
         0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea},
        {0xffffa9d3, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0,
         0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea},
        {0xffffaa99, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0,
         0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea},
    };

    inline uint32_t mask_if_zero(uint32_t value)
    {
      return ~(0u - ((value | (0u - value)) >> 31));
    }
    inline uint32_t select32(uint32_t mask, uint32_t when_set, uint32_t when_clear)
    {
      return (when_set & mask) | (when_clear & ~mask);
    }

    uint32_t fp_any(const Fp &a)
    {
      uint32_t value = 0;
      for (size_t index = 0; index < 12; ++index)
        value |= a.v[index];
      return value;
    }
    bool fp_is_zero(const Fp &a) { return fp_any(a) == 0; }
    bool fp_equal(const Fp &a, const Fp &b)
    {
      uint32_t diff = 0;
      for (size_t index = 0; index < 12; ++index)
        diff |= a.v[index] ^ b.v[index];
      return diff == 0;
    }
    void fp_select(Fp &out, uint32_t mask, const Fp &when_set, const Fp &when_clear)
    {
      for (size_t index = 0; index < 12; ++index)
      {
        out.v[index] = select32(mask, when_set.v[index], when_clear.v[index]);
      }
    }

    void fp_add(Fp &out, const Fp &a, const Fp &b)
    {
      uint32_t sum[12];
      uint64_t carry = 0;
      for (size_t index = 0; index < 12; ++index)
      {
        const uint64_t value = static_cast<uint64_t>(a.v[index]) + b.v[index] + carry;
        sum[index] = static_cast<uint32_t>(value);
        carry = value >> 32;
      }
      uint32_t reduced[12];
      uint64_t borrow = 0;
      for (size_t index = 0; index < 12; ++index)
      {
        const uint64_t value = static_cast<uint64_t>(sum[index]) - kP[index] - borrow;
        reduced[index] = static_cast<uint32_t>(value);
        borrow = (value >> 63) & 1u;
      }
      const uint32_t take = static_cast<uint32_t>(carry) |
                            static_cast<uint32_t>(1u - borrow);
      const uint32_t mask = 0u - take;
      for (size_t index = 0; index < 12; ++index)
      {
        out.v[index] = select32(mask, reduced[index], sum[index]);
      }
    }

    void fp_sub(Fp &out, const Fp &a, const Fp &b)
    {
      uint32_t difference[12];
      uint64_t borrow = 0;
      for (size_t index = 0; index < 12; ++index)
      {
        const uint64_t value =
            static_cast<uint64_t>(a.v[index]) - b.v[index] - borrow;
        difference[index] = static_cast<uint32_t>(value);
        borrow = (value >> 63) & 1u;
      }
      const uint32_t mask = 0u - static_cast<uint32_t>(borrow);
      uint64_t carry = 0;
      for (size_t index = 0; index < 12; ++index)
      {
        const uint64_t value = static_cast<uint64_t>(difference[index]) +
                               (kP[index] & mask) + carry;
        out.v[index] = static_cast<uint32_t>(value);
        carry = value >> 32;
      }
    }

    void fp_mul(Fp &out, const Fp &a, const Fp &b)
    {
      uint32_t product[25] = {};
      for (size_t i = 0; i < 12; ++i)
      {
        uint64_t carry = 0;
        for (size_t j = 0; j < 12; ++j)
        {
          const uint64_t value =
              static_cast<uint64_t>(a.v[i]) * b.v[j] + product[i + j] + carry;
          product[i + j] = static_cast<uint32_t>(value);
          carry = value >> 32;
        }
        for (size_t k = i + 12; k < 25; ++k)
        {
          const uint64_t value = static_cast<uint64_t>(product[k]) + carry;
          product[k] = static_cast<uint32_t>(value);
          carry = value >> 32;
        }
      }
      for (size_t i = 0; i < 12; ++i)
      {
        const uint32_t factor = product[i] * kMontgomeryN0;
        uint64_t carry = 0;
        for (size_t j = 0; j < 12; ++j)
        {
          const uint64_t value = static_cast<uint64_t>(factor) * kP[j] +
                                 product[i + j] + carry;
          product[i + j] = static_cast<uint32_t>(value);
          carry = value >> 32;
        }
        for (size_t k = i + 12; k < 25; ++k)
        {
          const uint64_t value = static_cast<uint64_t>(product[k]) + carry;
          product[k] = static_cast<uint32_t>(value);
          carry = value >> 32;
        }
      }
      uint32_t reduced[12];
      uint64_t borrow = 0;
      for (size_t index = 0; index < 12; ++index)
      {
        const uint64_t value =
            static_cast<uint64_t>(product[12 + index]) - kP[index] - borrow;
        reduced[index] = static_cast<uint32_t>(value);
        borrow = (value >> 63) & 1u;
      }
      const uint32_t top =
          (product[24] | (0u - product[24])) >> 31; // 0 or 1, branch-free
      const uint32_t take = top | static_cast<uint32_t>(1u - borrow);
      const uint32_t mask = 0u - take;
      for (size_t index = 0; index < 12; ++index)
      {
        out.v[index] =
            select32(mask, reduced[index], product[12 + index]);
      }
    }

    void fp_sqr(Fp &out, const Fp &a) { fp_mul(out, a, a); }
    void fp_neg(Fp &out, const Fp &a)
    {
      const Fp zero = {};
      fp_sub(out, zero, a);
    }

    // Converts a raw (non-Montgomery) limb array into Montgomery form.
    void fp_to_mont(Fp &out, const uint32_t raw[12])
    {
      Fp value;
      Fp r2;
      memcpy(value.v, raw, sizeof(value.v));
      memcpy(r2.v, kR2, sizeof(r2.v));
      fp_mul(out, value, r2);
    }

    void fp_from_mont(Fp &out, const Fp &a)
    {
      Fp one = {};
      one.v[0] = 1;
      fp_mul(out, a, one);
    }

    void fp_set_u64(Fp &out, uint64_t value)
    {
      uint32_t raw[12] = {};
      raw[0] = static_cast<uint32_t>(value);
      raw[1] = static_cast<uint32_t>(value >> 32);
      fp_to_mont(out, raw);
    }

    void fp_pow(Fp &out, const Fp &base, const uint32_t exponent[12])
    {
      Fp result;
      memcpy(result.v, kOne, sizeof(result.v));
      for (int bit = 383; bit >= 0; --bit)
      {
        fp_sqr(result, result);
        Fp temporary;
        fp_mul(temporary, result, base);
        const uint32_t set =
            (exponent[static_cast<size_t>(bit) >> 5] >>
             (static_cast<uint32_t>(bit) & 31u)) &
            1u;
        fp_select(result, 0u - set, temporary, result);
      }
      out = result;
    }

    bool fp_sqrt(Fp &out, const Fp &a)
    {
      Fp root;
      fp_pow(root, a, kSqrtExp);
      Fp check;
      fp_sqr(check, root);
      out = root;
      return fp_equal(check, a);
    }

    void fp_inv(Fp &out, const Fp &a)
    {
      if (fp_is_zero(a))
      {
        memset(&out, 0, sizeof(out));
        return;
      }
      fp_pow(out, a, kPm2);
    }

    // Reads a 48-byte big-endian value; rejects values >= p.
    bool fp_read_canonical(Fp &out, const uint8_t in[48])
    {
      uint32_t raw[12];
      for (size_t index = 0; index < 12; ++index)
      {
        const uint8_t *tail = in + (11 - index) * 4;
        raw[index] = (static_cast<uint32_t>(tail[0]) << 24) |
                     (static_cast<uint32_t>(tail[1]) << 16) |
                     (static_cast<uint32_t>(tail[2]) << 8) |
                     static_cast<uint32_t>(tail[3]);
      }
      for (size_t index = 12; index-- > 0;)
      {
        if (raw[index] < kP[index])
          break;
        if (raw[index] > kP[index])
          return false;
        if (index == 0)
          return false; // exactly p
      }
      fp_to_mont(out, raw);
      return true;
    }

    void fp_write_bytes(uint8_t out[48], const Fp &a)
    {
      Fp standard;
      fp_from_mont(standard, a);
      for (size_t index = 0; index < 12; ++index)
      {
        uint8_t *tail = out + (11 - index) * 4;
        tail[0] = static_cast<uint8_t>(standard.v[index] >> 24);
        tail[1] = static_cast<uint8_t>(standard.v[index] >> 16);
        tail[2] = static_cast<uint8_t>(standard.v[index] >> 8);
        tail[3] = static_cast<uint8_t>(standard.v[index]);
      }
    }

    int fp_compare_bytes(const uint8_t left[48], const uint8_t right[48])
    {
      const int order = memcmp(left, right, 48);
      return order < 0 ? -1 : (order > 0 ? 1 : 0);
    }

    // True when y is the lexicographically larger of y and -y.
    bool fp_lexicographically_largest(const Fp &y)
    {
      uint8_t encoded[48];
      uint8_t negated[48];
      Fp minus_y;
      fp_neg(minus_y, y);
      fp_write_bytes(encoded, y);
      fp_write_bytes(negated, minus_y);
      return fp_compare_bytes(encoded, negated) > 0;
    }

    uint32_t fp_parity(const Fp &a)
    {
      uint8_t encoded[48];
      fp_write_bytes(encoded, a);
      return encoded[47] & 1u;
    }

    void fp_read_reduced(Fp &out, const uint8_t in[64])
    {
      Fp accumulator = {};
      Fp one;
      memcpy(one.v, kOne, sizeof(one.v));
      for (size_t byte = 0; byte < 64; ++byte)
      {
        for (int bit = 7; bit >= 0; --bit)
        {
          fp_add(accumulator, accumulator, accumulator);
          const uint32_t set = (in[byte] >> bit) & 1u;
          Fp with_bit;
          fp_add(with_bit, accumulator, one);
          fp_select(accumulator, 0u - set, with_bit, accumulator);
        }
      }
      out = accumulator;
    }

    // ------------------------------- Fp2 -------------------------------------

    void fp2_add(Fp2 &out, const Fp2 &a, const Fp2 &b)
    {
      fp_add(out.c0, a.c0, b.c0);
      fp_add(out.c1, a.c1, b.c1);
    }
    void fp2_sub(Fp2 &out, const Fp2 &a, const Fp2 &b)
    {
      fp_sub(out.c0, a.c0, b.c0);
      fp_sub(out.c1, a.c1, b.c1);
    }
    void fp2_neg(Fp2 &out, const Fp2 &a)
    {
      fp_neg(out.c0, a.c0);
      fp_neg(out.c1, a.c1);
    }
    void fp2_mul(Fp2 &out, const Fp2 &a, const Fp2 &b)
    {
      Fp ac, bd, cross, t0, t1;
      fp_mul(ac, a.c0, b.c0);
      fp_mul(bd, a.c1, b.c1);
      fp_add(t0, a.c0, a.c1);
      fp_add(t1, b.c0, b.c1);
      fp_mul(cross, t0, t1);
      fp_sub(cross, cross, ac);
      fp_sub(cross, cross, bd);
      fp_sub(out.c0, ac, bd);
      out.c1 = cross;
    }
    void fp2_sqr(Fp2 &out, const Fp2 &a)
    {
      Fp ac, bd, cross, sum;
      fp_mul(ac, a.c0, a.c0);
      fp_mul(bd, a.c1, a.c1);
      fp_add(sum, a.c0, a.c1);
      fp_mul(cross, sum, sum);
      fp_sub(cross, cross, ac);
      fp_sub(cross, cross, bd);
      fp_sub(out.c0, ac, bd);
      out.c1 = cross;
    }
    void fp2_inv(Fp2 &out, const Fp2 &a)
    {
      Fp norm;
      fp_sqr(norm, a.c0);
      Fp squared;
      fp_sqr(squared, a.c1);
      fp_add(norm, norm, squared);
      if (fp_is_zero(norm))
      {
        memset(&out, 0, sizeof(out));
        return;
      }
      Fp inverse;
      fp_inv(inverse, norm);
      fp_mul(out.c0, a.c0, inverse);
      Fp negated;
      fp_neg(negated, a.c1);
      fp_mul(out.c1, negated, inverse);
    }
    bool fp2_is_zero(const Fp2 &a) { return fp_is_zero(a.c0) && fp_is_zero(a.c1); }
    void fp2_select(Fp2 &out, uint32_t mask, const Fp2 &when_set,
                    const Fp2 &when_clear)
    {
      fp_select(out.c0, mask, when_set.c0, when_clear.c0);
      fp_select(out.c1, mask, when_set.c1, when_clear.c1);
    }
    bool fp2_lexicographically_largest(const Fp2 &y)
    {
      if (!fp_is_zero(y.c1))
        return fp_lexicographically_largest(y.c1);
      return fp_lexicographically_largest(y.c0);
    }
    uint32_t fp2_sgn0(const Fp2 &x)
    {
      const uint32_t sign0 = fp_parity(x.c0);
      const uint32_t zero0 = fp_is_zero(x.c0) ? 1u : 0u;
      return sign0 | (zero0 & fp_parity(x.c1));
    }

    // Square root in Fp2 with p == 3 (mod 4), RFC 9380 appendix F.2.1.2.
    bool fp2_sqrt(Fp2 &out, const Fp2 &a)
    {
      if (fp_is_zero(a.c1))
      {
        Fp root;
        if (fp_sqrt(root, a.c0))
        {
          out.c0 = root;
          memset(&out.c1, 0, sizeof(out.c1));
          return true;
        }
        Fp negated;
        fp_neg(negated, a.c0);
        if (fp_sqrt(root, negated))
        {
          memset(&out.c0, 0, sizeof(out.c0));
          out.c1 = root;
          return true;
        }
        return false;
      }
      Fp alpha, squared;
      fp_sqr(alpha, a.c0);
      fp_sqr(squared, a.c1);
      fp_add(alpha, alpha, squared);
      Fp gamma;
      if (!fp_sqrt(gamma, alpha))
        return false;
      Fp two_inverse, delta;
      fp_set_u64(two_inverse, 2);
      fp_inv(two_inverse, two_inverse);
      fp_add(delta, a.c0, gamma);
      fp_mul(delta, delta, two_inverse);
      Fp root;
      if (fp_sqrt(root, delta))
      {
        if (fp_is_zero(root))
          return false;
        out.c0 = root;
        Fp denominator;
        fp_add(denominator, root, root);
        fp_inv(denominator, denominator);
        fp_mul(out.c1, a.c1, denominator);
        return true;
      }
      Fp negated;
      fp_neg(negated, delta);
      if (!fp_sqrt(root, negated) || fp_is_zero(root))
        return false;
      out.c1 = root;
      Fp denominator;
      fp_add(denominator, root, root);
      fp_inv(denominator, denominator);
      fp_mul(out.c0, a.c1, denominator);
      return true;
    }

    // ------------------------- curve coordinates -----------------------------

    struct G1Jac
    {
      Fp x, y, z;
    };
    struct G1Affine
    {
      Fp x, y;
      bool infinity;
    };
    struct G2Jac
    {
      Fp2 x, y, z;
    };
    struct G2Affine
    {
      Fp2 x, y;
      bool infinity;
    };

    void g1_infinity(G1Jac &p) { memset(&p, 0, sizeof(p)); }
    bool g1_is_infinity(const G1Jac &p) { return fp_is_zero(p.z); }
    void g1_select(G1Jac &out, uint32_t mask, const G1Jac &when_set,
                   const G1Jac &when_clear)
    {
      fp_select(out.x, mask, when_set.x, when_clear.x);
      fp_select(out.y, mask, when_set.y, when_clear.y);
      fp_select(out.z, mask, when_set.z, when_clear.z);
    }

    void g1_double(G1Jac &out, const G1Jac &p)
    {
      Fp a, b, c, d, e, f, t;
      Fp z3;
      fp_mul(z3, p.y, p.z);
      fp_add(z3, z3, z3);
      fp_sqr(a, p.x);
      fp_sqr(b, p.y);
      fp_sqr(c, b);
      fp_add(t, p.x, b);
      fp_sqr(t, t);
      fp_sub(t, t, a);
      fp_sub(t, t, c);
      fp_add(d, t, t);
      fp_add(e, a, a);
      fp_add(e, e, a);
      fp_sqr(f, e);
      fp_add(t, d, d);
      fp_sub(out.x, f, t);
      fp_sub(t, d, out.x);
      fp_mul(out.y, e, t);
      fp_add(t, c, c);
      fp_add(t, t, t);
      fp_add(t, t, t);
      fp_sub(out.y, out.y, t);
      out.z = z3;
    }

    // Complete addition: the regular formula and the doubling are both evaluated
    // and the correct one is selected with masks, so the ladder can add a point to
    // itself without a data-dependent branch.
    // `out` must not alias `p` or `q`; the ladder and the aggregate keep a
    // separate destination so no input is overwritten mid-formula.
    void g1_add(G1Jac &out, const G1Jac &p, const G1Jac &q)
    {
      Fp z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v, t;
      fp_sqr(z1z1, p.z);
      fp_sqr(z2z2, q.z);
      fp_mul(u1, p.x, z2z2);
      fp_mul(u2, q.x, z1z1);
      fp_mul(t, q.z, z2z2);
      fp_mul(s1, p.y, t);
      fp_mul(t, p.z, z1z1);
      fp_mul(s2, q.y, t);
      fp_sub(h, u2, u1);
      fp_add(i, h, h);
      fp_sqr(i, i);
      fp_mul(j, h, i);
      fp_sub(r, s2, s1);
      fp_add(r, r, r);
      fp_mul(v, u1, i);
      G1Jac sum;
      fp_sqr(sum.x, r);
      fp_sub(sum.x, sum.x, j);
      fp_sub(sum.x, sum.x, v);
      fp_sub(sum.x, sum.x, v);
      fp_sub(t, v, sum.x);
      fp_mul(sum.y, r, t);
      fp_mul(t, s1, j);
      fp_add(t, t, t);
      fp_sub(sum.y, sum.y, t);
      fp_add(t, p.z, q.z);
      fp_sqr(t, t);
      fp_sub(t, t, z1z1);
      fp_sub(t, t, z2z2);
      fp_mul(sum.z, t, h);

      G1Jac doubled;
      g1_double(doubled, p);
      G1Jac infinite;
      g1_infinity(infinite);
      const uint32_t h_zero = mask_if_zero(fp_any(h));
      const uint32_t r_zero = mask_if_zero(fp_any(r));
      G1Jac branch;
      g1_select(branch, r_zero, doubled, infinite);
      g1_select(out, h_zero, branch, sum);
      g1_select(out, mask_if_zero(fp_any(p.z)), q, out);
      g1_select(out, mask_if_zero(fp_any(q.z)), p, out);
    }

    void g1_from_affine(G1Jac &out, const G1Affine &p)
    {
      if (p.infinity)
      {
        g1_infinity(out);
        return;
      }
      out.x = p.x;
      out.y = p.y;
      Fp one;
      memcpy(one.v, kOne, sizeof(one.v));
      out.z = one;
    }

    bool g1_to_affine(G1Affine &out, const G1Jac &p)
    {
      if (g1_is_infinity(p))
      {
        memset(&out, 0, sizeof(out));
        out.infinity = true;
        return true;
      }
      Fp z_inverse, z2, z3;
      fp_inv(z_inverse, p.z);
      fp_sqr(z2, z_inverse);
      fp_mul(z3, z2, z_inverse);
      fp_mul(out.x, p.x, z2);
      fp_mul(out.y, p.y, z3);
      out.infinity = false;
      return true;
    }

    void g1_mul_bits(G1Jac &out, const G1Jac &base, const uint32_t *limbs,
                     size_t bits)
    {
      G1Jac accumulator;
      g1_infinity(accumulator);
      for (size_t index = bits; index-- > 0;)
      {
        g1_double(accumulator, accumulator);
        G1Jac sum;
        g1_add(sum, accumulator, base);
        const uint32_t set = (limbs[index >> 5] >> (index & 31u)) & 1u;
        g1_select(accumulator, 0u - set, sum, accumulator);
      }
      out = accumulator;
    }

    void g2_infinity(G2Jac &p) { memset(&p, 0, sizeof(p)); }
    bool g2_is_infinity(const G2Jac &p) { return fp2_is_zero(p.z); }
    void g2_select(G2Jac &out, uint32_t mask, const G2Jac &when_set,
                   const G2Jac &when_clear)
    {
      fp2_select(out.x, mask, when_set.x, when_clear.x);
      fp2_select(out.y, mask, when_set.y, when_clear.y);
      fp2_select(out.z, mask, when_set.z, when_clear.z);
    }

    void g2_double(G2Jac &out, const G2Jac &p)
    {
      Fp2 a, b, c, d, e, f, t;
      Fp2 z3;
      fp2_mul(z3, p.y, p.z);
      fp2_add(z3, z3, z3);
      fp2_sqr(a, p.x);
      fp2_sqr(b, p.y);
      fp2_sqr(c, b);
      fp2_add(t, p.x, b);
      fp2_sqr(t, t);
      fp2_sub(t, t, a);
      fp2_sub(t, t, c);
      fp2_add(d, t, t);
      fp2_add(e, a, a);
      fp2_add(e, e, a);
      fp2_sqr(f, e);
      fp2_add(t, d, d);
      fp2_sub(out.x, f, t);
      fp2_sub(t, d, out.x);
      fp2_mul(out.y, e, t);
      fp2_add(t, c, c);
      fp2_add(t, t, t);
      fp2_add(t, t, t);
      fp2_sub(out.y, out.y, t);
      out.z = z3;
    }

    uint32_t fp2_any(const Fp2 &a) { return fp_any(a.c0) | fp_any(a.c1); }

    // `out` must not alias `p` or `q`; see the note on g1_add.
    void g2_add(G2Jac &out, const G2Jac &p, const G2Jac &q)
    {
      Fp2 z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v, t;
      fp2_sqr(z1z1, p.z);
      fp2_sqr(z2z2, q.z);
      fp2_mul(u1, p.x, z2z2);
      fp2_mul(u2, q.x, z1z1);
      fp2_mul(t, q.z, z2z2);
      fp2_mul(s1, p.y, t);
      fp2_mul(t, p.z, z1z1);
      fp2_mul(s2, q.y, t);
      fp2_sub(h, u2, u1);
      fp2_add(i, h, h);
      fp2_sqr(i, i);
      fp2_mul(j, h, i);
      fp2_sub(r, s2, s1);
      fp2_add(r, r, r);
      fp2_mul(v, u1, i);
      G2Jac sum;
      fp2_sqr(sum.x, r);
      fp2_sub(sum.x, sum.x, j);
      fp2_sub(sum.x, sum.x, v);
      fp2_sub(sum.x, sum.x, v);
      fp2_sub(t, v, sum.x);
      fp2_mul(sum.y, r, t);
      fp2_mul(t, s1, j);
      fp2_add(t, t, t);
      fp2_sub(sum.y, sum.y, t);
      fp2_add(t, p.z, q.z);
      fp2_sqr(t, t);
      fp2_sub(t, t, z1z1);
      fp2_sub(t, t, z2z2);
      fp2_mul(sum.z, t, h);

      G2Jac doubled;
      g2_double(doubled, p);
      G2Jac infinite;
      g2_infinity(infinite);
      G2Jac branch;
      g2_select(branch, mask_if_zero(fp2_any(r)), doubled, infinite);
      g2_select(out, mask_if_zero(fp2_any(h)), branch, sum);
      g2_select(out, mask_if_zero(fp2_any(p.z)), q, out);
      g2_select(out, mask_if_zero(fp2_any(q.z)), p, out);
    }

    void g2_from_affine(G2Jac &out, const G2Affine &p)
    {
      if (p.infinity)
      {
        g2_infinity(out);
        return;
      }
      out.x = p.x;
      out.y = p.y;
      Fp2 one = {};
      memcpy(one.c0.v, kOne, sizeof(one.c0.v));
      out.z = one;
    }

    bool g2_to_affine(G2Affine &out, const G2Jac &p)
    {
      if (g2_is_infinity(p))
      {
        memset(&out, 0, sizeof(out));
        out.infinity = true;
        return true;
      }
      Fp2 z_inverse, z2, z3;
      fp2_inv(z_inverse, p.z);
      fp2_sqr(z2, z_inverse);
      fp2_mul(z3, z2, z_inverse);
      fp2_mul(out.x, p.x, z2);
      fp2_mul(out.y, p.y, z3);
      out.infinity = false;
      return true;
    }

    void g2_mul_bits(G2Jac &out, const G2Jac &base, const uint32_t *limbs,
                     size_t bits)
    {
      G2Jac accumulator;
      g2_infinity(accumulator);
      for (size_t index = bits; index-- > 0;)
      {
        g2_double(accumulator, accumulator);
        G2Jac sum;
        g2_add(sum, accumulator, base);
        const uint32_t set = (limbs[index >> 5] >> (index & 31u)) & 1u;
        g2_select(accumulator, 0u - set, sum, accumulator);
      }
      out = accumulator;
    }

    // -------------------------- serialization --------------------------------

    void g1_compress(uint8_t out[48], const G1Jac &p)
    {
      G1Affine affine;
      g1_to_affine(affine, p);
      if (affine.infinity)
      {
        memset(out, 0, 48);
        out[0] = 0xc0;
        return;
      }
      fp_write_bytes(out, affine.x);
      out[0] |= 0x80;
      if (fp_lexicographically_largest(affine.y))
        out[0] |= 0x20;
    }

    bool g1_decompress(G1Affine &out, const uint8_t in[48])
    {
      memset(&out, 0, sizeof(out));
      const bool compressed = (in[0] & 0x80) != 0;
      const bool infinity = (in[0] & 0x40) != 0;
      const bool sort = (in[0] & 0x20) != 0;
      if (!compressed)
        return false;
      if (infinity)
      {
        if (sort)
          return false;
        for (size_t index = 1; index < 48; ++index)
        {
          if (in[index] != 0)
            return false;
        }
        out.infinity = true;
        return true;
      }
      uint8_t encoded[48];
      memcpy(encoded, in, 48);
      encoded[0] &= 0x1f;
      Fp x;
      if (!fp_read_canonical(x, encoded))
        return false;
      Fp x2, x3, rhs, y;
      fp_sqr(x2, x);
      fp_mul(x3, x2, x);
      Fp four;
      fp_set_u64(four, 4);
      fp_add(rhs, x3, four);
      if (!fp_sqrt(y, rhs))
        return false;
      if (fp_lexicographically_largest(y) != sort)
        fp_neg(y, y);
      out.x = x;
      out.y = y;
      out.infinity = false;
      return true;
    }

    void g2_compress(uint8_t out[96], const G2Jac &p)
    {
      G2Affine affine;
      g2_to_affine(affine, p);
      if (affine.infinity)
      {
        memset(out, 0, 96);
        out[0] = 0xc0;
        return;
      }
      fp_write_bytes(out, affine.x.c1);
      fp_write_bytes(out + 48, affine.x.c0);
      out[0] |= 0x80;
      if (fp2_lexicographically_largest(affine.y))
        out[0] |= 0x20;
    }

    bool g2_decompress(G2Affine &out, const uint8_t in[96])
    {
      memset(&out, 0, sizeof(out));
      const bool compressed = (in[0] & 0x80) != 0;
      const bool infinity = (in[0] & 0x40) != 0;
      const bool sort = (in[0] & 0x20) != 0;
      if (!compressed)
        return false;
      if (infinity)
      {
        if (sort)
          return false;
        for (size_t index = 1; index < 96; ++index)
        {
          if (in[index] != 0)
            return false;
        }
        out.infinity = true;
        return true;
      }
      uint8_t encoded[48];
      memcpy(encoded, in, 48);
      encoded[0] &= 0x1f;
      Fp2 x;
      if (!fp_read_canonical(x.c1, encoded))
        return false;
      if (!fp_read_canonical(x.c0, in + 48))
        return false;
      Fp2 x2, x3, rhs, y;
      fp2_sqr(x2, x);
      fp2_mul(x3, x2, x);
      Fp2 b;
      fp_set_u64(b.c0, 4);
      fp_set_u64(b.c1, 4);
      fp2_add(rhs, x3, b);
      if (!fp2_sqrt(y, rhs))
        return false;
      if (fp2_lexicographically_largest(y) != sort)
        fp2_neg(y, y);
      out.x = x;
      out.y = y;
      out.infinity = false;
      return true;
    }

    // ------------------------- hash to curve --------------------------------

    bool expand_message_xmd(const uint8_t *message, size_t message_size,
                            const char *dst, uint8_t *out, size_t out_size)
    {
      const size_t dst_size = strlen(dst);
      if (dst_size > 255 || out_size == 0 || out_size > 255 * 32)
        return false;
      if (message == nullptr && message_size != 0)
        return false;
      if (message_size > 65535)
        return false;
      const size_t prefix = 64 + message_size + 2 + 1 + dst_size + 1;
      uint8_t *buffer = static_cast<uint8_t *>(malloc(prefix));
      if (buffer == nullptr)
        return false;
      memset(buffer, 0, 64);
      size_t offset = 64;
      if (message_size != 0)
      {
        memcpy(buffer + offset, message, message_size);
        offset += message_size;
      }
      buffer[offset++] = static_cast<uint8_t>(out_size >> 8);
      buffer[offset++] = static_cast<uint8_t>(out_size);
      buffer[offset++] = 0;
      memcpy(buffer + offset, dst, dst_size);
      offset += dst_size;
      buffer[offset++] = static_cast<uint8_t>(dst_size);
      uint8_t b0[32];
      bool ok = crypto_sha256(buffer, offset, b0);
      secure_zero(buffer, prefix);
      free(buffer);
      if (!ok)
        return false;

      uint8_t block[32];
      uint8_t previous[32];
      size_t produced = 0;
      for (uint32_t counter = 1; produced < out_size; ++counter)
      {
        uint8_t input[32 + 1 + 256];
        size_t input_size = 0;
        if (counter == 1)
        {
          memcpy(input, b0, 32);
          input_size = 32;
        }
        else
        {
          for (size_t index = 0; index < 32; ++index)
          {
            input[index] = static_cast<uint8_t>(b0[index] ^ previous[index]);
          }
          input_size = 32;
        }
        input[input_size++] = static_cast<uint8_t>(counter);
        memcpy(input + input_size, dst, dst_size);
        input_size += dst_size;
        input[input_size++] = static_cast<uint8_t>(dst_size);
        if (!crypto_sha256(input, input_size, block))
          return false;
        const size_t take = out_size - produced < 32 ? out_size - produced : 32;
        memcpy(out + produced, block, take);
        produced += take;
        memcpy(previous, block, 32);
      }
      secure_zero(b0, sizeof(b0));
      secure_zero(block, sizeof(block));
      secure_zero(previous, sizeof(previous));
      return true;
    }

    void hash_to_field(Fp2 u[2], const uint8_t uniform[256])
    {
      fp_read_reduced(u[0].c0, uniform);
      fp_read_reduced(u[0].c1, uniform + 64);
      fp_read_reduced(u[1].c0, uniform + 128);
      fp_read_reduced(u[1].c1, uniform + 192);
    }

    // isogeny constants converted on demand; the map runs once per hash.
    void isogeny_constant(Fp2 &out, size_t index)
    {
      fp_to_mont(out.c0, kIsoReal[index]);
      fp_to_mont(out.c1, kIsoImag[index]);
    }

    void iso_map(G2Affine &out, const G2Affine &in)
    {
      if (in.infinity)
      {
        memset(&out, 0, sizeof(out));
        out.infinity = true;
        return;
      }
      Fp2 x2, x3, t, k, x_num, x_den, y_num, y_den;
      fp2_sqr(x2, in.x);
      fp2_mul(x3, x2, in.x);
      // x_num = k13 x^3 + k12 x^2 + k11 x + k10
      isogeny_constant(k, 3);
      fp2_mul(x_num, k, x3);
      isogeny_constant(k, 2);
      fp2_mul(t, k, x2);
      fp2_add(x_num, x_num, t);
      isogeny_constant(k, 1);
      fp2_mul(t, k, in.x);
      fp2_add(x_num, x_num, t);
      isogeny_constant(k, 0);
      fp2_add(x_num, x_num, k);
      // x_den = x^2 + k21 x + k20
      isogeny_constant(k, 5);
      fp2_mul(x_den, k, in.x);
      fp2_add(x_den, x_den, x2);
      isogeny_constant(k, 4);
      fp2_add(x_den, x_den, k);
      // y_num = k33 x^3 + k32 x^2 + k31 x + k30
      isogeny_constant(k, 9);
      fp2_mul(y_num, k, x3);
      isogeny_constant(k, 8);
      fp2_mul(t, k, x2);
      fp2_add(y_num, y_num, t);
      isogeny_constant(k, 7);
      fp2_mul(t, k, in.x);
      fp2_add(y_num, y_num, t);
      isogeny_constant(k, 6);
      fp2_add(y_num, y_num, k);
      // y_den = x^3 + k42 x^2 + k41 x + k40
      isogeny_constant(k, 12);
      fp2_mul(y_den, k, x2);
      fp2_add(y_den, y_den, x3);
      isogeny_constant(k, 11);
      fp2_mul(t, k, in.x);
      fp2_add(y_den, y_den, t);
      isogeny_constant(k, 10);
      fp2_add(y_den, y_den, k);
      if (fp2_is_zero(x_den) || fp2_is_zero(y_den))
      {
        memset(&out, 0, sizeof(out));
        out.infinity = true;
        return;
      }
      Fp2 inverse;
      fp2_inv(inverse, x_den);
      fp2_mul(out.x, x_num, inverse);
      fp2_inv(inverse, y_den);
      fp2_mul(t, in.y, y_num);
      fp2_mul(out.y, t, inverse);
      out.infinity = false;
    }

    // Simplified SWU onto E': y^2 = x^3 + 240i x + 1012(1+i).
    bool map_to_curve(G2Affine &out, const Fp2 &u)
    {
      Fp2 a_prime, b_prime, z;
      fp_set_u64(a_prime.c0, 0);
      fp_set_u64(a_prime.c1, 240);
      fp_set_u64(b_prime.c0, 1012);
      fp_set_u64(b_prime.c1, 1012);
      Fp two, one;
      fp_set_u64(two, 2);
      fp_set_u64(one, 1);
      fp_neg(z.c0, two); // Z = -(2 + i)
      fp_neg(z.c1, one);

      Fp2 u2, u4, z2, t, x1, x2, gx1, gx2;
      fp2_sqr(u2, u);
      fp2_sqr(u4, u2);
      fp2_sqr(z2, z);
      fp2_mul(t, z2, u4);
      Fp2 term;
      fp2_mul(term, z, u2);
      fp2_add(t, t, term);
      if (fp2_is_zero(t))
      {
        // x1 = B / (Z * A)
        Fp2 denominator;
        fp2_mul(denominator, z, a_prime);
        if (fp2_is_zero(denominator))
          return false;
        Fp2 inverse;
        fp2_inv(inverse, denominator);
        fp2_mul(x1, b_prime, inverse);
      }
      else
      {
        Fp2 inverse, ratio, minus_b, one_fp2 = {};
        fp2_inv(inverse, t);
        // x1 = (-B/A) * (1 + 1/t)
        fp2_neg(minus_b, b_prime);
        fp2_inv(ratio, a_prime);
        fp2_mul(ratio, minus_b, ratio);
        memcpy(one_fp2.c0.v, kOne, sizeof(one_fp2.c0.v));
        fp2_add(t, inverse, one_fp2);
        fp2_mul(x1, ratio, t);
      }

      Fp2 x1_2, x1_3;
      fp2_sqr(x1_2, x1);
      fp2_mul(x1_3, x1_2, x1);
      fp2_mul(t, a_prime, x1);
      fp2_add(gx1, x1_3, t);
      fp2_add(gx1, gx1, b_prime);

      fp2_mul(x2, u2, x1);
      fp2_mul(x2, x2, z);
      Fp2 x2_2, x2_3;
      fp2_sqr(x2_2, x2);
      fp2_mul(x2_3, x2_2, x2);
      fp2_mul(t, a_prime, x2);
      fp2_add(gx2, x2_3, t);
      fp2_add(gx2, gx2, b_prime);

      Fp2 y;
      if (fp2_sqrt(y, gx1))
      {
        out.x = x1;
      }
      else if (fp2_sqrt(y, gx2))
      {
        out.x = x2;
      }
      else
      {
        return false;
      }
      if (fp2_sgn0(u) != fp2_sgn0(y))
        fp2_neg(y, y);
      out.y = y;
      out.infinity = false;
      return true;
    }

    bool hash_to_g2(G2Jac &out, const uint8_t *message, size_t message_size,
                    const char *dst)
    {
      uint8_t uniform[256];
      if (!expand_message_xmd(message, message_size, dst, uniform, sizeof(uniform)))
      {
        return false;
      }
      Fp2 u[2];
      hash_to_field(u, uniform);
      secure_zero(uniform, sizeof(uniform));
      G2Affine mapped[2];
      G2Jac points[2];
      for (size_t index = 0; index < 2; ++index)
      {
        G2Affine on_isogenous;
        if (!map_to_curve(on_isogenous, u[index]))
          return false;
        iso_map(mapped[index], on_isogenous);
        if (mapped[index].infinity)
          return false;
        g2_from_affine(points[index], mapped[index]);
      }
      G2Jac sum;
      g2_add(sum, points[0], points[1]);
      g2_mul_bits(out, sum, kHeff, kHeffBits);
      return !g2_is_infinity(out);
    }

    // ------------------------------ scalars ---------------------------------

    uint64_t scalar_add(uint32_t out[8], const uint32_t a[8], const uint32_t b[8])
    {
      uint64_t carry = 0;
      for (size_t index = 0; index < 8; ++index)
      {
        const uint64_t value = static_cast<uint64_t>(a[index]) + b[index] + carry;
        out[index] = static_cast<uint32_t>(value);
        carry = value >> 32;
      }
      return carry;
    }

    // Subtracts r when the 256-bit value is at least r. Returns the borrow.
    uint64_t scalar_reduce_once(uint32_t value[8], uint32_t top_carry)
    {
      uint32_t reduced[8];
      uint64_t borrow = 0;
      for (size_t index = 0; index < 8; ++index)
      {
        const uint64_t difference =
            static_cast<uint64_t>(value[index]) - kR[index] - borrow;
        reduced[index] = static_cast<uint32_t>(difference);
        borrow = (difference >> 63) & 1u;
      }
      const uint32_t take =
          top_carry | static_cast<uint32_t>(1u - borrow);
      const uint32_t mask = 0u - take;
      for (size_t index = 0; index < 8; ++index)
      {
        value[index] = select32(mask, reduced[index], value[index]);
      }
      return borrow;
    }

    void scalar_reduce_bytes(uint32_t out[8], const uint8_t *input, size_t size)
    {
      memset(out, 0, sizeof(uint32_t) * 8);
      for (size_t byte = 0; byte < size; ++byte)
      {
        for (int bit = 7; bit >= 0; --bit)
        {
          uint64_t carry = (input[byte] >> bit) & 1u;
          for (size_t index = 0; index < 8; ++index)
          {
            const uint64_t value = (static_cast<uint64_t>(out[index]) << 1) | carry;
            out[index] = static_cast<uint32_t>(value);
            carry = value >> 32;
          }
          // 2*acc + bit is below 2r, so one subtraction is enough.
          scalar_reduce_once(out, static_cast<uint32_t>(carry));
        }
      }
    }

    bool scalar_read_canonical(uint32_t out[8], const uint8_t in[32])
    {
      for (size_t index = 0; index < 8; ++index)
      {
        const uint8_t *tail = in + (7 - index) * 4;
        out[index] = (static_cast<uint32_t>(tail[0]) << 24) |
                     (static_cast<uint32_t>(tail[1]) << 16) |
                     (static_cast<uint32_t>(tail[2]) << 8) |
                     static_cast<uint32_t>(tail[3]);
      }
      // Branch-free comparison with r: the borrow is set exactly when the value
      // is below the group order. A secret key must not leak its bit length
      // through an early-exit limb comparison.
      uint64_t borrow = 0;
      for (size_t index = 0; index < 8; ++index)
      {
        const uint64_t difference =
            static_cast<uint64_t>(out[index]) - kR[index] - borrow;
        borrow = (difference >> 63) & 1u;
      }
      return borrow != 0;
    }

    void scalar_write_bytes(uint8_t out[32], const uint32_t in[8])
    {
      for (size_t index = 0; index < 8; ++index)
      {
        uint8_t *tail = out + (7 - index) * 4;
        tail[0] = static_cast<uint8_t>(in[index] >> 24);
        tail[1] = static_cast<uint8_t>(in[index] >> 16);
        tail[2] = static_cast<uint8_t>(in[index] >> 8);
        tail[3] = static_cast<uint8_t>(in[index]);
      }
    }

    bool scalar_is_zero(const uint32_t value[8])
    {
      uint32_t combined = 0;
      for (size_t index = 0; index < 8; ++index)
        combined |= value[index];
      return combined == 0;
    }

    bool hkdf_expand_block(const uint8_t prk[32], const uint8_t *previous,
                           size_t previous_size, uint8_t counter, uint8_t out[32])
    {
      uint8_t input[32 + 3 + 1];
      size_t offset = 0;
      if (previous_size != 0)
      {
        memcpy(input, previous, previous_size);
        offset = previous_size;
      }
      input[offset++] = 0x00;
      input[offset++] = 0x30; // L = 48, big-endian
      input[offset++] = counter;
      const bool ok = crypto_hmac_sha256(prk, 32, input, offset, out);
      secure_zero(input, sizeof(input));
      return ok;
    }

  } // namespace

  // ------------------------- exported backend -----------------------------

  bool bls_scalar_reduce(const uint8_t *input, size_t size, uint8_t out[32])
  {
    if (out == nullptr)
      return false;
    if (input == nullptr || size == 0 || size > 256)
    {
      secure_zero(out, 32);
      return false;
    }
    uint32_t reduced[8];
    scalar_reduce_bytes(reduced, input, size);
    scalar_write_bytes(out, reduced);
    secure_zero(reduced, sizeof(reduced));
    return true;
  }

  bool bls_secret_add(const uint8_t secret[32], const uint8_t offset[32],
                      uint8_t out[32])
  {
    if (out == nullptr)
      return false;
    if (secret == nullptr || offset == nullptr)
    {
      secure_zero(out, 32);
      return false;
    }
    uint32_t key[8];
    uint32_t delta[8];
    if (!scalar_read_canonical(key, secret) || scalar_is_zero(key) ||
        !scalar_read_canonical(delta, offset))
    {
      secure_zero(out, 32);
      return false;
    }
    uint32_t sum[8];
    const uint64_t carry = scalar_add(sum, key, delta);
    scalar_reduce_once(sum, static_cast<uint32_t>(carry));
    const bool ok = !scalar_is_zero(sum);
    if (ok)
      scalar_write_bytes(out, sum);
    else
      secure_zero(out, 32);
    secure_zero(key, sizeof(key));
    secure_zero(delta, sizeof(delta));
    secure_zero(sum, sizeof(sum));
    return ok;
  }

  bool bls_keygen_v3(const uint8_t *ikm, size_t ikm_size, uint8_t out_sk[32])
  {
    if (out_sk == nullptr)
      return false;
    if (ikm == nullptr || ikm_size < 32 || ikm_size > 256)
    {
      secure_zero(out_sk, 32);
      return false;
    }
    static const uint8_t kSalt[] = "BLS-SIG-KEYGEN-SALT-";
    uint8_t salt_input[257];
    memcpy(salt_input, ikm, ikm_size);
    salt_input[ikm_size] = 0;
    uint8_t prk[32];
    bool ok = crypto_hmac_sha256(kSalt, sizeof(kSalt) - 1, salt_input,
                                 ikm_size + 1, prk);
    secure_zero(salt_input, sizeof(salt_input));
    if (!ok)
    {
      secure_zero(out_sk, 32);
      return false;
    }
    uint8_t first[32];
    uint8_t second[32];
    ok = hkdf_expand_block(prk, nullptr, 0, 1, first) &&
         hkdf_expand_block(prk, first, sizeof(first), 2, second);
    uint8_t okm[48];
    if (ok)
    {
      memcpy(okm, first, 32);
      memcpy(okm + 32, second, 16);
      uint32_t reduced[8];
      scalar_reduce_bytes(reduced, okm, sizeof(okm));
      ok = !scalar_is_zero(reduced);
      if (ok)
        scalar_write_bytes(out_sk, reduced);
      secure_zero(reduced, sizeof(reduced));
    }
    if (!ok)
      secure_zero(out_sk, 32);
    secure_zero(prk, sizeof(prk));
    secure_zero(first, sizeof(first));
    secure_zero(second, sizeof(second));
    secure_zero(okm, sizeof(okm));
    return ok;
  }

  bool bls12_381_g1_public_key(const uint8_t secret_key[32],
                               uint8_t out_compressed[48])
  {
    if (out_compressed == nullptr)
      return false;
    if (secret_key == nullptr)
    {
      secure_zero(out_compressed, 48);
      return false;
    }
    uint32_t scalar[8];
    if (!scalar_read_canonical(scalar, secret_key) || scalar_is_zero(scalar))
    {
      secure_zero(out_compressed, 48);
      return false;
    }
    G1Affine generator;
    fp_to_mont(generator.x, kG1x);
    fp_to_mont(generator.y, kG1y);
    generator.infinity = false;
    G1Jac base;
    g1_from_affine(base, generator);
    G1Jac result;
    g1_mul_bits(result, base, scalar, 256);
    if (g1_is_infinity(result))
    {
      secure_zero(out_compressed, 48);
      return false;
    }
    g1_compress(out_compressed, result);
    secure_zero(scalar, sizeof(scalar));
    return true;
  }

  bool bls12_381_g1_add_generator(const uint8_t point[48],
                                  const uint8_t secret_offset[32],
                                  uint8_t out_compressed[48])
  {
    if (out_compressed == nullptr)
      return false;
    if (point == nullptr || secret_offset == nullptr)
    {
      secure_zero(out_compressed, 48);
      return false;
    }
    uint32_t offset[8];
    G1Affine base;
    if (!scalar_read_canonical(offset, secret_offset) ||
        !g1_decompress(base, point) || base.infinity)
    {
      secure_zero(out_compressed, 48);
      return false;
    }
    G1Jac base_jacobian;
    g1_from_affine(base_jacobian, base);
    // Subgroup check: r * P must be the identity. G1 has a cofactor, so an
    // on-curve point is not automatically a member of the signing subgroup.
    G1Jac subgroup;
    g1_mul_bits(subgroup, base_jacobian, kR, 256);
    if (!g1_is_infinity(subgroup))
    {
      secure_zero(out_compressed, 48);
      return false;
    }
    const G1Affine generator_affine = []
    {
      G1Affine value;
      fp_to_mont(value.x, kG1x);
      fp_to_mont(value.y, kG1y);
      value.infinity = false;
      return value;
    }();
    G1Jac generator;
    g1_from_affine(generator, generator_affine);
    G1Jac delta;
    g1_mul_bits(delta, generator, offset, 256);
    G1Jac sum;
    g1_add(sum, base_jacobian, delta);
    if (g1_is_infinity(sum))
    {
      secure_zero(out_compressed, 48);
      return false;
    }
    g1_compress(out_compressed, sum);
    secure_zero(offset, sizeof(offset));
    return true;
  }

  bool bls_g2_hash_to_curve(const uint8_t *message, size_t message_size,
                            const char *dst, uint8_t out_compressed[96])
  {
    if (out_compressed == nullptr)
      return false;
    if (dst == nullptr || (message == nullptr && message_size != 0))
    {
      secure_zero(out_compressed, 96);
      return false;
    }
    G2Jac point;
    if (!hash_to_g2(point, message, message_size, dst))
    {
      secure_zero(out_compressed, 96);
      return false;
    }
    g2_compress(out_compressed, point);
    return true;
  }

  bool bls_g2_sign_augmented(const uint8_t secret_key[32],
                             const uint8_t *augmentation,
                             size_t augmentation_size,
                             const uint8_t *message, size_t message_size,
                             const char *dst, uint8_t out_compressed[96])
  {
    if (out_compressed == nullptr)
      return false;
    if (secret_key == nullptr || dst == nullptr ||
        (augmentation == nullptr && augmentation_size != 0) ||
        (message == nullptr && message_size != 0))
    {
      secure_zero(out_compressed, 96);
      return false;
    }
    uint32_t scalar[8];
    if (!scalar_read_canonical(scalar, secret_key) || scalar_is_zero(scalar))
    {
      secure_zero(out_compressed, 96);
      return false;
    }
    const size_t total = augmentation_size + message_size;
    uint8_t *joined = nullptr;
    if (total != 0)
    {
      joined = static_cast<uint8_t *>(malloc(total));
      if (joined == nullptr)
      {
        secure_zero(out_compressed, 96);
        return false;
      }
      if (augmentation_size != 0)
      {
        memcpy(joined, augmentation, augmentation_size);
      }
      if (message_size != 0)
      {
        memcpy(joined + augmentation_size, message, message_size);
      }
    }
    G2Jac hashed;
    const bool hashed_ok = hash_to_g2(hashed, joined, total, dst);
    if (joined != nullptr)
    {
      secure_zero(joined, total);
      free(joined);
    }
    if (!hashed_ok)
    {
      secure_zero(out_compressed, 96);
      return false;
    }
    G2Jac signature;
    g2_mul_bits(signature, hashed, scalar, 256);
    if (g2_is_infinity(signature))
    {
      secure_zero(out_compressed, 96);
      return false;
    }
    g2_compress(out_compressed, signature);
    secure_zero(scalar, sizeof(scalar));
    return true;
  }

  bool bls_g2_aggregate(const uint8_t **signatures, size_t count,
                        uint8_t out_compressed[96])
  {
    if (out_compressed == nullptr)
      return false;
    if (signatures == nullptr || count == 0)
    {
      secure_zero(out_compressed, 96);
      return false;
    }
    G2Jac accumulator;
    g2_infinity(accumulator);
    bool ok = true;
    for (size_t index = 0; index < count && ok; ++index)
    {
      if (signatures[index] == nullptr)
      {
        ok = false;
        break;
      }
      G2Affine point;
      if (!g2_decompress(point, signatures[index]))
      {
        ok = false;
        break;
      }
      if (point.infinity)
        continue; // the canonical identity
      G2Jac jacobian;
      g2_from_affine(jacobian, point);
      G2Jac subgroup;
      g2_mul_bits(subgroup, jacobian, kR, 256);
      if (!g2_is_infinity(subgroup))
      {
        ok = false;
        break;
      }
      G2Jac next;
      g2_add(next, accumulator, jacobian);
      accumulator = next;
    }
    if (!ok)
    {
      secure_zero(out_compressed, 96);
      return false;
    }
    g2_compress(out_compressed, accumulator);
    return true;
  }

} // namespace hexwallet
