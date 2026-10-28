#include "BlsG2.h"

#include <mbedtls/bignum.h>
#include <stdio.h>
#include <string.h>

#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet
{
namespace
{

const char kFieldPrime[] =
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241ea"
    "bfffeb153ffffb9feffffffffaaab";

// Effective cofactor for G2 (RFC 9380 section 8.8.2).
const char kG2EffectiveCofactor[] =
    "bc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2"
    "f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0ade"
    "bbf6b4e8020005aaa95551";

struct IsogenyConstant
{
  const char *c0;
  const char *c1;
};

// 3-isogeny from E' to E (RFC 9380 appendix E.3), stored as (c0, c1).
const IsogenyConstant kIsogenyXNumerator[4] = {
    {"171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1",
     "0"},
    {"11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e",
     "8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d"},
    {"0",
     "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a"},
    {"5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
     "5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6"},
};

const IsogenyConstant kIsogenyXDenominator[2] = {
    {"c",
     "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f"},
    {"0",
     "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63"},
};

const IsogenyConstant kIsogenyYNumerator[4] = {
    {"124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10",
     "0"},
    {"11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c",
     "8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f"},
    {"0",
     "5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be"},
    {"1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
     "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706"},
};

const IsogenyConstant kIsogenyYDenominator[3] = {
    {"12",
     "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99"},
    {"0",
     "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3"},
    {"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
     "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"},
};

constexpr const char kAugmentedDst[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";

bool g_ready = false;
mbedtls_mpi g_prime;
mbedtls_mpi g_cofactor;

bool bls_ready()
{
  if (g_ready) return true;
  mbedtls_mpi_init(&g_prime);
  mbedtls_mpi_init(&g_cofactor);
  g_ready = mbedtls_mpi_read_string(&g_prime, 16, kFieldPrime) == 0 &&
            mbedtls_mpi_read_string(&g_cofactor, 16, kG2EffectiveCofactor) == 0;
  return g_ready;
}

struct F2
{
  mbedtls_mpi c0;
  mbedtls_mpi c1;
};

struct Affine
{
  F2 x;
  F2 y;
  bool infinity;
};

struct Jacobian
{
  F2 x;
  F2 y;
  F2 z;
};

void f2_init(F2 *value)
{
  mbedtls_mpi_init(&value->c0);
  mbedtls_mpi_init(&value->c1);
}

void f2_free(F2 *value)
{
  mbedtls_mpi_free(&value->c0);
  mbedtls_mpi_free(&value->c1);
}

bool f2_set(F2 *out, const F2 *in)
{
  return mbedtls_mpi_copy(&out->c0, &in->c0) == 0 &&
         mbedtls_mpi_copy(&out->c1, &in->c1) == 0;
}

void f2_zero(F2 *value)
{
  mbedtls_mpi_lset(&value->c0, 0);
  mbedtls_mpi_lset(&value->c1, 0);
}

bool f2_set_small(F2 *value, int c0, int c1)
{
  return mbedtls_mpi_lset(&value->c0, c0) == 0 &&
         mbedtls_mpi_lset(&value->c1, c1) == 0;
}

bool f2_from_hex(F2 *value, const char *c0, const char *c1)
{
  return mbedtls_mpi_read_string(&value->c0, 16, c0) == 0 &&
         mbedtls_mpi_read_string(&value->c1, 16, c1) == 0 &&
         mbedtls_mpi_mod_mpi(&value->c0, &value->c0, &g_prime) == 0 &&
         mbedtls_mpi_mod_mpi(&value->c1, &value->c1, &g_prime) == 0;
}

bool f2_is_zero(const F2 *value)
{
  return mbedtls_mpi_cmp_int(&value->c0, 0) == 0 &&
         mbedtls_mpi_cmp_int(&value->c1, 0) == 0;
}

bool f2_eq(const F2 *left, const F2 *right)
{
  return mbedtls_mpi_cmp_mpi(&left->c0, &right->c0) == 0 &&
         mbedtls_mpi_cmp_mpi(&left->c1, &right->c1) == 0;
}

bool field_sub_small(mbedtls_mpi *out, const mbedtls_mpi *value, unsigned int amount)
{
  mbedtls_mpi delta, reference;
  mbedtls_mpi_init(&delta);
  mbedtls_mpi_init(&reference);
  const bool ok = mbedtls_mpi_lset(&delta, static_cast<mbedtls_mpi_sint>(amount)) == 0 &&
                  mbedtls_mpi_sub_mpi(out, value, &delta) == 0;
  mbedtls_mpi_free(&delta);
  mbedtls_mpi_free(&reference);
  return ok;
}

bool field_add_small(mbedtls_mpi *out, const mbedtls_mpi *value, unsigned int amount)
{
  mbedtls_mpi delta;
  mbedtls_mpi_init(&delta);
  const bool ok = mbedtls_mpi_lset(&delta, static_cast<mbedtls_mpi_sint>(amount)) == 0 &&
                  mbedtls_mpi_add_mpi(out, value, &delta) == 0;
  mbedtls_mpi_free(&delta);
  return ok;
}

bool field_add(mbedtls_mpi *out, const mbedtls_mpi *left, const mbedtls_mpi *right)
{
  mbedtls_mpi sum;
  mbedtls_mpi_init(&sum);
  const bool ok = mbedtls_mpi_add_mpi(&sum, left, right) == 0 &&
                  mbedtls_mpi_mod_mpi(out, &sum, &g_prime) == 0;
  mbedtls_mpi_free(&sum);
  return ok;
}

bool field_sub(mbedtls_mpi *out, const mbedtls_mpi *left, const mbedtls_mpi *right)
{
  mbedtls_mpi difference;
  mbedtls_mpi_init(&difference);
  const bool ok = mbedtls_mpi_sub_mpi(&difference, left, right) == 0 &&
                  mbedtls_mpi_mod_mpi(out, &difference, &g_prime) == 0;
  mbedtls_mpi_free(&difference);
  return ok;
}

bool field_mul(mbedtls_mpi *out, const mbedtls_mpi *left, const mbedtls_mpi *right)
{
  mbedtls_mpi product;
  mbedtls_mpi_init(&product);
  const bool ok = mbedtls_mpi_mul_mpi(&product, left, right) == 0 &&
                  mbedtls_mpi_mod_mpi(out, &product, &g_prime) == 0;
  mbedtls_mpi_free(&product);
  return ok;
}

bool field_neg(mbedtls_mpi *out, const mbedtls_mpi *value)
{
  mbedtls_mpi difference;
  mbedtls_mpi_init(&difference);
  const bool ok = mbedtls_mpi_sub_mpi(&difference, &g_prime, value) == 0 &&
                  mbedtls_mpi_mod_mpi(out, &difference, &g_prime) == 0;
  mbedtls_mpi_free(&difference);
  return ok;
}

bool field_inv(mbedtls_mpi *out, const mbedtls_mpi *value)
{
  if (mbedtls_mpi_cmp_int(value, 0) == 0) return false;
  mbedtls_mpi exponent;
  mbedtls_mpi_init(&exponent);
  const bool ok = field_sub_small(&exponent, &g_prime, 2) &&
                  mbedtls_mpi_exp_mod(out, value, &exponent, &g_prime,
                                      nullptr) == 0;
  mbedtls_mpi_free(&exponent);
  return ok;
}

bool field_is_zero(const mbedtls_mpi *value)
{
  return mbedtls_mpi_cmp_int(value, 0) == 0;
}

bool field_is_square(const mbedtls_mpi *value)
{
  if (field_is_zero(value)) return true;
  mbedtls_mpi exponent, result;
  mbedtls_mpi_init(&exponent);
  mbedtls_mpi_init(&result);
  const bool ok =
      mbedtls_mpi_copy(&exponent, &g_prime) == 0 &&
      field_sub_small(&exponent, &exponent, 1) &&
      mbedtls_mpi_shift_r(&exponent, 1) == 0 &&
      mbedtls_mpi_exp_mod(&result, value, &exponent, &g_prime, nullptr) == 0;
  const bool square = ok && mbedtls_mpi_cmp_int(&result, 1) == 0;
  mbedtls_mpi_free(&exponent);
  mbedtls_mpi_free(&result);
  return square;
}

bool field_sqrt(mbedtls_mpi *out, const mbedtls_mpi *value)
{
  if (field_is_zero(value)) return mbedtls_mpi_lset(out, 0) == 0;
  mbedtls_mpi exponent, root, check;
  mbedtls_mpi_init(&exponent);
  mbedtls_mpi_init(&root);
  mbedtls_mpi_init(&check);
  bool ok = mbedtls_mpi_copy(&exponent, &g_prime) == 0 &&
            field_add_small(&exponent, &exponent, 1) &&
            mbedtls_mpi_shift_r(&exponent, 2) == 0 &&
            mbedtls_mpi_exp_mod(&root, value, &exponent, &g_prime, nullptr) == 0;
  if (ok)
  {
    ok = mbedtls_mpi_mul_mpi(&check, &root, &root) == 0 &&
         mbedtls_mpi_mod_mpi(&check, &check, &g_prime) == 0 &&
         mbedtls_mpi_cmp_mpi(&check, value) == 0 &&
         mbedtls_mpi_copy(out, &root) == 0;
  }
  mbedtls_mpi_free(&exponent);
  mbedtls_mpi_free(&root);
  mbedtls_mpi_free(&check);
  return ok;
}

bool f2_add(F2 *out, const F2 *left, const F2 *right)
{
  return field_add(&out->c0, &left->c0, &right->c0) &&
         field_add(&out->c1, &left->c1, &right->c1);
}

bool f2_sub(F2 *out, const F2 *left, const F2 *right)
{
  return field_sub(&out->c0, &left->c0, &right->c0) &&
         field_sub(&out->c1, &left->c1, &right->c1);
}

bool f2_neg(F2 *out, const F2 *value)
{
  return field_neg(&out->c0, &value->c0) && field_neg(&out->c1, &value->c1);
}

bool f2_mul(F2 *out, const F2 *left, const F2 *right)
{
  mbedtls_mpi ac, bd, ad, bc;
  mbedtls_mpi_init(&ac);
  mbedtls_mpi_init(&bd);
  mbedtls_mpi_init(&ad);
  mbedtls_mpi_init(&bc);
  const bool ok = field_mul(&ac, &left->c0, &right->c0) &&
                  field_mul(&bd, &left->c1, &right->c1) &&
                  field_mul(&ad, &left->c0, &right->c1) &&
                  field_mul(&bc, &left->c1, &right->c0) &&
                  field_sub(&out->c0, &ac, &bd) &&
                  field_add(&out->c1, &ad, &bc);
  mbedtls_mpi_free(&ac);
  mbedtls_mpi_free(&bd);
  mbedtls_mpi_free(&ad);
  mbedtls_mpi_free(&bc);
  return ok;
}

bool f2_sqr(F2 *out, const F2 *value)
{
  return f2_mul(out, value, value);
}

bool f2_inv(F2 *out, const F2 *value)
{
  if (f2_is_zero(value)) return false;
  mbedtls_mpi norm, c1_squared, inverse;
  mbedtls_mpi_init(&norm);
  mbedtls_mpi_init(&c1_squared);
  mbedtls_mpi_init(&inverse);
  const bool ok = field_mul(&norm, &value->c0, &value->c0) &&
                  field_mul(&c1_squared, &value->c1, &value->c1) &&
                  field_add(&norm, &norm, &c1_squared) &&
                  field_inv(&inverse, &norm) &&
                  field_mul(&out->c0, &value->c0, &inverse) &&
                  field_mul(&out->c1, &value->c1, &inverse) &&
                  field_neg(&out->c1, &out->c1);
  mbedtls_mpi_free(&norm);
  mbedtls_mpi_free(&c1_squared);
  mbedtls_mpi_free(&inverse);
  return ok;
}

bool f2_mul_small(F2 *out, const F2 *value, int scalar)
{
  mbedtls_mpi factor;
  mbedtls_mpi_init(&factor);
  const bool ok = mbedtls_mpi_lset(&factor, scalar) == 0 &&
                  field_mul(&out->c0, &value->c0, &factor) &&
                  field_mul(&out->c1, &value->c1, &factor);
  mbedtls_mpi_free(&factor);
  return ok;
}

int f2_sgn0(const F2 *value)
{
  if (!field_is_zero(&value->c0)) return mbedtls_mpi_get_bit(&value->c0, 0);
  return mbedtls_mpi_get_bit(&value->c1, 0);
}

bool f2_is_square(const F2 *value)
{
  mbedtls_mpi norm, c1_squared;
  mbedtls_mpi_init(&norm);
  mbedtls_mpi_init(&c1_squared);
  const bool ok = field_mul(&norm, &value->c0, &value->c0) &&
                  field_mul(&c1_squared, &value->c1, &value->c1) &&
                  field_add(&norm, &norm, &c1_squared) &&
                  field_is_square(&norm);
  mbedtls_mpi_free(&norm);
  mbedtls_mpi_free(&c1_squared);
  return ok;
}

// Complex square root for p == 3 (mod 4).
bool f2_sqrt(F2 *out, const F2 *value, bool allow_imaginary)
{
  if (f2_is_zero(value))
  {
    f2_zero(out);
    return true;
  }
  mbedtls_mpi half;
  mbedtls_mpi_init(&half);
  bool ok = mbedtls_mpi_lset(&half, 2) == 0 && field_inv(&half, &half);
  if (!ok)
  {
    mbedtls_mpi_free(&half);
    return false;
  }

  if (field_is_zero(&value->c1))
  {
    mbedtls_mpi root;
    mbedtls_mpi_init(&root);
    if (field_sqrt(&root, &value->c0))
    {
      f2_zero(out);
      ok = mbedtls_mpi_copy(&out->c0, &root) == 0;
    }
    else if (allow_imaginary)
    {
      mbedtls_mpi negated;
      mbedtls_mpi_init(&negated);
      ok = field_neg(&negated, &value->c0) && field_sqrt(&root, &negated);
      if (ok)
      {
        f2_zero(out);
        ok = mbedtls_mpi_copy(&out->c1, &root) == 0;
      }
      mbedtls_mpi_free(&negated);
    }
    else
    {
      ok = false;
    }
    mbedtls_mpi_free(&root);
    mbedtls_mpi_free(&half);
    return ok;
  }

  mbedtls_mpi norm, c1_squared, root;
  mbedtls_mpi_init(&norm);
  mbedtls_mpi_init(&c1_squared);
  mbedtls_mpi_init(&root);
  ok = field_mul(&norm, &value->c0, &value->c0) &&
       field_mul(&c1_squared, &value->c1, &value->c1) &&
       field_add(&norm, &norm, &c1_squared) && field_sqrt(&root, &norm);
  mbedtls_mpi_free(&norm);
  mbedtls_mpi_free(&c1_squared);
  if (!ok)
  {
    mbedtls_mpi_free(&root);
    mbedtls_mpi_free(&half);
    return false;
  }

  mbedtls_mpi delta;
  mbedtls_mpi_init(&delta);
  ok = field_add(&delta, &value->c0, &root) &&
       field_mul(&delta, &delta, &half);
  if (ok && !field_is_square(&delta))
  {
    ok = field_sub(&delta, &value->c0, &root) &&
         field_mul(&delta, &delta, &half);
  }
  if (ok) ok = field_sqrt(&delta, &delta);
  if (ok)
  {
    mbedtls_mpi twice, inverse;
    mbedtls_mpi_init(&twice);
    mbedtls_mpi_init(&inverse);
    ok = mbedtls_mpi_copy(&twice, &delta) == 0 &&
         field_add(&twice, &delta, &delta) && field_inv(&inverse, &twice) &&
         field_mul(&out->c1, &value->c1, &inverse) &&
         mbedtls_mpi_copy(&out->c0, &delta) == 0;
    mbedtls_mpi_free(&twice);
    mbedtls_mpi_free(&inverse);
  }
  mbedtls_mpi_free(&delta);
  mbedtls_mpi_free(&root);
  mbedtls_mpi_free(&half);
  return ok;
}

// ---------------------------------------------------------------------------
// Curve constants.
// ---------------------------------------------------------------------------

struct CurveConstants
{
  F2 a_prime;   // A' = 240i
  F2 b_prime;   // B' = 1012(1+i)
  F2 z;         // Z = -(2+i)
  F2 b_curve;   // B  = 4(1+i)
  F2 minus_b_over_a;
  F2 kx_num[4];
  F2 kx_den[2];
  F2 ky_num[4];
  F2 ky_den[3];
  mbedtls_mpi half;  // (p-1)/2
  bool ready;
};

CurveConstants g_curve = {};

bool curve_ready()
{
  if (g_curve.ready) return true;
  if (!bls_ready()) return false;
  for (size_t i = 0; i < 4; ++i)
  {
    f2_init(&g_curve.kx_num[i]);
    f2_init(&g_curve.ky_num[i]);
  }
  for (size_t i = 0; i < 2; ++i) f2_init(&g_curve.kx_den[i]);
  for (size_t i = 0; i < 3; ++i) f2_init(&g_curve.ky_den[i]);
  f2_init(&g_curve.a_prime);
  f2_init(&g_curve.b_prime);
  f2_init(&g_curve.z);
  f2_init(&g_curve.b_curve);
  f2_init(&g_curve.minus_b_over_a);
  mbedtls_mpi_init(&g_curve.half);

  mbedtls_mpi two, one;
  mbedtls_mpi_init(&two);
  mbedtls_mpi_init(&one);
  bool ok = f2_set_small(&g_curve.a_prime, 0, 240) &&
            f2_set_small(&g_curve.b_prime, 1012, 1012) &&
            f2_set_small(&g_curve.b_curve, 4, 4) &&
            mbedtls_mpi_lset(&two, 2) == 0 && mbedtls_mpi_lset(&one, 1) == 0 &&
            field_neg(&two, &two) && field_neg(&one, &one) &&
            f2_set_small(&g_curve.z, 0, 0) &&
            mbedtls_mpi_copy(&g_curve.z.c0, &two) == 0 &&
            mbedtls_mpi_copy(&g_curve.z.c1, &one) == 0;
  mbedtls_mpi_free(&two);
  mbedtls_mpi_free(&one);
  if (!ok) return false;

  for (size_t i = 0; i < 4; ++i)
  {
    ok = f2_from_hex(&g_curve.kx_num[i], kIsogenyXNumerator[i].c0,
                     kIsogenyXNumerator[i].c1) &&
         f2_from_hex(&g_curve.ky_num[i], kIsogenyYNumerator[i].c0,
                     kIsogenyYNumerator[i].c1);
    if (!ok) return false;
  }
  for (size_t i = 0; i < 2; ++i)
  {
    ok = f2_from_hex(&g_curve.kx_den[i], kIsogenyXDenominator[i].c0,
                     kIsogenyXDenominator[i].c1);
    if (!ok) return false;
  }
  for (size_t i = 0; i < 3; ++i)
  {
    ok = f2_from_hex(&g_curve.ky_den[i], kIsogenyYDenominator[i].c0,
                     kIsogenyYDenominator[i].c1);
    if (!ok) return false;
  }
  ok = mbedtls_mpi_copy(&g_curve.half, &g_prime) == 0 &&
       field_sub_small(&g_curve.half, &g_curve.half, 1) &&
       mbedtls_mpi_shift_r(&g_curve.half, 1) == 0;
  if (!ok) return false;

  F2 a_inverse;
  f2_init(&a_inverse);
  ok = f2_inv(&a_inverse, &g_curve.a_prime) &&
       f2_neg(&a_inverse, &a_inverse) &&
       f2_mul(&g_curve.minus_b_over_a, &g_curve.b_prime, &a_inverse);
  f2_free(&a_inverse);

  g_curve.ready = ok;
  return g_curve.ready;
}

// ---------------------------------------------------------------------------
// Affine points on y^2 = x^3 + a*x + b, used for E' before the isogeny.
// ---------------------------------------------------------------------------

void affine_init(Affine *point)
{
  f2_init(&point->x);
  f2_init(&point->y);
  point->infinity = true;
}

void affine_free(Affine *point)
{
  f2_free(&point->x);
  f2_free(&point->y);
}

void affine_set_infinity(Affine *point)
{
  f2_zero(&point->x);
  f2_zero(&point->y);
  point->infinity = true;
}

bool affine_copy(Affine *out, const Affine *in)
{
  out->infinity = in->infinity;
  return f2_set(&out->x, &in->x) && f2_set(&out->y, &in->y);
}

bool affine_double(Affine *out, const Affine *in, const F2 *a)
{
  if (in->infinity) return (affine_set_infinity(out), true);
  if (f2_is_zero(&in->y)) return (affine_set_infinity(out), true);

  F2 numerator, denominator, lambda, x3, t;
  f2_init(&numerator);
  f2_init(&denominator);
  f2_init(&lambda);
  f2_init(&x3);
  f2_init(&t);
  bool ok = f2_sqr(&numerator, &in->x) && f2_mul_small(&numerator, &numerator, 3);
  if (ok && !f2_is_zero(a)) ok = f2_add(&numerator, &numerator, a);
  if (ok) ok = f2_mul_small(&denominator, &in->y, 2);
  if (ok) ok = f2_inv(&denominator, &denominator);
  if (ok) ok = f2_mul(&lambda, &numerator, &denominator);
  if (ok) ok = f2_sqr(&x3, &lambda) && f2_mul_small(&t, &in->x, 2) &&
               f2_sub(&x3, &x3, &t);
  if (ok)
  {
    out->infinity = false;
    ok = f2_set(&out->x, &x3) &&
         f2_sub(&t, &in->x, &x3) && f2_mul(&t, &lambda, &t) &&
         f2_sub(&out->y, &t, &in->y);
  }
  f2_free(&numerator);
  f2_free(&denominator);
  f2_free(&lambda);
  f2_free(&x3);
  f2_free(&t);
  return ok;
}

bool affine_add(Affine *out, const Affine *left, const Affine *right,
                const F2 *a)
{
  if (left->infinity) return affine_copy(out, right);
  if (right->infinity) return affine_copy(out, left);
  if (f2_eq(&left->x, &right->x))
  {
    if (f2_eq(&left->y, &right->y)) return affine_double(out, left, a);
    affine_set_infinity(out);
    return true;
  }
  F2 lambda, x3, t;
  f2_init(&lambda);
  f2_init(&x3);
  f2_init(&t);
  bool ok = f2_sub(&lambda, &right->y, &left->y) &&
            f2_sub(&t, &right->x, &left->x) && f2_inv(&t, &t) &&
            f2_mul(&lambda, &lambda, &t);
  if (ok) ok = f2_sqr(&x3, &lambda) && f2_sub(&x3, &x3, &left->x) &&
               f2_sub(&x3, &x3, &right->x);
  if (ok)
  {
    out->infinity = false;
    ok = f2_set(&out->x, &x3) && f2_sub(&t, &left->x, &x3) &&
         f2_mul(&t, &lambda, &t) && f2_sub(&out->y, &t, &left->y);
  }
  f2_free(&lambda);
  f2_free(&x3);
  f2_free(&t);
  return ok;
}

// ---------------------------------------------------------------------------
// Jacobian points on E: y^2 = x^3 + B.
// ---------------------------------------------------------------------------

void jacobian_init(Jacobian *point)
{
  f2_init(&point->x);
  f2_init(&point->y);
  f2_init(&point->z);
}

void jacobian_free(Jacobian *point)
{
  f2_free(&point->x);
  f2_free(&point->y);
  f2_free(&point->z);
}

void jacobian_set_infinity(Jacobian *point)
{
  f2_zero(&point->x);
  f2_zero(&point->y);
  f2_zero(&point->z);
}

void jacobian_from_affine(Jacobian *out, const Affine *in)
{
  if (in->infinity)
  {
    jacobian_set_infinity(out);
    return;
  }
  f2_set(&out->x, &in->x);
  f2_set(&out->y, &in->y);
  f2_set_small(&out->z, 1, 0);
}

bool jacobian_to_affine(Affine *out, const Jacobian *in)
{
  if (f2_is_zero(&in->z))
  {
    affine_set_infinity(out);
    return true;
  }
  F2 z_inverse, z_inverse2, t;
  f2_init(&z_inverse);
  f2_init(&z_inverse2);
  f2_init(&t);
  bool ok = f2_inv(&z_inverse, &in->z) && f2_sqr(&z_inverse2, &z_inverse);
  if (ok) ok = f2_mul(&out->x, &in->x, &z_inverse2);
  if (ok)
  {
    ok = f2_mul(&t, &z_inverse2, &z_inverse) &&
         f2_mul(&out->y, &in->y, &t);
    out->infinity = false;
  }
  f2_free(&z_inverse);
  f2_free(&z_inverse2);
  f2_free(&t);
  return ok;
}

bool jacobian_double(Jacobian *out, const Jacobian *in)
{
  if (f2_is_zero(&in->z) || f2_is_zero(&in->y))
  {
    jacobian_set_infinity(out);
    return true;
  }
  F2 a, b, c, d, e, f, x3, y3, z3, t;
  f2_init(&a);
  f2_init(&b);
  f2_init(&c);
  f2_init(&d);
  f2_init(&e);
  f2_init(&f);
  f2_init(&x3);
  f2_init(&y3);
  f2_init(&z3);
  f2_init(&t);
  bool ok = f2_sqr(&a, &in->x) && f2_sqr(&b, &in->y) && f2_sqr(&c, &b);
  if (ok) ok = f2_add(&d, &in->x, &b) && f2_sqr(&d, &d) && f2_sub(&d, &d, &a) &&
               f2_sub(&d, &d, &c) && f2_mul_small(&d, &d, 2);
  if (ok) ok = f2_mul_small(&e, &a, 3) && f2_sqr(&f, &e);
  if (ok) ok = f2_mul_small(&t, &d, 2) && f2_sub(&x3, &f, &t);
  if (ok) ok = f2_sub(&t, &d, &x3) && f2_mul(&y3, &e, &t) &&
               f2_mul_small(&c, &c, 8) && f2_sub(&y3, &y3, &c);
  if (ok) ok = f2_mul(&z3, &in->y, &in->z) && f2_mul_small(&z3, &z3, 2);
  if (ok)
  {
    ok = f2_set(&out->x, &x3) && f2_set(&out->y, &y3) && f2_set(&out->z, &z3);
  }
  f2_free(&a);
  f2_free(&b);
  f2_free(&c);
  f2_free(&d);
  f2_free(&e);
  f2_free(&f);
  f2_free(&x3);
  f2_free(&y3);
  f2_free(&z3);
  f2_free(&t);
  return ok;
}

bool jacobian_add_affine(Jacobian *out, const Jacobian *in, const Affine *base)
{
  if (base->infinity)
  {
    return f2_set(&out->x, &in->x) && f2_set(&out->y, &in->y) &&
           f2_set(&out->z, &in->z);
  }
  if (f2_is_zero(&in->z))
  {
    jacobian_from_affine(out, base);
    return true;
  }
  F2 z1z1, u2, s2, h, rr, hh, hhh, v, x3, y3, z3, t;
  f2_init(&z1z1);
  f2_init(&u2);
  f2_init(&s2);
  f2_init(&h);
  f2_init(&rr);
  f2_init(&hh);
  f2_init(&hhh);
  f2_init(&v);
  f2_init(&x3);
  f2_init(&y3);
  f2_init(&z3);
  f2_init(&t);
  bool ok = f2_sqr(&z1z1, &in->z) && f2_mul(&u2, &base->x, &z1z1) &&
            f2_mul(&s2, &base->y, &in->z) && f2_mul(&s2, &s2, &z1z1);
  if (ok) ok = f2_sub(&h, &u2, &in->x);
  if (ok)
  {
    const bool h_zero = f2_is_zero(&h);
    ok = f2_sub(&rr, &s2, &in->y);
    if (ok && h_zero)
    {
      if (f2_is_zero(&rr))
      {
        ok = jacobian_double(out, in);
        f2_free(&z1z1);
        f2_free(&u2);
        f2_free(&s2);
        f2_free(&h);
        f2_free(&rr);
        f2_free(&hh);
        f2_free(&hhh);
        f2_free(&v);
        f2_free(&x3);
        f2_free(&y3);
        f2_free(&z3);
        f2_free(&t);
        return ok;
      }
      jacobian_set_infinity(out);
      f2_free(&z1z1);
      f2_free(&u2);
      f2_free(&s2);
      f2_free(&h);
      f2_free(&rr);
      f2_free(&hh);
      f2_free(&hhh);
      f2_free(&v);
      f2_free(&x3);
      f2_free(&y3);
      f2_free(&z3);
      f2_free(&t);
      return true;
    }
  }
  if (ok) ok = f2_sqr(&hh, &h) && f2_mul(&hhh, &h, &hh) && f2_mul(&v, &in->x, &hh);
  if (ok) ok = f2_sqr(&x3, &rr) && f2_sub(&x3, &x3, &hhh) &&
               f2_mul_small(&t, &v, 2) && f2_sub(&x3, &x3, &t);
  if (ok) ok = f2_sub(&t, &v, &x3) && f2_mul(&y3, &rr, &t) &&
               f2_mul(&t, &in->y, &hhh) && f2_sub(&y3, &y3, &t);
  if (ok) ok = f2_mul(&z3, &in->z, &h);
  if (ok)
  {
    ok = f2_set(&out->x, &x3) && f2_set(&out->y, &y3) && f2_set(&out->z, &z3);
  }
  f2_free(&z1z1);
  f2_free(&u2);
  f2_free(&s2);
  f2_free(&h);
  f2_free(&rr);
  f2_free(&hh);
  f2_free(&hhh);
  f2_free(&v);
  f2_free(&x3);
  f2_free(&y3);
  f2_free(&z3);
  f2_free(&t);
  return ok;
}

bool jacobian_scalar_mul(Jacobian *out, const Affine *base,
                         const mbedtls_mpi *scalar)
{
  Jacobian accumulator;
  jacobian_init(&accumulator);
  jacobian_set_infinity(&accumulator);
  const size_t bits = mbedtls_mpi_bitlen(scalar);
  bool ok = true;
  for (size_t i = bits; i-- > 0 && ok;)
  {
    ok = jacobian_double(&accumulator, &accumulator);
    if (ok && mbedtls_mpi_get_bit(scalar, i))
    {
      ok = jacobian_add_affine(&accumulator, &accumulator, base);
    }
  }
  if (ok)
  {
    ok = f2_set(&out->x, &accumulator.x) &&
         f2_set(&out->y, &accumulator.y) && f2_set(&out->z, &accumulator.z);
  }
  jacobian_free(&accumulator);
  return ok;
}

// ---------------------------------------------------------------------------
// Hash to curve.
// ---------------------------------------------------------------------------

bool gx_eprime(F2 *out, const F2 *x)
{
  F2 cube, linear;
  f2_init(&cube);
  f2_init(&linear);
  bool ok = f2_sqr(&cube, x) && f2_mul(&cube, &cube, x) &&
            f2_mul(&linear, &g_curve.a_prime, x) &&
            f2_add(&cube, &cube, &linear) &&
            f2_add(out, &cube, &g_curve.b_prime);
  f2_free(&cube);
  f2_free(&linear);
  return ok;
}

bool gx_curve(F2 *out, const F2 *x)
{
  F2 cube;
  f2_init(&cube);
  bool ok = f2_sqr(&cube, x) && f2_mul(&cube, &cube, x) &&
            f2_add(out, &cube, &g_curve.b_curve);
  f2_free(&cube);
  return ok;
}

bool map_to_curve_simple_swu(Affine *out, const F2 *u)
{
  F2 t, tv2, inverse, one, x1, gx1, x2, gx2, y;
  f2_init(&t);
  f2_init(&tv2);
  f2_init(&inverse);
  f2_init(&one);
  f2_init(&x1);
  f2_init(&gx1);
  f2_init(&x2);
  f2_init(&gx2);
  f2_init(&y);
  bool ok = f2_set_small(&one, 1, 0) && f2_sqr(&t, u) &&
            f2_mul(&t, &t, &g_curve.z);
  if (ok) ok = f2_sqr(&tv2, &t) && f2_add(&tv2, &tv2, &t);
  if (ok)
  {
    if (f2_is_zero(&tv2))
    {
      f2_zero(&inverse);
    }
    else
    {
      ok = f2_inv(&inverse, &tv2);
    }
  }
  if (ok) ok = f2_add(&x1, &one, &inverse) &&
               f2_mul(&x1, &x1, &g_curve.minus_b_over_a);
  if (ok && f2_is_zero(&inverse))
  {
    F2 denominator;
    f2_init(&denominator);
    ok = f2_mul(&denominator, &g_curve.z, &g_curve.a_prime) &&
         f2_inv(&denominator, &denominator) &&
         f2_mul(&x1, &g_curve.b_prime, &denominator);
    f2_free(&denominator);
  }
  if (ok) ok = gx_eprime(&gx1, &x1);
  if (ok) ok = f2_mul(&x2, &t, &x1) && gx_eprime(&gx2, &x2);
  if (ok)
  {
    const bool first = f2_is_square(&gx1);
    ok = f2_sqrt(&y, first ? &gx1 : &gx2, true);
    if (ok)
    {
      out->infinity = false;
      ok = f2_set(&out->x, first ? &x1 : &x2) && f2_set(&out->y, &y);
      if (ok && f2_sgn0(u) != f2_sgn0(&out->y))
      {
        ok = f2_neg(&out->y, &out->y);
      }
    }
  }
  f2_free(&t);
  f2_free(&tv2);
  f2_free(&inverse);
  f2_free(&one);
  f2_free(&x1);
  f2_free(&gx1);
  f2_free(&x2);
  f2_free(&gx2);
  f2_free(&y);
  return ok;
}

// Horner evaluation of a polynomial with the given coefficients, highest first.
bool poly_eval(F2 *out, const F2 *coefficients, size_t count, const F2 *x)
{
  bool ok = f2_set(out, &coefficients[0]);
  for (size_t i = 1; i < count && ok; ++i)
  {
    ok = f2_mul(out, out, x) && f2_add(out, out, &coefficients[i]);
  }
  return ok;
}

bool iso_map(Affine *out, const Affine *in)
{
  if (in->infinity)
  {
    affine_set_infinity(out);
    return true;
  }
  F2 x_numerator, x_denominator, y_numerator, y_denominator, x_squared, x_cubed;
  f2_init(&x_numerator);
  f2_init(&x_denominator);
  f2_init(&y_numerator);
  f2_init(&y_denominator);
  f2_init(&x_squared);
  f2_init(&x_cubed);
  bool ok = f2_sqr(&x_squared, &in->x) && f2_mul(&x_cubed, &x_squared, &in->x) &&
            poly_eval(&x_numerator, g_curve.kx_num, 4, &in->x) &&
            poly_eval(&x_denominator, g_curve.kx_den, 2, &in->x) &&
            f2_add(&x_denominator, &x_denominator, &x_squared) &&
            poly_eval(&y_numerator, g_curve.ky_num, 4, &in->x) &&
            poly_eval(&y_denominator, g_curve.ky_den, 3, &in->x) &&
            f2_add(&y_denominator, &y_denominator, &x_cubed);
  f2_free(&x_squared);
  f2_free(&x_cubed);
  if (ok && (f2_is_zero(&x_denominator) || f2_is_zero(&y_denominator)))
  {
    affine_set_infinity(out);
    f2_free(&x_numerator);
    f2_free(&x_denominator);
    f2_free(&y_numerator);
    f2_free(&y_denominator);
    return true;
  }
  if (ok) ok = f2_inv(&x_denominator, &x_denominator) &&
               f2_mul(&out->x, &x_numerator, &x_denominator);
  if (ok) ok = f2_inv(&y_denominator, &y_denominator) &&
               f2_mul(&out->y, &in->y, &y_numerator) &&
               f2_mul(&out->y, &out->y, &y_denominator);
  if (ok) out->infinity = false;
  f2_free(&x_numerator);
  f2_free(&x_denominator);
  f2_free(&y_numerator);
  f2_free(&y_denominator);
  return ok;
}

bool expand_message_xmd(const uint8_t *message, size_t message_size,
                        const char *dst, uint8_t *out, size_t out_size)
{
  const size_t dst_size = strlen(dst);
  if (dst_size == 0 || dst_size > 255) return false;
  if (message_size > 256) return false;
  const size_t block = 32;
  const size_t ell = (out_size + block - 1) / block;

  uint8_t dst_prime[256];
  memcpy(dst_prime, dst, dst_size);
  dst_prime[dst_size] = static_cast<uint8_t>(dst_size);
  const size_t dst_prime_size = dst_size + 1;

  uint8_t buffer[64 + 256 + 2 + 1 + 256];
  size_t offset = 0;
  memset(buffer, 0, 64);
  offset = 64;
  memcpy(buffer + offset, message, message_size);
  offset += message_size;
  buffer[offset++] = static_cast<uint8_t>((out_size >> 8) & 0xff);
  buffer[offset++] = static_cast<uint8_t>(out_size & 0xff);
  buffer[offset++] = 0x00;
  memcpy(buffer + offset, dst_prime, dst_prime_size);
  offset += dst_prime_size;

  uint8_t b0[32], previous[32];
  if (!crypto_sha256(buffer, offset, b0)) return false;
  if (!crypto_sha256(b0, 32, previous)) return false;
  {
    uint8_t second[32 + 1 + 256];
    memcpy(second, b0, 32);
    second[32] = 0x01;
    memcpy(second + 33, dst_prime, dst_prime_size);
    if (!crypto_sha256(second, 33 + dst_prime_size, previous)) return false;
  }
  size_t produced = 0;
  const size_t first = out_size < 32 ? out_size : 32;
  memcpy(out, previous, first);
  produced = first;
  for (size_t counter = 2; counter <= ell && produced < out_size; ++counter)
  {
    uint8_t chunk[32 + 1 + 256];
    for (size_t i = 0; i < 32; ++i) chunk[i] = b0[i] ^ previous[i];
    chunk[32] = static_cast<uint8_t>(counter);
    memcpy(chunk + 33, dst_prime, dst_prime_size);
    if (!crypto_sha256(chunk, 33 + dst_prime_size, previous)) return false;
    const size_t remaining = out_size - produced;
    const size_t take = remaining < 32 ? remaining : 32;
    memcpy(out + produced, previous, take);
    produced += take;
  }
  return produced == out_size;
}

bool hash_to_curve_g2(const uint8_t *message, size_t message_size,
                      const char *dst, Affine *out)
{
  uint8_t uniform[256];
  if (!expand_message_xmd(message, message_size, dst, uniform, sizeof(uniform)))
  {
    return false;
  }
  F2 u[2];
  f2_init(&u[0]);
  f2_init(&u[1]);
  bool ok = true;
  for (size_t i = 0; i < 2 && ok; ++i)
  {
    mbedtls_mpi c0, c1;
    mbedtls_mpi_init(&c0);
    mbedtls_mpi_init(&c1);
    ok = mbedtls_mpi_read_binary(&c0, uniform + 64 * (0 + i * 2), 64) == 0 &&
         mbedtls_mpi_read_binary(&c1, uniform + 64 * (1 + i * 2), 64) == 0 &&
         mbedtls_mpi_mod_mpi(&u[i].c0, &c0, &g_prime) == 0 &&
         mbedtls_mpi_mod_mpi(&u[i].c1, &c1, &g_prime) == 0;
    mbedtls_mpi_free(&c0);
    mbedtls_mpi_free(&c1);
  }

  Affine q0, q1, sum, mapped;
  affine_init(&q0);
  affine_init(&q1);
  affine_init(&sum);
  affine_init(&mapped);
  F2 zero_coefficient;
  f2_init(&zero_coefficient);
  f2_zero(&zero_coefficient);
  if (ok) ok = map_to_curve_simple_swu(&q0, &u[0]) &&
               map_to_curve_simple_swu(&q1, &u[1]);
  if (ok) ok = iso_map(&q0, &q0) && iso_map(&q1, &q1);
  if (ok) ok = affine_add(&sum, &q0, &q1, &zero_coefficient);
  if (ok) ok = affine_copy(&mapped, &sum);
  if (ok)
  {
    Jacobian cleared;
    jacobian_init(&cleared);
    ok = jacobian_scalar_mul(&cleared, &mapped, &g_cofactor) &&
         jacobian_to_affine(out, &cleared);
    jacobian_free(&cleared);
  }
  f2_free(&zero_coefficient);
  affine_free(&q0);
  affine_free(&q1);
  affine_free(&sum);
  affine_free(&mapped);
  f2_free(&u[0]);
  f2_free(&u[1]);
  return ok && !out->infinity;
}

void write_field_element(uint8_t out[48], const mbedtls_mpi *value)
{
  memset(out, 0, 48);
  mbedtls_mpi_write_binary(value, out, 48);
}

bool compress_g2(uint8_t out[96], const Affine *point)
{
  memset(out, 0, 96);
  if (point->infinity)
  {
    out[0] = 0xc0;
    return true;
  }
  uint8_t c1[48], c0[48];
  write_field_element(c1, &point->x.c1);
  write_field_element(c0, &point->x.c0);
  memcpy(out, c1, 48);
  memcpy(out + 48, c0, 48);
  out[0] |= 0x80;
  const int comparison = mbedtls_mpi_cmp_mpi(&point->y.c1, &g_curve.half);
  bool negative = comparison > 0;
  if (comparison == 0)
  {
    negative = mbedtls_mpi_cmp_mpi(&point->y.c0, &g_curve.half) > 0;
  }
  if (negative) out[0] |= 0x20;
  return true;
}

bool decompress_g2(Affine *out, const uint8_t in[96])
{
  if ((in[0] & 0x80) == 0) return false;
  if ((in[0] & 0x40) != 0)
  {
    affine_set_infinity(out);
    return true;
  }
  uint8_t c1[48], c0[48];
  memcpy(c1, in, 48);
  memcpy(c0, in + 48, 48);
  c1[0] &= 0x1f;
  const bool sign = (in[0] & 0x20) != 0;
  bool ok = mbedtls_mpi_read_binary(&out->x.c1, c1, 48) == 0 &&
            mbedtls_mpi_read_binary(&out->x.c0, c0, 48) == 0 &&
            mbedtls_mpi_cmp_mpi(&out->x.c1, &g_prime) < 0 &&
            mbedtls_mpi_cmp_mpi(&out->x.c0, &g_prime) < 0;
  F2 rhs, y;
  f2_init(&rhs);
  f2_init(&y);
  if (ok) ok = gx_curve(&rhs, &out->x) && f2_sqrt(&y, &rhs, false);
  if (ok)
  {
    const int comparison = mbedtls_mpi_cmp_mpi(&y.c1, &g_curve.half);
    bool negative = comparison > 0;
    if (comparison == 0)
    {
      negative = mbedtls_mpi_cmp_mpi(&y.c0, &g_curve.half) > 0;
    }
    if (negative != sign) ok = f2_neg(&y, &y);
  }
  if (ok)
  {
    out->infinity = false;
    ok = f2_set(&out->y, &y);
  }
  f2_free(&rhs);
  f2_free(&y);
  return ok;
}

} // namespace

bool bls12_381_g2_hash_to_curve(const uint8_t *message, size_t message_size,
                                const char *dst, uint8_t out[96])
{
  if (message == nullptr || dst == nullptr || out == nullptr) return false;
  if (!curve_ready()) return false;
  Affine point;
  affine_init(&point);
  const bool ok = hash_to_curve_g2(message, message_size, dst, &point) &&
                  compress_g2(out, &point);
  affine_free(&point);
  return ok;
}

bool bls12_381_g2_sign_augmented(const uint8_t secret_key[32],
                                 const uint8_t *message, size_t message_size,
                                 uint8_t out[96])
{
  if (secret_key == nullptr || out == nullptr) return false;
  if (!curve_ready()) return false;
  uint8_t public_key[kBlsG1CompressedSize];
  if (!bls12_381_g1_public_key(secret_key, public_key)) return false;

  uint8_t transcript[48 + 256];
  if (message_size > 256) return false;
  memcpy(transcript, public_key, 48);
  if (message_size) memcpy(transcript + 48, message, message_size);

  Affine hashed;
  affine_init(&hashed);
  bool ok = hash_to_curve_g2(transcript, 48 + message_size, kAugmentedDst,
                             &hashed);
  if (ok)
  {
    mbedtls_mpi scalar;
    mbedtls_mpi_init(&scalar);
    Jacobian product;
    jacobian_init(&product);
    Affine signature;
    affine_init(&signature);
    ok = mbedtls_mpi_read_binary(&scalar, secret_key, 32) == 0 &&
         jacobian_scalar_mul(&product, &hashed, &scalar) &&
         jacobian_to_affine(&signature, &product) &&
         compress_g2(out, &signature);
    mbedtls_mpi_free(&scalar);
    jacobian_free(&product);
    affine_free(&signature);
  }
  affine_free(&hashed);
  secure_zero(transcript, sizeof(transcript));
  return ok;
}

bool bls12_381_g2_aggregate(const uint8_t **signatures, size_t count,
                            uint8_t out[96])
{
  if (signatures == nullptr || out == nullptr || count == 0) return false;
  if (!curve_ready()) return false;
  Jacobian accumulator;
  jacobian_init(&accumulator);
  jacobian_set_infinity(&accumulator);
  bool ok = true;
  for (size_t i = 0; i < count && ok; ++i)
  {
    Affine point;
    affine_init(&point);
    ok = decompress_g2(&point, signatures[i]) &&
         jacobian_add_affine(&accumulator, &accumulator, &point);
    affine_free(&point);
  }
  if (ok)
  {
    Affine total;
    affine_init(&total);
    ok = jacobian_to_affine(&total, &accumulator) && compress_g2(out, &total);
    affine_free(&total);
  }
  jacobian_free(&accumulator);
  return ok;
}

bool run_bls_g2_self_tests()
{
  // Vectors generated with chia's blspy 2.0.3 (AugSchemeMPL).
  static const uint8_t kPrivateKey[32] = {
      0x4a, 0x35, 0x3b, 0xe3, 0xda, 0xc0, 0x91, 0xa0, 0xa7, 0xe6, 0x40,
      0x62, 0x03, 0x72, 0xf5, 0xe1, 0xe2, 0xe4, 0x40, 0x17, 0x17, 0xc1,
      0xe7, 0x9c, 0xac, 0x6f, 0xfb, 0xa8, 0xf6, 0x90, 0x56, 0x04};
  static const uint8_t kExpectedSignature[96] = {
      0xb8, 0x1a, 0x24, 0xe9, 0x87, 0x9b, 0x80, 0x26, 0x7d, 0xe8, 0x32,
      0xff, 0x3b, 0x0b, 0xc0, 0xb6, 0x88, 0x2c, 0xff, 0xaa, 0x45, 0xb8,
      0xd6, 0xb7, 0xf0, 0x9c, 0x63, 0xc5, 0x12, 0x8b, 0x76, 0x1c, 0xe3,
      0xb4, 0xff, 0x35, 0x93, 0x3d, 0xc0, 0xd2, 0xb9, 0xde, 0x64, 0x8a,
      0x7b, 0x5d, 0xe8, 0x5b, 0x04, 0x70, 0x41, 0x74, 0x34, 0x23, 0x03,
      0x13, 0x71, 0x2b, 0x3b, 0x93, 0x23, 0x91, 0x95, 0x31, 0xf2, 0x95,
      0xf1, 0xe6, 0x73, 0x4f, 0xce, 0xdf, 0xaf, 0xa3, 0x11, 0x25, 0xff,
      0x53, 0xbe, 0xa8, 0x96, 0x37, 0x62, 0x38, 0x69, 0x2e, 0xda, 0x2c,
      0x31, 0xa3, 0x0e, 0x82, 0x96, 0xad, 0x0f, 0xb3};
  // sk = 1; the augmented scheme hashes the public key into the message, so
  // this signature is the raw hash-to-curve output for the generator.
  static const uint8_t kOneKey[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  static const uint8_t kOneExpected[96] = {
      0x8f, 0xd6, 0x7d, 0x18, 0x71, 0x93, 0x23, 0x5e, 0x38, 0xc6, 0x5e,
      0x9c, 0x8c, 0xa7, 0xac, 0xc8, 0x62, 0xac, 0x6c, 0x5f, 0xe6, 0xef,
      0x04, 0x92, 0x7f, 0x72, 0xc5, 0xd6, 0x63, 0x35, 0x9e, 0x9d, 0x9e,
      0x18, 0x34, 0x07, 0x9b, 0x8d, 0xc7, 0x6c, 0x30, 0xa8, 0x33, 0x9b,
      0x4a, 0xe0, 0x59, 0x9f, 0x00, 0x03, 0x43, 0x20, 0x6d, 0x08, 0x80,
      0x2a, 0x05, 0x13, 0x69, 0x0e, 0x07, 0x16, 0x79, 0x60, 0xee, 0x1c,
      0xa4, 0xfe, 0xe2, 0x73, 0x5e, 0x2c, 0x16, 0xfa, 0x3a, 0xe8, 0x80,
      0x5a, 0xca, 0x8e, 0x53, 0xc5, 0x38, 0x26, 0x42, 0xa6, 0x73, 0xbb,
      0x30, 0x6a, 0x54, 0x3d, 0x5f, 0x60, 0x22, 0xb7};

  uint8_t signature[96] = {};
  uint8_t rfc_hash[96] = {};
  // RFC 9380 appendix J.10.1 vector: the empty message with the QUUX suite id.
  static const uint8_t kRfcExpected[96] = {
      0xa5, 0xcb, 0x84, 0x37, 0x53, 0x5e, 0x20, 0xec, 0xff, 0xae, 0xf7, 0x75,
      0x2b, 0xad, 0xdf, 0x98, 0x03, 0x41, 0x39, 0xc3, 0x84, 0x52, 0x45, 0x8b,
      0xae, 0xef, 0xab, 0x37, 0x9b, 0xa1, 0x3d, 0xff, 0x5b, 0xf5, 0xdd, 0x71,
      0xb7, 0x24, 0x18, 0x71, 0x70, 0x47, 0xf5, 0xb0, 0xf3, 0x7d, 0xa0, 0x3d,
      0x01, 0x41, 0xeb, 0xfb, 0xdc, 0xa4, 0x0e, 0xb8, 0x5b, 0x87, 0x14, 0x2e,
      0x13, 0x0a, 0xb6, 0x89, 0xc6, 0x73, 0xcf, 0x60, 0xf1, 0xa3, 0xe9, 0x8d,
      0x69, 0x33, 0x52, 0x66, 0xf3, 0x0d, 0x9b, 0x8d, 0x4a, 0xc4, 0x4c, 0x10,
      0x38, 0xe9, 0xdc, 0xdd, 0x53, 0x93, 0xfa, 0xf5, 0xc4, 0x1f, 0xb7, 0x8a};
  bool ok = bls12_381_g2_hash_to_curve(
                (const uint8_t *)"", 0,
                "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_", rfc_hash) &&
            memcmp(rfc_hash, kRfcExpected, sizeof(rfc_hash)) == 0;
  ok = ok && bls12_381_g2_sign_augmented(
                 kPrivateKey, (const uint8_t *)"hexwallet", 9, signature) &&
       memcmp(signature, kExpectedSignature, sizeof(signature)) == 0;
  if (!ok)
  {
#if defined(HEXWALLET_HOST_TEST)
    ::printf("bls-g2 sign mismatch\n");
#endif
    return false;
  }

  // sk = 1 must reproduce the bare hash-to-curve output, proving the augmented
  // public-key prefix is part of the signed message.
  uint8_t identified[96] = {};
  ok = bls12_381_g2_sign_augmented(kOneKey, (const uint8_t *)"hexwallet", 9,
                                   identified) &&
       memcmp(identified, kOneExpected, sizeof(identified)) == 0;

  // Aggregating one signature is the identity; two signatures must differ.
  const uint8_t *single[1] = {kExpectedSignature};
  uint8_t aggregate[96] = {};
  ok = ok && bls12_381_g2_aggregate(single, 1, aggregate) &&
       memcmp(aggregate, kExpectedSignature, sizeof(aggregate)) == 0;
  const uint8_t *pair[2] = {kExpectedSignature, kOneExpected};
  uint8_t combined[96] = {};
  ok = ok && bls12_381_g2_aggregate(pair, 2, combined) &&
       memcmp(combined, kExpectedSignature, sizeof(combined)) != 0 &&
       memcmp(combined, kOneExpected, sizeof(combined)) != 0;

  // An empty transcript must not collide with the real message.
  uint8_t empty_signature[96] = {};
  ok = ok && bls12_381_g2_sign_augmented(kPrivateKey, (const uint8_t *)"", 0,
                                         empty_signature) &&
       memcmp(empty_signature, kExpectedSignature, sizeof(empty_signature)) != 0;
  return ok;
}

} // namespace hexwallet