// BLS12-381 G1 (Chia address derivation) and EIP-2333 key derivation.
//
// The BLS12-381 base field is 381 bits; all big-integer arithmetic uses
// mbedtls_mpi (bundled with the ESP32 core). Point arithmetic is affine over
// y^2 = x^3 + 4. The whole chain is locked by run_crypto_extended_self_tests()
// against EIP-2333 test vectors and an independent Python reference.
#include "CryptoExtended.h"

#include <mbedtls/bignum.h>
#include <mbedtls/md.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

const char kFieldPrimeHex[] =
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
const char kGroupOrderHex[] =
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";
const char kGeneratorXHex[] =
    "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

constexpr size_t kBlsFieldBytes = 48;
constexpr size_t kBlsScalarBytes = 32;

struct BlsPoint {
  mbedtls_mpi x;
  mbedtls_mpi y;
  bool infinity;
};

void point_init(BlsPoint *point) {
  mbedtls_mpi_init(&point->x);
  mbedtls_mpi_init(&point->y);
  point->infinity = true;
}

void point_free(BlsPoint *point) {
  mbedtls_mpi_free(&point->x);
  mbedtls_mpi_free(&point->y);
  point->infinity = true;
}

void point_copy(BlsPoint *out, const BlsPoint *in) {
  if (out == in) return;
  mbedtls_mpi_copy(&out->x, &in->x);
  mbedtls_mpi_copy(&out->y, &in->y);
  out->infinity = in->infinity;
}

// Build the canonical generator from x and y^2 = x^3 + 4 (p == 3 mod 4).
bool generator_init(BlsPoint *generator) {
  mbedtls_mpi p, four, y_squared, exp, neg;
  mbedtls_mpi_init(&p);
  mbedtls_mpi_init(&four);
  mbedtls_mpi_init(&y_squared);
  mbedtls_mpi_init(&exp);
  mbedtls_mpi_init(&neg);
  int rc = 0;
  rc |= mbedtls_mpi_read_string(&p, 16, kFieldPrimeHex);
  rc |= mbedtls_mpi_lset(&four, 4);
  rc |= mbedtls_mpi_read_string(&generator->x, 16, kGeneratorXHex);
  rc |= mbedtls_mpi_mul_mpi(&y_squared, &generator->x, &generator->x);
  rc |= mbedtls_mpi_mul_mpi(&y_squared, &y_squared, &generator->x);
  rc |= mbedtls_mpi_add_mpi(&y_squared, &y_squared, &four);
  rc |= mbedtls_mpi_mod_mpi(&y_squared, &y_squared, &p);
  rc |= mbedtls_mpi_add_int(&exp, &p, 1);
  rc |= mbedtls_mpi_shift_r(&exp, 2);
  rc |= mbedtls_mpi_exp_mod(&generator->y, &y_squared, &exp, &p, nullptr);
  if (rc == 0) {
    // The canonical BLS12-381 G1 generator uses the SMALLER y root
    // (y < p - y), matching the ZCash sort-flag convention that Chia and
    // the wider ecosystem rely on for compressed point bytes.
    rc = mbedtls_mpi_sub_mpi(&neg, &p, &generator->y);
    if (rc == 0 && mbedtls_mpi_cmp_mpi(&generator->y, &neg) > 0) {
      rc = mbedtls_mpi_copy(&generator->y, &neg);
    }
  }
  generator->infinity = rc != 0;
  mbedtls_mpi_free(&p);
  mbedtls_mpi_free(&four);
  mbedtls_mpi_free(&y_squared);
  mbedtls_mpi_free(&exp);
  mbedtls_mpi_free(&neg);
  return rc == 0;
}

bool point_add(BlsPoint *out, const BlsPoint *left, const BlsPoint *right,
               const mbedtls_mpi *p) {
  if (left->infinity) {
    point_copy(out, right);
    return true;
  }
  if (right->infinity) {
    point_copy(out, left);
    return true;
  }
  mbedtls_mpi lambda, t0, t1, denom;
  mbedtls_mpi_init(&lambda);
  mbedtls_mpi_init(&t0);
  mbedtls_mpi_init(&t1);
  mbedtls_mpi_init(&denom);
  bool ok = false;
  const int x_equal = mbedtls_mpi_cmp_mpi(&left->x, &right->x);
  if (x_equal == 0) {
    // y1 == y2 -> double; y1 == -y2 -> infinity
    mbedtls_mpi neg;
    mbedtls_mpi_init(&neg);
    ok = mbedtls_mpi_sub_mpi(&neg, p, &right->y) == 0;
    if (ok && mbedtls_mpi_cmp_mpi(&left->y, &neg) == 0) {
      out->infinity = true;
      mbedtls_mpi_free(&neg);
      mbedtls_mpi_free(&lambda);
      mbedtls_mpi_free(&t0);
      mbedtls_mpi_free(&t1);
      mbedtls_mpi_free(&denom);
      return true;
    }
    if (ok) {
      // lambda = 3*x^2 / (2*y)
      ok = mbedtls_mpi_mul_mpi(&lambda, &left->x, &left->x) == 0;
      if (ok) ok = mbedtls_mpi_mul_int(&lambda, &lambda, 3) == 0;
      if (ok) ok = mbedtls_mpi_mul_int(&denom, &left->y, 2) == 0;
    }
    mbedtls_mpi_free(&neg);
  } else {
    // lambda = (y2 - y1) / (x2 - x1)
    ok = mbedtls_mpi_sub_mpi(&lambda, &right->y, &left->y) == 0;
    if (ok) ok = mbedtls_mpi_sub_mpi(&denom, &right->x, &left->x) == 0;
  }
  if (mbedtls_mpi_inv_mod(&denom, &denom, p) != 0) {
    ok = false;
  }
  if (ok) ok = mbedtls_mpi_mul_mpi(&lambda, &lambda, &denom) == 0;
  if (ok) ok = mbedtls_mpi_mod_mpi(&lambda, &lambda, p) == 0;
  // x3 = lambda^2 - x1 - x2
  mbedtls_mpi x3, y3;
  mbedtls_mpi_init(&x3);
  mbedtls_mpi_init(&y3);
  if (ok) ok = mbedtls_mpi_mul_mpi(&x3, &lambda, &lambda) == 0;
  if (ok) ok = mbedtls_mpi_sub_mpi(&x3, &x3, &left->x) == 0;
  if (ok) ok = mbedtls_mpi_sub_mpi(&x3, &x3, &right->x) == 0;
  if (ok) ok = mbedtls_mpi_mod_mpi(&x3, &x3, p) == 0;
  // y3 = lambda*(x1 - x3) - y1
  if (ok) ok = mbedtls_mpi_sub_mpi(&y3, &left->x, &x3) == 0;
  if (ok) ok = mbedtls_mpi_mul_mpi(&y3, &lambda, &y3) == 0;
  if (ok) ok = mbedtls_mpi_sub_mpi(&y3, &y3, &left->y) == 0;
  if (ok) ok = mbedtls_mpi_mod_mpi(&y3, &y3, p) == 0;
  if (ok) {
    mbedtls_mpi_copy(&out->x, &x3);
    mbedtls_mpi_copy(&out->y, &y3);
    out->infinity = false;
  }
  mbedtls_mpi_free(&lambda);
  mbedtls_mpi_free(&t0);
  mbedtls_mpi_free(&t1);
  mbedtls_mpi_free(&denom);
  mbedtls_mpi_free(&x3);
  mbedtls_mpi_free(&y3);
  return ok;
}

bool point_scalarmult(BlsPoint *out, const BlsPoint *point, const mbedtls_mpi *scalar,
                      const mbedtls_mpi *p) {
  BlsPoint accumulator, addend;
  point_init(&accumulator);
  point_init(&addend);
  point_copy(&addend, point);
  bool ok = true;
  const size_t bits = mbedtls_mpi_bitlen(scalar);
  for (size_t bit = bits; bit-- > 0;) {
    if (!point_add(&accumulator, &accumulator, &accumulator, p)) {
      ok = false;
      break;
    }
    if (mbedtls_mpi_get_bit(scalar, bit) == 1) {
      if (!point_add(&accumulator, &accumulator, &addend, p)) {
        ok = false;
        break;
      }
    }
  }
  if (ok) point_copy(out, &accumulator);
  point_free(&accumulator);
  point_free(&addend);
  return ok;
}

// 48-byte ZCash BLS12-381 compressed point:
//   bit 383 (0x80) compression flag C (always set for compressed points)
//   bit 382 (0x40) infinity flag I
//   bit 381 (0x20) sort flag S (set when y > p - y)
//   bits 380..0   x
bool point_compress(const BlsPoint *point, const mbedtls_mpi *p,
                    uint8_t out[48]) {
  memset(out, 0, 48);
  if (point->infinity) {
    out[0] = 0xc0;  // C | I
    return true;
  }
  // sort flag: y > p - y
  mbedtls_mpi neg;
  mbedtls_mpi_init(&neg);
  const bool ok = mbedtls_mpi_sub_mpi(&neg, p, &point->y) == 0;
  if (ok) {
    const bool sort = mbedtls_mpi_cmp_mpi(&point->y, &neg) > 0;
    size_t written = 0;
    mbedtls_mpi compressed;
    mbedtls_mpi_init(&compressed);
    mbedtls_mpi_copy(&compressed, &point->x);
    if (sort) {
      mbedtls_mpi_set_bit(&compressed, 381, 1);
    }
    mbedtls_mpi_set_bit(&compressed, 383, 1);  // compression flag
    mbedtls_mpi_write_binary(&compressed, out, 48);
    mbedtls_mpi_free(&compressed);
  }
  mbedtls_mpi_free(&neg);
  return ok;
}

bool point_decompress(const uint8_t data[48], const mbedtls_mpi *p,
                      BlsPoint *out) {
  mbedtls_mpi x, four, y2, exp, y;
  mbedtls_mpi_init(&x);
  mbedtls_mpi_init(&four);
  mbedtls_mpi_init(&y2);
  mbedtls_mpi_init(&exp);
  mbedtls_mpi_init(&y);
  const bool infinity = (data[0] & 0x40) != 0;
  const bool sort = (data[0] & 0x20) != 0;
  const bool compressed = (data[0] & 0x80) != 0;
  uint8_t x_bytes[48];
  memcpy(x_bytes, data, 48);
  x_bytes[0] &= 0x1f;  // clear the three flag bits (C/I/S)
  bool ok = compressed && mbedtls_mpi_read_binary(&x, x_bytes, 48) == 0;
  if (ok && infinity) {
    out->infinity = true;
  } else if (ok) {
    ok = mbedtls_mpi_lset(&four, 4) == 0;
    if (ok) ok = mbedtls_mpi_mul_mpi(&y2, &x, &x) == 0;
    if (ok) ok = mbedtls_mpi_mul_mpi(&y2, &y2, &x) == 0;
    if (ok) ok = mbedtls_mpi_add_mpi(&y2, &y2, &four) == 0;
    if (ok) ok = mbedtls_mpi_mod_mpi(&y2, &y2, p) == 0;
    if (ok) ok = mbedtls_mpi_add_int(&exp, p, 1) == 0;
    if (ok) ok = mbedtls_mpi_shift_r(&exp, 2) == 0;
    if (ok) ok = mbedtls_mpi_exp_mod(&y, &y2, &exp, p, nullptr) == 0;
    if (ok) {
      mbedtls_mpi neg;
      mbedtls_mpi_init(&neg);
      ok = mbedtls_mpi_sub_mpi(&neg, p, &y) == 0;
      if (ok && sort) {
        if (mbedtls_mpi_cmp_mpi(&y, &neg) < 0) ok = mbedtls_mpi_copy(&y, &neg) == 0;
      } else if (ok) {
        if (mbedtls_mpi_cmp_mpi(&y, &neg) > 0) ok = mbedtls_mpi_copy(&y, &neg) == 0;
      }
      mbedtls_mpi_free(&neg);
    }
    if (ok) {
      mbedtls_mpi_copy(&out->x, &x);
      mbedtls_mpi_copy(&out->y, &y);
      out->infinity = false;
    }
  }
  mbedtls_mpi_free(&x);
  mbedtls_mpi_free(&four);
  mbedtls_mpi_free(&y2);
  mbedtls_mpi_free(&exp);
  mbedtls_mpi_free(&y);
  return ok;
}

// ---------------------------------------------------------------------------
// EIP-2333 helpers (SHA-256 / HMAC-SHA256 based).
// ---------------------------------------------------------------------------

bool sha256(const uint8_t *data, size_t size, uint8_t out[32]) {
  return crypto_sha256(data, size, out);
}

bool hmac_sha256(const uint8_t *key, size_t key_size, const uint8_t *data,
                 size_t data_size, uint8_t out[32]) {
  return crypto_hmac_sha256(key, key_size, data, data_size, out);
}

// HKDF-Expand with SHA-256; info is prebuilt. Output length <= 255*32.
bool hkdf_expand_sha256(const uint8_t prk[32], const uint8_t *info,
                        size_t info_size, uint8_t *out, size_t out_size) {
  uint8_t block[32];
  uint8_t previous[32];
  size_t produced = 0;
  uint8_t counter = 1;
  bool first = true;
  while (produced < out_size) {
    uint8_t input[32 + 256 + 1];
    size_t input_size = 0;
    if (!first) {
      memcpy(input, previous, 32);
      input_size = 32;
    }
    memcpy(input + input_size, info, info_size);
    input_size += info_size;
    input[input_size++] = counter;
    if (!hmac_sha256(prk, 32, input, input_size, block)) return false;
    const size_t take = out_size - produced < 32 ? out_size - produced : 32;
    memcpy(out + produced, block, take);
    produced += take;
    memcpy(previous, block, 32);
    ++counter;
    first = false;
  }
  secure_zero(block, sizeof(block));
  secure_zero(previous, sizeof(previous));
  return true;
}

// HKDF-Extract then Expand (single call) with SHA-256.
bool hkdf_sha256(const uint8_t *salt, size_t salt_size, const uint8_t *ikm,
                 size_t ikm_size, const uint8_t *info, size_t info_size,
                 uint8_t *out, size_t out_size) {
  uint8_t prk[32];
  if (!hmac_sha256(salt, salt_size, ikm, ikm_size, prk)) return false;
  const bool ok = hkdf_expand_sha256(prk, info, info_size, out, out_size);
  secure_zero(prk, sizeof(prk));
  return ok;
}

// HKDF-mod-r per EIP-2333 (salt hashed before first extraction; the initial
// salt is the 20-byte ASCII string "BLS-SIG-KEYGEN-SALT-").
bool hkdf_mod_r(const uint8_t *ikm, size_t ikm_size, uint8_t out_sk[32]) {
  static const uint8_t kSaltPrefix[] = "BLS-SIG-KEYGEN-SALT-";
  constexpr size_t kSaltPrefixSize = sizeof(kSaltPrefix) - 1;
  mbedtls_mpi r, sk;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&sk);
  bool ok = mbedtls_mpi_read_string(&r, 16, kGroupOrderHex) == 0;
  uint8_t salt[32];
  memcpy(salt, kSaltPrefix, kSaltPrefixSize);
  size_t salt_size = kSaltPrefixSize;
  uint8_t okm[48];
  while (ok) {
    // salt = H(salt)
    if (!sha256(salt, salt_size, salt)) {
      ok = false;
      break;
    }
    salt_size = 32;
    uint8_t extract_input[256 + 1];
    if (ikm_size > sizeof(extract_input) - 1) {
      ok = false;
      break;
    }
    memcpy(extract_input, ikm, ikm_size);
    extract_input[ikm_size] = 0x00;  // I2OSP(0,1)
    uint8_t info[2] = {0x00, 0x30};  // I2OSP(48,2)
    if (!hkdf_sha256(salt, salt_size, extract_input, ikm_size + 1, info,
                     sizeof(info), okm, sizeof(okm))) {
      ok = false;
      break;
    }
    if (mbedtls_mpi_read_binary(&sk, okm, sizeof(okm)) != 0) {
      ok = false;
      break;
    }
    if (mbedtls_mpi_mod_mpi(&sk, &sk, &r) != 0) {
      ok = false;
      break;
    }
    if (!mbedtls_mpi_cmp_int(&sk, 0)) {
      // sk == 0 -> retry with hashed salt
      secure_zero(extract_input, sizeof(extract_input));
      continue;
    }
    break;
  }
  if (ok) {
    size_t written = 0;
    ok = mbedtls_mpi_write_binary(&sk, out_sk, 32) == 0;
    (void)written;
  }
  secure_zero(salt, sizeof(salt));
  secure_zero(okm, sizeof(okm));
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&sk);
  return ok;
}

constexpr size_t kLamportCount = 255;
constexpr size_t kLamportSkSize = kLamportCount * 32;

// PRK = HMAC(salt, IKM); OKM = HKDF-Expand(PRK, "", 255*32); split into chunks.
bool ikm_to_lamport_sk(const uint8_t *ikm, size_t ikm_size,
                       const uint8_t *salt, size_t salt_size,
                       uint8_t lamport[kLamportSkSize]) {
  uint8_t prk[32];
  if (!hmac_sha256(salt, salt_size, ikm, ikm_size, prk)) return false;
  const bool ok = hkdf_expand_sha256(prk, nullptr, 0, lamport, kLamportSkSize);
  secure_zero(prk, sizeof(prk));
  return ok;
}

bool parent_sk_to_lamport_pk(const uint8_t parent_sk[32], uint32_t index,
                             uint8_t out_compressed[32]) {
  // salt = I2OSP(index, 4) exactly (EIP-2333).
  uint8_t salt[4];
  salt[0] = static_cast<uint8_t>(index >> 24);
  salt[1] = static_cast<uint8_t>(index >> 16);
  salt[2] = static_cast<uint8_t>(index >> 8);
  salt[3] = static_cast<uint8_t>(index);
  uint8_t lamport0[kLamportSkSize];
  uint8_t lamport1[kLamportSkSize];
  uint8_t not_ikm[32];
  for (size_t index_byte = 0; index_byte < 32; ++index_byte) {
    not_ikm[index_byte] = static_cast<uint8_t>(~parent_sk[index_byte]);
  }
  const bool ok0 = ikm_to_lamport_sk(parent_sk, 32, salt, sizeof(salt), lamport0);
  const bool ok1 = ikm_to_lamport_sk(not_ikm, 32, salt, sizeof(salt), lamport1);
  if (!ok0 || !ok1) {
    secure_zero(lamport0, sizeof(lamport0));
    secure_zero(lamport1, sizeof(lamport1));
    secure_zero(not_ikm, sizeof(not_ikm));
    return false;
  }
  uint8_t lamport_pk[2 * kLamportCount * 32];
  for (size_t index_chunk = 0; index_chunk < kLamportCount; ++index_chunk) {
    if (!sha256(lamport0 + index_chunk * 32, 32, lamport_pk + index_chunk * 32)) {
      secure_zero(lamport0, sizeof(lamport0));
      secure_zero(lamport1, sizeof(lamport1));
      secure_zero(not_ikm, sizeof(not_ikm));
      return false;
    }
    if (!sha256(lamport1 + index_chunk * 32, 32,
                lamport_pk + kLamportCount * 32 + index_chunk * 32)) {
      secure_zero(lamport0, sizeof(lamport0));
      secure_zero(lamport1, sizeof(lamport1));
      secure_zero(not_ikm, sizeof(not_ikm));
      return false;
    }
  }
  const bool ok = sha256(lamport_pk, sizeof(lamport_pk), out_compressed);
  secure_zero(lamport0, sizeof(lamport0));
  secure_zero(lamport1, sizeof(lamport1));
  secure_zero(not_ikm, sizeof(not_ikm));
  secure_zero(lamport_pk, sizeof(lamport_pk));
  return ok;
}

// ---------------------------------------------------------------------------
// Chia tree hashes (SHA-256 based CLVM shatree).
// ---------------------------------------------------------------------------

void shatree_atom(const uint8_t *atom, size_t size, uint8_t out[32]) {
  uint8_t input[1 + 64];
  input[0] = 0x01;
  if (size != 0) memcpy(input + 1, atom, size);
  sha256(input, 1 + size, out);
}

void shatree_pair(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) {
  uint8_t input[65];
  input[0] = 0x02;
  memcpy(input + 1, left, 32);
  memcpy(input + 33, right, 32);
  sha256(input, sizeof(input), out);
}

}  // namespace

bool bls12_381_g1_public_key(const uint8_t secret_key[32],
                             uint8_t out_compressed[48]) {
  if (secret_key == nullptr || out_compressed == nullptr) return false;
  mbedtls_mpi p, sk;
  mbedtls_mpi_init(&p);
  mbedtls_mpi_init(&sk);
  BlsPoint generator, result;
  point_init(&generator);
  point_init(&result);
  const bool ok_read_p = mbedtls_mpi_read_string(&p, 16, kFieldPrimeHex) == 0;
  const bool ok_read_sk = mbedtls_mpi_read_binary(&sk, secret_key, 32) == 0;
  const bool ok_gen = generator_init(&generator);
  const bool ok_sm = point_scalarmult(&result, &generator, &sk, &p);
  const bool ok_comp = point_compress(&result, &p, out_compressed);
  bool ok = ok_read_p && ok_read_sk && ok_gen && ok_sm && ok_comp;
  mbedtls_mpi_free(&p);
  mbedtls_mpi_free(&sk);
  point_free(&generator);
  point_free(&result);
  return ok;
}

bool bls12_381_g1_add_generator(const uint8_t point[48],
                                const uint8_t secret_offset[32],
                                uint8_t out_compressed[48]) {
  if (point == nullptr || secret_offset == nullptr || out_compressed == nullptr) {
    return false;
  }
  mbedtls_mpi p, offset;
  mbedtls_mpi_init(&p);
  mbedtls_mpi_init(&offset);
  BlsPoint base, generator, offset_point, result;
  point_init(&base);
  point_init(&generator);
  point_init(&offset_point);
  point_init(&result);
  bool ok = mbedtls_mpi_read_string(&p, 16, kFieldPrimeHex) == 0 &&
            mbedtls_mpi_read_binary(&offset, secret_offset, 32) == 0 &&
            point_decompress(point, &p, &base) && generator_init(&generator) &&
            point_scalarmult(&offset_point, &generator, &offset, &p) &&
            point_add(&result, &base, &offset_point, &p) &&
            point_compress(&result, &p, out_compressed);
  mbedtls_mpi_free(&p);
  mbedtls_mpi_free(&offset);
  point_free(&base);
  point_free(&generator);
  point_free(&offset_point);
  point_free(&result);
  return ok;
}

bool eip2333_master_key(const uint8_t *seed, size_t seed_size,
                        uint8_t out_sk[32]) {
  if (seed == nullptr || out_sk == nullptr || seed_size == 0) return false;
  return hkdf_mod_r(seed, seed_size, out_sk);
}

bool eip2333_derive_child(const uint8_t parent_sk[32], uint32_t index,
                          uint8_t out_sk[32]) {
  if (parent_sk == nullptr || out_sk == nullptr) return false;
  uint8_t compressed[32];
  if (!parent_sk_to_lamport_pk(parent_sk, index, compressed)) return false;
  const bool ok = hkdf_mod_r(compressed, sizeof(compressed), out_sk);
  secure_zero(compressed, sizeof(compressed));
  return ok;
}

bool chia_standard_address(const uint8_t *seed, size_t seed_size,
                           uint32_t address_index, char *out, size_t out_size) {
  if (seed == nullptr || out == nullptr || seed_size == 0) return false;
  uint8_t sk[32];
  if (!hkdf_mod_r(seed, seed_size, sk)) return false;
  const uint32_t path[4] = {12381, 8444, 0, address_index};
  for (size_t index = 0; index < 4; ++index) {
    if (!eip2333_derive_child(sk, path[index], sk)) {
      secure_zero(sk, sizeof(sk));
      return false;
    }
  }
  uint8_t pubkey[48];
  if (!bls12_381_g1_public_key(sk, pubkey)) {
    secure_zero(sk, sizeof(sk));
    return false;
  }
  // DEFAULT_HIDDEN_PUZZLE = ff0980 => tree hash = pair(atom 0x09, nil).
  uint8_t atom09[1] = {0x09};
  uint8_t nil_hash[32];
  uint8_t atom09_hash[32];
  uint8_t hidden_hash[32];
  shatree_atom(nullptr, 0, nil_hash);
  shatree_atom(atom09, 1, atom09_hash);
  shatree_pair(atom09_hash, nil_hash, hidden_hash);

  // synthetic_offset = int(SHA256(pubkey || hidden_hash)) mod r
  mbedtls_mpi r, offset;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&offset);
  uint8_t offset_input[48 + 32];
  memcpy(offset_input, pubkey, 48);
  memcpy(offset_input + 48, hidden_hash, 32);
  uint8_t offset_digest[32];
  bool ok = mbedtls_mpi_read_string(&r, 16, kGroupOrderHex) == 0 &&
            sha256(offset_input, sizeof(offset_input), offset_digest) &&
            mbedtls_mpi_read_binary(&offset, offset_digest, 32) == 0 &&
            mbedtls_mpi_mod_mpi(&offset, &offset, &r) == 0;
  uint8_t offset_bytes[32];
  if (ok) ok = mbedtls_mpi_write_binary(&offset, offset_bytes, 32) == 0;
  if (ok) ok = bls12_381_g1_add_generator(pubkey, offset_bytes, pubkey);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&offset);

  // puzzle_hash = curry_and_treehash(QUOTED_MOD_HASH, shatree_atom(pubkey))
  static const uint8_t kModHash[32] = {
      0xe9, 0xaa, 0xa4, 0x9f, 0x45, 0xba, 0xd5, 0xc8, 0x89, 0xb8, 0x6e,
      0xe3, 0x34, 0x15, 0x50, 0xc1, 0x55, 0xcf, 0xdd, 0x10, 0xc3, 0xa6,
      0x75, 0x7d, 0xe6, 0x18, 0xd2, 0x06, 0x12, 0xff, 0xfd, 0x52,
  };
  uint8_t one_hash[32];
  uint8_t quoted_mod_hash[32];
  uint8_t arg_hash[32];
  uint8_t c_kw_hash[32];
  uint8_t a_kw_hash[32];
  uint8_t curried_values[32];
  uint8_t puzzle_hash[32];
  const uint8_t one_atom[1] = {0x01};
  const uint8_t two_atom[1] = {0x02};
  const uint8_t four_atom[1] = {0x04};
  if (ok) {
    shatree_atom(one_atom, 1, one_hash);              // shatree_int(1)
    shatree_pair(one_hash, kModHash, quoted_mod_hash);  // (q . MOD)
    shatree_atom(pubkey, 48, arg_hash);
    shatree_atom(four_atom, 1, c_kw_hash);
    shatree_atom(two_atom, 1, a_kw_hash);
    // curried_values = (c (q arg) (1 . nil))
    uint8_t quoted_arg[32];
    uint8_t tail[32];
    uint8_t cv_pair[32];
    uint8_t inner[32];
    shatree_pair(one_hash, arg_hash, quoted_arg);   // (q . arg)
    shatree_pair(one_hash, nil_hash, tail);         // (1 . nil)
    shatree_pair(quoted_arg, tail, cv_pair);        // ((q arg) . (1 nil))
    shatree_pair(c_kw_hash, cv_pair, curried_values);
    // puzzle_hash = (a (q . MOD) (curried . nil))
    shatree_pair(curried_values, nil_hash, inner);
    shatree_pair(quoted_mod_hash, inner, puzzle_hash);
    shatree_pair(a_kw_hash, puzzle_hash, puzzle_hash);
  }

  if (ok) {
    ok = bech32_encode("xch", puzzle_hash, 32, out, out_size, true);
  }
  secure_zero(sk, sizeof(sk));
  secure_zero(pubkey, sizeof(pubkey));
  secure_zero(hidden_hash, sizeof(hidden_hash));
  secure_zero(offset_digest, sizeof(offset_digest));
  secure_zero(offset_bytes, sizeof(offset_bytes));
  secure_zero(arg_hash, sizeof(arg_hash));
  secure_zero(curried_values, sizeof(curried_values));
  secure_zero(puzzle_hash, sizeof(puzzle_hash));
  return ok;
}

}  // namespace hexwallet
