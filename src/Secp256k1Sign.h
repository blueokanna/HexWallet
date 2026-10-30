#ifndef HEXWALLET_SECP256K1_SIGN_H
#define HEXWALLET_SECP256K1_SIGN_H

#include <mbedtls/ecdsa.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "RandomSource.h"
#include "WalletSecurity.h"

namespace hexwallet {

// One secp256k1 signature path for every UTXO and account adapter.
//
// Bitcoin, Dash, Zcash, the account-model chains and the self-tests all need the
// same thing: an RFC 6979 deterministic signature, normalised to low-S, encoded
// as strict DER, and verified before it is handed back. Each module used to keep
// its own copy of that code, which drifted - the Dash copy had quietly lost the
// blinding RNG and the self-check that the others pass to mbedtls. Keeping one
// implementation removes both the drift and the question of which copy a new
// chain will inherit.
//
// Determinism is load-bearing: the same key and digest must always produce the
// same bytes, because the pinned vectors compare signatures byte for byte.

namespace secp256k1_sign_detail {

// mbedtls needs an RNG for the scalar blinding it applies around the signing
// operation. Blinding does not change the RFC 6979 output, only the internal
// representation, so the pinned vectors stay stable while the secret-dependent
// multiplications stop being a pure function of the key.
inline int rng_callback(void *, unsigned char *out, size_t length) {
  random_fill(out, length);
  return 0;
}

inline size_t encode_integer(const mbedtls_mpi &value, uint8_t *out) {
  uint8_t raw[32];
  mbedtls_mpi_write_binary(&value, raw, sizeof(raw));
  size_t first = 0;
  while (first + 1 < sizeof(raw) && raw[first] == 0) ++first;
  const bool prefix_zero = (raw[first] & 0x80) != 0;
  const size_t length = sizeof(raw) - first + (prefix_zero ? 1 : 0);
  out[0] = 0x02;
  out[1] = static_cast<uint8_t>(length);
  size_t position = 2;
  if (prefix_zero) out[position++] = 0;
  memcpy(out + position, raw + first, sizeof(raw) - first);
  secure_zero(raw, sizeof(raw));
  return 2 + length;
}

} // namespace secp256k1_sign_detail

// Signs `digest` and writes DER into `der` (at most 72 bytes). `*der_size` is
// updated on success only. Returns false when the key is unusable, mbedtls
// fails, or the signature does not verify against the derived public key -
// a signature this function returns has been checked on the curve.
inline bool secp256k1_sign_der(const uint8_t private_key[kPrivateKeySize],
                               const uint8_t digest[kSha256Size], uint8_t *der,
                               size_t *der_size) {
  using namespace secp256k1_sign_detail;
  if (private_key == nullptr || digest == nullptr || der == nullptr ||
      der_size == nullptr) {
    return false;
  }
  mbedtls_ecp_group group;
  mbedtls_mpi d;
  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_mpi half_order;
  mbedtls_ecp_point public_key;
  mbedtls_ecp_group_init(&group);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&half_order);
  mbedtls_ecp_point_init(&public_key);
  int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
  if (result == 0) {
    result = mbedtls_mpi_read_binary(&d, private_key, kPrivateKeySize);
  }
  if (result == 0) {
    result = mbedtls_ecdsa_sign_det_ext(&group, &r, &s, &d, digest, kSha256Size,
                                        MBEDTLS_MD_SHA256, rng_callback,
                                        nullptr);
  }
  // Low-S: both Bitcoin and Dash reject a high-S signature outright.
  if (result == 0) result = mbedtls_mpi_copy(&half_order, &group.N);
  if (result == 0) result = mbedtls_mpi_shift_r(&half_order, 1);
  if (result == 0 && mbedtls_mpi_cmp_mpi(&s, &half_order) > 0) {
    result = mbedtls_mpi_sub_mpi(&s, &group.N, &s);
  }
  if (result == 0) {
    result = mbedtls_ecp_mul(&group, &public_key, &d, &group.G, rng_callback,
                             nullptr);
  }
  if (result == 0) {
    result = mbedtls_ecdsa_verify(&group, digest, kSha256Size, &public_key, &r,
                                  &s);
  }
  uint8_t integers[70];
  size_t integer_size = 0;
  if (result == 0) {
    integer_size = encode_integer(r, integers);
    integer_size += encode_integer(s, integers + integer_size);
    if (*der_size < integer_size + 2) result = -1;
  }
  if (result == 0) {
    der[0] = 0x30;
    der[1] = static_cast<uint8_t>(integer_size);
    memcpy(der + 2, integers, integer_size);
    *der_size = integer_size + 2;
  }
  secure_zero(integers, sizeof(integers));
  mbedtls_ecp_point_free(&public_key);
  mbedtls_mpi_free(&half_order);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&group);
  return result == 0;
}

// Strict DER verification, used by the self-tests that re-read a produced
// signature rather than trusting the signer's own bookkeeping.
inline bool secp256k1_verify_der(const uint8_t public_key[kCompressedPublicKeySize],
                                 const uint8_t digest[kSha256Size],
                                 const uint8_t *der, size_t der_size) {
  if (public_key == nullptr || digest == nullptr || der == nullptr ||
      der_size < 8) {
    return false;
  }
  mbedtls_ecp_group group;
  mbedtls_ecp_point point;
  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&point);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
  if (result == 0) {
    result = mbedtls_ecp_point_read_binary(&group, &point, public_key,
                                           kCompressedPublicKeySize);
  }
  if (result == 0) result = mbedtls_ecp_check_pubkey(&group, &point);
  if (result == 0 && der[0] == 0x30 && der[1] == der_size - 2 && der[2] == 0x02) {
    const size_t r_size = der[3];
    if (r_size != 0 && 4 + r_size + 2 <= der_size && der[4 + r_size] == 0x02) {
      const size_t s_size = der[5 + r_size];
      if (s_size != 0 && 6 + r_size + s_size == der_size) {
        result = mbedtls_mpi_read_binary(&r, der + 4, r_size);
        if (result == 0) {
          result = mbedtls_mpi_read_binary(&s, der + 6 + r_size, s_size);
        }
        if (result == 0) {
          result = mbedtls_ecdsa_verify(&group, digest, kSha256Size, &point, &r,
                                        &s);
        }
      } else {
        result = -1;
      }
    } else {
      result = -1;
    }
  } else if (result == 0) {
    result = -1;
  }
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_ecp_point_free(&point);
  mbedtls_ecp_group_free(&group);
  return result == 0;
}

} // namespace hexwallet

#endif