#ifndef HEXWALLET_P256_SIGN_H
#define HEXWALLET_P256_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"
#include "src/EcdsaCurve.h"

namespace hexwallet
{

  // NIST P-256 ECDSA for ES256 (FIDO2/CTAP2 credentials), delegating to the one
  // curve engine in src/EcdsaCurve.h.
  //
  // This file used to carry its own Montgomery field, Jacobian point arithmetic,
  // RFC 6979 nonce derivation and DER codec - about 1300 lines that were a
  // line-by-line copy of what secp256k1 needs, differing only in the curve
  // constants and in the `a` coefficient. Two copies of that much arithmetic is
  // a standing invitation for one of them to be fixed and the other forgotten,
  // so the arithmetic now lives once and this file keeps only the ES256 view of
  // it: uncompressed X || Y keys and r || s signatures.
  //
  // What is preserved, exactly: RFC 6979 deterministic nonces with SHA-256,
  // low-S normalisation, strict DER, and a verifier that every produced
  // signature passes before it is returned. run_p256_self_tests() still pins the
  // RFC 6979 A.2.5 answer byte for byte.

  namespace p256_detail
  {
    constexpr size_t kLimbs = ecdsa_detail::kLimbs;
    constexpr size_t kBytes = ecdsa_detail::kBytes;
    constexpr size_t kScalarSize = kEcdsaScalarSize;
  } // namespace p256_detail

  // X || Y of private_key * G.
  inline bool p256_public_key(const uint8_t private_key[p256_detail::kScalarSize],
                              uint8_t public_key[64])
  {
    return ecdsa_public_key(EcdsaCurve::Secp256r1, private_key, public_key);
  }

  // r || s, low-S.
  inline bool p256_sign_digest(const uint8_t private_key[p256_detail::kScalarSize],
                               const uint8_t digest[p256_detail::kBytes],
                               uint8_t signature[64])
  {
    return ecdsa_sign_digest(EcdsaCurve::Secp256r1, private_key, digest, signature);
  }

  // DER SEQUENCE(r, s); at most 72 bytes.
  inline bool p256_sign_der(const uint8_t private_key[p256_detail::kScalarSize],
                            const uint8_t digest[p256_detail::kBytes],
                            uint8_t *der, size_t *der_size)
  {
    return ecdsa_sign_digest_der(EcdsaCurve::Secp256r1, private_key, digest, der,
                                 der_size);
  }

  // Accepts high-S on purpose: consensus verifiers do not reject it, and a
  // verification helper that did would report valid historical signatures as
  // broken. Signing always produces low-S.
  inline bool p256_verify_digest(const uint8_t public_key[64],
                                 const uint8_t digest[p256_detail::kBytes],
                                 const uint8_t signature[64])
  {
    return ecdsa_verify_digest(EcdsaCurve::Secp256r1, public_key, digest, signature);
  }

  // Published KAT: RFC 6979 A.2.5 (P-256, SHA-256, message "sample") pins the
  // nonce and r byte for byte. The example's own s is high-S while this signer
  // normalises, so s is compared against n - s and both halves are verified.
  // The refusals are the ones that matter for an authenticator: a tampered
  // signature, a zero r or s, a different digest, an off-curve key, a zero key
  // and a key equal to the group order.
  inline bool run_p256_self_tests()
  {
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
    passed = passed && crypto_constant_time_equal(signature + 32, kExpectedS, 32);
    passed = passed && p256_verify_digest(public_key, digest, signature);

    // The RFC example's own s is high-S; the verifier must accept it as well.
    uint8_t high_s[64];
    memcpy(high_s, signature, sizeof(high_s));
    {
      ecdsa_detail::Num s;
      ecdsa_detail::Num negated;
      ecdsa_detail::parse_num(signature + 32, &s);
      negated = ecdsa_detail::scalar_sub(ecdsa_detail::zero(), s,
                                        *ecdsa_detail::curve_for(EcdsaCurve::Secp256r1));
      ecdsa_detail::write_num(negated, high_s + 32);
    }
    passed = passed && p256_verify_digest(public_key, digest, high_s);

    // DER must be a well-formed SEQUENCE of two minimally encoded INTEGERs.
    uint8_t der[72];
    size_t der_size = sizeof(der);
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

    // Refusals: tampered signature, zero r/s, wrong digest, off-curve key,
    // zero key and key equal to n.
    uint8_t tampered[64];
    memcpy(tampered, signature, sizeof(tampered));
    tampered[8] ^= 0x01;
    passed = passed && !p256_verify_digest(public_key, digest, tampered);
    uint8_t zero_signature[64] = {};
    passed = passed && !p256_verify_digest(public_key, digest, zero_signature);

    uint8_t other_digest[32];
    memcpy(other_digest, digest, sizeof(other_digest));
    other_digest[0] ^= 0x80;
    passed = passed && !p256_verify_digest(public_key, other_digest, signature);

    uint8_t off_curve[64];
    memcpy(off_curve, kPublicKey, sizeof(off_curve));
    off_curve[63] ^= 0x01;
    passed = passed && !p256_verify_digest(off_curve, digest, signature);

    const uint8_t zero_key[32] = {};
    passed = passed && !p256_sign_digest(zero_key, digest, signature);
    uint8_t order_key[32];
    ecdsa_detail::write_num(
        ecdsa_detail::curve_for(EcdsaCurve::Secp256r1)->order, order_key);
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
