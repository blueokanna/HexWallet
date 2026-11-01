#include "BlsG2.h"
#include <stdio.h>
#include <string.h>
#include "BlsBackend.h"
#include "CryptoExtended.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {
    constexpr char kAugmentedDst[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";
  }

  bool bls12_381_g2_hash_to_curve(const uint8_t *message, size_t message_size,
                                  const char *dst, uint8_t out[96])
  {
    if (out == nullptr)
      return false;
    if ((message == nullptr && message_size != 0) || dst == nullptr)
    {
      secure_zero(out, 96);
      return false;
    }
    if (!bls_g2_hash_to_curve(message, message_size, dst, out))
    {
      secure_zero(out, 96);
      return false;
    }
    return true;
  }

  bool bls12_381_g2_sign_augmented(const uint8_t secret_key[32],
                                   const uint8_t *message, size_t message_size,
                                   uint8_t out[96])
  {
    if (out == nullptr)
      return false;
    if (secret_key == nullptr || (message == nullptr && message_size != 0))
    {
      secure_zero(out, 96);
      return false;
    }
    uint8_t public_key[kBlsG1CompressedSize] = {};
    if (!bls12_381_g1_public_key(secret_key, public_key))
    {
      secure_zero(out, 96);
      return false;
    }
    // AugSchemeMPL binds the compressed public key into the XMD transcript.
    const bool ok = bls_g2_sign_augmented(
        secret_key, public_key, sizeof(public_key), message, message_size,
        kAugmentedDst, out);
    if (!ok)
      secure_zero(out, 96);
    secure_zero(public_key, sizeof(public_key));
    return ok;
  }

  bool bls12_381_g2_aggregate(const uint8_t **signatures, size_t count, uint8_t out[96])
  {
    if (out == nullptr)
      return false;
    if (signatures == nullptr || count == 0)
    {
      secure_zero(out, 96);
      return false;
    }
    if (!bls_g2_aggregate(signatures, count, out))
    {
      secure_zero(out, 96);
      return false;
    }
    return true;
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
    ok = ok && bls12_381_g2_sign_augmented(kPrivateKey, (const uint8_t *)"hexwallet", 9, signature) &&
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
    ok = ok && bls12_381_g2_sign_augmented(kPrivateKey, (const uint8_t *)"", 0, empty_signature) &&
         memcmp(empty_signature, kExpectedSignature, sizeof(empty_signature)) != 0;
    return ok;
  }

} // namespace hexwallet