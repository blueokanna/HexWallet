#ifndef HEXWALLET_SECP256K1_SIGN_H
#define HEXWALLET_SECP256K1_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"
#include "src/EcdsaCurve.h"

namespace hexwallet {

// secp256k1 ECDSA for the UTXO adapters, delegating to the one curve engine in
// src/EcdsaCurve.h.
//
// This used to call mbedtls_ecdsa_sign_det_ext. That had three problems: the
// host build links a stub mbedtls that refuses every EC operation, so no host
// test had ever verified a produced signature; the device had to link mbedtls'
// EC code just for this; and the firmware then carried two independent
// implementations of the same curve, which is the drift risk a second copy
// invites.
//
// Behaviour that must not change, because pinned vectors compare bytes:
// RFC 6979 deterministic nonces with HMAC-SHA-256, low-S normalisation, strict
// DER, and a signature verified against the derived public key before it is
// returned.

// Signs `digest` and writes DER into `der` (at most 72 bytes). `*der_size` is
// updated on success only.
inline bool secp256k1_sign_der(const uint8_t private_key[kPrivateKeySize],
                               const uint8_t digest[kSha256Size], uint8_t *der,
                               size_t *der_size) {
  return ecdsa_sign_digest_der(EcdsaCurve::Secp256k1, private_key, digest, der,
                               der_size);
}

// Strict DER verification against a SEC1 compressed public key.
inline bool secp256k1_verify_der(const uint8_t public_key[kCompressedPublicKeySize],
                                 const uint8_t digest[kSha256Size],
                                 const uint8_t *der, size_t der_size) {
  return ecdsa_verify_der(EcdsaCurve::Secp256k1, public_key,
                          kCompressedPublicKeySize, digest, der, der_size);
}

} // namespace hexwallet

#endif
