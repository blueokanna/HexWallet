#include "CryptoNoteOutputScan.h"
#include "CryptoNoteRingCt.h"
#include "CryptoNoteAddress.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"
#include <string.h>
#include <initializer_list>
namespace hexwallet
{
  bool cryptonote_scan_output(const uint8_t view_secret[32],
                              const uint8_t spend_public[32], const uint8_t tx_public[32],
                              uint64_t output_index, const uint8_t output_public[32],
                              RingCtAmountEncoding encoding, const uint8_t *ecdh, size_t ecdh_size,
                              const uint8_t commitment[32], uint64_t *amount)
  {
    if (amount == nullptr)
      return false;
    *amount = 0;
    if (!view_secret || !spend_public || !tx_public || !output_public ||
        !ecdh || !commitment)
      return false;
    uint8_t derivation[32] = {}, expected[32] = {}, key[32] = {}, mask[32] = {};
    const uint8_t zero[32] = {};
    uint64_t decoded = 0;
    const bool ok = cryptonote_generate_key_derivation(tx_public, view_secret, derivation) &&
                    cryptonote_derive_public_key(derivation, output_index, spend_public, expected) &&
                    crypto_constant_time_equal(expected, output_public, 32) &&
                    cryptonote_derive_secret_key(derivation, output_index, zero, key) &&
                    ringct_decode_amount(encoding, key, ecdh, ecdh_size, commitment, &decoded, mask);
    if (ok)
      *amount = decoded;
    secure_zero(&decoded, sizeof(decoded));
    secure_zero(derivation, sizeof(derivation));
    secure_zero(expected, sizeof(expected));
    secure_zero(key, sizeof(key));
    secure_zero(mask, sizeof(mask));
    return ok;
  }
  bool run_cryptonote_output_scan_self_tests()
  {
    // Public synthetic keys; no real funds. Exercise the recipient/sender ECDH
    // paths independently, both ECDH encodings and host substitution rejection.
    uint8_t a[32] = {3}, b[32] = {5}, r[32] = {7}, zero[32] = {};
    uint8_t A[32], B[32], R[32], d[32], P[32], key[32], C[32], wire[64];
    if (cryptonote_public_key_from_scalar(a, A) != WalletError::Ok ||
        cryptonote_public_key_from_scalar(b, B) != WalletError::Ok ||
        cryptonote_public_key_from_scalar(r, R) != WalletError::Ok ||
        !cryptonote_generate_key_derivation(A, r, d) ||
        !cryptonote_derive_public_key(d, 128, B, P) ||
        !cryptonote_derive_secret_key(d, 128, zero, key))
      return false;
    for (auto encoding : {RingCtAmountEncoding::Legacy, RingCtAmountEncoding::Compact})
    {
      const size_t n = encoding == RingCtAmountEncoding::Legacy ? 64 : 8;
      uint64_t amount = 0;
      if (!ringct_encode_amount(encoding, key, 123456789, b, wire, n, C) ||
          !cryptonote_scan_output(a, B, R, 128, P, encoding, wire, n, C, &amount) ||
          amount != 123456789)
        return false;
      if (cryptonote_scan_output(a, B, R, 129, P, encoding, wire, n, C, &amount) || amount != 0)
        return false;
      wire[0] ^= 1;
      if (cryptonote_scan_output(a, B, R, 128, P, encoding, wire, n, C, &amount) || amount != 0)
        return false;
      wire[0] ^= 1;
      C[0] ^= 1;
      if (cryptonote_scan_output(a, B, R, 128, P, encoding, wire, n, C, &amount) || amount != 0)
        return false;
      C[0] ^= 1;
      if (cryptonote_scan_output(a, B, R, 128, P, encoding, wire, n - 1, C, &amount) || amount != 0)
        return false;
    }
    return true;
  }
}
