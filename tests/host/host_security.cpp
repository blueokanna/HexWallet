// Host-side definitions for the small set of WalletSecurity symbols that the
// tested firmware units reference. The cryptographic bodies live in
// WalletSecurity.cpp and are exercised on-device via run_bip39/run_bip32/
// run_secp256k1_self_tests; they are not needed for the extended primitives.
// The BIP32/SLIP-0010 body is deliberately absent: any host code path that
// tries to derive a key fails instead of being silently approximated.
#include "WalletSecurity.h"

#include <string.h>

namespace hexwallet {

void secure_zero(void *data, size_t length) {
  if (data == nullptr || length == 0) return;
  volatile uint8_t *cursor = static_cast<volatile uint8_t *>(data);
  while (length--) *cursor++ = 0;
}

bool is_ascii(const char *text) {
  if (text == nullptr) return false;
  for (; *text != '\0'; ++text) {
    if (static_cast<unsigned char>(*text) > 0x7f) return false;
  }
  return true;
}

WalletError hd_private_derive(const HdPrivateNode *parent, uint32_t index,
                              HdPrivateNode *out_node) {
  (void)parent;
  (void)index;
  (void)out_node;
  return WalletError::CryptoFailure;
}

WalletError public_key_from_private(const uint8_t private_key[kPrivateKeySize],
                                    uint8_t out_public[kCompressedPublicKeySize]) {
  (void)private_key;
  (void)out_public;
  return WalletError::CryptoFailure;
}

WalletError hd_private_from_seed(const uint8_t *seed, size_t seed_size,
                                 HdPrivateNode *out_node) {
  (void)seed;
  (void)seed_size;
  (void)out_node;
  return WalletError::CryptoFailure;
}

WalletError hd_private_derive_path(const HdPrivateNode *master, const char *path,
                                  HdPrivateNode *out_node) {
  (void)master; (void)path; (void)out_node;
  return WalletError::CryptoFailure;
}

WalletError secp256k1_schnorr_sign(const uint8_t private_key[kPrivateKeySize],
                                   const uint8_t message[kPrivateKeySize],
                                   const uint8_t aux_rand[kPrivateKeySize],
                                   uint8_t out_signature[64]) {
  (void)private_key;
  (void)message;
  (void)aux_rand;
  (void)out_signature;
  return WalletError::CryptoFailure;
}

WalletError uncompressed_public_key_from_private(
    const uint8_t private_key[kPrivateKeySize],
    uint8_t out_public[kUncompressedPublicKeySize]) {
  (void)private_key;
  (void)out_public;
  return WalletError::CryptoFailure;
}

WalletError secp256k1_sign_digest_recoverable(
    const uint8_t private_key[kPrivateKeySize], const uint8_t digest[kPrivateKeySize],
    RecoverableSignature *out_signature) {
  (void)private_key;
  (void)digest;
  (void)out_signature;
  return WalletError::CryptoFailure;
}

WalletError secp256k1_xonly_public_key(const uint8_t private_key[kPrivateKeySize],
                                       uint8_t out_xonly[kPrivateKeySize],
                                       uint8_t *out_parity) {
  (void)private_key;
  (void)out_xonly;
  (void)out_parity;
  return WalletError::CryptoFailure;
}

}  // namespace hexwallet

void esp_fill_random(void *buffer, size_t length) {
  if (buffer == nullptr) return;
  memset(buffer, 0x5a, length);
}
