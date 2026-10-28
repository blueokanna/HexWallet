#ifndef HEXWALLET_NEM_TRANSACTION_H
#define HEXWALLET_NEM_TRANSACTION_H
#include "ChainTransaction.h"
namespace hexwallet {
// SLIP10 child bytes are the Keccak-Ed25519 seed. nem-sdk's hex private key
// API reverses this seed; do not substitute RFC8032 Ed25519.
bool nem_public_key(const uint8_t seed[32], uint8_t public_key[32]);
WalletError nem_address(const uint8_t public_key[32], char *out, size_t capacity);
ChainError nem_review_payload(const uint8_t *payload, size_t size,
    const char *sender, ChainReview *review, uint8_t digest[32]);
ChainError nem_sign_payload(const uint8_t *payload, size_t size,
    const uint8_t seed[32], uint8_t *out, size_t *capacity);
}
#endif
