#ifndef HEXWALLET_HEDERA_TRANSACTION_H
#define HEXWALLET_HEDERA_TRANSACTION_H
#include "ChainTransaction.h"
namespace hexwallet {
bool hedera_key_alias(const uint8_t public_key[32], char *out, size_t capacity);
ChainError hedera_review_payload(const uint8_t *body, size_t size,
                                 const char *key_alias, ChainReview *review,
                                 uint8_t digest[32]);
ChainError hedera_sign_payload(const uint8_t *body, size_t size,
                               const uint8_t private_seed[32], uint8_t *out,
                               size_t *in_out_size);
}  // namespace hexwallet
#endif
