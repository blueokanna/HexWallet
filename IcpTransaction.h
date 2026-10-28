#ifndef HEXWALLET_ICP_TRANSACTION_H
#define HEXWALLET_ICP_TRANSACTION_H
#include "ChainTransaction.h"
namespace hexwallet {
bool icp_identity(const uint8_t public_key[32], uint8_t principal[29], uint8_t account[32]);
WalletError icp_ledger_address(const uint8_t public_key[32], char *out, size_t capacity);
ChainError icp_review_payload(const uint8_t *payload, size_t size, const uint8_t public_key[32],
    ChainReview *review, uint8_t digest[32]);
ChainError icp_sign_payload(const uint8_t *payload, size_t size, const uint8_t seed[32],
    uint8_t *out, size_t *capacity);
}
#endif
