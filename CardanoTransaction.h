#ifndef HEXWALLET_CARDANO_TRANSACTION_H
#define HEXWALLET_CARDANO_TRANSACTION_H

#include "ChainTransaction.h"

namespace hexwallet {

// Mainnet ADA-only body CBOR, one destination and optional wallet-owned change.
// Returns a complete signed Conway transaction, preserving the body byte-for-byte.
ChainError cardano_review_payload(const uint8_t *body, size_t size,
                                  const char *sender, ChainReview *review,
                                  uint8_t digest[32]);
ChainError cardano_sign_payload(const uint8_t *body, size_t size,
                                const uint8_t seed[64], uint32_t index,
                                uint8_t *out, size_t *in_out_size);
bool run_cardano_transaction_self_tests();

}  // namespace hexwallet
#endif
