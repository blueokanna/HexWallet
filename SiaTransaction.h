#ifndef HEXWALLET_SIA_TRANSACTION_H
#define HEXWALLET_SIA_TRANSACTION_H

#include "ChainTransaction.h"

namespace hexwallet {

// Sia v2 PolicyPublicKey address, not the legacy UnlockConditions address.
WalletError sia_address(const uint8_t public_key[32], char *out, size_t out_size);
ChainError sia_review_payload(const uint8_t *payload, size_t size,
                              const char *sender, ChainReview *review,
                              uint8_t digest[32]);
// Returns the 64-byte Ed25519 signature for SatisfiedPolicy.Signatures[0].
ChainError sia_sign_payload(const uint8_t *payload, size_t size,
                            const uint8_t private_key[32], uint8_t *out,
                            size_t *in_out_size);
bool run_sia_self_tests();

}  // namespace hexwallet
#endif
