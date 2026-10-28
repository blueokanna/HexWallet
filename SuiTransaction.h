#ifndef HEXWALLET_SUI_TRANSACTION_H
#define HEXWALLET_SUI_TRANSACTION_H
#include "ChainTransaction.h"
namespace hexwallet {
// Ed25519 scheme (flag 0), SLIP-0010 m/44'/784'/account'/change'/index'.
bool sui_address(const uint8_t public_key[32], char *out, size_t capacity);
bool run_sui_self_tests();
// Canonical BCS TransactionData::V1, one SplitCoins(GasCoin, amount) followed
// by TransferObjects of that result. No Move calls, sponsorship or whole gas
// coin transfers. The signed result is flag || signature || public key (97B).
ChainError sui_review_payload(const uint8_t *data, size_t size,
                              const char *sender, ChainReview *review,
                              uint8_t digest[32]);
ChainError sui_sign_payload(const uint8_t *data, size_t size,
                            const uint8_t private_key[32], uint8_t *out,
                            size_t *in_out_size);
}
#endif
