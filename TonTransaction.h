#ifndef HEXWALLET_TON_TRANSACTION_H
#define HEXWALLET_TON_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet {

constexpr size_t kTonPayloadSize = 66;
constexpr size_t kTonSignedSize = 96;
constexpr uint8_t kTonSendMode = 3;  // ignore errors + pay fees separately
constexpr uint8_t kTonNonBounceable = 0x51;
constexpr uint8_t kTonBounceable = 0x11;

// Compact review payload (little-endian):
//   "TON1" | u32 wallet_id | u32 valid_until | u32 seqno |
//   u8 send_mode | u8 bounce | u8 recipient[32] | u8 amount_nanoton_be[16]
// One native transfer with an empty body to a wallet-v4R2 account. Comments,
// jettons, multi-message orders and custom wallet ids are rejected.
ChainError ton_review_payload(const uint8_t *payload, size_t size,
                              const char *sender, ChainReview *review,
                              uint8_t digest[32]);

// Returns signature(64) || signing-message hash(32). The phone builds the
// external message (signature cell + signing-message ref) and its BoC.
ChainError ton_sign_payload(const uint8_t *payload, size_t size,
                            const uint8_t seed[32], uint8_t *out,
                            size_t *in_out_size);

bool run_ton_self_tests();

}  // namespace hexwallet

#endif
