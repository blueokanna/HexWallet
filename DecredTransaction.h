#ifndef HEXWALLET_DECRED_TRANSACTION_H
#define HEXWALLET_DECRED_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet {

constexpr size_t kDcrMaxOutputs = 2;
constexpr size_t kDcrMaxScript = 34;
constexpr size_t kDcrPayloadSize = 62 + kDcrMaxOutputs * 43;
constexpr size_t kDcrMaxSigned = 512;

// Compact review payload:
//   "DCR1" | u8 prev_txid[32] (wire byte order) | u32 prev_index | u8 tree |
//   u32 sequence | u32 lock_time | u32 expiry | u64 input_value |
//   u8 output_count (1..2) | outputs: u64 value, u8 script_size, script
// One P2PKH input owned by this wallet and up to two transparent outputs.
ChainError dcr_review_payload(const uint8_t *payload, size_t size,
                              const uint8_t public_key[33],
                              const char *sender, ChainReview *review,
                              uint8_t digest[32]);

// Returns the fully serialized signed transaction (one P2PKH input).
ChainError dcr_sign_payload(const uint8_t *payload, size_t size,
                            const uint8_t private_key[32], uint8_t *out,
                            size_t *in_out_size);

bool run_decred_self_tests();

}  // namespace hexwallet

#endif
