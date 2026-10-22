#ifndef HEXWALLET_CRYPTONOTE_AMOUNTS_H
#define HEXWALLET_CRYPTONOTE_AMOUNTS_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Wire format must come from the validated transaction type, never a host hint.
// Masari's inspected upstream uses Legacy; Monero RCT types 4/5/6 use Compact.
enum class RingCtAmountEncoding : uint8_t { Legacy, Compact };

// C = mask*G + amount*H. Mask must be a canonical scalar; zero is valid.
bool ringct_commitment(const uint8_t mask[32], uint64_t amount, uint8_t out[32]);

// Monero compact ECDH derives its mask from the per-output amount key.
bool ringct_commitment_mask(const uint8_t amount_key[32], uint8_t out[32]);

// Exact wire sizes: Legacy=64 (mask || amount), Compact=8 (amount only).
// Compact ignores legacy_mask and derives the mask. Legacy requires a reduced
// legacy_mask. On failure both output buffers are cleared when non-null.
bool ringct_encode_amount(RingCtAmountEncoding encoding,
                          const uint8_t amount_key[32], uint64_t amount,
                          const uint8_t legacy_mask[32], uint8_t *wire,
                          size_t wire_size, uint8_t out_commitment[32]);

// Decode and authenticate against the transaction's output commitment.
// No amount/mask is returned until the commitment matches. This does not
// verify a range proof or establish transaction inclusion in the blockchain.
bool ringct_decode_amount(RingCtAmountEncoding encoding,
                          const uint8_t amount_key[32], const uint8_t *wire,
                          size_t wire_size, const uint8_t commitment[32],
                          uint64_t *out_amount, uint8_t out_mask[32]);

bool run_ringct_amount_self_tests();

}  // namespace hexwallet
#endif
