#ifndef HEXWALLET_VECHAIN_TRANSACTION_H
#define HEXWALLET_VECHAIN_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet {

constexpr size_t kVeChainPayloadSize = 80;
constexpr uint32_t kVeChainMainnetTag = 0x27;
constexpr size_t kVeChainMaxUnsigned = 192;
constexpr size_t kVeChainMaxSigned = kVeChainMaxUnsigned + 80;

// Compact review payload (little-endian integers):
//   "VET1" | u32 chain_tag | u8 block_ref[8] | u32 expiration |
//   u32 gas_price_coef | u64 gas | u8 clause_count (must be 1) |
//   u8 to_size (must be 20) | u8 to[20] | u8 value_be[16] |
//   u16 data_size (must be 0) | u64 nonce
// One native clause only; contract data, multiple clauses, delegation and
// reserved features are rejected.
ChainError vechain_review_payload(const uint8_t *payload, size_t size,
                                  const char *sender, ChainReview *review,
                                  uint8_t digest[32]);

// Builds the canonical 9-field RLP unsigned transaction.
ChainError vechain_build_unsigned(const uint8_t *payload, size_t size,
                                  uint8_t *out, size_t *in_out_size);

// Returns the complete signed RLP transaction (10 fields).
ChainError vechain_sign_payload(const uint8_t *payload, size_t size,
                                const uint8_t private_key[32], uint8_t *out,
                                size_t *in_out_size);

bool run_vechain_self_tests();

}  // namespace hexwallet

#endif
