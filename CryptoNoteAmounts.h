#ifndef HEXWALLET_CRYPTONOTE_AMOUNTS_H
#define HEXWALLET_CRYPTONOTE_AMOUNTS_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {
enum class RingCtAmountEncoding : uint8_t { Legacy, Compact };

bool ringct_commitment(const uint8_t mask[32], uint64_t amount, uint8_t out[32]);

bool ringct_commitment_mask(const uint8_t amount_key[32], uint8_t out[32]);

bool ringct_encode_amount(RingCtAmountEncoding encoding,
                          const uint8_t amount_key[32], uint64_t amount,
                          const uint8_t legacy_mask[32], uint8_t *wire,
                          size_t wire_size, uint8_t out_commitment[32]);
bool ringct_decode_amount(RingCtAmountEncoding encoding,
                          const uint8_t amount_key[32], const uint8_t *wire,
                          size_t wire_size, const uint8_t commitment[32],
                          uint64_t *out_amount, uint8_t out_mask[32]);

bool run_ringct_amount_self_tests();

}
#endif
