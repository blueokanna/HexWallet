#pragma once
#include "ChainTransaction.h"

namespace hexwallet {
ChainError quantus_review(const uint8_t *payload, size_t size, const char *sender, ChainReview &review,
                          uint8_t digest[32]);
ChainError quantus_sign(const uint8_t *payload, size_t size, const uint8_t child_seed[32], uint8_t *out,
                        size_t *capacity);
} // namespace hexwallet
