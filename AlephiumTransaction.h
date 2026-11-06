#pragma once
#include "ChainTransaction.h"

namespace hexwallet {
ChainError alephium_review(const uint8_t *wire, size_t size, const uint8_t public_key[33], const char *sender,
                           ChainReview &review, uint8_t digest[32]);
}
