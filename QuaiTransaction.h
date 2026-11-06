#pragma once

#include "ChainTransaction.h"

namespace hexwallet {
// go-quai ProtoEncodeTxSigningData. Only mainnet account-ledger transfers
// within Cyprus-1 with empty calldata and an empty access list are reviewed.
ChainError quai_review_payload(const uint8_t *payload, size_t size, const char *sender,
                               ChainReview *review, uint8_t digest[32]);
bool quai_cyprus1_address(const char *address);
bool run_quai_self_tests();
}
