#ifndef HEXWALLET_POLKADOT_TRANSACTION_H
#define HEXWALLET_POLKADOT_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet
{

    constexpr size_t kPolkadotPayloadSize = 130;   // "DOT1": immortal era, tip 0
    constexpr size_t kPolkadotPayloadSizeV2 = 156; // "DOT2": mortal era + tip
    constexpr size_t kPolkadotMaxSigned = 320;
    ChainError polkadot_review_payload(ChainFamily family, const uint8_t *payload,
                                       size_t size, const char *sender,
                                       ChainReview *review, uint8_t digest[32]);

    ChainError polkadot_sign_payload(ChainFamily family, const uint8_t *payload,
                                     size_t size, const uint8_t seed[32],
                                     uint8_t *out, size_t *in_out_size);

    bool run_polkadot_self_tests();

}

#endif
