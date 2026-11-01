#ifndef HEXWALLET_CRYPTONOTE_OUTPUT_SCAN_H
#define HEXWALLET_CRYPTONOTE_OUTPUT_SCAN_H
#include "CryptoNoteAmounts.h"
namespace hexwallet
{
    bool cryptonote_scan_output(const uint8_t view_secret[32],
                                const uint8_t spend_public[32], const uint8_t tx_public[32],
                                uint64_t output_index, const uint8_t output_public[32],
                                RingCtAmountEncoding encoding, const uint8_t *ecdh, size_t ecdh_size,
                                const uint8_t commitment[32], uint64_t *amount);
    bool run_cryptonote_output_scan_self_tests();
}
#endif
