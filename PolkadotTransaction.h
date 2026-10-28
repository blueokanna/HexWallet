#ifndef HEXWALLET_POLKADOT_TRANSACTION_H
#define HEXWALLET_POLKADOT_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet {

constexpr size_t kPolkadotPayloadSize = 130;   // "DOT1": immortal era, tip 0
constexpr size_t kPolkadotPayloadSizeV2 = 156; // "DOT2": mortal era + tip
constexpr size_t kPolkadotMaxSigned = 320;

// Compact review payload. Integers little-endian except amounts, which are
// big-endian. Two layouts are admitted:
//
//   "DOT1" | u8 network | u8 call | recipient[32] | amount_be[16] |
//   u32 nonce | u32 spec_version | u32 transaction_version |
//   genesis[32] | block_hash[32]                       (immortal, tip = 0)
//
//   "DOT2" | u8 network | u8 call | recipient[32] | amount_be[16] |
//   u32 nonce | u32 spec_version | u32 transaction_version |
//   tip_be[16] | u16 era_period | u64 era_block |
//   genesis[32] | era_block_hash[32]                   (mortal or immortal)
//
// network: 0 PolkaDOT (SS58 0), 2 Kusama (SS58 2).
// call:    0 balances.transfer, 3 balances.transferKeepAlive.
// era_period == 0 selects the immortal era; otherwise it must be a power of
// two in [4, 65536] and era_block_hash must be the hash of the era birth block
// (era_block - era_block % era_period). The genesis hash is pinned per network,
// so a DOT payload cannot be signed as KSM.
ChainError polkadot_review_payload(ChainFamily family, const uint8_t *payload,
                                   size_t size, const char *sender,
                                   ChainReview *review, uint8_t digest[32]);

// Returns the signed extrinsic, including the SCALE compact length prefix.
ChainError polkadot_sign_payload(ChainFamily family, const uint8_t *payload,
                                 size_t size, const uint8_t seed[32],
                                 uint8_t *out, size_t *in_out_size);

bool run_polkadot_self_tests();

}  // namespace hexwallet

#endif
