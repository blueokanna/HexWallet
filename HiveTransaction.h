#ifndef HEXWALLET_HIVE_TRANSACTION_H
#define HEXWALLET_HIVE_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet {

// HIVE (graphene) native transfer.
//
// HIVE accounts are named, not derived from the key, so the device can only
// prove which public key signs. The review therefore shows the derived
// "STM..." key as the sender and labels the account name as host-provided.
//
// Payload (little-endian):
//   "HIV1"
//   u16 ref_block_num
//   u32 ref_block_prefix
//   u32 expiration
//   u8  from_size (1..16) + from[from_size]
//   u8  to_size   (1..16) + to[to_size]
//   u8  amount_size (8..16) + amount[amount_size]   "1.234 HIVE" / "1.234 HBD"
//   u8  memo_size (0..64) + printable ASCII memo[memo_size]
//
// Only one `transfer` operation is admitted; extensions must be empty and
// encrypted memos (`#...`) are rejected because their content cannot be shown.
constexpr size_t kHiveMaxNameSize = 16;
constexpr size_t kHiveMaxAmountSize = 16;
constexpr size_t kHiveMaxMemoSize = 64;
constexpr size_t kHivePayloadSize = 4 + 2 + 4 + 4 + 3 * (1 + kHiveMaxNameSize) +
                                    1 + kHiveMaxMemoSize;
constexpr uint8_t kHiveCollateral = 27 + 4;

ChainError hive_review_payload(const uint8_t *payload, size_t size,
                               const char *sender_key, ChainReview *review,
                               uint8_t digest[32]);
ChainError hive_sign_payload(const uint8_t *payload, size_t size,
                             const uint8_t private_key[32], uint8_t *out,
                             size_t *in_out_size);
bool run_hive_self_tests();

}  // namespace hexwallet

#endif
