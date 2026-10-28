#ifndef HEXWALLET_ICON_TRANSACTION_H
#define HEXWALLET_ICON_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet {

constexpr size_t kIconPayloadSize = 69;
constexpr uint32_t kIconMainnetNid = 1;
constexpr size_t kIconMaxSerialized = 384;

// Compact review payload (little-endian integers):
//   "ICX1" | u32 nid | u64 nonce | u64 step_limit | u64 timestamp_us |
//   u8 value_be[16] | u8 to_size (must be 20) | u8 to[20]
// Native ICX transfer only (data type "call" with an empty data field). The
// sender is the wallet-derived address and is never taken from the host.
ChainError icon_review_payload(const uint8_t *payload, size_t size,
                               const char *sender, ChainReview *review,
                               uint8_t digest[32]);

// Canonical `icx_sendTransaction.<key>.<value>` text used for the SHA3-256
// signature hash. Exposed so a host test can pin the reference vector.
ChainError icon_serialize_payload(const uint8_t *payload, size_t size,
                                  const char *sender, char *out,
                                  size_t out_size);

// Returns the 65-byte recoverable r || s || recovery-id signature.
ChainError icon_sign_payload(const uint8_t *payload, size_t size,
                             const uint8_t private_key[32], const char *sender,
                             uint8_t *out, size_t *in_out_size);

bool run_icon_self_tests();

}  // namespace hexwallet

#endif
