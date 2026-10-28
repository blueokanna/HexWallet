#ifndef HEXWALLET_ERGO_TRANSACTION_H
#define HEXWALLET_ERGO_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet {

// Ergo P2PK (ProveDlog) transactions.
//
// The signed message is the Ergo transaction id preimage: the transaction
// serialized with empty spending proofs. Every input of a P2PK transaction
// signs those same bytes, so the device rebuilds them from the payload and
// hashes them with BLAKE2b-256 to obtain the transaction id it displays.
//
// Payload "ERG1" (all multi-byte fields explicit):
//   0   "ERG1"
//   4   u8 network (0 = mainnet)
//   5   u64 host_input_total_be[8]  (host supplied, shown as FEE (HOST))
//   13  u8 input_count (1..16)
//       input_count x { box_id[32], u16 tree_len_le, tree[tree_len] }
//       u8 data_input_count (0..16)
//       data_input_count x { box_id[32] }
//       u8 distinct_token_count (0..32)
//       distinct_token_count x { token_id[32] }
//       u8 output_count (1..32)
//       output_count x {
//         u64 value_be[8], u32 creation_height_le[4],
//         u16 tree_len_le, tree[tree_len],
//         u8 token_count (0..16), token_count x { u16 index_le, u64 amount_be[8] },
//         u8 register_count (0..6), register_count x { u16 len_le, bytes }
//       }
ChainError ergo_review_payload(const uint8_t *payload, size_t size,
                               const char *sender, ChainReview *review,
                               uint8_t digest[32]);

// Produces the fully serialized signed transaction. Every input box script must
// be P2PK for the derived public key; anything else is rejected rather than
// signed.
ChainError ergo_sign_payload(const uint8_t *payload, size_t size,
                             const uint8_t private_key[32], uint8_t *out,
                             size_t *in_out_size);

bool run_ergo_self_tests();

}  // namespace hexwallet

#endif
