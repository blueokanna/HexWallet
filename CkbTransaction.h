#ifndef HEXWALLET_CKB_TRANSACTION_H
#define HEXWALLET_CKB_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet {

// Nervos CKB native CKB transfer.
//
// The payload is a deliberately narrow subset: exactly one input and one or
// two outputs, all locked by the standard SECP256K1/blake160 lock script with
// no type script. Output 0 is the recipient; output 1, when present, is the
// wallet change cell and must carry the wallet's own lock args.
//
// Layout (little endian):
//   "CKB1"
//   u8 input_count (= 1)
//   input: tx_hash[32], index u32, since u64, capacity u64
//   u8 output_count (1..2)
//   output: capacity u64, lock_args[20]
//
// The trusted display derives the recipient address from lock_args, so a
// tampered host cannot substitute an address string.
constexpr size_t kCkbPayloadSize = 5 + 52 + 1 + 2 * 28;

ChainError ckb_review_payload(const uint8_t *payload, size_t size,
                              const uint8_t public_key[33], const char *sender,
                              ChainReview *review, uint8_t digest[32]);
ChainError ckb_sign_payload(const uint8_t *payload, size_t size,
                            const uint8_t private_key[32], uint8_t *out,
                            size_t *in_out_size);
bool run_ckb_self_tests();

}  // namespace hexwallet

#endif
