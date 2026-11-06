#ifndef HEXWALLET_AETERNITY_TRANSACTION_H
#define HEXWALLET_AETERNITY_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet {

// Aeternity SpendTx (tag 12, version 1) on the ChainTransaction envelope.
//
// Every constant below comes from one real mainnet transaction
// (th_hyXNAEdi3bhJvs54qzY5ftBNcgfqQJ6VC8VcjfUCw5RcdD9HW, block 1377799):
//
//   payload  = rlp([12, 1, sender_id, recipient_id, amount, fee, ttl, nonce,
//                   payload])                          218 bytes
//   message  = "ae_mainnet" || payload                  what Ed25519 signs
//   signed   = rlp([11, 1, [signature], payload])       293 bytes
//   tx hash  = blake2b-256(signed)                      the th_ payload
//
// Two details are easy to get wrong from memory and are pinned by that vector:
// the network id is the nine-byte ASCII string, not a single 0x01 byte, and the
// text prefixes split by alphabet - `ak_`/`sg_`/`th_` are base58check while
// `tx_`/`ba_` are base64check.
constexpr size_t kAeternityPublicKeySize = 32;
constexpr size_t kAeternitySignatureSize = 64;
// The transaction payload field is a free-form byte string; 256 bytes covers an
// invoice id or a memo and keeps the signed transaction inside the 512-byte CLI
// buffer.
constexpr size_t kAeternityMaxTxPayload = 256;
constexpr size_t kAeternityMaxPayload = 512;
constexpr size_t kAeternityMaxSignedSize = 576;
constexpr uint8_t kAeternityDecimals = 18;

// Identifier tags from the upstream `id()` type. Only an account id can be
// rendered and verified as `ak_`, so the others are refused rather than guessed.
constexpr uint8_t kAeternityIdAccount = 1;

struct AeternitySpend {
  uint8_t sender[kAeternityPublicKeySize];
  uint8_t recipient[kAeternityPublicKeySize];
  uint8_t recipient_tag;
  uint64_t amount;
  uint64_t fee;
  uint64_t ttl;
  uint64_t nonce;
  uint8_t payload[kAeternityMaxTxPayload];
  size_t payload_size;
};

// Parses the payload, re-encodes it canonically and requires the two to match,
// so no byte can ride along outside the digest. `sender_public_key` is the
// wallet's own key: a payload built for another account is refused here.
ChainError aeternity_review_payload(const uint8_t *payload, size_t size,
                                    const uint8_t sender_public_key[32],
                                    ChainReview *review, uint8_t digest[32]);

// Signs "ae_mainnet" || payload and returns rlp([11, 1, [sig], payload]).
ChainError aeternity_sign_payload(const uint8_t *payload, size_t size,
                                  const uint8_t private_seed[32], uint8_t *out,
                                  size_t *in_out_size);

// blake2b-256 of a signed transaction, i.e. the 32 bytes a `th_` string carries.
bool aeternity_transaction_hash(const uint8_t *signed_tx, size_t size,
                               uint8_t out[32]);

// `tx_` (base64check) and `th_` (base58check) text forms, NUL terminated.
bool aeternity_encode_tx_text(const uint8_t *signed_tx, size_t size, char *out,
                             size_t out_size);
bool aeternity_encode_hash_text(const uint8_t hash[32], char *out,
                               size_t out_size);

// Pins the RLP layout, the message prefix and the hash function against the
// mainnet vector above, and checks that the parser refuses tampering.
bool run_aeternity_self_tests();

}  // namespace hexwallet

#endif
