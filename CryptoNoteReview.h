#ifndef HEXWALLET_CRYPTONOTE_REVIEW_H
#define HEXWALLET_CRYPTONOTE_REVIEW_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoNoteRingCt.h"
#include "CryptoNoteTransaction.h"

namespace hexwallet
{
  enum class CryptoNoteReviewNetwork : uint8_t
  {
    MoneroMainnet,
    MasariMainnet
  };
  struct CryptoNoteReviewPolicy
  {
    CryptoNoteReviewNetwork network;
    uint64_t max_fee_atomic;
    uint16_t ring_size;
    uint8_t max_inputs;
    uint8_t max_outputs;
  };

  const CryptoNoteReviewPolicy *cryptonote_review_policy(const char *network_id);
  const CryptoNoteReviewPolicy *cryptonote_review_policy(
      CryptoNoteReviewNetwork network);

  CryptoNoteTxError cryptonote_review_fee_policy(CryptoNoteReviewNetwork network,
                                                 uint64_t fee);
  struct CryptoNoteReviewInput
  {
    uint64_t amount;     // scanned from the chain
    uint16_t real_index; // position of our output in the ring
    uint16_t ring_size;
    uint8_t original_tx_public[kCryptoNoteKeySize]; // tx public key that created our output
    uint64_t output_index;                          // our output's index in that transaction
    const CryptoNoteRingMember *ring;               // ring_size entries: dest + commitment
    const uint64_t *key_offsets;                    // ring_size entries
    uint8_t pseudo_out_mask[kCryptoNoteKeySize];    // c_out, the host's pseudo output mask
    // Subaddress that owns this output. (0, 0) is the standard address.
    uint32_t subaddress_major;
    uint32_t subaddress_minor;
  };

  struct CryptoNoteReviewOutput
  {
    bool change;
    uint8_t address_type; // 0 standard; 1 subaddress
    // 0 selects the primary transaction secret. A nonzero value is one-based
    // and selects the corresponding additional transaction secret. Monero
    // binds additional key i to output i, so the review layer checks that
    // relationship against tx_extra as well as against the output keys.
    uint8_t tx_key_index;
    uint8_t spend_public[kCryptoNoteKeySize];
    uint8_t view_public[kCryptoNoteKeySize];
    uint64_t amount;
    uint8_t mask[kCryptoNoteKeySize];
    // Claimed subaddress of a change output. External subaddresses carry
    // their public keys directly and leave these indices at zero.
    uint32_t subaddress_major;
    uint32_t subaddress_minor;
  };

  struct CryptoNoteReviewSummary
  {
    uint64_t total_input;
    uint64_t total_output;
    uint64_t change;
    uint64_t fee;
    uint8_t output_count;
    uint8_t input_count;
    bool decoys_host_supplied;
  };

  struct CryptoNoteReviewResult
  {
    CryptoNoteReviewSummary summary;
    uint8_t signing_mask[kCryptoNoteMaxTxInputs][kCryptoNoteKeySize];
  };

  CryptoNoteTxError cryptonote_review_transaction(
      const CryptoNoteTransaction &tx,
      const uint8_t view_secret[kCryptoNoteKeySize],
      const uint8_t spend_secret[kCryptoNoteKeySize],
      const uint8_t tx_secret[kCryptoNoteKeySize],
      const CryptoNoteReviewInput *inputs, size_t input_count,
      const CryptoNoteReviewOutput *outputs, size_t output_count,
      CryptoNoteReviewResult *result);

  // Monero destinations that mix standard addresses and subaddresses use one
  // additional transaction secret per output. The secrets are supplied by the
  // host only as transaction-construction witnesses; the device verifies their
  // public keys, tx_extra placement and output derivations before review.
  CryptoNoteTxError cryptonote_review_transaction_with_additional_keys(
      const CryptoNoteTransaction &tx,
      const uint8_t view_secret[kCryptoNoteKeySize],
      const uint8_t spend_secret[kCryptoNoteKeySize],
      const uint8_t tx_secret[kCryptoNoteKeySize],
      const uint8_t additional_tx_secrets[][kCryptoNoteKeySize],
      size_t additional_tx_key_count,
      const CryptoNoteReviewInput *inputs, size_t input_count,
      const CryptoNoteReviewOutput *outputs, size_t output_count,
      CryptoNoteReviewResult *result);

  bool cryptonote_tx_extra_public_key(const CryptoNoteTransaction &tx,
                                      uint8_t out[kCryptoNoteKeySize]);

  struct CryptoNoteTxExtraPublicKeys
  {
    uint8_t primary[kCryptoNoteKeySize];
    uint8_t additional_count;
    uint8_t additional[kCryptoNoteMaxTxOutputs][kCryptoNoteKeySize];
  };

  // Restricted signing schema: one primary public key, at most one nonce,
  // optional additional public-key vector, and optional trailing zero padding.
  // Unknown, duplicate, non-canonical or truncated fields are rejected.
  bool cryptonote_review_extra_public_keys(
      const uint8_t *extra, size_t size, CryptoNoteTxExtraPublicKeys *out);

  bool cryptonote_review_extra_public_key(const uint8_t *extra, size_t size,
                                          uint8_t out[kCryptoNoteKeySize]);

  bool run_cryptonote_review_self_tests();

  int cryptonote_review_last_stage();
  int cryptonote_review_last_error();

}

#endif
