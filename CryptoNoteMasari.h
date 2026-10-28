#ifndef HEXWALLET_CRYPTONOTE_MASARI_H
#define HEXWALLET_CRYPTONOTE_MASARI_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoNoteReview.h"
#include "CryptoNoteRingCt.h"
#include "CryptoNoteTransaction.h"

namespace hexwallet
{

  // Masari is a CryptoNote fork with its own RCT enum:
  //   1 = RCTTypeFull, 2 = RCTTypeSimple, 3 = RCTTypeBulletproof.
  // It predates Monero's compact amounts and CLSAG, so it uses the legacy
  // 64-byte ECDH tuple (mask || amount encrypted by scalar addition) and
  // MLSAG signatures. None of this may run through the Monero type-6 code.
  constexpr uint8_t kMasariRctFull = 1;
  constexpr uint8_t kMasariRctSimple = 2;
  constexpr uint8_t kMasariRctBulletproof = 3;

  constexpr size_t kMasariMaxTxInputs = 4;
  constexpr size_t kMasariMaxRingSize = 16;
  // A legacy Borromean proof is 6176 bytes per output. The transport and RAM
  // budget allow two of them; Masari's own wallet emits Bulletproofs for
  // larger transactions, which this path also accepts.
  constexpr size_t kMasariMaxTxOutputs = 4;
  constexpr size_t kMasariMaxTxExtra = 256;
  constexpr size_t kMasariMaxTxBytes = 16384;
  constexpr size_t kMasariBorromeanProofSize =
      64 * kCryptoNoteKeySize * 2 + kCryptoNoteKeySize + 64 * kCryptoNoteKeySize;
  constexpr size_t kMasariMaxProofRounds = 8;

  struct MasariInput
  {
    uint16_t offset_count;
    uint64_t key_offsets[kMasariMaxRingSize];
    uint8_t key_image[kCryptoNoteKeySize];
  };

  struct MasariOutput
  {
    uint8_t public_key[kCryptoNoteKeySize];
    uint8_t ecdh_mask[kCryptoNoteKeySize];
    uint8_t ecdh_amount[kCryptoNoteKeySize];
    uint8_t commitment[kCryptoNoteKeySize];
  };

  // MLSAG matrix: ss[ring member][row]. Simple RCT has 2 rows per input;
  // full RCT has one signature with (inputs + 1) rows.
  struct MasariMg
  {
    uint8_t rows;
    uint8_t cc[kCryptoNoteKeySize];
    // Flat [ring_member * rows + row] matrix, matching MLSAG's column-major
    // access order.
    uint8_t ss[kMasariMaxRingSize * (kMasariMaxTxInputs + 1)][kCryptoNoteKeySize];
  };

  struct MasariBulletproof
  {
    uint8_t a[kCryptoNoteKeySize];
    uint8_t s[kCryptoNoteKeySize];
    uint8_t t1[kCryptoNoteKeySize];
    uint8_t t2[kCryptoNoteKeySize];
    uint8_t taux[kCryptoNoteKeySize];
    uint8_t mu[kCryptoNoteKeySize];
    uint8_t a_scalar[kCryptoNoteKeySize];
    uint8_t b[kCryptoNoteKeySize];
    uint8_t t[kCryptoNoteKeySize];
    uint8_t l_count;
    uint8_t r_count;
    uint8_t l[kMasariMaxProofRounds][kCryptoNoteKeySize];
    uint8_t r[kMasariMaxProofRounds][kCryptoNoteKeySize];
  };

  struct MasariTransaction
  {
    uint16_t input_count;
    uint16_t output_count;
    MasariInput inputs[kMasariMaxTxInputs];
    MasariOutput outputs[kMasariMaxTxOutputs];
    uint16_t extra_size;
    uint8_t extra[kMasariMaxTxExtra];
    uint8_t rct_type;
    uint64_t fee;
    uint8_t pseudo_outs[kMasariMaxTxInputs][kCryptoNoteKeySize];
    uint8_t mg_count;
    MasariMg mgs[kMasariMaxTxInputs];
    uint8_t bp_count;
    MasariBulletproof bps[1];
    // Keccak(prefix || rct_base || proof_fields), the message MLSAG signs.
    uint8_t message[kCryptoNoteKeySize];
  };

  // Parses a version-2 Masari transaction. Range proofs are verified while
  // they are parsed and are never stored, so a huge Borromean proof costs no
  // RAM. Returns Unsupported for RCTTypeNull and malformed / oversized data.
  CryptoNoteTxError masari_parse_transaction(const uint8_t *data, size_t size,
                                             MasariTransaction *out);

  bool masari_tx_extra_public_key(const MasariTransaction &tx,
                                  uint8_t out[kCryptoNoteKeySize]);

  // Same contract as cryptonote_review_transaction: every amount, fee,
  // destination and key image is re-derived. Legacy ECDH is decoded here.
  struct MasariReviewInput
  {
    uint64_t amount;
    uint16_t real_index;
    uint16_t ring_size;
    uint8_t original_tx_public[kCryptoNoteKeySize];
    uint64_t output_index;
    const CryptoNoteRingMember *ring;
    const uint64_t *key_offsets;
    uint8_t pseudo_out_mask[kCryptoNoteKeySize];
    // Subaddress that owns this output; (0, 0) is the standard address.
    uint32_t subaddress_major;
    uint32_t subaddress_minor;
  };

  struct MasariReviewOutput
  {
    bool change;
    uint8_t address_type;
    uint8_t spend_public[kCryptoNoteKeySize];
    uint8_t view_public[kCryptoNoteKeySize];
    uint64_t amount;
    // Type-1 (full RCT) only: every output blinding factor, so the single
    // MLSAG can sign the sum row. For simple/bulletproof this is unused.
    uint8_t mask[kCryptoNoteKeySize];
    // Claimed subaddress of a change output; ignored for external outputs.
    uint32_t subaddress_major;
    uint32_t subaddress_minor;
  };

  struct MasariReviewResult
  {
    CryptoNoteReviewSummary summary;
    // z = c_a - c_out per input (simple/bulletproof), or the summed z for the
    // last row of a full-RCT signature (only entry 0 is used).
    uint8_t signing_mask[kMasariMaxTxInputs][kCryptoNoteKeySize];
    uint8_t message[kCryptoNoteKeySize];
  };

  CryptoNoteTxError masari_review_transaction(
      MasariTransaction *tx,
      const uint8_t view_secret[kCryptoNoteKeySize],
      const uint8_t spend_secret[kCryptoNoteKeySize],
      const uint8_t tx_secret[kCryptoNoteKeySize],
      const MasariReviewInput *inputs, size_t input_count,
      const MasariReviewOutput *outputs, size_t output_count,
      MasariReviewResult *result);

  // Signs the reviewed MLSAGs and writes a compact signature blob:
  //   version(1) | mg_count(1) | rows(1) | ring_size(1) | message(32)
  //   then per MG: cc(32) | ss[ring][rows](32 each)
  // The phone merges the blob into the transaction it built. Proofs and the
  // transaction body never need to be re-serialized.
  CryptoNoteTxError masari_sign_transaction(
      MasariTransaction *tx, const MasariReviewResult &review,
      const uint8_t view_secret[kCryptoNoteKeySize],
      const uint8_t spend_secret[kCryptoNoteKeySize],
      const MasariReviewInput *inputs, size_t input_count,
      const uint8_t nonce_seed[kCryptoNoteKeySize], uint8_t *out,
      size_t *in_out_size);

  // Exposed for the host self-test and for defence-in-depth checks.
  bool masari_mlsag_verify(const uint8_t message[kCryptoNoteKeySize],
                           const uint8_t (*matrix)[kCryptoNoteKeySize],
                           size_t columns, size_t rows, size_t ds_rows,
                           const uint8_t cc[kCryptoNoteKeySize],
                           const uint8_t (*ss)[kCryptoNoteKeySize],
                           const uint8_t (*key_images)[kCryptoNoteKeySize]);

  bool run_masari_self_tests();

  int masari_last_stage();
  int masari_last_error();

  // Masari's RCTTypeBulletproof (type 3) verifier is implemented but has no
  // mainnet transaction vector yet, so the parser refuses those transactions by
  // default. Run tools/fetch_masari_bulletproof_vector.py against a Masari node
  // to obtain tests/fixtures/masari/tx3.bin, let the host self-test validate it,
  // and only then build shipping firmware with
  // -DHEXWALLET_MSR_ENABLE_RCT_TYPE3=1.
  bool masari_rct_type3_enabled();

  // Byte offset of the RCT type field in the last parsed transaction. Diagnostic
  // for the tamper tests; MTAs never see it.
  size_t masari_last_rct_type_offset();

} // namespace hexwallet

#endif
