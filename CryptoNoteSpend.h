#ifndef HEXWALLET_CRYPTONOTE_SPEND_H
#define HEXWALLET_CRYPTONOTE_SPEND_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoNoteRingCt.h"
#include "CryptoNoteTransaction.h"

namespace hexwallet
{

  constexpr size_t kCryptoNoteMaxSpendInputs = kCryptoNoteMaxTxInputs;
  constexpr size_t kCryptoNoteMaxSpendOutputs = kCryptoNoteMaxTxOutputs;

  struct CryptoNoteSpendInput
  {
    uint64_t amount;
    uint8_t mask[kCryptoNoteKeySize];
    uint8_t commitment[kCryptoNoteKeySize];
    uint8_t spend_secret[kCryptoNoteKeySize];
    uint16_t real_index;
    uint16_t ring_size;
    CryptoNoteRingMember ring[kCryptoNoteMaxRingSize];
    uint64_t key_offsets[kCryptoNoteMaxRingSize];
  };

  struct CryptoNoteSpendOutput
  {
    uint8_t spend_public[kCryptoNoteKeySize];
    uint8_t view_public[kCryptoNoteKeySize];
    uint64_t amount;
    bool change;
  };

  CryptoNoteTxError cryptonote_build_spend_transaction(
      const CryptoNoteSpendInput *inputs, size_t input_count,
      const CryptoNoteSpendOutput *outputs, size_t output_count, uint64_t fee,
      const uint8_t entropy[kCryptoNoteKeySize], CryptoNoteTransaction *out,
      const CryptoNoteBpPlusProof *proofs, size_t proof_count,
      // Optional: receives the pseudo output masks the builder derived, so a
      // caller can audit the transaction without re-deriving them. Points at
      // kCryptoNoteMaxTxInputs * kCryptoNoteKeySize bytes, or is null.
      uint8_t *pseudo_masks_out = nullptr);

  // The transaction secret key derived from `entropy`, so a caller that built a
  // transaction can reproduce it for review. Same derivation the builder uses.
  bool cryptonote_spend_tx_secret(const uint8_t entropy[kCryptoNoteKeySize],
                                  uint8_t out[kCryptoNoteKeySize]);

  bool run_cryptonote_spend_self_tests();

} // namespace hexwallet

#endif
