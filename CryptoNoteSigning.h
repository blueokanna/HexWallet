#ifndef HEXWALLET_CRYPTONOTE_SIGNING_H
#define HEXWALLET_CRYPTONOTE_SIGNING_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoNoteReview.h"
#include "CryptoNoteTransaction.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  constexpr size_t kCryptoNoteMaxSignInputs = 8;
  constexpr size_t kCryptoNoteMaxSignOutputs = kCryptoNoteMaxTxOutputs;
  constexpr uint8_t kCryptoNoteSigningPayloadVersion = 2;
  constexpr uint8_t kCryptoNoteSigningPayloadVersionAdditionalKeys = 3;
  constexpr uint8_t kCryptoNoteSigningPayloadVersionStandardOnly = 1;
  constexpr size_t kCryptoNoteMaxSigningPayload = 16384;

  struct CryptoNoteSigningInput
  {
    uint64_t amount;
    uint16_t real_index;
    uint16_t ring_size;
    uint8_t original_tx_public[kCryptoNoteKeySize];
    uint64_t output_index;
    uint8_t pseudo_out_mask[kCryptoNoteKeySize];
    uint64_t key_offsets[kCryptoNoteMaxRingSize];
    CryptoNoteRingMember ring[kCryptoNoteMaxRingSize];
    // Subaddress that owns this output; (0, 0) is the standard address.
    uint32_t subaddress_major;
    uint32_t subaddress_minor;
  };

  struct CryptoNoteSigningOutput
  {
    bool change;
    uint8_t address_type;
    uint8_t tx_key_index;
    uint8_t spend_public[kCryptoNoteKeySize];
    uint8_t view_public[kCryptoNoteKeySize];
    uint64_t amount;
    uint32_t subaddress_major;
    uint32_t subaddress_minor;
  };

  // Fully reviewed spend that is waiting for the on-device APPROVE button.
  // No master key material is kept here; the one-time secrets are re-derived
  // from the seed inside cryptonote_signing_sign().
  struct CryptoNoteSigningState
  {
    CryptoNoteReviewNetwork network;
    CryptoNoteTransaction transaction;
    uint8_t tx_secret[kCryptoNoteKeySize];
    uint8_t additional_tx_key_count;
    uint8_t additional_tx_secrets[kCryptoNoteMaxSignOutputs][kCryptoNoteKeySize];
    uint32_t address_index;
    uint8_t input_count;
    uint8_t output_count;
    uint8_t ring_size;
    CryptoNoteSigningInput inputs[kCryptoNoteMaxSignInputs];
    CryptoNoteSigningOutput outputs[kCryptoNoteMaxSignOutputs];
    uint8_t signing_mask[kCryptoNoteMaxSignInputs][kCryptoNoteKeySize];
    CryptoNoteReviewSummary summary;
  };

  static_assert(sizeof(CryptoNoteSigningState) <= 32 * 1024,
                "CryptoNoteSigningState exceeds the static RAM budget");

  CryptoNoteTxError cryptonote_signing_prepare(
      const char *network_id, const uint8_t *payload, size_t payload_size,
      const uint8_t seed[kSeedSize], CryptoNoteSigningState *state);

  CryptoNoteTxError cryptonote_signing_sign(
      CryptoNoteSigningState *state, const uint8_t seed[kSeedSize],
      const uint8_t nonce_seed[kCryptoNoteKeySize], uint8_t *out,
      size_t *in_out_size);

  CryptoNoteTxError cryptonote_signing_prepare_with_keys(
      const char *network_id, const uint8_t *payload, size_t payload_size,
      const uint8_t view_secret[kCryptoNoteKeySize],
      const uint8_t spend_secret[kCryptoNoteKeySize],
      CryptoNoteSigningState *state);

  CryptoNoteTxError cryptonote_signing_sign_with_keys(
      CryptoNoteSigningState *state,
      const uint8_t view_secret[kCryptoNoteKeySize],
      const uint8_t spend_secret[kCryptoNoteKeySize],
      const uint8_t nonce_seed[kCryptoNoteKeySize], uint8_t *out,
      size_t *in_out_size);

  void cryptonote_signing_clear(CryptoNoteSigningState *state);

  bool run_cryptonote_signing_self_tests();

  int cryptonote_signing_last_stage();
  int cryptonote_signing_last_error();

}

#endif
