#ifndef HEXWALLET_CRYPTONOTE_SIGNING_H
#define HEXWALLET_CRYPTONOTE_SIGNING_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoNoteMasari.h"
#include "CryptoNoteReview.h"
#include "CryptoNoteTransaction.h"
#include "WalletSecurity.h"

namespace hexwallet
{

  // A host may propose at most this many inputs for one CryptoNote spend. The
  // limit keeps the reviewed request inside the link payload and the device
  // RAM budget; larger transactions must be split by the host wallet.
  constexpr size_t kCryptoNoteMaxSignInputs = 8;
  constexpr size_t kCryptoNoteMaxSignOutputs = kCryptoNoteMaxTxOutputs;
  // Version 1 carries only standard-address inputs/outputs. Version 2 appends
  // the owning subaddress (major, minor) to every input and output record.
  constexpr uint8_t kCryptoNoteSigningPayloadVersion = 2;
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
    // Wire value 0 = standard, 1 = subaddress. Only 0 is currently admitted:
    // subaddress outputs need additional transaction-public-key binding.
    uint8_t address_type;
    uint8_t spend_public[kCryptoNoteKeySize];
    uint8_t view_public[kCryptoNoteKeySize];
    uint64_t amount;
    // Masari RCT type 1 (full) needs every output blinding factor for its
    // single MLSAG. Unused by the Monero type-6 path.
    uint8_t mask[kCryptoNoteKeySize];
    // Reserved output indices: both must be zero until subaddress sends have
    // independent transaction and receiver-scanning evidence.
    uint32_t subaddress_major;
    uint32_t subaddress_minor;
  };

  // Fully reviewed spend that is waiting for the on-device APPROVE button.
  // No master key material is kept here; the one-time secrets are re-derived
  // from the seed inside cryptonote_signing_sign().
  struct CryptoNoteSigningState
  {
    CryptoNoteReviewNetwork network;
    union {
      CryptoNoteTransaction monero;
      MasariTransaction masari;
    } chain;
    uint8_t tx_secret[kCryptoNoteKeySize];
    uint32_t address_index;
    uint8_t input_count;
    uint8_t output_count;
    uint8_t ring_size;
    CryptoNoteSigningInput inputs[kCryptoNoteMaxSignInputs];
    CryptoNoteSigningOutput outputs[kCryptoNoteMaxSignOutputs];
    uint8_t signing_mask[kCryptoNoteMaxSignInputs][kCryptoNoteKeySize];
    CryptoNoteReviewSummary summary;
  };

  // Static session budget: this struct lives in .bss for the whole session, so
  // it must never grow silently past what the target MCUs can spare.
  static_assert(sizeof(CryptoNoteSigningState) <= 32 * 1024,
                "CryptoNoteSigningState exceeds the static RAM budget");

  // Parses and fully verifies a host-proposed CryptoNote transaction. This is
  // the only path that fills CryptoNoteSigningState: the summary it returns is
  // therefore the reviewed truth and safe to render.
  CryptoNoteTxError cryptonote_signing_prepare(
      const char *network_id, const uint8_t *payload, size_t payload_size,
      const uint8_t seed[kSeedSize], CryptoNoteSigningState *state);

  // Signs every input with a fresh, per-input nonce derived from `nonce_seed`
  // and returns the serialized transaction. The state is zeroized on both
  // success and failure.
  CryptoNoteTxError cryptonote_signing_sign(
      CryptoNoteSigningState *state, const uint8_t seed[kSeedSize],
      const uint8_t nonce_seed[kCryptoNoteKeySize], uint8_t *out,
      size_t *in_out_size);

  // Core entry points used by the firmware (which derives the keys from the
  // seed) and by the host tests (which use the public reference fixture).
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

  // Diagnostics for the boot self-test.
  int cryptonote_signing_last_stage();
  int cryptonote_signing_last_error();

} // namespace hexwallet

#endif
