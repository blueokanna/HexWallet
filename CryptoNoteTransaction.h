#ifndef HEXWALLET_CRYPTONOTE_TRANSACTION_H
#define HEXWALLET_CRYPTONOTE_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoNoteRingCt.h"

namespace hexwallet
{
  constexpr size_t kCryptoNoteMaxTxInputs = 8;
  constexpr size_t kCryptoNoteMaxTxOutputs = 16;
  // tx_extra carries the tx public key plus, commonly, a nonce and sometimes a
  // payment id or merge-mining tag. Real mainnet transactions reach 160+ bytes,
  // so the cap has to leave room for them.
  constexpr size_t kCryptoNoteMaxTxExtra = 256;
  constexpr size_t kCryptoNoteMaxBpProofs = 2;
  constexpr size_t kCryptoNoteMaxBpLr = 10;
  constexpr size_t kCryptoNoteMaxTxBytes = 6144;
  constexpr uint64_t kCryptoNoteMaxFee = 1000000000000ULL;

  enum class CryptoNoteTxError : uint8_t
  {
    Ok = 0,
    InvalidArgument,
    Truncated,
    NonCanonical, // non-minimal varint or trailing bytes
    Unsupported,  // not version 2 / not RCT type 6 / unsupported input type
    TooLarge,
    TooManyItems,
    InvalidAmount, // nonzero amount in an RCT output, or fee out of range
    CryptoFailure,
    BufferTooSmall,
    FeePolicy,    // local wallet spending policy, not a consensus fee limit
  };

  struct CryptoNoteTxInput
  {
    uint8_t key_image[kCryptoNoteKeySize];
    uint16_t key_offset_count;
    uint64_t key_offsets[kCryptoNoteMaxRingSize];
    uint8_t s[kCryptoNoteMaxRingSize][kCryptoNoteKeySize];
    uint8_t c1[kCryptoNoteKeySize];
    uint8_t d[kCryptoNoteKeySize];
  };

  struct CryptoNoteTxOutput
  {
    bool tagged;
    uint8_t view_tag;
    uint8_t public_key[kCryptoNoteKeySize];
    uint8_t ecdh_amount[8];
    uint8_t commitment[kCryptoNoteKeySize];
  };

  struct CryptoNoteBpPlusProof
  {
    uint8_t a[kCryptoNoteKeySize];
    uint8_t a1[kCryptoNoteKeySize];
    uint8_t b[kCryptoNoteKeySize];
    uint8_t r1[kCryptoNoteKeySize];
    uint8_t s1[kCryptoNoteKeySize];
    uint8_t d1[kCryptoNoteKeySize];
    uint8_t l_count;
    uint8_t r_count;
    uint8_t l[kCryptoNoteMaxBpLr][kCryptoNoteKeySize];
    uint8_t r[kCryptoNoteMaxBpLr][kCryptoNoteKeySize];
  };

  struct CryptoNoteRctData
  {
    uint8_t type; // must be 6
    uint64_t fee;
    uint8_t proof_count;
    CryptoNoteBpPlusProof proofs[kCryptoNoteMaxBpProofs];
    uint8_t pseudo_outs[kCryptoNoteMaxTxInputs][kCryptoNoteKeySize];
    uint16_t ring_size;
  };

  struct CryptoNoteTransaction
  {
    uint64_t version;
    uint64_t unlock_time;
    uint16_t input_count;
    CryptoNoteTxInput inputs[kCryptoNoteMaxTxInputs];
    uint16_t output_count;
    CryptoNoteTxOutput outputs[kCryptoNoteMaxTxOutputs];
    uint16_t extra_size;
    uint8_t extra[kCryptoNoteMaxTxExtra];
    CryptoNoteRctData rct;
  };

  CryptoNoteTxError cryptonote_parse_transaction(const uint8_t *data, size_t size,
                                                 CryptoNoteTransaction *out);

  CryptoNoteTxError cryptonote_serialize_transaction(const CryptoNoteTransaction &tx,
                                                     uint8_t *out,
                                                     size_t *in_out_size);

  bool cryptonote_transaction_balance_ok(const CryptoNoteTransaction &tx);

  // Ring size every input must use for the current network rules.
  bool cryptonote_transaction_ring_uniform(const CryptoNoteTransaction &tx,
                                           uint16_t *out_ring_size);

  CryptoNoteTxError cryptonote_transaction_prefix_hash(
      const CryptoNoteTransaction &tx, uint8_t out[32]);
  CryptoNoteTxError cryptonote_transaction_rct_base_hash(
      const CryptoNoteTransaction &tx, uint8_t out[32]);
  CryptoNoteTxError cryptonote_transaction_hash(
      const CryptoNoteTransaction &tx, uint8_t out[32]);
  CryptoNoteTxError cryptonote_transaction_signing_hash(
      const CryptoNoteTransaction &tx, uint8_t out[32]);

  CryptoNoteTxError cryptonote_sign_input(CryptoNoteTransaction *tx,
                                          uint16_t input_index,
                                          uint16_t real_index,
                                          const CryptoNoteRingMember *ring,
                                          const uint8_t spend_secret[32],
                                          const uint8_t commitment_mask[32],
                                          const uint8_t nonce_seed[32]);

  const char *cryptonote_tx_error_text(CryptoNoteTxError error);
  void clear_cryptonote_transaction(CryptoNoteTransaction *tx);

  bool run_cryptonote_transaction_self_tests();
  bool run_cryptonote_mainnet_vector_self_test();

} // namespace hexwallet

#endif
