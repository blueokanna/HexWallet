#ifndef HEXWALLET_CRYPTONOTE_TRANSACTION_H
#define HEXWALLET_CRYPTONOTE_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoNoteRingCt.h"

namespace hexwallet {

// Monero / Masari transaction layer, version 2 RingCT with CLSAG plus
// Bulletproofs+ (RCT type 6, the format every current wallet produces).
//
// Scope, stated precisely:
//   * This module parses, validates and re-serializes the wire format, and
//     checks the commitment balance Sigma(pseudoOut) == Sigma(outPk) + fee*H.
//   * It does NOT verify the Bulletproofs+ range proofs and does NOT produce
//     CLSAG signatures yet. Those two steps are gated on external vectors; see
//     AUDIT.md. Signing is therefore still not reachable from the catalog.
//
// Every field is stored in a fixed-capacity structure so the parser performs
// no dynamic allocation, and every length is checked against a compile-time
// bound before use.

// kCryptoNoteKeySize (32) and kCryptoNoteMaxRingSize (16) come from
// CryptoNoteRingCt.h so the key layer and the wire layer cannot drift.
constexpr size_t kCryptoNoteMaxTxInputs = 8;
constexpr size_t kCryptoNoteMaxTxOutputs = 16;
constexpr size_t kCryptoNoteMaxTxExtra = 128;
constexpr size_t kCryptoNoteMaxBpProofs = 2;
// A Bulletproofs+ proof over M*N values has log2(M*N) L/R terms. 16 outputs
// times 64 bits caps out at 10, which is also the upstream limit check.
constexpr size_t kCryptoNoteMaxBpLr = 10;
constexpr size_t kCryptoNoteMaxTxBytes = 6144;
// Upstream consensus cap; anything larger is rejected before it reaches the
// device. Monero's own limit is 2^16 in the CT layer.
constexpr uint64_t kCryptoNoteMaxFee = 1000000000000ULL;

enum class CryptoNoteTxError : uint8_t {
  Ok = 0,
  InvalidArgument,
  Truncated,
  NonCanonical,   // non-minimal varint or trailing bytes
  Unsupported,    // not version 2 / not RCT type 6 / unsupported input type
  TooLarge,
  TooManyItems,
  InvalidAmount,  // nonzero amount in an RCT output, or fee out of range
  CryptoFailure,
  BufferTooSmall,
};

struct CryptoNoteTxInput {
  uint8_t key_image[kCryptoNoteKeySize];
  uint16_t key_offset_count;
  uint64_t key_offsets[kCryptoNoteMaxRingSize];
  // CLSAG for this input. Serialized as s[ring], c1, D; the key image inside
  // the signature is the txin key image above (upstream does not re-serialize
  // it), so it is kept once.
  uint8_t s[kCryptoNoteMaxRingSize][kCryptoNoteKeySize];
  uint8_t c1[kCryptoNoteKeySize];
  uint8_t d[kCryptoNoteKeySize];
};

struct CryptoNoteTxOutput {
  bool tagged;  // txout_to_tagged_key (type 3) rather than txout_to_key (2)
  uint8_t view_tag;
  uint8_t public_key[kCryptoNoteKeySize];
  // 8-byte truncated amount from ecdhInfo (type 4 and later).
  uint8_t ecdh_amount[8];
  // Full commitment (outPk[i]); the range proof commits to the same value.
  uint8_t commitment[kCryptoNoteKeySize];
};

struct CryptoNoteBpPlusProof {
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

struct CryptoNoteRctData {
  uint8_t type;  // must be 6
  uint64_t fee;
  uint8_t proof_count;
  CryptoNoteBpPlusProof proofs[kCryptoNoteMaxBpProofs];
  // pseudoOuts follow the CLSAG signatures on the wire and have no length
  // prefix: the count is the input count.
  uint8_t pseudo_outs[kCryptoNoteMaxTxInputs][kCryptoNoteKeySize];
  uint16_t ring_size;
};

struct CryptoNoteTransaction {
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

// Strict parser. Rejects non-minimal varints, unknown input/output/target
// types, unsupported RCT types, oversized vectors and any trailing bytes.
CryptoNoteTxError cryptonote_parse_transaction(const uint8_t *data, size_t size,
                                               CryptoNoteTransaction *out);

// Byte-exact re-serialization of a parsed (or locally built) transaction.
// On failure the output buffer is cleared and in_out_size is set to 0.
CryptoNoteTxError cryptonote_serialize_transaction(const CryptoNoteTransaction &tx,
                                                   uint8_t *out,
                                                   size_t *in_out_size);

// Sigma(pseudoOut) == Sigma(outPk) + fee*H, using the Ed25519 group. This is
// the check that stops a phone from hiding value in a transaction the device
// is about to review. It does not replace range-proof verification.
bool cryptonote_transaction_balance_ok(const CryptoNoteTransaction &tx);

// Ring size every input must use for the current network rules.
bool cryptonote_transaction_ring_uniform(const CryptoNoteTransaction &tx,
                                         uint16_t *out_ring_size);

const char *cryptonote_tx_error_text(CryptoNoteTxError error);
void clear_cryptonote_transaction(CryptoNoteTransaction *tx);

bool run_cryptonote_transaction_self_tests();

}  // namespace hexwallet

#endif
