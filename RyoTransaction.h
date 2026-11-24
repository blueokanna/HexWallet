#ifndef HEXWALLET_RYO_TRANSACTION_H
#define HEXWALLET_RYO_TRANSACTION_H
#include <stddef.h>
#include <stdint.h>
#include "RyoBulletproof.h"
#include "RyoMlsag.h"

namespace hexwallet {
constexpr size_t kRyoMaxTxInputs = 8;
constexpr size_t kRyoMaxTxOutputs = 16;
constexpr size_t kRyoMaxTxExtra = 256;
constexpr size_t kRyoMaxTxBytes = 128 * 1024;

enum class RyoTxError : uint8_t {
  Ok, InvalidArgument, Truncated, NonCanonical, Unsupported, TooLarge,
  InvalidPoint, InvalidScalar, InvalidProof, InvalidBalance, InvalidSignature
};

struct RyoTxInputView {
  const uint8_t *relative_offsets;
  size_t offsets_size;
  const uint8_t *key_image;
  const uint8_t *responses; // ring_size * 2 * 32, no vector length on the wire
  const uint8_t *challenge;
  const uint8_t *pseudo_out;
};
struct RyoTxOutputView {
  const uint8_t *destination;
  const uint8_t *ecdh; // legacy scalar mask[32] || scalar amount[32]
  const uint8_t *commitment;
};

// Borrowed immutable transaction data. Parsing validates lengths and canonical
// wire structure only, not ownership, range proofs, MLSAGs or user approval.
// The buffer must outlive the view and must not overlap the view object.
struct RyoTransactionView {
  uint8_t version;
  uint64_t unlock_time;
  uint64_t fee;
  uint16_t ring_size;
  uint8_t input_count;
  uint8_t output_count;
  const uint8_t *bytes;
  size_t size;
  size_t prefix_size;
  size_t base_size; // length after prefix, before the prunable portion
  const uint8_t *extra;
  size_t extra_size;
  RyoTxInputView inputs[kRyoMaxTxInputs];
  RyoTxOutputView outputs[kRyoMaxTxOutputs];
  RyoBulletproofView proof; // commitments are restored during verification
};
static_assert(sizeof(RyoTransactionView) <= 2048, "Ryo transaction view exceeds stack budget");

struct RyoTransactionHashes {
  uint8_t prefix[32];
  uint8_t base[32];
  uint8_t prunable[32];
  uint8_t transaction[32];
  uint8_t signing[32];
};

struct RyoPublicAddress {
  uint8_t spend[32];
  uint8_t view[32];
};

struct RyoPaymentDetails {
  uint64_t amount;
  uint64_t change;
  uint64_t fee;
  bool has_payment_id;
  uint8_t payment_id[32];
};

// Recover an outgoing v3 standard-address payment from the actual outputs.
// The caller supplies its own change address and transaction secret. Supports
// one recipient and optional change, pubkey + uniform payment ID extra only.
// Input ownership, range proofs, ring selection and approval are separate.
bool ryo_decode_payment(const uint8_t *data, size_t size, const uint8_t tx_secret[32],
                        const RyoPublicAddress &recipient, const RyoPublicAddress &wallet,
                        RyoPaymentDetails *out);

// The ring is supplied in the same order as this input's on-chain offsets.
// Offline verification can establish ownership, not chain membership or age.
struct RyoSpendSource {
  const RyoRingMember *ring;
  const uint64_t *absolute_offsets; // one global output index per supplied member
  size_t ring_size;
  size_t real_index;
  uint8_t funding_tx_public[32];
  uint64_t funding_output_index;
  uint8_t funding_ecdh[64];
  uint8_t pseudo_mask[32];
};

struct RyoSpendReview {
  RyoPaymentDetails payment;
  RyoPublicAddress recipient;
  RyoPublicAddress wallet;
  uint64_t total_input;
  uint8_t binding[32];
};

// Standard-address v3 payments with existing key images and zero-filled
// MLSAG slots. Funding openings, images, amount conservation, outputs, the
// fork's relay fee floor and the original range proof are checked at review.
bool ryo_review_spend(const uint8_t *wire, size_t size, const RyoSpendSource *sources, size_t count,
                      const uint8_t spend[32], const uint8_t view[32], const uint8_t tx_secret[32],
                      const RyoPublicAddress &recipient, RyoSpendReview *out);

// Internal signing backend. The caller owns the device approval, fee policy,
// nonce entropy and a separate workspace. All output buffers must be disjoint
// from the immutable reviewed inputs. Failures erase the signed output.
bool ryo_sign_spend(const uint8_t *wire, size_t size, const RyoSpendSource *sources, size_t count,
                    const uint8_t spend[32], const uint8_t view[32], const uint8_t tx_secret[32],
                    const RyoPublicAddress &recipient, const RyoSpendReview &approved,
                    const uint8_t entropy[32], RyoMlsagSignature *workspace,
                    uint8_t *signed_tx, size_t *in_out_size);

// All APIs borrow an immutable input buffer that must not overlap any output.
// Version 2/3, RingCT type 3, uniform 2..241-member rings, one padded original
// Bulletproof. These are codec limits. Fork-specific admission is a separate
// wallet policy; historical version 2 must not become a new signing request.
RyoTxError ryo_parse_transaction(const uint8_t *data, size_t size,
                                  RyoTransactionView *out);
RyoTxError ryo_transaction_hashes(const uint8_t *data, size_t size,
                                  RyoTransactionHashes *out);
// Checks curve/scalar validity, commitment balance and the original Bulletproof.
// Does not authenticate chain UTXOs, ECDH amounts, recipient addresses or extra.
RyoTxError ryo_transaction_verify_semantics(const uint8_t *data, size_t size);
// Each ring must be resolved against the input's absolute chain offsets by the
// caller. This verifies the MLSAG against the transaction-derived signing hash.
RyoTxError ryo_transaction_verify_input(const uint8_t *data, size_t size,
    size_t input_index, const RyoRingMember *ring, size_t ring_size);
}  // namespace hexwallet
#endif
