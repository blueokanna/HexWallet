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
