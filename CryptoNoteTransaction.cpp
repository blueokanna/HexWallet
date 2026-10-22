#include "CryptoNoteTransaction.h"

#include <string.h>

#include "CryptoExtended.h"
#include "CryptoNoteAmounts.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

constexpr uint8_t kTxinToKey = 3;
constexpr uint8_t kTxoutToKey = 2;
constexpr uint8_t kTxoutToTaggedKey = 3;
constexpr uint8_t kRctTypeBpPlus = 6;
constexpr uint64_t kTxVersionRingCt = 2;
constexpr size_t kTruncatedAmountSize = 8;
// Bulletproofs+ aggregates at most 16 outputs per proof (M * N = 16 * 64).
constexpr size_t kOutputsPerBpProof = 16;

const uint8_t kEd25519Identity[kCryptoNoteKeySize] = { 1 };

static_assert(sizeof(CryptoNoteTransaction) < 12288,
              "CryptoNoteTransaction must stay within the device RAM budget");

struct Cursor {
  const uint8_t *data;
  size_t size;
  size_t offset;
  // Distinguishes "ran out of bytes" from "overlong varint encoding" so the
  // caller can report the precise rejection reason.
  bool non_canonical;

  bool remaining(size_t count) const {
    return count <= size - offset;
  }
  bool byte(uint8_t *out) {
    if (!remaining(1)) return false;
    *out = data[offset++];
    return true;
  }
  bool bytes(uint8_t *out, size_t count) {
    if (!remaining(count)) return false;
    memcpy(out, data + offset, count);
    offset += count;
    return true;
  }
  bool skip(size_t count) {
    if (!remaining(count)) return false;
    offset += count;
    return true;
  }
  bool varint(uint64_t *out) {
    uint64_t value = 0;
    unsigned shift = 0;
    size_t consumed = 0;
    for (;;) {
      uint8_t byte_value = 0;
      if (!byte(&byte_value)) return false;
      ++consumed;
      // 64 bits need at most 10 groups of 7; the 10th may only carry one bit.
      if (consumed > 10) return false;
      if (shift >= 64) return false;
      const uint64_t payload = static_cast<uint64_t>(byte_value & 0x7f);
      if (shift == 63 && payload > 1) return false;
      value |= payload << shift;
      if ((byte_value & 0x80) == 0) {
        // Minimal encoding: a multi-byte varint may not end in a zero group.
        if (consumed > 1 && payload == 0) {
          non_canonical = true;
          return false;
        }
        *out = value;
        return true;
      }
      shift += 7;
    }
  }
};

struct Writer {
  uint8_t *data;
  size_t capacity;
  size_t offset;

  bool byte(uint8_t value) {
    if (offset >= capacity) return false;
    data[offset++] = value;
    return true;
  }
  bool bytes(const uint8_t *value, size_t count) {
    if (count > capacity - offset) return false;
    if (count != 0) memcpy(data + offset, value, count);
    offset += count;
    return true;
  }
  bool zeroes(size_t count) {
    if (count > capacity - offset) return false;
    memset(data + offset, 0, count);
    offset += count;
    return true;
  }
  bool varint(uint64_t value) {
    while (value >= 0x80) {
      if (!byte(static_cast<uint8_t>((value & 0x7f) | 0x80))) return false;
      value >>= 7;
    }
    return byte(static_cast<uint8_t>(value));
  }
};

CryptoNoteTxError varint_or_error(Cursor *cursor, uint64_t *value) {
  if (cursor->varint(value)) return CryptoNoteTxError::Ok;
  return cursor->non_canonical ? CryptoNoteTxError::NonCanonical
                               : CryptoNoteTxError::Truncated;
}

bool read_key_vector(Cursor *cursor, uint8_t *out, size_t max_items,
                     uint8_t *out_count) {
  uint64_t count = 0;
  if (!cursor->varint(&count)) return false;
  if (count > max_items) return false;
  for (uint64_t index = 0; index < count; ++index) {
    if (!cursor->bytes(out + index * kCryptoNoteKeySize, kCryptoNoteKeySize)) {
      return false;
    }
  }
  *out_count = static_cast<uint8_t>(count);
  return true;
}

CryptoNoteTxError parse_signatures(Cursor *cursor, CryptoNoteTransaction *tx) {
  CryptoNoteTxError e = CryptoNoteTxError::Ok;
  uint8_t type = 0;
  if (!cursor->byte(&type)) return CryptoNoteTxError::Truncated;
  // Type 5 (CLSAG + Bulletproofs) and the legacy types have a different proof
  // layout; only the current type 6 is parsed. Rejecting is the safe default.
  if (type != kRctTypeBpPlus) return CryptoNoteTxError::Unsupported;
  tx->rct.type = type;

  uint64_t fee = 0;
  e = varint_or_error(cursor, &fee); if (e != CryptoNoteTxError::Ok) return e;
  if (fee > kCryptoNoteMaxFee) return CryptoNoteTxError::InvalidAmount;
  tx->rct.fee = fee;

  // ecdhInfo: one 8-byte truncated amount per output (type 4 and later).
  for (uint16_t index = 0; index < tx->output_count; ++index) {
    if (!cursor->bytes(tx->outputs[index].ecdh_amount, kTruncatedAmountSize)) {
      return CryptoNoteTxError::Truncated;
    }
  }
  // outPk: one 32-byte commitment per output.
  for (uint16_t index = 0; index < tx->output_count; ++index) {
    if (!cursor->bytes(tx->outputs[index].commitment, kCryptoNoteKeySize)) {
      return CryptoNoteTxError::Truncated;
    }
  }

  uint64_t proof_count = 0;
  e = varint_or_error(cursor, &proof_count); if (e != CryptoNoteTxError::Ok) return e;
  if (proof_count == 0 || proof_count > kCryptoNoteMaxBpProofs) {
    return CryptoNoteTxError::TooManyItems;
  }
  if (proof_count * kOutputsPerBpProof < tx->output_count) {
    return CryptoNoteTxError::TooManyItems;
  }
  tx->rct.proof_count = static_cast<uint8_t>(proof_count);
  for (uint8_t proof = 0; proof < tx->rct.proof_count; ++proof) {
    CryptoNoteBpPlusProof &item = tx->rct.proofs[proof];
    if (!cursor->bytes(item.a, sizeof(item.a)) ||
        !cursor->bytes(item.a1, sizeof(item.a1)) ||
        !cursor->bytes(item.b, sizeof(item.b)) ||
        !cursor->bytes(item.r1, sizeof(item.r1)) ||
        !cursor->bytes(item.s1, sizeof(item.s1)) ||
        !cursor->bytes(item.d1, sizeof(item.d1))) {
      return CryptoNoteTxError::Truncated;
    }
    if (!read_key_vector(cursor, &item.l[0][0], kCryptoNoteMaxBpLr,
                         &item.l_count)) {
      return CryptoNoteTxError::TooManyItems;
    }
    if (!read_key_vector(cursor, &item.r[0][0], kCryptoNoteMaxBpLr,
                         &item.r_count)) {
      return CryptoNoteTxError::TooManyItems;
    }
    if (item.l_count == 0 || item.l_count != item.r_count) {
      return CryptoNoteTxError::NonCanonical;
    }
  }

  // CLSAGs: s[ring], c1, D per input. No length prefix: the ring size is
  // implied by key_offsets, which the prefix already fixed.
  for (uint16_t index = 0; index < tx->input_count; ++index) {
    CryptoNoteTxInput &input = tx->inputs[index];
    if (input.key_offset_count == 0) return CryptoNoteTxError::NonCanonical;
    for (uint16_t member = 0; member < input.key_offset_count; ++member) {
      if (!cursor->bytes(input.s[member], kCryptoNoteKeySize)) {
        return CryptoNoteTxError::Truncated;
      }
    }
    if (!cursor->bytes(input.c1, sizeof(input.c1)) ||
        !cursor->bytes(input.d, sizeof(input.d))) {
      return CryptoNoteTxError::Truncated;
    }
  }

  // pseudoOuts: one per input, again without a length prefix.
  for (uint16_t index = 0; index < tx->input_count; ++index) {
    if (!cursor->bytes(tx->rct.pseudo_outs[index], kCryptoNoteKeySize)) {
      return CryptoNoteTxError::Truncated;
    }
  }
  return CryptoNoteTxError::Ok;
}

CryptoNoteTxError write_signatures(Writer *writer,
                                   const CryptoNoteTransaction &tx) {
  if (tx.rct.type != kRctTypeBpPlus) return CryptoNoteTxError::Unsupported;
  if (!writer->byte(tx.rct.type)) return CryptoNoteTxError::BufferTooSmall;
  if (!writer->varint(tx.rct.fee)) return CryptoNoteTxError::BufferTooSmall;
  for (uint16_t index = 0; index < tx.output_count; ++index) {
    if (!writer->bytes(tx.outputs[index].ecdh_amount, kTruncatedAmountSize)) {
      return CryptoNoteTxError::BufferTooSmall;
    }
  }
  for (uint16_t index = 0; index < tx.output_count; ++index) {
    if (!writer->bytes(tx.outputs[index].commitment, kCryptoNoteKeySize)) {
      return CryptoNoteTxError::BufferTooSmall;
    }
  }
  if (tx.rct.proof_count == 0 || tx.rct.proof_count > kCryptoNoteMaxBpProofs) {
    return CryptoNoteTxError::TooManyItems;
  }
  if (!writer->varint(tx.rct.proof_count)) {
    return CryptoNoteTxError::BufferTooSmall;
  }
  for (uint8_t proof = 0; proof < tx.rct.proof_count; ++proof) {
    const CryptoNoteBpPlusProof &item = tx.rct.proofs[proof];
    if (!writer->bytes(item.a, sizeof(item.a)) ||
        !writer->bytes(item.a1, sizeof(item.a1)) ||
        !writer->bytes(item.b, sizeof(item.b)) ||
        !writer->bytes(item.r1, sizeof(item.r1)) ||
        !writer->bytes(item.s1, sizeof(item.s1)) ||
        !writer->bytes(item.d1, sizeof(item.d1))) {
      return CryptoNoteTxError::BufferTooSmall;
    }
    if (item.l_count == 0 || item.l_count != item.r_count ||
        item.l_count > kCryptoNoteMaxBpLr) {
      return CryptoNoteTxError::NonCanonical;
    }
    if (!writer->varint(item.l_count) ||
        !writer->bytes(&item.l[0][0], static_cast<size_t>(item.l_count) * kCryptoNoteKeySize) ||
        !writer->varint(item.r_count) ||
        !writer->bytes(&item.r[0][0], static_cast<size_t>(item.r_count) * kCryptoNoteKeySize)) {
      return CryptoNoteTxError::BufferTooSmall;
    }
  }
  for (uint16_t index = 0; index < tx.input_count; ++index) {
    const CryptoNoteTxInput &input = tx.inputs[index];
    if (input.key_offset_count == 0 ||
        input.key_offset_count > kCryptoNoteMaxRingSize) {
      return CryptoNoteTxError::NonCanonical;
    }
    if (!writer->bytes(&input.s[0][0],
                       static_cast<size_t>(input.key_offset_count) * kCryptoNoteKeySize)) {
      return CryptoNoteTxError::BufferTooSmall;
    }
    if (!writer->bytes(input.c1, sizeof(input.c1)) ||
        !writer->bytes(input.d, sizeof(input.d))) {
      return CryptoNoteTxError::BufferTooSmall;
    }
  }
  for (uint16_t index = 0; index < tx.input_count; ++index) {
    if (!writer->bytes(tx.rct.pseudo_outs[index], kCryptoNoteKeySize)) {
      return CryptoNoteTxError::BufferTooSmall;
    }
  }
  return CryptoNoteTxError::Ok;
}

// Shared prefix serializer. `signatures` selects whether the rct block is
// appended; the txid/prefix hash are defined over the prefix only.
CryptoNoteTxError write_transaction(const CryptoNoteTransaction &tx, Writer *writer,
                                    bool with_signatures) {
  if (tx.version != kTxVersionRingCt) return CryptoNoteTxError::Unsupported;
  if (tx.input_count == 0 || tx.input_count > kCryptoNoteMaxTxInputs ||
      tx.output_count == 0 || tx.output_count > kCryptoNoteMaxTxOutputs) {
    return CryptoNoteTxError::TooManyItems;
  }
  if (tx.extra_size > kCryptoNoteMaxTxExtra) return CryptoNoteTxError::TooLarge;
  if (!writer->varint(tx.version) || !writer->varint(tx.unlock_time)) {
    return CryptoNoteTxError::BufferTooSmall;
  }
  if (!writer->varint(tx.input_count)) return CryptoNoteTxError::BufferTooSmall;
  for (uint16_t index = 0; index < tx.input_count; ++index) {
    const CryptoNoteTxInput &input = tx.inputs[index];
    if (input.key_offset_count == 0 ||
        input.key_offset_count > kCryptoNoteMaxRingSize) {
      return CryptoNoteTxError::NonCanonical;
    }
    // RCT spends carry a zero amount and the real key image.
    if (!writer->varint(kTxinToKey) || !writer->varint(0) ||
        !writer->varint(input.key_offset_count)) {
      return CryptoNoteTxError::BufferTooSmall;
    }
    for (uint16_t member = 0; member < input.key_offset_count; ++member) {
      if (!writer->varint(input.key_offsets[member])) {
        return CryptoNoteTxError::BufferTooSmall;
      }
    }
    if (!writer->bytes(input.key_image, sizeof(input.key_image))) {
      return CryptoNoteTxError::BufferTooSmall;
    }
  }
  if (!writer->varint(tx.output_count)) return CryptoNoteTxError::BufferTooSmall;
  for (uint16_t index = 0; index < tx.output_count; ++index) {
    const CryptoNoteTxOutput &output = tx.outputs[index];
    if (!writer->varint(0) ||
        !writer->varint(output.tagged ? kTxoutToTaggedKey : kTxoutToKey) ||
        !writer->bytes(output.public_key, sizeof(output.public_key))) {
      return CryptoNoteTxError::BufferTooSmall;
    }
    if (output.tagged && !writer->byte(output.view_tag)) {
      return CryptoNoteTxError::BufferTooSmall;
    }
  }
  if (!writer->varint(tx.extra_size) ||
      !writer->bytes(tx.extra, tx.extra_size)) {
    return CryptoNoteTxError::BufferTooSmall;
  }
  if (!with_signatures) return CryptoNoteTxError::Ok;
  return write_signatures(writer, tx);
}

}  // namespace

CryptoNoteTxError cryptonote_parse_transaction(const uint8_t *data, size_t size,
                                               CryptoNoteTransaction *out) {
  if (out == nullptr) return CryptoNoteTxError::InvalidArgument;
  clear_cryptonote_transaction(out);
  if (data == nullptr) return CryptoNoteTxError::InvalidArgument;
  if (size < 16) return CryptoNoteTxError::Truncated;
  if (size > kCryptoNoteMaxTxBytes) return CryptoNoteTxError::TooLarge;

  Cursor cursor = { data, size, 0, false };
  CryptoNoteTxError e = CryptoNoteTxError::Ok;
  uint64_t version = 0;
  uint64_t unlock_time = 0;
  e = varint_or_error(&cursor, &version); if (e != CryptoNoteTxError::Ok) return e;
  if (version != kTxVersionRingCt) return CryptoNoteTxError::Unsupported;
  e = varint_or_error(&cursor, &unlock_time); if (e != CryptoNoteTxError::Ok) return e;
  out->version = version;
  out->unlock_time = unlock_time;

  uint64_t input_count = 0;
  e = varint_or_error(&cursor, &input_count); if (e != CryptoNoteTxError::Ok) return e;
  if (input_count == 0) return CryptoNoteTxError::InvalidArgument;
  if (input_count > kCryptoNoteMaxTxInputs) return CryptoNoteTxError::TooManyItems;
  out->input_count = static_cast<uint16_t>(input_count);
  for (uint16_t index = 0; index < out->input_count; ++index) {
    CryptoNoteTxInput &input = out->inputs[index];
    uint64_t type = 0;
    e = varint_or_error(&cursor, &type); if (e != CryptoNoteTxError::Ok) return e;
    if (type != kTxinToKey) return CryptoNoteTxError::Unsupported;
    uint64_t amount = 0;
    e = varint_or_error(&cursor, &amount); if (e != CryptoNoteTxError::Ok) return e;
    if (amount != 0) return CryptoNoteTxError::InvalidAmount;
    uint64_t offset_count = 0;
    e = varint_or_error(&cursor, &offset_count); if (e != CryptoNoteTxError::Ok) return e;
    if (offset_count == 0) return CryptoNoteTxError::InvalidArgument;
    if (offset_count > kCryptoNoteMaxRingSize) return CryptoNoteTxError::TooManyItems;
    input.key_offset_count = static_cast<uint16_t>(offset_count);
    for (uint16_t member = 0; member < input.key_offset_count; ++member) {
      e = varint_or_error(&cursor, &input.key_offsets[member]);
      if (e != CryptoNoteTxError::Ok) return e;
    }
    if (!cursor.bytes(input.key_image, sizeof(input.key_image))) {
      return CryptoNoteTxError::Truncated;
    }
  }

  uint64_t output_count = 0;
  e = varint_or_error(&cursor, &output_count); if (e != CryptoNoteTxError::Ok) return e;
  if (output_count == 0) return CryptoNoteTxError::InvalidArgument;
  if (output_count > kCryptoNoteMaxTxOutputs) return CryptoNoteTxError::TooManyItems;
  out->output_count = static_cast<uint16_t>(output_count);
  for (uint16_t index = 0; index < out->output_count; ++index) {
    CryptoNoteTxOutput &output = out->outputs[index];
    uint64_t amount = 0;
    e = varint_or_error(&cursor, &amount); if (e != CryptoNoteTxError::Ok) return e;
    if (amount != 0) return CryptoNoteTxError::InvalidAmount;
    uint64_t target = 0;
    e = varint_or_error(&cursor, &target); if (e != CryptoNoteTxError::Ok) return e;
    if (target != kTxoutToKey && target != kTxoutToTaggedKey) {
      return CryptoNoteTxError::Unsupported;
    }
    output.tagged = target == kTxoutToTaggedKey;
    if (!cursor.bytes(output.public_key, sizeof(output.public_key))) {
      return CryptoNoteTxError::Truncated;
    }
    if (output.tagged && !cursor.byte(&output.view_tag)) {
      return CryptoNoteTxError::Truncated;
    }
  }

  uint64_t extra_size = 0;
  e = varint_or_error(&cursor, &extra_size); if (e != CryptoNoteTxError::Ok) return e;
  if (extra_size > kCryptoNoteMaxTxExtra) return CryptoNoteTxError::TooLarge;
  out->extra_size = static_cast<uint16_t>(extra_size);
  if (!cursor.bytes(out->extra, out->extra_size)) {
    return CryptoNoteTxError::Truncated;
  }

  const CryptoNoteTxError signatures = parse_signatures(&cursor, out);
  if (signatures != CryptoNoteTxError::Ok) {
    clear_cryptonote_transaction(out);
    return signatures;
  }
  // Trailing bytes mean the device and the host disagree about the format.
  if (cursor.offset != cursor.size) {
    clear_cryptonote_transaction(out);
    return CryptoNoteTxError::NonCanonical;
  }

  uint16_t ring_size = 0;
  if (!cryptonote_transaction_ring_uniform(*out, &ring_size)) {
    clear_cryptonote_transaction(out);
    return CryptoNoteTxError::NonCanonical;
  }
  out->rct.ring_size = ring_size;
  return CryptoNoteTxError::Ok;
}

CryptoNoteTxError cryptonote_serialize_transaction(const CryptoNoteTransaction &tx,
                                                   uint8_t *out,
                                                   size_t *in_out_size) {
  if (out == nullptr || in_out_size == nullptr) {
    return CryptoNoteTxError::InvalidArgument;
  }
  Writer writer = { out, *in_out_size, 0 };
  const CryptoNoteTxError error = write_transaction(tx, &writer, true);
  if (error != CryptoNoteTxError::Ok) {
    memset(out, 0, *in_out_size);
    *in_out_size = 0;
    return error;
  }
  *in_out_size = writer.offset;
  return CryptoNoteTxError::Ok;
}

bool cryptonote_transaction_ring_uniform(const CryptoNoteTransaction &tx,
                                         uint16_t *out_ring_size) {
  if (tx.input_count == 0) return false;
  const uint16_t expected = tx.inputs[0].key_offset_count;
  if (expected == 0) return false;
  for (uint16_t index = 1; index < tx.input_count; ++index) {
    if (tx.inputs[index].key_offset_count != expected) return false;
  }
  if (out_ring_size != nullptr) *out_ring_size = expected;
  return true;
}

bool cryptonote_transaction_balance_ok(const CryptoNoteTransaction &tx) {
  if (tx.input_count == 0 || tx.output_count == 0) return false;
  if (tx.rct.type != kRctTypeBpPlus) return false;

  uint8_t sum_pseudo[kCryptoNoteKeySize];
  uint8_t sum_outputs[kCryptoNoteKeySize];
  memcpy(sum_pseudo, kEd25519Identity, sizeof(sum_pseudo));
  memcpy(sum_outputs, kEd25519Identity, sizeof(sum_outputs));

  uint8_t scratch[kCryptoNoteKeySize];
  for (uint16_t index = 0; index < tx.input_count; ++index) {
    if (!ed25519_point_add_compressed(sum_pseudo, tx.rct.pseudo_outs[index],
                                      scratch)) {
      return false;
    }
    memcpy(sum_pseudo, scratch, sizeof(sum_pseudo));
  }
  for (uint16_t index = 0; index < tx.output_count; ++index) {
    if (!ed25519_point_add_compressed(sum_outputs, tx.outputs[index].commitment,
                                      scratch)) {
      return false;
    }
    memcpy(sum_outputs, scratch, sizeof(sum_outputs));
  }
  // fee * H, i.e. a commitment with a zero mask.
  static const uint8_t kZeroMask[kCryptoNoteKeySize] = { 0 };
  if (!ringct_commitment(kZeroMask, tx.rct.fee, scratch)) return false;
  if (!ed25519_point_add_compressed(sum_outputs, scratch, sum_outputs)) {
    return false;
  }

  const bool balanced =
      crypto_constant_time_equal(sum_pseudo, sum_outputs, kCryptoNoteKeySize);
  secure_zero(sum_pseudo, sizeof(sum_pseudo));
  secure_zero(sum_outputs, sizeof(sum_outputs));
  secure_zero(scratch, sizeof(scratch));
  return balanced;
}

const char *cryptonote_tx_error_text(CryptoNoteTxError error) {
  switch (error) {
    case CryptoNoteTxError::Ok: return "ok";
    case CryptoNoteTxError::InvalidArgument: return "invalid-argument";
    case CryptoNoteTxError::Truncated: return "truncated";
    case CryptoNoteTxError::NonCanonical: return "non-canonical";
    case CryptoNoteTxError::Unsupported: return "unsupported-transaction-type";
    case CryptoNoteTxError::TooLarge: return "too-large";
    case CryptoNoteTxError::TooManyItems: return "too-many-items";
    case CryptoNoteTxError::InvalidAmount: return "invalid-amount";
    case CryptoNoteTxError::CryptoFailure: return "crypto-failure";
    case CryptoNoteTxError::BufferTooSmall: return "buffer-too-small";
  }
  return "unknown";
}

void clear_cryptonote_transaction(CryptoNoteTransaction *tx) {
  if (tx != nullptr) secure_zero(tx, sizeof(*tx));
}

namespace {

void fill_pattern(uint8_t *out, size_t size, uint8_t seed) {
  for (size_t index = 0; index < size; ++index) {
    out[index] = static_cast<uint8_t>(seed + index * 7);
  }
}

void store_scalar(uint8_t out[kCryptoNoteKeySize], uint64_t value) {
  memset(out, 0, kCryptoNoteKeySize);
  for (size_t index = 0; index < 8; ++index) {
    out[index] = static_cast<uint8_t>(value >> (index * 8));
  }
}

// Builds a self-consistent type-6 transaction whose pseudo output equals the
// sum of the output commitments plus the fee, so the balance check can be
// exercised in both directions.
bool build_sample(CryptoNoteTransaction *tx) {
  clear_cryptonote_transaction(tx);
  tx->version = kTxVersionRingCt;
  tx->unlock_time = 0;
  tx->input_count = 1;
  tx->output_count = 2;
  tx->extra_size = 5;
  fill_pattern(tx->extra, tx->extra_size, 0x11);

  CryptoNoteTxInput &input = tx->inputs[0];
  input.key_offset_count = kCryptoNoteMaxRingSize;
  for (uint16_t index = 0; index < input.key_offset_count; ++index) {
    input.key_offsets[index] = 1000 + index;
  }
  fill_pattern(input.key_image, sizeof(input.key_image), 0x21);
  for (uint16_t member = 0; member < input.key_offset_count; ++member) {
    fill_pattern(input.s[member], kCryptoNoteKeySize,
                 static_cast<uint8_t>(0x30 + member));
  }
  fill_pattern(input.c1, sizeof(input.c1), 0x51);
  fill_pattern(input.d, sizeof(input.d), 0x61);

  static const uint64_t kAmounts[2] = { 100, 50 };
  static const uint64_t kMasks[2] = { 1, 2 };
  for (uint16_t index = 0; index < tx->output_count; ++index) {
    CryptoNoteTxOutput &output = tx->outputs[index];
    output.tagged = true;
    output.view_tag = static_cast<uint8_t>(0x40 + index);
    fill_pattern(output.public_key, sizeof(output.public_key),
                 static_cast<uint8_t>(0x70 + index));
    fill_pattern(output.ecdh_amount, sizeof(output.ecdh_amount),
                 static_cast<uint8_t>(0x80 + index));
    uint8_t mask[kCryptoNoteKeySize];
    store_scalar(mask, kMasks[index]);
    if (!ringct_commitment(mask, kAmounts[index], output.commitment)) return false;
  }

  tx->rct.type = kRctTypeBpPlus;
  tx->rct.fee = 10;
  tx->rct.proof_count = 1;
  tx->rct.ring_size = kCryptoNoteMaxRingSize;
  CryptoNoteBpPlusProof &proof = tx->rct.proofs[0];
  fill_pattern(proof.a, sizeof(proof.a), 0x91);
  fill_pattern(proof.a1, sizeof(proof.a1), 0xa1);
  fill_pattern(proof.b, sizeof(proof.b), 0xb1);
  fill_pattern(proof.r1, sizeof(proof.r1), 0xc1);
  fill_pattern(proof.s1, sizeof(proof.s1), 0xd1);
  fill_pattern(proof.d1, sizeof(proof.d1), 0xe1);
  proof.l_count = kCryptoNoteMaxBpLr;
  proof.r_count = kCryptoNoteMaxBpLr;
  fill_pattern(&proof.l[0][0], sizeof(proof.l), 0x13);
  fill_pattern(&proof.r[0][0], sizeof(proof.r), 0x27);

  // pseudoOut = C1 + C2 + fee*H
  uint8_t sum[kCryptoNoteKeySize];
  uint8_t fee_point[kCryptoNoteKeySize];
  static const uint8_t kZeroMask[kCryptoNoteKeySize] = { 0 };
  if (!ed25519_point_add_compressed(tx->outputs[0].commitment,
                                    tx->outputs[1].commitment, sum)) {
    return false;
  }
  if (!ringct_commitment(kZeroMask, tx->rct.fee, fee_point)) return false;
  if (!ed25519_point_add_compressed(sum, fee_point, tx->rct.pseudo_outs[0])) {
    return false;
  }
  return true;
}

}  // namespace

// The boot self-test runs on the loop task stack, which is 32 KiB, so the
// fixtures live in static storage instead of a 20 KiB stack spike. Only one
// transaction copy is kept: the parsed result overwrites the sample, and the
// byte-exact re-serialization check is what proves the round trip.
bool run_cryptonote_transaction_self_tests() {
  static CryptoNoteTransaction tx;
  static uint8_t wire[kCryptoNoteMaxTxBytes];
  static uint8_t wire2[kCryptoNoteMaxTxBytes];

  if (!build_sample(&tx)) return false;
  bool ok = cryptonote_transaction_balance_ok(tx);

  size_t wire_size = sizeof(wire);
  ok = ok && cryptonote_serialize_transaction(tx, wire, &wire_size) ==
                 CryptoNoteTxError::Ok &&
       wire_size > 0;

  const CryptoNoteTxError parse_error =
      cryptonote_parse_transaction(wire, wire_size, &tx);
  ok = ok && parse_error == CryptoNoteTxError::Ok;

  // Field-level checks against the values build_sample() wrote.
  ok = ok && tx.version == kTxVersionRingCt && tx.unlock_time == 0 &&
       tx.input_count == 1 && tx.output_count == 2 && tx.extra_size == 5 &&
       tx.rct.type == kRctTypeBpPlus && tx.rct.fee == 10 &&
       tx.rct.proof_count == 1 && tx.rct.ring_size == kCryptoNoteMaxRingSize &&
       tx.inputs[0].key_offset_count == kCryptoNoteMaxRingSize &&
       tx.inputs[0].key_offsets[0] == 1000 &&
       tx.inputs[0].key_offsets[kCryptoNoteMaxRingSize - 1] ==
           1000 + kCryptoNoteMaxRingSize - 1 &&
       tx.rct.proofs[0].l_count == kCryptoNoteMaxBpLr &&
       tx.outputs[0].tagged && tx.outputs[1].tagged &&
       tx.outputs[0].view_tag == 0x40 && tx.outputs[1].view_tag == 0x41 &&
       tx.inputs[0].key_image[0] == 0x21 &&
       tx.outputs[1].commitment[0] != 0;

  // Byte-exact re-serialization.
  size_t wire2_size = sizeof(wire2);
  ok = ok && cryptonote_serialize_transaction(tx, wire2, &wire2_size) ==
                 CryptoNoteTxError::Ok &&
       wire2_size == wire_size &&
       crypto_constant_time_equal(wire, wire2, wire_size);
  ok = ok && cryptonote_transaction_balance_ok(tx);

  // Any change to a commitment or the fee must break the balance.
  tx.outputs[0].commitment[5] ^= 0x01;
  ok = ok && !cryptonote_transaction_balance_ok(tx);
  tx.outputs[0].commitment[5] ^= 0x01;
  tx.rct.fee += 1;
  ok = ok && !cryptonote_transaction_balance_ok(tx);
  tx.rct.fee -= 1;
  ok = ok && cryptonote_transaction_balance_ok(tx);

  // Truncation, trailing bytes and non-minimal varints are rejected.
  ok = ok && cryptonote_parse_transaction(wire, wire_size - 1, &tx) ==
                 CryptoNoteTxError::Truncated;
  memcpy(wire2, wire, wire_size);
  wire2[wire_size] = 0;
  ok = ok && cryptonote_parse_transaction(wire2, wire_size + 1, &tx) ==
                 CryptoNoteTxError::NonCanonical;

  // version is the first varint (2 = 0x02); 0x82 0x00 is an overlong encoding.
  memcpy(wire2, wire, wire_size);
  wire2[0] = 0x82;
  wire2[1] = 0x00;
  ok = ok && cryptonote_parse_transaction(wire2, wire_size, &tx) ==
                 CryptoNoteTxError::NonCanonical;
  // A different version must be refused before any key material is parsed.
  wire2[0] = 0x01;
  ok = ok && cryptonote_parse_transaction(wire2, wire_size, &tx) ==
                 CryptoNoteTxError::Unsupported;

  secure_zero(wire, sizeof(wire));
  secure_zero(wire2, sizeof(wire2));
  clear_cryptonote_transaction(&tx);
  return ok;
}

}  // namespace hexwallet
