#ifndef HEXWALLET_AIRGAP_FRAME_H
#define HEXWALLET_AIRGAP_FRAME_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Airgap framing: a blob is cut into `total_chunks` chunks and animated as a
// sequence of QR frames. Two pieces live here, and they are deliberately
// separate from the QR encoder:
//
//   1. A frame header that binds chunk index, plan index, total chunks and the
//      payload with a CRC, so a half-scanned or mis-ordered symbol is rejected
//      instead of being stitched into the wrong blob.
//   2. An exact enumerative index over the set of *valid frame plans*: a plan is
//      a composition of `total_chunks` into `frame_count` non-empty groups whose
//      consecutive sizes differ by at most one. Bounded steps keep the symbol
//      density smooth while it animates - a QR that alternates between nearly
//      empty and maximally dense frames makes phone cameras hunt for focus and
//      costs rescans.
//
// The ranking is the chain case of enumerative coding: every valid plan gets a
// unique index in [0, count), unranking an index produces exactly that plan, and
// the index can therefore be derived from the blob id instead of transmitted.
// Counting is exact in 64 bits; a configuration whose count overflows is
// refused rather than silently truncated.

constexpr size_t kAirgapMaxChunks = 64;
constexpr size_t kAirgapMaxFrames = 8;
constexpr size_t kAirgapMaxGroup = 6;

enum class AirgapResult : uint8_t {
  Ok = 0,
  InvalidArgument,
  // A parameter is outside the supported envelope (chunks 1..64, frames 1..8,
  // group 1..6).
  OutOfRange,
  // No composition exists for this (chunks, frames, group) triple.
  EmptyPlanSpace,
  // The exact count does not fit in 64 bits. Neither side may approximate it:
  // a truncated count breaks the rank/unrank bijection.
  CountOverflow,
  IndexOutOfRange,
  ChecksumMismatch,
  BufferTooSmall,
};

// Scratch for the counting sweep. The caller owns it so the module keeps no
// static state and two airgap transfers cannot interfere.
struct AirgapScratch {
  // ways[frame][previous_group][remaining_chunks]
  uint64_t ways[kAirgapMaxFrames + 1][kAirgapMaxGroup + 2][kAirgapMaxChunks + 1];
};

struct AirgapPlanParams {
  uint8_t chunks;
  uint8_t frames;
  uint8_t max_group;
};

// Total number of valid plans. Returns EmptyPlanSpace when nothing fits and
// CountOverflow when the exact count does not fit in 64 bits.
AirgapResult airgap_plan_count(const AirgapPlanParams &params,
                               AirgapScratch *scratch, uint64_t *count);

// Unranks `index` into `groups[frames]`. Every entry is in [1, max_group], the
// sum is exactly `chunks`, and consecutive entries differ by at most one.
AirgapResult airgap_plan_unrank(const AirgapPlanParams &params, uint64_t index,
                                AirgapScratch *scratch, uint8_t *groups);

// Inverse of airgap_plan_unrank. Rejects any group sequence that is not a valid
// plan, so a host cannot smuggle an unconstrained plan past the device.
AirgapResult airgap_plan_rank(const AirgapPlanParams &params,
                              const uint8_t *groups, AirgapScratch *scratch,
                              uint64_t *index);

// Maps the blob id and plan index into a value in [0, count) without modulo bias:
// the raw 64-bit draw is rejected and redrawn from a counter-mode PRF.
// `seed` is the 32-byte value the sender and receiver already share (the blob
// hash), so the plan index never travels on the wire.
uint64_t airgap_plan_index(uint64_t blob_tag, const uint8_t seed[32],
                           uint64_t count);

// Frame header: magic, version, blob tag, plan index, chunk index, chunk count,
// payload length and a CRC-32 over everything else.
constexpr size_t kAirgapHeaderSize = 26;
constexpr size_t kAirgapCrcSize = 4;

// Writes header + payload + CRC. `out` must hold payload_size + 30 bytes.
AirgapResult airgap_frame_pack(uint64_t blob_tag, uint64_t plan_index,
                               uint8_t chunk_index, uint8_t chunk_count,
                               uint8_t max_group, uint16_t chunk_bytes,
                               const uint8_t *payload, size_t payload_size,
                               uint8_t *out, size_t out_capacity,
                               size_t *out_size);

struct AirgapFrameView {
  uint64_t blob_tag;
  uint64_t plan_index;
  uint8_t chunk_index;
  uint8_t chunk_count;
  // Plan space this frame was cut from; the receiver needs it to unrank the
  // plan, because the same index means different groups under a different bound.
  uint8_t max_group;
  // Length of every chunk except the last one, which may be shorter.
  uint16_t chunk_bytes;
  const uint8_t *payload;
  size_t payload_size;
};

// Validates magic, version, lengths and CRC. `frame` is not modified.
AirgapResult airgap_frame_parse(const uint8_t *frame, size_t frame_size,
                                AirgapFrameView *view);

// CRC-32/ISO-HDLC (reflected, init 0xFFFFFFFF, xorout 0xFFFFFFFF).
uint32_t airgap_crc32(const uint8_t *data, size_t size);

// First plan position whose chunk range is not fully covered by `seen`, i.e. the
// frame the operator should rescan. Returns false when everything is covered or
// the plan is inconsistent with the bitset.
bool airgap_next_needed(const uint8_t *groups, size_t frames,
                        const uint8_t *seen, size_t chunk_count,
                        uint8_t *frame_index);

// ---------------------------------------------------------------------------
// Transfer state machines
// ---------------------------------------------------------------------------
//
// The sender cuts one blob into `chunk_count` contiguous chunks and hands out
// the frames named by the plan. The receiver rebuilds the blob from whichever
// frames it manages to scan, in whatever order they arrive, and reports the
// frame that is still missing. Chunk geometry is self-describing: every chunk
// except the last has the same length, so no total-size field is needed and a
// truncated final chunk is still accepted while a short middle chunk is not.

constexpr size_t kAirgapMaxBlob = 2048;

struct AirgapSender {
  AirgapPlanParams params;
  uint64_t blob_tag;
  uint64_t plan_index;
  uint8_t groups[kAirgapMaxFrames];
  size_t chunk_offset[kAirgapMaxChunks];
  size_t chunk_length[kAirgapMaxChunks];
  size_t chunk_bytes;
  size_t chunk_count;
  size_t blob_size;
  // Borrowed, not copied: the caller keeps the blob alive for the animation.
  const uint8_t *blob;
};

// Picks the plan from the blob tag and a 32-byte seed both sides hold (the
// blob hash), then fixes the chunk geometry. `frames` is clamped down until a
// plan exists, so a small blob never asks for more frames than it can fill.
AirgapResult airgap_sender_begin(AirgapSender *sender, const uint8_t *blob,
                                 size_t blob_size, uint8_t frames,
                                 uint8_t max_group, const uint8_t seed[32],
                                 AirgapScratch *scratch);

// Renders frame `index` (header + payload + CRC) into `out`.
AirgapResult airgap_sender_render(const AirgapSender *sender, size_t index,
                                  uint8_t *out, size_t out_capacity,
                                  size_t *out_size);

struct AirgapReceiver {
  uint64_t blob_tag;
  uint64_t plan_index;
  uint8_t chunk_count;
  uint8_t frame_count;
  uint8_t groups[kAirgapMaxFrames];
  size_t chunk_bytes;
  size_t chunk_length[kAirgapMaxChunks];
  size_t chunk_offset[kAirgapMaxChunks];
  uint8_t seen[(kAirgapMaxChunks + 7) / 8];
  uint8_t data[kAirgapMaxBlob];
  size_t data_size;
  uint8_t received;
  bool started;
};

void airgap_receiver_reset(AirgapReceiver *receiver);

// Accepts one scanned frame. A duplicate is accepted and changes nothing, which
// is what happens when the operator rescans the same symbol. A frame that does
// not belong to the transfer already in progress is refused rather than merged.
// `scratch` is only touched while the first frame fixes the plan, but it is a
// parameter so this call is reentrant and the 37 KB table never lands in .bss.
AirgapResult airgap_receiver_accept(AirgapReceiver *receiver,
                                    const uint8_t *frame, size_t frame_size,
                                    AirgapScratch *scratch);

// True while frames are still missing; `frame_index` receives the next frame to
// show or rescan.
bool airgap_receiver_next(const AirgapReceiver *receiver, uint8_t *frame_index);

// Copies the reassembled blob out. Fails unless every chunk arrived.
AirgapResult airgap_receiver_blob(const AirgapReceiver *receiver, uint8_t *out,
                                  size_t out_capacity, size_t *out_size);

bool run_airgap_self_tests();

// Stage of the last failing check; host diagnostics only.
int airgap_last_stage();

}  // namespace hexwallet

#endif
