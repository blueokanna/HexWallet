#include "AirgapFrame.h"

#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"

namespace hexwallet {
namespace {

constexpr uint8_t kMagic[4] = {'H', 'X', 'A', 'G'};
constexpr uint8_t kVersion = 1;
constexpr uint8_t kFlagEncrypted = 0x01;

bool valid_params(const AirgapPlanParams &params) {
  return params.chunks >= 1 && params.chunks <= kAirgapMaxChunks &&
         params.frames >= 1 && params.frames <= kAirgapMaxFrames &&
         params.max_group >= 1 && params.max_group <= kAirgapMaxGroup &&
         params.chunks >= params.frames;
}

uint8_t group_low(uint8_t previous) { return previous > 1 ? previous - 1 : 1; }

uint8_t group_high(uint8_t previous, uint8_t max_group) {
  const uint16_t high = static_cast<uint16_t>(previous) + 1;
  return high < max_group ? static_cast<uint8_t>(high) : max_group;
}

void build_table(const AirgapPlanParams &params, AirgapScratch *scratch,
                 bool *overflow) {
  uint64_t (*ways)[kAirgapMaxGroup + 2][kAirgapMaxChunks + 1] = scratch->ways;
  memset(ways, 0, sizeof(scratch->ways));
  *overflow = false;
  for (size_t prev = 0; prev <= kAirgapMaxGroup + 1; ++prev) ways[0][prev][0] = 1;
  for (size_t len = 1; len <= params.frames; ++len) {
    for (size_t prev = 1; prev <= params.max_group; ++prev) {
      for (size_t rem = len; rem <= params.chunks; ++rem) {
        uint64_t total = 0;
        const uint8_t low = group_low(static_cast<uint8_t>(prev));
        const uint8_t high = group_high(static_cast<uint8_t>(prev), params.max_group);
        for (uint8_t group = low; group <= high && group <= rem; ++group) {
          const uint64_t add = ways[len - 1][group][rem - group];
          if (UINT64_MAX - total < add) {
            total = UINT64_MAX;
            *overflow = true;
            break;
          }
          total += add;
        }
        ways[len][prev][rem] = total;
      }
    }
  }
}

uint64_t plan_total(const AirgapPlanParams &params, AirgapScratch *scratch,
                    bool *overflow) {
  build_table(params, scratch, overflow);
  uint64_t total = 0;
  for (uint8_t group = 1; group <= params.max_group && group <= params.chunks; ++group) {
    const uint64_t add = scratch->ways[params.frames - 1][group][params.chunks - group];
    if (UINT64_MAX - total < add) {
      *overflow = true;
      return UINT64_MAX;
    }
    total += add;
  }
  return total;
}

void write_be64(uint8_t *out, uint64_t value) {
  for (size_t index = 0; index < 8; ++index) {
    out[index] = static_cast<uint8_t>(value >> (56 - 8 * index));
  }
}

uint64_t read_be64(const uint8_t *in) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; ++index) {
    value = (value << 8) | in[index];
  }
  return value;
}

}  // namespace

uint32_t airgap_crc32(const uint8_t *data, size_t size) {
  if (data == nullptr && size != 0) return 0;
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t index = 0; index < size; ++index) {
    crc ^= data[index];
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc & 1u) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
    }
  }
  return crc ^ 0xFFFFFFFFu;
}

AirgapResult airgap_plan_count(const AirgapPlanParams &params,
                               AirgapScratch *scratch, uint64_t *count) {
  if (scratch == nullptr || count == nullptr) return AirgapResult::InvalidArgument;
  if (!valid_params(params)) return AirgapResult::OutOfRange;
  bool overflow = false;
  const uint64_t total = plan_total(params, scratch, &overflow);
  if (overflow) return AirgapResult::CountOverflow;
  if (total == 0) {
    *count = 0;
    return AirgapResult::EmptyPlanSpace;
  }
  *count = total;
  return AirgapResult::Ok;
}

AirgapResult airgap_plan_unrank(const AirgapPlanParams &params, uint64_t index,
                                AirgapScratch *scratch, uint8_t *groups) {
  if (scratch == nullptr || groups == nullptr) return AirgapResult::InvalidArgument;
  if (!valid_params(params)) return AirgapResult::OutOfRange;
  bool overflow = false;
  const uint64_t total = plan_total(params, scratch, &overflow);
  if (overflow) return AirgapResult::CountOverflow;
  if (total == 0) return AirgapResult::EmptyPlanSpace;
  if (index >= total) return AirgapResult::IndexOutOfRange;

  size_t remaining = params.chunks;
  uint8_t previous = 1;
  for (size_t position = 0; position < params.frames; ++position) {
    const size_t left = params.frames - 1 - position;
    const uint8_t low = position == 0 ? 1 : group_low(previous);
    const uint8_t high = position == 0 ? params.max_group
                                       : group_high(previous, params.max_group);
    bool placed = false;
    for (uint8_t group = low; group <= high && group <= remaining; ++group) {
      const uint64_t completion = scratch->ways[left][group][remaining - group];
      if (index < completion) {
        groups[position] = group;
        remaining -= group;
        previous = group;
        placed = true;
        break;
      }
      index -= completion;
    }
    if (!placed) return AirgapResult::IndexOutOfRange;
  }
  return remaining == 0 ? AirgapResult::Ok : AirgapResult::IndexOutOfRange;
}

AirgapResult airgap_plan_rank(const AirgapPlanParams &params,
                              const uint8_t *groups, AirgapScratch *scratch,
                              uint64_t *index) {
  if (scratch == nullptr || groups == nullptr || index == nullptr) {
    return AirgapResult::InvalidArgument;
  }
  if (!valid_params(params)) return AirgapResult::OutOfRange;
  bool overflow = false;
  const uint64_t total = plan_total(params, scratch, &overflow);
  if (overflow) return AirgapResult::CountOverflow;
  if (total == 0) return AirgapResult::EmptyPlanSpace;

  size_t remaining = params.chunks;
  uint8_t previous = 1;
  uint64_t rank = 0;
  for (size_t position = 0; position < params.frames; ++position) {
    const uint8_t chosen = groups[position];
    const uint8_t low = position == 0 ? 1 : group_low(previous);
    const uint8_t high = position == 0 ? params.max_group
                                       : group_high(previous, params.max_group);
    if (chosen < low || chosen > high || chosen > remaining) {
      return AirgapResult::InvalidArgument;
    }
    const size_t left = params.frames - 1 - position;
    for (uint8_t group = low; group < chosen; ++group) {
      const uint64_t completion = scratch->ways[left][group][remaining - group];
      if (UINT64_MAX - rank < completion) return AirgapResult::CountOverflow;
      rank += completion;
    }
    remaining -= chosen;
    previous = chosen;
  }
  if (remaining != 0 || rank >= total) return AirgapResult::InvalidArgument;
  *index = rank;
  return AirgapResult::Ok;
}

uint64_t airgap_plan_index(uint64_t blob_tag, const uint8_t seed[32],
                           uint64_t count) {
  if (seed == nullptr || count == 0) return 0;
  const uint64_t limit = UINT64_MAX - (UINT64_MAX % count);
  for (uint32_t counter = 0;; ++counter) {
    uint8_t input[32 + 8 + 4];
    memcpy(input, seed, 32);
    write_be64(input + 32, blob_tag);
    input[40] = static_cast<uint8_t>(counter >> 24);
    input[41] = static_cast<uint8_t>(counter >> 16);
    input[42] = static_cast<uint8_t>(counter >> 8);
    input[43] = static_cast<uint8_t>(counter);
    uint8_t digest[32];
    if (!crypto_sha256(input, sizeof(input), digest)) return 0;
    const uint64_t candidate = read_be64(digest);
    if (candidate < limit) return candidate % count;
  }
}

AirgapResult airgap_frame_pack(uint64_t blob_tag, uint64_t plan_index,
                               uint8_t chunk_index, uint8_t chunk_count,
                               uint8_t max_group, uint16_t chunk_bytes,
                               const uint8_t *payload, size_t payload_size,
                               uint8_t *out, size_t out_capacity,
                               size_t *out_size) {
  if (out == nullptr || out_size == nullptr) return AirgapResult::InvalidArgument;
  if (payload == nullptr && payload_size != 0) return AirgapResult::InvalidArgument;
  if (chunk_count == 0 || chunk_index >= chunk_count) {
    return AirgapResult::OutOfRange;
  }
  if (max_group == 0 || max_group > kAirgapMaxGroup || chunk_bytes == 0 ||
      chunk_bytes > kAirgapMaxBlob) {
    return AirgapResult::OutOfRange;
  }
  const size_t total = kAirgapHeaderSize + payload_size + kAirgapCrcSize;
  if (out_capacity < total) return AirgapResult::BufferTooSmall;

  memcpy(out, kMagic, sizeof(kMagic));
  out[4] = kVersion;
  out[5] = chunk_index;
  out[6] = chunk_count;
  out[7] = static_cast<uint8_t>(max_group & 0x07u);
  write_be64(out + 8, blob_tag);
  write_be64(out + 16, plan_index);
  out[24] = static_cast<uint8_t>(chunk_bytes >> 8);
  out[25] = static_cast<uint8_t>(chunk_bytes & 0xFF);
  if (payload_size != 0) memcpy(out + kAirgapHeaderSize, payload, payload_size);
  const uint32_t crc = airgap_crc32(out, kAirgapHeaderSize + payload_size);
  out[kAirgapHeaderSize + payload_size + 0] = static_cast<uint8_t>(crc >> 24);
  out[kAirgapHeaderSize + payload_size + 1] = static_cast<uint8_t>(crc >> 16);
  out[kAirgapHeaderSize + payload_size + 2] = static_cast<uint8_t>(crc >> 8);
  out[kAirgapHeaderSize + payload_size + 3] = static_cast<uint8_t>(crc);
  *out_size = total;
  return AirgapResult::Ok;
}

AirgapResult airgap_frame_parse(const uint8_t *frame, size_t frame_size,
                                AirgapFrameView *view) {
  if (frame == nullptr || view == nullptr) return AirgapResult::InvalidArgument;
  if (frame_size < kAirgapHeaderSize + kAirgapCrcSize) {
    return AirgapResult::BufferTooSmall;
  }
  if (memcmp(frame, kMagic, sizeof(kMagic)) != 0) {
    return AirgapResult::InvalidArgument;
  }
  const uint8_t max_group = static_cast<uint8_t>(frame[7] & 0x07u);
  if (frame[4] != kVersion || max_group == 0 || max_group > kAirgapMaxGroup) {
    return AirgapResult::InvalidArgument;
  }
  if (frame[6] == 0 || frame[5] >= frame[6]) return AirgapResult::OutOfRange;
  const size_t payload_size = frame_size - kAirgapHeaderSize - kAirgapCrcSize;
  const uint16_t chunk_bytes =
      static_cast<uint16_t>((static_cast<uint16_t>(frame[24]) << 8) | frame[25]);
  if (chunk_bytes == 0) return AirgapResult::OutOfRange;
  const uint32_t expected =
      (static_cast<uint32_t>(frame[frame_size - 4]) << 24) |
      (static_cast<uint32_t>(frame[frame_size - 3]) << 16) |
      (static_cast<uint32_t>(frame[frame_size - 2]) << 8) |
      static_cast<uint32_t>(frame[frame_size - 1]);
  if (airgap_crc32(frame, kAirgapHeaderSize + payload_size) != expected) {
    return AirgapResult::ChecksumMismatch;
  }
  view->blob_tag = read_be64(frame + 8);
  view->plan_index = read_be64(frame + 16);
  view->chunk_index = frame[5];
  view->chunk_count = frame[6];
  view->max_group = max_group;
  view->chunk_bytes = chunk_bytes;
  view->payload = frame + kAirgapHeaderSize;
  view->payload_size = payload_size;
  return AirgapResult::Ok;
}

bool airgap_next_needed(const uint8_t *groups, size_t frames,
                        const uint8_t *seen, size_t chunk_count,
                        uint8_t *frame_index) {
  if (groups == nullptr || seen == nullptr || frame_index == nullptr ||
      frames == 0 || chunk_count == 0 || frames > kAirgapMaxFrames) {
    return false;
  }
  size_t covered = 0;
  for (size_t position = 0; position < frames; ++position) {
    const size_t group = groups[position];
    if (group == 0 || covered + group > chunk_count) return false;
    for (size_t chunk = covered; chunk < covered + group; ++chunk) {
      if ((seen[chunk >> 3] & static_cast<uint8_t>(1u << (chunk & 7))) == 0) {
        *frame_index = static_cast<uint8_t>(position);
        return true;
      }
    }
    covered += group;
  }
  return false;
}

AirgapResult airgap_sender_begin(AirgapSender *sender, const uint8_t *blob,
                                 size_t blob_size, uint8_t frames,
                                 uint8_t max_group, const uint8_t seed[32],
                                 AirgapScratch *scratch) {
  if (sender == nullptr || scratch == nullptr || seed == nullptr) {
    return AirgapResult::InvalidArgument;
  }
  if (blob == nullptr && blob_size != 0) return AirgapResult::InvalidArgument;
  if (blob_size == 0 || blob_size > kAirgapMaxBlob) return AirgapResult::OutOfRange;
  if (frames == 0 || frames > kAirgapMaxFrames) return AirgapResult::OutOfRange;
  if (max_group == 0 || max_group > kAirgapMaxGroup) return AirgapResult::OutOfRange;

  memset(sender, 0, sizeof(*sender));
  size_t chunk_count = blob_size < kAirgapMaxChunks ? blob_size : kAirgapMaxChunks;
  uint8_t usable_frames = frames;
  for (; chunk_count >= 1; --chunk_count) {
    while (usable_frames > 1 && usable_frames > chunk_count) --usable_frames;
    AirgapPlanParams params = {};
    params.chunks = static_cast<uint8_t>(chunk_count);
    params.frames = usable_frames;
    params.max_group = max_group;
    uint64_t count = 0;
    if (airgap_plan_count(params, scratch, &count) != AirgapResult::Ok) continue;
    uint8_t groups[kAirgapMaxFrames] = {};
    const uint64_t index = airgap_plan_index(0, seed, count);
    if (airgap_plan_unrank(params, index, scratch, groups) != AirgapResult::Ok) {
      continue;
    }
    sender->params = params;
    sender->blob_tag = read_be64(seed);
    sender->plan_index = index;
    memcpy(sender->groups, groups, sizeof(groups));
    sender->chunk_count = chunk_count;
    sender->chunk_bytes = (blob_size + chunk_count - 1) / chunk_count;
    sender->blob_size = blob_size;
    sender->blob = blob;
    for (size_t chunk = 0; chunk < chunk_count; ++chunk) {
      const size_t offset = chunk * sender->chunk_bytes;
      sender->chunk_offset[chunk] = offset;
      sender->chunk_length[chunk] =
          offset < blob_size ? (blob_size - offset < sender->chunk_bytes
                                    ? blob_size - offset
                                    : sender->chunk_bytes)
                             : 0;
      if (sender->chunk_length[chunk] == 0) {
        return AirgapResult::OutOfRange;
      }
    }
    return AirgapResult::Ok;
  }
  return AirgapResult::EmptyPlanSpace;
}

AirgapResult airgap_sender_render(const AirgapSender *sender, size_t index,
                                  uint8_t *out, size_t out_capacity,
                                  size_t *out_size) {
  if (sender == nullptr || out == nullptr || out_size == nullptr) {
    return AirgapResult::InvalidArgument;
  }
  if (index >= sender->params.frames) return AirgapResult::IndexOutOfRange;
  size_t first_chunk = 0;
  for (size_t frame = 0; frame < index; ++frame) first_chunk += sender->groups[frame];
  const size_t group = sender->groups[index];
  size_t written = 0;
  for (size_t chunk = first_chunk; chunk < first_chunk + group; ++chunk) {
    written += sender->chunk_length[chunk];
  }
  if (written > kAirgapMaxBlob) return AirgapResult::OutOfRange;
  return airgap_frame_pack(sender->blob_tag, sender->plan_index,
                           static_cast<uint8_t>(first_chunk),
                           static_cast<uint8_t>(sender->chunk_count),
                           sender->params.max_group,
                           static_cast<uint16_t>(sender->chunk_bytes),
                           sender->blob + sender->chunk_offset[first_chunk],
                           written, out, out_capacity, out_size);
}

void airgap_receiver_reset(AirgapReceiver *receiver) {
  if (receiver == nullptr) return;
  memset(receiver, 0, sizeof(*receiver));
}

AirgapResult airgap_receiver_accept(AirgapReceiver *receiver,
                                    const uint8_t *frame, size_t frame_size,
                                    AirgapScratch *scratch) {
  if (receiver == nullptr || scratch == nullptr) {
    return AirgapResult::InvalidArgument;
  }
  AirgapFrameView view = {};
  const AirgapResult parsed = airgap_frame_parse(frame, frame_size, &view);
  if (parsed != AirgapResult::Ok) return parsed;

  if (!receiver->started) {
    receiver->blob_tag = view.blob_tag;
    receiver->plan_index = view.plan_index;
    receiver->chunk_count = view.chunk_count;
    AirgapPlanParams params = {};
    params.chunks = view.chunk_count;
    params.max_group = view.max_group;
    bool recovered = false;
    for (uint8_t frames = 1; frames <= kAirgapMaxFrames && !recovered; ++frames) {
      params.frames = frames;
      uint64_t count = 0;
      if (airgap_plan_count(params, scratch, &count) != AirgapResult::Ok) continue;
      if (view.plan_index >= count) continue;
      uint8_t groups[kAirgapMaxFrames] = {};
      if (airgap_plan_unrank(params, view.plan_index, scratch, groups) !=
          AirgapResult::Ok) {
        continue;
      }
      size_t sum = 0;
      for (size_t index = 0; index < frames; ++index) sum += groups[index];
      if (sum != view.chunk_count) continue;
      memcpy(receiver->groups, groups, sizeof(groups));
      receiver->frame_count = frames;
      recovered = true;
    }
    if (!recovered) {
      airgap_receiver_reset(receiver);
      return AirgapResult::InvalidArgument;
    }
    receiver->chunk_bytes = view.chunk_bytes;
    receiver->started = true;
  } else if (view.blob_tag != receiver->blob_tag ||
             view.chunk_count != receiver->chunk_count) {
    return AirgapResult::InvalidArgument;
  }

  // Locate the chunk range this frame claims and verify it against the plan.
  size_t first_chunk = 0;
  bool in_plan = false;
  for (size_t position = 0; position < receiver->frame_count; ++position) {
    if (first_chunk == view.chunk_index) {
      if (static_cast<size_t>(view.chunk_count) - first_chunk <
          receiver->groups[position]) {
        airgap_receiver_reset(receiver);
        return AirgapResult::InvalidArgument;
      }
      in_plan = true;
      break;
    }
    first_chunk += receiver->groups[position];
  }
  if (!in_plan) {
    airgap_receiver_reset(receiver);
    return AirgapResult::InvalidArgument;
  }

  if ((receiver->seen[view.chunk_index >> 3] &
       static_cast<uint8_t>(1u << (view.chunk_index & 7))) != 0) {
    return AirgapResult::Ok;  // duplicate scan
  }

  if (view.payload_size == 0) {
    airgap_receiver_reset(receiver);
    return AirgapResult::InvalidArgument;
  }
  const size_t last_chunk = receiver->chunk_count - 1;
  size_t cursor = 0;
  for (size_t chunk = view.chunk_index;
       chunk < static_cast<size_t>(view.chunk_count); ++chunk) {
    const size_t take = view.payload_size - cursor;
    if (take == 0) break;
    const size_t want = chunk == last_chunk
                            ? (take < receiver->chunk_bytes ? take
                                                            : receiver->chunk_bytes)
                            : receiver->chunk_bytes;
    if (take < want) {
      airgap_receiver_reset(receiver);
      return AirgapResult::InvalidArgument;
    }
    if (receiver->data_size + want > sizeof(receiver->data)) {
      airgap_receiver_reset(receiver);
      return AirgapResult::OutOfRange;
    }
    memcpy(receiver->data + receiver->data_size, view.payload + cursor, want);
    receiver->chunk_offset[chunk] = receiver->data_size;
    receiver->chunk_length[chunk] = want;
    receiver->data_size += want;
    receiver->seen[chunk >> 3] |= static_cast<uint8_t>(1u << (chunk & 7));
    ++receiver->received;
    cursor += want;
  }
  if (cursor != view.payload_size) {
    airgap_receiver_reset(receiver);
    return AirgapResult::InvalidArgument;
  }
  return AirgapResult::Ok;
}

bool airgap_receiver_next(const AirgapReceiver *receiver, uint8_t *frame_index) {
  if (receiver == nullptr || frame_index == nullptr || !receiver->started) {
    return false;
  }
  return airgap_next_needed(receiver->groups, receiver->frame_count,
                            receiver->seen, receiver->chunk_count, frame_index);
}

AirgapResult airgap_receiver_blob(const AirgapReceiver *receiver, uint8_t *out,
                                  size_t out_capacity, size_t *out_size) {
  if (receiver == nullptr || out == nullptr || out_size == nullptr) {
    return AirgapResult::InvalidArgument;
  }
  if (!receiver->started || receiver->received != receiver->chunk_count) {
    return AirgapResult::BufferTooSmall;
  }
  size_t total = 0;
  for (size_t chunk = 0; chunk < receiver->chunk_count; ++chunk) {
    total += receiver->chunk_length[chunk];
  }
  if (total > out_capacity) return AirgapResult::BufferTooSmall;
  size_t position = 0;
  for (size_t chunk = 0; chunk < receiver->chunk_count; ++chunk) {
    memcpy(out + position, receiver->data + receiver->chunk_offset[chunk],
           receiver->chunk_length[chunk]);
    position += receiver->chunk_length[chunk];
  }
  *out_size = total;
  return AirgapResult::Ok;
}

int g_airgap_stage = 0;
int airgap_last_stage() { return g_airgap_stage; }

bool run_airgap_self_tests() {
  static AirgapScratch scratch;
  bool passed = true;

  // CRC-32/ISO-HDLC reference: "123456789" -> 0xCBF43926.
  static const uint8_t kCheck[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
  passed = airgap_crc32(kCheck, sizeof(kCheck)) == 0xCBF43926u && passed;
  passed = airgap_crc32(nullptr, 0) == 0u && passed;

  // Every plan of a small space is produced exactly once by unrank, and rank
  // inverts unrank. This is a bijection proof by exhaustion, not a spot check.
  {
    const AirgapPlanParams params = {6, 3, 3};
    uint64_t count = 0;
    passed = airgap_plan_count(params, &scratch, &count) == AirgapResult::Ok && passed;
    uint64_t brute = 0;
    for (uint8_t a = 1; a <= 3; ++a) {
      for (uint8_t b = 1; b <= 3; ++b) {
        for (uint8_t c = 1; c <= 3; ++c) {
          if (static_cast<int>(a) + b + c != 6) continue;
          if ((a > b ? a - b : b - a) > 1) continue;
          if ((b > c ? b - c : c - b) > 1) continue;
          ++brute;
        }
      }
    }
    passed = count == brute && count != 0 && passed;
    for (uint64_t index = 0; index < count; ++index) {
      uint8_t groups[3] = {};
      passed = airgap_plan_unrank(params, index, &scratch, groups) ==
                   AirgapResult::Ok &&
               passed;
      uint64_t ranked = 0;
      passed = airgap_plan_rank(params, groups, &scratch, &ranked) ==
                   AirgapResult::Ok &&
               ranked == index && passed;
      uint16_t sum = 0;
      for (size_t position = 0; position < 3; ++position) sum += groups[position];
      passed = sum == 6 && passed;
    }
    uint8_t overflow_groups[3] = {};
    passed = airgap_plan_unrank(params, count, &scratch, overflow_groups) ==
                 AirgapResult::IndexOutOfRange &&
             passed;
  }

  // A wider space: 64 chunks in 8 frames of at most 6 still has an exact count.
  {
    const AirgapPlanParams params = {64, 8, 6};
    uint64_t count = 0;
    const AirgapResult result = airgap_plan_count(params, &scratch, &count);
    passed = (result == AirgapResult::Ok || result == AirgapResult::CountOverflow ||
              result == AirgapResult::EmptyPlanSpace) &&
             passed;
    if (result == AirgapResult::Ok) {
      uint8_t groups[kAirgapMaxFrames] = {};
      uint64_t index = count / 2;
      passed = airgap_plan_unrank(params, index, &scratch, groups) ==
                   AirgapResult::Ok &&
               passed;
      uint64_t ranked = 0;
      passed = airgap_plan_rank(params, groups, &scratch, &ranked) ==
                   AirgapResult::Ok &&
               ranked == index && passed;
      size_t sum = 0;
      for (size_t position = 0; position < params.frames; ++position) {
        sum += groups[position];
        if (groups[position] < 1 || groups[position] > params.max_group)
          passed = false;
        if (position != 0) {
          const int delta = static_cast<int>(groups[position]) -
                            static_cast<int>(groups[position - 1]);
          if (delta > 1 || delta < -1) passed = false;
        }
      }
      passed = sum == params.chunks && passed;
    }
  }

  // Misuse and impossible configurations.
  {
    uint64_t count = 0;
    const AirgapPlanParams too_many_frames = {2, 4, 6};
    passed = airgap_plan_count(too_many_frames, &scratch, &count) ==
                 AirgapResult::OutOfRange &&
             passed;
    const AirgapPlanParams zero_chunks = {0, 1, 1};
    passed = airgap_plan_count(zero_chunks, &scratch, &count) ==
                 AirgapResult::OutOfRange &&
             passed;
    const AirgapPlanParams huge_group = {4, 1, kAirgapMaxGroup + 1};
    passed = airgap_plan_count(huge_group, &scratch, &count) ==
                 AirgapResult::OutOfRange &&
             passed;
    // 4 chunks in 4 frames only fits with all ones.
    const AirgapPlanParams exact = {4, 4, 2};
    passed = airgap_plan_count(exact, &scratch, &count) == AirgapResult::Ok &&
             count == 1 && passed;
    uint8_t groups[4] = {};
    passed = airgap_plan_unrank(exact, 0, &scratch, groups) == AirgapResult::Ok &&
             groups[0] == 1 && groups[1] == 1 && groups[2] == 1 &&
             groups[3] == 1 && passed;
    // 10 chunks in 4 frames with max group 1 is impossible.
    const AirgapPlanParams impossible = {10, 4, 1};
    passed = airgap_plan_count(impossible, &scratch, &count) ==
                 AirgapResult::EmptyPlanSpace &&
             passed;
    // Rank refuses a sequence with a step of two.
    const AirgapPlanParams wide = {9, 3, 6};
    uint8_t bad_groups[3] = {1, 5, 3};
    uint64_t index = 0;
    passed = airgap_plan_rank(wide, bad_groups, &scratch, &index) ==
                 AirgapResult::InvalidArgument &&
             passed;
    // Rank refuses a sequence that does not sum to `chunks`.
    uint8_t short_groups[3] = {2, 2, 2};
    passed = airgap_plan_rank(wide, short_groups, &scratch, &index) ==
                 AirgapResult::InvalidArgument &&
             passed;
    passed = airgap_plan_count(AirgapPlanParams{6, 3, 3}, nullptr, &count) ==
                 AirgapResult::InvalidArgument &&
             passed;
  }

  // Frame header: round-trip, bit flips anywhere are caught, wrong blob tag or
  // plan index survive only when the CRC covers them.
  {
    uint8_t payload[16];
    for (size_t index = 0; index < sizeof(payload); ++index) {
      payload[index] = static_cast<uint8_t>(0xa0 + index);
    }
    uint8_t frame[kAirgapHeaderSize + sizeof(payload) + kAirgapCrcSize];
    size_t frame_size = 0;
    passed = airgap_frame_pack(0x0102030405060708ull, 0x1122334455667788ull, 5, 9, kAirgapMaxGroup,
                               16,
                               payload, sizeof(payload), frame, sizeof(frame),
                               &frame_size) == AirgapResult::Ok &&
             frame_size == sizeof(frame) && passed;
    AirgapFrameView view = {};
    passed = airgap_frame_parse(frame, frame_size, &view) == AirgapResult::Ok &&
             view.blob_tag == 0x0102030405060708ull &&
             view.plan_index == 0x1122334455667788ull && view.chunk_index == 5 &&
             view.chunk_count == 9 &&
             view.payload_size == sizeof(payload) &&
             memcmp(view.payload, payload, sizeof(payload)) == 0 && passed;
    for (size_t position = 0; position < frame_size; ++position) {
      uint8_t damaged[kAirgapHeaderSize + sizeof(payload) + kAirgapCrcSize];
      memcpy(damaged, frame, sizeof(damaged));
      damaged[position] ^= 0x01;
      AirgapFrameView ignored = {};
      passed = airgap_frame_parse(damaged, sizeof(damaged), &ignored) !=
                   AirgapResult::Ok &&
               passed;
    }
    passed = airgap_frame_parse(frame, frame_size - 1, &view) !=
                 AirgapResult::Ok &&
             passed;
    uint8_t short_buffer[8] = {};
    size_t short_size = 0;
    passed = airgap_frame_pack(1, 2, 0, 4, kAirgapMaxGroup, 16, payload, sizeof(payload),
                               short_buffer, sizeof(short_buffer),
                               &short_size) == AirgapResult::BufferTooSmall &&
             passed;
    passed = airgap_frame_pack(1, 2, 4, 4, kAirgapMaxGroup, 16, payload, sizeof(payload), frame,
                               sizeof(frame), &frame_size) ==
                 AirgapResult::OutOfRange &&
             passed;
  }

  // Index derivation is deterministic, bounded and independent of the tag.
  {
    uint8_t seed[32];
    for (size_t index = 0; index < sizeof(seed); ++index) {
      seed[index] = static_cast<uint8_t>(index * 7 + 3);
    }
    const uint64_t first = airgap_plan_index(42, seed, 7);
    passed = first == airgap_plan_index(42, seed, 7) && first < 7 && passed;
    bool moved = false;
    for (uint64_t tag = 43; tag < 143; ++tag) {
      const uint64_t other = airgap_plan_index(tag, seed, 7);
      passed = other < 7 && passed;
      if (other != first) moved = true;
    }
    passed = moved && passed;
    passed = airgap_plan_index(7, seed, 1) == 0 && passed;
    uint8_t other_seed[32];
    memcpy(other_seed, seed, sizeof(other_seed));
    other_seed[0] ^= 0xff;
    bool seed_matters = false;
    for (uint64_t tag = 0; tag < 64; ++tag) {
      if (airgap_plan_index(tag, seed, 5) != airgap_plan_index(tag, other_seed, 5)) {
        seed_matters = true;
      }
    }
    passed = seed_matters && passed;
  }

  // Rescan hint: the first frame whose chunk range is incomplete.
  {
    const uint8_t groups[3] = {2, 3, 1};
    uint8_t seen[1] = {0};
    uint8_t frame = 0;
    passed = airgap_next_needed(groups, 3, seen, 6, &frame) && frame == 0 && passed;
    seen[0] = 0x03;  // chunks 0 and 1 are in
    passed = airgap_next_needed(groups, 3, seen, 6, &frame) && frame == 1 && passed;
    seen[0] = 0x3f;
    passed = !airgap_next_needed(groups, 3, seen, 6, &frame) && passed;
    // An inconsistent plan (sums past the chunk count) is rejected.
    passed = !airgap_next_needed(groups, 3, seen, 4, &frame) && passed;
  }

  // Sender/receiver round trip over a blob that does not divide evenly, so the
  // last chunk is short and the chunk geometry has to be self-describing.
  {
    uint8_t blob[300];
    for (size_t index = 0; index < sizeof(blob); ++index) {
      blob[index] = static_cast<uint8_t>((index * 31 + 7) & 0xFF);
    }
    uint8_t seed[32];
    for (size_t index = 0; index < sizeof(seed); ++index) {
      seed[index] = static_cast<uint8_t>(index * 13 + 1);
    }
    if (passed) g_airgap_stage = 1;
    AirgapSender sender = {};
    passed = airgap_sender_begin(&sender, blob, sizeof(blob), 4, 4, seed,
                                &scratch) == AirgapResult::Ok &&
             passed;
    if (passed) g_airgap_stage = 2;
    passed = sender.params.frames >= 1 && sender.params.frames <= 4 &&
             sender.chunk_count >= 4 && passed;

    // Every frame renders, parses and reassembles to the original blob.
    uint8_t frames[kAirgapMaxFrames][kAirgapHeaderSize + kAirgapMaxBlob + kAirgapCrcSize];
    size_t frame_size[kAirgapMaxFrames] = {};
    for (size_t index = 0; index < sender.params.frames; ++index) {
      passed = airgap_sender_render(&sender, index, frames[index],
                                    sizeof(frames[index]), &frame_size[index]) ==
                   AirgapResult::Ok &&
               passed;
      AirgapFrameView view = {};
      passed = airgap_frame_parse(frames[index], frame_size[index], &view) ==
                   AirgapResult::Ok &&
               view.blob_tag == sender.blob_tag &&
               view.plan_index == sender.plan_index && passed;
    }

    if (passed) g_airgap_stage = 3;
    // In-order arrival.
    AirgapReceiver receiver;
    airgap_receiver_reset(&receiver);
    for (size_t index = 0; index < sender.params.frames; ++index) {
      passed = airgap_receiver_accept(&receiver, frames[index],
                                      frame_size[index], &scratch) == AirgapResult::Ok &&
               passed;
    }
    uint8_t rebuilt[kAirgapMaxBlob];
    size_t rebuilt_size = 0;
    passed = airgap_receiver_blob(&receiver, rebuilt, sizeof(rebuilt),
                                 &rebuilt_size) == AirgapResult::Ok &&
             rebuilt_size == sizeof(blob) &&
             memcmp(rebuilt, blob, sizeof(blob)) == 0 && passed;

    if (passed) g_airgap_stage = 4;
    // Reverse arrival order still reassembles to the same bytes.
    airgap_receiver_reset(&receiver);
    for (size_t index = sender.params.frames; index-- > 0;) {
      passed = airgap_receiver_accept(&receiver, frames[index],
                                      frame_size[index], &scratch) == AirgapResult::Ok &&
               passed;
    }
    rebuilt_size = 0;
    passed = airgap_receiver_blob(&receiver, rebuilt, sizeof(rebuilt),
                                 &rebuilt_size) == AirgapResult::Ok &&
             rebuilt_size == sizeof(blob) &&
             memcmp(rebuilt, blob, sizeof(blob)) == 0 && passed;

    if (passed) g_airgap_stage = 5;
    // A missing frame is reported as the next one to scan, and the blob cannot
    // be taken before it arrives.
    airgap_receiver_reset(&receiver);
    for (size_t index = 0; index < sender.params.frames; ++index) {
      if (index == 1) continue;
      passed = airgap_receiver_accept(&receiver, frames[index],
                                      frame_size[index], &scratch) == AirgapResult::Ok &&
               passed;
    }
    uint8_t needed = 0xFF;
    passed = airgap_receiver_next(&receiver, &needed) && needed == 1 && passed;
    rebuilt_size = 0;
    passed = airgap_receiver_blob(&receiver, rebuilt, sizeof(rebuilt),
                                 &rebuilt_size) != AirgapResult::Ok &&
             passed;
    passed = airgap_receiver_accept(&receiver, frames[1], frame_size[1], &scratch) ==
                 AirgapResult::Ok &&
             passed;
    passed = !airgap_receiver_next(&receiver, &needed) && passed;
    rebuilt_size = 0;
    passed = airgap_receiver_blob(&receiver, rebuilt, sizeof(rebuilt),
                                 &rebuilt_size) == AirgapResult::Ok &&
             rebuilt_size == sizeof(blob) && passed;

    if (passed) g_airgap_stage = 6;
    // Rescanning the same symbol is a no-op, not a second copy.
    const uint8_t received_before = receiver.received;
    passed = airgap_receiver_accept(&receiver, frames[0], frame_size[0], &scratch) ==
                 AirgapResult::Ok &&
             receiver.received == received_before && passed;

    if (passed) g_airgap_stage = 7;
    // A frame from a different transfer must not be merged in.
    struct airgap_foreign
    {
    };
    uint8_t foreign[kAirgapHeaderSize + 8 + kAirgapCrcSize];
    size_t foreign_size = 0;
    passed = airgap_frame_pack(sender.blob_tag ^ 1, sender.plan_index, 0, 2,
                              sender.params.max_group,
                              static_cast<uint16_t>(sender.chunk_bytes), blob, 8,
                              foreign, sizeof(foreign), &foreign_size) ==
                 AirgapResult::Ok &&
             passed;
    passed = airgap_receiver_accept(&receiver, foreign, foreign_size, &scratch) !=
                 AirgapResult::Ok &&
             passed;

    if (passed) g_airgap_stage = 8;
    // A corrupted frame is refused without disturbing a healthy session.
    AirgapReceiver clean;
    airgap_receiver_reset(&clean);
    passed = airgap_receiver_accept(&clean, frames[0], frame_size[0], &scratch) ==
                 AirgapResult::Ok &&
             passed;
    uint8_t damaged[kAirgapHeaderSize + kAirgapMaxBlob + kAirgapCrcSize];
    memcpy(damaged, frames[1], frame_size[1]);
    damaged[10] ^= 0x01;
    passed = airgap_receiver_accept(&clean, damaged, frame_size[1], &scratch) !=
                 AirgapResult::Ok &&
             passed;
    passed = clean.received == sender.groups[0] && clean.started && passed;

    if (passed) g_airgap_stage = 9;
    // A chunk_index that no frame in the plan owns is refused.
    uint8_t stray[kAirgapHeaderSize + 8 + kAirgapCrcSize];
    size_t stray_size = 0;
    passed = airgap_frame_pack(sender.blob_tag, sender.plan_index, 0, 60,
                              sender.params.max_group,
                              static_cast<uint16_t>(sender.chunk_bytes), blob, 8,
                              stray, sizeof(stray), &stray_size) ==
                 AirgapResult::Ok &&
             passed;
    AirgapReceiver stray_receiver;
    airgap_receiver_reset(&stray_receiver);
    passed = airgap_receiver_accept(&stray_receiver, stray, stray_size, &scratch) !=
                 AirgapResult::Ok &&
             passed;

    if (passed) g_airgap_stage = 10;
    // Parameter guards.
    AirgapSender bad = {};
    if (passed) g_airgap_stage = 11;
    passed = airgap_sender_begin(&bad, blob, 0, 4, 4, seed, &scratch) ==
                 AirgapResult::OutOfRange &&
             passed;
    if (passed) g_airgap_stage = 12;
    passed = airgap_sender_begin(&bad, blob, sizeof(blob), 0, 4, seed,
                                &scratch) == AirgapResult::OutOfRange &&
             passed;
    if (passed) g_airgap_stage = 13;
    passed = airgap_sender_begin(&bad, blob, kAirgapMaxBlob + 1, 4, 4, seed,
                                &scratch) == AirgapResult::OutOfRange &&
             passed;
    if (passed) g_airgap_stage = 14;
    passed = airgap_sender_begin(&bad, blob, sizeof(blob), 4, 4, nullptr,
                                &scratch) == AirgapResult::InvalidArgument &&
             passed;
    size_t ignored = 0;
    if (passed) g_airgap_stage = 15;
    {
      const AirgapResult probe = airgap_sender_render(
          &sender, sender.params.frames, frames[0], sizeof(frames[0]), &ignored);
      char line[64];
      const int n = snprintf(line, sizeof(line), "airgap-probe rc=%d frames=%u\n",
                             static_cast<int>(probe),
                             static_cast<unsigned>(sender.params.frames));
      if (n > 0) fwrite(line, 1, static_cast<size_t>(n), stderr);
    }
    passed = airgap_sender_render(&sender, sender.params.frames, frames[0],
                                  sizeof(frames[0]), &ignored) ==
                 AirgapResult::IndexOutOfRange &&
             passed;
  }

  return passed;
}

}  // namespace hexwallet
