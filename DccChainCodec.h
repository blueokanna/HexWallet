#ifndef HEXWALLET_DCC_CHAIN_CODEC_H
#define HEXWALLET_DCC_CHAIN_CODEC_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

constexpr size_t kDccMaxCoordinates = 16;
constexpr size_t kDccMaxNodeWidth = 16;
constexpr uint32_t kDccMaxOffset = 65535;
constexpr size_t kDccIntervalSlots =
    kDccMaxNodeWidth * (kDccMaxNodeWidth + 1) / 2;

// P consists of integer x with lower[i] <= x[i] <= upper[i] and
// step_lower[i] <= x[i+1]-x[i] <= step_upper[i]. The visible codebook is
// {z : exists x in P with 0 <= x[i]-z[i] <= offset}. Coordinates are read
// in array order. All parameters are shared side information, not encoded data.
struct DccChainSpec {
  uint8_t length;
  uint32_t offset;
  int32_t lower[kDccMaxCoordinates];
  int32_t upper[kDccMaxCoordinates];
  int32_t step_lower[kDccMaxCoordinates - 1];
  int32_t step_upper[kDccMaxCoordinates - 1];
};

enum class DccResult : uint8_t {
  Ok,
  InvalidArgument,
  OutOfRange,
  EmptyCodebook,
  CountOverflow,
  NotPrepared,
  InvalidWord,
  RankOutOfRange,
  BufferTooSmall,
};

// Original implementation of the absolute-interval chain construction in
// "Exact Enumerative Coding of Projected Difference Constraints", v27, §3.
// Counts distinct visible words, not hidden explanations. No dynamic allocation
// or cryptographic behavior. All count arithmetic is exact uint64_t; overflow
// invalidates the instance. Queries are read-only and may run concurrently
// after successful preparation; prepare() requires exclusive ownership.
//
// This object is roughly 54 KiB. Place it in static storage or an appropriately
// sized caller allocation, never an ESP32 task's small automatic stack.
class DccChainCodec {
 public:
  DccChainCodec();
  DccChainCodec(const DccChainCodec &) = delete;
  DccChainCodec &operator=(const DccChainCodec &) = delete;

  DccResult prepare(const DccChainSpec &spec);
  uint64_t count() const { return prepared_ ? count_ : 0; }
  size_t stored_interval_count() const;
  bool prepared() const { return prepared_; }

  // Exact word length required. Visible symbols use int64_t because lower-h
  // can lie below INT32_MIN even when nominal endpoints fit int32_t.
  // On failure rank is set to zero; unrank leaves the caller's word unchanged.
  DccResult rank(const int64_t *word, size_t length, uint64_t *out_rank) const;
  DccResult unrank(uint64_t rank, int64_t *out_word, size_t capacity) const;

 private:
  struct Layer {
    uint64_t count[kDccIntervalSlots];
    uint64_t row[kDccIntervalSlots];
    uint64_t column[kDccIntervalSlots];
    uint64_t diagonal[kDccMaxNodeWidth];
  } layers_[kDccMaxCoordinates];
  DccChainSpec spec_;
  uint64_t count_;
  bool prepared_;

  static size_t slot(size_t lower, size_t upper);
  uint64_t completion(size_t layer, int64_t lower, int64_t upper) const;
  uint64_t row_prefix(size_t layer, int64_t lower, int64_t upper) const;
  uint64_t column_prefix(size_t layer, int64_t lower, int64_t upper) const;
  uint64_t diagonal_prefix(size_t layer, int64_t lower) const;
  bool build_sums(size_t layer);
  bool mass(size_t layer, int64_t lower, int64_t upper, int64_t visible_max,
            uint64_t *out) const;
};

}  // namespace hexwallet

#endif
