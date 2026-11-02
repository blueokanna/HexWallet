#include "DccChainCodec.h"

#include <string.h>

namespace hexwallet {
namespace {

int64_t minimum(int64_t a, int64_t b) { return a < b ? a : b; }
int64_t maximum(int64_t a, int64_t b) { return a > b ? a : b; }

bool add_exact(uint64_t a, uint64_t b, uint64_t *out) {
  if (b > UINT64_MAX - a) return false;
  *out = a + b;
  return true;
}

bool multiply_exact(uint64_t a, uint64_t b, uint64_t *out) {
  if (a != 0 && b > UINT64_MAX / a) return false;
  *out = a * b;
  return true;
}

}  // namespace

DccChainCodec::DccChainCodec() : layers_{}, spec_{}, count_(0), prepared_(false) {}

size_t DccChainCodec::slot(size_t lower, size_t upper) {
  // Packed upper triangle of the fixed maximum node domain. This expression
  // avoids unsigned lower-1 when lower is zero.
  return lower * (2 * kDccMaxNodeWidth - lower + 1) / 2 + upper - lower;
}

uint64_t DccChainCodec::completion(size_t layer, int64_t lower, int64_t upper) const {
  if (lower < spec_.lower[layer] || upper > spec_.upper[layer] || lower > upper ||
      upper - lower > spec_.offset) return 0;
  return layers_[layer].count[slot(static_cast<size_t>(lower - spec_.lower[layer]),
                                   static_cast<size_t>(upper - spec_.lower[layer]))];
}

uint64_t DccChainCodec::row_prefix(size_t layer, int64_t lower, int64_t upper) const {
  if (upper < lower) return 0;
  return layers_[layer].row[slot(static_cast<size_t>(lower - spec_.lower[layer]),
                                 static_cast<size_t>(upper - spec_.lower[layer]))];
}

uint64_t DccChainCodec::column_prefix(size_t layer, int64_t lower, int64_t upper) const {
  if (lower < maximum(spec_.lower[layer], upper - spec_.offset)) return 0;
  return layers_[layer].column[slot(static_cast<size_t>(lower - spec_.lower[layer]),
                                    static_cast<size_t>(upper - spec_.lower[layer]))];
}

uint64_t DccChainCodec::diagonal_prefix(size_t layer, int64_t lower) const {
  if (lower < spec_.lower[layer]) return 0;
  return layers_[layer].diagonal[static_cast<size_t>(lower - spec_.lower[layer])];
}

bool DccChainCodec::build_sums(size_t layer) {
  const int64_t a = spec_.lower[layer], b = spec_.upper[layer];
  const int64_t h = spec_.offset;
  for (int64_t lower = a; lower <= b; ++lower) {
    uint64_t sum = 0;
    for (int64_t upper = lower; upper <= minimum(b, lower + h); ++upper) {
      if (!add_exact(sum, completion(layer, lower, upper), &sum)) return false;
      layers_[layer].row[slot(static_cast<size_t>(lower - a),
                              static_cast<size_t>(upper - a))] = sum;
    }
  }
  for (int64_t upper = a; upper <= b; ++upper) {
    uint64_t sum = 0;
    for (int64_t lower = maximum(a, upper - h); lower <= upper; ++lower) {
      if (!add_exact(sum, completion(layer, lower, upper), &sum)) return false;
      layers_[layer].column[slot(static_cast<size_t>(lower - a),
                                 static_cast<size_t>(upper - a))] = sum;
    }
  }
  uint64_t diagonal = 0;
  for (int64_t lower = a; lower <= b - h; ++lower) {
    if (!add_exact(diagonal, completion(layer, lower, lower + h), &diagonal)) return false;
    layers_[layer].diagonal[static_cast<size_t>(lower - a)] = diagonal;
  }
  return true;
}

bool DccChainCodec::mass(size_t layer, int64_t a, int64_t b,
                        int64_t visible_max, uint64_t *out) const {
  *out = 0;
  if (a > b) return true;
  const int64_t h = spec_.offset;
  if (visible_max < a - h) return true;
  const int64_t cap = minimum(visible_max, b);
  uint64_t total = 0, contribution = 0;

  // Table 2 and equation (13): each piece is clipped to (-infinity, cap].
  // The pieces are disjoint even at d=h, h=0 and singleton hidden domains.
  int64_t r = a - h, s = minimum(cap, minimum(a - 1, b - h));
  if (r <= s) {
    total = row_prefix(layer, a, s + h) - row_prefix(layer, a, r + h - 1);
  }
  if (b - a >= h) {
    r = a;
    s = minimum(cap, b - h);
    if (r <= s) {
      contribution = diagonal_prefix(layer, s) - diagonal_prefix(layer, r - 1);
      if (!add_exact(total, contribution, &total)) return false;
    }
  } else {
    r = b - h + 1;
    s = minimum(cap, a - 1);
    if (r <= s) {
      // Many distinct labels reach one interval: multiply its suffix mass,
      // rather than counting that interval once or counting its explanations.
      if (!multiply_exact(static_cast<uint64_t>(s - r + 1),
                          completion(layer, a, b), &contribution) ||
          !add_exact(total, contribution, &total)) return false;
    }
  }
  r = maximum(a, b - h + 1);
  s = cap;
  if (r <= s) {
    contribution = column_prefix(layer, s, b) - column_prefix(layer, r - 1, b);
    if (!add_exact(total, contribution, &total)) return false;
  }
  *out = total;
  return true;
}

DccResult DccChainCodec::prepare(const DccChainSpec &spec) {
  // A failed reconfiguration must never leave the previous codebook usable.
  prepared_ = false;
  count_ = 0;
  if (spec.length == 0 || spec.length > kDccMaxCoordinates ||
      spec.offset > kDccMaxOffset) return DccResult::OutOfRange;
  for (size_t i = 0; i < spec.length; ++i) {
    const int64_t width = static_cast<int64_t>(spec.upper[i]) - spec.lower[i] + 1;
    if (width < 1 || width > static_cast<int64_t>(kDccMaxNodeWidth))
      return DccResult::OutOfRange;
    if (i + 1 < spec.length && spec.step_lower[i] > spec.step_upper[i])
      return DccResult::InvalidArgument;
  }
  spec_ = spec;
  memset(layers_, 0, sizeof(layers_));
  for (size_t reverse = spec_.length; reverse > 0; --reverse) {
    const size_t layer = reverse - 1;
    const int64_t a = spec_.lower[layer], b = spec_.upper[layer];
    for (int64_t lower = a; lower <= b; ++lower) {
      for (int64_t upper = lower; upper <= minimum(b, lower + spec_.offset); ++upper) {
        uint64_t value = 1;  // C_k(L,U) = 1 for every valid interval.
        if (layer + 1 < spec_.length) {
          const int64_t next_lower = maximum(spec_.lower[layer + 1],
                                             lower + spec_.step_lower[layer]);
          const int64_t next_upper = minimum(spec_.upper[layer + 1],
                                             upper + spec_.step_upper[layer]);
          if (!mass(layer + 1, next_lower, next_upper, next_upper, &value))
            return DccResult::CountOverflow;
        }
        layers_[layer].count[slot(static_cast<size_t>(lower - a),
                                  static_cast<size_t>(upper - a))] = value;
      }
    }
    if (!build_sums(layer)) return DccResult::CountOverflow;
  }
  if (!mass(0, spec_.lower[0], spec_.upper[0], spec_.upper[0], &count_)) {
    count_ = 0;
    return DccResult::CountOverflow;
  }
  if (count_ == 0) return DccResult::EmptyCodebook;
  prepared_ = true;
  return DccResult::Ok;
}

size_t DccChainCodec::stored_interval_count() const {
  if (!prepared_) return 0;
  size_t sum = 0;
  for (size_t i = 0; i < spec_.length; ++i) {
    const size_t n = static_cast<size_t>(static_cast<int64_t>(spec_.upper[i]) - spec_.lower[i] + 1);
    const size_t r = spec_.offset < n - 1 ? spec_.offset : n - 1;
    sum += (r + 1) * n - r * (r + 1) / 2;
  }
  return sum;
}

DccResult DccChainCodec::rank(const int64_t *word, size_t length, uint64_t *out_rank) const {
  if (out_rank != nullptr) *out_rank = 0;
  if (word == nullptr || out_rank == nullptr) return DccResult::InvalidArgument;
  if (!prepared_) return DccResult::NotPrepared;
  if (length != spec_.length) return DccResult::InvalidWord;
  uint64_t result = 0;
  int64_t a = spec_.lower[0], b = spec_.upper[0];
  for (size_t i = 0; i < length; ++i) {
    const int64_t value = word[i];
    // Check before subtracting one or adding h: a malicious INT64 endpoint
    // cannot overflow the arithmetic used for a legal visible domain.
    if (a > b || value < a - spec_.offset || value > b) return DccResult::InvalidWord;
    uint64_t before = 0;
    if (!mass(i, a, b, value - 1, &before) || !add_exact(result, before, &result))
      return DccResult::CountOverflow;
    const int64_t lower = maximum(a, value);
    const int64_t upper = minimum(b, value + spec_.offset);
    if (completion(i, lower, upper) == 0) return DccResult::InvalidWord;
    if (i + 1 < length) {
      a = maximum(spec_.lower[i + 1], lower + spec_.step_lower[i]);
      b = minimum(spec_.upper[i + 1], upper + spec_.step_upper[i]);
    }
  }
  if (result >= count_) return DccResult::InvalidWord;
  *out_rank = result;
  return DccResult::Ok;
}

DccResult DccChainCodec::unrank(uint64_t rank_value, int64_t *out_word, size_t capacity) const {
  if (out_word == nullptr) return DccResult::InvalidArgument;
  if (!prepared_) return DccResult::NotPrepared;
  if (capacity < spec_.length) return DccResult::BufferTooSmall;
  if (rank_value >= count_) return DccResult::RankOutOfRange;
  int64_t decoded[kDccMaxCoordinates] = {};
  int64_t a = spec_.lower[0], b = spec_.upper[0];
  for (size_t i = 0; i < spec_.length; ++i) {
    int64_t low = a - spec_.offset, high = b;
    while (low < high) {
      const int64_t middle = low + (high - low) / 2;
      uint64_t cumulative = 0;
      if (!mass(i, a, b, middle, &cumulative)) return DccResult::CountOverflow;
      if (cumulative > rank_value) high = middle;
      else low = middle + 1;
    }
    uint64_t before = 0;
    if (!mass(i, a, b, low - 1, &before)) return DccResult::CountOverflow;
    if (before > rank_value) return DccResult::RankOutOfRange;
    rank_value -= before;
    decoded[i] = low;
    const int64_t lower = maximum(a, low), upper = minimum(b, low + spec_.offset);
    if (rank_value >= completion(i, lower, upper)) return DccResult::RankOutOfRange;
    if (i + 1 < spec_.length) {
      a = maximum(spec_.lower[i + 1], lower + spec_.step_lower[i]);
      b = minimum(spec_.upper[i + 1], upper + spec_.step_upper[i]);
    }
  }
  memcpy(out_word, decoded, spec_.length * sizeof(decoded[0]));
  return DccResult::Ok;
}

}  // namespace hexwallet
