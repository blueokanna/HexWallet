#include "DccChainCodec.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <set>
#include <vector>

using namespace hexwallet;
using Word = std::vector<int64_t>;
using Codebook = std::set<Word>;

static void require(bool condition, const char *reason) {
  if (!condition) {
    std::fprintf(stderr, "FAIL: %s\n", reason);
    std::exit(1);
  }
}

// Independent oracle: enumerate nominal integer vectors and every offset,
// then explicitly deduplicate projected visible words. No interval-state DP,
// line sums or rank implementation is shared with the production codec.
static void project_offsets(const DccChainSpec &s, const Word &x, size_t i,
                            Word *z, Codebook *result, uint64_t *pairs) {
  if (i == s.length) {
    result->insert(*z);
    ++*pairs;
    return;
  }
  for (uint32_t e = 0; e <= s.offset; ++e) {
    (*z)[i] = x[i] - e;
    project_offsets(s, x, i + 1, z, result, pairs);
  }
}

static void enumerate_hidden(const DccChainSpec &s, size_t i, Word *x,
                             Codebook *result, uint64_t *pairs) {
  if (i == s.length) {
    Word z(s.length);
    project_offsets(s, *x, 0, &z, result, pairs);
    return;
  }
  for (int64_t value = s.lower[i]; value <= s.upper[i]; ++value) {
    if (i != 0 && (value - (*x)[i - 1] < s.step_lower[i - 1] ||
                   value - (*x)[i - 1] > s.step_upper[i - 1])) continue;
    (*x)[i] = value;
    enumerate_hidden(s, i + 1, x, result, pairs);
  }
}

static Codebook project(const DccChainSpec &spec, uint64_t *pairs) {
  Word x(spec.length);
  Codebook result;
  *pairs = 0;
  enumerate_hidden(spec, 0, &x, &result, pairs);
  return result;
}

static DccChainSpec homogeneous(uint8_t length, int32_t width, uint32_t offset,
                                int32_t lo, int32_t hi) {
  DccChainSpec spec = {};
  spec.length = length;
  spec.offset = offset;
  for (size_t i = 0; i < length; ++i) {
    spec.upper[i] = width - 1;
    if (i + 1 < length) {
      spec.step_lower[i] = lo;
      spec.step_upper[i] = hi;
    }
  }
  return spec;
}

static void check_projection(DccChainCodec *codec, const DccChainSpec &spec) {
  uint64_t pairs = 0;
  const Codebook expected = project(spec, &pairs);
  const DccResult result = codec->prepare(spec);
  if (expected.empty()) {
    require(result == DccResult::EmptyCodebook && !codec->prepared() && codec->count() == 0,
            "empty projected codebook");
    return;
  }
  require(result == DccResult::Ok && codec->count() == expected.size(), "distinct projection count");
  uint64_t ordinal = 0;
  for (const Word &word : expected) {
    uint64_t rank = UINT64_MAX;
    require(codec->rank(word.data(), word.size(), &rank) == DccResult::Ok && rank == ordinal,
            "lexicographic rank agrees with independent set order");
    int64_t decoded[kDccMaxCoordinates] = {};
    require(codec->unrank(ordinal, decoded, kDccMaxCoordinates) == DccResult::Ok &&
            std::equal(word.begin(), word.end(), decoded), "unrank agrees with independent projected word");
    ++ordinal;
  }
  int64_t decoded[kDccMaxCoordinates];
  std::fill_n(decoded, kDccMaxCoordinates, int64_t{42});
  require(codec->unrank(codec->count(), decoded, kDccMaxCoordinates) == DccResult::RankOutOfRange &&
          decoded[0] == 42, "invalid rank leaves output untouched");
  Word invalid(spec.length);
  std::copy(expected.begin()->begin(), expected.begin()->end(), invalid.begin());
  invalid[0] = static_cast<int64_t>(spec.lower[0]) - spec.offset - 1;
  uint64_t rank = UINT64_MAX;
  require(codec->rank(invalid.data(), invalid.size(), &rank) == DccResult::InvalidWord && rank == 0,
          "out of domain word rejected");
}

static uint32_t random_word(uint32_t *state) {
  *state ^= *state << 13;
  *state ^= *state >> 17;
  *state ^= *state << 5;
  return *state;
}

// Performance comparator, not the correctness oracle: the straightforward
// interval-state DP scans every visible next label. Arithmetic is checked.
static uint64_t scan_count(const DccChainSpec &s) {
  uint64_t table[kDccMaxCoordinates][kDccMaxNodeWidth][kDccMaxNodeWidth] = {};
  for (size_t reverse = s.length; reverse > 0; --reverse) {
    const size_t j = reverse - 1;
    for (int64_t l = s.lower[j]; l <= s.upper[j]; ++l) {
      for (int64_t u = l; u <= std::min<int64_t>(s.upper[j], l + s.offset); ++u) {
        uint64_t c = 1;
        if (j + 1 < s.length) {
          c = 0;
          const int64_t a = std::max<int64_t>(s.lower[j + 1], l + s.step_lower[j]);
          const int64_t b = std::min<int64_t>(s.upper[j + 1], u + s.step_upper[j]);
          if (a <= b) {
            for (int64_t t = a - s.offset; t <= b; ++t) {
              const auto il = static_cast<size_t>(std::max(a, t) - s.lower[j + 1]);
              const auto iu = static_cast<size_t>(std::min(b, t + s.offset) - s.lower[j + 1]);
              const uint64_t add = table[j + 1][il][iu];
              require(add <= UINT64_MAX - c, "scan comparator count overflow");
              c += add;
            }
          }
        }
        table[j][l - s.lower[j]][u - s.lower[j]] = c;
      }
    }
  }
  uint64_t total = 0;
  for (int64_t t = static_cast<int64_t>(s.lower[0]) - s.offset; t <= s.upper[0]; ++t) {
    const auto l = static_cast<size_t>(std::max<int64_t>(s.lower[0], t) - s.lower[0]);
    const auto u = static_cast<size_t>(std::min<int64_t>(s.upper[0], t + s.offset) - s.lower[0]);
    require(table[0][l][u] <= UINT64_MAX - total, "scan comparator initial overflow");
    total += table[0][l][u];
  }
  return total;
}

static void benchmark(DccChainCodec *codec, uint32_t offset) {
  const DccChainSpec spec = homogeneous(6, 8, offset, -1, 1);
  require(codec->prepare(spec) == DccResult::Ok, "benchmark prepare");
  const uint64_t expected = codec->count();
  require(scan_count(spec) == expected, "aggregate and scanning counts agree");
  constexpr size_t repetitions = 100;
  using Clock = std::chrono::steady_clock;
  auto start = Clock::now();
  for (size_t i = 0; i < repetitions; ++i)
    require(codec->prepare(spec) == DccResult::Ok && codec->count() == expected, "aggregate benchmark");
  const auto aggregate_us = std::chrono::duration<double, std::micro>(Clock::now() - start).count() / repetitions;
  start = Clock::now();
  for (size_t i = 0; i < repetitions; ++i) require(scan_count(spec) == expected, "scan benchmark");
  const auto scan_us = std::chrono::duration<double, std::micro>(Clock::now() - start).count() / repetitions;
  start = Clock::now();
  for (uint64_t i = 0; i < 128; ++i) {
    const uint64_t rank = (expected / 128) * i;
    int64_t word[kDccMaxCoordinates] = {};
    uint64_t result = UINT64_MAX;
    require(codec->unrank(rank, word, kDccMaxCoordinates) == DccResult::Ok &&
            codec->rank(word, spec.length, &result) == DccResult::Ok && result == rank,
            "benchmark rank/unrank roundtrip");
  }
  const auto query_us = std::chrono::duration<double, std::micro>(Clock::now() - start).count() / 128;
  std::printf("benchmark k=6 N=8 h=%u count=%llu interval_entries=%zu object_bytes=%zu "
              "aggregate_prepare_us=%.3f scan_prepare_us=%.3f roundtrip_us=%.3f reps=%zu\n",
              offset, static_cast<unsigned long long>(expected), codec->stored_interval_count(),
              sizeof(*codec), aggregate_us, scan_us, query_us, repetitions);
}

int main() {
  static DccChainCodec codec;
  uint64_t rank = 123;
  int64_t word[kDccMaxCoordinates] = {};
  require(codec.rank(word, 1, &rank) == DccResult::NotPrepared && rank == 0, "unprepared rank");
  require(codec.unrank(0, word, kDccMaxCoordinates) == DccResult::NotPrepared, "unprepared unrank");

  auto spec = homogeneous(2, 2, 1, 0, 0);
  uint64_t pairs = 0;
  const auto projected = project(spec, &pairs);
  require(pairs == 8 && projected.size() == 7, "paper ambiguity example: 8 explanations, 7 words");
  check_projection(&codec, spec);

  spec = homogeneous(3, 6, 3, 0, 1);
  check_projection(&codec, spec);
  const int64_t paper_word[] = {-3, -1, 0};
  require(codec.count() == 320 && codec.rank(paper_word, 3, &rank) == DccResult::Ok && rank == 14,
          "paper section 3.3: Q=320, rank(-3,-1,0)=14");
  require(codec.stored_interval_count() == 54, "paper 18 interval states per layer");

  for (uint32_t h = 0; h <= 6; ++h) {
    for (int32_t n = 1; n <= 5; ++n) {
      check_projection(&codec, homogeneous(2, n, h, -1, 1));
      check_projection(&codec, homogeneous(2, n, h, 0, 0));
    }
  }
  uint32_t state = 0xdcc27001U;
  for (size_t trial = 0; trial < 300; ++trial) {
    spec = {};
    spec.length = static_cast<uint8_t>(1 + random_word(&state) % 4);
    spec.offset = random_word(&state) % 4;
    for (size_t i = 0; i < spec.length; ++i) {
      spec.lower[i] = static_cast<int32_t>(random_word(&state) % 9) - 4;
      spec.upper[i] = spec.lower[i] + static_cast<int32_t>(random_word(&state) % 4);
      if (i + 1 < spec.length) {
        spec.step_lower[i] = static_cast<int32_t>(random_word(&state) % 7) - 3;
        spec.step_upper[i] = spec.step_lower[i] + static_cast<int32_t>(random_word(&state) % 5);
      }
    }
    check_projection(&codec, spec);
  }

  spec = homogeneous(3, 1, 0, 0, 0);
  check_projection(&codec, spec);
  require(codec.count() == 1, "singleton codebook");
  spec = homogeneous(2, 2, 0, 0, 0);
  require(codec.prepare(spec) == DccResult::Ok, "invalid word profile");
  word[0] = 0; word[1] = 1;
  require(codec.rank(word, 2, &rank) == DccResult::InvalidWord && rank == 0,
          "node-valid but difference-invalid word");
  word[0] = INT64_MIN;
  require(codec.rank(word, 2, &rank) == DccResult::InvalidWord, "INT64_MIN untrusted word");
  word[0] = INT64_MAX;
  require(codec.rank(word, 2, &rank) == DccResult::InvalidWord, "INT64_MAX untrusted word");
  require(codec.unrank(0, word, 1) == DccResult::BufferTooSmall, "short output");

  spec = homogeneous(1, 1, kDccMaxOffset, 0, 0);
  spec.lower[0] = spec.upper[0] = INT32_MIN;
  require(codec.prepare(spec) == DccResult::Ok && codec.count() == 65536 &&
          codec.unrank(0, word, kDccMaxCoordinates) == DccResult::Ok &&
          word[0] == static_cast<int64_t>(INT32_MIN) - 65535 &&
          codec.rank(word, 1, &rank) == DccResult::Ok && rank == 0, "minimum signed endpoint");
  spec.lower[0] = spec.upper[0] = INT32_MAX;
  require(codec.prepare(spec) == DccResult::Ok &&
          codec.unrank(65535, word, kDccMaxCoordinates) == DccResult::Ok && word[0] == INT32_MAX,
          "maximum signed endpoint");

  spec = homogeneous(4, 1, 65534, 0, 0);
  require(codec.prepare(spec) == DccResult::Ok && codec.count() == 18445618199572250625ULL,
          "exact count near uint64 limit");
  require(codec.unrank(codec.count() - 1, word, kDccMaxCoordinates) == DccResult::Ok &&
          codec.rank(word, 4, &rank) == DccResult::Ok && rank == codec.count() - 1,
          "near-uint64 final rank roundtrip");
  spec.offset = 65535;
  require(codec.prepare(spec) == DccResult::CountOverflow && !codec.prepared() && codec.count() == 0 &&
          codec.unrank(0, word, kDccMaxCoordinates) == DccResult::NotPrepared,
          "2^64 codebook refuses overflow and stale tables");
  spec.length = 0;
  require(codec.prepare(spec) == DccResult::OutOfRange, "zero coordinates");
  spec = homogeneous(1, 17, 0, 0, 0);
  require(codec.prepare(spec) == DccResult::OutOfRange, "node width bound");
  spec = homogeneous(2, 1, 0, 1, 0);
  require(codec.prepare(spec) == DccResult::InvalidArgument, "reversed difference interval");
  spec = homogeneous(1, 1, kDccMaxOffset + 1, 0, 0);
  require(codec.prepare(spec) == DccResult::OutOfRange, "offset bound");
  spec = homogeneous(2, 1, 0, INT32_MIN, INT32_MAX);
  spec.lower[0] = spec.upper[0] = INT32_MIN;
  spec.lower[1] = spec.upper[1] = INT32_MAX;
  require(codec.prepare(spec) == DccResult::EmptyCodebook, "wide signed endpoint difference is not truncated");

  for (uint32_t h : {8U, 64U, 512U}) benchmark(&codec, h);
  std::puts("dcc=pass oracle=explicit-hidden-offset-projection randomized_specs=300 seed=0xdcc27001");
  return 0;
}
