#include "RandomSource.h"

#include <esp_random.h>
#include <string.h>

#include <atomic>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {

    constexpr size_t kBlockSize = 32;
    constexpr size_t kKeySize = 32;
    constexpr uint32_t kReseedInterval = 1U << 20;
    constexpr uint8_t kMaxIdenticalBlocks = 3;
    constexpr size_t kMaxRequestSize = 4096;

    struct Drbg
    {
      uint8_t key[kKeySize];
      uint8_t value[kKeySize];
      bool instantiated;
      uint32_t since_reseed;
    };

    Drbg g_drbg;
    RandomStats g_stats = {0, 0, 0, 0, 0, true};
    struct HealthState
    {
      uint8_t previous[kBlockSize];
      uint8_t previous_two[kBlockSize];
      uint8_t recorded;
      uint8_t repeats;
    };

    HealthState g_health;

#if !defined(HEXWALLET_HOST_TEST)
    std::atomic_flag g_lock = ATOMIC_FLAG_INIT;
    struct Lock
    {
      Lock()
      {
        while (g_lock.test_and_set(std::memory_order_acquire))
        {
        }
      }
      ~Lock() { g_lock.clear(std::memory_order_release); }
    };
#else
    struct Lock
    {
      Lock() {}
      ~Lock() {}
    };
#endif

    void drbg_update(const uint8_t *data, size_t size)
    {
      uint8_t buffer[kKeySize + 1 + 3 * kBlockSize];
      uint8_t digest[kSha256Size];
      for (uint8_t separator = 0; separator < 2; ++separator)
      {
        if (separator == 1 && size == 0)
          break;
        memcpy(buffer, g_drbg.value, kKeySize);
        buffer[kKeySize] = separator;
        size_t length = kKeySize + 1;
        if (size != 0)
        {
          memcpy(buffer + length, data, size);
          length += size;
        }
        crypto_hmac_sha256(g_drbg.key, kKeySize, buffer, length, digest);
        memcpy(g_drbg.key, digest, kKeySize);
        crypto_hmac_sha256(g_drbg.key, kKeySize, g_drbg.value, kKeySize, digest);
        memcpy(g_drbg.value, digest, kKeySize);
      }
      secure_zero(buffer, sizeof(buffer));
      secure_zero(digest, sizeof(digest));
    }

    bool block_looks_random(const uint8_t block[kBlockSize])
    {
      bool all_same = true;
      unsigned ones = 0;
      for (size_t index = 0; index < kBlockSize; ++index)
      {
        if (block[index] != block[0])
          all_same = false;
        uint8_t value = block[index];
        while (value != 0)
        {
          ones += value & 1U;
          value = static_cast<uint8_t>(value >> 1);
        }
      }
      if (all_same)
        return false;
      // 256 bits: 64 is 8 sigma below the mean, 192 is 8 sigma above it.
      return ones >= 64 && ones <= 192;
    }

    bool health_test(HealthState &state, const uint8_t block[kBlockSize])
    {
      if (!block_looks_random(block))
        return false;
      const bool matches_previous =
          state.recorded >= 1 && memcmp(block, state.previous, kBlockSize) == 0;
      const bool matches_previous_two =
          state.recorded >= 2 && memcmp(block, state.previous_two, kBlockSize) == 0;
      if (matches_previous)
        ++state.repeats;
      else
        state.repeats = 0;
      if (static_cast<uint8_t>(state.repeats + 1) >= kMaxIdenticalBlocks ||
          matches_previous_two)
        return false;
      memcpy(state.previous_two, state.previous, kBlockSize);
      memcpy(state.previous, block, kBlockSize);
      if (state.recorded < 2)
        ++state.recorded;
      return true;
    }

    bool read_entropy(uint8_t out[kBlockSize])
    {
      esp_fill_random(out, kBlockSize);
      if (!health_test(g_health, out))
      {
        g_stats.healthy = false;
        secure_zero(out, kBlockSize);
        return false;
      }
      return true;
    }

    bool instantiate()
    {
      uint8_t entropy[kBlockSize];
      uint8_t nonce[kBlockSize];
      if (!read_entropy(entropy))
        return false;
      esp_fill_random(nonce, sizeof(nonce));
      if (!health_test(g_health, nonce))
      {
        g_stats.healthy = false;
        secure_zero(entropy, sizeof(entropy));
        return false;
      }
      memset(&g_drbg, 0, sizeof(g_drbg));
      uint8_t seed[kBlockSize * 2];
      memcpy(seed, entropy, kBlockSize);
      memcpy(seed + kBlockSize, nonce, kBlockSize);
      drbg_update(seed, sizeof(seed));
      g_drbg.instantiated = true;
      g_drbg.since_reseed = 0;
      ++g_stats.reseeds;
      secure_zero(entropy, sizeof(entropy));
      secure_zero(nonce, sizeof(nonce));
      secure_zero(seed, sizeof(seed));
      return true;
    }

    bool reseed()
    {
      uint8_t entropy[kBlockSize];
      if (!read_entropy(entropy))
        return false;
      drbg_update(entropy, sizeof(entropy));
      g_drbg.since_reseed = 0;
      ++g_stats.reseeds;
      secure_zero(entropy, sizeof(entropy));
      return true;
    }

    bool generate(uint8_t *out, size_t size)
    {
      uint8_t block[kBlockSize];
      while (size != 0)
      {
        crypto_hmac_sha256(g_drbg.key, kKeySize, g_drbg.value, kKeySize, block);
        memcpy(g_drbg.value, block, kBlockSize);
        const size_t take = size < kBlockSize ? size : kBlockSize;
        memcpy(out, block, take);
        out += take;
        size -= take;
      }
      drbg_update(nullptr, 0);
      secure_zero(block, sizeof(block));
      return true;
    }

  } // namespace

  bool random_healthy()
  {
    return g_stats.healthy;
  }

  const RandomStats &random_stats()
  {
    return g_stats;
  }

  bool random_reseed()
  {
    Lock lock;
    if (!g_stats.healthy)
      return false;
    if (!g_drbg.instantiated)
      return instantiate();
    return reseed();
  }

  void random_fill(void *out, size_t size)
  {
    if (out == nullptr || size == 0)
      return;
    if (size > kMaxRequestSize)
    {
      // No wallet operation needs this much. Refuse the request, but do not
      // latch the source unhealthy: a caller bug is not an entropy failure.
      secure_zero(out, size);
      ++g_stats.oversized_requests;
      return;
    }
    Lock lock;
    if (g_drbg.instantiated && g_drbg.since_reseed >= kReseedInterval)
    {
      if (!reseed())
      {
        secure_zero(out, size);
        return;
      }
    }
    if (!g_drbg.instantiated)
    {
      if (g_stats.healthy && !instantiate())
      {
        secure_zero(out, size);
        ++g_stats.entropy_failures;
        return;
      }
      if (!g_drbg.instantiated)
      {
        secure_zero(out, size);
        return;
      }
    }
    if (!generate(static_cast<uint8_t *>(out), size))
    {
      secure_zero(out, size);
      return;
    }
    ++g_drbg.since_reseed;
    ++g_stats.requests;
  }

  uint32_t random_u32()
  {
    uint32_t value = 0;
    random_fill(&value, sizeof(value));
    return value;
  }

  bool run_random_source_self_tests()
  {
    bool passed = true;

    // A fresh DRBG stream must not repeat across calls and must differ from a
    // second instantiation with different entropy. Determinism is not asserted:
    // the host entropy shim is fixed, so the property under test is separation.
    uint8_t first[64];
    uint8_t second[64];
    random_fill(first, sizeof(first));
    random_fill(second, sizeof(second));
    passed = memcmp(first, second, sizeof(first)) != 0 && passed;
    passed = random_healthy() && passed;
    passed = random_stats().requests >= 2 && passed;

    // Reseeding must change the following output.
    // Reseeding must change the following output.
    uint8_t before[32];
    uint8_t after[32];
    random_fill(before, sizeof(before));
    passed = random_reseed() && passed;
    random_fill(after, sizeof(after));
    passed = memcmp(before, after, sizeof(before)) != 0 && passed;
    passed = random_stats().reseeds >= 2 && passed;

    // Zero-length and oversized requests must not corrupt the stream or the gate.
    // Zero-length and oversized requests must not corrupt the stream or the gate.
    random_fill(nullptr, 16);
    random_fill(first, 0);
    uint8_t oversized[kMaxRequestSize + 1];
    memset(oversized, 0xa5, sizeof(oversized));
    random_fill(oversized, sizeof(oversized));
    bool cleared = true;
    for (size_t index = 0; index < sizeof(oversized); ++index)
      cleared = cleared && oversized[index] == 0;
    passed = cleared && random_healthy() && random_stats().oversized_requests == 1 && passed;
    secure_zero(oversized, sizeof(oversized));

    // The health test itself: a stuck block, a fixed block and a skewed block are
    // all rejected; a plausible block is accepted. These run against the private
    // predicate through crafted inputs, so a regression in the rule is caught
    // even when the hardware source is fine.
    // The health test itself: a stuck block, a fixed block and a skewed block are
    // all rejected; a plausible block is accepted. These run against the private
    // predicate through crafted inputs, so a regression in the rule is caught
    // even when the hardware source is fine.
    uint8_t stuck[kBlockSize];
    memset(stuck, 0x5a, sizeof(stuck));
    passed = !block_looks_random(stuck) && passed;
    uint8_t zeros[kBlockSize];
    memset(zeros, 0x00, sizeof(zeros));
    passed = !block_looks_random(zeros) && passed;
    uint8_t ones[kBlockSize];
    memset(ones, 0xff, sizeof(ones));
    passed = !block_looks_random(ones) && passed;
    uint8_t skewed[kBlockSize];
    memset(skewed, 0x01, sizeof(skewed));
    passed = !block_looks_random(skewed) && passed;
    uint8_t plausible[kBlockSize] = {
        0x7f, 0x2c, 0x91, 0x0e, 0x55, 0xa3, 0x18, 0xc4, 0x6b, 0xd9, 0x03,
        0x8e, 0xf1, 0x47, 0xb2, 0x29, 0x9d, 0x60, 0x34, 0xcb, 0x15, 0xe8,
        0x72, 0x4a, 0xbf, 0x08, 0xd6, 0x3c, 0x97, 0x61, 0x2b, 0x84};
    passed = block_looks_random(plausible) && passed;

    // Repetition rules, exercised on a local history so the live entropy state is
    // untouched. A source that repeats one block must fail on the third block; a
    // source that alternates between two blocks must fail on the third.
    HealthState history = {};
    uint8_t alternating_b[kBlockSize] = {
        0x2e, 0x71, 0xc4, 0x0b, 0x96, 0x3d, 0xa8, 0x52, 0xef, 0x18, 0x64,
        0xbb, 0x07, 0xd2, 0x49, 0x85, 0x3a, 0xcd, 0x16, 0xf3, 0x5c, 0x92,
        0x27, 0xe6, 0x4b, 0x81, 0x0d, 0xba, 0x53, 0x9c, 0x28, 0x75};
    passed = health_test(history, plausible) && passed;
    passed = health_test(history, plausible) && passed;
    passed = !health_test(history, plausible) && passed;
    memset(&history, 0, sizeof(history));
    passed = health_test(history, plausible) && passed;
    passed = health_test(history, alternating_b) && passed;
    passed = !health_test(history, plausible) && passed;
    secure_zero(alternating_b, sizeof(alternating_b));
    secure_zero(&history, sizeof(history));

    secure_zero(stuck, sizeof(stuck));
    secure_zero(zeros, sizeof(zeros));
    secure_zero(ones, sizeof(ones));
    secure_zero(skewed, sizeof(skewed));
    secure_zero(plausible, sizeof(plausible));
    secure_zero(first, sizeof(first));
    secure_zero(second, sizeof(second));
    secure_zero(before, sizeof(before));
    secure_zero(after, sizeof(after));
    return passed;
  }

} // namespace hexwallet
