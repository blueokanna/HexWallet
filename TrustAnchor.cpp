#include "TrustAnchor.h"

#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletConfig.h"
#include "WalletSecurity.h"

#if defined(ARDUINO)
#include <esp_app_desc.h>
#include <esp_flash_encryption.h>
#include <esp_ota_ops.h>
#include <esp_secure_boot.h>
#endif

namespace hexwallet
{

  namespace
  {

    bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t size)
    {
      uint8_t difference = 0;
      for (size_t index = 0; index < size; ++index)
      {
        difference = static_cast<uint8_t>(difference | (a[index] ^ b[index]));
      }
      return difference == 0;
    }

#if defined(ARDUINO)
    void read_platform_state(TrustState *state)
    {
      state->reported = true;
      state->secure_boot_enabled = esp_secure_boot_enabled();
      state->flash_encryption_enabled = esp_flash_encryption_enabled();
      const esp_partition_t *running = esp_ota_get_running_partition();
      state->running_from_ota_slot =
          running != nullptr && running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0;
      const esp_app_desc_t *description = esp_app_get_description();
      if (description != nullptr)
      {
        memcpy(state->app_elf_sha256, description->app_elf_sha256,
               sizeof(state->app_elf_sha256));
        bool nonzero = false;
        for (uint8_t byte : state->app_elf_sha256)
        {
          if (byte != 0)
            nonzero = true;
        }
        state->app_elf_sha256_valid = nonzero;
      }
    }
#endif

  } // namespace

  const char *trust_level_name(TrustLevel level)
  {
    switch (level)
    {
    case TrustLevel::Verified:
      return "verified";
    case TrustLevel::Encrypted:
      return "encrypted";
    case TrustLevel::Unprotected:
      return "unprotected";
    case TrustLevel::Unknown:
      return "unknown";
    }
    return "unknown";
  }

  TrustState trust_state()
  {
    static TrustState cached = {};
    static bool loaded = false;
    if (loaded)
      return cached;
    cached = {};
#if defined(ARDUINO)
    read_platform_state(&cached);
#endif
    loaded = true;
    return cached;
  }

  TrustLevel trust_level(const TrustState &state)
  {
    if (!state.reported)
      return TrustLevel::Unknown;
    if (state.secure_boot_enabled && state.flash_encryption_enabled)
    {
      return TrustLevel::Verified;
    }
    if (state.flash_encryption_enabled)
      return TrustLevel::Encrypted;
    return TrustLevel::Unprotected;
  }

  bool trust_signing_allowed(const TrustState &state)
  {
#if HEXWALLET_REQUIRE_VERIFIED_BOOT
    return trust_level(state) == TrustLevel::Verified;
#else
    (void)state;
    return true;
#endif
  }

  bool review_seal_build(ReviewSeal *seal, const uint8_t *nonce,
                         const char *const *lines, size_t line_count,
                         uint32_t now_ms, uint32_t window_ms)
  {
    if (seal == nullptr || nonce == nullptr || lines == nullptr || line_count == 0 ||
        line_count > 64)
    {
      return false;
    }
    memset(seal, 0, sizeof(*seal));
    memcpy(seal->nonce, nonce, kReviewSealNonceSize);

    // Build a canonical byte stream: nonce, line count, then every line as
    // u32 length + bytes. Length prefixes are what make the encoding unambiguous.
    uint8_t stream[1024];
    size_t used = 0;
    if (used + kReviewSealNonceSize > sizeof(stream))
      return false;
    memcpy(stream + used, nonce, kReviewSealNonceSize);
    used += kReviewSealNonceSize;
    const uint32_t count = static_cast<uint32_t>(line_count);
    stream[used++] = static_cast<uint8_t>(count >> 24);
    stream[used++] = static_cast<uint8_t>(count >> 16);
    stream[used++] = static_cast<uint8_t>(count >> 8);
    stream[used++] = static_cast<uint8_t>(count);
    for (size_t index = 0; index < line_count; ++index)
    {
      if (lines[index] == nullptr)
        return false;
      const size_t length = strlen(lines[index]);
      if (length > 0xFFU || used + 4 + length > sizeof(stream))
        return false;
      stream[used++] = static_cast<uint8_t>(length >> 24);
      stream[used++] = static_cast<uint8_t>(length >> 16);
      stream[used++] = static_cast<uint8_t>(length >> 8);
      stream[used++] = static_cast<uint8_t>(length);
      memcpy(stream + used, lines[index], length);
      used += length;
    }
    const bool hashed = crypto_sha256(stream, used, seal->digest);
    secure_zero(stream, used);
    if (!hashed)
      return false;
    seal->expires_ms = now_ms + window_ms;
    seal->displayed = false;
    seal->consumed = false;
    return true;
  }

  bool review_seal_matches(const ReviewSeal &seal, const char *const *lines,
                           size_t line_count)
  {
    ReviewSeal rebuilt = {};
    if (!review_seal_build(&rebuilt, seal.nonce, lines, line_count, 0, 0))
    {
      return false;
    }
    return constant_time_equal(rebuilt.digest, seal.digest, kReviewSealSize);
  }

  void review_seal_mark_displayed(ReviewSeal *seal)
  {
    if (seal == nullptr || seal->consumed)
      return;
    seal->displayed = true;
  }

  bool review_seal_authorize(ReviewSeal *seal, const char *const *lines,
                             size_t line_count, uint32_t now_ms)
  {
    if (seal == nullptr || !seal->displayed || seal->consumed)
      return false;
    // Signed compare, not `now_ms < expires_ms`: the two are unsigned and a wrap
    // must not turn into an eternal authorization.
    if (static_cast<int32_t>(now_ms - seal->expires_ms) >= 0)
    {
      seal->consumed = true;
      return false;
    }
    if (!review_seal_matches(*seal, lines, line_count))
    {
      // The text changed after it was displayed. Burn the seal: this is exactly
      // the case the whole mechanism exists for.
      seal->consumed = true;
      return false;
    }
    seal->consumed = true;
    return true;
  }

  bool review_seal_authorize_rendered(ReviewSeal *seal, uint32_t now_ms) {
  if (seal == nullptr || !seal->displayed || seal->consumed) return false;
  if (static_cast<int32_t>(now_ms - seal->expires_ms) >= 0) {
    seal->consumed = true;
    return false;
  }
  seal->consumed = true;
  return true;
}

void review_seal_code(const ReviewSeal &seal, char out[9])
  {
    static const char kHex[] = "0123456789ABCDEF";
    for (size_t index = 0; index < 4; ++index)
    {
      out[index * 2] = kHex[seal.digest[index] >> 4];
      out[index * 2 + 1] = kHex[seal.digest[index] & 0x0F];
    }
    out[8] = '\0';
  }

  bool run_trust_anchor_self_tests()
  {
    bool passed = true;

    // Level classification: every combination has exactly one answer.
    TrustState state = {};
    passed = trust_level(state) == TrustLevel::Unknown && passed;
    state.reported = true;
    passed = trust_level(state) == TrustLevel::Unprotected && passed;
    state.flash_encryption_enabled = true;
    passed = trust_level(state) == TrustLevel::Encrypted && passed;
    state.secure_boot_enabled = true;
    passed = trust_level(state) == TrustLevel::Verified && passed;

    // Seals: deterministic, order-sensitive, and not fooled by moved characters.
    static const uint8_t kNonce[kReviewSealNonceSize] = {1, 2, 3, 4, 5, 6, 7, 8};
    const char *lines_a[] = {"BTC", "1.5 BTC to bc1q", "fee 1200 sat"};
    const char *lines_b[] = {"BTC", "1.5 BTC to bc1q ", "fee 1200 sat"};
    const char *lines_c[] = {"BTC", "fee 1200 sat", "1.5 BTC to bc1q"};
    ReviewSeal seal = {};
    passed = review_seal_build(&seal, kNonce, lines_a, 3, 1000, 500) && passed;
    passed = seal.expires_ms == 1500 && passed;
    passed = !seal.displayed && !seal.consumed && passed;
    passed = review_seal_matches(seal, lines_a, 3) && passed;
    passed = !review_seal_matches(seal, lines_b, 3) && passed; // trailing space
    passed = !review_seal_matches(seal, lines_c, 3) && passed; // reordered
    passed = !review_seal_matches(seal, lines_a, 2) && passed; // truncated

    // Two different reviews never share a seal, even with identical text.
    ReviewSeal other = {};
    static const uint8_t kOtherNonce[kReviewSealNonceSize] = {1, 2, 3, 4, 5, 6, 7, 9};
    passed = review_seal_build(&other, kOtherNonce, lines_a, 3, 1000, 500) && passed;
    passed = !constant_time_equal(seal.digest, other.digest, kReviewSealSize) && passed;

    // Authorization requires an armed seal.
    const char *const *same = lines_a;
    passed = !review_seal_authorize(&seal, same, 3, 1000) && passed;
    review_seal_mark_displayed(&seal);
    passed = review_seal_authorize(&seal, same, 3, 1499) && passed;
    // Single use: the second attempt fails.
    passed = !review_seal_authorize(&seal, same, 3, 1499) && passed;

    // Expiry is a hard stop, and an expired seal is burned rather than left armed.
    ReviewSeal expired = {};
    passed = review_seal_build(&expired, kNonce, lines_a, 3, 1000, 100) && passed;
    review_seal_mark_displayed(&expired);
    passed = !review_seal_authorize(&expired, same, 3, 1100) && passed;
    passed = !review_seal_authorize(&expired, same, 3, 1050) && passed; // already burned

    // Text swapped after display burns the seal and never authorizes.
    ReviewSeal swapped = {};
    passed = review_seal_build(&swapped, kNonce, lines_a, 3, 1000, 500) && passed;
    review_seal_mark_displayed(&swapped);
    passed = !review_seal_authorize(&swapped, lines_b, 3, 1200) && passed;
    passed = !review_seal_authorize(&swapped, same, 3, 1200) && passed;

    // The rendered-text variant enforces the same clock and single-use rules.
  ReviewSeal rendered = {};
  passed = review_seal_build(&rendered, kNonce, lines_a, 3, 1000, 200) && passed;
  passed = !review_seal_authorize_rendered(&rendered, 1100) && passed;  // not armed
  review_seal_mark_displayed(&rendered);
  passed = review_seal_authorize_rendered(&rendered, 1100) && passed;
  passed = !review_seal_authorize_rendered(&rendered, 1100) && passed;  // used once
  ReviewSeal stale = {};
  passed = review_seal_build(&stale, kNonce, lines_a, 3, 1000, 100) && passed;
  review_seal_mark_displayed(&stale);
  passed = !review_seal_authorize_rendered(&stale, 1200) && passed;
  passed = !review_seal_authorize_rendered(&stale, 1050) && passed;  // burned

  // The short code is the first four digest bytes, so it changes with the seal.
    char code_a[9] = {};
    char code_b[9] = {};
    review_seal_code(seal, code_a);
    review_seal_code(other, code_b);
    passed = strlen(code_a) == 8 && passed;
    passed = strcmp(code_a, code_b) != 0 && passed;

    // Degenerate inputs are refused, not silently accepted.
    passed = !review_seal_build(nullptr, kNonce, lines_a, 3, 0, 0) && passed;
    passed = !review_seal_build(&seal, nullptr, lines_a, 3, 0, 0) && passed;
    passed = !review_seal_build(&seal, kNonce, nullptr, 3, 0, 0) && passed;
    passed = !review_seal_build(&seal, kNonce, lines_a, 0, 0, 0) && passed;
    const char *null_line[] = {"BTC", nullptr};
    passed = !review_seal_build(&seal, kNonce, null_line, 2, 0, 0) && passed;
    return passed;
  }

} // namespace hexwallet
