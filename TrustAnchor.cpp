#include "TrustAnchor.h"

#include <string.h>
#include <mbedtls/md.h>

#include "CryptoPrimitives.h"
#include "WalletConfig.h"
#include "WalletSecurity.h"

#if defined(ARDUINO)
// The Arduino core ships neither esp_flash_encryption.h nor the private
// bootloader headers that esp_secure_boot.h pulls in (soc/efuse_reg.h,
// rom/efuse.h, ...). That is what broke the CI device build. What *is* available
// is documented here rather than papered over:
//
//   * esp_flash_encryption_enabled() is defined by libbootloader_support.a
//     (checked with nm) even though its header is missing, so the prototype is
//     declared locally and the real eFuse-backed answer is used;
//   * secure boot cannot be read at runtime without those private headers, so the
//     sdkconfig that arduino-cli compiles with is used instead. CONFIG_SECURE_BOOT
//     means the bootloader refuses unsigned images; it does not prove the eFuses
//     are burned, and TrustState records which of the two it is.
#include <esp_err.h>
#include <esp_ota_ops.h> // brings esp_app_desc_t and esp_partition.h

extern "C" bool esp_flash_encryption_enabled(void);

#if defined(CONFIG_SECURE_BOOT) || defined(CONFIG_SECURE_BOOT_V2_ENABLED)
#define HEXWALLET_SECURE_BOOT_COMPILED 1
#else
#define HEXWALLET_SECURE_BOOT_COMPILED 0
#endif
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
    bool flash_encryption_state(bool *known)
    {
      // The symbol is part of bootloader_support on every core this firmware
      // targets, so the answer is always known; only the header may be absent.
      *known = true;
      return esp_flash_encryption_enabled();
    }

    bool secure_boot_state()
    {
      return HEXWALLET_SECURE_BOOT_COMPILED != 0;
    }

    void read_platform_state(TrustState *state)
    {
      state->reported = true;
      state->secure_boot_enabled = secure_boot_state();
      // Compiled-in secure boot, not a runtime eFuse read: the header chain for a
      // runtime check is not shipped by the Arduino core.
      state->secure_boot_from_config = HEXWALLET_SECURE_BOOT_COMPILED != 0;
      state->flash_encryption_enabled =
          flash_encryption_state(&state->flash_encryption_known);
      const esp_partition_t *running = esp_ota_get_running_partition();
      state->running_from_ota_slot =
          running != nullptr && running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0;
      const esp_app_desc_t *description = esp_ota_get_app_description();
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
    // Without a readable flash-encryption state the device cannot be classified,
    // so it is never promoted to Verified.
    if (!state.flash_encryption_known)
      return TrustLevel::Unknown;
    if (state.secure_boot_enabled && !state.secure_boot_from_config &&
        state.flash_encryption_enabled)
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
    if (seal == nullptr) return false;
    // Copy first: nonce may refer to seal->nonce when a review is rebuilt.
    uint8_t nonce_copy[kReviewSealNonceSize] = {};
    if (nonce != nullptr) memcpy(nonce_copy, nonce, sizeof(nonce_copy));
    memset(seal, 0, sizeof(*seal));
    seal->consumed = true; // Every failure revokes any previous authorization.
    if (nonce == nullptr || lines == nullptr || line_count == 0 ||
        line_count > kReviewSealMaxLines || window_ms > INT32_MAX) return false;

    // Preserve the canonical encoding without a large stack buffer: nonce,
    // big-endian u32 count, then u32 length + exact bytes for each label.
    mbedtls_md_context_t context;
    mbedtls_md_init(&context);
    struct Cleanup {
      mbedtls_md_context_t *context;
      ~Cleanup() { mbedtls_md_free(context); }
    } cleanup{&context};
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == nullptr || mbedtls_md_setup(&context, info, 0) != 0 ||
        mbedtls_md_starts(&context) != 0 ||
        mbedtls_md_update(&context, nonce_copy, sizeof(nonce_copy)) != 0) return false;
    auto length_prefix = [&context](size_t length) {
      const uint8_t bytes[4] = {static_cast<uint8_t>(length >> 24),
          static_cast<uint8_t>(length >> 16), static_cast<uint8_t>(length >> 8),
          static_cast<uint8_t>(length)};
      return mbedtls_md_update(&context, bytes, sizeof(bytes)) == 0;
    };
    if (!length_prefix(line_count)) return false;
    size_t text_bytes = 0;
    for (size_t index = 0; index < line_count; ++index)
    {
      if (lines[index] == nullptr)
        return false;
      size_t length = 0;
      while (length <= kReviewSealMaxLineBytes && lines[index][length] != '\0') ++length;
      if (length > kReviewSealMaxLineBytes ||
          length > kReviewSealMaxTextBytes - text_bytes) return false;
      text_bytes += length;
      if (!length_prefix(length) ||
          mbedtls_md_update(&context, reinterpret_cast<const uint8_t *>(lines[index]), length) != 0)
        return false;
    }
    if (mbedtls_md_finish(&context, seal->digest) != 0) {
      secure_zero(seal->digest, sizeof(seal->digest));
      return false;
    }
    memcpy(seal->nonce, nonce_copy, sizeof(nonce_copy));
    seal->expires_ms = now_ms + window_ms;
    seal->built = true;
    seal->displayed = false;
    seal->consumed = false;
    return true;
  }

  bool review_seal_matches(const ReviewSeal &seal, const char *const *lines,
                           size_t line_count)
  {
    if (!seal.built) return false;
    ReviewSeal rebuilt = {};
    if (!review_seal_build(&rebuilt, seal.nonce, lines, line_count, 0, 0))
    {
      return false;
    }
    return constant_time_equal(rebuilt.digest, seal.digest, kReviewSealSize);
  }

  void review_seal_mark_displayed(ReviewSeal *seal)
  {
    if (seal == nullptr || !seal->built || seal->consumed)
      return;
    seal->displayed = true;
  }

  bool review_seal_authorize(ReviewSeal *seal, const char *const *lines,
                             size_t line_count, uint32_t now_ms)
  {
    if (seal == nullptr || !seal->built || !seal->displayed || seal->consumed)
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
  if (seal == nullptr || !seal->built || !seal->displayed || seal->consumed) return false;
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
    // Reported but unreadable encryption state is still "unknown", never
    // "unprotected": the device must not be classified on a guess.
    passed = trust_level(state) == TrustLevel::Unknown && passed;
    state.flash_encryption_known = true;
    passed = trust_level(state) == TrustLevel::Unprotected && passed;
    state.flash_encryption_enabled = true;
    passed = trust_level(state) == TrustLevel::Encrypted && passed;
    state.secure_boot_enabled = true;
    passed = trust_level(state) == TrustLevel::Verified && passed;
    state.secure_boot_from_config = true;
    passed = trust_level(state) == TrustLevel::Encrypted && passed;

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
    review_seal_mark_displayed(&seal);
    passed = !seal.built && !seal.displayed && seal.consumed && passed;
    passed = !review_seal_authorize_rendered(&seal, UINT32_MAX) && passed;

    // Full EVM access-list labels exceed the former 255-byte/1 KiB limits.
    // Exercise the last byte, truncation rejection, line count and total cap.
    static char large[kReviewSealMaxLineBytes + 2];
    memset(large, 'A', sizeof(large));
    large[kReviewSealMaxLineBytes] = '\0';
    const char *long_lines[] = {"ETH", large};
    passed = review_seal_build(&seal, kNonce, long_lines, 2, UINT32_MAX - 49, 100) && passed;
    passed = review_seal_matches(seal, long_lines, 2) && passed;
    large[kReviewSealMaxLineBytes - 1] = 'B';
    passed = !review_seal_matches(seal, long_lines, 2) && passed;
    large[kReviewSealMaxLineBytes - 1] = 'A';
    review_seal_mark_displayed(&seal);
    passed = review_seal_authorize(&seal, long_lines, 2, 20) && passed;
    large[kReviewSealMaxLineBytes] = 'A';
    large[kReviewSealMaxLineBytes + 1] = '\0';
    passed = !review_seal_build(&seal, kNonce, long_lines, 2, 0, 100) && passed;
    large[kReviewSealMaxLineBytes] = '\0';
    const char *many[kReviewSealMaxLines + 1];
    for (const char *&line : many) line = "";
    passed = review_seal_build(&seal, kNonce, many, kReviewSealMaxLines, 0, 100) && passed;
    passed = !review_seal_build(&seal, kNonce, many, kReviewSealMaxLines + 1, 0, 100) && passed;
    for (size_t i = 0; i < 9; ++i) many[i] = large;
    passed = review_seal_build(&seal, kNonce, many, 8, 0, 100) && passed;
    passed = !review_seal_build(&seal, kNonce, many, 9, 0, 100) && passed;
    passed = !review_seal_build(&seal, kNonce, lines_a, 3, 0, 0x80000000U) && passed;
    // A failed rebuild must revoke a previously displayed seal, even when
    // validation fails before hashing begins.
    passed = review_seal_build(&seal, kNonce, lines_a, 3, 0, 100) && passed;
    review_seal_mark_displayed(&seal);
    passed = !review_seal_build(&seal, nullptr, lines_a, 3, 0, 100) && passed;
    passed = !review_seal_authorize(&seal, lines_a, 3, 1) && passed;
    return passed;
  }

} // namespace hexwallet
