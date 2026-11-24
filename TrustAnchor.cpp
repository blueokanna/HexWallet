#include "TrustAnchor.h"

#include <mbedtls/md.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletConfig.h"
#include "WalletSecurity.h"

#if defined(ARDUINO)
// The P4 SDK exports runtime boot state and the active key digests. The other
// profiles report their compiled boot configuration separately.
#include <esp_err.h>
#include <esp_ota_ops.h> // brings esp_app_desc_t and esp_partition.h
#if defined(CONFIG_IDF_TARGET_ESP32P4)
#include <esp_chip_info.h>
#include <esp_efuse.h>
#include <esp_efuse_table.h>
#include <esp_flash_encrypt.h>
#if HEXWALLET_BOARD == HEXWALLET_BOARD_ESP32P4_EINK
#include <atomic>
#include <nvs_flash.h>
namespace {
std::atomic<bool> wallet_nvs_initialized{false};
}
extern "C" esp_err_t __real_nvs_flash_init();
extern "C" esp_err_t __wrap_nvs_flash_init() {
  const esp_err_t status = __real_nvs_flash_init();
  wallet_nvs_initialized.store(status == ESP_OK);
  if (status == ESP_ERR_NVS_NO_FREE_PAGES ||
      status == ESP_ERR_NVS_NEW_VERSION_FOUND)
    return ESP_ERR_INVALID_STATE;
  return status;
}
#endif
#if CONFIG_SECURE_BOOT_V2_ENABLED && CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME
#include <esp_secure_boot.h>
#endif
#endif

extern "C" bool esp_flash_encryption_enabled(void);

#if defined(CONFIG_SECURE_BOOT) || defined(CONFIG_SECURE_BOOT_V2_ENABLED)
#define HEXWALLET_SECURE_BOOT_COMPILED 1
#else
#define HEXWALLET_SECURE_BOOT_COMPILED 0
#endif
#endif

namespace hexwallet {

namespace {

bool rsa_covers_boot_keys(const void *const *active, size_t slot_count,
                          const uint8_t (*rsa)[32], size_t rsa_count) {
  if (rsa_count == 0 || rsa_count > slot_count)
    return false;
  bool found = false;
  for (size_t slot = 0; slot < slot_count; ++slot) {
    if (!active[slot])
      continue;
    found = true;
    bool matched = false;
    for (size_t i = 0; i < rsa_count; ++i)
      matched |= memcmp(active[slot], rsa[i], sizeof(rsa[i])) == 0;
    if (!matched)
      return false;
  }
  return found;
}

bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t size) {
  uint8_t difference = 0;
  for (size_t index = 0; index < size; ++index) {
    difference = static_cast<uint8_t>(difference | (a[index] ^ b[index]));
  }
  return difference == 0;
}

#if defined(ARDUINO)
bool flash_encryption_state(bool *known) {
  // The symbol is part of bootloader_support on every core this firmware
  // targets, so the answer is always known; only the header may be absent.
  *known = true;
  return esp_flash_encryption_enabled();
}

bool secure_boot_state(bool *from_config) {
  *from_config = true;
#if defined(CONFIG_IDF_TARGET_ESP32P4)
  uint8_t enabled = 0;
  if (esp_efuse_read_field_blob(ESP_EFUSE_SECURE_BOOT_EN, &enabled, 1) ==
      ESP_OK) {
    *from_config = false;
    return (enabled & 1U) != 0;
  }
#endif
  return HEXWALLET_SECURE_BOOT_COMPILED != 0;
}

void read_platform_state(TrustState *state) {
  state->reported = true;
  state->secure_boot_enabled =
      secure_boot_state(&state->secure_boot_from_config);
#if defined(CONFIG_IDF_TARGET_ESP32P4)
  if (state->secure_boot_enabled && !state->secure_boot_from_config) {
    esp_chip_info_t chip = {};
    esp_chip_info(&chip);
    // AR2026-006 affects P4 through v3.2. An eFuse digest by itself
    // does not identify the algorithm of the key it authorizes.
    state->secure_boot_key_policy_verified =
        chip.model == CHIP_ESP32P4 && chip.revision > 302;
#if CONFIG_SECURE_BOOT_V2_ENABLED && CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME
    if (chip.model == CHIP_ESP32P4 && chip.revision <= 302) {
      esp_image_sig_public_key_digests_t rsa = {};
      esp_secure_boot_key_digests_t active = {};
      if (esp_secure_boot_get_signature_blocks_for_running_app(true, &rsa) ==
              ESP_OK &&
          esp_secure_boot_read_key_digests(&active) == ESP_OK) {
        state->secure_boot_key_policy_verified = rsa_covers_boot_keys(
            active.key_digests, SOC_EFUSE_SECURE_BOOT_KEY_DIGESTS,
            rsa.key_digests, rsa.num_digests);
      }
    }
#endif
  }
#endif
  state->flash_encryption_enabled =
      flash_encryption_state(&state->flash_encryption_known);
  const esp_partition_t *running = esp_ota_get_running_partition();
  state->running_from_ota_slot =
      running != nullptr && running->type == ESP_PARTITION_TYPE_APP &&
      running->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_0 &&
      running->subtype < ESP_PARTITION_SUBTYPE_APP_OTA_MAX;
  const esp_app_desc_t *description = esp_app_get_description();
  if (description != nullptr) {
    memcpy(state->app_elf_sha256, description->app_elf_sha256,
           sizeof(state->app_elf_sha256));
    bool nonzero = false;
    for (uint8_t byte : state->app_elf_sha256) {
      if (byte != 0)
        nonzero = true;
    }
    state->app_elf_sha256_valid = nonzero;
  }
}
#endif

} // namespace

const char *trust_level_name(TrustLevel level) {
  switch (level) {
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

TrustState trust_state() {
  TrustState state = {};
#if defined(ARDUINO)
  read_platform_state(&state);
#endif
  return state;
}

TrustLevel trust_level(const TrustState &state) {
  if (!state.reported)
    return TrustLevel::Unknown;
  if (!state.flash_encryption_known)
    return TrustLevel::Unknown;
  if (state.secure_boot_enabled && !state.secure_boot_from_config &&
      state.secure_boot_key_policy_verified && state.flash_encryption_enabled) {
    return TrustLevel::Verified;
  }
  if (state.flash_encryption_enabled)
    return TrustLevel::Encrypted;
  return TrustLevel::Unprotected;
}

bool trust_signing_allowed(const TrustState &state) {
#if HEXWALLET_REQUIRE_VERIFIED_BOOT
  return trust_level(state) == TrustLevel::Verified &&
         board_credential_storage_ready();
#else
  (void)state;
  return true;
#endif
}

bool board_credential_storage_ready() {
#if HEXWALLET_BOARD == HEXWALLET_BOARD_ESP32P4_EINK
  // The wallet uses the SDK's default NVS partition. Flash encryption by
  // itself does not enable NVS encryption. A panic must not export RAM.
#if defined(ARDUINO) && CONFIG_IDF_TARGET_ESP32P4 && CONFIG_NVS_ENCRYPTION &&  \
    CONFIG_SECURE_BOOT && CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME &&              \
    CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE &&                             \
    !CONFIG_ESP_COREDUMP_ENABLE_TO_UART
  if (!wallet_nvs_initialized.load() ||
      trust_level(trust_state()) != TrustLevel::Verified ||
      esp_get_flash_encryption_mode() != ESP_FLASH_ENC_MODE_RELEASE)
    return false;
#if CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH
  if (esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                               ESP_PARTITION_SUBTYPE_DATA_COREDUMP, nullptr))
    return false;
#endif
  return true;
#else
  return false;
#endif
#else
  return true;
#endif
}

bool review_seal_build(ReviewSeal *seal, const uint8_t *nonce,
                       const char *const *lines, size_t line_count,
                       uint32_t now_ms, uint32_t window_ms) {
  if (seal == nullptr)
    return false;
  // Copy first: nonce may refer to seal->nonce when a review is rebuilt.
  uint8_t nonce_copy[kReviewSealNonceSize] = {};
  if (nonce != nullptr)
    memcpy(nonce_copy, nonce, sizeof(nonce_copy));
  memset(seal, 0, sizeof(*seal));
  seal->consumed = true; // Every failure revokes any previous authorization.
  if (nonce == nullptr || lines == nullptr || line_count == 0 ||
      line_count > kReviewSealMaxLines || window_ms > INT32_MAX)
    return false;

  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  struct Cleanup {
    mbedtls_md_context_t *context;
    ~Cleanup() { mbedtls_md_free(context); }
  } cleanup{&context};
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info == nullptr || mbedtls_md_setup(&context, info, 0) != 0 ||
      mbedtls_md_starts(&context) != 0 ||
      mbedtls_md_update(&context, nonce_copy, sizeof(nonce_copy)) != 0)
    return false;
  auto length_prefix = [&context](size_t length) {
    const uint8_t bytes[4] = {
        static_cast<uint8_t>(length >> 24), static_cast<uint8_t>(length >> 16),
        static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)};
    return mbedtls_md_update(&context, bytes, sizeof(bytes)) == 0;
  };
  if (!length_prefix(line_count))
    return false;
  size_t text_bytes = 0;
  for (size_t index = 0; index < line_count; ++index) {
    if (lines[index] == nullptr)
      return false;
    size_t length = 0;
    while (length <= kReviewSealMaxLineBytes && lines[index][length] != '\0')
      ++length;
    if (length > kReviewSealMaxLineBytes ||
        length > kReviewSealMaxTextBytes - text_bytes)
      return false;
    text_bytes += length;
    if (!length_prefix(length) ||
        mbedtls_md_update(&context,
                          reinterpret_cast<const uint8_t *>(lines[index]),
                          length) != 0)
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
                         size_t line_count) {
  if (!seal.built)
    return false;
  ReviewSeal rebuilt = {};
  if (!review_seal_build(&rebuilt, seal.nonce, lines, line_count, 0, 0)) {
    return false;
  }
  return constant_time_equal(rebuilt.digest, seal.digest, kReviewSealSize);
}

void review_seal_mark_displayed(ReviewSeal *seal) {
  if (seal == nullptr || !seal->built || seal->consumed)
    return;
  seal->displayed = true;
}

bool review_seal_authorize(ReviewSeal *seal, const char *const *lines,
                           size_t line_count, uint32_t now_ms) {
  if (seal == nullptr || !seal->built || !seal->displayed || seal->consumed)
    return false;
  if (static_cast<int32_t>(now_ms - seal->expires_ms) >= 0) {
    seal->consumed = true;
    return false;
  }
  if (!review_seal_matches(*seal, lines, line_count)) {
    seal->consumed = true;
    return false;
  }
  seal->consumed = true;
  return true;
}

bool review_seal_authorize_rendered(ReviewSeal *seal, uint32_t now_ms) {
  if (seal == nullptr || !seal->built || !seal->displayed || seal->consumed)
    return false;
  if (static_cast<int32_t>(now_ms - seal->expires_ms) >= 0) {
    seal->consumed = true;
    return false;
  }
  seal->consumed = true;
  return true;
}

void review_seal_code(const ReviewSeal &seal, char out[9]) {
  static const char kHex[] = "0123456789ABCDEF";
  for (size_t index = 0; index < 4; ++index) {
    out[index * 2] = kHex[seal.digest[index] >> 4];
    out[index * 2 + 1] = kHex[seal.digest[index] & 0x0F];
  }
  out[8] = '\0';
}

bool run_trust_anchor_self_tests() {
  bool passed = true;
  const uint8_t rsa[2][32] = {{1}, {2}};
  const uint8_t unknown[32] = {3};
  const void *active[3] = {};
  passed = !rsa_covers_boot_keys(active, 3, rsa, 2) && passed;
  active[0] = rsa[1];
  active[2] = rsa[0];
  passed = rsa_covers_boot_keys(active, 3, rsa, 2) && passed;
  active[1] = unknown;
  passed = !rsa_covers_boot_keys(active, 3, rsa, 2) && passed;

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
  passed = trust_level(state) == TrustLevel::Encrypted && passed;
  state.secure_boot_key_policy_verified = true;
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
  static const uint8_t kOtherNonce[kReviewSealNonceSize] = {1, 2, 3, 4,
                                                            5, 6, 7, 9};
  passed =
      review_seal_build(&other, kOtherNonce, lines_a, 3, 1000, 500) && passed;
  passed = !constant_time_equal(seal.digest, other.digest, kReviewSealSize) &&
           passed;

  // Authorization requires an armed seal.
  const char *const *same = lines_a;
  passed = !review_seal_authorize(&seal, same, 3, 1000) && passed;
  review_seal_mark_displayed(&seal);
  passed = review_seal_authorize(&seal, same, 3, 1499) && passed;
  // Single use: the second attempt fails.
  passed = !review_seal_authorize(&seal, same, 3, 1499) && passed;

  // Expiry is a hard stop, and an expired seal is burned rather than left
  // armed.
  ReviewSeal expired = {};
  passed = review_seal_build(&expired, kNonce, lines_a, 3, 1000, 100) && passed;
  review_seal_mark_displayed(&expired);
  passed = !review_seal_authorize(&expired, same, 3, 1100) && passed;
  passed = !review_seal_authorize(&expired, same, 3, 1050) &&
           passed; // already burned

  // Text swapped after display burns the seal and never authorizes.
  ReviewSeal swapped = {};
  passed = review_seal_build(&swapped, kNonce, lines_a, 3, 1000, 500) && passed;
  review_seal_mark_displayed(&swapped);
  passed = !review_seal_authorize(&swapped, lines_b, 3, 1200) && passed;
  passed = !review_seal_authorize(&swapped, same, 3, 1200) && passed;

  // The rendered-text variant enforces the same clock and single-use rules.
  ReviewSeal rendered = {};
  passed =
      review_seal_build(&rendered, kNonce, lines_a, 3, 1000, 200) && passed;
  passed =
      !review_seal_authorize_rendered(&rendered, 1100) && passed; // not armed
  review_seal_mark_displayed(&rendered);
  passed = review_seal_authorize_rendered(&rendered, 1100) && passed;
  passed =
      !review_seal_authorize_rendered(&rendered, 1100) && passed; // used once
  ReviewSeal stale = {};
  passed = review_seal_build(&stale, kNonce, lines_a, 3, 1000, 100) && passed;
  review_seal_mark_displayed(&stale);
  passed = !review_seal_authorize_rendered(&stale, 1200) && passed;
  passed = !review_seal_authorize_rendered(&stale, 1050) && passed; // burned

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
  passed =
      review_seal_build(&seal, kNonce, long_lines, 2, UINT32_MAX - 49, 100) &&
      passed;
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
  for (const char *&line : many)
    line = "";
  passed =
      review_seal_build(&seal, kNonce, many, kReviewSealMaxLines, 0, 100) &&
      passed;
  passed = !review_seal_build(&seal, kNonce, many, kReviewSealMaxLines + 1, 0,
                              100) &&
           passed;
  for (size_t i = 0; i < 9; ++i)
    many[i] = large;
  passed = review_seal_build(&seal, kNonce, many, 8, 0, 100) && passed;
  passed = !review_seal_build(&seal, kNonce, many, 9, 0, 100) && passed;
  passed =
      !review_seal_build(&seal, kNonce, lines_a, 3, 0, 0x80000000U) && passed;
  passed = review_seal_build(&seal, kNonce, lines_a, 3, 0, 100) && passed;
  review_seal_mark_displayed(&seal);
  passed = !review_seal_build(&seal, nullptr, lines_a, 3, 0, 100) && passed;
  passed = !review_seal_authorize(&seal, lines_a, 3, 1) && passed;
  return passed;
}

}
