#ifndef HEXWALLET_TRUST_ANCHOR_H
#define HEXWALLET_TRUST_ANCHOR_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{

  // Trusted verification has two halves and this file owns both:
  //
  //  1. Device trust - what the hardware can prove about the firmware it is
  //     running: secure boot enabled, flash encryption enabled, anti-rollback
  //     counter, and the running app's ELF digest. On the ESP32-P4 these come from
  //     eFuses and the app descriptor, not from anything the firmware writes
  //     about itself.
  //
  //  2. Review seal - a single-use authorization ticket for exactly the text the
  //     panel was asked to show. It is built when a review is rendered, armed when
  //     the panel reports the frame committed, and consumed by the signing call.
  //     Nothing can be signed without a seal that was displayed, still fresh, and
  //     never used before.
  //
  // Neither half is a substitute for the other: a device can be perfectly sealed
  // and still show a different transaction, and a review seal means nothing on a
  // device whose firmware an attacker replaced.

  enum class TrustLevel : uint8_t
  {
    Unknown = 0, // platform did not answer (host build, unknown silicon)
    Unprotected, // neither secure boot nor flash encryption
    Encrypted,   // flash encryption only: data at rest, not code authenticity
    Verified,    // secure boot + flash encryption
  };

  const char *trust_level_name(TrustLevel level);

  struct TrustState
  {
    bool reported;
    bool secure_boot_enabled;
    bool flash_encryption_enabled;
    // False when the platform exposes neither the flash-encryption API nor the
    // eFuse counter. "Cannot tell" is kept separate from "off": a wrong "off"
    // would be as misleading as a wrong "on".
    bool flash_encryption_known;
    // True when secure_boot_enabled came from CONFIG_SECURE_BOOT (compiled-in
    // bootloader policy) rather than a runtime eFuse read.
    bool secure_boot_from_config;
    bool running_from_ota_slot;
    bool app_elf_sha256_valid;
    uint8_t app_elf_sha256[32];
  };

  TrustState trust_state();
  TrustLevel trust_level(const TrustState &state);

  bool trust_signing_allowed(const TrustState &state);

  constexpr size_t kReviewSealSize = 32;
  constexpr size_t kReviewSealNonceSize = 8;

  struct ReviewSeal
  {
    uint8_t nonce[kReviewSealNonceSize];
    uint8_t digest[kReviewSealSize];
    uint32_t expires_ms;
    bool displayed;
    bool consumed;
  };

  bool review_seal_build(ReviewSeal *seal, const uint8_t *nonce,
                         const char *const *lines, size_t line_count,
                         uint32_t now_ms, uint32_t window_ms);

  // Recomputes the digest and compares in constant time.
  bool review_seal_matches(const ReviewSeal &seal, const char *const *lines,
                           size_t line_count);

  // Arms the seal. Only a committed panel frame may call this.
  void review_seal_mark_displayed(ReviewSeal *seal);

  // Consumes the seal if it was armed, still fresh, and still matches the text.
  // Single use: a second call fails, so one displayed review authorizes one
  // signature.
  bool review_seal_authorize(ReviewSeal *seal, const char *const *lines,
                           size_t line_count, uint32_t now_ms);

// Same authorization rules, for callers whose rendered text is immutable and
// owned by them (the LVGL labels). Skips the re-hash: the digest was taken from
// exactly those labels when the screen was built, and the screen cannot mutate
// them afterwards. Displayed / fresh / unused are still enforced.
bool review_seal_authorize_rendered(ReviewSeal *seal, uint32_t now_ms);

  // Eight uppercase hex characters shown under the review and comparable on the
  // host side.
  void review_seal_code(const ReviewSeal &seal, char out[9]);

  bool run_trust_anchor_self_tests();

}

#endif
