#ifndef HEXWALLET_CONFIG_H
#define HEXWALLET_CONFIG_H

// Local spending safety policy (0.1 XMR), not Monero consensus or a live fee
// estimate. Only firmware configuration can change this; host requests cannot.
#ifndef HEXWALLET_XMR_MAX_FEE_ATOMIC
#define HEXWALLET_XMR_MAX_FEE_ATOMIC 100000000000ULL
#endif

// Masari has the same 12-decimal coin unit; 0.1 MSR is the local ceiling.
#ifndef HEXWALLET_MSR_MAX_FEE_ATOMIC
#define HEXWALLET_MSR_MAX_FEE_ATOMIC 100000000000ULL
#endif

// Masari's RCTTypeBulletproof (type 3) verifier is implemented but has not
// yet been validated against a mainnet transaction vector. It stays disabled
// by default so a malformed proof can never be treated as accepted.
#ifndef HEXWALLET_MSR_ENABLE_RCT_TYPE3
#define HEXWALLET_MSR_ENABLE_RCT_TYPE3 0
#endif

#if defined(ARDUINO_ARCH_ESP32)
#include <sdkconfig.h>
#endif

// ---------------------------------------------------------------------------
// Board selection. Compile-time hardware target; every board profile lives in
// WalletBoardPins.h and the drivers in WalletBoardPort.cpp.
// ---------------------------------------------------------------------------
#define HEXWALLET_BOARD_NONE 0
#define HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED 1
#define HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED_PLUS 2
#define HEXWALLET_BOARD_T_DISPLAY_S3 3
#define HEXWALLET_BOARD_T_DECK_MAX 4
#define HEXWALLET_BOARD_T_ECHO_LITE 5
#define HEXWALLET_BOARD_HEADLESS 6
#define HEXWALLET_BOARD_ESP32P4_EINK 7

#ifndef HEXWALLET_BOARD
#if defined(CONFIG_IDF_TARGET_ESP32P4)
#define HEXWALLET_BOARD HEXWALLET_BOARD_HEADLESS
#else
#define HEXWALLET_BOARD HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED
#endif
#endif

#if defined(CONFIG_IDF_TARGET_ESP32P4) && HEXWALLET_BOARD != HEXWALLET_BOARD_NONE && \
    HEXWALLET_BOARD != HEXWALLET_BOARD_HEADLESS && HEXWALLET_BOARD != HEXWALLET_BOARD_ESP32P4_EINK
#error "No ESP32-P4 board port is registered for this board id."
#endif

// ---------------------------------------------------------------------------
// Headless (no display) target - e.g. any generic ESP32-S3 dev board, or a
// USB-stick wallet. Pure authenticated Serial CLI; no LVGL, no panel driver,
// no touch. Signing remains disabled without a trusted local display unless
// host-only confirmation is explicitly enabled for development.
// ---------------------------------------------------------------------------
#if HEXWALLET_BOARD == HEXWALLET_BOARD_HEADLESS
#ifndef HEXWALLET_ENABLE_LVGL
#define HEXWALLET_ENABLE_LVGL 0
#endif
#endif

#ifndef HEXWALLET_ENABLE_LVGL
#define HEXWALLET_ENABLE_LVGL 1
#endif

#if HEXWALLET_ENABLE_LVGL
#if !__has_include(<lvgl.h>)
#error "LVGL is enabled. Install LVGL 9.5.0 or build with HEXWALLET_ENABLE_LVGL=0."
#endif
#define HEXWALLET_HAS_LVGL 1
#else
#define HEXWALLET_HAS_LVGL 0
#endif

// The full vector suite (crypto, chains, link, signing) carries its fixtures as
// static arrays: 461 KiB of .bss in the ESP32-S3 image, on a 320 KiB DRAM
// segment. Those vectors belong in CI, which runs them on every commit; the
// device keeps the runtime checks (RNG health, custody gate, seal logic). Enable
// on a bench unit with -DHEXWALLET_DEVICE_SELF_TESTS=1.
#ifndef HEXWALLET_DEVICE_SELF_TESTS
#if defined(ARDUINO)
#define HEXWALLET_DEVICE_SELF_TESTS 0
#else
#define HEXWALLET_DEVICE_SELF_TESTS 1
#endif
#endif

#ifndef HEXWALLET_RUN_SELF_TESTS
#define HEXWALLET_RUN_SELF_TESTS 1
#endif

#ifndef HEXWALLET_WORKER_STACK_BYTES
#define HEXWALLET_WORKER_STACK_BYTES (24 * 1024)
#endif

#ifndef HEXWALLET_SOL_MAX_FEE_LAMPORTS
#define HEXWALLET_SOL_MAX_FEE_LAMPORTS 10000000ULL
#endif

#ifndef HEXWALLET_WORKER_JOB_TIMEOUT_MS
#define HEXWALLET_WORKER_JOB_TIMEOUT_MS 120000UL
#endif

#ifndef HEXWALLET_SELFTEST_TIMEOUT_MS
#define HEXWALLET_SELFTEST_TIMEOUT_MS 300000UL
#endif

#ifndef HEXWALLET_ENABLE_CLI
#define HEXWALLET_ENABLE_CLI 1
#endif

#ifndef HEXWALLET_CLI_SESSION_TIMEOUT_MS
#define HEXWALLET_CLI_SESSION_TIMEOUT_MS (5UL * 60UL * 1000UL)
#endif

#ifndef HEXWALLET_CLI_PBKDF2_ITERATIONS
#define HEXWALLET_CLI_PBKDF2_ITERATIONS 120000UL
#endif

#ifndef HEXWALLET_MAX_PSBT_BYTES
#define HEXWALLET_MAX_PSBT_BYTES 4096U
#endif

#ifndef HEXWALLET_MAX_BITCOIN_FEE_SATS
#define HEXWALLET_MAX_BITCOIN_FEE_SATS 1000000ULL
#endif

#ifndef HEXWALLET_MAX_BITCOIN_FEE_RATE
#define HEXWALLET_MAX_BITCOIN_FEE_RATE 500ULL
#endif

#ifndef HEXWALLET_MAX_EVM_FEE_WEI
#define HEXWALLET_MAX_EVM_FEE_WEI 1000000000000000000ULL
#endif

#ifndef HEXWALLET_MAX_ZCASH_FEE_ZATS
#define HEXWALLET_MAX_ZCASH_FEE_ZATS 1000000ULL
#endif

#ifndef HEXWALLET_MAX_ZCASH_FEE_RATE
#define HEXWALLET_MAX_ZCASH_FEE_RATE 10000ULL
#endif

// Dash: 0.01 DASH absolute ceiling and 500 duffs/vbyte. Dash relay fees are
// 1 duff/byte, so the rate cap only stops a host from presenting an absurd
// fee as an ordinary one; it is not a recommendation.
#ifndef HEXWALLET_MAX_DASH_FEE_DUFFS
#define HEXWALLET_MAX_DASH_FEE_DUFFS 1000000ULL
#endif

#ifndef HEXWALLET_MAX_DASH_FEE_RATE
#define HEXWALLET_MAX_DASH_FEE_RATE 500ULL
#endif

#ifndef HEXWALLET_USB_DATA_DEFAULT
#define HEXWALLET_USB_DATA_DEFAULT 0
#endif

#ifndef HEXWALLET_USB_ENABLE_HOLD_MS
#define HEXWALLET_USB_ENABLE_HOLD_MS 3000UL
#endif

#ifndef HEXWALLET_USB_ENABLE_WINDOW_MS
#define HEXWALLET_USB_ENABLE_WINDOW_MS (10UL * 60UL * 1000UL)
#endif

#ifndef HEXWALLET_ENABLE_SECRET_EXPORT
#define HEXWALLET_ENABLE_SECRET_EXPORT 0
#endif

#ifndef HEXWALLET_REQUIRE_SECURE_CUSTODY
#if defined(HEXWALLET_HOST_TEST)
#define HEXWALLET_REQUIRE_SECURE_CUSTODY 0
#else
#define HEXWALLET_REQUIRE_SECURE_CUSTODY 1
#endif
#endif

#if HEXWALLET_ENABLE_SECRET_EXPORT
#error "Secret export is not supported by this wallet."
#endif
#if !defined(HEXWALLET_HOST_TEST) && !HEXWALLET_REQUIRE_SECURE_CUSTODY
#error "Device builds require secure custody; software sessions are host-test only."
#endif
#if defined(HEXWALLET_HOST_TEST) && defined(ARDUINO)
#error "Host-test security exemptions must never be compiled into device firmware."
#endif

#ifndef HEXWALLET_REQUIRE_VERIFIED_BOOT
#define HEXWALLET_REQUIRE_VERIFIED_BOOT 0
#endif
#ifndef HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION
#define HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION 0
#endif

namespace hexwallet
{

      enum class DisplayKind : unsigned char
      {
            Color,
            MonoEink,
      };

      struct UiPolicy
      {
            DisplayKind display_kind;
            unsigned long eink_min_refresh_ms;
            bool allow_animations;
            uint16_t logical_width;
            uint16_t logical_height;
      };

      inline const UiPolicy &ui_policy()
      {
            static const UiPolicy kPolicy = []()
            {
#if HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED || HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED_PLUS
                  return UiPolicy{DisplayKind::Color, 0UL, true, 240, 536};
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3
                  return UiPolicy{DisplayKind::Color, 0UL, true, 170, 320};
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_DECK_MAX
                  return UiPolicy{DisplayKind::MonoEink, 900UL, false, 800, 480};
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_ECHO_LITE
                  return UiPolicy{DisplayKind::MonoEink, 900UL, false, 176, 192};
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_HEADLESS
                  // No UI surface on the headless target; values are unused.
                  return UiPolicy{DisplayKind::Color, 0UL, false, 0, 0};
#else
                  return UiPolicy{DisplayKind::Color, 0UL, true, 240, 536};
#endif
            }();
            return kPolicy;
      }

}

#endif
