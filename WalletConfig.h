#ifndef HEXWALLET_CONFIG_H
#define HEXWALLET_CONFIG_H

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

#ifndef HEXWALLET_BOARD
#if defined(CONFIG_IDF_TARGET_ESP32P4)
#define HEXWALLET_BOARD HEXWALLET_BOARD_HEADLESS
#else
#define HEXWALLET_BOARD HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED
#endif
#endif

#if defined(CONFIG_IDF_TARGET_ESP32P4) && HEXWALLET_BOARD != HEXWALLET_BOARD_NONE && HEXWALLET_BOARD != HEXWALLET_BOARD_HEADLESS
#error "No ESP32-P4 display board port is registered. Select HEADLESS until a verified P4 board port is available."
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

#ifndef HEXWALLET_RUN_SELF_TESTS
#define HEXWALLET_RUN_SELF_TESTS 1
#endif

// Stack for the second-core crypto worker (bytes). The boot self-tests run
// there so the display can come up in parallel; BLS/XMSS need real headroom.
#ifndef HEXWALLET_WORKER_STACK_BYTES
#define HEXWALLET_WORKER_STACK_BYTES (24 * 1024)
#endif

// Upper bound for a full boot self-test pass on the worker.
#ifndef HEXWALLET_SELFTEST_TIMEOUT_MS
#define HEXWALLET_SELFTEST_TIMEOUT_MS 120000UL
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

// USB data transport is OFF by default. The user must long-press the physical
// BOOT/user button to enable it for a bounded window; it turns off again on
// reset, timeout, or another long press. This gates the serial CLI and any
// future USB HID/CCID link, not the ROM bootloader used for flashing.
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
