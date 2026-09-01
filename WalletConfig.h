#ifndef HEXWALLET_CONFIG_H
#define HEXWALLET_CONFIG_H

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
// Default target: the reference board the port was developed and validated on.
#define HEXWALLET_BOARD HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED
#endif

// ---------------------------------------------------------------------------
// Headless (no display) target - e.g. any generic ESP32-S3 dev board, or a
// USB-stick wallet. Pure authenticated Serial CLI; no LVGL, no panel driver,
// no touch. Transaction approval falls back to the host (serial) with a
// printed confirm code (see HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION below).
// ---------------------------------------------------------------------------
#if HEXWALLET_BOARD == HEXWALLET_BOARD_HEADLESS
#ifndef HEXWALLET_ENABLE_LVGL
#define HEXWALLET_ENABLE_LVGL 0
#endif
#ifndef HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION
#define HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION 1
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

#ifndef HEXWALLET_ENABLE_SECRET_EXPORT
#define HEXWALLET_ENABLE_SECRET_EXPORT 0
#endif

#ifndef HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION
#define HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION 0
#endif

namespace hexwallet {

enum class DisplayKind : unsigned char {
  Color,
  MonoEink,
};

struct UiPolicy {
  DisplayKind display_kind;
  unsigned long eink_min_refresh_ms;
  bool allow_animations;
  uint16_t logical_width;
  uint16_t logical_height;
};

inline const UiPolicy &ui_policy() {
  static const UiPolicy kPolicy = []() {
#if HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED || HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED_PLUS
    return UiPolicy{ DisplayKind::Color, 0UL, true, 240, 536 };
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3
    return UiPolicy{ DisplayKind::Color, 0UL, true, 170, 320 };
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_DECK_MAX
    return UiPolicy{ DisplayKind::MonoEink, 900UL, false, 800, 480 };
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_ECHO_LITE
    return UiPolicy{ DisplayKind::MonoEink, 900UL, false, 176, 192 };
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_HEADLESS
    // No UI surface on the headless target; values are unused.
    return UiPolicy{ DisplayKind::Color, 0UL, false, 0, 0 };
#else
    return UiPolicy{ DisplayKind::Color, 0UL, true, 240, 536 };
#endif
  }();
  return kPolicy;
}

}

#endif
