#ifndef HEXWALLET_CONFIG_H
#define HEXWALLET_CONFIG_H

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

namespace hexwallet {

enum class DisplayKind : unsigned char {
  Color,
  MonoEink,
};

struct UiPolicy {
  DisplayKind display_kind;
  unsigned long eink_min_refresh_ms;
  bool allow_animations;
};

static const UiPolicy kUiPolicy = {
  DisplayKind::MonoEink,
  900UL,
  false,
};

}  // namespace hexwallet

#endif
