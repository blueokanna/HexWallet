#ifndef HEXWALLET_CONFIG_H
#define HEXWALLET_CONFIG_H

// Board policy belongs here. Do not place display pins or controller commands
// in wallet, BIP, or UI code.
#if __has_include(<lvgl.h>)
#define HEXWALLET_HAS_LVGL 1
#else
#define HEXWALLET_HAS_LVGL 0
#endif

#ifndef HEXWALLET_ENABLE_LVGL
#define HEXWALLET_ENABLE_LVGL HEXWALLET_HAS_LVGL
#endif

#ifndef HEXWALLET_RUN_SELF_TESTS
#define HEXWALLET_RUN_SELF_TESTS 0
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

// This is deliberately independent of panel resolution. The LVGL board port
// supplies the actual dimensions after initializing the panel driver.
static const UiPolicy kUiPolicy = {
  DisplayKind::MonoEink,
  900UL,
  false,
};

}  // namespace hexwallet

#endif
