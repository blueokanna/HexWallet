#ifndef HEXWALLET_BOARD_PORT_H
#define HEXWALLET_BOARD_PORT_H

#include <stdint.h>

#include "WalletConfig.h"

namespace hexwallet {

// ---------------------------------------------------------------------------
// Board port API.
//
// The port owns everything hardware-specific: panel driver, LVGL draw
// buffers, flush callback, input device and power sequencing. WalletUi and
// the CLI only ever talk to this interface plus the compile-time policy in
// WalletConfig.h, so a new board is a new profile in WalletBoardPins.h plus a
// driver branch in WalletBoardPort.cpp - nothing in the wallet core changes.
// ---------------------------------------------------------------------------

// Identity / capability queries (all compile-time or read-once).
const char *board_name();
DisplayKind board_display_kind();
bool board_has_display();
bool board_has_touch();
bool board_is_color();
bool board_is_eink();

// Display lifecycle. board_display_init() calls lv_init() and registers the
// display (and input device, when touch is present) before returning true.
// Returns false on any initialization failure and leaves the system in a
// fail-closed state (no UI surfaces).
bool board_display_init();
void board_display_service();

uint16_t board_display_width();
uint16_t board_display_height();

// Power / environment.
// board_power(on) gates the panel rail / backlight. On battery-only boards it
// is advisory; the panel driver must still work with power applied.
void board_power(bool on);
// Raw battery voltage in millivolts; 0 when the board has no battery ADC or
// the reading is not available yet.
uint16_t board_battery_millivolts();

// Physical user button (BOOT on the ESP32 boards). Active-low, debounced by
// the caller. Returns false when the board has no verified user button.
bool board_has_user_button();
bool board_user_button_pressed();

// SE050 presence probe. "PresentUnverified" means an I2C device answered at
// 0x48; it does not prove the part is an SE050C1H1, that SCP03 was
// established, or that a key was imported. The wallet therefore keeps the
// MCU-only custody profile until a real applet driver verifies the device.
enum class SecureElementProbeState : uint8_t {
  NotConfigured = 0,
  NoResponse,
  PresentUnverified,
};

SecureElementProbeState board_secure_element_probe();

}  // namespace hexwallet

#endif
