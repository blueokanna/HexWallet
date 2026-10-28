#ifndef HEXWALLET_BOARD_PORT_H
#define HEXWALLET_BOARD_PORT_H

#include <stddef.h>
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
// 1 for monochrome e-paper, 3 for black/white/red, 4 for black/white/red/
// yellow. The panel driver class must match this value; the fallback is 1.
uint8_t board_display_colors();

// Display lifecycle. board_display_init() calls lv_init() and registers the
// display (and input device, when touch is present) before returning true.
// Returns false on any initialization failure and leaves the system in a
// fail-closed state (no UI surfaces).
bool board_display_init();
void board_display_service();
// A new approval screen must finish rendering and panel transfer before it can
// accept APPROVE. This is a software barrier, not optical verification.
void board_display_prepare_review();
bool board_display_review_ready();

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

// SE05x presence probe. "PresentUnverified" now requires a well-formed ATR, not
// just an I2C ACK: an ACK proves something sits at the address, an ATR with a
// valid TA/TB/TC/TD chain and TCK proves it is a smart card. Neither is proof
// that the part is the requested SE051C2HQ1, that SCP03 was established, or
// that a key was imported, so the wallet keeps the MCU-only custody profile
// until a real applet driver verifies the device.
enum class SecureElementProbeState : uint8_t {
  NotConfigured = 0,
  NoResponse,
  PresentUnverified,
};

SecureElementProbeState board_secure_element_probe();

// Reads the answer-to-reset for diagnostics. Returns false when the bus is not
// configured or the card did not answer with a structurally valid ATR.
bool board_secure_element_atr(uint8_t *out, size_t capacity, size_t *size);

}  // namespace hexwallet

#endif
