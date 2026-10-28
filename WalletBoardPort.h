#ifndef HEXWALLET_BOARD_PORT_H
#define HEXWALLET_BOARD_PORT_H

#include <stddef.h>
#include <stdint.h>

#include "CameraPort.h"
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
// True when the panel can update a sub-rectangle without a full refresh.
// E-paper only: it is what makes the companion animation affordable.
bool board_partial_refresh_supported();
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

// Presence only: an I2C ACK or an open SDK transport, never device identity,
// authenticated channel or key-custody attestation. Does not touch an open
// SDK transport. Run diagnostics on the same serialized worker as SE sessions.
enum class SecureElementProbeState : uint8_t {
  NotConfigured = 0,
  NoResponse,
  PresentUnverified,
};

SecureElementProbeState board_secure_element_probe();

// Legacy diagnostic, unsupported. ATR must come from NXP's T=1 reset exchange.
// Clears outputs and returns false without consuming bytes on the SE bus.
bool board_secure_element_atr(uint8_t *out, size_t capacity, size_t *size);

// OV9281 presence probe over SCCB. Returns NotConfigured until a board profile
// defines the sensor's SCCB bus, which is the honest answer for the current PCB:
// its CSI pads run into series resistors and the camera FPC footprint carries no
// nets, so there is no sensor to address yet.
CameraProbeState board_camera_probe();

}  // namespace hexwallet

#endif
