# ESP32 and LVGL Porting

This project targets ESP32 with LVGL 9. Install the following through Arduino
IDE before compiling:

- Espressif ESP32 board package, version 3.x or later.
- LVGL 9.x.
- A display driver library for the exact panel. `TFT_eSPI` is suitable for a
  configured color TFT. E-ink panels require their vendor driver or a reviewed
  GxEPD2 integration.

`WalletBoardPort.cpp` intentionally fails closed. Replace its four functions
for one board only. The board port owns GPIO assignments, bus initialization,
power/reset sequencing, LVGL draw buffers, panel flush, touch/buttons, and
`lv_tick_inc`. Never put those details in `WalletSecurity.*` or `WalletUi.*`.

## LVGL 9 color-panel skeleton

The following belongs in a board-specific replacement for
`WalletBoardPort.cpp`. Configure the controller and pins in TFT_eSPI before
using it. The 1/10-height draw buffer scales with panel width and works across
common 2.4, 2.8, and 2.9 inch color panels.

```cpp
#include <Arduino.h>
#include <esp_heap_caps.h>
#include <TFT_eSPI.h>
#include <lvgl.h>
#include "WalletBoardPort.h"

namespace {
TFT_eSPI panel;
lv_display_t *display = nullptr;
uint16_t *draw_buffer = nullptr;
uint32_t last_tick = 0;

void flush(lv_display_t *display, const lv_area_t *area, uint8_t *pixels) {
  const uint32_t width = area->x2 - area->x1 + 1;
  const uint32_t height = area->y2 - area->y1 + 1;
  panel.startWrite();
  panel.setAddrWindow(area->x1, area->y1, width, height);
  panel.pushColors(reinterpret_cast<uint16_t *>(pixels), width * height, true);
  panel.endWrite();
  lv_display_flush_ready(display);
}
}

namespace hexwallet {
bool board_display_init() {
  lv_init();
  panel.begin();
  panel.setRotation(1);
  const uint32_t pixels = panel.width() * 24;
  draw_buffer = static_cast<uint16_t *>(heap_caps_malloc(pixels * sizeof(uint16_t), MALLOC_CAP_DMA));
  if (draw_buffer == nullptr) return false;
  display = lv_display_create(panel.width(), panel.height());
  lv_display_set_color_format(display, LV_COLOR_FORMAT_RGB565);
  lv_display_set_buffers(display, draw_buffer, nullptr, pixels * sizeof(uint16_t), LV_DISPLAY_RENDER_MODE_PARTIAL);
  lv_display_set_flush_cb(display, flush);
  last_tick = millis();
  return true;
}
void board_display_service() {
  const uint32_t now = millis();
  lv_tick_inc(now - last_tick);
  last_tick = now;
}
uint16_t board_display_width() { return panel.width(); }
uint16_t board_display_height() { return panel.height(); }
}
```

## E-ink requirements

An e-ink port must make panel refresh explicit. Use partial refresh only for
small, non-sensitive status changes; after a PIN, mnemonic, address, or
transaction review screen, perform a full refresh and wait for the controller
to become idle. The port must not refresh faster than
`kUiPolicy.eink_min_refresh_ms`, must avoid LVGL animations, and must clear the
panel on lock. If a panel library only exposes blocking full refresh, use a
smaller monochrome LVGL draw buffer and call the library from the LVGL flush
callback after validating the dirty rectangle.

## Security release gate

Do not put assets on a device until all of these are complete:

- Replace the default board port and test power-loss behavior.
- Add official BIP39, BIP32, BIP13, and BIP173 test vectors to a host CI build.
- Use a secure element or encrypted NVS with a hardware-bound key; do not keep
  a mnemonic or seed in SPIFFS, PSRAM, UART logs, or crash dumps.
- Implement a PIN retry policy, secure wipe, verified firmware update, and a
  physical confirmation flow that shows every transaction field on the trusted
  display.
- Independently audit transaction parsing and signing for each supported chain.

The repository currently has no transaction parser, no secure-element driver,
no PIN storage, and no signed firmware-update implementation. It must not be
used to hold funds before those components and independent review exist.
