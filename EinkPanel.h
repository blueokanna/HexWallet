#ifndef HEXWALLET_EINK_PANEL_H
#define HEXWALLET_EINK_PANEL_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Monochrome e-paper panel layer for the 2.9" 128x296 class (SSD1680 and the
// UC8151-compatible clones), plus the 4-color variant of the same size
// (SSD1683). Two things this file is deliberately explicit about:
//
//  1. These panels are SPI. A 128x296 e-paper module has no MIPI DSI interface;
//     MIPI DSI is what the colour panels in this project use. If a future board
//     wires the panel through a MIPI bridge, only EinkBus changes - the command
//     sequence does not.
//
//  2. Partial refresh needs a waveform LUT that is specific to the panel batch,
//     and every byte of it matters. The sequence is implemented here, the LUT is
//     a board-profile constant (EinkPanelConfig::partial_lut). With no LUT the
//     driver refuses partial updates instead of pretending and producing grey
//     smears; callers fall back to a full refresh. The 4-color panels have no
//     partial waveform at all, so EinkColorMode::FourColor rejects
//     partial_refresh() outright, whatever the config says.
//
// Framebuffer formats (both MSB-first, rows padded to a byte):
//   Mono       1 bit per pixel, bit 1 = black.
//   FourColor  2 bits per pixel, 4 pixels per byte. The nibble values are not
//              painted by this driver: EinkPanelConfig::palette maps the
//              framebuffer's palette index (0 black, 1 white, 2 red, 3 yellow,
//              the order EinkFrame produces) to the panel's code. SSD1683
//              4-color modules use {0b00, 0b01, 0b11, 0b10}; that is the
//              default, and a panel with a different table must override it
//              rather than being drawn with the wrong colours.

struct EinkRect {
  uint16_t x;
  uint16_t y;
  uint16_t width;
  uint16_t height;
};

constexpr uint16_t kEink29Width = 128;
constexpr uint16_t kEink29Height = 296;

enum class EinkColorMode : uint8_t {
  Mono = 0,
  FourColor = 1,
};

// Framebuffer palette indices, the order eink_convert_rgb565() writes.
constexpr uint8_t kEinkPaletteBlack = 0;
constexpr uint8_t kEinkPaletteWhite = 1;
constexpr uint8_t kEinkPaletteRed = 2;
constexpr uint8_t kEinkPaletteYellow = 3;

// Row stride in bytes for a frame of the given width and mode.
constexpr size_t eink_row_bytes(uint16_t width, EinkColorMode mode) {
  const size_t per_pixel_bits = mode == EinkColorMode::FourColor ? 2U : 1U;
  return (static_cast<size_t>(width) * per_pixel_bits + 7U) / 8U;
}

constexpr size_t eink_frame_bytes(uint16_t width, uint16_t height,
                                  EinkColorMode mode) {
  return eink_row_bytes(width, mode) * height;
}

// Monochrome callers keep the original one-argument form.
constexpr size_t eink_row_bytes(uint16_t width) {
  return eink_row_bytes(width, EinkColorMode::Mono);
}

constexpr size_t eink_frame_bytes(uint16_t width, uint16_t height) {
  return eink_frame_bytes(width, height, EinkColorMode::Mono);
}

// Transport supplied by the board port. `context` is opaque (an SPI instance,
// a test recorder, ...). `busy` returns true while BUSY is asserted.
struct EinkBus {
  void *context;
  bool (*command)(void *context, uint8_t command, const uint8_t *data,
                  size_t size);
  void (*reset)(void *context, bool asserted);
  bool (*busy)(void *context);
  void (*delay_ms)(void *context, uint32_t milliseconds);
};

struct EinkPanelConfig {
  uint16_t width;
  uint16_t height;
  EinkColorMode color;
  // Framebuffer palette index -> panel 2-bit code, used by FourColor only.
  // Defaults to the SSD1683 4-color table when left zero-initialised, see
  // EinkPanel::begin().
  uint8_t palette[4];
  // Waveform LUT for partial updates; nullptr disables partial refresh. A
  // 4-color panel must leave this null: it has no partial waveform.
  const uint8_t *partial_lut;
  size_t partial_lut_size;
  // BUSY timeout. A panel that never releases BUSY is a hardware fault and the
  // caller must not treat the frame as displayed.
  uint32_t full_timeout_ms;
  uint32_t partial_timeout_ms;
  // After this many partial updates the driver reports that a full refresh is
  // due. E-paper accumulates ghosting; the policy keeps it bounded.
  uint8_t partial_budget;
};

enum class EinkRefreshResult : uint8_t {
  Ok = 0,
  NotInitialised,
  BusFault,
  BusyTimeout,
  PartialUnsupported,
  InvalidWindow,
  BufferTooSmall,
};

struct EinkStats {
  uint32_t full_refreshes;
  uint32_t partial_refreshes;
  uint32_t busy_timeouts;
  uint8_t partials_since_full;
  bool initialised;
};

class EinkPanel {
 public:
  bool begin(const EinkBus &bus, const EinkPanelConfig &config);
  EinkRefreshResult full_refresh(const uint8_t *bitmap, size_t size);
  EinkRefreshResult partial_refresh(const uint8_t *bitmap, size_t size,
                                    const EinkRect &window);

  // Deep sleep; the panel keeps its content and draws microamps.
  EinkRefreshResult sleep();

  const EinkStats &stats() const { return stats_; }
  bool partial_supported() const {
    return config_.color == EinkColorMode::Mono && config_.partial_lut != nullptr;
  }
  EinkColorMode color_mode() const { return config_.color; }
  size_t frame_bytes() const {
    return eink_frame_bytes(config_.width, config_.height, config_.color);
  }
  bool full_refresh_due() const {
    return stats_.partials_since_full >= config_.partial_budget;
  }
  const EinkPanelConfig &config() const { return config_; }

 private:
  EinkRefreshResult wait_idle(uint32_t timeout_ms);
  bool push_window(const uint8_t *bitmap, size_t size, const EinkRect &window);
  // Packs one frame row slice into panel codes. Mono copies bytes through;
  // FourColor unpacks 2-bit palette indices and remaps them via palette_.
  bool push_window_color(const uint8_t *bitmap, size_t size,
                         const EinkRect &window);
  bool set_window(const EinkRect &window);
  bool begin_panel();

  EinkBus bus_ = {};
  EinkPanelConfig config_ = {};
  EinkStats stats_ = {};
};

// Damage accumulator: callers report which rectangles LVGL invalidated, the
// panel layer asks for the union. Keeps the "full vs partial" decision in one
// place instead of scattering heuristics through the flush callback.
class EinkDamage {
 public:
  void reset(uint16_t width, uint16_t height);
  void add(const EinkRect &rect);
  bool empty() const { return count_ == 0; }
  EinkRect bounds() const;
  bool prefers_full_refresh(uint32_t area_threshold_percent) const;

 private:
  EinkRect rects_[16];
  uint8_t count_;
  uint16_t width_;
  uint16_t height_;
};

bool run_eink_panel_self_tests();

}

#endif
