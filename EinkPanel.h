#ifndef HEXWALLET_EINK_PANEL_H
#define HEXWALLET_EINK_PANEL_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// SPI panel protocols: SSD1680 monochrome and the SSD1683-class 2.9 inch
// four-color panel (128x296, black/white/red/yellow). Controller selection is
// explicit. UC8151, JD79667, grayscale SSD1680 modes and other four-color
// panels are not interchangeable.
//
// Mono uses 1 bit/pixel, 1=black; the driver inverts for SSD1680 RAM.
// FourColor uses 2 bits/pixel in palette order black/white/red/yellow, wire
// codes 00/01/11/10. Both formats are MSB-first.
// Partial refresh needs no host waveform: the SSD1680 runs the mode-2 table it
// keeps in OTP. FourColor has no partial waveform at all. Controller
// capabilities do not identify a panel or prove its OTP contents. A failed
// transfer invalidates the panel state.

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

enum class EinkController : uint8_t { Ssd1680, Ssd1683 };

// Board-owned register settings verified against the fitted panel's hardware
// documentation. No unknown analogue/boost settings are supplied by default.
struct EinkInitCommand {
  uint8_t command;
  uint8_t size;
  uint8_t bytes[8];
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
  // Continue the current RAM command without issuing a new command byte.
  bool (*data)(void *context, const uint8_t *data, size_t size);
};

struct EinkPanelConfig {
  uint16_t width;
  uint16_t height;
  EinkColorMode color;
  // Framebuffer palette index -> panel 2-bit code, used by FourColor only.
  // A zero-initialised config gets the 00/01/11/10 table; see
  // EinkPanel::begin().
  uint8_t palette[4];
  // Optional SSD1680 complete waveform setting: 159 bytes, that is the 153 LUT
  // bytes of section 6.7 followed by EOPT, VGH, VSH1, VSH2, VSL and VCOM.
  // A bare LUT omits required voltage/end settings and is rejected. Leave it
  // null to run the panel's own OTP table. Never set it on FourColor.
  const uint8_t *partial_lut;
  size_t partial_lut_size;
  // BUSY timeout. A panel that never releases BUSY is a hardware fault and the
  // caller must not treat the frame as displayed.
  uint32_t full_timeout_ms;
  uint32_t partial_timeout_ms;
  // After this many partial updates the driver reports that a full refresh is
  // due. E-paper accumulates ghosting; the policy keeps it bounded.
  uint8_t partial_budget;
  EinkController controller = EinkController::Ssd1680;
  const EinkInitCommand *color_init = nullptr;
  size_t color_init_count = 0;
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
    return stats_.initialised && config_.color == EinkColorMode::Mono;
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
  bool command(uint8_t command, const uint8_t *data, size_t size);
  bool data(const uint8_t *bytes, size_t size);
  bool push_window(const uint8_t *bitmap, size_t size, const EinkRect &window,
                   uint8_t ram_command = 0x24);
  // Packs one frame row slice into panel codes. Mono converts 1=black to 0=black;
  // FourColor unpacks 2-bit palette indices and remaps them via palette_.
  bool push_window_color(const uint8_t *bitmap, size_t size,
                         const EinkRect &window);
  bool set_window(const EinkRect &window);
  bool begin_panel();
  bool begin_four_color();

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
