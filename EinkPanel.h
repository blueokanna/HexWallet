#ifndef HEXWALLET_EINK_PANEL_H
#define HEXWALLET_EINK_PANEL_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Monochrome e-paper panel layer for the 2.9" 128x296 class (SSD1680 and the
// UC8151-compatible clones). Two things this file is deliberately explicit
// about:
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
//     smears; callers fall back to a full refresh.
//
// Framebuffer format: 1 bit per pixel, MSB first, each row padded to a byte,
// bit 1 = black. That is the format the panel RAM takes after the inversion the
// controller applies, so no per-pixel branch is needed on the hot path.

struct EinkRect {
  uint16_t x;
  uint16_t y;
  uint16_t width;
  uint16_t height;
};

constexpr uint16_t kEink29Width = 128;
constexpr uint16_t kEink29Height = 296;

// Row stride in bytes for a 1bpp frame of the given width.
constexpr size_t eink_row_bytes(uint16_t width) {
  return static_cast<size_t>((width + 7) / 8);
}

constexpr size_t eink_frame_bytes(uint16_t width, uint16_t height) {
  return eink_row_bytes(width) * height;
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
  // Waveform LUT for partial updates; nullptr disables partial refresh.
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
  bool partial_supported() const { return config_.partial_lut != nullptr; }
  bool full_refresh_due() const {
    return stats_.partials_since_full >= config_.partial_budget;
  }
  const EinkPanelConfig &config() const { return config_; }

 private:
  EinkRefreshResult wait_idle(uint32_t timeout_ms);
  bool push_window(const uint8_t *bitmap, size_t size, const EinkRect &window);
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
