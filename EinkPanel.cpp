#include "EinkPanel.h"

#include <string.h>

namespace hexwallet
{
  namespace
  {

    // SSD1680 command set, limited to what a wallet screen needs.
    constexpr uint8_t kCmdDriverOutput = 0x01;
    constexpr uint8_t kCmdDeepSleep = 0x10;
    constexpr uint8_t kCmdDataEntry = 0x11;
    constexpr uint8_t kCmdSwReset = 0x12;
    constexpr uint8_t kCmdMasterActivation = 0x20;
    constexpr uint8_t kCmdUpdateControl2 = 0x22;
    constexpr uint8_t kCmdWriteRam = 0x24;
    constexpr uint8_t kCmdWriteLut = 0x32;
    constexpr uint8_t kCmdBorderWaveform = 0x3C;
    constexpr uint8_t kCmdUpdateControl = 0x21;
    constexpr uint8_t kCmdTemperatureSensor = 0x18;
    constexpr uint8_t kCmdSetRamX = 0x44;
    constexpr uint8_t kCmdSetRamY = 0x45;
    constexpr uint8_t kCmdSetRamXCursor = 0x4E;
    constexpr uint8_t kCmdSetRamYCursor = 0x4F;

    constexpr uint8_t kUpdateFull = 0xF7;
    constexpr uint8_t kUpdatePartial = 0xFF;

    constexpr uint8_t kBorderSetting = 0x05;
    constexpr uint8_t kDeepSleepMode = 0x01;

    constexpr size_t kChunk = 64;

    bool valid_rect(const EinkRect &rect, uint16_t width, uint16_t height)
    {
      if (rect.width == 0 || rect.height == 0)
        return false;
      if (rect.x >= width || rect.y >= height)
        return false;
      if (static_cast<uint32_t>(rect.x) + rect.width > width)
        return false;
      if (static_cast<uint32_t>(rect.y) + rect.height > height)
        return false;
      return true;
    }

  } // namespace

  bool EinkPanel::begin(const EinkBus &bus, const EinkPanelConfig &config)
  {
    if (bus.command == nullptr || bus.reset == nullptr || bus.busy == nullptr ||
        bus.delay_ms == nullptr)
    {
      return false;
    }
    if (config.width == 0 || config.height == 0 || config.height > 4096)
      return false;
    // The mono RAM is addressed in whole bytes, the 4-color RAM in whole
    // pixels-per-byte, so the width granularity differs.
    if (config.color == EinkColorMode::FourColor)
    {
      if (config.width % 4 != 0)
        return false;
      // A 4-color panel has no partial waveform. Accepting a LUT here would
      // mean shipping a refresh that physically cannot work.
      if (config.partial_lut != nullptr)
        return false;
    }
    else if (config.width % 8 != 0)
    {
      return false;
    }
    if (config.partial_lut != nullptr && config.partial_lut_size == 0)
    {
      return false;
    }
    bus_ = bus;
    config_ = config;
    if (config_.color == EinkColorMode::FourColor)
    {
      // SSD1683 4-color modules take black=00, white=01, red=11, yellow=10.
      // A zero-initialised config gets that table; a board with a different
      // panel overrides it explicitly.
      bool all_zero = true;
      for (size_t index = 0; index < sizeof(config_.palette); ++index)
      {
        if (config_.palette[index] != 0)
          all_zero = false;
      }
      if (all_zero)
      {
        config_.palette[kEinkPaletteBlack] = 0x00;
        config_.palette[kEinkPaletteWhite] = 0x01;
        config_.palette[kEinkPaletteRed] = 0x03;
        config_.palette[kEinkPaletteYellow] = 0x02;
      }
    }
    memset(&stats_, 0, sizeof(stats_));
    if (!begin_panel())
      return false;
    stats_.initialised = true;
    return true;
  }

  bool EinkPanel::begin_panel()
  {
    bus_.reset(bus_.context, true);
    bus_.delay_ms(bus_.context, 10);
    bus_.reset(bus_.context, false);
    bus_.delay_ms(bus_.context, 10);

    if (!bus_.command(bus_.context, kCmdSwReset, nullptr, 0))
      return false;
    if (wait_idle(config_.full_timeout_ms) != EinkRefreshResult::Ok)
      return false;

    const uint8_t output[3] = {
        static_cast<uint8_t>((config_.height - 1) & 0xFF),
        static_cast<uint8_t>((config_.height - 1) >> 8), 0x00};
    if (!bus_.command(bus_.context, kCmdDriverOutput, output, sizeof(output)))
    {
      return false;
    }
    const uint8_t entry = 0x03; // X increment, Y increment
    if (!bus_.command(bus_.context, kCmdDataEntry, &entry, 1))
      return false;
    const uint8_t border = kBorderSetting;
    if (!bus_.command(bus_.context, kCmdBorderWaveform, &border, 1))
      return false;
    // Standard SSD1680/SSD1683 init tail: use the panel's own temperature
    // sensor and keep the update sequence in normal (non-inverted) mode. The
    // waveform tables assume the reading they take here.
    const uint8_t update_control[2] = {0x00, 0x80};
    if (!bus_.command(bus_.context, kCmdUpdateControl, update_control,
                      sizeof(update_control)))
    {
      return false;
    }
    const uint8_t temperature = 0x80;
    if (!bus_.command(bus_.context, kCmdTemperatureSensor, &temperature, 1))
      return false;
    const EinkRect whole = {0, 0, config_.width, config_.height};
    return set_window(whole);
  }

  bool EinkPanel::set_window(const EinkRect &window)
  {
    const uint8_t pixels_per_byte =
        config_.color == EinkColorMode::FourColor ? 4U : 8U;
    const uint8_t x[2] = {
        static_cast<uint8_t>(window.x / pixels_per_byte),
        static_cast<uint8_t>((window.x + window.width - 1) / pixels_per_byte)};
    if (!bus_.command(bus_.context, kCmdSetRamX, x, sizeof(x)))
      return false;
    const uint16_t end_y = static_cast<uint16_t>(window.y + window.height - 1);
    const uint8_t y[4] = {static_cast<uint8_t>(window.y & 0xFF),
                          static_cast<uint8_t>(window.y >> 8),
                          static_cast<uint8_t>(end_y & 0xFF),
                          static_cast<uint8_t>(end_y >> 8)};
    if (!bus_.command(bus_.context, kCmdSetRamY, y, sizeof(y)))
      return false;
    const uint8_t cursor_x = static_cast<uint8_t>(window.x / pixels_per_byte);
    if (!bus_.command(bus_.context, kCmdSetRamXCursor, &cursor_x, 1))
      return false;
    const uint8_t cursor_y[2] = {static_cast<uint8_t>(window.y & 0xFF),
                                 static_cast<uint8_t>(window.y >> 8)};
    return bus_.command(bus_.context, kCmdSetRamYCursor, cursor_y,
                        sizeof(cursor_y));
  }

  bool EinkPanel::push_window(const uint8_t *bitmap, size_t size,
                              const EinkRect &window)
  {
    if (bitmap == nullptr || size < eink_frame_bytes(config_.width,
                                                     config_.height))
    {
      return false;
    }
    const size_t stride = eink_row_bytes(config_.width);
    const size_t start_byte = window.x / 8;
    const size_t width_bytes = eink_row_bytes(window.width);
    uint8_t chunk[kChunk];
    for (uint16_t row = 0; row < window.height; ++row)
    {
      const uint8_t *source =
          bitmap + static_cast<size_t>(window.y + row) * stride + start_byte;
      size_t remaining = width_bytes;
      const uint8_t *cursor = source;
      while (remaining != 0)
      {
        const size_t take = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
        memcpy(chunk, cursor, take);
        if (!bus_.command(bus_.context, kCmdWriteRam, chunk, take))
          return false;
        cursor += take;
        remaining -= take;
      }
    }
    return true;
  }

  bool EinkPanel::push_window_color(const uint8_t *bitmap, size_t size,
                                    const EinkRect &window)
  {
    const size_t stride = eink_row_bytes(config_.width, EinkColorMode::FourColor);
    if (bitmap == nullptr || size < eink_frame_bytes(config_.width,
                                                     config_.height,
                                                     EinkColorMode::FourColor))
    {
      return false;
    }
    if ((window.x & 3U) != 0 || (window.width & 3U) != 0)
    {
      return false;
    }
    const size_t start_byte = window.x / 4;
    const size_t width_bytes = window.width / 4;
    uint8_t chunk[kChunk];
    for (uint16_t row = 0; row < window.height; ++row)
    {
      const uint8_t *source =
          bitmap + static_cast<size_t>(window.y + row) * stride + start_byte;
      size_t produced = 0;
      for (size_t index = 0; index < width_bytes; ++index)
      {
        const uint8_t packed = source[index];
        uint8_t out = 0;
        for (size_t pixel = 0; pixel < 4; ++pixel)
        {
          const uint8_t shift = static_cast<uint8_t>(6U - 2U * pixel);
          const uint8_t palette_index =
              static_cast<uint8_t>((packed >> shift) & 0x03U);
          out = static_cast<uint8_t>(
              out | ((config_.palette[palette_index] & 0x03U) << shift));
        }
        chunk[produced++] = out;
        if (produced == sizeof(chunk))
        {
          if (!bus_.command(bus_.context, kCmdWriteRam, chunk, produced))
            return false;
          produced = 0;
        }
      }
      if (produced != 0 &&
          !bus_.command(bus_.context, kCmdWriteRam, chunk, produced))
      {
        return false;
      }
    }
    return true;
  }

  EinkRefreshResult EinkPanel::wait_idle(uint32_t timeout_ms)
  {
    uint32_t waited = 0;
    while (bus_.busy(bus_.context))
    {
      if (waited >= timeout_ms)
      {
        ++stats_.busy_timeouts;
        return EinkRefreshResult::BusyTimeout;
      }
      bus_.delay_ms(bus_.context, 10);
      waited += 10;
    }
    return EinkRefreshResult::Ok;
  }

  EinkRefreshResult EinkPanel::full_refresh(const uint8_t *bitmap, size_t size)
  {
    if (!stats_.initialised)
      return EinkRefreshResult::NotInitialised;
    if (bitmap == nullptr || size < frame_bytes())
    {
      return EinkRefreshResult::BufferTooSmall;
    }
    const EinkRect whole = {0, 0, config_.width, config_.height};
    if (!set_window(whole))
      return EinkRefreshResult::BusFault;
    const bool pushed = config_.color == EinkColorMode::FourColor
                            ? push_window_color(bitmap, size, whole)
                            : push_window(bitmap, size, whole);
    if (!pushed)
      return EinkRefreshResult::BusFault;
    const uint8_t update = kUpdateFull;
    if (!bus_.command(bus_.context, kCmdUpdateControl2, &update, 1))
    {
      return EinkRefreshResult::BusFault;
    }
    if (!bus_.command(bus_.context, kCmdMasterActivation, nullptr, 0))
    {
      return EinkRefreshResult::BusFault;
    }
    const EinkRefreshResult result = wait_idle(config_.full_timeout_ms);
    if (result != EinkRefreshResult::Ok)
      return result;
    ++stats_.full_refreshes;
    stats_.partials_since_full = 0;
    return EinkRefreshResult::Ok;
  }

  EinkRefreshResult EinkPanel::partial_refresh(const uint8_t *bitmap, size_t size,
                                               const EinkRect &window)
  {
    if (!stats_.initialised)
      return EinkRefreshResult::NotInitialised;
    // A 4-color panel has no partial waveform at all: refuse before touching
    // BUSY, the LUT or RAM.
    if (config_.color != EinkColorMode::Mono)
      return EinkRefreshResult::PartialUnsupported;
    if (config_.partial_lut == nullptr)
      return EinkRefreshResult::PartialUnsupported;
    if (!valid_rect(window, config_.width, config_.height))
    {
      return EinkRefreshResult::InvalidWindow;
    }
    if ((window.x % 8) != 0)
      return EinkRefreshResult::InvalidWindow;
    if (bitmap == nullptr || size < frame_bytes())
    {
      return EinkRefreshResult::BufferTooSmall;
    }
    if (!bus_.command(bus_.context, kCmdWriteLut, config_.partial_lut,
                      config_.partial_lut_size))
    {
      return EinkRefreshResult::BusFault;
    }
    if (!set_window(window))
      return EinkRefreshResult::BusFault;
    if (!push_window(bitmap, size, window))
      return EinkRefreshResult::BusFault;
    const uint8_t update = kUpdatePartial;
    if (!bus_.command(bus_.context, kCmdUpdateControl2, &update, 1))
    {
      return EinkRefreshResult::BusFault;
    }
    if (!bus_.command(bus_.context, kCmdMasterActivation, nullptr, 0))
    {
      return EinkRefreshResult::BusFault;
    }
    const EinkRefreshResult result = wait_idle(config_.partial_timeout_ms);
    if (result != EinkRefreshResult::Ok)
      return result;
    ++stats_.partial_refreshes;
    if (stats_.partials_since_full < 0xFF)
      ++stats_.partials_since_full;
    return EinkRefreshResult::Ok;
  }

  EinkRefreshResult EinkPanel::sleep()
  {
    if (!stats_.initialised)
      return EinkRefreshResult::NotInitialised;
    const uint8_t mode = kDeepSleepMode;
    if (!bus_.command(bus_.context, kCmdDeepSleep, &mode, 1))
    {
      return EinkRefreshResult::BusFault;
    }
    stats_.initialised = false;
    return EinkRefreshResult::Ok;
  }

  void EinkDamage::reset(uint16_t width, uint16_t height)
  {
    count_ = 0;
    width_ = width;
    height_ = height;
  }

  void EinkDamage::add(const EinkRect &rect)
  {
    if (rect.width == 0 || rect.height == 0)
      return;
    if (count_ >= sizeof(rects_) / sizeof(rects_[0]))
    {
      rects_[0] = {0, 0, width_, height_};
      count_ = 1;
      return;
    }
    rects_[count_++] = rect;
  }

  EinkRect EinkDamage::bounds() const
  {
    if (count_ == 0)
      return {0, 0, 0, 0};
    uint32_t left = width_;
    uint32_t top = height_;
    uint32_t right = 0;
    uint32_t bottom = 0;
    for (uint8_t index = 0; index < count_; ++index)
    {
      const EinkRect &rect = rects_[index];
      const uint32_t rect_left = rect.x;
      const uint32_t rect_top = rect.y;
      uint32_t rect_right = static_cast<uint32_t>(rect.x) + rect.width;
      uint32_t rect_bottom = static_cast<uint32_t>(rect.y) + rect.height;
      if (rect_right > width_)
        rect_right = width_;
      if (rect_bottom > height_)
        rect_bottom = height_;
      if (rect_left < left)
        left = rect_left;
      if (rect_top < top)
        top = rect_top;
      if (rect_right > right)
        right = rect_right;
      if (rect_bottom > bottom)
        bottom = rect_bottom;
    }
    if (right <= left || bottom <= top)
      return {0, 0, 0, 0};
    return {static_cast<uint16_t>(left), static_cast<uint16_t>(top),
            static_cast<uint16_t>(right - left),
            static_cast<uint16_t>(bottom - top)};
  }

  bool EinkDamage::prefers_full_refresh(uint32_t area_threshold_percent) const
  {
    const EinkRect rect = bounds();
    if (rect.width == 0 || rect.height == 0)
      return false;
    const uint32_t total = static_cast<uint32_t>(width_) * height_;
    if (total == 0)
      return true;
    const uint32_t area = static_cast<uint32_t>(rect.width) * rect.height;
    return area * 100U >= total * area_threshold_percent;
  }

  // ---------------------------------------------------------------------------
  // Self-tests: a recording fake bus proves the command sequence, the window
  // arithmetic and the failure paths without a panel.
  // ---------------------------------------------------------------------------

  namespace
  {

    struct FakeBus
    {
      uint8_t commands[512];
      size_t command_count;
      size_t ram_bytes;
      size_t lut_bytes;
      uint8_t window_x[2];
      uint8_t window_y[4];
      uint8_t first_ram;
      bool have_ram;
      int busy_polls;
      bool fail_next;
    };

    bool fake_command(void *context, uint8_t command, const uint8_t *data,
                      size_t size)
    {
      FakeBus *bus = static_cast<FakeBus *>(context);
      if (bus->fail_next)
      {
        bus->fail_next = false;
        return false;
      }
      if (bus->command_count < sizeof(bus->commands))
      {
        bus->commands[bus->command_count++] = command;
      }
      switch (command)
      {
      case 0x24:
        if (!bus->have_ram && size != 0 && data != nullptr)
        {
          bus->first_ram = data[0];
          bus->have_ram = true;
        }
        bus->ram_bytes += size;
        break;
      case 0x32:
        bus->lut_bytes = size;
        break;
      case 0x44:
        if (size == 2)
          memcpy(bus->window_x, data, 2);
        break;
      case 0x45:
        if (size == 4)
          memcpy(bus->window_y, data, 4);
        break;
      default:
        break;
      }
      return true;
    }

    void fake_reset(void *context, bool asserted)
    {
      (void)context;
      (void)asserted;
    }

    bool fake_busy(void *context)
    {
      FakeBus *bus = static_cast<FakeBus *>(context);
      if (bus->busy_polls > 0)
      {
        --bus->busy_polls;
        return true;
      }
      return false;
    }

    void fake_delay(void *context, uint32_t milliseconds)
    {
      (void)context;
      (void)milliseconds;
    }

    size_t count_command(const FakeBus &bus, uint8_t command)
    {
      size_t total = 0;
      for (size_t index = 0; index < bus.command_count; ++index)
      {
        if (bus.commands[index] == command)
          ++total;
      }
      return total;
    }

  } // namespace

  bool run_eink_panel_self_tests()
  {
    bool passed = true;
    static uint8_t frame[eink_frame_bytes(kEink29Width, kEink29Height)];
    memset(frame, 0xA5, sizeof(frame));
    static uint8_t lut[153];
    memset(lut, 0x11, sizeof(lut));

    FakeBus fake = {};
    EinkBus bus = {&fake, fake_command, fake_reset, fake_busy, fake_delay};
    EinkPanelConfig config = {};
    config.width = kEink29Width;
    config.height = kEink29Height;
    config.color = EinkColorMode::Mono;
    config.full_timeout_ms = 4000;
    config.partial_timeout_ms = 1500;
    config.partial_budget = 8;
    EinkPanel panel;

    // Width must be byte aligned: a ragged stride would shift every row.
    EinkPanelConfig ragged = config;
    ragged.width = 130;
    passed = !panel.begin(bus, ragged) && passed;

    passed = panel.begin(bus, config) && passed;
    passed = panel.stats().initialised && passed;
    passed = count_command(fake, 0x12) == 1 && passed; // software reset
    passed = count_command(fake, 0x11) == 1 && passed; // data entry
    passed = count_command(fake, 0x44) >= 1 && passed; // RAM X window
    passed = count_command(fake, 0x45) >= 1 && passed; // RAM Y window
    // Boot leaves the RAM window at the full panel.
    passed = fake.window_x[0] == 0 && fake.window_x[1] == kEink29Width / 8 - 1 &&
             passed;
    passed = fake.window_y[0] == 0 && fake.window_y[1] == 0 &&
             fake.window_y[2] == ((kEink29Height - 1) & 0xFF) &&
             fake.window_y[3] == ((kEink29Height - 1) >> 8) && passed;

    // Full refresh: window, 0x24 data, 0xF7 update control, 0x20 activation.
    fake = FakeBus{};
    passed = panel.full_refresh(frame, sizeof(frame)) == EinkRefreshResult::Ok && passed;
    passed = fake.ram_bytes == sizeof(frame) && passed;
    passed = count_command(fake, 0x20) == 1 && passed;
    passed = panel.stats().full_refreshes == 1 && passed;
    // A short buffer is refused before anything is pushed.
    fake = FakeBus{};
    passed = panel.full_refresh(frame, 10) == EinkRefreshResult::BufferTooSmall &&
             fake.ram_bytes == 0 && passed;

    // Partial without a LUT must be refused and must not touch the panel.
    fake = FakeBus{};
    passed = panel.partial_refresh(frame, sizeof(frame), {0, 0, 32, 16}) ==
                 EinkRefreshResult::PartialUnsupported &&
             passed;
    passed = count_command(fake, 0x20) == 0 && passed;
    passed = !panel.partial_supported() && passed;

    // With a LUT the sequence loads it, sets the window, writes only that window
    // and uses the partial update control value.
    config.partial_lut = lut;
    config.partial_lut_size = sizeof(lut);
    EinkPanel partial_panel;
    passed = partial_panel.begin(bus, config) && passed;
    passed = partial_panel.partial_supported() && passed;
    fake = FakeBus{};
    passed = partial_panel.partial_refresh(frame, sizeof(frame), {16, 32, 32, 16}) ==
                 EinkRefreshResult::Ok &&
             passed;
    passed = fake.lut_bytes == sizeof(lut) && passed;
    passed = count_command(fake, 0x20) == 1 && passed;
    passed = partial_panel.stats().partial_refreshes == 1 && passed;
    // The X window is expressed in bytes: 16..47 -> 2..5; Y is rows 32..47.
    passed = fake.window_x[0] == 2 && fake.window_x[1] == 5 && passed;
    passed = fake.window_y[0] == 32 && fake.window_y[1] == 0 &&
             fake.window_y[2] == 47 && fake.window_y[3] == 0 && passed;
    // Only 32 pixels wide and 16 rows tall were pushed: 4 bytes per row.
    passed = fake.ram_bytes == 4U * 16U && passed;
    passed = !partial_panel.full_refresh_due() && passed;
    for (uint8_t index = 1; index < config.partial_budget; ++index)
    {
      partial_panel.partial_refresh(frame, sizeof(frame), {0, 0, 8, 8});
    }
    passed = partial_panel.full_refresh_due() && passed;
    // A full refresh clears the debt.
    passed = partial_panel.full_refresh(frame, sizeof(frame)) ==
                 EinkRefreshResult::Ok &&
             !partial_panel.full_refresh_due() && passed;

    // Window validation.
    passed = partial_panel.partial_refresh(frame, sizeof(frame), {0, 0, 0, 8}) ==
                 EinkRefreshResult::InvalidWindow &&
             passed;
    passed = partial_panel.partial_refresh(frame, sizeof(frame), {120, 0, 16, 8}) ==
                 EinkRefreshResult::InvalidWindow &&
             passed;
    // A window that is not byte aligned would shift every row.
    passed = partial_panel.partial_refresh(frame, sizeof(frame), {4, 0, 8, 8}) ==
                 EinkRefreshResult::InvalidWindow &&
             passed;
    // Short buffer must be refused, not partially pushed.
    fake = FakeBus{};
    passed = partial_panel.partial_refresh(frame, 10, {0, 0, 8, 8}) ==
                 EinkRefreshResult::BufferTooSmall &&
             fake.ram_bytes == 0 && passed;

    // A BUSY line that never releases is a fault, not a completed frame.
    FakeBus stuck = {};
    stuck.busy_polls = 100000;
    EinkBus stuck_bus = {&stuck, fake_command, fake_reset, fake_busy, fake_delay};
    EinkPanel stuck_panel;
    passed = !stuck_panel.begin(stuck_bus, config) && passed;
    EinkPanel busy_panel;
    FakeBus healthy = {};
    EinkBus healthy_bus = {&healthy, fake_command, fake_reset, fake_busy, fake_delay};
    passed = busy_panel.begin(healthy_bus, config) && passed;
    healthy.busy_polls = 100000;
    passed = busy_panel.full_refresh(frame, sizeof(frame)) ==
                 EinkRefreshResult::BusyTimeout &&
             passed;
    passed = busy_panel.stats().busy_timeouts == 1 && passed;

    // --- 4-color panel: 2bpp, full refresh only --------------------------
    {
      static uint8_t color_frame[eink_frame_bytes(kEink29Width, kEink29Height,
                                                  EinkColorMode::FourColor)];
      // 0b00 0b01 0b10 0b11 = black, white, red, yellow in the converter's
      // palette order.
      color_frame[0] = 0x1B;
      memset(color_frame + 1, 0x55, sizeof(color_frame) - 1);  // all white
      EinkPanelConfig color_config = config;
      color_config.color = EinkColorMode::FourColor;
      // A 4-color panel with a partial LUT is a configuration bug: the panel
      // physically cannot do it.
      EinkPanelConfig bad = color_config;
      bad.partial_lut = lut;
      bad.partial_lut_size = sizeof(lut);
      EinkPanel color_panel;
      passed = !color_panel.begin(bus, bad) && passed;
      // 2bpp RAM needs a width that is a whole number of pixels per byte.
      EinkPanelConfig odd = color_config;
      odd.width = 130;
      passed = !color_panel.begin(bus, odd) && passed;

      FakeBus color_fake = {};
      EinkBus color_bus = {&color_fake, fake_command, fake_reset, fake_busy,
                           fake_delay};
      passed = color_panel.begin(color_bus, color_config) && passed;
      passed = color_panel.color_mode() == EinkColorMode::FourColor && passed;
      passed = !color_panel.partial_supported() && passed;
      passed = color_panel.frame_bytes() == sizeof(color_frame) && passed;
      // The X window is expressed in 4-pixel bytes now.
      passed = color_fake.window_x[0] == 0 &&
               color_fake.window_x[1] == kEink29Width / 4 - 1 && passed;

      color_fake = FakeBus{};
      passed = color_panel.full_refresh(color_frame, sizeof(color_frame)) ==
                   EinkRefreshResult::Ok &&
               passed;
      passed = color_fake.ram_bytes == sizeof(color_frame) && passed;
      // black->00, white->01, red->11, yellow->10 gives 0b00 01 11 10 = 0x1E.
      passed = color_fake.have_ram && color_fake.first_ram == 0x1E && passed;
      passed = count_command(color_fake, 0x20) == 1 && passed;
      passed = color_panel.stats().full_refreshes == 1 && passed;

      // Partial refresh on a 4-color panel is refused before any bus traffic.
      color_fake = FakeBus{};
      passed = color_panel.partial_refresh(color_frame, sizeof(color_frame),
                                           {0, 0, 32, 16}) ==
                   EinkRefreshResult::PartialUnsupported &&
               passed;
      passed = color_fake.command_count == 0 && passed;
      // A 1bpp frame is too small for the 2bpp RAM and must be refused.
      color_fake = FakeBus{};
      passed = color_panel.full_refresh(frame, sizeof(frame)) ==
                   EinkRefreshResult::BufferTooSmall &&
               color_fake.ram_bytes == 0 && passed;
      passed = color_panel.sleep() == EinkRefreshResult::Ok && passed;
    }

    // Damage union and clipping.
    EinkDamage damage;
    damage.reset(kEink29Width, kEink29Height);
    passed = damage.empty() && passed;
    damage.add({10, 20, 10, 10});
    damage.add({60, 5, 20, 40});
    const EinkRect merged = damage.bounds();
    passed = merged.x == 10 && merged.y == 5 && merged.width == 70 &&
             merged.height == 40 && passed;
    damage.reset(kEink29Width, kEink29Height);
    damage.add({120, 290, 40, 40}); // clipped to the panel edge
    const EinkRect clipped = damage.bounds();
    passed = clipped.width == 8 && clipped.height == 6 && passed;
    damage.reset(kEink29Width, kEink29Height);
    damage.add({0, 0, 8, 8});
    passed = !damage.prefers_full_refresh(15) && passed;
    damage.add({0, 0, 128, 296});
    passed = damage.prefers_full_refresh(15) && passed;
    damage.reset(kEink29Width, kEink29Height);
    for (int index = 0; index < 20; ++index)
      damage.add({0, 0, 1, 1});
    const EinkRect collapsed = damage.bounds();
    passed = collapsed.width == kEink29Width && collapsed.height == kEink29Height &&
             passed;
    return passed;
  }

} // namespace hexwallet
