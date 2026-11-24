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
    constexpr uint8_t kUpdatePartialOtp = 0xFF;
    // Mode 2 using MCU-supplied registers, without reloading the OTP waveform.
    constexpr uint8_t kUpdatePartialHost = 0xCF;

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
    last_error_ = EinkRefreshResult::InvalidConfig;
    stats_ = {};
    sleeping_ = false;
    needs_baseline_ = true;
    config_ = {};
    if (bus.command == nullptr || bus.reset == nullptr || bus.busy == nullptr ||
        bus.delay_ms == nullptr || bus.data == nullptr)
    {
      return false;
    }
    if (config.width != kEink29Width || config.height != kEink29Height ||
        config.full_timeout_ms == 0 || config.full_timeout_ms > 120000 ||
        config.partial_timeout_ms > 120000 ||
        (config.color != EinkColorMode::Mono && config.color != EinkColorMode::FourColor))
      return false;
    if (config.controller == EinkController::Ssd1683)
    {
      if (config.color != EinkColorMode::FourColor ||
          config.color_init == nullptr || config.color_init_count == 0 || config.color_init_count > 32)
        return false;
      for (size_t i = 0; i < config.color_init_count; ++i)
        if (config.color_init[i].size > sizeof(config.color_init[i].bytes))
          return false;
    }
    else if ((config.controller != EinkController::Ssd1680 &&
              config.controller != EinkController::HinkE029A01) || config.color != EinkColorMode::Mono)
    {
      return false;
    }
    else if (config.color_init != nullptr || config.color_init_count != 0)
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
    if ((config.controller == EinkController::Ssd1680 || config.partial_lut != nullptr) &&
        (config.partial_timeout_ms == 0 || config.partial_budget == 0)) return false;
    const size_t waveform_bytes = config.controller == EinkController::HinkE029A01 ? 30 : 159;
    if ((config.partial_lut != nullptr && config.partial_lut_size != waveform_bytes) ||
        (config.partial_lut == nullptr && config.partial_lut_size != 0))
    {
      return false;
    }
    bus_ = bus;
    config_ = config;
    if (config_.color == EinkColorMode::FourColor)
    {
      // SSD1683-class 2.9 inch modules take black=00, white=01, red=11, yellow=10.
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
      uint8_t seen = 0;
      for (uint8_t code : config_.palette)
      {
        if (code > 3 || (seen & (1U << code)) != 0)
          return false;
        seen |= 1U << code;
      }
    }
    memset(&stats_, 0, sizeof(stats_));
    last_error_ = EinkRefreshResult::Ok;
    if (!begin_panel())
      return false;
    stats_.initialised = true;
    return true;
  }

  bool EinkPanel::begin_panel()
  {
    const bool four_color = config_.controller == EinkController::Ssd1683;
    if (!reset(false))
      return false;
    bus_.delay_ms(bus_.context, 200);
    if (!reset(true))
      return false;
    bus_.delay_ms(bus_.context, four_color ? 2 : 10);
    if (!reset(false))
      return false;
    bus_.delay_ms(bus_.context, 200);
    if (wait_idle(config_.full_timeout_ms) != EinkRefreshResult::Ok)
      return false;
    if (four_color)
      return begin_four_color();

    if (!command(kCmdSwReset, nullptr, 0))
      return false;
    bus_.delay_ms(bus_.context, 10);
    if (wait_idle(config_.full_timeout_ms) != EinkRefreshResult::Ok)
      return false;

    const uint8_t output[3] = {
        static_cast<uint8_t>((config_.height - 1) & 0xFF),
        static_cast<uint8_t>((config_.height - 1) >> 8), 0x00};
    if (!command(kCmdDriverOutput, output, sizeof(output)))
    {
      return false;
    }
    const uint8_t entry = 0x03; // X increment, Y increment
    if (!command(kCmdDataEntry, &entry, 1))
      return false;
    const EinkRect whole = {0, 0, config_.width, config_.height};
    if (config_.controller == EinkController::HinkE029A01)
    {
      // HINK-E029A01 A/0, sections 6.3 and 7. The board leaves TSCL/TSDA
      // open. Select the room-temperature OTP waveform through register 1Ah.
      const uint8_t room_temperature[] = {0x19, 0x00};
      const uint8_t booster[] = {0xcf, 0xce, 0x8d};
      const uint8_t dummy_lines = 0x1a, gate_width = 0x08;
      return command(0x0c, booster, sizeof(booster)) &&
             command(0x3a, &dummy_lines, 1) && command(0x3b, &gate_width, 1) &&
             command(0x1a, room_temperature, sizeof(room_temperature)) && set_window(whole);
    }
    const uint8_t border = kBorderSetting;
    if (!command(kCmdBorderWaveform, &border, 1))
      return false;
    // SSD1680 init tail: use the panel's own temperature
    // sensor and keep the update sequence in normal (non-inverted) mode. The
    // waveform tables assume the reading they take here.
    const uint8_t update_control[2] = {0x00, 0x80};
    if (!command(kCmdUpdateControl, update_control,
                      sizeof(update_control)))
    {
      return false;
    }
    const uint8_t temperature = 0x80;
    if (!command(kCmdTemperatureSensor, &temperature, 1))
      return false;
    return set_window(whole);
  }

  bool EinkPanel::begin_four_color()
  {
    // SSD1683-class panel manual sections 7 and 8. The reset/transport
    // protocol is independent of the module's analogue initialisation values.
    for (size_t i = 0; i < config_.color_init_count; ++i)
    {
      const EinkInitCommand &s = config_.color_init[i];
      if (!command(s.command, s.bytes, s.size))
        return false;
    }
    return wait_idle(config_.full_timeout_ms) == EinkRefreshResult::Ok;
  }

  bool EinkPanel::command(uint8_t code, const uint8_t *bytes, size_t size)
  {
    if (bus_.command(bus_.context, code, bytes, size))
      return true;
    stats_.initialised = false;
    last_error_ = EinkRefreshResult::BusFault;
    return false;
  }

  bool EinkPanel::reset(bool asserted)
  {
    if (bus_.reset(bus_.context, asserted)) return true;
    stats_.initialised = false;
    last_error_ = EinkRefreshResult::ResetFault;
    return false;
  }

  bool EinkPanel::data(const uint8_t *bytes, size_t size)
  {
    if (bus_.data(bus_.context, bytes, size))
      return true;
    stats_.initialised = false;
    last_error_ = EinkRefreshResult::BusFault;
    return false;
  }

  bool EinkPanel::set_window(const EinkRect &window)
  {
    const uint8_t pixels_per_byte =
        config_.color == EinkColorMode::FourColor ? 4U : 8U;
    const uint8_t x[2] = {
        static_cast<uint8_t>(window.x / pixels_per_byte),
        static_cast<uint8_t>((window.x + window.width - 1) / pixels_per_byte)};
    if (!command(kCmdSetRamX, x, sizeof(x)))
      return false;
    const uint16_t end_y = static_cast<uint16_t>(window.y + window.height - 1);
    const uint8_t y[4] = {static_cast<uint8_t>(window.y & 0xFF),
                          static_cast<uint8_t>(window.y >> 8),
                          static_cast<uint8_t>(end_y & 0xFF),
                          static_cast<uint8_t>(end_y >> 8)};
    if (!command(kCmdSetRamY, y, sizeof(y)))
      return false;
    const uint8_t cursor_x = static_cast<uint8_t>(window.x / pixels_per_byte);
    if (!command(kCmdSetRamXCursor, &cursor_x, 1))
      return false;
    const uint8_t cursor_y[2] = {static_cast<uint8_t>(window.y & 0xFF),
                                 static_cast<uint8_t>(window.y >> 8)};
    return command(kCmdSetRamYCursor, cursor_y,
                        sizeof(cursor_y));
  }

  bool EinkPanel::push_window(const uint8_t *bitmap, size_t size,
                              const EinkRect &window, uint8_t ram_command)
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
    size_t filled = 0;
    if (!command(ram_command, nullptr, 0))
      return false;
    for (uint16_t row = 0; row < window.height; ++row)
    {
      const uint8_t *source =
          bitmap + static_cast<size_t>(window.y + row) * stride + start_byte;
      for (size_t i = 0; i < width_bytes; ++i)
      {
        chunk[filled++] = static_cast<uint8_t>(~source[i]);
        if (filled == sizeof(chunk))
        {
          if (!data(chunk, filled)) return false;
          filled = 0;
        }
      }
    }
    return filled == 0 || data(chunk, filled);
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
    if (!command(0x10, nullptr, 0))
      return false;
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
          if (!data(chunk, produced))
            return false;
          produced = 0;
        }
      }
      if (produced != 0 &&
          !data(chunk, produced))
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
        stats_.initialised = false;
        last_error_ = EinkRefreshResult::BusyTimeout;
        return EinkRefreshResult::BusyTimeout;
      }
      bus_.delay_ms(bus_.context, 10);
      waited += 10;
    }
    return EinkRefreshResult::Ok;
  }

  EinkRefreshResult EinkPanel::wait_refresh_cycle(uint32_t timeout_ms)
  {
    // Activation can return before BUSY asserts (polarity is board-specific).
    // A disconnected panel can
    // otherwise appear idle for the entire transaction, even for a full frame.
    const uint32_t start_timeout = timeout_ms < 100 ? timeout_ms : 100;
    for (uint32_t elapsed = 0; ; ++elapsed)
    {
      if (bus_.busy(bus_.context)) return wait_idle(timeout_ms - elapsed);
      if (elapsed == start_timeout) break;
      bus_.delay_ms(bus_.context, 1);
    }
    ++stats_.busy_timeouts;
    stats_.initialised = false;
    last_error_ = EinkRefreshResult::BusyNotAsserted;
    return EinkRefreshResult::BusyNotAsserted;
  }

  EinkRefreshResult EinkPanel::activate_mono(uint8_t update, uint32_t timeout_ms)
  {
    // Establish an idle baseline before requesting the new waveform. An
    // earlier BUSY pulse must never be credited to this image.
    const auto idle = wait_idle(timeout_ms);
    if (idle != EinkRefreshResult::Ok) return idle;
    if (!command(kCmdUpdateControl2, &update, 1) ||
        !command(kCmdMasterActivation, nullptr, 0))
      return EinkRefreshResult::BusFault;
    return wait_refresh_cycle(timeout_ms);
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
    if (config_.controller == EinkController::Ssd1683)
    {
      if (!push_window_color(bitmap, size, whole))
        return EinkRefreshResult::BusFault;
      if (!command(0x04, nullptr, 0))
        return EinkRefreshResult::BusFault;
      bus_.delay_ms(bus_.context, 100);
      const auto powered = wait_idle(config_.full_timeout_ms);
      if (powered != EinkRefreshResult::Ok)
        return powered;
      const uint8_t zero = 0;
      if (!command(0x12, &zero, 1))
        return EinkRefreshResult::BusFault;
      bus_.delay_ms(bus_.context, 100);
      auto result = wait_idle(config_.full_timeout_ms);
      if (result != EinkRefreshResult::Ok)
        return result;
      if (!command(0x02, &zero, 1))
        return EinkRefreshResult::BusFault;
      bus_.delay_ms(bus_.context, 100);
      result = wait_idle(config_.full_timeout_ms);
      if (result == EinkRefreshResult::Ok)
      {
        ++stats_.full_refreshes;
        stats_.partials_since_full = 0;
      }
      return result;
    }
    // Restore full-refresh border/temperature/RAM mode after a partial cycle.
    const bool hink = config_.controller == EinkController::HinkE029A01;
    if (hink && wait_idle(config_.full_timeout_ms) != EinkRefreshResult::Ok)
      return last_error_;
    if (!hink && stats_.partials_since_full != 0 && !begin_panel())
    {
      stats_.initialised = false;
      return last_error_;
    }
    if (!set_window(whole))
      return EinkRefreshResult::BusFault;
    if (!push_window(bitmap, size, whole))
      return EinkRefreshResult::BusFault;
    if (!hink && (!set_window(whole) || !push_window(bitmap, size, whole, 0x26)))
      return EinkRefreshResult::BusFault;
    // HINK R22h: enable clock and pump, load OTP LUT, initial + pattern
    // display, then power down. Skip the external temperature sensor read.
    const uint8_t update = hink ? 0xdf : kUpdateFull;
    const auto result = activate_mono(update, config_.full_timeout_ms);
    if (result != EinkRefreshResult::Ok)
      return result;
    // SSD1608 switches its writable RAM bank on activation. Seed the other
    // bank before any differential refresh, including the first after wake.
    if (hink && partial_supported() && (!set_window(whole) || !push_window(bitmap, size, whole)))
      return EinkRefreshResult::BusFault;
    ++stats_.full_refreshes;
    stats_.partials_since_full = 0;
    needs_baseline_ = false;
    return EinkRefreshResult::Ok;
  }

  EinkRefreshResult EinkPanel::partial_refresh(const uint8_t *bitmap, size_t size,
                                               const EinkRect &window)
  {
    if (!stats_.initialised)
      return EinkRefreshResult::NotInitialised;
    // Refuse unsupported partial updates before touching BUSY, the LUT or RAM.
    if (!partial_supported())
      return EinkRefreshResult::PartialUnsupported;
    if (!valid_rect(window, config_.width, config_.height))
    {
      return EinkRefreshResult::InvalidWindow;
    }
    if ((window.x % 8) != 0 || (window.width % 8) != 0)
      return EinkRefreshResult::InvalidWindow;
    if (bitmap == nullptr || size < frame_bytes())
    {
      return EinkRefreshResult::BufferTooSmall;
    }
    // Differential waveforms require a known old frame. The first update and
    // exhausted ghosting budget always establish a complete new baseline.
    if (needs_baseline_ || full_refresh_due())
      return full_refresh(bitmap, size);
    if (config_.controller == EinkController::HinkE029A01 &&
        wait_idle(config_.partial_timeout_ms) != EinkRefreshResult::Ok)
      return last_error_;
    const auto prepared = prepare_partial_update();
    if (prepared != EinkRefreshResult::Ok) return prepared;
    if (!set_window(window) || !push_window(bitmap, size, window))
      return EinkRefreshResult::BusFault;
    const bool hink = config_.controller == EinkController::HinkE029A01;
    // SSD1608 R22h: enable clock + charge pump, apply pattern, disable both.
    // Leave the host LUT intact and skip the initial-display (flashing) phase.
    uint8_t update = 0xc7;
    if (!hink) update = config_.partial_lut ? kUpdatePartialHost : kUpdatePartialOtp;
    const auto result = activate_mono(update, config_.partial_timeout_ms);
    if (result != EinkRefreshResult::Ok) return result;
    // Synchronize only the changed bytes after BUSY releases. SSD1608 writes
    // the newly selected bank via 24h; SSD1680 explicitly addresses old RAM.
    if (!set_window(window) || !push_window(bitmap, size, window, hink ? kCmdWriteRam : 0x26))
      return EinkRefreshResult::BusFault;
    ++stats_.partial_refreshes;
    if (stats_.partials_since_full < 0xFF) ++stats_.partials_since_full;
    return EinkRefreshResult::Ok;
  }

  EinkRefreshResult EinkPanel::prepare_partial_update()
  {
    if (config_.controller == EinkController::HinkE029A01)
    {
      return command(kCmdWriteLut, config_.partial_lut, config_.partial_lut_size)
                 ? EinkRefreshResult::Ok : EinkRefreshResult::BusFault;
    }
    // Complete WS layout from SSD1680 section 6.7. Voltage/end settings must
    // travel with the LUT; an OTP load must not replace this register content.
    if (config_.partial_lut != nullptr)
    {
      const uint8_t *ws = config_.partial_lut;
      if (!command(kCmdWriteLut, ws, 153) ||
          !command(0x3f, ws + 153, 1) ||
          !command(0x03, ws + 154, 1) ||
          !command(0x04, ws + 155, 3) ||
          !command(0x2c, ws + 158, 1))
        return EinkRefreshResult::BusFault;
    }
    // Keep the OTP display-mode table intact. Writing zeroes to 0x37 would
    // reclassify every stored waveform as mode 1 and break mode-2 lookup.
    const uint8_t border = 0x80, power = 0xc0;
    if (!command(kCmdBorderWaveform, &border, 1) ||
        !command(kCmdUpdateControl2, &power, 1) ||
        !command(kCmdMasterActivation, nullptr, 0))
      return EinkRefreshResult::BusFault;
    bus_.delay_ms(bus_.context, 10);
    return wait_idle(config_.partial_timeout_ms);
  }

  EinkRefreshResult EinkPanel::sleep()
  {
    if (!stats_.initialised)
      return EinkRefreshResult::NotInitialised;
    if (config_.controller == EinkController::Ssd1683)
    {
      const uint8_t zero = 0, check = 0xa5;
      if (!command(0x02, &zero, 1))
        return EinkRefreshResult::BusFault;
      bus_.delay_ms(bus_.context, 100);
      const auto result = wait_idle(config_.full_timeout_ms);
      if (result != EinkRefreshResult::Ok)
        return result;
      bus_.delay_ms(bus_.context, 20);
      if (!command(0x07, &check, 1))
        return EinkRefreshResult::BusFault;
      stats_.initialised = false;
      sleeping_ = true;
      return EinkRefreshResult::Ok;
    }
    const uint8_t mode = kDeepSleepMode;
    if (config_.controller == EinkController::HinkE029A01 &&
        wait_idle(config_.full_timeout_ms) != EinkRefreshResult::Ok)
      return last_error_;
    if (!command(kCmdDeepSleep, &mode, 1))
    {
      return EinkRefreshResult::BusFault;
    }
    stats_.initialised = false;
    sleeping_ = true;
    return EinkRefreshResult::Ok;
  }

  bool EinkPanel::wake()
  {
    if (!sleeping_)
      return stats_.initialised;
    sleeping_ = false;
    needs_baseline_ = true;
    stats_.partials_since_full = 0;
    stats_.initialised = begin_panel();
    return stats_.initialised;
  }

  EinkRect eink_mono_changes(const uint8_t *previous, const uint8_t *next)
  {
    constexpr uint16_t stride = kEink29Width / 8;
    uint16_t left = stride, right = 0, top = kEink29Height, bottom = 0;
    for (uint16_t y = 0; y < kEink29Height; ++y, previous += stride, next += stride)
    {
      if (memcmp(previous, next, stride) == 0) continue;
      if (top == kEink29Height) top = y;
      bottom = y + 1;
      for (uint16_t x = 0; x < stride; ++x)
      {
        if (previous[x] == next[x]) continue;
        if (x < left) left = x;
        if (x >= right) right = x + 1;
      }
    }
    if (right == 0) return {};
    return {uint16_t(left * 8), top, uint16_t((right - left) * 8), uint16_t(bottom - top)};
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
      uint8_t active_command;
      bool have_ram;
      int busy_polls;
      bool fail_next;
      bool ignore_activation;
      bool fail_reset;
      uint8_t update_control;
      uint8_t temperature[2];
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
      bus->active_command = command;
      switch (command)
      {
      case 0x1a:
        if (size == 2) memcpy(bus->temperature, data, 2);
        break;
      case kCmdUpdateControl2:
        if (size == 1) bus->update_control = data[0];
        break;
      case kCmdMasterActivation:
        if (!bus->ignore_activation && bus->busy_polls == 0) bus->busy_polls = 3;
        break;
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

    bool fake_data(void *context, const uint8_t *data, size_t size)
    {
      FakeBus *bus = static_cast<FakeBus *>(context);
      if (bus->fail_next)
      {
        bus->fail_next = false;
        return false;
      }
      if (bus->active_command == 0x24 || bus->active_command == 0x10)
      {
        if (!bus->have_ram && size != 0)
        {
          bus->first_ram = data[0];
          bus->have_ram = true;
        }
        bus->ram_bytes += size;
      }
      return true;
    }

    bool fake_reset(void *context, bool asserted)
    {
      (void)asserted;
      return !static_cast<FakeBus *>(context)->fail_reset;
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
    // 153 LUT bytes plus EOPT, VGH, VSH1, VSH2, VSL and VCOM.
    static uint8_t lut[159];
    memset(lut, 0x11, sizeof(lut));

    FakeBus fake = {};
    EinkBus bus = {&fake, fake_command, fake_reset, fake_busy, fake_delay, fake_data};
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
    passed = fake.ram_bytes == sizeof(frame) && fake.first_ram == 0x5a && passed;
    passed = count_command(fake, 0x20) == 1 && passed;
    passed = panel.stats().full_refreshes == 1 && passed;
    // A short buffer is refused before anything is pushed.
    fake = FakeBus{};
    passed = panel.full_refresh(frame, 10) == EinkRefreshResult::BufferTooSmall &&
             fake.ram_bytes == 0 && passed;

    // Without a board-supplied table the OTP waveform drives the update: no
    // 0x32 write, but the window and the partial update value still apply.
    fake = FakeBus{};
    passed = panel.partial_supported() && passed;
    passed = panel.partial_refresh(frame, sizeof(frame), {0, 0, 32, 16}) ==
                 EinkRefreshResult::Ok &&
             passed;
    passed = fake.lut_bytes == 0 && passed;
    passed = count_command(fake, 0x20) == 2 && passed;
    passed = panel.stats().partial_refreshes == 1 && passed;

    // With a LUT the sequence loads it, sets the window, writes only that window
    // and uses the partial update control value.
    config.partial_lut = lut;
    config.partial_lut_size = sizeof(lut);
    EinkPanel partial_panel;
    passed = partial_panel.begin(bus, config) && passed;
    passed = partial_panel.partial_supported() && passed;
    passed = partial_panel.full_refresh(frame, sizeof(frame)) == EinkRefreshResult::Ok && passed;
    fake = FakeBus{};
    passed = partial_panel.partial_refresh(frame, sizeof(frame), {16, 32, 32, 16}) ==
                 EinkRefreshResult::Ok &&
             passed;
    // Only the 153 waveform bytes go to 0x32; the tail travels as its own
    // EOPT/VGH/VSH1/VSH2/VSL/VCOM commands.
    passed = fake.lut_bytes == 153 && passed;
    passed = count_command(fake, 0x3f) == 1 && count_command(fake, 0x04) == 1 && passed;
    passed = count_command(fake, 0x20) == 2 && passed;
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
    EinkBus stuck_bus = {&stuck, fake_command, fake_reset, fake_busy, fake_delay, fake_data};
    EinkPanel stuck_panel;
    passed = !stuck_panel.begin(stuck_bus, config) && passed;
    EinkPanel busy_panel;
    FakeBus healthy = {};
    EinkBus healthy_bus = {&healthy, fake_command, fake_reset, fake_busy, fake_delay, fake_data};
    passed = busy_panel.begin(healthy_bus, config) && passed;
    healthy.busy_polls = 100000;
    passed = busy_panel.full_refresh(frame, sizeof(frame)) ==
                 EinkRefreshResult::BusyTimeout &&
             passed;
    passed = busy_panel.stats().busy_timeouts == 1 && passed;

    healthy = FakeBus{};
    healthy.ignore_activation = true;
    passed = busy_panel.begin(healthy_bus, config) && passed;
    passed = busy_panel.full_refresh(frame, sizeof(frame)) == EinkRefreshResult::BusyNotAsserted && passed;
    passed = !busy_panel.stats().initialised && busy_panel.stats().full_refreshes == 0 && passed;

    // HINK uses the old mono register set, not SSD1680's sensor/old-RAM/LUT.
    {
      FakeBus hink_fake = {};
      EinkBus hink_bus = {&hink_fake, fake_command, fake_reset, fake_busy, fake_delay, fake_data};
      EinkPanelConfig hink_config = {};
      hink_config.width = kEink29Width;
      hink_config.height = kEink29Height;
      hink_config.controller = EinkController::HinkE029A01;
      hink_config.full_timeout_ms = 4000;
      EinkPanel hink_panel;
      passed = hink_panel.begin(hink_bus, hink_config) && !hink_panel.partial_supported() && passed;
      passed = hink_fake.temperature[0] == 0x19 && hink_fake.temperature[1] == 0 &&
          count_command(hink_fake, 0x18) == 0 && count_command(hink_fake, 0x21) == 0 && passed;
      hink_fake = {};
      passed = hink_panel.full_refresh(frame, sizeof(frame)) == EinkRefreshResult::Ok && passed;
      passed = hink_fake.ram_bytes == sizeof(frame) && hink_fake.first_ram == 0x5a &&
          count_command(hink_fake, 0x26) == 0 && count_command(hink_fake, 0x32) == 0 &&
          hink_fake.update_control == 0xdf && passed;
      hink_fake = {};
      passed = hink_panel.partial_refresh(frame, sizeof(frame), {0, 0, 8, 8}) ==
          EinkRefreshResult::PartialUnsupported && hink_fake.command_count == 0 && passed;
      passed = hink_panel.sleep() == EinkRefreshResult::Ok && hink_panel.wake() && passed;
      // BUSY left over from an earlier operation must not acknowledge an
      // activation that the panel ignores.
      hink_fake.busy_polls = 3;
      hink_fake.ignore_activation = true;
      passed = hink_panel.full_refresh(frame, sizeof(frame)) == EinkRefreshResult::BusyNotAsserted &&
          !hink_panel.stats().initialised && hink_panel.stats().full_refreshes == 1 && passed;
      hink_fake = {};
      passed = hink_panel.begin(hink_bus, hink_config) && passed;
      hink_fake = {};
      hink_fake.busy_polls = 10000;
      passed = hink_panel.full_refresh(frame, sizeof(frame)) == EinkRefreshResult::BusyTimeout &&
          hink_fake.command_count == 0 && hink_fake.ram_bytes == 0 && passed;
      hink_fake = {};
      passed = hink_panel.begin(hink_bus, hink_config) &&
          hink_panel.sleep() == EinkRefreshResult::Ok && passed;
      hink_fake = {};
      hink_fake.fail_reset = true;
      passed = !hink_panel.wake() && !hink_panel.stats().initialised &&
          hink_panel.last_error() == EinkRefreshResult::ResetFault && hink_fake.command_count == 0 && passed;
      passed = !hink_panel.begin(hink_bus, hink_config) &&
          hink_panel.last_error() == EinkRefreshResult::ResetFault && hink_fake.command_count == 0 && passed;
      hink_config.partial_lut = lut;
      hink_config.partial_lut_size = sizeof(lut);
      hink_config.partial_timeout_ms = 4000;
      hink_config.partial_budget = 1;
      passed = !hink_panel.begin(hink_bus, hink_config) &&
          hink_panel.last_error() == EinkRefreshResult::InvalidConfig && passed;

      // E029A01's 30-byte host LUT and alternating RAM banks. The first
      // request, the exhausted budget and waking must all reseed both banks.
      hink_fake = {};
      hink_config.partial_lut_size = 30;
      const EinkRect strip = {16, 260, 8, 2};
      passed = hink_panel.begin(hink_bus, hink_config) && hink_panel.partial_supported() && passed;
      for (unsigned cycle = 0; cycle < 2; ++cycle)
      {
        hink_fake = {};
        passed = hink_panel.partial_refresh(frame, sizeof(frame), strip) == EinkRefreshResult::Ok &&
            hink_fake.update_control == 0xdf && hink_fake.ram_bytes == 2 * sizeof(frame) &&
            hink_fake.lut_bytes == 0 && count_command(hink_fake, 0x24) == 2 && passed;
        hink_fake = {};
        passed = hink_panel.partial_refresh(frame, sizeof(frame), strip) == EinkRefreshResult::Ok &&
            hink_fake.update_control == 0xc7 && hink_fake.lut_bytes == 30 &&
            hink_fake.window_x[0] == 2 && hink_fake.window_x[1] == 2 &&
            hink_fake.window_y[0] == 4 && hink_fake.window_y[1] == 1 &&
            hink_fake.window_y[2] == 5 && hink_fake.window_y[3] == 1 &&
            hink_fake.ram_bytes == 4 && count_command(hink_fake, 0x24) == 2 &&
            count_command(hink_fake, 0x20) == 1 && count_command(hink_fake, 0x26) == 0 &&
            count_command(hink_fake, 0x3f) == 0 && hink_panel.full_refresh_due() && passed;
      }
      passed = hink_panel.sleep() == EinkRefreshResult::Ok && hink_panel.wake() && passed;
      hink_fake = {};
      passed = hink_panel.partial_refresh(frame, sizeof(frame), strip) == EinkRefreshResult::Ok &&
          hink_fake.update_control == 0xdf && hink_fake.ram_bytes == 2 * sizeof(frame) && passed;
      hink_fake = {};
      hink_fake.ignore_activation = true;
      passed = hink_panel.partial_refresh(frame, sizeof(frame), strip) == EinkRefreshResult::BusyNotAsserted &&
          count_command(hink_fake, 0x24) == 1 && !hink_panel.stats().initialised && passed;
    }

    // --- 4-color panel: 2bpp, full refresh only --------------------------
    {
      static uint8_t color_frame[eink_frame_bytes(kEink29Width, kEink29Height,
                                                  EinkColorMode::FourColor)];
      // 0b00 0b01 0b10 0b11 = black, white, red, yellow in the converter's
      // palette order.
      color_frame[0] = 0x1B;
      memset(color_frame + 1, 0x55, sizeof(color_frame) - 1); // all white
      EinkPanelConfig color_config = {};
      color_config.width = kEink29Width;
      color_config.height = kEink29Height;
      color_config.color = EinkColorMode::FourColor;
      color_config.controller = EinkController::Ssd1683;
      color_config.full_timeout_ms = 4000;
      color_config.partial_timeout_ms = 1500;
      color_config.partial_budget = 8;
      // A four-color panel is defined by its module's own register table; the
      // driver refuses to guess analogue settings.
      static const EinkInitCommand kColorInit[] = {{0x18, 1, {0x80}},
                                                   {0x21, 1, {0x00}}};
      color_config.color_init = kColorInit;
      color_config.color_init_count = sizeof(kColorInit) / sizeof(kColorInit[0]);
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
                           fake_delay, fake_data};
      passed = color_panel.begin(color_bus, color_config) && passed;
      passed = color_panel.color_mode() == EinkColorMode::FourColor && passed;
      passed = !color_panel.partial_supported() && passed;
      passed = color_panel.frame_bytes() == sizeof(color_frame) && passed;
      // The X window is expressed in 4-pixel bytes now.
      passed = count_command(color_fake, 0x44) == 0 && passed;

      color_fake = FakeBus{};
      passed = color_panel.full_refresh(color_frame, sizeof(color_frame)) ==
                   EinkRefreshResult::Ok &&
               passed;
      passed = color_fake.ram_bytes == sizeof(color_frame) && passed;
      // black->00, white->01, red->11, yellow->10 gives 0b00 01 11 10 = 0x1E.
      passed = color_fake.have_ram && color_fake.first_ram == 0x1E && passed;
      passed = count_command(color_fake, 0x12) == 1 && count_command(color_fake, 0x24) == 0 && passed;
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
