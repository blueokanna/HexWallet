#include "EinkFrame.h"

#include <string.h>

#include "WalletSecurity.h"

namespace hexwallet {
namespace {

struct Rgb {
  uint8_t r;
  uint8_t g;
  uint8_t b;
};

Rgb unpack(uint16_t value) {
  return {static_cast<uint8_t>(((value >> 11) & 0x1f) * 255 / 31),
          static_cast<uint8_t>(((value >> 5) & 0x3f) * 255 / 63),
          static_cast<uint8_t>((value & 0x1f) * 255 / 31)};
}

uint8_t palette_index(const Rgb &c, uint8_t depth) {
  // Chromatic classification must precede the luminance test: pure red has a
  // luminance of only 76 and would otherwise be flattened to black.
  if (c.r > 90 && c.r > c.g + 50 && c.r > c.b + 50) return 2;  // red
  if (depth >= 4 && c.r > 110 && c.g > 85 && c.b < 95 &&
      static_cast<int>(c.r) - static_cast<int>(c.g) < 90) {
    return 3;  // yellow
  }
  const uint32_t luminance = (static_cast<uint32_t>(c.r) * 299U +
                              static_cast<uint32_t>(c.g) * 587U +
                              static_cast<uint32_t>(c.b) * 114U) / 1000U;
  if (luminance < 96U) return 0;  // black
  return 1;  // white
}

}  // namespace

size_t eink_frame_size(uint16_t width, uint16_t height, uint8_t depth) {
  if (width == 0 || height == 0) return 0;
  if (depth == 1) return ((static_cast<size_t>(width) + 7U) / 8U) * height;
  if (depth == 3 || depth == 4) return ((static_cast<size_t>(width) + 3U) / 4U) * height;
  return 0;
}

bool eink_convert_rgb565(const uint8_t *rgb565, uint16_t width, uint16_t height,
                         uint8_t depth, bool swapped, uint8_t *out,
                         size_t capacity) {
  if (rgb565 == nullptr || out == nullptr || width == 0 || height == 0 ||
      (depth != 1 && depth != 3 && depth != 4)) {
    return false;
  }
  const size_t needed = eink_frame_size(width, height, depth);
  if (needed == 0 || capacity < needed) return false;
  memset(out, 0, needed);
  const size_t count = static_cast<size_t>(width) * height;
  const size_t stride = eink_frame_size(width, 1, depth);
  for (size_t index = 0; index < count; ++index) {
    // Byte loads accept unaligned LVGL buffers without aliasing violations.
    const uint16_t raw = static_cast<uint16_t>(rgb565[index * 2]) |
                         (static_cast<uint16_t>(rgb565[index * 2 + 1]) << 8);
    const uint16_t value = swapped ? static_cast<uint16_t>((raw << 8) | (raw >> 8)) : raw;
    const Rgb rgb = unpack(value);
    const uint8_t colour = palette_index(rgb, depth);
    const size_t x = index % width;
    const size_t row = (index / width) * stride;
    if (depth == 1) {
      const uint32_t luminance = (299U * rgb.r + 587U * rgb.g + 114U * rgb.b) / 1000U;
      if (luminance < 128U) out[row + (x >> 3)] |= static_cast<uint8_t>(0x80U >> (x & 7U));
    } else {
      const size_t byte = row + (x >> 2);
      const uint8_t shift = static_cast<uint8_t>(6U - 2U * (x & 3U));
      out[byte] = static_cast<uint8_t>(out[byte] | (colour << shift));
    }
  }
  return true;
}

bool run_eink_frame_self_tests() {
  // Four pixels exercise every palette slot and the MSB-first packing order.
  const uint16_t pixels[4] = {0x0000, 0xFFFF, 0xF800, 0xFFE0};
  uint8_t out[2] = {};
  bool ok = eink_convert_rgb565(reinterpret_cast<const uint8_t *>(pixels), 4, 1,
                                4, false, out, sizeof(out)) &&
            out[0] == 0x1B && out[1] == 0x00;
  // 3-colour panels cannot show yellow; it must become white, not red/black.
  memset(out, 0, sizeof(out));
  ok = ok && eink_convert_rgb565(reinterpret_cast<const uint8_t *>(pixels), 4, 1,
                                 3, false, out, sizeof(out)) &&
       out[0] == 0x19;
  // 1bpp: black and dark red are black; light yellow and white are white.
  memset(out, 0, sizeof(out));
  ok = ok && eink_convert_rgb565(reinterpret_cast<const uint8_t *>(pixels), 4, 1,
                                 1, false, out, sizeof(out)) &&
       out[0] == 0xA0;
  // Swapped bytes must produce the same RGB565 colour.
  const uint16_t swapped_red = 0x00F8;
  memset(out, 0, sizeof(out));
  ok = ok && eink_convert_rgb565(reinterpret_cast<const uint8_t *>(&swapped_red),
                                 1, 1, 4, true, out, sizeof(out)) && out[0] == 0x80;
  // Capacity and invalid depth fail closed.
  ok = ok && !eink_convert_rgb565(reinterpret_cast<const uint8_t *>(pixels), 4,
                                  1, 4, false, out, 0) &&
       !eink_convert_rgb565(reinterpret_cast<const uint8_t *>(pixels), 4, 1, 2,
                            false, out, sizeof(out));
  // Odd row widths and unaligned input must neither merge rows nor load a
  // misaligned uint16_t. Row 0 = black/white/black; row 1 = white/black/white.
  const uint8_t unaligned[] = {0x55, 0,0, 255,255, 0,0, 255,255, 0,0, 255,255};
  uint8_t rows[3] = {0, 0, 0xA5};
  ok = ok && eink_frame_size(3, 2, 1) == 2 &&
       eink_convert_rgb565(unaligned + 1, 3, 2, 1, false, rows, 2) &&
       rows[0] == 0xA0 && rows[1] == 0x40 && rows[2] == 0xA5 &&
       eink_frame_size(3, 2, 4) == 2 &&
       eink_convert_rgb565(unaligned + 1, 3, 2, 4, false, rows, 2) &&
       rows[0] == 0x10 && rows[1] == 0x44 && rows[2] == 0xA5;
  return ok;
}

}  // namespace hexwallet
