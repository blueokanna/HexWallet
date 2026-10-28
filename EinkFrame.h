#ifndef HEXWALLET_EINK_FRAME_H
#define HEXWALLET_EINK_FRAME_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Packed palette frames, with each row padded to a complete byte.
//   depth 1: 1bpp, bit 1 = black, MSB first
//   depth 3/4: 2bpp, 0=black, 1=white, 2=red, 3=yellow, 4 pixels/byte
// The panel backend must translate these indices to its own RAM format.
// They are NOT a universal wire format for 3-/4-colour controllers.
// In depth 3 yellow maps to white; in depth 1 all colours use luminance.
size_t eink_frame_size(uint16_t width, uint16_t height, uint8_t depth);

// rgb565 points at width*height native RGB565 pixels. When swapped is true,
// the two bytes of each pixel are exchanged first (LVGL LV_COLOR_16_SWAP).
bool eink_convert_rgb565(const uint8_t *rgb565, uint16_t width, uint16_t height,
                         uint8_t depth, bool swapped, uint8_t *out,
                         size_t capacity);

bool run_eink_frame_self_tests();

}  // namespace hexwallet

#endif
