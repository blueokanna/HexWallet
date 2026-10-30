#pragma once
#include "Mascot.h"

namespace hexwallet {
constexpr size_t kMaidSpriteWidth = 64;
constexpr size_t kMaidSpriteHeight = 64;
constexpr size_t kMaidSpriteRowBytes = kMaidSpriteWidth / 8;
// Packed MSB-first pixels, 8 bytes per row. Lifetime: entire firmware session.
const uint8_t *maid_sprite_pixels(MascotMood mood, uint8_t frame);
// Compose the original pose and code-drawn accents into a caller-owned 1bpp
// surface. No palette bytes, allocation, LVGL dependency or global scratch.
// Invalid arguments leave the output untouched. Padding bytes are cleared.
bool maid_sprite_render(MascotMood mood, uint8_t frame, uint8_t *pixels,
                        size_t capacity, size_t stride = kMaidSpriteRowBytes);
bool run_maid_sprite_self_tests();
}
