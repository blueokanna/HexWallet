#pragma once
#include "Mascot.h"

namespace hexwallet {
constexpr size_t kMaidSpriteWidth = 64;
constexpr size_t kMaidSpriteHeight = 64;
constexpr size_t kMaidSpriteRowBytes = kMaidSpriteWidth / 8;
const uint8_t *maid_sprite_pixels(MascotMood mood, uint8_t frame);
bool maid_sprite_render(MascotMood mood, uint8_t frame, uint8_t *pixels,
                        size_t capacity, size_t stride = kMaidSpriteRowBytes);
bool run_maid_sprite_self_tests();
}
