#include "MaidSprite.h"
#include <string.h>
#ifdef ARDUINO_ARCH_ESP32
#include <sdkconfig.h>
#if CONFIG_IDF_TARGET_ESP32P4
extern "C" void hexwallet_p4_copy_sprite(uint8_t *destination, const uint8_t *source);
#endif
#endif

namespace hexwallet
{
  namespace
  {
#include "src/generated/MaidSprite.inc"

    void dot(uint8_t *pixels, size_t stride, int x, int y)
    {
      if (x < 0 || x >= static_cast<int>(kMaidSpriteWidth) ||
          y < 0 || y >= static_cast<int>(kMaidSpriteHeight))
        return;
      pixels[static_cast<size_t>(y) * stride + static_cast<size_t>(x) / 8] |=
          static_cast<uint8_t>(0x80U >> (x & 7));
    }

    void sparkle(uint8_t *pixels, size_t stride, int x, int y, uint8_t size)
    {
      for (int step = -size; step <= size; ++step)
      {
        dot(pixels, stride, x + step, y);
        dot(pixels, stride, x, y + step);
      }
    }
  }

  const uint8_t *maid_sprite_pixels(MascotMood mood, uint8_t frame)
  {
    uint8_t index = 0;
    switch (mood)
    {
    case MascotMood::Calm:
      index = frame % kMascotAnimationFrames == 3 ? 1 : 0;
      break;
    case MascotMood::Happy:
    case MascotMood::Bubbles:
      index = 2;
      break;
    case MascotMood::Alert:
    case MascotMood::Angry:
    case MascotMood::Working:
      index = 3;
      break;
    case MascotMood::Sleep:
      index = 4;
      break;
    case MascotMood::Eating:
      index = 5;
      break;
    case MascotMood::Shy:
      index = 6;
      break;
    case MascotMood::Excited:
      index = 7;
      break;
    }
    return kMaidFrames[index];
  }

  bool maid_sprite_render(MascotMood mood, uint8_t frame, uint8_t *pixels,
                          size_t capacity, size_t stride)
  {
    if (pixels == nullptr || static_cast<uint8_t>(mood) >= kMascotMoodCount ||
        stride < kMaidSpriteRowBytes || stride > capacity / kMaidSpriteHeight)
      return false;
    frame %= kMascotAnimationFrames;
    const uint8_t *source = maid_sprite_pixels(mood, frame);
    const int lift = (mood == MascotMood::Excited && (frame & 1U)) ? 1 : 0;
    const size_t rows = kMaidSpriteHeight - lift;
    source += lift * kMaidSpriteRowBytes;
    if (stride == kMaidSpriteRowBytes) {
#if defined(ARDUINO_ARCH_ESP32) && CONFIG_IDF_TARGET_ESP32P4
      static_assert(kMaidSpriteRowBytes * kMaidSpriteHeight == 512);
      if (!lift && ((reinterpret_cast<uintptr_t>(pixels) | reinterpret_cast<uintptr_t>(source)) & 15) == 0)
        hexwallet_p4_copy_sprite(pixels, source);
      else
#endif
      memcpy(pixels, source, rows * stride);
    } else {
      for (size_t y = 0; y < rows; ++y) {
        memcpy(pixels + y * stride, source + y * kMaidSpriteRowBytes, kMaidSpriteRowBytes);
        memset(pixels + y * stride + kMaidSpriteRowBytes, 0, stride - kMaidSpriteRowBytes);
      }
    }
    if (lift) memset(pixels + rows * stride, 0, stride);
    switch (mood)
    {
    case MascotMood::Calm:
      break;
    case MascotMood::Happy:
    case MascotMood::Excited:
      sparkle(pixels, stride, 6, 13 - frame, 1 + (frame & 1U));
      sparkle(pixels, stride, 57, 8 + frame, 1 + ((frame + 1U) & 1U));
      break;
    case MascotMood::Bubbles:
      for (unsigned i = 0; i < 3; ++i) {
        const int phase = (frame + i) % kMascotAnimationFrames;
        const int x = 48 + 4 * phase, y = 29 - 6 * phase;
        dot(pixels, stride, x, y - 1);
        dot(pixels, stride, x, y + 1);
        dot(pixels, stride, x - 1, y);
        dot(pixels, stride, x + 1, y);
      }
      break;
    case MascotMood::Alert:
      for (int y = 6; y < 11 + static_cast<int>(frame & 1U); ++y)
        dot(pixels, stride, 56, y);
      dot(pixels, stride, 56, 14);
      break;
    case MascotMood::Angry:
      for (int step = 0; step < 2 + static_cast<int>(frame & 1U); ++step)
      {
        dot(pixels, stride, 55 - step, 8);
        dot(pixels, stride, 55, 8 - step);
        dot(pixels, stride, 58 + step, 11);
        dot(pixels, stride, 58, 11 + step);
      }
      break;
    case MascotMood::Eating:
      for (int y = 0; y < 5; ++y)
      {
        dot(pixels, stride, 5 + static_cast<int>((y + frame) & 1U),
            31 - frame * 2 + y);
        dot(pixels, stride, 57 + static_cast<int>((y + frame + 1) & 1U),
            28 - frame * 2 + y);
      }
      break;
    case MascotMood::Sleep:
    {
      const int x = 52, y = 7 - frame;
      for (int step = 0; step < 5; ++step)
      {
        dot(pixels, stride, x + step, y);
        dot(pixels, stride, x + 4 - step, y + step);
        dot(pixels, stride, x + step, y + 4);
      }
      break;
    }
    case MascotMood::Shy:
      if (frame & 1U)
        sparkle(pixels, stride, 7, 17, 1);
      else
        sparkle(pixels, stride, 56, 14, 1);
      break;
    case MascotMood::Working:
      break;
    }
    return true;
  }

  bool run_maid_sprite_self_tests()
  {
    alignas(16) uint8_t aligned[512];
    if (!maid_sprite_render(MascotMood::Calm, 0, aligned, sizeof(aligned), 8) ||
        memcmp(aligned, maid_sprite_pixels(MascotMood::Calm, 0), sizeof(aligned))) return false;
    uint8_t first[64 * 9 + 2], second[64 * 9 + 2];
    bool passed = true;
    for (uint8_t mood = 0; mood < kMascotMoodCount; ++mood)
    {
      memset(first, 0xA5, sizeof(first));
      memset(second, 0xA5, sizeof(second));
      const MascotMood value = static_cast<MascotMood>(mood);
      passed = maid_sprite_render(value, 0, first + 1, sizeof(first) - 2, 9) && passed;
      const uint8_t other_frame = value == MascotMood::Calm ? 3 : 1;
      passed = maid_sprite_render(value, other_frame, second + 1, sizeof(second) - 2, 9) && passed;
      passed = first[0] == 0xA5 && first[sizeof(first) - 1] == 0xA5 &&
               second[0] == 0xA5 && second[sizeof(second) - 1] == 0xA5 && passed;
      for (size_t row = 0; row < kMaidSpriteHeight; ++row)
        passed = first[1 + row * 9 + 8] == 0 && passed;
      const bool changed = memcmp(first, second, sizeof(first)) != 0;
      passed = (changed == (value != MascotMood::Working)) && passed;
    }
    memset(first, 0xA5, sizeof(first));
    passed = !maid_sprite_render(MascotMood::Calm, 0, first, sizeof(first), SIZE_MAX) && passed;
    passed = !maid_sprite_render(MascotMood::Calm, 0, first, 511) && passed;
    passed = !maid_sprite_render(static_cast<MascotMood>(kMascotMoodCount), 0, first, sizeof(first)) && passed;
    passed = !maid_sprite_render(MascotMood::Calm, 0, nullptr, sizeof(first)) && passed;
    for (size_t index = 0; index < sizeof(first); ++index)
      passed = first[index] == 0xA5 && passed;
    return passed;
  }
}
