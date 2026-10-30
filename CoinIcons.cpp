#include "CoinIcons.h"

#include <string.h>

namespace hexwallet
{

  namespace
  {

#include "src/generated/CoinIcons.inc"

    constexpr size_t kCoinIconTableCount =
        sizeof(kCoinIconTable) / sizeof(kCoinIconTable[0]);

    size_t ink_pixels(const CoinIcon &icon)
    {
      size_t ink = 0;
      for (uint32_t byte = 0; byte < icon.size; ++byte)
      {
        uint8_t value = icon.pixels[byte];
        for (uint8_t bit = 0; bit < 8; ++bit)
        {
          if ((value & (0x80U >> bit)) != 0)
            ++ink;
        }
      }
      return ink;
    }

  } // namespace

  size_t coin_icon_count() { return kCoinIconTableCount; }

  const CoinIcon *coin_icon_at(size_t index)
  {
    return index < kCoinIconTableCount ? &kCoinIconTable[index] : nullptr;
  }

  const CoinIcon *coin_icon_find(const char *key)
  {
    if (key == nullptr || key[0] == '\0')
      return nullptr;
    for (size_t index = 0; index < kCoinIconTableCount; ++index)
    {
      if (strcmp(kCoinIconTable[index].key, key) == 0)
        return &kCoinIconTable[index];
    }
    return nullptr;
  }

  bool run_coin_icon_self_tests()
  {
    if (kCoinIconTableCount == 0)
      return false;
    constexpr size_t kPixels = kCoinIconSize * kCoinIconSize;
    for (size_t index = 0; index < kCoinIconTableCount; ++index)
    {
      const CoinIcon &icon = kCoinIconTable[index];
      if (icon.key == nullptr || icon.key[0] == '\0' ||
          icon.pixels == nullptr || icon.size != kCoinIconBytes)
      {
        return false;
      }
      // Keys must be unique, otherwise a lookup depends on table order rather
      // than on the manifest.
      for (size_t other = index + 1; other < kCoinIconTableCount; ++other)
      {
        if (strcmp(icon.key, kCoinIconTable[other].key) == 0)
          return false;
      }
      const size_t ink = ink_pixels(icon);
      // Blank and fully filled masks are what a mis-mapped or empty source file
      // looks like after packing; either one means the packer lied.
      if (ink * 10 < kPixels || ink * 10 > kPixels * 9)
        return false;
      // Two different icons sharing one blob means a manifest or packer bug,
      // and the review would show the wrong logo with full confidence.
      for (size_t other = 0; other < kCoinIconTableCount; ++other)
      {
        const CoinIcon &candidate = kCoinIconTable[other];
        if (candidate.pixels == icon.pixels)
          continue;
        if (candidate.size == icon.size &&
            memcmp(candidate.pixels, icon.pixels, icon.size) == 0)
        {
          return false;
        }
      }
    }
    // Contract the display relies on.
    const CoinIcon *dash = coin_icon_find("DASH");
    if (dash == nullptr || dash->size != kCoinIconBytes)
      return false;
    // Case sensitivity, and chains we ship no artwork for, must stay honest.
    return coin_icon_find("dash") == nullptr && coin_icon_find("EVM") == nullptr &&
           coin_icon_find("NEAR") == nullptr && coin_icon_find("") == nullptr &&
           coin_icon_find(nullptr) == nullptr;
  }

} // namespace hexwallet