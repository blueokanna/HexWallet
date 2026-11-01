#ifndef HEXWALLET_COIN_ICONS_H
#define HEXWALLET_COIN_ICONS_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{
  constexpr uint16_t kCoinIconSize = 32;
  constexpr uint16_t kCoinIconStride = kCoinIconSize / 8;
  constexpr uint32_t kCoinIconBytes = kCoinIconStride * kCoinIconSize;

  struct CoinIcon
  {
    const char *key;
    const uint8_t *pixels;
    uint32_t size;
  };

  size_t coin_icon_count();
  const CoinIcon *coin_icon_at(size_t index);
  const CoinIcon *coin_icon_find(const char *key);

  bool run_coin_icon_self_tests();

}

#endif