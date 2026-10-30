#ifndef HEXWALLET_COIN_ICONS_H
#define HEXWALLET_COIN_ICONS_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Coin artwork for the trusted review header. The panel on this board is
// monochrome, so the data is packed at build time (tools/pack_coin_icons.ps1)
// as a 32x32 I1 bitmap: 4 bytes per row, MSB first, 128 bytes per icon. A set
// bit means ink and is painted with the theme foreground, which keeps the same
// mask readable whatever the paper colour is.
//
// The table deliberately has no LVGL types: the lookup and its guarantees are
// testable on the host, and only WalletUi.cpp knows about canvases.
constexpr uint16_t kCoinIconSize = 32;
constexpr uint16_t kCoinIconStride = kCoinIconSize / 8;
constexpr uint32_t kCoinIconBytes = kCoinIconStride * kCoinIconSize;

struct CoinIcon {
  // Uppercase ticker or the exact trusted-display name ("ZCASH", "SOLANA").
  const char *key;
  const uint8_t *pixels;
  uint32_t size;
};

size_t coin_icon_count();
const CoinIcon *coin_icon_at(size_t index);

// Exact, case-sensitive lookup. Unknown keys return nullptr: a wrong logo on
// the approval screen is worse than no logo, so there is no fuzzy matching and
// no "closest" fallback.
const CoinIcon *coin_icon_find(const char *key);

// Host-safe: table shape, key uniqueness, per-icon ink coverage, and that no
// two icons were packed from the same source by mistake.
bool run_coin_icon_self_tests();

} // namespace hexwallet

#endif