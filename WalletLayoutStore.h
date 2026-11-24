#pragma once
#include <stdint.h>

namespace hexwallet {
enum class AssetLayout : uint8_t { List = 0, Grid = 1, Card = 2 };
// Returns nullptr on success, otherwise a stable platform diagnostic.
const char *load_asset_layout(AssetLayout &layout);
const char *save_asset_layout(AssetLayout layout);
}
