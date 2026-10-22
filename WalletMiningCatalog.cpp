#include "WalletMiningCatalog.h"

#include <ctype.h>
#include <string.h>

namespace hexwallet {
namespace {

const MiningCoinEntry kMiningCoins[] = {
#include "src/generated/WalletMiningCatalog.inc"
};

bool equals_ignore_case(const char *left, const char *right) {
  if (left == nullptr || right == nullptr) return false;
  while (*left != '\0' && *right != '\0') {
    if (tolower(static_cast<unsigned char>(*left)) !=
        tolower(static_cast<unsigned char>(*right))) {
      return false;
    }
    ++left;
    ++right;
  }
  return *left == *right;
}

}  // namespace

const char *mining_coin_type_name(MiningCoinType type) {
  switch (type) {
    case MiningCoinType::Asic: return "ASIC";
    case MiningCoinType::Gpu: return "GPU";
    case MiningCoinType::Cpu: return "CPU";
    case MiningCoinType::Hdd: return "HDD";
  }
  return "?";
}

size_t mining_coin_count() {
  return sizeof(kMiningCoins) / sizeof(kMiningCoins[0]);
}

bool mining_coin_at(size_t index, MiningCoinEntry *out) {
  if (out == nullptr || index >= mining_coin_count()) return false;
  *out = kMiningCoins[index];
  return true;
}

const MiningCoinEntry *mining_coin_find(const char *symbol_or_name) {
  if (symbol_or_name == nullptr || *symbol_or_name == '\0') return nullptr;
  for (const MiningCoinEntry &coin : kMiningCoins) {
    if (equals_ignore_case(coin.symbol, symbol_or_name) ||
        equals_ignore_case(coin.name, symbol_or_name)) {
      return &coin;
    }
  }
  return nullptr;
}

bool mining_coin_lookup(const MiningCoinEntry &coin, WalletCatalogEntry *out) {
  if (out == nullptr || coin.catalog_id == nullptr) return false;
  for (size_t index = 0; index < wallet_catalog_count(); ++index) {
    WalletCatalogEntry entry;
    if (!wallet_catalog_at(index, &entry)) continue;
    if (strcmp(entry.id, coin.catalog_id) == 0) {
      *out = entry;
      return true;
    }
  }
  return false;
}

bool run_mining_catalog_self_tests() {
  if (mining_coin_count() == 0) return false;
  for (const MiningCoinEntry &coin : kMiningCoins) {
    if (coin.symbol == nullptr || coin.name == nullptr ||
        coin.algorithm == nullptr || coin.catalog_id == nullptr ||
        *coin.symbol == '\0' || *coin.name == '\0' ||
        *coin.algorithm == '\0' || *coin.catalog_id == '\0') {
      return false;
    }
    if (static_cast<uint8_t>(coin.type) > static_cast<uint8_t>(MiningCoinType::Hdd)) {
      return false;
    }
    WalletCatalogEntry entry;
    if (!mining_coin_lookup(coin, &entry) ||
        !wallet_catalog_has(entry, WalletCapabilitySigning)) {
      return false;
    }
  }
  const MiningCoinEntry *btc = mining_coin_find("BTC");
  WalletCatalogEntry entry;
  if (btc == nullptr || !mining_coin_lookup(*btc, &entry) ||
      !wallet_catalog_has(entry, WalletCapabilitySigning)) {
    return false;
  }
  return mining_coin_find("XMR") == nullptr;
}

}  // namespace hexwallet
