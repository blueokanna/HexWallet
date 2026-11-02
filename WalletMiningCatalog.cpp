#include "WalletMiningCatalog.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

namespace hexwallet
{
  namespace
  {

    const MiningCoinEntry kMiningCoins[] = {
#include "src/generated/WalletMiningCatalog.inc"
    };

    bool equals_ignore_case(const char *left, const char *right)
    {
      if (left == nullptr || right == nullptr)
        return false;
      while (*left != '\0' && *right != '\0')
      {
        if (tolower(static_cast<unsigned char>(*left)) !=
            tolower(static_cast<unsigned char>(*right)))
        {
          return false;
        }
        ++left;
        ++right;
      }
      return *left == *right;
    }

  } // namespace

  const char *mining_coin_type_name(MiningCoinType type)
  {
    switch (type)
    {
    case MiningCoinType::Asic:
      return "ASIC";
    case MiningCoinType::Gpu:
      return "GPU";
    case MiningCoinType::Cpu:
      return "CPU";
    case MiningCoinType::Hdd:
      return "HDD";
    }
    return "?";
  }

  size_t mining_coin_count()
  {
    return sizeof(kMiningCoins) / sizeof(kMiningCoins[0]);
  }

  bool mining_coin_at(size_t index, MiningCoinEntry *out)
  {
    if (out == nullptr || index >= mining_coin_count())
      return false;
    *out = kMiningCoins[index];
    return true;
  }

  const MiningCoinEntry *mining_coin_find(const char *symbol_or_name)
  {
    if (symbol_or_name == nullptr || *symbol_or_name == '\0')
      return nullptr;
    for (const MiningCoinEntry &coin : kMiningCoins)
    {
      if (equals_ignore_case(coin.symbol, symbol_or_name) ||
          equals_ignore_case(coin.name, symbol_or_name))
      {
        return &coin;
      }
    }
    return nullptr;
  }

  bool mining_coin_lookup(const MiningCoinEntry &coin, WalletCatalogEntry *out)
  {
    if (out == nullptr || coin.catalog_id == nullptr)
      return false;
    for (size_t index = 0; index < wallet_catalog_count(); ++index)
    {
      WalletCatalogEntry entry;
      if (!wallet_catalog_at(index, &entry))
        continue;
      if (strcmp(entry.id, coin.catalog_id) == 0)
      {
        *out = entry;
        return true;
      }
    }
    return false;
  }

  bool run_mining_catalog_self_tests()
  {
    if (mining_coin_count() == 0)
      return false;
    for (const MiningCoinEntry &coin : kMiningCoins)
    {
      if (coin.symbol == nullptr || coin.name == nullptr ||
          coin.algorithm == nullptr || coin.catalog_id == nullptr ||
          coin.source_id == nullptr || *coin.symbol == '\0' || *coin.name == '\0' ||
          *coin.algorithm == '\0' || *coin.catalog_id == '\0' ||
          *coin.source_id == '\0')
      {
        return false;
      }
      // A coin may appear once per mining algorithm, and a merged-mining row is
      // a real listing rather than a placeholder, so the type bound is Merged.
      if (static_cast<uint8_t>(coin.type) > static_cast<uint8_t>(MiningCoinType::Merged))
      {
        return false;
      }
      // Every row must resolve to a catalog coin of the same symbol. That is
      // also what rules out an orphan listing for a chain the catalog withdrew:
      // without this join the mining screen would offer something the wallet
      // cannot address.
      WalletCatalogEntry entry;
      if (!mining_coin_lookup(coin, &entry) || strcmp(coin.symbol, entry.symbol) != 0)
        return false;
      // source_id is the pool-listing key, so a duplicate would make one of the
      // two rows unreachable. Symbols repeat by design; this must not.
      for (const MiningCoinEntry &other : kMiningCoins)
      {
        if (&other != &coin && strcmp(other.source_id, coin.source_id) == 0)
          return false;
      }
    }
    const MiningCoinEntry *btc = mining_coin_find("BTC");
    WalletCatalogEntry entry;
    if (btc == nullptr || !mining_coin_lookup(*btc, &entry) ||
        !wallet_catalog_has(entry, WalletCapabilitySigning))
    {
      return false;
    }
    // The name lookup has to keep working for the two coins whose catalog id
    // does not match their symbol.
    const MiningCoinEntry *xmr = mining_coin_find("monero");
    const MiningCoinEntry *chia = mining_coin_find("chia");
    return xmr != nullptr && strcmp(xmr->catalog_id, "xmr") == 0 &&
           chia != nullptr && strcmp(chia->catalog_id, "xch") == 0;
  }


}
