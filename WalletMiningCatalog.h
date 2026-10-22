#ifndef HEXWALLET_MINING_CATALOG_H
#define HEXWALLET_MINING_CATALOG_H

#include <stddef.h>
#include <stdint.h>

#include "WalletCatalog.h"

namespace hexwallet {

enum class MiningCoinType : uint8_t { Asic, Gpu, Cpu, Hdd };

struct MiningCoinEntry {
  const char *symbol;
  const char *name;
  const char *algorithm;
  MiningCoinType type;
  const char *catalog_id;
};

const char *mining_coin_type_name(MiningCoinType type);
size_t mining_coin_count();
bool mining_coin_at(size_t index, MiningCoinEntry *out);
const MiningCoinEntry *mining_coin_find(const char *symbol_or_name);
bool mining_coin_lookup(const MiningCoinEntry &coin, WalletCatalogEntry *out);
bool run_mining_catalog_self_tests();

}

#endif
