#ifndef HEXWALLET_CATALOG_H
#define HEXWALLET_CATALOG_H

#include <stddef.h>
#include <stdint.h>

#include "WalletNetworks.h"

namespace hexwallet {

enum WalletCapability : uint8_t {
  WalletCapabilityNone = 0,
  WalletCapabilityAddress = 1 << 0,
  WalletCapabilityTransactionReview = 1 << 1,
  WalletCapabilitySigning = 1 << 2,
};

struct WalletCatalogEntry {
  const char *id;
  const char *symbol;
  const char *name;
  uint32_t slip44_coin_type;
  uint8_t capabilities;
  const NetworkProfile *network;
  const char *status;
};

size_t wallet_catalog_count();
bool wallet_catalog_at(size_t index, WalletCatalogEntry *out);
bool wallet_catalog_find(const char *id_or_symbol, WalletCatalogEntry *out);
bool wallet_catalog_matches(const WalletCatalogEntry &entry, const char *query);
bool wallet_catalog_has(const WalletCatalogEntry &entry, WalletCapability capability);

}

#endif
