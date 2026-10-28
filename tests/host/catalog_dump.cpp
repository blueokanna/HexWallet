#include <stdio.h>

#include "../../WalletCatalog.h"

int main() {
  for (size_t index = 0; index < hexwallet::wallet_catalog_count(); ++index) {
    hexwallet::WalletCatalogEntry entry;
    if (!hexwallet::wallet_catalog_at_sorted(index, &entry)) continue;
    unsigned caps = 0;
    if (hexwallet::wallet_catalog_has(entry, hexwallet::WalletCapabilityAddress)) caps |= 1;
    if (hexwallet::wallet_catalog_has(entry, hexwallet::WalletCapabilityTransactionReview)) caps |= 2;
    if (hexwallet::wallet_catalog_has(entry, hexwallet::WalletCapabilitySigning)) caps |= 4;
    if (hexwallet::wallet_catalog_has(entry, hexwallet::WalletCapabilityTokenAccount)) caps |= 8;
    printf("%s|%s|%s|%u|%s\n", entry.id, entry.symbol, entry.name, caps,
           entry.network == nullptr ? "" : entry.network->id);
  }
  return 0;
}
