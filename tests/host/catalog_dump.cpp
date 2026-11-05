#include <stdio.h>
#include <string.h>

#include "../../WalletCatalog.h"
#include "../../WalletMiningCatalog.h"
#include "../../WalletTokens.h"
#include "../../WalletCustomTokens.h"

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
    const bool catalog = hexwallet::run_catalog_self_tests();
    const bool mining = hexwallet::run_mining_catalog_self_tests();
    const bool tokens = hexwallet::run_token_profile_self_tests();
    const bool custom = hexwallet::run_custom_token_self_tests();
    printf("catalog=%s mining=%s tokens=%s custom-tokens=%s\n",
           catalog ? "pass" : "FAIL", mining ? "pass" : "FAIL",
           tokens ? "pass" : "FAIL", custom ? "pass" : "FAIL");
    printf("catalog-entries=%zu token-deployments=%zu custom-token-capacity=%zu\n",
           hexwallet::wallet_catalog_count(), hexwallet::kTokenProfileCount, hexwallet::kCustomTokenMax);
    return catalog && mining && tokens && custom ? 0 : 1;
  }
  const bool detailed = argc == 2 && strcmp(argv[1], "--native") == 0;
  if (argc > 1 && !detailed) return 2;
  for (size_t index = 0; index < hexwallet::wallet_catalog_count(); ++index) {
    hexwallet::WalletCatalogEntry entry;
    if (!hexwallet::wallet_catalog_at_sorted(index, &entry)) continue;
    unsigned caps = 0;
    if (hexwallet::wallet_catalog_has(entry, hexwallet::WalletCapabilityAddress)) caps |= 1;
    if (hexwallet::wallet_catalog_has(entry, hexwallet::WalletCapabilityTransactionReview)) caps |= 2;
    if (hexwallet::wallet_catalog_has(entry, hexwallet::WalletCapabilitySigning)) caps |= 4;
    if (hexwallet::wallet_catalog_has(entry, hexwallet::WalletCapabilityTokenAccount)) caps |= 8;
    printf("%s|%s|%s|%u|%s", entry.id, entry.symbol, entry.name, caps,
           entry.network == nullptr ? "" : entry.network->id);
    if (detailed) {
      const auto *network = entry.network;
      if (network == nullptr) return 1;
      using hexwallet::AddressEncoding;
      // Different derivation/address forms do not create another blockchain.
      // Match the consensus address domain and key domain, never ticker alone.
      const bool bitcoin_address = network->encoding == AddressEncoding::P2pkh ||
          network->encoding == AddressEncoding::P2wpkh || network->encoding == AddressEncoding::P2shP2wpkh;
      if (network->encoding == AddressEncoding::Evm)
        printf("|evm:%lu", static_cast<unsigned long>(network->evm_chain_id));
      else if (bitcoin_address)
        printf("|utxo:%lu:%u:%u", static_cast<unsigned long>(network->derivation_coin_type),
               network->utxo.p2pkh_version, network->utxo.p2sh_version);
      else printf("|native:%s", network->id);
      printf("|%s", entry.status);
    }
    puts("");
  }
  return 0;
}
