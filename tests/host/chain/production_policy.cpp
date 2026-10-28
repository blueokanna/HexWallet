#include <stdio.h>
#include <string.h>
#include "ChainTransaction.h"
#include "Clvm.h"
#include "CryptoPrimitives.h"
#include "WalletCatalog.h"
#include "WalletCustody.h"
#include "WalletEngine.h"
#include "WalletSession.h"
#include "QrlXmss.h"

using namespace hexwallet;
static bool zero(const void *v, size_t n) {
  const auto *p = static_cast<const uint8_t *>(v);
  for (size_t i = 0; i < n; ++i) if (p[i]) return false;
  return true;
}
#define CHECK(condition) do { if (!(condition)) { \
  printf("FAIL line=%d: %s\n", __LINE__, #condition); return 1; } } while (0)
int main() {
  HdPrivateNode master{};
  uint8_t seed[kSeedSize]{};
  CHECK(!secure_custody_backend_ready());
  set_active_secure_element_profile(&se051c2hq1_profile());
  CHECK(&active_secure_element_profile() == &software_only_profile());
  CHECK(!wallet_session_custody_available());
  CHECK(wallet_session_generate() == WalletError::CustodyUnavailable);
  CHECK(wallet_session_import("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about") == WalletError::CustodyUnavailable);
  CHECK(!wallet_session_is_loaded());
  memset(seed, 0xa5, sizeof(seed));
  memset(&master, 0xa5, sizeof(master));
  CHECK(wallet_session_load_seed(seed) == WalletError::CustodyUnavailable);
  CHECK(wallet_session_load_master(&master) == WalletError::CustodyUnavailable);
  CHECK(zero(seed, sizeof(seed)) && zero(&master, sizeof(master)));
  CHECK(wallet_session_mnemonic_for_export() == nullptr);

  const char *blocked[] = {"dot", "ksm", "erg", "xch"};
  const ChainFamily families[] = {ChainFamily::Polkadot, ChainFamily::Kusama,
      ChainFamily::Ergo, ChainFamily::Chia};
  for (size_t i = 0; i < 4; ++i) {
    ChainFamily family = ChainFamily::None;
    CHECK(!chain_family_for_network(blocked[i], &family));
    WalletCatalogEntry entry{};
    CHECK(wallet_catalog_find(blocked[i], &entry));
    CHECK(!wallet_catalog_has(entry, WalletCapabilitySigning));
    ChainTransaction tx{};
    const uint8_t payload = 0;
    CHECK(chain_review_transaction(families[i], &payload, 1, master, seed, 0, &tx) == ChainError::Unsupported);
    tx.family = families[i]; tx.payload_size = 1;
    uint8_t out[65]; memset(out, 0xa5, sizeof(out)); size_t n = 64;
    CHECK(chain_sign_transaction(tx, master, seed, out, &n) == ChainError::Unsupported);
    CHECK(n == 0 && zero(out, 64) && out[64] == 0xa5);
  }
  WalletCatalogEntry hive{};
  CHECK(wallet_catalog_find("hive", &hive));
  CHECK(!wallet_catalog_has(hive, WalletCapabilityAddress));
  CHECK(wallet_catalog_has(hive, WalletCapabilitySigning));
  DerivedAddress address{};
  CHECK(derive_address(master, seed, *find_network_profile("xch"), 0, 0, 0, &address) != WalletError::Ok);
  CHECK(zero(&address, sizeof(address)));
  CHECK(derive_address(master, seed, *find_network_profile("qubic"), 0, 0, 0, &address) == WalletError::InvalidArgument);
  CHECK(zero(&address, sizeof(address)));
  CHECK(key_scheme_for(*find_network_profile("qubic")) == KeyScheme::Unsupported);
  CHECK(derive_address(master, seed, *find_network_profile("qrl"), 1, 0, 0, &address) == WalletError::InvalidArgument);
  CHECK(derive_address(master, seed, *find_network_profile("qrl"), 0, 1, 0, &address) == WalletError::InvalidArgument);
  CHECK(run_clvm_self_tests());
  CHECK(run_custody_self_tests());
  puts("production_policy=pass");
  return 0;
}
