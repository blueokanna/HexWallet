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
#include "SecureElementPort.h"

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

  // Regression: an authenticated transport must not unlock MCU seed custody.
  const SecureElementBackend transport = {
    "test-authenticated-channel", [](char *, size_t) { return true; },
    []() { return true; },
    [](uint32_t, const uint8_t *, uint8_t *, size_t *) { return false; },
    [](uint32_t, uint8_t *, size_t *) { return false; }, []() {}};
  CHECK(secure_element_register_backend(&transport));
  CHECK(secure_element_open(nullptr, 0) && secure_element_ready());
  CHECK(!secure_custody_backend_ready());
  CHECK(&active_secure_element_profile() == &software_only_profile());
  CHECK(wallet_session_generate() == WalletError::CustodyUnavailable);
  CHECK(wallet_session_import("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about") == WalletError::CustodyUnavailable);
  CHECK(secure_element_register_backend(nullptr));

  // Historical Substrate codecs are host-test only. Production has no
  // authenticated runtime metadata, so DOT/KSM must not be admitted at all.
  static const char *const kBlockedNetworks[] = {"dot", "ksm"};
  for (const char *blocked : kBlockedNetworks) {
    ChainFamily family = ChainFamily::None;
    CHECK(!chain_family_for_network(blocked, &family));
    WalletCatalogEntry entry{};
    CHECK(wallet_catalog_find(blocked, &entry));
    CHECK(!wallet_catalog_has(entry, WalletCapabilitySigning));
  }

  // Chia is address-only: the BLS secret scalar path is variable time, so even
  // address derivation is refused on a production build.
  WalletCatalogEntry xch{};
  CHECK(wallet_catalog_find("xch", &xch));
  CHECK(wallet_catalog_has(xch, WalletCapabilityAddress));
  CHECK(!wallet_catalog_has(xch, WalletCapabilitySigning));
  ChainFamily chia_family = ChainFamily::None;
  CHECK(chain_family_for_network("xch", &chia_family));
  CHECK(chia_family == ChainFamily::Chia);

  // Ergo P2PK signing is admitted; a one-byte frame is not a review request and
  // every failure path must clear the caller's output range.
  WalletCatalogEntry erg{};
  CHECK(wallet_catalog_find("erg", &erg));
  CHECK(wallet_catalog_has(erg, WalletCapabilitySigning));
  ChainFamily erg_family = ChainFamily::None;
  CHECK(chain_family_for_network("erg", &erg_family));
  CHECK(erg_family == ChainFamily::Ergo);

  WalletCatalogEntry hive{};
  CHECK(wallet_catalog_find("hive", &hive));
  CHECK(!wallet_catalog_has(hive, WalletCapabilityAddress));
  CHECK(wallet_catalog_has(hive, WalletCapabilitySigning));
  DerivedAddress address{};
  CHECK(derive_address(master, seed, *find_network_profile("xch"), 0, 0, 0, &address) != WalletError::Ok);
  CHECK(zero(&address, sizeof(address)));
  // Qubic needs FourQ/KangarooTwelve. The former Ed25519/SHA3/base26 substitute
  // could not produce a spendable identity, so the profile is gone; it must not
  // reappear without a native implementation and independent vectors.
  CHECK(find_network_profile("qubic") == nullptr);
  CHECK(derive_address(master, seed, *find_network_profile("qrl"), 1, 0, 0, &address) == WalletError::InvalidArgument);
  CHECK(derive_address(master, seed, *find_network_profile("qrl"), 0, 1, 0, &address) == WalletError::InvalidArgument);
  static const ChainFamily kGuardedFamilies[] = {ChainFamily::Chia,
                                                 ChainFamily::Ergo};
  for (ChainFamily family : kGuardedFamilies) {
    ChainTransaction tx{};
    const uint8_t payload = 0;
    CHECK(chain_review_transaction(family, &payload, 1, master, seed, 0, &tx) != ChainError::Ok);
    tx.family = family;
    tx.payload_size = 1;
    uint8_t out[65];
    memset(out, 0xa5, sizeof(out));
    size_t n = 64;
    CHECK(chain_sign_transaction(tx, master, seed, out, &n) != ChainError::Ok);
    CHECK(n == 0 && zero(out, 64) && out[64] == 0xa5);
  }
  CHECK(run_clvm_self_tests());
  CHECK(run_custody_self_tests());
  puts("production_policy=pass");
  return 0;
}
