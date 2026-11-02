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
#include "StarknetTransaction.h"
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
  // It answers "user verified" and "keys non-exportable" as favourably as a
  // backend could, so the remaining blockers are the only thing holding the
  // gate shut.
  const SecureElementBackend transport = {
    "test-authenticated-channel",
    [](char *, size_t) { return true; },
    []() { return true; },
    []() { return true; },
    []() { return true; },
    [](uint32_t, const uint8_t *, uint8_t *, size_t *) { return false; },
    [](uint32_t, uint8_t *, size_t *) { return false; },
    []() {}};
  CHECK(secure_element_register_backend(&transport));
  CHECK(secure_element_open(nullptr, 0) && secure_element_ready());
  CHECK(secure_element_user_authenticated());
  CHECK(secure_element_keys_non_exportable());
  CHECK(!secure_custody_backend_ready());
  // The gate must be shut by the wallet layer, not by the card.
  const CustodyGateState gate = custody_gate_state();
  CHECK(gate.backend_registered && gate.channel_authenticated &&
        gate.user_authenticated && gate.keys_non_exportable);
  CHECK(!gate.wallet_uses_handles);
  CHECK(custody_gate_blocker(gate) == CustodyBlocker::WalletLayerNotConverted);
  CHECK(&active_secure_element_profile() == &software_only_profile());
  CHECK(wallet_session_generate() == WalletError::CustodyUnavailable);
  CHECK(wallet_session_import("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about") == WalletError::CustodyUnavailable);
  CHECK(secure_element_register_backend(nullptr));
  // With nothing registered the same gate names the card, not the wallet.
  CHECK(custody_gate_blocker(custody_gate_state()) ==
        CustodyBlocker::BackendMissing);

  // DOT/KSM are admitted in production only through the pinned runtime pair.
  // The historical DOT1 layout is not compiled into this build at all, so a
  // DOT1 payload must be refused before any key is touched.
  static const char *const kPinnedNetworks[] = {"dot", "ksm"};
  for (size_t i = 0; i < sizeof(kPinnedNetworks) / sizeof(kPinnedNetworks[0]); ++i) {
    const char *network = kPinnedNetworks[i];
    ChainFamily family = ChainFamily::None;
    CHECK(chain_family_for_network(network, &family));
    CHECK(family == (strcmp(network, "dot") == 0 ? ChainFamily::Polkadot
                                                 : ChainFamily::Kusama));
    WalletCatalogEntry entry{};
    CHECK(wallet_catalog_find(network, &entry));
    CHECK(wallet_catalog_has(entry, WalletCapabilitySigning));
  }
  {
    uint8_t dot1[130] = {};
    memcpy(dot1, "DOT1", 4);
    ChainTransaction tx{};
    // No legacy DOT1 payload may be reviewable in a production build: the codec
    // for that layout is compiled out, so this never reaches a signature.
    CHECK(chain_review_transaction(ChainFamily::Polkadot, dot1, sizeof(dot1),
                                   master, seed, 0, &tx) != ChainError::Ok);
    memset(dot1, 0, sizeof(dot1));
  }

  // Chia signs with the in-tree BLS12-381 backend, so a production build admits both
  // the address and the standard-coin spend path.
  WalletCatalogEntry xch{};
  CHECK(wallet_catalog_find("xch", &xch));
  CHECK(wallet_catalog_has(xch, WalletCapabilityAddress));
  CHECK(wallet_catalog_has(xch, WalletCapabilitySigning));
  ChainFamily chia_family = ChainFamily::None;
  CHECK(chain_family_for_network("xch", &chia_family));
  CHECK(chia_family == ChainFamily::Chia);

  // QRL signs native transfers only after a durable one-time index exists. With
  // no Mbed TLS custody in this build the adapter must still refuse a malformed
  // payload instead of reaching the signer.
  {
    WalletCatalogEntry qrl_entry{};
    CHECK(wallet_catalog_find("qrl", &qrl_entry));
    CHECK(wallet_catalog_has(qrl_entry, WalletCapabilitySigning));
    ChainFamily qrl_family = ChainFamily::None;
    CHECK(chain_family_for_network("qrl", &qrl_family));
    CHECK(qrl_family == ChainFamily::Qrl);
    uint8_t bad[8] = {'Q', 'R', 'L', '1', 0, 0, 0, 0};
    ChainTransaction tx{};
    CHECK(chain_review_transaction(ChainFamily::Qrl, bad, sizeof(bad), master,
                                   seed, 0, &tx) != ChainError::Ok);
  }

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

  // Starknet signs only v3 deploy_account / single-transfer invoke, and proves
  // the account belongs to this key by recomputing its SNIP-5 address.
  WalletCatalogEntry stark{};
  CHECK(wallet_catalog_find("stark", &stark));
  CHECK(wallet_catalog_has(stark, WalletCapabilityAddress));
  CHECK(wallet_catalog_has(stark, WalletCapabilitySigning));
  ChainFamily stark_family = ChainFamily::None;
  CHECK(chain_family_for_network("stark", &stark_family));
  CHECK(stark_family == ChainFamily::Starknet);
  CHECK(run_starknet_self_tests());
  DerivedAddress address{};
  // Chia is admitted now that the in-tree BLS12-381 scalar multiplication is
  // constant time; the account must be a real xch1 address.
  CHECK(derive_address(master, seed, *find_network_profile("xch"), 0, 0, 0,
                       &address) == WalletError::Ok);
  CHECK(strncmp(address.address, "xch1", 4) == 0);
  // Qubic needs FourQ/KangarooTwelve. The former Ed25519/SHA3/base26 substitute
  // could not produce a spendable identity, so the profile is gone; it must not
  // reappear without a native implementation and independent vectors.
  CHECK(find_network_profile("qubic") == nullptr);
  CHECK(derive_address(master, seed, *find_network_profile("qrl"), 1, 0, 0, &address) == WalletError::InvalidArgument);
  CHECK(derive_address(master, seed, *find_network_profile("qrl"), 0, 1, 0, &address) == WalletError::InvalidArgument);
  static const ChainFamily kGuardedFamilies[] = {ChainFamily::Chia,
                                                 ChainFamily::Ergo,
                                                 ChainFamily::Starknet};
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
