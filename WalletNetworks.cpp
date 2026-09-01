#include "WalletNetworks.h"
#include <string.h>

namespace hexwallet {
namespace {
constexpr UtxoAddressProfile kUtxoBitcoin = {0x00, 0x05, "bc", false};
constexpr UtxoAddressProfile kUtxoLitecoin = {0x30, 0x32, "ltc", false};
constexpr UtxoAddressProfile kUtxoDogecoin = {0x1e, 0x16, nullptr, false};
constexpr UtxoAddressProfile kUtxoDash = {0x4c, 0x10, nullptr, false};
constexpr UtxoAddressProfile kUtxoBitcoinGold = {0x26, 0x17, "btg", false};
constexpr UtxoAddressProfile kUtxoRavencoin = {0x3c, 0x7a, nullptr, false};
constexpr UtxoAddressProfile kUtxoVertcoin = {0x47, 0x05, "vtc", false};
constexpr UtxoAddressProfile kUtxoAxe = {0x8c, 0x13, "axe", false};
constexpr UtxoAddressProfile kUtxoXrp = {0x00, 0x00, nullptr, true};
}  // namespace

const NetworkProfile kNetworkProfiles[] = {
    // --- Bitcoin family ---------------------------------------------------
    {"btc", "BTC", "Bitcoin Native SegWit", 0, 0, 84, DerivationStyle::Bip44, AddressEncoding::P2wpkh, kUtxoBitcoin, 0, 0, 0, 0, nullptr},
    {"btc49", "BTC", "Bitcoin Nested SegWit", 0, 0, 49, DerivationStyle::Bip44, AddressEncoding::P2shP2wpkh, kUtxoBitcoin, 0, 0, 0, 0, nullptr},
    {"btc44", "BTC", "Bitcoin Legacy", 0, 0, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoBitcoin, 0, 0, 0, 0, nullptr},
    {"ltc", "LTC", "Litecoin", 2, 2, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoLitecoin, 0, 0, 0, 0, nullptr},
    {"doge", "DOGE", "Dogecoin", 3, 3, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoDogecoin, 0, 0, 0, 0, nullptr},
    {"dash", "DASH", "Dash", 5, 5, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoDash, 0, 0, 0, 0, nullptr},
    {"btg", "BTG", "Bitcoin Gold", 156, 156, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoBitcoinGold, 0, 0, 0, 0, nullptr},
    {"rvn", "RVN", "Ravencoin", 175, 175, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoRavencoin, 0, 0, 0, 0, nullptr},
    {"vtc", "VTC", "Vertcoin", 28, 28, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoVertcoin, 0, 0, 0, 0, nullptr},
    {"vtc84", "VTC", "Vertcoin Native SegWit", 28, 28, 84, DerivationStyle::Bip44, AddressEncoding::P2wpkh, kUtxoVertcoin, 0, 0, 0, 0, nullptr},
    {"axe", "AXE", "Axe", 4242, 4242, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoAxe, 0, 0, 0, 0, nullptr},
    // --- EVM networks ------------------------------------------------------
    {"eth", "ETH", "Ethereum", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1, 0, 0, nullptr},
    {"etc", "ETC", "Ethereum Classic", 61, 61, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 61, 0, 0, nullptr},
    {"cro", "CRO", "Cronos", 394, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 25, 0, 0, nullptr},
    {"kava", "KAVA", "Kava EVM", 459, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 2222, 0, 0, nullptr},
    {"opt", "OPT", "Optimism", 614, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 10, 0, 0, nullptr},
    {"xdai", "XDAI", "Gnosis Chain", 700, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 100, 0, 0, nullptr},
    {"matic", "MATIC", "Polygon", 966, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 137, 0, 0, nullptr},
    {"ftm", "FTM", "Fantom", 1007, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 250, 0, 0, nullptr},
    {"core", "CORE", "Core", 1116, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1116, 0, 0, nullptr},
    {"glmr", "GLMR", "Moonbeam", 1284, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1284, 0, 0, nullptr},
    {"movr", "MOVR", "Moonriver", 1285, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1285, 0, 0, nullptr},
    {"base", "BASE", "Base", 8453, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 8453, 0, 0, nullptr},
    {"arb1", "ARB1", "Arbitrum One", 9001, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 42161, 0, 0, nullptr},
    {"avaxc", "AVAXC", "Avalanche C-Chain", 9005, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 43114, 0, 0, nullptr},
    {"bsc", "BSC", "Binance Smart Chain", 9006, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 56, 0, 0, nullptr},
    {"celo", "CELO", "Celo", 52752, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 42220, 0, 0, nullptr},
    // --- Other existing chains ---------------------------------------------
    {"xrp", "XRP", "XRP Ledger", 144, 144, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoXrp, 0, 0, 0, 0, nullptr},
    {"trx", "TRX", "TRON", 195, 195, 44, DerivationStyle::Bip44, AddressEncoding::Tron, {0, 0, nullptr, false}, 0x41, 0, 0, 0, nullptr},
    {"xmr", "XMR", "Monero", 128, 128, 44, DerivationStyle::Bip44, AddressEncoding::CryptoNote, {0, 0, nullptr, false}, 18, 0, 0, 0, nullptr},
    {"msr", "MSR", "Masari", 413, 413, 44, DerivationStyle::Bip44, AddressEncoding::CryptoNote, {0, 0, nullptr, false}, 28, 0, 0, 0, nullptr},
    // --- New multi-coin support (SLIP-0044) --------------------------------
    {"kas", "KAS", "Kaspa", 111111, 111111, 44, DerivationStyle::Bip44, AddressEncoding::KaspaBech32, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
    {"zec", "ZEC", "Zcash (transparent)", 133, 133, 44, DerivationStyle::Bip44, AddressEncoding::ZcashTransparent, {0, 0, nullptr, false}, 0, 0, 0x1cb8, 0x1cbd, nullptr},
    {"flux", "FLUX", "Flux (transparent)", 19167, 19167, 44, DerivationStyle::Bip44, AddressEncoding::ZcashTransparent, {0, 0, nullptr, false}, 0, 0, 0x1cb8, 0x1cbd, nullptr},
    {"bch", "BCH", "Bitcoin Cash", 145, 145, 44, DerivationStyle::Bip44, AddressEncoding::CashAddr, {0, 0, nullptr, false}, 0, 0, 0, 0, "bitcoincash"},
    {"xec", "XEC", "eCash", 899, 899, 44, DerivationStyle::Bip44, AddressEncoding::CashAddr, {0, 0, nullptr, false}, 0, 0, 0, 0, "ecash"},
    {"sol", "SOL", "Solana", 501, 501, 44, DerivationStyle::SolanaBip44, AddressEncoding::Ed25519Base58, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
    {"algo", "ALGO", "Algorand", 283, 283, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::Ed25519Base32, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
    {"xtz", "XTZ", "Tezos (tz1)", 1729, 1729, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::Ed25519Blake2bBase58, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
    {"ada", "ADA", "Cardano", 1815, 1815, 1852, DerivationStyle::CardanoBip1852, AddressEncoding::Ed25519Blake2b224Bech32, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
    {"qubic", "QUBIC", "Qubic", 83293, 83293, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::QubicBase26, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
    {"croorg", "CRO", "Crypto.org Chain", 394, 394, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Cosmos, {0, 0, nullptr, false}, 0, 0, 0, 0, "cro"},
    {"sei", "SEI", "SEI", 19000118, 19000118, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Cosmos, {0, 0, nullptr, false}, 0, 0, 0, 0, "sei"},
    {"avax", "AVAX", "Avalanche X/P Chain", 9000, 9000, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Avalanche, {0, 0, nullptr, false}, 0, 0, 0, 0, "avax"},
    {"fil", "FIL", "Filecoin", 461, 461, 44, DerivationStyle::Bip44, AddressEncoding::Blake2bBase32Filecoin, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
    {"erg", "ERG", "Ergo", 429, 429, 44, DerivationStyle::Bip44, AddressEncoding::Blake2bBase58Ergo, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
    {"xch", "XCH", "Chia", 8444, 8444, 12381, DerivationStyle::ChiaEip2333, AddressEncoding::Bech32mBlsChia, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
};

const size_t kNetworkProfileCount = sizeof(kNetworkProfiles) / sizeof(kNetworkProfiles[0]);

const NetworkProfile *find_network_profile(const char *id) {
  if (id == nullptr) return nullptr;
  for (size_t index = 0; index < kNetworkProfileCount; ++index) {
    if (strcmp(kNetworkProfiles[index].id, id) == 0) return &kNetworkProfiles[index];
  }
  return nullptr;
}

bool network_supports_token_accounts(const NetworkProfile &network) {
  return network.encoding == AddressEncoding::Evm && network.evm_chain_id != 0;
}

bool run_network_profile_self_tests() {
  for (size_t left = 0; left < kNetworkProfileCount; ++left) {
    const NetworkProfile &network = kNetworkProfiles[left];
    if (network.id == nullptr || network.id[0] == '\0' || network.symbol == nullptr ||
        network.symbol[0] == '\0' || network.name == nullptr || network.name[0] == '\0' ||
        network.bip_purpose >= kHardenedOffset || network.slip44_coin_type >= kHardenedOffset ||
        network.derivation_coin_type >= kHardenedOffset) return false;
    if (network.encoding == AddressEncoding::Evm) {
      const uint32_t expected_derivation_type = strcmp(network.id, "etc") == 0 ? 61 : 60;
      if (network.derivation_coin_type != expected_derivation_type || network.evm_chain_id == 0) {
        return false;
      }
    } else if (network.evm_chain_id != 0) {
      return false;
    }
    if (network.encoding == AddressEncoding::CryptoNote && network.account_version == 0) return false;
    if ((network.encoding == AddressEncoding::ZcashTransparent) &&
        (network.alt_p2pkh_version == 0 || network.alt_p2sh_version == 0)) return false;
    if (network.encoding == AddressEncoding::CashAddr && network.alt_hrp == nullptr) return false;
    if (network.encoding == AddressEncoding::Bech32Cosmos && network.alt_hrp == nullptr) return false;
    if (network.encoding == AddressEncoding::Bech32Avalanche && network.alt_hrp == nullptr) return false;
    if (network.encoding == AddressEncoding::P2wpkh && network.utxo.bech32_hrp == nullptr) return false;
    for (size_t right = left + 1; right < kNetworkProfileCount; ++right) {
      const NetworkProfile &candidate = kNetworkProfiles[right];
      if (strcmp(network.id, candidate.id) == 0) return false;
      if (network.encoding == AddressEncoding::Evm && candidate.encoding == AddressEncoding::Evm &&
          network.evm_chain_id == candidate.evm_chain_id) return false;
    }
  }
  const NetworkProfile *ethereum = find_network_profile("eth");
  const NetworkProfile *ethereum_classic = find_network_profile("etc");
  const NetworkProfile *bsc = find_network_profile("bsc");
  const NetworkProfile *monero = find_network_profile("xmr");
  const NetworkProfile *masari = find_network_profile("msr");
  const NetworkProfile *kaspa = find_network_profile("kas");
  const NetworkProfile *algorand = find_network_profile("algo");
  const NetworkProfile *solana = find_network_profile("sol");
  const NetworkProfile *chia = find_network_profile("xch");
  return ethereum != nullptr && ethereum->evm_chain_id == 1 &&
         ethereum_classic != nullptr && ethereum_classic->derivation_coin_type == 61 &&
         ethereum_classic->evm_chain_id == 61 &&
         bsc != nullptr && bsc->derivation_coin_type == 60 && bsc->evm_chain_id == 56 &&
         monero != nullptr && monero->account_version == 18 &&
         masari != nullptr && masari->account_version == 28 &&
         kaspa != nullptr && kaspa->slip44_coin_type == 111111 &&
         algorand != nullptr && algorand->slip44_coin_type == 283 &&
         solana != nullptr && solana->slip44_coin_type == 501 &&
         chia != nullptr && chia->slip44_coin_type == 8444 && chia->bip_purpose == 12381;
}

}  // namespace hexwallet
