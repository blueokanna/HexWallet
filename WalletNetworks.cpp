#include "WalletNetworks.h"
#include <string.h>

namespace hexwallet {
const NetworkProfile kNetworkProfiles[] = {
    {"btc", "BTC", "Bitcoin Native SegWit", 0, 0, 84, AddressEncoding::P2wpkh, {0x00, 0x05, "bc", false}, 0, 0},
    {"btc49", "BTC", "Bitcoin Nested SegWit", 0, 0, 49, AddressEncoding::P2shP2wpkh, {0x00, 0x05, "bc", false}, 0, 0},
    {"btc44", "BTC", "Bitcoin Legacy", 0, 0, 44, AddressEncoding::P2pkh, {0x00, 0x05, "bc", false}, 0, 0},
    {"ltc", "LTC", "Litecoin", 2, 2, 44, AddressEncoding::P2pkh, {0x30, 0x32, "ltc", false}, 0, 0},
    {"doge", "DOGE", "Dogecoin", 3, 3, 44, AddressEncoding::P2pkh, {0x1e, 0x16, nullptr, false}, 0, 0},
    {"dash", "DASH", "Dash", 5, 5, 44, AddressEncoding::P2pkh, {0x4c, 0x10, nullptr, false}, 0, 0},
    {"eth", "ETH", "Ethereum", 60, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1},
    {"etc", "ETC", "Ethereum Classic", 61, 61, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 61},
    {"xrp", "XRP", "XRP Ledger", 144, 144, 44, AddressEncoding::P2pkh, {0x00, 0, nullptr, true}, 0, 0},
    {"btg", "BTG", "Bitcoin Gold", 156, 156, 44, AddressEncoding::P2pkh, {0x26, 0x17, "btg", false}, 0, 0},
    {"rvn", "RVN", "Ravencoin", 175, 175, 44, AddressEncoding::P2pkh, {0x3c, 0x7a, nullptr, false}, 0, 0},
    {"trx", "TRX", "TRON", 195, 195, 44, AddressEncoding::Tron, {0, 0, nullptr, false}, 0x41, 0},
    {"cro", "CRO", "Cronos", 394, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 25},
    {"kava", "KAVA", "Kava EVM", 459, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 2222},
    {"opt", "OPT", "Optimism", 614, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 10},
    {"xdai", "XDAI", "Gnosis Chain", 700, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 100},
    {"matic", "MATIC", "Polygon", 966, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 137},
    {"ftm", "FTM", "Fantom", 1007, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 250},
    {"core", "CORE", "Core", 1116, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1116},
    {"glmr", "GLMR", "Moonbeam", 1284, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1284},
    {"movr", "MOVR", "Moonriver", 1285, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1285},
    {"base", "BASE", "Base", 8453, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 8453},
    {"arb1", "ARB1", "Arbitrum One", 9001, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 42161},
    {"avaxc", "AVAXC", "Avalanche C-Chain", 9005, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 43114},
    {"bsc", "BSC", "Binance Smart Chain", 9006, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 56},
    {"celo", "CELO", "Celo", 52752, 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 42220},
    {"xmr", "XMR", "Monero", 128, 128, 44, AddressEncoding::CryptoNote, {0, 0, nullptr, false}, 18, 0},
    {"msr", "MSR", "Masari", 413, 413, 44, AddressEncoding::CryptoNote, {0, 0, nullptr, false}, 28, 0},
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
      if (network.derivation_coin_type != 60 || network.evm_chain_id == 0) return false;
    } else if (network.evm_chain_id != 0) {
      return false;
    } else if (network.encoding == AddressEncoding::CryptoNote && network.account_version == 0) {
      return false;
    }
    for (size_t right = left + 1; right < kNetworkProfileCount; ++right) {
      const NetworkProfile &candidate = kNetworkProfiles[right];
      if (strcmp(network.id, candidate.id) == 0) return false;
      if (network.encoding == AddressEncoding::Evm && candidate.encoding == AddressEncoding::Evm &&
          network.evm_chain_id == candidate.evm_chain_id) return false;
    }
  }
  const NetworkProfile *ethereum = find_network_profile("eth");
  const NetworkProfile *bsc = find_network_profile("bsc");
  const NetworkProfile *monero = find_network_profile("xmr");
  const NetworkProfile *masari = find_network_profile("msr");
  return ethereum != nullptr && ethereum->evm_chain_id == 1 &&
         bsc != nullptr && bsc->derivation_coin_type == 60 && bsc->evm_chain_id == 56 &&
         monero != nullptr && monero->account_version == 18 &&
         masari != nullptr && masari->account_version == 28;
}

}
