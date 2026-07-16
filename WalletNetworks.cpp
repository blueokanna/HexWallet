#include "WalletNetworks.h"
#include <string.h>

namespace hexwallet {
const NetworkProfile kNetworkProfiles[] = {
    {"btc", "BTC", "Bitcoin Native SegWit", 0, 84, AddressEncoding::P2wpkh, {0x00, 0x05, "bc", false}, 0},
    {"btc49", "BTC", "Bitcoin Nested SegWit", 0, 49, AddressEncoding::P2shP2wpkh, {0x00, 0x05, "bc", false}, 0},
    {"btc44", "BTC", "Bitcoin Legacy", 0, 44, AddressEncoding::P2pkh, {0x00, 0x05, "bc", false}, 0},
    {"ltc", "LTC", "Litecoin", 2, 44, AddressEncoding::P2pkh, {0x30, 0x32, "ltc", false}, 0},
    {"doge", "DOGE", "Dogecoin", 3, 44, AddressEncoding::P2pkh, {0x1e, 0x16, nullptr, false}, 0},
    {"dash", "DASH", "Dash", 5, 44, AddressEncoding::P2pkh, {0x4c, 0x10, nullptr, false}, 0},
    {"eth", "ETH", "Ethereum", 60, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0},
    {"etc", "ETC", "Ethereum Classic", 61, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0},
    {"xrp", "XRP", "XRP Ledger", 144, 44, AddressEncoding::P2pkh, {0x00, 0, nullptr, true}, 0},
    {"btg", "BTG", "Bitcoin Gold", 156, 44, AddressEncoding::P2pkh, {0x26, 0x17, "btg", false}, 0},
    {"rvn", "RVN", "Ravencoin", 175, 44, AddressEncoding::P2pkh, {0x3c, 0x7a, nullptr, false}, 0},
    {"trx", "TRX", "TRON", 195, 44, AddressEncoding::Tron, {0, 0, nullptr, false}, 0x41},
    {"opt", "OPT", "Optimism", 614, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0},
    {"matic", "MATIC", "Polygon", 966, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0},
    {"ftm", "FTM", "Fantom", 1007, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0},
    {"base", "BASE", "Base", 8453, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0},
    {"arb1", "ARB1", "Arbitrum", 9001, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0},
    {"avaxc", "AVAXC", "Avalanche C-Chain", 9005, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0},
    {"bsc", "BSC", "Binance Smart Chain", 9006, 44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0},
};

const size_t kNetworkProfileCount = sizeof(kNetworkProfiles) / sizeof(kNetworkProfiles[0]);

const NetworkProfile *find_network_profile(const char *id) {
  if (id == nullptr) return nullptr;
  for (size_t index = 0; index < kNetworkProfileCount; ++index) {
    if (strcmp(kNetworkProfiles[index].id, id) == 0) return &kNetworkProfiles[index];
  }
  return nullptr;
}

}
