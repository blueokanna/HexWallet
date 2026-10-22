#include "WalletCatalog.h"

#include <ctype.h>
#include <string.h>

namespace hexwallet {
namespace {

struct CatalogSeed {
  const char *id;
  const char *symbol;
  const char *name;
  uint32_t slip44;
  uint8_t capabilities;
  const char *network_id;
  const char *status;
};

const CatalogSeed kCatalog[] = {
  { "btc", "BTC", "Bitcoin", 0, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "btc", "P2WPKH PSBT signing" },
  { "btc49", "BTC", "Bitcoin Nested SegWit", 0, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "btc49", "P2SH-P2WPKH PSBT signing" },
  { "btc44", "BTC", "Bitcoin Legacy", 0, WalletCapabilityAddress, "btc44", "P2PKH address only; signing requires verified non_witness_utxo support" },
  { "ltc", "LTC", "Litecoin Legacy", 2, WalletCapabilityAddress, "ltc", "P2PKH address and Bitcoin-sighash signing" },
  { "ltc49", "LTC", "Litecoin Nested SegWit", 2, WalletCapabilityAddress, "ltc49", "P2SH-P2WPKH address and BIP143 signing" },
  { "ltc84", "LTC", "Litecoin Native SegWit", 2, WalletCapabilityAddress, "ltc84", "P2WPKH address and BIP143 signing" },
  { "doge", "DOGE", "Dogecoin", 3, WalletCapabilityAddress, "doge", "address only" },
  { "dash", "DASH", "Dash", 5, WalletCapabilityAddress, "dash", "address only" },
  { "eth", "ETH", "Ethereum", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "eth", "EVM address and token account support; EIP-155 signing" },
  { "etc", "ETC", "Ethereum Classic", 61, WalletCapabilityAddress | WalletCapabilityTokenAccount, "etc", "EVM address and token account support; EIP-155 signing" },
  { "btg", "BTG", "Bitcoin Gold Legacy", 156, WalletCapabilityAddress, "btg", "P2PKH address and Bitcoin-sighash signing" },
  { "btg49", "BTG", "Bitcoin Gold Nested SegWit", 156, WalletCapabilityAddress, "btg49", "P2SH-P2WPKH address and BIP143 signing" },
  { "btg84", "BTG", "Bitcoin Gold Native SegWit", 156, WalletCapabilityAddress, "btg84", "P2WPKH address and BIP143 signing" },
  { "rvn", "RVN", "Ravencoin", 175, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "rvn", "P2PKH address and Bitcoin-sighash signing" },
  { "cro", "CRO", "Cronos", 394, WalletCapabilityAddress | WalletCapabilityTokenAccount, "cro", "EVM address and token account support; EIP-155 signing" },
  { "kava", "KAVA", "Kava EVM", 459, WalletCapabilityAddress | WalletCapabilityTokenAccount, "kava", "EVM address and token account support; EIP-155 signing" },
  { "opt", "OPT", "Optimism", 614, WalletCapabilityAddress | WalletCapabilityTokenAccount, "opt", "EVM address and token account support; EIP-155 signing" },
  { "xdai", "XDAI", "Gnosis Chain", 700, WalletCapabilityAddress | WalletCapabilityTokenAccount, "xdai", "EVM address and token account support; EIP-155 signing" },
  { "matic", "MATIC", "Polygon", 966, WalletCapabilityAddress | WalletCapabilityTokenAccount, "matic", "EVM address and token account support; EIP-155 signing" },
  { "ftm", "FTM", "Fantom", 1007, WalletCapabilityAddress | WalletCapabilityTokenAccount, "ftm", "EVM address and token account support; EIP-155 signing" },
  { "core", "CORE", "Core", 1116, WalletCapabilityAddress | WalletCapabilityTokenAccount, "core", "EVM address and token account support; EIP-155 signing" },
  { "cfx", "CFX", "Conflux eSpace", 503, WalletCapabilityAddress | WalletCapabilityTokenAccount, "cfx", "EVM address and token account support; EIP-155 signing" },
  { "glmr", "GLMR", "Moonbeam", 1284, WalletCapabilityAddress | WalletCapabilityTokenAccount, "glmr", "EVM address and token account support; EIP-155 signing" },
  { "movr", "MOVR", "Moonriver", 1285, WalletCapabilityAddress | WalletCapabilityTokenAccount, "movr", "EVM address and token account support; EIP-155 signing" },
  { "base", "BASE", "Base", 8453, WalletCapabilityAddress | WalletCapabilityTokenAccount, "base", "EVM address and token account support; EIP-155 signing" },
  { "arb1", "ARB1", "Arbitrum One", 9001, WalletCapabilityAddress | WalletCapabilityTokenAccount, "arb1", "EVM address and token account support; EIP-155 signing" },
  { "avaxc", "AVAXC", "Avalanche C-Chain", 9005, WalletCapabilityAddress | WalletCapabilityTokenAccount, "avaxc", "EVM address and token account support; EIP-155 signing" },
  { "bsc", "BSC", "Binance Smart Chain", 9006, WalletCapabilityAddress | WalletCapabilityTokenAccount, "bsc", "EVM address and token account support; EIP-155 signing" },
  { "celo", "CELO", "Celo", 52752, WalletCapabilityAddress | WalletCapabilityTokenAccount, "celo", "EVM address and token account support; EIP-155 signing" },
  { "rsk", "RBTC", "Rootstock", 137, WalletCapabilityAddress | WalletCapabilityTokenAccount, "rsk", "EVM address and token account support; EIP-155 signing" },
  { "linea", "ETH", "Linea", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "linea", "EVM address and token account support; EIP-155 signing" },
  { "scroll", "ETH", "Scroll", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "scroll", "EVM address and token account support; EIP-155 signing" },
  { "blast", "ETH", "Blast", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "blast", "EVM address and token account support; EIP-155 signing" },
  { "mantle", "MNT", "Mantle", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "mantle", "EVM address and token account support; EIP-155 signing" },
  { "opbnb", "BNB", "opBNB", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "opbnb", "EVM address and token account support; EIP-155 signing" },
  { "zkevm", "ETH", "Polygon zkEVM", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "zkevm", "EVM address and token account support; EIP-155 signing" },
  { "aurora", "ETH", "Aurora", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "aurora", "EVM address and token account support; EIP-155 signing" },
  { "metis", "METIS", "Metis Andromeda", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "metis", "EVM address and token account support; EIP-155 signing" },
  { "kaia", "KAIA", "Kaia", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "kaia", "EVM address and token account support; EIP-155 signing" },
  { "astar", "ASTR", "Astar", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "astar", "EVM address and token account support; EIP-155 signing" },
  { "canto", "CANTO", "Canto", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "canto", "EVM address and token account support; EIP-155 signing" },
  { "dogechain", "DOGE", "Dogechain EVM", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "dogechain", "EVM address and token account support; EIP-155 signing" },
  { "fuse", "FUSE", "Fuse", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "fuse", "EVM address and token account support; EIP-155 signing" },
  { "evmos", "EVMOS", "Evmos EVM", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "evmos", "EVM address and token account support; EIP-155 signing" },
  { "harmony", "ONE", "Harmony EVM", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "harmony", "EVM address and token account support; EIP-155 signing" },
  { "telos", "TLOS", "Telos EVM", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "telos", "EVM address and token account support; EIP-155 signing" },
  { "seievm", "SEI", "Sei EVM", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "seievm", "EVM address and token account support; EIP-155 signing" },
  { "ethw", "ETHW", "EthereumPoW", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "ethw", "EVM address and token account support; EIP-155 signing" },
  { "clo", "CLO", "Callisto Network", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "clo", "EVM address and token account support; EIP-155 signing" },
  { "etho", "ETHO", "Etho Protocol", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "etho", "EVM address and token account support; EIP-155 signing" },
  { "octa", "OCTA", "OctaSpace", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "octa", "EVM address and token account support; EIP-155 signing" },
  { "egaz", "EGAZ", "Etica", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "egaz", "EVM address and token account support; EIP-155 signing" },
  { "avs", "AVS", "Aves", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "avs", "EVM address and token account support; EIP-155 signing" },
  { "cau", "CAU", "Canxium", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "cau", "EVM address and token account support; EIP-155 signing" },
  { "btn", "BTN", "Bitnet", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "btn", "EVM address and token account support; EIP-155 signing" },
  { "lrs", "LRS", "Larissa Chain", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "lrs", "EVM address and token account support; EIP-155 signing" },
  { "vbc", "VBC", "VirBiCoin", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "vbc", "EVM address and token account support; EIP-155 signing" },
  { "bch", "BCH", "Bitcoin Cash", 145, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "bch", "CashAddr; forkid sighash signing" },
  { "bsv", "BSV", "Bitcoin SV", 236, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "bsv", "P2PKH PSBT signing, BIP143 + SIGHASH_FORKID" },
  { "xec", "XEC", "eCash", 899, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "xec", "CashAddr; forkid sighash signing" },
  { "dgb", "DGB", "DigiByte Legacy", 20, WalletCapabilityAddress, "dgb", "P2PKH address and Bitcoin-sighash signing" },
  { "dgb49", "DGB", "DigiByte Nested SegWit", 20, WalletCapabilityAddress, "dgb49", "P2SH-P2WPKH address and BIP143 signing" },
  { "dgb84", "DGB", "DigiByte Native SegWit", 20, WalletCapabilityAddress, "dgb84", "P2WPKH address and BIP143 signing" },
  { "nmc", "NMC", "Namecoin", 7, WalletCapabilityAddress, "nmc", "P2PKH address and Bitcoin-sighash signing" },
  { "zec", "ZEC", "Zcash", 133, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "zec", "transparent t1/t3 address; v4 transparent ZIP-243 review and signing (NU6.2)" },
  { "kas", "KAS", "Kaspa", 111111, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "kas", "Kaspa bech32 address; BIP340 Schnorr v0 transaction review and signing" },
  { "vtc", "VTC", "Vertcoin Legacy", 28, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "vtc", "P2PKH address and Bitcoin-sighash signing" },
  { "vtc49", "VTC", "Vertcoin Nested SegWit", 28, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "vtc49", "P2SH-P2WPKH address and BIP143 signing" },
  { "vtc84", "VTC", "Vertcoin Native SegWit", 28, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "vtc84", "P2WPKH address and Bitcoin-sighash signing" },
  { "axe", "AXE", "Axe", 4242, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "axe", "P2PKH address and Bitcoin-sighash signing" },
#include "src/generated/WalletForkCatalog.inc"
};

WalletCatalogEntry resolved_entry(size_t index) {
  const CatalogSeed &seed = kCatalog[index];
  static const NetworkProfile *network_cache[sizeof(kCatalog) / sizeof(kCatalog[0])] = {};
  if (network_cache[index] == nullptr && seed.network_id != nullptr) {
    network_cache[index] = find_network_profile(seed.network_id);
  }
  const NetworkProfile *network = network_cache[index];
  uint8_t capabilities = seed.capabilities;
  const char *status = seed.status;
  if (network != nullptr && network->encoding == AddressEncoding::Evm) {
    capabilities |= WalletCapabilityTransactionReview | WalletCapabilitySigning;
    status = network_supports_eip1559(*network)
                 ? "EIP-155/EIP-1559 native and whitelisted ERC-20/721/1155/4626/777/3525/6551/OFT/ONFT call signing"
                 : "EIP-155 legacy native and whitelisted token-call signing; type-2 rejected by chain policy";
  }
  const NetworkSigningPolicy *policy =
      network == nullptr ? nullptr : find_network_signing_policy(network->id);
  if (policy != nullptr) {
    capabilities |= WalletCapabilityTransactionReview | WalletCapabilitySigning;
    if (network != nullptr && network->encoding == AddressEncoding::P2wpkh) {
      status = "BIP84 native SegWit PSBT signing (BIP143)";
    } else if (network != nullptr &&
               network->encoding == AddressEncoding::P2shP2wpkh) {
      status = "BIP49 nested SegWit PSBT signing (BIP143)";
    } else if (policy->family == SighashFamily::ZcashZip243) {
      status = "Zcash v4 transparent ZIP-243 review and signing (NU6.2)";
    } else {
      status = policy->family == SighashFamily::ForkId
                   ? "P2PKH PSBT signing, BIP143 + SIGHASH_FORKID"
                   : "P2PKH legacy sighash and BIP143 witness PSBT signing";
    }
  }
  return { seed.id, seed.symbol, seed.name, seed.slip44, capabilities, network, status };
}

bool equals_ignore_case(const char *left, const char *right) {
  if (left == nullptr || right == nullptr) return false;
  while (*left != '\0' && *right != '\0') {
    if (tolower(static_cast<unsigned char>(*left++)) != tolower(static_cast<unsigned char>(*right++))) return false;
  }
  return *left == '\0' && *right == '\0';
}

bool contains_ignore_case(const char *text, const char *query) {
  if (text == nullptr || query == nullptr) return false;
  if (*query == '\0') return true;
  const size_t query_size = strlen(query);
  for (; *text != '\0'; ++text) {
    size_t offset = 0;
    while (offset < query_size && text[offset] != '\0' && tolower(static_cast<unsigned char>(text[offset])) == tolower(static_cast<unsigned char>(query[offset]))) ++offset;
    if (offset == query_size) return true;
  }
  return false;
}

}

size_t wallet_catalog_count() {
  return sizeof(kCatalog) / sizeof(kCatalog[0]);
}

namespace {

int catalog_name_compare(const CatalogSeed &left, const CatalogSeed &right) {
  const unsigned char *a = reinterpret_cast<const unsigned char *>(left.name);
  const unsigned char *b = reinterpret_cast<const unsigned char *>(right.name);
  while (*a != '\0' && *b != '\0') {
    const int la = tolower(*a);
    const int lb = tolower(*b);
    if (la != lb) return la < lb ? -1 : 1;
    ++a;
    ++b;
  }
  return (*a == *b) ? 0 : (*a == '\0' ? -1 : 1);
}

// A-Z presentation order, built once with an insertion sort (the table is
// static and small). Kept out of the seed table so lookups stay O(n) by id and
// the grouped-by-family source layout stays readable.
const uint16_t *sorted_order() {
  static uint16_t order[sizeof(kCatalog) / sizeof(kCatalog[0])];
  static bool ready = false;
  if (!ready) {
    const size_t count = wallet_catalog_count();
    for (size_t index = 0; index < count; ++index) order[index] = static_cast<uint16_t>(index);
    for (size_t index = 1; index < count; ++index) {
      const uint16_t key = order[index];
      size_t position = index;
      while (position > 0 &&
             catalog_name_compare(kCatalog[order[position - 1]], kCatalog[key]) > 0) {
        order[position] = order[position - 1];
        --position;
      }
      order[position] = key;
    }
    ready = true;
  }
  return order;
}

}

bool wallet_catalog_at(size_t index, WalletCatalogEntry *out) {
  if (index >= wallet_catalog_count() || out == nullptr) return false;
  *out = resolved_entry(index);
  return true;
}

bool wallet_catalog_at_sorted(size_t position, WalletCatalogEntry *out) {
  if (out == nullptr || position >= wallet_catalog_count()) return false;
  *out = resolved_entry(sorted_order()[position]);
  return true;
}

bool wallet_catalog_find(const char *id_or_symbol, WalletCatalogEntry *out) {
  if (out == nullptr) return false;
  for (size_t index = 0; index < wallet_catalog_count(); ++index) {
    const WalletCatalogEntry entry = resolved_entry(index);
    if (equals_ignore_case(entry.id, id_or_symbol) || equals_ignore_case(entry.symbol, id_or_symbol)) {
      *out = entry;
      return true;
    }
  }
  return false;
}

bool wallet_catalog_matches(const WalletCatalogEntry &entry, const char *query) {
  return query == nullptr || *query == '\0' || contains_ignore_case(entry.id, query) || contains_ignore_case(entry.symbol, query) || contains_ignore_case(entry.name, query);
}

bool wallet_catalog_has(const WalletCatalogEntry &entry, WalletCapability capability) {
  return (entry.capabilities & static_cast<uint8_t>(capability)) != 0;
}

bool run_catalog_self_tests() {
  for (size_t index = 0; index < wallet_catalog_count(); ++index) {
    const WalletCatalogEntry entry = resolved_entry(index);
    if (entry.id == nullptr || entry.symbol == nullptr || entry.name == nullptr ||
        entry.status == nullptr) {
      return false;
    }
    if ((entry.capabilities & static_cast<uint8_t>(WalletCapabilityAddress)) != 0 &&
        entry.network == nullptr) {
      return false;
    }
    if ((entry.capabilities & static_cast<uint8_t>(WalletCapabilitySigning)) != 0 &&
        entry.network == nullptr) {
      return false;
    }
    if ((entry.capabilities & static_cast<uint8_t>(WalletCapabilitySigning)) != 0) {
      const bool evm = entry.network->encoding == AddressEncoding::Evm;
      const bool utxo_policy = find_network_signing_policy(entry.network->id) != nullptr;
      const bool kaspa = entry.network->encoding == AddressEncoding::KaspaBech32;
      if (!evm && !utxo_policy && !kaspa) return false;
      // CryptoNote signing stays gated until Bulletproofs+, full RingCT
      // serialization, decoy selection, wallet scanning and a real node
      // acceptance run exist. A catalog entry that claims otherwise would be
      // a lie, so the guard is enforced here rather than in a comment.
      if (entry.network->encoding == AddressEncoding::CryptoNote) return false;
    }
    for (size_t other = index + 1; other < wallet_catalog_count(); ++other) {
      const WalletCatalogEntry candidate = resolved_entry(other);
      if (strcmp(entry.id, candidate.id) == 0) return false;
    }
  }
  for (size_t index = 0; index < kNetworkProfileCount; ++index) {
    const NetworkProfile &network = kNetworkProfiles[index];
    bool cataloged = false;
    for (size_t entry = 0; entry < wallet_catalog_count(); ++entry) {
      const WalletCatalogEntry candidate = resolved_entry(entry);
      if (candidate.network == &network) {
        cataloged = true;
        break;
      }
    }
    if (cataloged) continue;
    const bool signable =
        network.encoding == AddressEncoding::Evm ||
        network.encoding == AddressEncoding::KaspaBech32 ||
        find_network_signing_policy(network.id) != nullptr;
    if (signable) return false;
  }
  // XMR/MSR must not be reachable as a wallet at all while their signing path
  // is incomplete: the phone link and the CLI both resolve through the catalog.
  for (size_t index = 0; index < kNetworkProfileCount; ++index) {
    const NetworkProfile &network = kNetworkProfiles[index];
    if (network.encoding != AddressEncoding::CryptoNote) continue;
    for (size_t entry = 0; entry < wallet_catalog_count(); ++entry) {
      if (resolved_entry(entry).network == &network) return false;
    }
  }
  return true;
}

}
