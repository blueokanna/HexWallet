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
    {"btc", "BTC", "Bitcoin", 0, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "btc", "P2WPKH PSBT signing"},
    {"btc49", "BTC", "Bitcoin Nested SegWit", 0, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "btc49", "P2SH-P2WPKH PSBT signing"},
    {"btc44", "BTC", "Bitcoin Legacy", 0, WalletCapabilityAddress, "btc44", "P2PKH address only; signing requires verified non_witness_utxo support"},
    {"ltc", "LTC", "Litecoin", 2, WalletCapabilityAddress, "ltc", "address only"},
    {"doge", "DOGE", "Dogecoin", 3, WalletCapabilityAddress, "doge", "address only"},
    {"dash", "DASH", "Dash", 5, WalletCapabilityAddress, "dash", "address only"},
    {"eth", "ETH", "Ethereum", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "eth", "EVM address and ERC-20 account support; signing unavailable"},
    {"etc", "ETC", "Ethereum Classic", 61, WalletCapabilityAddress | WalletCapabilityTokenAccount, "etc", "EVM address and token account support; signing unavailable"},
    {"xrp", "XRP", "XRP Ledger", 144, WalletCapabilityAddress, "xrp", "address only"},
    {"btg", "BTG", "Bitcoin Gold", 156, WalletCapabilityAddress, "btg", "address only"},
    {"rvn", "RVN", "Ravencoin", 175, WalletCapabilityAddress, "rvn", "address only"},
    {"trx", "TRX", "TRON", 195, WalletCapabilityAddress, "trx", "address only"},
    {"cro", "CRO", "Cronos", 394, WalletCapabilityAddress | WalletCapabilityTokenAccount, "cro", "EVM address and token account support; signing unavailable"},
    {"kava", "KAVA", "Kava EVM", 459, WalletCapabilityAddress | WalletCapabilityTokenAccount, "kava", "EVM address and token account support; signing unavailable"},
    {"opt", "OPT", "Optimism", 614, WalletCapabilityAddress | WalletCapabilityTokenAccount, "opt", "EVM address and ERC-20 account support; signing unavailable"},
    {"xdai", "XDAI", "Gnosis Chain", 700, WalletCapabilityAddress | WalletCapabilityTokenAccount, "xdai", "EVM address and token account support; signing unavailable"},
    {"matic", "MATIC", "Polygon", 966, WalletCapabilityAddress | WalletCapabilityTokenAccount, "matic", "EVM address and ERC-20 account support; signing unavailable"},
    {"ftm", "FTM", "Fantom", 1007, WalletCapabilityAddress | WalletCapabilityTokenAccount, "ftm", "EVM address and token account support; signing unavailable"},
    {"core", "CORE", "Core", 1116, WalletCapabilityAddress | WalletCapabilityTokenAccount, "core", "EVM address and token account support; signing unavailable"},
    {"glmr", "GLMR", "Moonbeam", 1284, WalletCapabilityAddress | WalletCapabilityTokenAccount, "glmr", "EVM address and token account support; signing unavailable"},
    {"movr", "MOVR", "Moonriver", 1285, WalletCapabilityAddress | WalletCapabilityTokenAccount, "movr", "EVM address and token account support; signing unavailable"},
    {"base", "BASE", "Base", 8453, WalletCapabilityAddress | WalletCapabilityTokenAccount, "base", "EVM address and ERC-20 account support; signing unavailable"},
    {"avax", "AVAX", "Avalanche", 9000, WalletCapabilityNone, nullptr, "X/P-Chain address stack not implemented"},
    {"arb1", "ARB1", "Arbitrum One", 9001, WalletCapabilityAddress | WalletCapabilityTokenAccount, "arb1", "EVM address and ERC-20 account support; signing unavailable"},
    {"avaxc", "AVAXC", "Avalanche C-Chain", 9005, WalletCapabilityAddress | WalletCapabilityTokenAccount, "avaxc", "EVM address and ERC-20 account support; signing unavailable"},
    {"bsc", "BSC", "Binance Smart Chain", 9006, WalletCapabilityAddress | WalletCapabilityTokenAccount, "bsc", "EVM address and ERC-20 account support; signing unavailable"},
    {"celo", "CELO", "Celo", 52752, WalletCapabilityAddress | WalletCapabilityTokenAccount, "celo", "EVM address and token account support; signing unavailable"},
    {"bch", "BCH", "Bitcoin Cash", 145, WalletCapabilityNone, nullptr, "CashAddr and signing not implemented"},
    {"bsv", "BSV", "Bitcoin SV", 236, WalletCapabilityNone, nullptr, "address and signing not implemented"},
    {"xec", "XEC", "eCash", 899, WalletCapabilityNone, nullptr, "CashAddr and signing not implemented"},
    {"dgb", "DGB", "DigiByte", 20, WalletCapabilityNone, nullptr, "address vectors pending"},
    {"ppc", "PPC", "Peercoin", 6, WalletCapabilityNone, nullptr, "address vectors pending"},
    {"nmc", "NMC", "Namecoin", 7, WalletCapabilityNone, nullptr, "address vectors pending"},
    {"xmr", "XMR", "Monero", 128, WalletCapabilityAddress, "xmr", "CryptoNote standard address; RingCT/CLSAG transaction signing unavailable"},
    {"msr", "MSR", "Masari", 413, WalletCapabilityAddress, "msr", "CryptoNote standard address; transaction signing unavailable"},
    {"zec", "ZEC", "Zcash", 133, WalletCapabilityNone, nullptr, "transparent/shielded wallet not implemented"},
    {"kas", "KAS", "Kaspa", 111111, WalletCapabilityNone, nullptr, "Schnorr transaction stack not implemented"},
    {"erg", "ERG", "Ergo", 429, WalletCapabilityNone, nullptr, "Ergo transaction stack not implemented"},
    {"ckb", "CKB", "Nervos CKB", 309, WalletCapabilityNone, nullptr, "CKB transaction stack not implemented"},
    {"flux", "FLUX", "Flux", 19167, WalletCapabilityNone, nullptr, "Zcash-derived transaction stack not implemented"},
    {"xch", "XCH", "Chia", 8444, WalletCapabilityNone, nullptr, "BLS wallet not implemented"},
    {"ada", "ADA", "Cardano", 1815, WalletCapabilityNone, nullptr, "Cardano address and transaction stack not implemented"},
    {"algo", "ALGO", "Algorand", 283, WalletCapabilityNone, nullptr, "Algorand address and transaction stack not implemented"},
    {"aptos", "APTOS", "Aptos", 637, WalletCapabilityNone, nullptr, "Aptos ed25519 transaction stack not implemented"},
    {"atom", "ATOM", "Cosmos Hub", 118, WalletCapabilityNone, nullptr, "Cosmos address and transaction stack not implemented"},
    {"dot", "DOT", "Polkadot", 354, WalletCapabilityNone, nullptr, "Substrate address and transaction stack not implemented"},
    {"eos", "EOS", "EOS", 194, WalletCapabilityNone, nullptr, "EOS address and transaction stack not implemented"},
    {"fil", "FIL", "Filecoin", 461, WalletCapabilityNone, nullptr, "Filecoin address and transaction stack not implemented"},
    {"hbar", "HBAR", "Hedera HBAR", 3030, WalletCapabilityNone, nullptr, "Hedera address and transaction stack not implemented"},
    {"icp", "ICP", "Internet Computer", 223, WalletCapabilityNone, nullptr, "Internet Computer account stack not implemented"},
    {"ksm", "KSM", "Kusama", 434, WalletCapabilityNone, nullptr, "Substrate address and transaction stack not implemented"},
    {"near", "NEAR", "NEAR Protocol", 397, WalletCapabilityNone, nullptr, "NEAR ed25519 transaction stack not implemented"},
    {"sol", "SOL", "Solana", 501, WalletCapabilityNone, nullptr, "Solana ed25519 transaction stack not implemented"},
    {"sui", "SUI", "Sui", 784, WalletCapabilityNone, nullptr, "Sui ed25519 transaction stack not implemented"},
    {"ton", "TON", "TON", 607, WalletCapabilityNone, nullptr, "TON address and transaction stack not implemented"},
    {"vet", "VET", "VeChain Token", 818, WalletCapabilityNone, nullptr, "VeChain address and transaction stack not implemented"},
    {"xlm", "XLM", "Stellar Lumens", 148, WalletCapabilityNone, nullptr, "Stellar ed25519 transaction stack not implemented"},
    {"xtz", "XTZ", "Tezos", 1729, WalletCapabilityNone, nullptr, "Tezos address and transaction stack not implemented"},
};

WalletCatalogEntry resolved_entry(size_t index) {
  const CatalogSeed &seed = kCatalog[index];
  return {seed.id, seed.symbol, seed.name, seed.slip44, seed.capabilities,
          seed.network_id == nullptr ? nullptr : find_network_profile(seed.network_id), seed.status};
}

bool equals_ignore_case(const char *left, const char *right) {
  if (left == nullptr || right == nullptr) return false;
  while (*left != '\0' && *right != '\0') {
    if (tolower(static_cast<unsigned char>(*left++)) !=
        tolower(static_cast<unsigned char>(*right++))) return false;
  }
  return *left == '\0' && *right == '\0';
}

bool contains_ignore_case(const char *text, const char *query) {
  if (text == nullptr || query == nullptr) return false;
  if (*query == '\0') return true;
  const size_t query_size = strlen(query);
  for (; *text != '\0'; ++text) {
    size_t offset = 0;
    while (offset < query_size && text[offset] != '\0' &&
           tolower(static_cast<unsigned char>(text[offset])) ==
               tolower(static_cast<unsigned char>(query[offset]))) ++offset;
    if (offset == query_size) return true;
  }
  return false;
}

}

size_t wallet_catalog_count() {
  return sizeof(kCatalog) / sizeof(kCatalog[0]);
}

bool wallet_catalog_at(size_t index, WalletCatalogEntry *out) {
  if (index >= wallet_catalog_count() || out == nullptr) return false;
  *out = resolved_entry(index);
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
  return query == nullptr || *query == '\0' || contains_ignore_case(entry.id, query) ||
         contains_ignore_case(entry.symbol, query) || contains_ignore_case(entry.name, query);
}

bool wallet_catalog_has(const WalletCatalogEntry &entry, WalletCapability capability) {
  return (entry.capabilities & static_cast<uint8_t>(capability)) != 0;
}

}
