#include "WalletTokens.h"

#include <string.h>

namespace hexwallet {
namespace {

bool is_hex(char value) {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
         (value >= 'A' && value <= 'F');
}

bool valid_erc20_contract(const char *contract) {
  if (contract == nullptr || strlen(contract) != 42 || contract[0] != '0' || contract[1] != 'x') return false;
  for (size_t index = 2; index < 42; ++index) {
    if (!is_hex(contract[index])) return false;
  }
  return true;
}

bool valid_spl_mint(const char *mint) {
  if (mint == nullptr) return false;
  const size_t length = strlen(mint);
  if (length < 32 || length > 44) return false;
  for (size_t index = 0; index < length; ++index) {
    const char value = mint[index];
    if (!((value >= '1' && value <= '9') || (value >= 'A' && value <= 'H') ||
          (value >= 'J' && value <= 'N') || (value >= 'P' && value <= 'Z') ||
          (value >= 'a' && value <= 'k') || (value >= 'm' && value <= 'z'))) return false;
  }
  return true;
}

}  // namespace

const TokenProfile kTokenProfiles[] = {
    {"eth-usdc", "eth", "USDC", "USD Coin", TokenStandard::Erc20,
     "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"eth-usdt", "eth", "USDT", "Tether USD", TokenStandard::Erc20,
     "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"eth-dai", "eth", "DAI", "Dai Stablecoin", TokenStandard::Erc20,
     "0x6B175474E89094C44Da98b954EedeAC495271d0F", 18, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"eth-wbtc", "eth", "WBTC", "Wrapped Bitcoin", TokenStandard::Erc20,
     "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", 8, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"bsc-usdt", "bsc", "USDT", "Binance-Peg BSC-USD", TokenStandard::Erc20,
     "0x55d398326f99059fF775485246999027B3197955", 18, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"bsc-usdc", "bsc", "USDC", "Binance-Peg USD Coin", TokenStandard::Erc20,
     "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 18, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"bsc-busd", "bsc", "BUSD", "Binance USD", TokenStandard::Erc20,
     "0xe9e7CEA3Dedca5984780Bafc599bD69ADd087D56", 18, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"matic-usdc", "matic", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x3c499c542cEF5E3811e1192ce70d8cc03d5c3359", 6, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"matic-usdt", "matic", "USDT", "Tether USD", TokenStandard::Erc20,
     "0xc2132D05D31c914a87C6611C10748AaCbEbfA6E", 6, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"arb-usdc", "arb1", "USDC", "USD Coin", TokenStandard::Erc20,
     "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"arb-usdt", "arb1", "USDT", "Tether USD", TokenStandard::Erc20,
     "0xfd086bC7CD5C481DCC9C85eFfA478A1C0b69FCbb", 6, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"opt-usdc", "opt", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x7F5c764cBc14f9669B88837ca1490cCa17c31607", 6, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"base-usdc", "base", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"avaxc-usdc", "avaxc", "USDC", "USD Coin", TokenStandard::Erc20,
     "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", 6, TokenCapabilityAccountAddress,
     "ERC-20 account address supported; transfer signing unavailable"},
    {"sol-usdc", "sol", "USDC", "USD Coin", TokenStandard::Spl,
     "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", 6, TokenCapabilityNone,
     "SPL mint registered; Solana address and transfer signing unavailable"},
};

const size_t kTokenProfileCount = sizeof(kTokenProfiles) / sizeof(kTokenProfiles[0]);

const TokenProfile *find_token_profile(const char *id) {
  if (id == nullptr) return nullptr;
  for (size_t index = 0; index < kTokenProfileCount; ++index) {
    if (strcmp(kTokenProfiles[index].id, id) == 0) return &kTokenProfiles[index];
  }
  return nullptr;
}

const NetworkProfile *token_network(const TokenProfile &token) {
  return find_network_profile(token.network_id);
}

bool token_supports_account_address(const TokenProfile &token) {
  const NetworkProfile *network = token_network(token);
  return (token.capabilities & TokenCapabilityAccountAddress) != 0 && network != nullptr &&
         network_supports_token_accounts(*network);
}

const char *token_standard_text(TokenStandard standard) {
  switch (standard) {
    case TokenStandard::Erc20: return "ERC-20";
    case TokenStandard::Spl: return "SPL";
  }
  return "unknown";
}

bool run_token_profile_self_tests() {
  for (size_t left = 0; left < kTokenProfileCount; ++left) {
    const TokenProfile &token = kTokenProfiles[left];
    if (token.id == nullptr || token.id[0] == '\0' || token.network_id == nullptr ||
        token.network_id[0] == '\0' || token.symbol == nullptr || token.symbol[0] == '\0' ||
        token.name == nullptr || token.name[0] == '\0' || token.contract_or_mint == nullptr ||
        token.contract_or_mint[0] == '\0' || token.status == nullptr || token.status[0] == '\0') return false;
    if (token.standard == TokenStandard::Erc20) {
      if (!valid_erc20_contract(token.contract_or_mint) || !token_supports_account_address(token)) return false;
    } else if (token.standard == TokenStandard::Spl) {
      if (!valid_spl_mint(token.contract_or_mint) || token_supports_account_address(token)) return false;
    } else {
      return false;
    }
    for (size_t right = left + 1; right < kTokenProfileCount; ++right) {
      if (strcmp(token.id, kTokenProfiles[right].id) == 0) return false;
    }
  }
  const TokenProfile *usdc = find_token_profile("eth-usdc");
  const TokenProfile *solana_usdc = find_token_profile("sol-usdc");
  return usdc != nullptr && token_supports_account_address(*usdc) && solana_usdc != nullptr &&
         !token_supports_account_address(*solana_usdc);
}

}  // namespace hexwallet
