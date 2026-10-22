#include "WalletTokens.h"

#include <string.h>

#include "base58.h"
#include "CryptoExtended.h"
#include "WalletAltAddresses.h"

namespace hexwallet {
namespace {

bool is_hex(char value) {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
         (value >= 'A' && value <= 'F');
}

bool valid_evm_contract(const char *contract) {
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
     "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"eth-usdt", "eth", "USDT", "Tether USD", TokenStandard::Erc20,
     "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"eth-dai", "eth", "DAI", "Dai Stablecoin", TokenStandard::Erc20,
     "0x6B175474E89094C44Da98b954EedeAC495271d0F", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"eth-wbtc", "eth", "WBTC", "Wrapped Bitcoin", TokenStandard::Erc20,
     "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", 8, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"bsc-usdt", "bsc", "USDT", "Binance-Peg BSC-USD", TokenStandard::Erc20,
     "0x55d398326f99059fF775485246999027B3197955", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"bsc-usdc", "bsc", "USDC", "Binance-Peg USD Coin", TokenStandard::Erc20,
     "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"bsc-busd", "bsc", "BUSD", "Binance USD", TokenStandard::Erc20,
     "0xe9e7CEA3Dedca5984780Bafc599bD69ADd087D56", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"matic-usdc", "matic", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x3c499c542cEF5E3811e1192ce70d8cc03d5c3359", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"arb-usdc", "arb1", "USDC", "USD Coin", TokenStandard::Erc20,
     "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"arb-usdt", "arb1", "USDT", "Tether USD", TokenStandard::Erc20,
     "0xfd086bC7CD5C481DCC9C85eFfA478A1C0b69FCbb", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"opt-usdc", "opt", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x7F5c764cBc14f9669B88837ca1490cCa17c31607", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"base-usdc", "base", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"avaxc-usdc", "avaxc", "USDC", "USD Coin", TokenStandard::Erc20,
     "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"sol-usdc", "sol", "USDC", "USD Coin", TokenStandard::Spl,
     "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", 6, TokenCapabilityAccountAddress,
     "SPL mint registered; associated token account address supported; transfer signing unavailable"},
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

bool token_supports_transfer_signing(const TokenProfile &token) {
  return token.standard != TokenStandard::Spl &&
         (token.capabilities & TokenCapabilityTransferSigning) != 0;
}

WalletError token_spl_account_address(const TokenProfile &token,
                                      const uint8_t owner_seed[32],
                                      char *out, size_t out_size) {
  if (token.standard != TokenStandard::Spl || owner_seed == nullptr ||
      out == nullptr || !token_supports_account_address(token)) {
    return WalletError::InvalidArgument;
  }
  uint8_t mint[32];
  size_t mint_size = sizeof(mint);
  if (!b58dec(mint, &mint_size, token.contract_or_mint,
              strlen(token.contract_or_mint)) ||
      mint_size != sizeof(mint)) {
    secure_zero(mint, sizeof(mint));
    return WalletError::InvalidArgument;
  }
  uint8_t owner[32];
  const bool derived = ed25519_public_key(owner_seed, owner);
  const WalletError result = derived
    ? address_solana_associated_token(owner, mint, out, out_size)
    : WalletError::CryptoFailure;
  secure_zero(owner, sizeof(owner));
  secure_zero(mint, sizeof(mint));
  return result;
}

const char *token_standard_text(TokenStandard standard) {
  switch (standard) {
    case TokenStandard::Erc20: return "ERC-20";
    case TokenStandard::Erc721: return "ERC-721";
    case TokenStandard::Erc1155: return "ERC-1155";
    case TokenStandard::Erc4626: return "ERC-4626";
    case TokenStandard::Erc777: return "ERC-777";
    case TokenStandard::Erc3525: return "ERC-3525";
    case TokenStandard::Erc6551: return "ERC-6551";
    case TokenStandard::LayerZeroOft: return "LayerZero OFT";
    case TokenStandard::LayerZeroOnft: return "LayerZero ONFT";
    case TokenStandard::Spl: return "SPL";
  }
  return "unknown";
}

EvmTokenStandard token_evm_standard(TokenStandard standard) {
  switch (standard) {
    case TokenStandard::Erc20: return EvmTokenStandard::Erc20;
    case TokenStandard::Erc721: return EvmTokenStandard::Erc721;
    case TokenStandard::Erc1155: return EvmTokenStandard::Erc1155;
    case TokenStandard::Erc4626: return EvmTokenStandard::Erc4626;
    case TokenStandard::Erc777: return EvmTokenStandard::Erc777;
    case TokenStandard::Erc3525: return EvmTokenStandard::Erc3525;
    case TokenStandard::Erc6551: return EvmTokenStandard::Erc6551;
    case TokenStandard::LayerZeroOft: return EvmTokenStandard::LayerZeroOft;
    case TokenStandard::LayerZeroOnft: return EvmTokenStandard::LayerZeroOnft;
    case TokenStandard::Spl: return EvmTokenStandard::Unknown;
  }
  return EvmTokenStandard::Unknown;
}

bool run_token_profile_self_tests() {
  for (size_t left = 0; left < kTokenProfileCount; ++left) {
    const TokenProfile &token = kTokenProfiles[left];
    if (token.id == nullptr || token.id[0] == '\0' || token.network_id == nullptr ||
        token.network_id[0] == '\0' || token.symbol == nullptr || token.symbol[0] == '\0' ||
        token.name == nullptr || token.name[0] == '\0' || token.contract_or_mint == nullptr ||
        token.contract_or_mint[0] == '\0' || token.status == nullptr || token.status[0] == '\0') return false;
    if (token.standard != TokenStandard::Spl) {
      if (!valid_evm_contract(token.contract_or_mint) ||
          !token_supports_account_address(token) ||
          !token_supports_transfer_signing(token) ||
          token_evm_standard(token.standard) == EvmTokenStandard::Unknown) {
        return false;
      }
    } else if (token.standard == TokenStandard::Spl) {
      if (!valid_spl_mint(token.contract_or_mint) ||
          !token_supports_account_address(token) ||
          token_supports_transfer_signing(token)) {
        return false;
      }
    } else {
      return false;
    }
    for (size_t right = left + 1; right < kTokenProfileCount; ++right) {
      if (strcmp(token.id, kTokenProfiles[right].id) == 0) return false;
    }
  }
  const TokenProfile *usdc = find_token_profile("eth-usdc");
  const TokenProfile *solana_usdc = find_token_profile("sol-usdc");
  if (usdc == nullptr || !token_supports_account_address(*usdc) ||
      solana_usdc == nullptr || !token_supports_account_address(*solana_usdc) ||
      token_supports_transfer_signing(*solana_usdc)) {
    return false;
  }
  static const uint8_t kOwnerSeed[32] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  };
  char account[64];
  const bool ata = token_spl_account_address(*solana_usdc, kOwnerSeed, account,
                                             sizeof(account)) == WalletError::Ok &&
                   strcmp(account, "3wvJdyFnGvaMWpbq93NU91SggiVRveULUXL6iX5VZDGP") == 0;
  secure_zero(account, sizeof(account));
  return ata;
}

}  // namespace hexwallet
