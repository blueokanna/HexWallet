#include "WalletTokens.h"

#include <string.h>

#include "base58.h"

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

}  // namespace

const TokenProfile kTokenProfiles[] = {
    {"eth-lsk", "eth", "LSK", "Lisk", TokenStandard::Erc20,
     "0x6033F7f88332B8db6ad452B7C6D5bB643990aE3f", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "Ethereum LSK ERC-20 transfer; not legacy Lisk L1 or Lisk Chain bridge withdrawal"},
    {"xlayer-usdt0", "xlayer", "USDT0", "USDT0", TokenStandard::Erc20,
     "0x779Ded0c9e1022225f8E0630b35a9b54bE713736", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "USDT0 deployment; same-chain ERC-20 transfer only"},
    {"monad-usdt0", "monad", "USDT0", "USDT0", TokenStandard::Erc20,
     "0xe7cd86e13AC4309349F30B3435a9d337750fC82D", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "USDT0 deployment; same-chain ERC-20 transfer only"},
    {"plasma-usdt0", "plasma", "USDT0", "USDT0", TokenStandard::Erc20,
     "0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "USDT0 deployment; same-chain ERC-20 transfer only"},
    {"bera-usdt0", "bera", "USDT0", "USDT0", TokenStandard::Erc20,
     "0x779Ded0c9e1022225f8E0630b35a9b54bE713736", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "USDT0 deployment; same-chain ERC-20 transfer only"},
    {"opt-usdt0", "opt", "USDT0", "USDT0", TokenStandard::Erc20,
     "0x01bFF41798a0BcF287b996046Ca68b395DbC1071", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "USDT0 deployment; same-chain ERC-20 transfer only"},
    {"unichain-usdt0", "unichain", "USDT0", "USDT0", TokenStandard::Erc20,
     "0x9151434b16b9763660705744891fA906F660EcC5", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "USDT0 deployment; same-chain ERC-20 transfer only"},
    {"opt-usdc-native", "opt", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "Registered ERC-20 transfer; network-bound contract review required"},
    {"matic-usdc-e", "matic", "USDC.e", "Bridged USD Coin", TokenStandard::Erc20,
     "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "Registered ERC-20 transfer; network-bound contract review required"},
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
     "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"opt-usdc", "opt", "USDC.e", "Bridged USD Coin", TokenStandard::Erc20,
     "0x7F5c764cBc14f9669B88837ca1490cCa17c31607", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"base-usdc", "base", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"avaxc-usdc", "avaxc", "USDC", "USD Coin", TokenStandard::Erc20,
     "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    // USDC deployments below are taken from Circle's published
    // usdc-contract-addresses table; every EVM deployment uses 6 decimals.
    {"unichain-usdc", "unichain", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x078D782b760474a361dDA0AF3839290b0EF57AD6", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; address from Circle USDC contract table"},
    {"monad-usdc", "monad", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x754704Bc059F8C67012fEd69BC8A327a5aafb603", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; address from Circle USDC contract table"},
    {"plasma-usdc", "plasma", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x2d661C89D812261039AF9764eceaAee884f5F67F", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; address from Circle USDC contract table"},
    {"xlayer-usdc", "xlayer", "USDC", "USD Coin", TokenStandard::Erc20,
     "0xB6CEceAB302E2E4948951eE7843FC24E92933061", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; address from Circle USDC contract table"},
    {"zksync-usdc", "zksync", "USDC", "USD Coin", TokenStandard::Erc20,
     "0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; address from Circle USDC contract table"},
    {"eth-xaut", "eth", "XAUT", "Tether Gold", TokenStandard::Erc20,
     "0x68749665FF8D2d112Fa859AA293F07A622782F38", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; address from Tether supported-protocols table, symbol/decimals verified on-chain"},
    {"eth-paxg", "eth", "PAXG", "PAX Gold", TokenStandard::Erc20,
     "0x45804880De22913dAFE09f4980848ECE6EcbAf78", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; Paxos contract, symbol/decimals verified on-chain"},
    {"eth-mana", "eth", "MANA", "Decentraland", TokenStandard::Erc20,
     "0x0F5D2fB29fb7d3CFeE444a200298f468908cC942", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; Decentraland contract, symbol/decimals verified on-chain"},
    {"matic-mana", "matic", "MANA", "Decentraland", TokenStandard::Erc20,
     "0xA1c57f48F0Deb89f569dFbE6E2B7f46D33606fD4", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer on Polygon; symbol/decimals verified on-chain"},
    // Polygon's 0xc2132… contract now reports the on-chain symbol USDT0, not
    // USDT. Registering it as USDT would misstate the asset.
    {"matic-usdt0", "matic", "USDT0", "USDT0", TokenStandard::Erc20,
     "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; on-chain symbol/decimals verified via Polygon RPC"},
    {"matic-dai", "matic", "DAI", "Dai Stablecoin", TokenStandard::Erc20,
     "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; on-chain symbol/decimals verified via Polygon RPC"},
    {"bsc-dai", "bsc", "DAI", "Dai Stablecoin", TokenStandard::Erc20,
     "0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-btcb", "bsc", "BTCB", "Bitcoin BEP2", TokenStandard::Erc20,
     "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-eth", "bsc", "ETH", "Ethereum Token", TokenStandard::Erc20,
     "0x2170Ed0880ac9A755fd29B2688956BD959F933F8", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"arb-dai", "arb1", "DAI", "Dai Stablecoin", TokenStandard::Erc20,
     "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; on-chain symbol/decimals verified via Arbitrum RPC"},
    {"avaxc-usdt", "avaxc", "USDT", "Tether USD", TokenStandard::Erc20,
     "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; on-chain symbol/decimals verified via Avalanche RPC"},
    {"opt-usdt", "opt", "USDT", "Tether USD", TokenStandard::Erc20,
     "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; on-chain symbol/decimals verified via Optimism RPC"},
    {"kaia-usdt", "kaia", "USDT", "Tether USD", TokenStandard::Erc20,
     "0xd077a400968890eacc75cdc901f0356c943e4fdb", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; on-chain symbol/decimals verified via Kaia RPC"},
    {"celo-usdt", "celo", "USDT", "Tether USD", TokenStandard::Erc20,
     "0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; on-chain symbol/decimals verified via Celo RPC"},
    // TRC-20 entries are reviewed by TronTransaction, not by the EVM ABI path.
    // Contract identity and decimals come from Tether's published protocol
    // table; an unregistered TRC-20 contract is refused.
    {"trx-usdt", "trx", "USDT", "Tether USD", TokenStandard::Trc20,
     "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "TRC-20 transfer; contract verified against Tether supported-protocols table"},
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
  return (token.capabilities & TokenCapabilityTransferSigning) != 0;
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
    case TokenStandard::Trc20: return "TRC-20";
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
    // TRC-20 is not an EVM ABI profile; it is reviewed by TronTransaction.
    case TokenStandard::Trc20: return EvmTokenStandard::Unknown;
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
    if (token.standard == TokenStandard::Trc20) {
      const NetworkProfile *network = token_network(token);
      uint8_t decoded[32] = {};
      size_t decoded_size = sizeof(decoded);
      if (network == nullptr || network->encoding != AddressEncoding::Tron ||
          !b58check_dec(decoded, &decoded_size, token.contract_or_mint) ||
          decoded_size != 21 || decoded[0] != 0x41) {
        return false;
      }
    } else if (!valid_evm_contract(token.contract_or_mint) ||
               token_evm_standard(token.standard) == EvmTokenStandard::Unknown) {
      return false;
    }
    if (!token_supports_account_address(token) ||
        !token_supports_transfer_signing(token)) {
      return false;
    }
    for (size_t right = left + 1; right < kTokenProfileCount; ++right) {
      if (strcmp(token.id, kTokenProfiles[right].id) == 0) return false;
    }
  }
  const TokenProfile *usdc = find_token_profile("eth-usdc");
  return usdc != nullptr && token_supports_account_address(*usdc) &&
         token_supports_transfer_signing(*usdc);
}

}
