#include "WalletTokens.h"

#include <string.h>

#include "base58.h"

namespace hexwallet {
namespace {

// TRC-10 identifiers are capped at 32 bytes by the chain. Mirrors
// TronTransaction's kTronAssetIdSize without pulling that module in here.
constexpr size_t kTrc10IdMaxLength = 32;

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
    {"bsc-usdt", "bsc", "USDT", "Binance-Peg BSC-USD", TokenStandard::Bep20,
     "0x55d398326f99059fF775485246999027B3197955", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"bsc-usdc", "bsc", "USDC", "Binance-Peg USD Coin", TokenStandard::Bep20,
     "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 account address and transfer signing supported"},
    {"bsc-busd", "bsc", "BUSD", "Binance USD", TokenStandard::Bep20,
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
    {"bsc-dai", "bsc", "DAI", "Dai Stablecoin", TokenStandard::Bep20,
     "0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "ERC-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-btcb", "bsc", "BTCB", "Bitcoin BEP2", TokenStandard::Bep20,
     "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-eth", "bsc", "ETH", "Ethereum Token", TokenStandard::Bep20,
     "0x2170Ed0880ac9A755fd29B2688956BD959F933F8", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    // BEP-20 set verified by eth_call(symbol, decimals) against
    // https://bsc-dataseed.binance.org on 2026-10-28. CAKE reports the
    // on-chain symbol "Cake"; the registry keeps the canonical ticker.
    {"bsc-wbnb", "bsc", "WBNB", "Wrapped BNB", TokenStandard::Bep20,
     "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-cake", "bsc", "CAKE", "PancakeSwap Token", TokenStandard::Bep20,
     "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol Cake, decimals 18"},
    {"bsc-fdusd", "bsc", "FDUSD", "First Digital USD", TokenStandard::Bep20,
     "0xc5f0f7b66764F6ec8C8Dff7BA683102295E16409", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-tusd", "bsc", "TUSD", "TrueUSD", TokenStandard::Bep20,
     "0x40af3827F39D0eACBF4A168f8D4ee67c121D11c9", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-link", "bsc", "LINK", "ChainLink Token", TokenStandard::Bep20,
     "0xF8A0BF9cF54Bb92F17374d9e9A321E6a111a51bD", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-dot", "bsc", "DOT", "Polkadot Token", TokenStandard::Bep20,
     "0x7083609fCE4d1d8Dc0C979AAb8c869Ea2C873402", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-ada", "bsc", "ADA", "Binance-Peg Cardano Token", TokenStandard::Bep20,
     "0x3EE2200Efb3400fAbB9AacF31297cBdD1d435D47", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-xrp", "bsc", "XRP", "Binance-Peg XRP Token", TokenStandard::Bep20,
     "0x1D2F0da169ceB9fC7B3144628dB156f3F6c60dBE", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-doge", "bsc", "DOGE", "Binance-Peg Dogecoin", TokenStandard::Bep20,
     "0xbA2aE424d960c26247Dd6c32edC70B295c744C43", 8, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-shib", "bsc", "SHIB", "Shiba Inu", TokenStandard::Bep20,
     "0x2859e4544C4bB03966803b044A93563Bd2D0DD4D", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-uni", "bsc", "UNI", "Uniswap", TokenStandard::Bep20,
     "0xBf5140A22578168FD562DCcF235E5D43A02ce9B1", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-aave", "bsc", "AAVE", "Aave Token", TokenStandard::Bep20,
     "0xfb6115445Bff7b52FeB98650C87f44907E58f802", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-atom", "bsc", "ATOM", "Cosmos Token", TokenStandard::Bep20,
     "0x0Eb3a705fc54725037CC9e008bDede697f62F335", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-xvs", "bsc", "XVS", "Venus", TokenStandard::Bep20,
     "0xcF6BB5389c92Bdda8a3747Ddb454cB7a64626C63", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-bsw", "bsc", "BSW", "Biswap", TokenStandard::Bep20,
     "0x965F527D9159dCe6288a2219DB51fc6Eef120dD1", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-ankr", "bsc", "ANKR", "Ankr", TokenStandard::Bep20,
     "0xf307910A4c7bbc79691fD374889b36d8531B08e3", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-comp", "bsc", "COMP", "Compound", TokenStandard::Bep20,
     "0x52CE071Bd9b1C4B00A0b92D298c512478CaD67e8", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-beth", "bsc", "BETH", "Binance Beacon ETH", TokenStandard::Bep20,
     "0x250632378E573c6Be1AC2f97Fcdf00515d0Aa91B", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-avax", "bsc", "AVAX", "Binance-Peg Avalanche Token", TokenStandard::Bep20,
     "0x1CE0c2827e2eF14D5C4f29a091d735A204794041", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "BEP-20 transfer; on-chain symbol/decimals verified via BSC RPC"},
    {"bsc-pendle", "bsc", "PENDLE", "Pendle", TokenStandard::Bep20,
     "0xb3Ed0A426155B79B898849803E3B36552f7ED507", 18, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
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
    // TRC-10 has no contract address: the chain keys the asset by a numeric id
    // that its issuance record mirrors. Id, abbr and precision below were read
    // back from that record with wallet/getassetissuebyid. A TRC-10 transfer
    // still signs when the id is unregistered; it then renders the exact base
    // units instead of an issuer-defined decimal place.
    {"trx-btt-trc10", "trx", "BTT", "BitTorrent", TokenStandard::Trc10,
     "1002000", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "TRC-10 transfer; id and precision verified via TronGrid getassetissuebyid"},
    {"trx-jst-trc10", "trx", "JST", "JUST", TokenStandard::Trc10,
     "1003000", 6, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "TRC-10 transfer; id and precision verified via TronGrid getassetissuebyid"},
    {"trx-seed-trc10", "trx", "SEED", "SEED", TokenStandard::Trc10,
     "1000001", 0, TokenCapabilityAccountAddress | TokenCapabilityTransferSigning,
     "TRC-10 transfer; id and precision verified via TronGrid getassetissuebyid"},
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
    case TokenStandard::Bep20: return "BEP-20";
    case TokenStandard::Erc721: return "ERC-721";
    case TokenStandard::Erc1155: return "ERC-1155";
    case TokenStandard::Erc4626: return "ERC-4626";
    case TokenStandard::Erc777: return "ERC-777";
    case TokenStandard::Erc3525: return "ERC-3525";
    case TokenStandard::Erc6551: return "ERC-6551";
    case TokenStandard::LayerZeroOft: return "LayerZero OFT";
    case TokenStandard::LayerZeroOnft: return "LayerZero ONFT";
    case TokenStandard::Trc20: return "TRC-20";
    case TokenStandard::Trc10: return "TRC-10";
  }
  return "unknown";
}

EvmTokenStandard token_evm_standard(TokenStandard standard) {
  switch (standard) {
    case TokenStandard::Erc20: return EvmTokenStandard::Erc20;
    // BEP-20 is the BSC deployment of the ERC-20 ABI. It is kept as a distinct
    // display label but uses the exact same transfer/balance calldata path.
    case TokenStandard::Bep20: return EvmTokenStandard::Erc20;
    case TokenStandard::Erc721: return EvmTokenStandard::Erc721;
    case TokenStandard::Erc1155: return EvmTokenStandard::Erc1155;
    case TokenStandard::Erc4626: return EvmTokenStandard::Erc4626;
    case TokenStandard::Erc777: return EvmTokenStandard::Erc777;
    case TokenStandard::Erc3525: return EvmTokenStandard::Erc3525;
    case TokenStandard::Erc6551: return EvmTokenStandard::Erc6551;
    case TokenStandard::LayerZeroOft: return EvmTokenStandard::LayerZeroOft;
    case TokenStandard::LayerZeroOnft: return EvmTokenStandard::LayerZeroOnft;
    // TRC-20/TRC-10 are not EVM ABI profiles; TronTransaction reviews them.
    case TokenStandard::Trc20: return EvmTokenStandard::Unknown;
    case TokenStandard::Trc10: return EvmTokenStandard::Unknown;
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
    } else if (token.standard == TokenStandard::Trc10) {
      // The chain-assigned id is a canonical decimal string; anything else
      // would never match the bytes a node resolves.
      const NetworkProfile *network = token_network(token);
      const size_t length = strlen(token.contract_or_mint);
      if (network == nullptr || network->encoding != AddressEncoding::Tron ||
          length == 0 || length > kTrc10IdMaxLength ||
          token.contract_or_mint[0] < '1' || token.contract_or_mint[0] > '9') {
        return false;
      }
      for (size_t index = 1; index < length; ++index) {
        if (token.contract_or_mint[index] < '0' ||
            token.contract_or_mint[index] > '9') {
          return false;
        }
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
