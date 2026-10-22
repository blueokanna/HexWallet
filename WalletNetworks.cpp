#include "WalletNetworks.h"
#include <string.h>

#include "WalletAltAddresses.h"

namespace hexwallet
{
  namespace
  {
    constexpr UtxoAddressProfile kUtxoBitcoin = {0x00, 0x05, "bc", false};
    constexpr UtxoAddressProfile kUtxoLitecoin = {0x30, 0x32, "ltc", false};
    constexpr UtxoAddressProfile kUtxoDogecoin = {0x1e, 0x16, nullptr, false};
    constexpr UtxoAddressProfile kUtxoDash = {0x4c, 0x10, nullptr, false};
    constexpr UtxoAddressProfile kUtxoBitcoinGold = {0x26, 0x17, "btg", false};
    constexpr UtxoAddressProfile kUtxoRavencoin = {0x3c, 0x7a, nullptr, false};
    constexpr UtxoAddressProfile kUtxoVertcoin = {0x47, 0x05, "vtc", false};
    constexpr UtxoAddressProfile kUtxoAxe = {0x8c, 0x13, "axe", false};
    constexpr UtxoAddressProfile kUtxoXrp = {0x00, 0x00, nullptr, true};
  } // namespace

  const NetworkProfile kNetworkProfiles[] = {
      // --- Bitcoin family ---------------------------------------------------
      {"btc", "BTC", "Bitcoin Native SegWit", 0, 0, 84, DerivationStyle::Bip44, AddressEncoding::P2wpkh, kUtxoBitcoin, 0, 0, 0, 0, nullptr},
      {"btc49", "BTC", "Bitcoin Nested SegWit", 0, 0, 49, DerivationStyle::Bip44, AddressEncoding::P2shP2wpkh, kUtxoBitcoin, 0, 0, 0, 0, nullptr},
      {"btc44", "BTC", "Bitcoin Legacy", 0, 0, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoBitcoin, 0, 0, 0, 0, nullptr},
      {"ltc", "LTC", "Litecoin Legacy", 2, 2, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoLitecoin, 0, 0, 0, 0, nullptr},
      {"ltc49", "LTC", "Litecoin Nested SegWit", 2, 2, 49, DerivationStyle::Bip44, AddressEncoding::P2shP2wpkh, kUtxoLitecoin, 0, 0, 0, 0, nullptr},
      {"ltc84", "LTC", "Litecoin Native SegWit", 2, 2, 84, DerivationStyle::Bip44, AddressEncoding::P2wpkh, kUtxoLitecoin, 0, 0, 0, 0, nullptr},
      {"doge", "DOGE", "Dogecoin", 3, 3, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoDogecoin, 0, 0, 0, 0, nullptr},
      {"dash", "DASH", "Dash", 5, 5, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoDash, 0, 0, 0, 0, nullptr},
      {"btg", "BTG", "Bitcoin Gold Legacy", 156, 156, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoBitcoinGold, 0, 0, 0, 0, nullptr},
      {"btg49", "BTG", "Bitcoin Gold Nested SegWit", 156, 156, 49, DerivationStyle::Bip44, AddressEncoding::P2shP2wpkh, kUtxoBitcoinGold, 0, 0, 0, 0, nullptr},
      {"btg84", "BTG", "Bitcoin Gold Native SegWit", 156, 156, 84, DerivationStyle::Bip44, AddressEncoding::P2wpkh, kUtxoBitcoinGold, 0, 0, 0, 0, nullptr},
      {"rvn", "RVN", "Ravencoin", 175, 175, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoRavencoin, 0, 0, 0, 0, nullptr},
      {"vtc", "VTC", "Vertcoin Legacy", 28, 28, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoVertcoin, 0, 0, 0, 0, nullptr},
      {"vtc49", "VTC", "Vertcoin Nested SegWit", 28, 28, 49, DerivationStyle::Bip44, AddressEncoding::P2shP2wpkh, kUtxoVertcoin, 0, 0, 0, 0, nullptr},
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
      {"rsk", "RBTC", "Rootstock", 137, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 30, 0, 0, nullptr},
      // --- Other existing chains ---------------------------------------------
      {"xrp", "XRP", "XRP Ledger", 144, 144, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, kUtxoXrp, 0, 0, 0, 0, nullptr},
      {"trx", "TRX", "TRON", 195, 195, 44, DerivationStyle::Bip44, AddressEncoding::Tron, {0, 0, nullptr, false}, 0x41, 0, 0, 0, nullptr},
      {"xmr", "XMR", "Monero", 128, 128, 44, DerivationStyle::Bip44, AddressEncoding::CryptoNote, {0, 0, nullptr, false}, 18, 0, 0, 0, nullptr, 19, 42, false},
      {"msr", "MSR", "Masari", 413, 413, 44, DerivationStyle::Bip44, AddressEncoding::CryptoNote, {0, 0, nullptr, false}, 28, 0, 0, 0, nullptr, 0, 0, false},
      // --- New multi-coin support (SLIP-0044) --------------------------------
      {"kas", "KAS", "Kaspa", 111111, 111111, 44, DerivationStyle::Bip44, AddressEncoding::KaspaBech32, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"zec", "ZEC", "Zcash (transparent)", 133, 133, 44, DerivationStyle::Bip44, AddressEncoding::ZcashTransparent, {0, 0, nullptr, false}, 0, 0, 0x1cb8, 0x1cbd, nullptr},
      {"flux", "FLUX", "Flux (transparent)", 19167, 19167, 44, DerivationStyle::Bip44, AddressEncoding::ZcashTransparent, {0, 0, nullptr, false}, 0, 0, 0x1cb8, 0x1cbd, nullptr},
      {"bch", "BCH", "Bitcoin Cash", 145, 145, 44, DerivationStyle::Bip44, AddressEncoding::CashAddr, {0, 0, nullptr, false}, 0, 0, 0, 0, "bitcoincash"},
      {"xec", "XEC", "eCash", 899, 899, 44, DerivationStyle::Bip44, AddressEncoding::CashAddr, {0, 0, nullptr, false}, 0, 0, 0, 0, "ecash"},
      {"bsv", "BSV", "Bitcoin SV", 236, 236, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, {0x00, 0x05, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"dgb", "DGB", "DigiByte Legacy", 20, 20, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, {0x1e, 0x3f, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"dgb49", "DGB", "DigiByte Nested SegWit", 20, 20, 49, DerivationStyle::Bip44, AddressEncoding::P2shP2wpkh, {0x1e, 0x3f, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"dgb84", "DGB", "DigiByte Native SegWit", 20, 20, 84, DerivationStyle::Bip44, AddressEncoding::P2wpkh, {0x1e, 0x3f, "dgb", false}, 0, 0, 0, 0, nullptr},
      {"ppc", "PPC", "Peercoin", 6, 6, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, {0x37, 0x75, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"nmc", "NMC", "Namecoin", 7, 7, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, {0x34, 0x0d, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"sol", "SOL", "Solana", 501, 501, 44, DerivationStyle::SolanaBip44, AddressEncoding::Ed25519Base58, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"algo", "ALGO", "Algorand", 283, 283, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::Ed25519Base32, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"xtz", "XTZ", "Tezos (tz1)", 1729, 1729, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::Ed25519Blake2bBase58, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"ada", "ADA", "Cardano", 1815, 1815, 1852, DerivationStyle::CardanoBip1852, AddressEncoding::Ed25519Blake2b224Bech32, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"qubic", "QUBIC", "Qubic", 83293, 83293, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::QubicBase26, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"croorg", "CRO", "Crypto.org Chain", 394, 394, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Cosmos, {0, 0, nullptr, false}, 0, 0, 0, 0, "cro"},
      {"atom", "ATOM", "Cosmos Hub", 118, 118, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Cosmos, {0, 0, nullptr, false}, 0, 0, 0, 0, "cosmos"},
      {"sei", "SEI", "SEI", 19000118, 19000118, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Cosmos, {0, 0, nullptr, false}, 0, 0, 0, 0, "sei"},
      {"avax", "AVAX", "Avalanche X/P Chain", 9000, 9000, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Avalanche, {0, 0, nullptr, false}, 0, 0, 0, 0, "avax"},
      {"fil", "FIL", "Filecoin", 461, 461, 44, DerivationStyle::Bip44, AddressEncoding::Blake2bBase32Filecoin, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"erg", "ERG", "Ergo", 429, 429, 44, DerivationStyle::Bip44, AddressEncoding::Blake2bBase58Ergo, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"xch", "XCH", "Chia", 8444, 8444, 12381, DerivationStyle::ChiaEip2333, AddressEncoding::Bech32mBlsChia, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"qrl", "QRL", "Quantum Resistant Ledger", 0, 0, 0, DerivationStyle::QrlXmss, AddressEncoding::QrlXmss, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr, 0, 0, true},
#include "WalletForkProfiles.inc"
  };

  const size_t kNetworkProfileCount = sizeof(kNetworkProfiles) / sizeof(kNetworkProfiles[0]);

  // A row here is a claim that the chains's consensus code accepts the sighash
  // this firmware produces for the listed address family.  Rows are added only
  // after a signed transaction from the chain's own reference wallet has been
  // reproduced bit-for-bit; an address profile alone never earns a row.
  const NetworkSigningPolicy kNetworkSigningPolicies[] = {
      {"btc", SighashFamily::Bitcoin, 0},
      {"btc49", SighashFamily::Bitcoin, 0},
      {"btc44", SighashFamily::Bitcoin, 0},
      {"ltc", SighashFamily::Bitcoin, 0},
      {"ltc49", SighashFamily::Bitcoin, 0},
      {"ltc84", SighashFamily::Bitcoin, 0},
      {"doge", SighashFamily::Bitcoin, 0},
      {"dash", SighashFamily::Bitcoin, 0},
      {"dgb", SighashFamily::Bitcoin, 0},
      {"dgb49", SighashFamily::Bitcoin, 0},
      {"dgb84", SighashFamily::Bitcoin, 0},
      {"btg", SighashFamily::Bitcoin, 0},
      {"btg49", SighashFamily::Bitcoin, 0},
      {"btg84", SighashFamily::Bitcoin, 0},
      {"ppc", SighashFamily::Bitcoin, 0},
      {"nmc", SighashFamily::Bitcoin, 0},
      {"vtc", SighashFamily::Bitcoin, 0},
      {"vtc49", SighashFamily::Bitcoin, 0},
      {"vtc84", SighashFamily::Bitcoin, 0},
      {"axe", SighashFamily::Bitcoin, 0},
      {"bch", SighashFamily::ForkId, 0},
      {"xec", SighashFamily::ForkId, 0},
      {"bsv", SighashFamily::ForkId, 0},
      // Source-verified Bitcoin-0.16 forks: standard legacy sighash and
      // BIP143 are inherited unchanged from their consensus code.
      {"fork_sugarchain", SighashFamily::Bitcoin, 0},
      {"fork_sugarchain84", SighashFamily::Bitcoin, 0},
      {"fork_sugarchain49", SighashFamily::Bitcoin, 0},
      {"fork_ravencoinclassic", SighashFamily::Bitcoin, 0},
      {"fork_ravencoinclassic49", SighashFamily::Bitcoin, 0},
  };

  const size_t kNetworkSigningPolicyCount =
      sizeof(kNetworkSigningPolicies) / sizeof(kNetworkSigningPolicies[0]);

  const NetworkSigningPolicy *find_network_signing_policy(const char *network_id)
  {
    if (network_id == nullptr)
      return nullptr;
    for (size_t index = 0; index < kNetworkSigningPolicyCount; ++index)
    {
      if (strcmp(kNetworkSigningPolicies[index].network_id, network_id) == 0)
        return &kNetworkSigningPolicies[index];
    }
    return nullptr;
  }

  const NetworkProfile *find_network_profile(const char *id)
  {
    if (id == nullptr)
      return nullptr;
    for (size_t index = 0; index < kNetworkProfileCount; ++index)
    {
      if (strcmp(kNetworkProfiles[index].id, id) == 0)
        return &kNetworkProfiles[index];
    }
    return nullptr;
  }

  bool network_supports_token_accounts(const NetworkProfile &network)
  {
    return (network.encoding == AddressEncoding::Evm && network.evm_chain_id != 0) ||
           network.encoding == AddressEncoding::Ed25519Base58;
  }

  bool run_network_profile_self_tests()
  {
    for (size_t left = 0; left < kNetworkProfileCount; ++left)
    {
      const NetworkProfile &network = kNetworkProfiles[left];
      if (network.id == nullptr || network.id[0] == '\0' || network.symbol == nullptr || network.symbol[0] == '\0' || network.name == nullptr || network.name[0] == '\0' || network.bip_purpose >= kHardenedOffset || network.slip44_coin_type >= kHardenedOffset || network.derivation_coin_type >= kHardenedOffset)
        return false;
      if (network.encoding == AddressEncoding::Evm)
      {
        const uint32_t expected_derivation_type = strcmp(network.id, "etc") == 0 ? 61 : 60;
        if (network.derivation_coin_type != expected_derivation_type || network.evm_chain_id == 0)
        {
          return false;
        }
      }
      else if (network.evm_chain_id != 0)
      {
        return false;
      }
      if (network.encoding == AddressEncoding::CryptoNote && network.account_version == 0)
        return false;
      if (network.encoding == AddressEncoding::CryptoNote &&
          ((network.cryptonote_integrated_prefix == 0) !=
           (network.cryptonote_subaddress_prefix == 0)))
      {
        return false;
      }
      if (network.encoding == AddressEncoding::QrlXmss && !network.explicit_only_derivation)
        return false;
      if ((network.encoding == AddressEncoding::ZcashTransparent) && (network.alt_p2pkh_version == 0 || network.alt_p2sh_version == 0))
        return false;
      if (network.encoding == AddressEncoding::CashAddr && network.alt_hrp == nullptr)
        return false;
      if (network.encoding == AddressEncoding::Bech32Cosmos && network.alt_hrp == nullptr)
        return false;
      if (network.encoding == AddressEncoding::Bech32Avalanche && network.alt_hrp == nullptr)
        return false;
      if (network.encoding == AddressEncoding::P2wpkh && network.utxo.bech32_hrp == nullptr)
        return false;
      for (size_t right = left + 1; right < kNetworkProfileCount; ++right)
      {
        const NetworkProfile &candidate = kNetworkProfiles[right];
        if (strcmp(network.id, candidate.id) == 0)
          return false;
        if (network.encoding == AddressEncoding::Evm && candidate.encoding == AddressEncoding::Evm && network.evm_chain_id == candidate.evm_chain_id)
          return false;
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
    const NetworkProfile *qrl = find_network_profile("qrl");
    const uint8_t test_public_key[kCompressedPublicKeySize] = {
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
        0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
        0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
    char test_address[128];
    size_t test_size = sizeof(test_address);
    const NetworkProfile *adcoin = find_network_profile("fork_adcoin");
    const NetworkProfile *anon = find_network_profile("fork_anon");
    const NetworkProfile *digibyte = find_network_profile("dgb");
    const NetworkProfile *cosmos = find_network_profile("atom");
    if (adcoin == nullptr || address_p2pkh(adcoin->utxo, test_public_key,
                                          test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "AST9CekEhDWuxHPynRmeyjg5biNFSijvb3") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (anon == nullptr || address_zcash_transparent(anon->alt_p2pkh_version,
                                                     anon->alt_p2sh_version,
                                                     test_public_key, test_address,
                                                     &test_size) != WalletError::Ok ||
        strcmp(test_address, "AnYEktGAqUSEAGTn8jKkhZeCFZNibUjnYxN") != 0) {
      return false;
    }
    const NetworkProfile *sugar = find_network_profile("fork_sugarchain");
    const NetworkProfile *sugar84 = find_network_profile("fork_sugarchain84");
    const NetworkProfile *sugar49 = find_network_profile("fork_sugarchain49");
    const NetworkProfile *rvc = find_network_profile("fork_ravencoinclassic");
    const NetworkProfile *rvc49 = find_network_profile("fork_ravencoinclassic49");
    test_size = sizeof(test_address);
    if (sugar == nullptr || address_p2pkh(sugar->utxo, test_public_key,
                                          test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "SXyGazfm6S3xfcySmD6QNkZYmtfysC2jvc") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (sugar49 == nullptr || address_p2sh_p2wpkh(sugar49->utxo, test_public_key,
                                                  test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "sbUiFaYTL16erD6g8Tmkf9SkApHVf8vGjP") != 0) {
      return false;
    }
    if (sugar84 == nullptr ||
        address_p2wpkh(sugar84->utxo, test_public_key, test_address,
                       sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address,
               "sugar1qw508d6qejxtdg4y5r3zarvary0c5xw7kjjlkp2") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (rvc == nullptr || address_p2pkh(rvc->utxo, test_public_key,
                                        test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "RKxTdfmtxtfLDKZBgx6SvNkBtNu9jRYnLh") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (rvc49 == nullptr || address_p2sh_p2wpkh(rvc49->utxo, test_public_key,
                                                test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "rPTuJFebCTi2PugR4CmoCmdPHJWfVh28Ha") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (digibyte == nullptr || address_p2pkh(digibyte->utxo, test_public_key,
                                             test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE") != 0) {
      return false;
    }
    const NetworkProfile *litecoin = find_network_profile("ltc");
    const NetworkProfile *litecoin49 = find_network_profile("ltc49");
    const NetworkProfile *litecoin84 = find_network_profile("ltc84");
    const NetworkProfile *digibyte49 = find_network_profile("dgb49");
    const NetworkProfile *digibyte84 = find_network_profile("dgb84");
    const NetworkProfile *bitcoin_gold = find_network_profile("btg");
    const NetworkProfile *bitcoin_gold49 = find_network_profile("btg49");
    const NetworkProfile *bitcoin_gold84 = find_network_profile("btg84");
    const NetworkProfile *vertcoin49 = find_network_profile("vtc49");
    const NetworkProfile *vertcoin84 = find_network_profile("vtc84");
    test_size = sizeof(test_address);
    if (litecoin == nullptr || address_p2pkh(litecoin->utxo, test_public_key,
                                             test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (litecoin49 == nullptr || address_p2sh_p2wpkh(litecoin49->utxo, test_public_key,
                                                     test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "MR8UQSBr5ULwWheBHznrHk2jxyxkHQu8vB") != 0) {
      return false;
    }
    if (litecoin84 == nullptr ||
        address_p2wpkh(litecoin84->utxo, test_public_key, test_address,
                       sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (digibyte49 == nullptr || address_p2sh_p2wpkh(digibyte49->utxo, test_public_key,
                                                     test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "SeXKCr4bJpNL9LTJcT7zbNZy9YK1Vihyox") != 0) {
      return false;
    }
    if (digibyte84 == nullptr ||
        address_p2wpkh(digibyte84->utxo, test_public_key, test_address,
                       sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "dgb1qw508d6qejxtdg4y5r3zarvary0c5xw7kmudfnm") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (bitcoin_gold == nullptr || address_p2pkh(bitcoin_gold->utxo, test_public_key,
                                                 test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (bitcoin_gold49 == nullptr ||
        address_p2sh_p2wpkh(bitcoin_gold49->utxo, test_public_key, test_address,
                            &test_size) != WalletError::Ok ||
        strcmp(test_address, "AZ1BpW94ubqHRzsqdfoFCMgVyN1H4CnSEp") != 0) {
      return false;
    }
    if (bitcoin_gold84 == nullptr ||
        address_p2wpkh(bitcoin_gold84->utxo, test_public_key, test_address,
                       sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "btg1qw508d6qejxtdg4y5r3zarvary0c5xw7k6w057a") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (vertcoin49 == nullptr || address_p2sh_p2wpkh(vertcoin49->utxo, test_public_key,
                                                     test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN") != 0) {
      return false;
    }
    if (vertcoin84 == nullptr ||
        address_p2wpkh(vertcoin84->utxo, test_public_key, test_address,
                       sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "vtc1qw508d6qejxtdg4y5r3zarvary0c5xw7kuk9r06") != 0) {
      return false;
    }
    const NetworkProfile *peercoin = find_network_profile("ppc");
    const NetworkProfile *namecoin = find_network_profile("nmc");
    const NetworkProfile *bitcoin_sv = find_network_profile("bsv");
    test_size = sizeof(test_address);
    if (peercoin == nullptr || address_p2pkh(peercoin->utxo, test_public_key,
                                              test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (namecoin == nullptr || address_p2pkh(namecoin->utxo, test_public_key,
                                              test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "N7FdkoPbHSxKfrSVVbRu3NZtrLqc1oKpAR") != 0) {
      return false;
    }
    test_size = sizeof(test_address);
    if (bitcoin_sv == nullptr || address_p2pkh(bitcoin_sv->utxo, test_public_key,
                                               test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") != 0) {
      return false;
    }
    if (cosmos == nullptr || cosmos->alt_hrp == nullptr ||
        address_cosmos_bech32(cosmos->alt_hrp, test_public_key, test_address,
                              sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c") != 0) {
      return false;
    }
    for (size_t index = 0; index < kNetworkProfileCount; ++index) {
      const NetworkProfile &network = kNetworkProfiles[index];
      test_size = sizeof(test_address);
      if (network.encoding == AddressEncoding::P2pkh &&
          address_p2pkh(network.utxo, test_public_key, test_address,
                        &test_size) != WalletError::Ok) {
        return false;
      }
      if (network.encoding == AddressEncoding::ZcashTransparent &&
          address_zcash_transparent(network.alt_p2pkh_version,
                                    network.alt_p2sh_version, test_public_key,
                                    test_address, &test_size) != WalletError::Ok) {
        return false;
      }
      if (network.encoding == AddressEncoding::Bech32Cosmos &&
          address_cosmos_bech32(network.alt_hrp, test_public_key, test_address,
                                sizeof(test_address)) != WalletError::Ok) {
        return false;
      }
    }
    for (size_t index = 0; index < kNetworkSigningPolicyCount; ++index) {
      const NetworkSigningPolicy &policy = kNetworkSigningPolicies[index];
      const NetworkProfile *network = find_network_profile(policy.network_id);
      if (network == nullptr || policy.family == SighashFamily::None) return false;
      const bool utxo_family = network->encoding == AddressEncoding::P2pkh ||
                               network->encoding == AddressEncoding::P2shP2wpkh ||
                               network->encoding == AddressEncoding::P2wpkh;
      const bool cashaddr_family = network->encoding == AddressEncoding::CashAddr &&
                                   network->alt_hrp != nullptr;
      if (!utxo_family && !cashaddr_family) return false;
      if (policy.family == SighashFamily::ForkId) {
        const bool p2pkh = network->encoding == AddressEncoding::P2pkh;
        if (!p2pkh && !cashaddr_family) return false;
      } else if (cashaddr_family) {
        return false;
      }
      for (size_t other = index + 1; other < kNetworkSigningPolicyCount; ++other) {
        if (strcmp(kNetworkSigningPolicies[other].network_id, policy.network_id) == 0) {
          return false;
        }
      }
    }
    return ethereum != nullptr && ethereum->evm_chain_id == 1 && ethereum_classic != nullptr && ethereum_classic->derivation_coin_type == 61 && ethereum_classic->evm_chain_id == 61 && bsc != nullptr && bsc->derivation_coin_type == 60 && bsc->evm_chain_id == 56 && monero != nullptr && monero->account_version == 18 && monero->cryptonote_integrated_prefix == 19 && monero->cryptonote_subaddress_prefix == 42 && masari != nullptr && masari->account_version == 28 && masari->cryptonote_subaddress_prefix == 0 && kaspa != nullptr && kaspa->slip44_coin_type == 111111 && algorand != nullptr && algorand->slip44_coin_type == 283 && solana != nullptr && solana->slip44_coin_type == 501 && chia != nullptr && chia->slip44_coin_type == 8444 && chia->bip_purpose == 12381 && qrl != nullptr && qrl->encoding == AddressEncoding::QrlXmss && qrl->explicit_only_derivation;
  }

} // namespace hexwallet
