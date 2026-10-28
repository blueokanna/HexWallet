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

#if defined(HEXWALLET_HOST_TEST)
    struct ForkAddressVector
    {
      const char *id;
      const char *address;
    };

    const ForkAddressVector kForkAddressVectors[] = {
#include "tests/fixtures/WalletForkAddressVectorsTest.inc"
    };
#endif
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
      // Official network references and supported envelopes: docs/evm-network-evidence.md.
      {"xlayer", "OKB", "X Layer", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 196, 0, 0, nullptr},
      {"zksync", "ETH", "zkSync Era", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 324, 0, 0, nullptr},
      {"eth", "ETH", "Ethereum", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1, 0, 0, nullptr},
      {"etc", "ETC", "Ethereum Classic", 61, 61, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 61, 0, 0, nullptr},
      {"cro", "CRO", "Cronos", 394, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 25, 0, 0, nullptr},
      {"kava", "KAVA", "Kava EVM", 459, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 2222, 0, 0, nullptr},
      {"opt", "OPT", "Optimism", 614, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 10, 0, 0, nullptr},
      {"xdai", "XDAI", "Gnosis Chain", 700, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 100, 0, 0, nullptr},
      {"matic", "MATIC", "Polygon", 966, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 137, 0, 0, nullptr},
      {"ftm", "FTM", "Fantom", 1007, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 250, 0, 0, nullptr},
      {"core", "CORE", "Core", 1116, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1116, 0, 0, nullptr},
      // Conflux eSpace mainnet chain id 1030 (doc.confluxnetwork.org/docs/espace/network-endpoints).
      // SLIP-0044 coin type 503, matching the official Conflux Ledger app path m/44'/503'/...
      {"cfx", "CFX", "Conflux eSpace", 503, 503, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1030, 0, 0, nullptr},
      {"glmr", "GLMR", "Moonbeam", 1284, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1284, 0, 0, nullptr},
      {"movr", "MOVR", "Moonriver", 1285, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1285, 0, 0, nullptr},
      {"base", "BASE", "Base", 8453, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 8453, 0, 0, nullptr},
      {"arb1", "ARB1", "Arbitrum One", 9001, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 42161, 0, 0, nullptr},
      {"avaxc", "AVAXC", "Avalanche C-Chain", 9005, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 43114, 0, 0, nullptr},
      {"bsc", "BSC", "Binance Smart Chain", 9006, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 56, 0, 0, nullptr},
      {"celo", "CELO", "Celo", 52752, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 42220, 0, 0, nullptr},
      {"rsk", "RBTC", "Rootstock", 137, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 30, 0, 0, nullptr},
      {"linea", "ETH", "Linea", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 59144, 0, 0, nullptr},
      {"scroll", "ETH", "Scroll", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 534352, 0, 0, nullptr},
      {"blast", "ETH", "Blast", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 81457, 0, 0, nullptr},
      {"mantle", "MNT", "Mantle", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 5000, 0, 0, nullptr},
      {"opbnb", "BNB", "opBNB", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 204, 0, 0, nullptr},
      {"zkevm", "ETH", "Polygon zkEVM", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1101, 0, 0, nullptr},
      {"aurora", "ETH", "Aurora", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1313161554, 0, 0, nullptr},
      {"metis", "METIS", "Metis Andromeda", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1088, 0, 0, nullptr},
      {"kaia", "KAIA", "Kaia", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 8217, 0, 0, nullptr},
      {"astar", "ASTR", "Astar", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 592, 0, 0, nullptr},
      {"canto", "CANTO", "Canto", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 7700, 0, 0, nullptr},
      {"dogechain", "DOGE", "Dogechain EVM", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 2000, 0, 0, nullptr},
      {"fuse", "FUSE", "Fuse", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 122, 0, 0, nullptr},
      {"evmos", "EVMOS", "Evmos EVM", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 9001, 0, 0, nullptr},
      {"harmony", "ONE", "Harmony EVM", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1666600000, 0, 0, nullptr},
      {"telos", "TLOS", "Telos EVM", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 40, 0, 0, nullptr},
      {"seievm", "SEI", "Sei EVM", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1329, 0, 0, nullptr},
      {"ethw", "ETHW", "EthereumPoW", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 10001, 0, 0, nullptr},
      {"clo", "CLO", "Callisto Network", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 820, 0, 0, nullptr},
      {"etho", "ETHO", "Etho Protocol", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 1313114, 0, 0, nullptr},
      {"octa", "OCTA", "OctaSpace", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 800001, 0, 0, nullptr},
      {"egaz", "EGAZ", "Etica", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 61803, 0, 0, nullptr},
      {"avs", "AVS", "Aves", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 33333, 0, 0, nullptr},
      {"cau", "CAU", "Canxium", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 3003, 0, 0, nullptr},
      {"btn", "BTN", "Bitnet", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 210, 0, 0, nullptr},
      {"lrs", "LRS", "Larissa Chain", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 9898, 0, 0, nullptr},
      {"vbc", "VBC", "VirBiCoin", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 329, 0, 0, nullptr},
      // Chain IDs below are from the chains' own network-information pages
      // (Uniswap Unichain docs, Monad docs, Plasma docs, Berachain docs,
      // Circle Arc docs). Derivation stays on coin type 60, except where the
      // chain publishes its own SLIP-44 path.
      {"unichain", "ETH", "Unichain", 130, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 130, 0, 0, nullptr},
      {"monad", "MON", "Monad", 143, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 143, 0, 0, nullptr},
      {"plasma", "XPL", "Plasma", 9745, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 9745, 0, 0, nullptr},
      {"bera", "BERA", "Berachain", 80094, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 80094, 0, 0, nullptr},
      // Arc uses USDC as its native gas token with 18 decimals; the native EVM
      // value path already renders 18 decimals, so no token row is registered.
      {"arc", "USDC", "Arc", 5042, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 5042, 0, 0, nullptr},
      // EIP-155 registrations from chainid.network (chainlist): X Layer 196,
      // zkSync Era 324, OKT Chain 66. Token rows are only added where the
      // issuer publishes the contract (Circle USDC table below).
      {"okt", "OKT", "OKT Chain", 66, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 66, 0, 0, nullptr},
      // --- Other existing chains ---------------------------------------------
      {"xrp", "XRP", "XRP Ledger", 144, 144, 44, DerivationStyle::Bip44, AddressEncoding::Ripple, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"trx", "TRX", "TRON", 195, 195, 44, DerivationStyle::Bip44, AddressEncoding::Tron, {0, 0, nullptr, false}, 0x41, 0, 0, 0, nullptr},
      {"xlm", "XLM", "Stellar", 148, 148, 44, DerivationStyle::StellarSep5, AddressEncoding::StellarStrKey, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"xmr", "XMR", "Monero", 128, 128, 44, DerivationStyle::Bip44, AddressEncoding::CryptoNote, {0, 0, nullptr, false}, 18, 0, 0, 0, nullptr, 19, 42, false},
      // --- New multi-coin support (SLIP-0044) --------------------------------
      {"kas", "KAS", "Kaspa", 111111, 111111, 44, DerivationStyle::Bip44, AddressEncoding::KaspaBech32, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"zec", "ZEC", "Zcash (transparent)", 133, 133, 44, DerivationStyle::Bip44, AddressEncoding::ZcashTransparent, {0, 0, nullptr, false}, 0, 0, 0x1cb8, 0x1cbd, nullptr},
      // Firo (formerly Zcoin) transparent P2PKH. SLIP-0044 136 (XZC).
      {"firo", "FIRO", "Firo (transparent)", 136, 136, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, {0x52, 0x07, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"vet", "VET", "VeChain", 818, 818, 44, DerivationStyle::Bip44, AddressEncoding::VeChainAddress, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      // Flow EVM is a distinct address/transaction domain from Cadence accounts.
      {"flow-evm", "FLOW", "Flow EVM Mainnet", 60, 60, 44, DerivationStyle::Bip44, AddressEncoding::Evm, {0, 0, nullptr, false}, 0, 747, 0, 0, nullptr},
      {"sui", "SUI", "Sui", 784, 784, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::SuiEd25519, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"icx", "ICX", "ICON", 74, 74, 44, DerivationStyle::Bip44, AddressEncoding::IconAddress, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      // Substrate ed25519 accounts. Ledger seed/path recovery equivalence has
      // not been established by these SS58 encoding tests. The
      // SS58 network prefix lives in account_version.
      {"dot", "DOT", "Polkadot", 354, 354, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::Ss58Ed25519, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"ksm", "KSM", "Kusama", 434, 434, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::Ss58Ed25519, {0, 0, nullptr, false}, 2, 0, 0, 0, nullptr},
      // TON wallet v4R2, SLIP-0044 607, default subwallet id for workchain 0.
      {"ton", "TON", "TON", 607, 607, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::TonAddress, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr, 0, 0, false, 698983191},
      {"hbar", "HBAR", "Hedera (Ed25519 alias)", 3030, 3030, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::HederaKeyAlias, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"sc", "SC", "Siacoin v2", 1991, 1991, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::SiaV2, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"xem", "XEM", "NEM mainnet", 43, 43, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::Nem, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"dcr", "DCR", "Decred", 42, 42, 44, DerivationStyle::Bip44, AddressEncoding::DecredAddress, {0, 0, nullptr, false}, 0, 0, 0x073f, 0x071a, nullptr},
      // Nervos CKB, SLIP-0044 309. Short bech32 address of the standard
      // SECP256K1/blake160 lock script.
      {"ckb", "CKB", "Nervos CKB", 309, 309, 44, DerivationStyle::Bip44, AddressEncoding::CkbAddress, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      // Hive (SLIP-0044 3054). Accounts are named; the device derives the
      // graphene "STM..." public key identity.
      {"hive", "HIVE", "Hive", 3054, 3054, 44, DerivationStyle::Bip44, AddressEncoding::GraphenePubkey, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      // Default ledger account for an Ed25519 identity; not Ledger's secp256k1 path.
      {"icp", "ICP", "Internet Computer", 223, 223, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::IcpLedgerAccount, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      // Qtum uses Bitcoin script and BIP143 rules with its own base58 versions
      // and "qc" bech32 prefix. Only transparent UTXO transfers are admitted.
      {"qtum", "QTUM", "Qtum", 2301, 2301, 44, DerivationStyle::Bip44, AddressEncoding::P2pkh, {0x3a, 0x32, "qc", false}, 0, 0, 0, 0, nullptr},
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
      {"near", "NEAR", "NEAR Protocol", 397, 397, 44, DerivationStyle::NearSlip10, AddressEncoding::NearImplicit, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"xtz", "XTZ", "Tezos (tz1)", 1729, 1729, 44, DerivationStyle::AllHardenedBip44, AddressEncoding::Ed25519Blake2bBase58, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"ada", "ADA", "Cardano (Ledger CIP-1852)", 1815, 1815, 1852, DerivationStyle::CardanoBip1852, AddressEncoding::Ed25519Blake2b224Bech32, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"croorg", "CRO", "Crypto.org Chain", 394, 394, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Cosmos, {0, 0, nullptr, false}, 0, 0, 0, 0, "cro"},
      {"atom", "ATOM", "Cosmos Hub", 118, 118, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Cosmos, {0, 0, nullptr, false}, 0, 0, 0, 0, "cosmos"},
      {"osmo", "OSMO", "Osmosis", 118, 118, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Cosmos, {0, 0, nullptr, false}, 0, 0, 0, 0, "osmo"},
      {"tia", "TIA", "Celestia", 118, 118, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Cosmos, {0, 0, nullptr, false}, 0, 0, 0, 0, "celestia"},
      {"sei", "SEI", "SEI", 19000118, 19000118, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Cosmos, {0, 0, nullptr, false}, 0, 0, 0, 0, "sei"},
      {"avax", "AVAX", "Avalanche X/P Chain", 9000, 9000, 44, DerivationStyle::Bip44, AddressEncoding::Bech32Avalanche, {0, 0, nullptr, false}, 0, 0, 0, 0, "avax"},
      {"fil", "FIL", "Filecoin", 461, 461, 44, DerivationStyle::Bip44, AddressEncoding::Blake2bBase32Filecoin, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"erg", "ERG", "Ergo", 429, 429, 44, DerivationStyle::Bip44, AddressEncoding::Blake2bBase58Ergo, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"xch", "XCH", "Chia", 8444, 8444, 12381, DerivationStyle::ChiaEip2333, AddressEncoding::Bech32mBlsChia, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr},
      {"qrl", "QRL", "Quantum Resistant Ledger", 0, 0, 0, DerivationStyle::QrlXmss, AddressEncoding::QrlXmss, {0, 0, nullptr, false}, 0, 0, 0, 0, nullptr, 0, 0, true},
#include "src/generated/WalletForkProfiles.inc"
  };

  const size_t kNetworkProfileCount = sizeof(kNetworkProfiles) / sizeof(kNetworkProfiles[0]);
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
      {"rvn", SighashFamily::Bitcoin, 0},
      {"nmc", SighashFamily::Bitcoin, 0},
      {"vtc", SighashFamily::Bitcoin, 0},
      {"vtc49", SighashFamily::Bitcoin, 0},
      {"vtc84", SighashFamily::Bitcoin, 0},
      {"axe", SighashFamily::Bitcoin, 0},
      {"bch", SighashFamily::ForkId, 0},
      {"xec", SighashFamily::ForkId, 0},
      {"bsv", SighashFamily::ForkId, 0},
      {"zec", SighashFamily::ZcashZip243, 0},
      {"firo", SighashFamily::Bitcoin, 0},
      {"qtum", SighashFamily::Bitcoin, 0},
#include "src/generated/WalletForkSigningPolicies.inc"
  };

  const size_t kNetworkSigningPolicyCount =
      sizeof(kNetworkSigningPolicies) / sizeof(kNetworkSigningPolicies[0]);

  const ZcashNetworkPolicy kZcashNetworkPolicies[] = {
      // NU6.2 (zcash/src/consensus/upgrades.cpp, mainnet activation 3364600).
      {"zec", 0x5437f330, 21000000ULL * 100000000ULL},
  };

  const size_t kZcashNetworkPolicyCount =
      sizeof(kZcashNetworkPolicies) / sizeof(kZcashNetworkPolicies[0]);

  const ZcashNetworkPolicy *find_zcash_network_policy(const char *network_id)
  {
    if (network_id == nullptr)
      return nullptr;
    for (size_t index = 0; index < kZcashNetworkPolicyCount; ++index)
    {
      if (strcmp(kZcashNetworkPolicies[index].network_id, network_id) == 0)
        return &kZcashNetworkPolicies[index];
    }
    return nullptr;
  }

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
           network.encoding == AddressEncoding::Ed25519Base58 ||
           network.encoding == AddressEncoding::Tron;
  }

  bool network_supports_eip1559(const NetworkProfile &network)
  {
    if (network.encoding != AddressEncoding::Evm)
      return false;
    static const char *const kEip1559Networks[] = {
        "xlayer",
        "zksync",
        "eth",
        "matic",
        "opt",
        "arb1",
        "base",
        "avaxc",
        "xdai",
        "glmr",
        "movr",
        "cro",
        "kava",
        "core",
        "unichain",
        "monad",
        "plasma",
        "bera",
        "arc",
    };
    for (const char *id : kEip1559Networks)
    {
      if (strcmp(network.id, id) == 0)
        return true;
    }
    return false;
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
        const uint32_t expected_derivation_type =
            strcmp(network.id, "etc") == 0   ? 61
            : strcmp(network.id, "cfx") == 0 ? 503
                                             : 60;
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
    const NetworkProfile *conflux = find_network_profile("cfx");
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
    const uint8_t test_uncompressed[kUncompressedPublicKeySize] = {
        0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
        0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
        0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb,
        0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85,
        0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8};
    char test_address[128];
    size_t test_size = sizeof(test_address);
    const NetworkProfile *komodo = find_network_profile("fork_komodo");
    const NetworkProfile *anon = find_network_profile("fork_anon");
    const NetworkProfile *digibyte = find_network_profile("dgb");
    const NetworkProfile *cosmos = find_network_profile("atom");
    if (komodo == nullptr || address_p2pkh(komodo->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "RKxTdfmtxtfLDKZBgx6SvNkBtNu9jRYnLh") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (anon == nullptr || address_zcash_transparent(anon->alt_p2pkh_version, anon->alt_p2sh_version, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "AnYEktGAqUSEAGTn8jKkhZeCFZNibUjnYxN") != 0)
    {
      return false;
    }
    const NetworkProfile *sugar = find_network_profile("fork_sugarchain");
    const NetworkProfile *sugar84 = find_network_profile("fork_sugarchain84");
    const NetworkProfile *sugar49 = find_network_profile("fork_sugarchain49");
    test_size = sizeof(test_address);
    if (sugar == nullptr || address_p2pkh(sugar->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "SXyGazfm6S3xfcySmD6QNkZYmtfysC2jvc") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (sugar49 == nullptr || address_p2sh_p2wpkh(sugar49->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "sbUiFaYTL16erD6g8Tmkf9SkApHVf8vGjP") != 0)
    {
      return false;
    }
    if (sugar84 == nullptr ||
        address_p2wpkh(sugar84->utxo, test_public_key, test_address,
                       sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address,
               "sugar1qw508d6qejxtdg4y5r3zarvary0c5xw7kjjlkp2") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (digibyte == nullptr || address_p2pkh(digibyte->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE") != 0)
    {
      return false;
    }
    const NetworkProfile *firo = find_network_profile("firo");
    const NetworkProfile *qtum = find_network_profile("qtum");
    const NetworkProfile *vechain = find_network_profile("vet");
    const NetworkProfile *icon = find_network_profile("icx");
    const NetworkProfile *polkadot = find_network_profile("dot");
    const NetworkProfile *kusama = find_network_profile("ksm");
    const NetworkProfile *ton = find_network_profile("ton");
    const NetworkProfile *decred = find_network_profile("dcr");
    const NetworkProfile *ckb = find_network_profile("ckb");
    test_size = sizeof(test_address);
    if (firo == nullptr || address_p2pkh(firo->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "aBPjJ4LEarrcCrd6EBRTb8jVjUZuHQFVnD") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (qtum == nullptr || address_p2pkh(qtum->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "QXHFfTBKYXjaaTH1e7Rox8CcdNPGHVhM59") != 0)
    {
      return false;
    }
    if (vechain == nullptr ||
        address_vechain(test_uncompressed, test_address,
                        sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf") != 0)
    {
      return false;
    }
    if (icon == nullptr ||
        address_icon(test_uncompressed, test_address,
                     sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "hx0502987e630ea7ebb2bf1d84a65a727109385bcf") != 0)
    {
      return false;
    }
    const uint8_t substrate_public_key[32] = {
        0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd,
        0x18, 0xe7, 0x4b, 0xc0, 0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5,
        0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8};
    if (polkadot == nullptr ||
        address_ss58(polkadot->account_version, substrate_public_key,
                     test_address, sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "15kypVvwBLVS1eFtT9tb2ZS2HLXLbsy5iZaddcFzRrm5izi") != 0)
    {
      return false;
    }
    if (kusama == nullptr ||
        address_ss58(kusama->account_version, substrate_public_key,
                     test_address, sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "Cf5Voajhm5wk8TBhWuwLq6HKFd7Sy91Tbfqrztrv93jeZkE") != 0)
    {
      return false;
    }
    if (ton == nullptr ||
        address_ton(substrate_public_key, ton->ton_wallet_id, 0x51,
                    test_address, sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "UQDTcUOcJvwtMx4R6Vbb+uYCtJELCzAAvdD439fc2Y0UNpjM") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (decred == nullptr ||
        address_decred(decred->alt_p2pkh_version, test_public_key,
                       test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "DsmcYVbP1Nmag2H4AS17UTvmWXmGeA7nLDx") != 0)
    {
      return false;
    }
    if (ckb == nullptr || ckb->encoding != AddressEncoding::CkbAddress ||
        address_ckb(test_public_key, test_address, sizeof(test_address)) !=
            WalletError::Ok ||
        strcmp(test_address,
               "ckb1qyq829u0x32fchlfe5dqc4awh5q70h0eyj0q2zdh7f") != 0)
    {
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
    if (litecoin == nullptr || address_p2pkh(litecoin->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (litecoin49 == nullptr || address_p2sh_p2wpkh(litecoin49->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "MR8UQSBr5ULwWheBHznrHk2jxyxkHQu8vB") != 0)
    {
      return false;
    }
    if (litecoin84 == nullptr ||
        address_p2wpkh(litecoin84->utxo, test_public_key, test_address,
                       sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (digibyte49 == nullptr || address_p2sh_p2wpkh(digibyte49->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "SeXKCr4bJpNL9LTJcT7zbNZy9YK1Vihyox") != 0)
    {
      return false;
    }
    if (digibyte84 == nullptr ||
        address_p2wpkh(digibyte84->utxo, test_public_key, test_address,
                       sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "dgb1qw508d6qejxtdg4y5r3zarvary0c5xw7kmudfnm") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (bitcoin_gold == nullptr || address_p2pkh(bitcoin_gold->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (bitcoin_gold49 == nullptr ||
        address_p2sh_p2wpkh(bitcoin_gold49->utxo, test_public_key, test_address,
                            &test_size) != WalletError::Ok ||
        strcmp(test_address, "AZ1BpW94ubqHRzsqdfoFCMgVyN1H4CnSEp") != 0)
    {
      return false;
    }
    if (bitcoin_gold84 == nullptr ||
        address_p2wpkh(bitcoin_gold84->utxo, test_public_key, test_address,
                       sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "btg1qw508d6qejxtdg4y5r3zarvary0c5xw7k6w057a") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (vertcoin49 == nullptr || address_p2sh_p2wpkh(vertcoin49->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN") != 0)
    {
      return false;
    }
    if (vertcoin84 == nullptr ||
        address_p2wpkh(vertcoin84->utxo, test_public_key, test_address,
                       sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "vtc1qw508d6qejxtdg4y5r3zarvary0c5xw7kuk9r06") != 0)
    {
      return false;
    }
    const NetworkProfile *peercoin = find_network_profile("ppc");
    const NetworkProfile *namecoin = find_network_profile("nmc");
    const NetworkProfile *bitcoin_sv = find_network_profile("bsv");
    const NetworkProfile *zcash = find_network_profile("zec");
    const ZcashNetworkPolicy *zcash_policy = find_zcash_network_policy("zec");
    test_size = sizeof(test_address);
    if (peercoin == nullptr || address_p2pkh(peercoin->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (namecoin == nullptr || address_p2pkh(namecoin->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "N7FdkoPbHSxKfrSVVbRu3NZtrLqc1oKpAR") != 0)
    {
      return false;
    }
    test_size = sizeof(test_address);
    if (bitcoin_sv == nullptr || address_p2pkh(bitcoin_sv->utxo, test_public_key, test_address, &test_size) != WalletError::Ok ||
        strcmp(test_address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") != 0)
    {
      return false;
    }
    if (cosmos == nullptr || cosmos->alt_hrp == nullptr ||
        address_cosmos_bech32(cosmos->alt_hrp, test_public_key, test_address,
                              sizeof(test_address)) != WalletError::Ok ||
        strcmp(test_address, "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c") != 0)
    {
      return false;
    }
    for (size_t index = 0; index < kNetworkProfileCount; ++index)
    {
      const NetworkProfile &network = kNetworkProfiles[index];
      test_size = sizeof(test_address);
      if (network.encoding == AddressEncoding::P2pkh &&
          address_p2pkh(network.utxo, test_public_key, test_address,
                        &test_size) != WalletError::Ok)
      {
        return false;
      }
      if (network.encoding == AddressEncoding::ZcashTransparent &&
          address_zcash_transparent(network.alt_p2pkh_version,
                                    network.alt_p2sh_version, test_public_key,
                                    test_address, &test_size) != WalletError::Ok)
      {
        return false;
      }
      if (network.encoding == AddressEncoding::Bech32Cosmos &&
          address_cosmos_bech32(network.alt_hrp, test_public_key, test_address,
                                sizeof(test_address)) != WalletError::Ok)
      {
        return false;
      }
    }
    for (size_t index = 0; index < kNetworkSigningPolicyCount; ++index)
    {
      const NetworkSigningPolicy &policy = kNetworkSigningPolicies[index];
      const NetworkProfile *network = find_network_profile(policy.network_id);
      if (network == nullptr || policy.family == SighashFamily::None)
        return false;
      const bool utxo_family = network->encoding == AddressEncoding::P2pkh ||
                               network->encoding == AddressEncoding::P2shP2wpkh ||
                               network->encoding == AddressEncoding::P2wpkh;
      const bool cashaddr_family = network->encoding == AddressEncoding::CashAddr &&
                                   network->alt_hrp != nullptr;
      if (policy.family == SighashFamily::ZcashZip243)
      {
        if (network->encoding != AddressEncoding::ZcashTransparent ||
            find_zcash_network_policy(network->id) == nullptr)
        {
          return false;
        }
      }
      else
      {
        if (!utxo_family && !cashaddr_family)
          return false;
        if (policy.family == SighashFamily::ForkId)
        {
          const bool p2pkh = network->encoding == AddressEncoding::P2pkh;
          if (!p2pkh && !cashaddr_family)
            return false;
        }
        else if (cashaddr_family)
        {
          return false;
        }
      }
      for (size_t other = index + 1; other < kNetworkSigningPolicyCount; ++other)
      {
        if (strcmp(kNetworkSigningPolicies[other].network_id, policy.network_id) == 0)
        {
          return false;
        }
      }
    }
    // Peercoin v<3 transactions serialize nTime; the Bitcoin legacy path cannot sign them.
    if (find_network_signing_policy("ppc") != nullptr)
      return false;
#if defined(HEXWALLET_HOST_TEST)
    for (const ForkAddressVector &vector : kForkAddressVectors)
    {
      const NetworkProfile *network = find_network_profile(vector.id);
      test_size = sizeof(test_address);
      if (network == nullptr ||
          address_p2pkh(network->utxo, test_public_key, test_address,
                        &test_size) != WalletError::Ok ||
          strcmp(test_address, vector.address) != 0)
      {
        return false;
      }
    }
#endif
    const NetworkProfile *rootstock = find_network_profile("rsk");
    if (ethereum == nullptr || ethereum->evm_chain_id != 1 ||
        ethereum_classic == nullptr ||
        ethereum_classic->derivation_coin_type != 61 ||
        ethereum_classic->evm_chain_id != 61 || bsc == nullptr ||
        bsc->derivation_coin_type != 60 || bsc->evm_chain_id != 56 ||
        conflux == nullptr || conflux->slip44_coin_type != 503 ||
        conflux->derivation_coin_type != 503 || conflux->evm_chain_id != 1030 ||
        rootstock == nullptr || rootstock->evm_chain_id != 30 ||
        monero == nullptr || monero->account_version != 18 ||
        monero->cryptonote_integrated_prefix != 19 ||
        monero->cryptonote_subaddress_prefix != 42 || masari != nullptr ||
        zcash == nullptr || zcash->encoding != AddressEncoding::ZcashTransparent ||
        zcash->alt_p2pkh_version != 0x1cb8 || zcash->alt_p2sh_version != 0x1cbd ||
        zcash_policy == nullptr || zcash_policy->branch_id != 0x5437f330 ||
        kaspa == nullptr || kaspa->slip44_coin_type != 111111 ||
        algorand == nullptr || algorand->slip44_coin_type != 283 ||
        solana == nullptr || solana->slip44_coin_type != 501 || chia == nullptr ||
        chia->slip44_coin_type != 8444 || chia->bip_purpose != 12381 ||
        qrl == nullptr || qrl->encoding != AddressEncoding::QrlXmss ||
        !qrl->explicit_only_derivation)
    {
      return false;
    }
    return network_supports_eip1559(*ethereum) &&
           !network_supports_eip1559(*ethereum_classic) &&
           !network_supports_eip1559(*bsc) &&
           !network_supports_eip1559(*conflux) &&
           !network_supports_eip1559(*rootstock);
  }

} // namespace hexwallet
