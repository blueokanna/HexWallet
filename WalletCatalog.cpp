#include "WalletCatalog.h"

#include <ctype.h>
#include <string.h>

#include "ChainTransaction.h"
#include "CosmosTransaction.h"
#include "CryptoNoteReview.h"

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
  { "xrp", "XRP", "XRP Ledger", 144, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "xrp", "Classic r-addresses; native Payment only; no issued currencies, paths, memos or partial payments" },
  { "xtz", "XTZ", "Tezos (tz1)", 1729, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "xtz", "Modern Ed25519 reveal and native implicit-account transfers; no KT1, FA tokens or NFT calls; branch origin unverified offline" },
  { "algo", "ALGO", "Algorand", 283, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "algo", "Mainnet canonical MessagePack payments, ASA transfers and opt-in; no groups, rekey or account closing" },
  { "near", "NEAR", "NEAR Protocol", 397, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "near", "Implicit receive accounts; Borsh V0 native Transfer; named account key membership and block network cannot be checked offline" },
  { "sol", "SOL", "Solana", 501, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "sol", "SOL, SPL Token and Token-2022 TransferChecked: legacy/v0, single payer; exact mint/token accounts reviewed; Token-2022 extension warning; no ALTs or ATA creation" },
  { "btc", "BTC", "Bitcoin", 0, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "btc", "P2WPKH PSBT signing" },
  { "btc49", "BTC", "Bitcoin Nested SegWit", 0, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "btc49", "P2SH-P2WPKH PSBT signing" },
  { "btc44", "BTC", "Bitcoin Legacy", 0, WalletCapabilityAddress, "btc44", "P2PKH address only; signing requires verified non_witness_utxo support" },
  { "ltc", "LTC", "Litecoin Legacy", 2, WalletCapabilityAddress, "ltc", "P2PKH address and Bitcoin-sighash signing" },
  { "ltc49", "LTC", "Litecoin Nested SegWit", 2, WalletCapabilityAddress, "ltc49", "P2SH-P2WPKH address and BIP143 signing" },
  { "ltc84", "LTC", "Litecoin Native SegWit", 2, WalletCapabilityAddress, "ltc84", "P2WPKH address and BIP143 signing" },
  { "doge", "DOGE", "Dogecoin", 3, WalletCapabilityAddress, "doge", "address only" },
  { "dash", "DASH", "Dash", 5, WalletCapabilityAddress, "dash", "address only" },
  { "xlayer", "OKB", "X Layer", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "xlayer", "EIP-155/type-2 transfers; registered tokens only; additional L1 fees are not in the execution fee cap" },
  { "zksync", "ETH", "zkSync Era", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "zksync", "EIP-155/type-2 EOA transfers only; no type-113, paymasters or account abstraction" },
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
  { "unichain", "ETH", "Unichain", 130, WalletCapabilityAddress | WalletCapabilityTokenAccount, "unichain", "EVM address and token account support; EIP-155/1559 signing" },
  { "monad", "MON", "Monad", 143, WalletCapabilityAddress | WalletCapabilityTokenAccount, "monad", "EVM address and token account support; EIP-155/1559 signing" },
  { "plasma", "XPL", "Plasma", 9745, WalletCapabilityAddress | WalletCapabilityTokenAccount, "plasma", "EVM address and token account support; EIP-155/1559 signing" },
  { "bera", "BERA", "Berachain", 80094, WalletCapabilityAddress | WalletCapabilityTokenAccount, "bera", "EVM address and token account support; EIP-155/1559 signing" },
  { "arc", "USDC", "Arc", 5042, WalletCapabilityAddress | WalletCapabilityTokenAccount, "arc", "EVM address; EIP-155/1559 signing; native gas token is 18-decimal USDC" },
  { "okt", "OKT", "OKT Chain", 66, WalletCapabilityAddress | WalletCapabilityTokenAccount, "okt", "EVM address and token account support; EIP-155 legacy signing" },
  { "bch", "BCH", "Bitcoin Cash", 145, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "bch", "CashAddr; forkid sighash signing" },
  { "bsv", "BSV", "Bitcoin SV", 236, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "bsv", "P2PKH PSBT signing, BIP143 + SIGHASH_FORKID" },
  { "xec", "XEC", "eCash", 899, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "xec", "CashAddr; forkid sighash signing" },
  { "dgb", "DGB", "DigiByte Legacy", 20, WalletCapabilityAddress, "dgb", "P2PKH address and Bitcoin-sighash signing" },
  { "dgb49", "DGB", "DigiByte Nested SegWit", 20, WalletCapabilityAddress, "dgb49", "P2SH-P2WPKH address and BIP143 signing" },
  { "dgb84", "DGB", "DigiByte Native SegWit", 20, WalletCapabilityAddress, "dgb84", "P2WPKH address and BIP143 signing" },
  { "nmc", "NMC", "Namecoin", 7, WalletCapabilityAddress, "nmc", "P2PKH address and Bitcoin-sighash signing" },
  { "zec", "ZEC", "Zcash", 133, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "zec", "transparent t1/t3 address; v4 transparent ZIP-243 review and signing (NU6.2)" },
  { "flux", "FLUX", "Flux", 19167, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "flux", "transparent t1/t3 v4 ZIP-243 transfer; no shielded or FluxNode transactions" },
  { "firo", "FIRO", "Firo", 136, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "firo", "transparent P2PKH address and Bitcoin-sighash PSBT signing; no privacy (Lelantus/Spark) transactions" },
  { "qtum", "QTUM", "Qtum", 2301, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "qtum", "P2PKH address and Bitcoin/BIP143 PSBT signing; no Qtum EVM contract calls" },
  { "vet", "VET", "VeChain", 818, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "vet", "native VET transfer; one clause, empty data, mainnet chain tag; no VIP-191 delegation or contract calls" },
  { "flow-evm", "FLOW", "Flow EVM Mainnet", 60, WalletCapabilityAddress | WalletCapabilityTokenAccount, "flow-evm", "Flow EVM chain 747, native FLOW, EIP-155 transfer; distinct from Cadence accounts" },
  { "icx", "ICX", "ICON", 74, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "icx", "native ICX transfer with canonical icx_sendTransaction serialization; no SCORE calls" },
  { "ton", "TON", "TON", 607, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "ton", "wallet v4R2 native transfer; empty body only; no comments, jettons or multi-message orders" },
  { "hbar", "HBAR", "Hedera", 3030, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "hbar", "Ed25519 key alias receive; numeric-account HBAR CryptoTransfer, one debit/credit; no HTS, allowances or contracts; node must verify payer ownership and network" },
  { "sc", "SC", "Siacoin v2", 1991, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "sc", "v2 PolicyPublicKey single-input transfer; node must validate parent/proof/maturity; no contracts; wallet-specific SLIP10 seed derivation" },
  { "xem", "XEM", "NEM mainnet", 43, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "xem", "Keccak-Ed25519 native transfer v1, printable plaintext memo; no mosaics or multisig" },
  { "dcr", "DCR", "Decred", 42, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "dcr", "transparent P2PKH single-input transfer; no stake tickets, treasury or mix transactions" },
  { "ckb", "CKB", "Nervos CKB", 309, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "ckb", "native CKB single-input transfer to SECP256K1/blake160 locks; no type scripts or DAO operations" },
  { "hive", "HIVE", "Hive", 3054, WalletCapabilityTransactionReview | WalletCapabilitySigning, "hive", "Single transfer; derived STM value is an active PUBLIC KEY, not a receive address. Named account/authority must be checked by node; no encrypted memo" },
  { "icp", "ICP", "Internet Computer", 223, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "icp", "Ed25519 default ledger account; pinned ICP ledger Candid transfer and signed CBOR request; no arbitrary canisters or staking; not Ledger seed/path compatible" },
  { "dot", "DOT", "Polkadot", 354, WalletCapabilityAddress, "dot", "Ed25519 SS58 address; signing disabled until current runtime metadata and signed extensions are authenticated" },
  { "ksm", "KSM", "Kusama", 434, WalletCapabilityAddress, "ksm", "Ed25519 SS58 address; signing disabled until current runtime metadata and signed extensions are authenticated" },
  { "kas", "KAS", "Kaspa", 111111, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "kas", "Kaspa bech32 address; BIP340 Schnorr v0 transaction review and signing" },
  { "vtc", "VTC", "Vertcoin Legacy", 28, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "vtc", "P2PKH address and Bitcoin-sighash signing" },
  { "vtc49", "VTC", "Vertcoin Nested SegWit", 28, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "vtc49", "P2SH-P2WPKH address and BIP143 signing" },
  { "vtc84", "VTC", "Vertcoin Native SegWit", 28, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "vtc84", "P2WPKH address and Bitcoin-sighash signing" },
  { "axe", "AXE", "Axe", 4242, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "axe", "P2PKH address and Bitcoin-sighash signing" },
  { "xmr", "XMR", "Monero", 128, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "xmr", "RingCT type-6 review and CLSAG signing; fully offline, host supplies decoys" },
  { "trx", "TRX", "TRON", 195, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "trx", "native TRX and registered TRC-20 transfer signing; owner permission only, strict protobuf review" },
  { "xlm", "XLM", "Stellar", 148, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "xlm", "SEP-0005; public-network XDR Payment/CreateAccount; G addresses and explicit memo review" },
  { "atom", "ATOM", "Cosmos Hub", 118, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "atom", "Cosmos SDK native MsgSend; direct sign mode, strict protobuf review" },
  { "osmo", "OSMO", "Osmosis", 118, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "osmo", "Cosmos SDK native MsgSend; direct sign mode, strict protobuf review" },
  { "tia", "TIA", "Celestia", 118, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "tia", "Cosmos SDK native MsgSend; direct sign mode, strict protobuf review" },
  // Address encoders already exist and are verified; transaction signing is
  // not enabled for these rows until a review/sign adapter is admitted.
  { "ada", "ADA", "Cardano (Ledger CIP-1852)", 1815, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "ada", "CIP-0003 Ledger/BitBox02 root, CIP-1852 BIP32-Ed25519; mainnet ADA-only transfer; UTxO ownership/value must be checked by the node; no tokens, scripts, staking or governance" },
  { "fil", "FIL", "Filecoin", 461, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "fil", "f1 sender, f0/f1/f3 recipient; canonical CBOR Send, CID signing; no actor calls or BLS signing" },
  { "sui", "SUI", "Sui", 784, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "sui", "Ed25519 BCS split-gas native SUI transfer; no Move calls, sponsored transactions or tokens" },
  { "erg", "ERG", "Ergo", 429, WalletCapabilityAddress | WalletCapabilityTransactionReview | WalletCapabilitySigning, "erg", "P2PK (ProveDlog) transfers: device rebuilds the tx-id preimage, signs the Schnorr proof and returns the signed transaction. Review displays the single external output plus every token it carries and refuses a second external output or an undisplayable token list; only inputs owned by this key are signed" },
  { "xch", "XCH", "Chia", 8444, WalletCapabilityAddress, "xch", "Address verified against blspy (EIP-2333 raw-salt order, authoritative curry, independent bech32m). Signing stays disabled: AGG_SIG_ME is now bound on-device to the displayed conditions, but the BLS secret-scalar operations still use variable-time MPI, so no constant-time backend exists yet" },
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
                 ? "EIP-155/EIP-1559 native and registered token-call signing; ABI recognition alone does not enable a contract"
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
      const bool solana = strcmp(entry.network->id, "sol") == 0;
      const bool tron = entry.network->encoding == AddressEncoding::Tron;
      const bool cosmos =
          entry.network->encoding == AddressEncoding::Bech32Cosmos &&
          cosmos_chain_params(entry.network->id) != nullptr;
      // A CryptoNote signing claim is valid only when the firmware has a
      // review policy for that network. Masari has no enabled policy, so a
      // catalog entry that claimed its signing would fail here.
      const bool cryptonote =
          entry.network->encoding == AddressEncoding::CryptoNote &&
          cryptonote_review_policy(entry.network->id) != nullptr;
      ChainFamily family = ChainFamily::None;
      const bool chain = chain_family_for_network(entry.network->id, &family);
      if (!evm && !utxo_policy && !kaspa && !cryptonote && !solana && !tron &&
          !cosmos && !chain && entry.network->encoding != AddressEncoding::StellarStrKey &&
          strcmp(entry.network->id, "algo") != 0 && strcmp(entry.network->id, "near") != 0 &&
          strcmp(entry.network->id, "xtz") != 0 &&
          strcmp(entry.network->id, "xrp") != 0) return false;
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
  // XMR stays supported; MSR must not return through a generated catalog.
  bool xmr_signable = false;
  bool msr_signable = false;
  for (size_t index = 0; index < wallet_catalog_count(); ++index) {
    const WalletCatalogEntry entry = resolved_entry(index);
    if (entry.network == nullptr ||
        entry.network->encoding != AddressEncoding::CryptoNote) {
      continue;
    }
    const bool signable =
        wallet_catalog_has(entry, WalletCapabilitySigning) &&
        cryptonote_review_policy(entry.network->id) != nullptr;
    if (strcmp(entry.network->id, "xmr") == 0) xmr_signable = signable;
    if (strcmp(entry.network->id, "msr") == 0) msr_signable = true;
  }
  return xmr_signable && !msr_signable && cryptonote_review_policy("msr") == nullptr;
}

}
