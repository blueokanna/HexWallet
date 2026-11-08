# Supported chains

[中文](Supported-Chains-zh) · [Home](Home)

The catalog holds 215 wallet entries over 247 compiled network profiles. An entry is a derivation
path plus a review/sign policy. It is not a statement that a node accepted a transaction.

Capability bits are literal: `address` derives and displays an address, `review` parses a payload
into reviewable fields, `sign` releases a signature, `token-account` means the network has a token
registry. Only four entries lack `sign`, and exactly one lacks `address`.

## UTXO and UTXO-like

| Entry                                                                            | Path                    | Scope                                                                                                                                                                                                                                    |
| -------------------------------------------------------------------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `btc`                                                                            | BIP84 `m/84'/0'/0'/0/i` | PSBT v0/v2, P2WPKH, BIP143                                                                                                                                                                                                               |
| `btc49`                                                                          | BIP49                   | P2SH-P2WPKH, BIP143                                                                                                                                                                                                                      |
| `btc44`                                                                          | BIP44                   | P2PKH, legacy sighash, needs `non_witness_utxo` for legacy inputs                                                                                                                                                                        |
| `btc86`                                                                          | BIP86                   | P2TR key-path, `SIGHASH_DEFAULT`/`ALL`, no script tree                                                                                                                                                                                   |
| `prl`                                                                            | BIP86                   | Pearl mainnet, Taproot key-path only; no P2MR, XMSS or script-path                                                                                                                                                                       |
| `zec`                                                                            | BIP44                   | v4 transparent, ZIP-243, t1 P2PKH and t3 P2SH-P2PK, NU6.2                                                                                                                                                                                |
| `dash`                                                                           | BIP44                   | Dedicated adapter: type-0 plain payments, legacy digest, P2PKH/P2SH outputs, one funding transaction per input so the reviewed fee is computed rather than supplied; InstantSend intent is displayed, the lock is not verifiable offline |
| `kas`                                                                            | BIP44                   | BIP340 Schnorr, v0 transactions, `SIGHASH_ALL`, KIP-0009 mass                                                                                                                                                                            |
| `ltc`, `ltc49`, `ltc84`, `doge`, `rvn`, `vtc*`, `btg*`, `dgb*`, `grs*`, `axe`, … | per profile             | UTXO forks whose sighash family was audited: legacy, BIP143, `SIGHASH_FORKID`, Groestl-512                                                                                                                                               |

105 fork profiles are generated from `tools/fork_registry.json`. A fork is admitted only when the
upstream `chainparams` show a base58 version with a legacy P2PKH sighash and a header without
`nTime` or a wide `nType`. Chains with timestamp sighashes or wide headers stay out: the Bitcoin
legacy signer is never used as a guess.

## EVM

62 networks share one signer: EIP-155, EIP-2930 where the chain requires an access list, and
EIP-1559 where the chain supports it. Native transfers, registered token calls, arbitrary calldata
and contract creation are all signable; calldata that is not a registered token call is reviewed as
raw bytes with its keccak-256, never decoded as a transfer.

| Blockchain / Currency Name | Symbol               | Description                                                                                                                                     |
| -------------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **Acala EVM**              | ACA                  | An EVM-compatible decentralized finance (DeFi) hub and stablecoin platform within the Polkadot ecosystem.                                       |
| **Arbitrum One**           | ARB (ETH\*)          | A leading Ethereum Layer 2 scaling network powered by Optimistic Rollup technology.                                                             |
| **Arc**                    | ARC                  | An EVM-compatible blockchain network focused on decentralized applications (DApps) and Web3 infrastructure.                                     |
| **Astar**                  | ASTR                 | A multi-chain smart contract platform on Polkadot that supports both EVM and WASM virtual machines.                                             |
| **Aurora**                 | AURORA (ETH\*)       | An Ethereum Virtual Machine (EVM) built on the NEAR Protocol, providing Ethereum ecosystem compatibility on NEAR.                               |
| **Avalanche C-Chain**      | AVAX                 | The smart contract chain of the Avalanche platform, designed for high-throughput, low-latency EVM applications.                                 |
| **Aves**                   | AVS                  | A standalone Proof-of-Work (PoW) Layer 1 blockchain network with full EVM compatibility.                                                        |
| **Base**                   | ETH\*                | An Ethereum Layer 2 network incubated by Coinbase and built on the OP Stack (operates without a separate native token).                         |
| **Berachain**              | BERA                 | A high-performance, EVM-identical Layer 1 blockchain powered by the Proof-of-Liquidity (PoL) consensus mechanism.                               |
| **Binance Smart Chain**    | BNB                  | Now known as BNB Smart Chain, a high-throughput, low-fee EVM-compatible blockchain launched by Binance.                                         |
| **Bitlayer**               | BTC\*                | A Bitcoin Layer 2 network built on the BitVM paradigm, offering Turing-complete smart contracts and EVM compatibility.                          |
| **Bitnet**                 | BTN                  | An independent EVM-compatible public chain designed for low-cost transactions and DApp deployment.                                              |
| **Blast**                  | BLAST (ETH\*)        | An Ethereum Optimistic Rollup Layer 2 network that offers native yield for ETH and stablecoins.                                                 |
| **Canto**                  | CANTO                | An EVM-compatible blockchain built with the Cosmos SDK, pioneering Free Public Infrastructure (FPI) for DeFi.                                   |
| **Canxium**                | CAU                  | An EVM-compatible blockchain characterized by an offline mining mechanism and hydro-powered mining initiatives.                                 |
| **Celo**                   | CELO                 | A carbon-negative, mobile-first EVM network focused on micropayments and Real-World Assets (RWA), transitioning into an Ethereum L2.            |
| **Conflux eSpace**         | CFX                  | A fully EVM-compatible execution space on the Conflux network, leveraging Tree-Graph consensus for high throughput.                             |
| **Core**                   | CORE                 | An EVM-compatible Layer 1 blockchain secured by the "Satoshi Plus" consensus, combining Bitcoin's PoW with Delegated Proof-of-Stake (DPoS).     |
| **Cronos**                 | CRO                  | An EVM-compatible blockchain built on the Cosmos SDK and backed by Crypto.com, focusing on DeFi, NFTs, and Web3 gaming.                         |
| **Dogechain EVM**          | DOGE / DC            | A standalone EVM network built on Polygon Edge designed to bring smart contracts, DeFi, and NFTs to Dogecoin holders.                           |
| **Ethereum**               | ETH                  | The world's leading decentralized smart contract platform and the foundational standard for all EVM-compatible networks.                        |
| **Ethereum Classic**       | ETC                  | The original Ethereum blockchain that maintained the unaltered ledger and PoW consensus following the 2016 DAO hard fork.                       |
| **EthereumPoW**            | ETHW                 | A Proof-of-Work fork of Ethereum maintained by the mining community after Ethereum's transition to Proof-of-Stake in 2022.                      |
| **Etho Protocol**          | ETHO                 | An EVM-compatible network that combines Ethereum smart contracts with decentralized IPFS storage nodes.                                         |
| **Etica**                  | EGAZ                 | A decentralized PoW blockchain dedicated to funding open-source, patent-free medical research.                                                  |
| **Evmos EVM**              | EVMOS                | The flagship EVM hub on Cosmos, bridging Ethereum assets and applications into the Inter-Blockchain Communication (IBC) ecosystem.              |
| **Fantom**                 | FTM (S)              | A high-speed DAG-based smart contract platform utilizing the Lachesis consensus mechanism (upgraded to the Sonic network).                      |
| **Flare**                  | FLR                  | A data-focused EVM-compatible Layer 1 blockchain featuring enshrined oracles and cross-chain data interoperability protocols.                   |
| **Flow EVM**               | FLOW                 | The EVM-equivalent environment on the consumer-grade Flow blockchain, enabling seamless interoperability between Cadence and Solidity.          |
| **Fuse**                   | FUSE                 | A lightweight EVM-compatible blockchain tailored for mobile payments, stablecoin settlements, and business micro-transactions.                  |
| **Gnosis Chain**           | xDAI (GNO)           | An Ethereum sidechain (formerly xDai Chain) that uses the xDAI stablecoin for gas fees and GNO for staking and governance.                      |
| **Harmony EVM**            | ONE                  | A fast and open EVM-compatible blockchain utilizing Effective Proof-of-Stake (EPoS) and sharding for high scalability.                          |
| **Kaia**                   | KAIA                 | A flagship Asian EVM Layer 1 blockchain formed by the merger of Klaytn (backed by Kakao) and Finschia (backed by LINE).                         |
| **Kava EVM**               | KAVA                 | A Layer 1 blockchain featuring a "Co-Chain" architecture that combines the speed of Cosmos with Ethereum's developer ecosystem.                 |
| **Larissa Chain**          | LRS                  | A Proof-of-Work (PoW) EVM-compatible blockchain integrated with a decentralized node architecture.                                              |
| **Linea**                  | ETH\*                | A developer-ready zkEVM Layer 2 scaling network for Ethereum built by Consensys.                                                                |
| **Mantle**                 | MNT                  | A modular Ethereum Layer 2 network governed by one of the largest decentralized autonomous organizations (DAOs).                                |
| **Merlin Chain**           | MERL (BTC\*)         | A ZK-Rollup Bitcoin Layer 2 network dedicated to empowering native Bitcoin assets, protocols, and applications.                                 |
| **Metis Andromeda**        | METIS                | An Ethereum Layer 2 Rollup platform featuring a decentralized sequencer and support for Decentralized Autonomous Companies (DACs).              |
| **Monad**                  | MON                  | A next-generation, high-performance EVM-compatible Layer 1 blockchain utilizing parallel execution to achieve up to 10,000 TPS.                 |
| **Moonbeam**               | GLMR                 | A fully Ethereum-compatible smart contract parachain on the Polkadot network.                                                                   |
| **Moonriver**              | MOVR                 | The companion network to Moonbeam, operating as a canary EVM-compatible parachain on Kusama.                                                    |
| **Oasis Sapphire**         | ROSE                 | The industry's first confidential EVM runtime launched by the Oasis Network, enabling privacy-preserving smart contracts.                       |
| **OctaSpace**              | OCTA                 | An EVM-compatible blockchain platform offering distributed cloud computing, GPU rendering, data storage, and VPN services.                      |
| **OKT Chain**              | OKT                  | A Cosmos-based, 100% EVM-compatible high-performance blockchain developed by the OKX exchange (formerly OKExChain).                             |
| **opBNB**                  | BNB\*                | A high-performance Layer 2 scaling solution for the BNB Smart Chain built on the OP Stack, optimized for gaming and high-frequency trading.     |
| **Optimism**               | OP (ETH\*)           | A pioneer in Ethereum Optimistic Rollup scaling and the core developer behind the open-source OP Stack and Superchain ecosystem.                |
| **Plasma**                 | PLASMA               | Either the classic Ethereum Layer 2 scaling framework or a specialized EVM network optimized for zero-fee stablecoin settlements.               |
| **Polygon**                | POL (formerly MATIC) | One of the most widely adopted Ethereum scaling and infrastructure platforms (PoS sidechain), evolving into the Polygon 2.0 aggregated network. |
| **Polygon zkEVM**          | ETH\* (POL)          | An Ethereum Layer 2 scaling solution by Polygon utilizing zero-knowledge rollups to provide EVM equivalence.                                    |
| **Robinhood Chain**        | ETH\* / TBD          | An EVM-compatible Layer 2 network built on the Arbitrum Orbit stack by financial services platform Robinhood.                                   |
| **Ronin**                  | RON                  | An EVM-compatible blockchain specifically forged for Web3 gaming by Sky Mavis, the creators of Axie Infinity.                                   |
| **Rootstock**              | RBTC (RIF)           | A long-standing Bitcoin smart contract sidechain that brings EVM compatibility to Bitcoin via a two-way peg and merged mining.                  |
| **Scroll**                 | SCR (ETH\*)          | A community-driven Ethereum Layer 2 network utilizing zkEVM technology to achieve bytecode-level compatibility with Ethereum.                   |
| **Sei EVM**                | SEI                  | Initially a trading-optimized Cosmos chain, upgraded in Sei V2 to become the first high-performance parallelized EVM blockchain.                |
| **Telos EVM**              | TLOS                 | An EVM execution layer built on the Telos network, engineered for high throughput, low fixed gas fees, and protection against front-running.    |
| **Theta**                  | THETA (TFUEL)        | A dual-token, EVM-compatible blockchain built for decentralized video streaming, edge computing, and AI infrastructure.                         |
| **Unichain**               | ETH\* (UNI)          | A DeFi-native Ethereum Layer 2 network built on the OP Stack by Uniswap Labs to optimize cross-chain liquidity and execution speed.             |
| **VirBiCoin**              | VBC                  | An early Ethereum codebase fork operating as an independent Proof-of-Work (PoW) EVM-compatible blockchain.                                      |
| **X Layer**                | OKB                  | A ZK-Rollup Ethereum Layer 2 network built by OKX using the Polygon CDK, utilizing OKB as its native gas token.                                 |
| **XinFin Network**         | XDC                  | Also known as the XDC Network, an enterprise-ready hybrid EVM blockchain optimized for international trade finance and RWA tokenization.        |
| **zkSync Era**             | ZK (ETH\*)           | A leading Ethereum Layer 2 scaling protocol developed by Matter Labs, powered by zero-knowledge (ZK) rollup technology.                         |

> **Note:** Symbols marked with an asterisk `*` (such as `ETH*`, `BTC*`, or `BNB*`) indicate that the Layer 2 network uses the native currency of its underlying Layer 1 mainnet to pay for transaction (gas) fees, while the accompanying ticker outside or inside the parentheses represents the network's ecosystem/governance token.

Theta is the one network with two routes: TFUEL transfers use the EVM adapter, native `SendTx`
uses the Theta adapter, and the payload format decides which runs.

78 token records are pinned across 18 networks (`WalletTokens.cpp`). User-declared tokens can be
added on the device; the review marks them as declared, and they never change the signed bytes.

## Native adapters

These take a payload in their own format through `chain begin <network> <index> <payload-hex>`.
The exact envelope is in [Chain-Payloads](Chain-Payloads).

| Entry                                                  | Scope notes                                                                                                                                                                                  |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `xmr`                                                  | RCT type 6, CLSAG, Bulletproofs+, 16-member rings, subaddress spends; decoys come from the phone                                                                                             |
| `alph`                                                 | Native ALPH P2PKH transfers with one recipient, optional wallet change and reviewed gas. The transaction ID and signature match Alephium SDK 3.0.5.                                          |
| `quantus`                                              | Mainnet runtime 153/6. Transparent ML-DSA-87 accounts, SS58 prefix 189 and signed v4 balances transfers with nonce, tip and era review.                                                      |
| `zeph`                                                 | Native ZPH transfers with the Zephyr v3 prefix, RingCT type 6 and 16-member CLSAG rings. Spend and view keys use the agreed XMR derivation. Addresses and asset fields are network-specific. |
| `trx`                                                  | Owner-permission transfers, TRC-10, registered TRC-20, printable memo ≤ 64 bytes; no NFT, batch or multi-contract                                                                            |
| `xlm`                                                  | SEP-0005, public XDR Payment/CreateAccount, issued assets and memo review; ≤ 8 operations                                                                                                    |
| `sol`                                                  | Legacy/v0, System Transfer, SPL and Token-2022 `TransferChecked`, exact mint/account review; no ALTs or ATA creation                                                                         |
| `xrp`                                                  | Native Payment, canonical XRPL binary, SHA-512Half; no issued currencies, paths, memo, partial payment or multisig                                                                           |
| `atom`, `osmo`, `tia`, `kava`, `terra`, `terraclassic` | 1–4 `MsgSend`, `SIGN_MODE_DIRECT`, optional memo; no IBC, authz, wasm or amino signing                                                                                                       |
| `ada`                                                  | Conway body review and Ed25519-BIP32 signing; no input value/owner, so balance needs a node                                                                                                  |
| `algo`                                                 | Canonical MessagePack `pay`/`axfer`, genesis/fee/round checks, ASA opt-in; mainnet only                                                                                                      |
| `apt`                                                  | Aptos transfer payloads with Ed25519 authentication key derivation                                                                                                                           |
| `ckb`                                                  | Secp256k1 sighash and Molecule serialisation                                                                                                                                                 |
| `dcr`                                                  | BLAKE-256, legacy prefix/witness sighash, P2PKH                                                                                                                                              |
| `erg`                                                  | P2PK ProveDlog: the device rebuilds the tx-id preimage and returns a complete proof transaction                                                                                              |
| `fil`                                                  | CBOR `Send`, CID digest, f1 sender                                                                                                                                                           |
| `hbar`                                                 | Hedera transfer body signing                                                                                                                                                                 |
| `hive`                                                 | Review + sign only: an STM public key is not a receive address, so this entry has no address capability                                                                                      |
| `icp`                                                  | Ed25519 request signing with the IC principal derivation                                                                                                                                     |
| `vet`                                                  | Compact payload, canonical RLP, BLAKE2b-256, recoverable signature; single-clause VET only                                                                                                   |
| `icx`                                                  | `icx_sendTransaction` canonical text, SHA3-256; native ICX only                                                                                                                              |
| `dot`, `ksm`                                           | `DOT2` payload, pinned runtime `spec_version`/`transaction_version`, short-lived era + tip; the historical DOT1 layout is host-test only                                                     |
| `qrl`                                                  | XMSS/SHAKE-256 height 10; the leaf is reserved in durable storage before signing, and the device verifies its own signature                                                                  |
| `qrl2`                                                 | ML-DSA-87 accounts, SHAKE-256 checksummed `Q` address, keccak-256 envelope; mainnet chain id 1 only                                                                                          |
| `stark`                                                | Stark curve keys, Cairo v3 `deploy_account` and one ERC-20 `transfer` via `execute`; `SN_MAIN` only                                                                                          |
| `theta`                                                | Native 46-byte `SendTx` payload; EVM transfers of TFUEL go through the EVM entry                                                                                                             |
| `ton`                                                  | Wallet v4R2 cell/BoC serialisation, user-friendly address, empty body                                                                                                                        |
| `sui`                                                  | BCS split-gas native transfer, Ed25519; no Move calls, sponsorship or tokens                                                                                                                 |
| `xch`                                                  | Chia `CREATE_COIN` only; BLS12-381 G1 keys                                                                                                                                                   |
| `xem`                                                  | NEM Keccak-Ed25519 variant; not RFC 8032 Ed25519                                                                                                                                             |

## Address only

| Entry  | Why                                        |
| ------ | ------------------------------------------ |
| `ryo`  | CryptoNote long address, prefix `0x2ce192` |
| `zano` | CryptoNote `Zx` address, prefix `0xc5`     |

## Refused

The refusal list is part of the contract, not a caveat: shielded Zcash, Peercoin signing, TRON NFTs
and batch calls, Cosmos IBC/authz/amino, Dash special transactions, EVM blind decoding, Lightning,
Stacks, Mimblewimble chains as wallets, and every chain without an upstream SLIP-0044 number.
[Admission-Policy](Admission-Policy) explains how a chain gets in.

## Machine-generated matrices

- `wiki/native-chain-capabilities.md` — one row per compiled profile, generated by
  `tools/native_coverage.ps1` from the built objects.
- `wiki/miningpoolstats-coverage.md` — every MiningPoolStats listing with its resolution status,
  generated by `tools/generate_mining_catalog.py`.
- `wiki/chain-support.md` and `wiki/chain-protocols.md` — the detailed as-built engineering records.

If a page and the generated matrix disagree, the matrix is right and the page is a bug.
