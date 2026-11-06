# Supported chains

[中文](Supported-Chains-zh) · [Home](Home)

The catalog holds 215 wallet entries over 247 compiled network profiles. An entry is a derivation
path plus a review/sign policy. It is not a statement that a node accepted a transaction.

Capability bits are literal: `address` derives and displays an address, `review` parses a payload
into reviewable fields, `sign` releases a signature, `token-account` means the network has a token
registry. Only four entries lack `sign`, and exactly one lacks `address`.

## UTXO and UTXO-like

| Entry | Path | Scope |
| --- | --- | --- |
| `btc` | BIP84 `m/84'/0'/0'/0/i` | PSBT v0/v2, P2WPKH, BIP143 |
| `btc49` | BIP49 | P2SH-P2WPKH, BIP143 |
| `btc44` | BIP44 | P2PKH, legacy sighash, needs `non_witness_utxo` for legacy inputs |
| `btc86` | BIP86 | P2TR key-path, `SIGHASH_DEFAULT`/`ALL`, no script tree |
| `prl` | BIP86 | Pearl mainnet, Taproot key-path only; no P2MR, XMSS or script-path |
| `zec` | BIP44 | v4 transparent, ZIP-243, t1 P2PKH and t3 P2SH-P2PK, NU6.2 |
| `dash` | BIP44 | Dedicated adapter: type-0 plain payments, legacy digest, P2PKH/P2SH outputs, one funding transaction per input so the reviewed fee is computed rather than supplied; InstantSend intent is displayed, the lock is not verifiable offline |
| `kas` | BIP44 | BIP340 Schnorr, v0 transactions, `SIGHASH_ALL`, KIP-0009 mass |
| `ltc`, `ltc49`, `ltc84`, `doge`, `rvn`, `vtc*`, `btg*`, `dgb*`, `grs*`, `axe`, … | per profile | UTXO forks whose sighash family was audited: legacy, BIP143, `SIGHASH_FORKID`, Groestl-512 |

105 fork profiles are generated from `tools/fork_registry.json`. A fork is admitted only when the
upstream `chainparams` show a base58 version with a legacy P2PKH sighash and a header without
`nTime` or a wide `nType`. Chains with timestamp sighashes or wide headers stay out: the Bitcoin
legacy signer is never used as a guess.

## EVM

62 networks share one signer: EIP-155, EIP-2930 where the chain requires an access list, and
EIP-1559 where the chain supports it. Native transfers, registered token calls, arbitrary calldata
and contract creation are all signable; calldata that is not a registered token call is reviewed as
raw bytes with its keccak-256, never decoded as a transfer.

```text
Acala EVM, Arbitrum One, Arc, Astar, Aurora, Avalanche C-Chain, Aves, Base, Berachain,
Binance Smart Chain, Bitlayer, Bitnet, Blast, Canto, Canxium, Celo, Conflux eSpace, Core,
Cronos, Dogechain EVM, Ethereum, Ethereum Classic, EthereumPoW, Etho Protocol, Etica,
Evmos EVM, Fantom, Flare, Flow EVM, Fuse, Gnosis Chain, Harmony EVM, Kaia,
Kava EVM, Larissa Chain, Linea, Mantle, Merlin Chain, Metis Andromeda, Monad, Moonbeam,
Moonriver, Oasis Sapphire, OctaSpace, OKT Chain, opBNB, Optimism, Plasma, Polygon,
Polygon zkEVM, Robinhood Chain, Ronin, Rootstock, Scroll, Sei EVM, Telos EVM, Theta,
Unichain, VirBiCoin, X Layer, XinFin Network, zkSync Era
```

Theta is the one network with two routes: TFUEL transfers use the EVM adapter, native `SendTx`
uses the Theta adapter, and the payload format decides which runs.

78 token records are pinned across 18 networks (`WalletTokens.cpp`). User-declared tokens can be
added on the device; the review marks them as declared, and they never change the signed bytes.

## Native adapters

These take a payload in their own format through `chain begin <network> <index> <payload-hex>`.
The exact envelope is in [Chain-Payloads](Chain-Payloads).

| Entry | Scope notes |
| --- | --- |
| `xmr` | RCT type 6, CLSAG, Bulletproofs+, 16-member rings, subaddress spends; decoys come from the phone |
| `alph` | Native ALPH P2PKH transfers with one recipient, optional wallet change and reviewed gas. The transaction ID and signature match Alephium SDK 3.0.5. |
| `quantus` | Mainnet runtime 153/6. Transparent ML-DSA-87 accounts, SS58 prefix 189 and signed v4 balances transfers with nonce, tip and era review. |
| `zeph` | Native ZPH transfers with the Zephyr v3 prefix, RingCT type 6 and 16-member CLSAG rings. Spend and view keys use the agreed XMR derivation. Addresses and asset fields are network-specific. |
| `trx` | Owner-permission transfers, TRC-10, registered TRC-20, printable memo ≤ 64 bytes; no NFT, batch or multi-contract |
| `xlm` | SEP-0005, public XDR Payment/CreateAccount, issued assets and memo review; ≤ 8 operations |
| `sol` | Legacy/v0, System Transfer, SPL and Token-2022 `TransferChecked`, exact mint/account review; no ALTs or ATA creation |
| `xrp` | Native Payment, canonical XRPL binary, SHA-512Half; no issued currencies, paths, memo, partial payment or multisig |
| `atom`, `osmo`, `tia`, `kava`, `terra`, `terraclassic` | 1–4 `MsgSend`, `SIGN_MODE_DIRECT`, optional memo; no IBC, authz, wasm or amino signing |
| `ada` | Conway body review and Ed25519-BIP32 signing; no input value/owner, so balance needs a node |
| `algo` | Canonical MessagePack `pay`/`axfer`, genesis/fee/round checks, ASA opt-in; mainnet only |
| `apt` | Aptos transfer payloads with Ed25519 authentication key derivation |
| `ckb` | Secp256k1 sighash and Molecule serialisation |
| `dcr` | BLAKE-256, legacy prefix/witness sighash, P2PKH |
| `erg` | P2PK ProveDlog: the device rebuilds the tx-id preimage and returns a complete proof transaction |
| `fil` | CBOR `Send`, CID digest, f1 sender |
| `hbar` | Hedera transfer body signing |
| `hive` | Review + sign only: an STM public key is not a receive address, so this entry has no address capability |
| `icp` | Ed25519 request signing with the IC principal derivation |
| `vet` | Compact payload, canonical RLP, BLAKE2b-256, recoverable signature; single-clause VET only |
| `icx` | `icx_sendTransaction` canonical text, SHA3-256; native ICX only |
| `dot`, `ksm` | `DOT2` payload, pinned runtime `spec_version`/`transaction_version`, short-lived era + tip; the historical DOT1 layout is host-test only |
| `qrl` | XMSS/SHAKE-256 height 10; the leaf is reserved in durable storage before signing, and the device verifies its own signature |
| `qrl2` | ML-DSA-87 accounts, SHAKE-256 checksummed `Q` address, keccak-256 envelope; mainnet chain id 1 only |
| `stark` | Stark curve keys, Cairo v3 `deploy_account` and one ERC-20 `transfer` via `execute`; `SN_MAIN` only |
| `theta` | Native 46-byte `SendTx` payload; EVM transfers of TFUEL go through the EVM entry |
| `ton` | Wallet v4R2 cell/BoC serialisation, user-friendly address, empty body |
| `sui` | BCS split-gas native transfer, Ed25519; no Move calls, sponsorship or tokens |
| `xch` | Chia `CREATE_COIN` only; BLS12-381 G1 keys |
| `xem` | NEM Keccak-Ed25519 variant; not RFC 8032 Ed25519 |

## Address only

| Entry | Why |
| --- | --- |
| `ryo` | CryptoNote long address, prefix `0x2ce192` |
| `zano` | CryptoNote `Zx` address, prefix `0xc5` |

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
