# HexWallet

Display, TOTP, USB/NFC and FIDO2 implementation boundaries are tracked in [authentication status](docs/authentication-status.md). CTAPHID transport alone is not a working passkey authenticator.

MiningPoolStats identity mappings, exact capability scope and the 64-entry custom token store are documented in [network registry](docs/network-registry.md). The [complete snapshot report](docs/miningpoolstats-coverage.md) includes unmapped projects; a website listing is not a wallet-support claim.

> Every chain in the table below has a signing path in this tree; none of them has
> completed hardware or node acceptance. Latest additions: Starknet (Cairo v3
> `deploy_account`, and `execute` with 1-4 ERC-20 `transfer` calls), QRL v2
> (ML-DSA-87), Aptos, and user-declared tokens on EVM, TRON, Solana, Stellar and
> Starknet. MSR support was withdrawn on 2026-10-24. Per-chain scope and the
> evidence behind each claim are in [chain-gates](docs/chain-gates.md).

HexWallet is an offline-first hardware wallet for ESP32-S3. It derives keys from a BIP39 seed, builds and reviews transactions on the MCU, and signs only after a one-time confirmation on the trusted display. The host never receives the seed or private keys.

The public wallet catalog is filtered by the configured signing policies. This filter is not proof that every listed chain has passed independent consensus or hardware validation. Address-only profiles and MiningPoolStats listings without an adapter are not exposed as wallets. That is deliberate: a ticker in a catalog is not a wallet.

## Security model

- BIP39/BIP32 derivation and all signing happen on the device. Secret export is disabled by default (`HEXWALLET_ENABLE_SECRET_EXPORT=0`).
- Secure-element custody is a contract, not a claim: `SecureElementPort.h` requires every backend operation, allows one backend per boot, and unregisters a backend that reports success without an authenticated card session. No backend ships today, so the SE051C2HQ1 profile never becomes active and `HEXWALLET_REQUIRE_SECURE_CUSTODY=1` refuses to open a wallet. See [docs/security.md](docs/security.md).
- Every signing request is parsed into a bounded review structure and displayed on the trusted UI. Phone-link signing requires a single-use on-device approval with a 120-second lifetime.
- Bitcoin PSBT inputs must commit to wallet-owned UTXOs. Zcash payloads must carry every prevout value/script, and the signer re-derives and checks each P2PKH hash. Kaspa payloads are validated against BIP340 keys and KIP-0009 mass.
- Fee caps, amount bounds, duplicate-input checks, canonical encoding checks, and explicit refusal of unsupported transaction families are enforced before ECDSA/Schnorr.
- Host-only confirmation is disabled unless the firmware is built with `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION=1`. Production devices should use a trusted display.
- The boot self-test must pass before wallet services start. A failure disables the wallet instead of degrading silently.

## Supported wallets

| Family | Receive | Review + sign | Scope |
| --- | --- | --- | --- |
| Bitcoin | BIP44/BIP49/BIP84 | PSBT v0, `SIGHASH_ALL` | Native SegWit, nested SegWit, legacy P2PKH |
| Bitcoin-family forks | P2PKH / SegWit profiles | Legacy sighash or BIP143 + `SIGHASH_FORKID` | Litecoin, Dogecoin, Dash, DigiByte, Bitcoin Gold, Ravencoin, Namecoin, Vertcoin, Axe, BCH, BSV, XEC, Sugarchain, e-Gulden, LBRY, MazaCoin, Myriad, NewYorkCoin, Auroracoin, Bitcore, CPUchain, DigitalCoin, Einsteinium, Feathercoin, GoByte, Monacoin, Ritocoin, VIVO, and other source-verified generated profiles |
| EVM | BIP44 secp256k1 | EIP-155 / EIP-1559, native and whitelisted token calls | 69 registered networks; BSC BEP-20 registry has 26 RPC-checked contracts |
| XRP | BIP44 secp256k1, `m/44'/144'/0'/0/i` | Native Payment, canonical XRPL binary, SHA-512Half, secp256k1 DER | No issued currency, paths, memo, partial payments or multisig |
| TRON | BIP44 secp256k1, `m/44'/195'/0'/0/i` | Owner-permission `TransferContract`, `TransferAssetContract` (TRC-10), registered TRC-20 `transfer`/self-`transferFrom`, printable memo ≤64 bytes | No TRC-721/1155 (no NFT registration exists, every request is refused), batch NFT, multi-contract, multisig or third-party-debit `transferFrom`; unregistered TRC-10 ids show exact base units |
| Stellar | SEP-0005 Ed25519, `m/44'/148'/i'` | Public-network XDR Payment/CreateAccount, issued-asset issuer and memo review | Up to eight operations; G addresses; no fee bump, muxed accounts, Soroban or multisig |
| Solana | SLIP-0010 ed25519, `m/44'/501'/0'/0'/i'` | Legacy/v0, System Transfer, SPL and Token-2022 `TransferChecked` | Single payer; no ALTs, ATA creation, staking or extra token accounts |
| Cosmos SDK | BIP44 secp256k1 | 1-4 `MsgSend`s, `SIGN_MODE_DIRECT`, optional memo, native or verbatim denom (unpinned precision renders exact base units) | ATOM, OSMO, TIA, KAVA (Cosmos), LUNA, LUNC; no IBC packet messages, authz, wasm execute or amino/JSON signing |
| Airgap | — | 枚举帧计划（有界步长合成）+ 帧头 CRC + 发送/接收状态机 + 重扫提示 | UI 帧动画与摄像头侧解码尚未接线（传输层已可验收） |
| Algorand | SLIP-0010 Ed25519, `m/44'/283'/0'/0'/i'` | Canonical MessagePack `pay`/`axfer`, genesis/fee/round checks, ASA transfer and opt-in | Mainnet only; no groups, rekey, close, clawback, LogicSig or application calls |
| NEAR | SLIP-0010 Ed25519, `m/44'/397'/i'` | Borsh `TransactionV0`, 1–16 native Transfers, SHA-256/Ed25519 | Implicit accounts only; no FunctionCall, access keys, delegation or staking |
| Tezos | SLIP-0010 Ed25519, `m/44'/1729'/account'/change'/index'` | Manager operations, optional reveal, tz1–tz4 native transfers, BLAKE2b/Ed25519 | No KT1, Michelson, delegation or FA tokens; branch origin not authenticated |
| Kaspa | BIP44 secp256k1 | BIP340 Schnorr, v0 transactions | `SIGHASH_ALL`, KIP-0009 mass |
| Zcash | BIP44 secp256k1, t1/t3 addresses | ZIP-243, v4 transparent, NU6.2 | t1 P2PKH and t3 P2SH-P2PK inputs, t1/t3 outputs; no multisig or other redeem scripts |
| Monero | BIP44 ed25519, `m/44'/128'/0'/0/i` | RCT type 6, CLSAG, Bulletproofs+, 16-member rings | Standard and subaddress spending, account 0 |
| Aeternity | SLIP-0010 Ed25519, `m/44'/457'/0'/0'/i'` | Address verification only | `ak_` account address; native spend signing is not enabled |
| RyoCurrency | BIP44 secp256k1, `m/44'/382'/0'/0/i` | Address verification only | CryptoNote long address, prefix `0x2ce192`; review/signing not enabled |
| Zano | BIP44 secp256k1, `m/44'/1018'/0'/0/i` | Address verification only | `Zx` CryptoNote address, prefix `0xc5`; review/signing not enabled |
| Cardano | Ledger CIP-1852 Ed25519-BIP32, `m/1852'/1815'/a'/role/i` | Native ADA body review and Ed25519-BIP32 signing | Body carries no input value/owner; UTxO ownership and balance need a node; no tokens, scripts or staking |
| Ergo | BIP44 secp256k1 | P2PK ProveDlog: the device rebuilds the tx-id preimage and returns a complete 56-byte-proof transaction | One external output with every token listed; host-supplied fee; no scripts, multisig or non-P2PK inputs |
| VeChain | BIP44 secp256k1, `m/44'/818'/0'/0/i` | Compact payload, canonical RLP, BLAKE2b-256, recoverable signature | Single-clause native VET only; no contract calls, multi-clause or VIP-191 delegation |
| ICON | BIP44 secp256k1, `m/44'/74'/0'/0/i` | `icx_sendTransaction` canonical text, SHA3-256 | Native ICX only; no SCORE calls; nid/nonce/timestamp need node checks |
| Sui | SLIP-0010 Ed25519, `m/44'/784'/0'/0'/i'` | BCS split-gas native SUI transfer, Ed25519 address and signature | No Move calls, sponsorship or tokens |
| Filecoin | BIP44 secp256k1, `m/44'/461'/0'/0/i` | CBOR `Send`, CID digest, f1 sender | f1 recipients only; no actor calls or BLS |
| TON | SLIP-0010 Ed25519, `m/44'/607'/0'/0'/i'` | Wallet v4R2 cell/BoC serialization, user-friendly address | Native transfer with an empty body; no jettons or comments |
| Decred | BIP44 secp256k1, `m/44'/42'/0'/0/i` | BLAKE-256, legacy prefix/witness sighash, P2PKH | Single-input transparent transfer; no staking, treasury or mix |
| Nervos CKB | BIP44 secp256k1, `m/44'/309'/0'/0/i` | Molecule `RawTransaction`, `ckb-default-hash` BLAKE2b, SECP256K1/blake160 lock | One input, 1–2 outputs, no type script; no DAO or UDT |
| Hive | BIP44 secp256k1, `m/44'/3054'/0'/0/i` | Single transfer, binary asset, graphene compact signature | `STM` is a public key, not a receive address; account ownership needs a node; no encrypted memo |
| Internet Computer | SLIP-0010 Ed25519, `m/44'/223'/0'/0'/i'` | Fixed ICP ledger canister Candid transfer, request id, CBOR envelope | Default ledger account only; no arbitrary canisters, ICRC or staking |
| Polkadot / Kusama | SLIP-0010 Ed25519, `m/44'/coin'/0'/0'/i'` | `balances.transfer` / `transferKeepAlive`, mortal era and tip, SCALE extrinsic | Signed extensions pinned to runtime 2005002/26 (DOT) and 2005001/26 (KSM) with genesis pinned; `CheckMetadataHash` carried as an explicitly disabled mode; a runtime upgrade needs a firmware update |
| Chia | EIP-2333 from the BIP39 seed, `[12381, 8444, 0, i]` | Standard coin spend: the device rebuilds `(q . conditions)`, hashes the tree itself and signs AGG_SIG_ME | CREATE_COIN-only standard coins; CAT/NFT, plot-NFT and offer spends are refused |
| QRL (v1) | BIP39 seed → SHAKE-256 → XMSS(sk_seed, pub_seed), hash height 10 | Native transfer preimage `master ‖ fee ‖ message ‖ (addr ‖ amount)*`, XMSS/SHAKE-256 signature | One-time leaf reserved in durable NVS before the signature exists and the signature is self-verified. Use the `qrl2` catalog id for v2 accounts |
| QRL v2 (Zond) | BIP44 `m/44'/238'/a'/c/i`, child key seeds ML-DSA-87 | `0x02` dynamic-fee envelope, keccak-256 digest, hedged ML-DSA-87 signature | Mainnet chain id 1, descriptor `01 00 00`, empty extra params; no staking, tokens or cross-chain messages |
| Aptos | SLIP-0010 Ed25519, `m/44'/637'/account'/0'/index'` | `0x1::aptos_account::transfer` BCS `RawTransaction`, `sha3-256("APTOS::RawTransaction" ‖ BCS)` | Native APT only; no arbitrary EntryFunction, multisig, sponsored transactions or FA tokens |
| Starknet | BIP44 `m/44'/9004'/a'/c/i`, child key ground into a Stark scalar | Cairo v3 `deploy_account` and account `execute` with 1-4 ERC-20 `transfer` calls, Pedersen/Poseidon v3 hash, Stark-curve ECDSA | The account address is recomputed per transaction from class hash, salt and the single-key constructor, so a host cannot swap in a foreign account; `SN_MAIN` only. No `declare`, paymaster, multisig or session keys, and no more than four calls, because five would not fit the review |

Address-only profiles (no transaction signing): Aeternity, RyoCurrency and Zano.

The Aeternity, RyoCurrency and Zano rows above are deliberately address-only:
the encoders are vector-checked, but there is no reviewed transaction format,
fee policy or signing path for them yet. Presenting them as signable wallets
would be worse than omitting them.

BEP-20 coverage is a registry, not a blind-signing fallback. `WalletTokens.cpp`
registers 79 token rows over 61 EVM networks (27 of them BSC), and
`tools/token_audit.ps1` re-checks every EVM row against the live chain with
`symbol()` / `decimals()` / `name()`: a decimals mismatch fails the audit, a label
drift is only reported, because issuers rename contracts in place - Arbitrum's USDT
contract now reports `USD-T0` at the same address with the same 6 decimals. An
unregistered contract is still rejected.

User-declared tokens live in `WalletCustomTokens`: at most eight records, each
bound to one network and one chain-native identifier - a 20-byte EVM contract, a
21-byte TRON account, a 32-byte SPL mint, a Stellar issuer plus asset code, or a
32-byte Starknet contract address. The width follows the network, so a caller
cannot file an Ethereum-shaped key under a Starknet token. The table is one
digest-checked blob; a torn or edited blob is rejected whole instead of being
half-applied, and v1 (EVM-only) blobs are upgraded on load.

A record is a label, never an authorization. The amount that gets signed is
always the base-unit integer the chain carries; the device only rescales it for
display, and when it does, the row is marked `UNVERIFIED` and the note says the
label came from this device rather than the issuer. Shipped registry rows win
over user records. Device commands: `token custom-list`, `token custom-add
<network> <id-hex> <symbol> <name> <decimals>`, `token custom-add-stellar
<issuer-hex> <code> <symbol> <name> <decimals>`, and the matching
`custom-remove` forms. Without a record the device prints the raw amount
(`1500000 raw`) rather than guessing decimals.

The strict catalog is generated from `WalletForkCatalog.inc` and `WalletCatalog.cpp`. A profile whose network lacks a signing policy is internal test data, not a user wallet.

Generated fork profiles are admitted only after the upstream chainparams were checked for base58 versions, a legacy P2PKH sighash and a transaction header without `nTime` or a wide `nType`; `tools/fork_registry.json` records that audit per row. Fork-id, timestamp-sighash, and wide-type chains stay address-only: the Bitcoin legacy signer is never used as a guess.

## Deliberately unsupported

- Zcash shielded addresses, shielded spends/outputs, JoinSplits, and v3/v5 transactions.
- Spending t3 P2SH Zcash outputs whose redeem script is anything but a single-key `CHECKSIG`. P2SH-P2PK spends are signed (ZIP-243 commits the redeem script and the device re-hashes it against the address); multisig and non-canonical redeem scripts are refused.
- Peercoin signing. PPC v<3 transactions serialize `nTime`; the Bitcoin legacy signer would build an invalid transaction. PPC is an internal address primitive, not a wallet, until a dedicated Peercoin sighash family with vectors lands.
- XMR subaddress output support outside the verified forms. A single subaddress destination and mixed/multi-destination transactions using the version-3 additional-key binding are reviewed; malformed, unbound, or MSR subaddress outputs remain rejected.
- Starknet beyond the two admitted operations: `declare`, `deploy` of non-account contracts,
  paymaster-sponsored fees, multisig or session-key accounts, batches larger than four calls, and
  every network other than `SN_MAIN`. Calls other than ERC-20 `transfer` are refused instead of
  being signed as an opaque digest, so an approve-then-swap batch has to be sent from a phone-only
  wallet for now. See [chain gates](docs/chain-gates.md).
- Theta and Pearl (PRL) need chain-specific native signing (the Theta EVM only moves TFUEL), and
  Beam needs the Mimblewimble slate exchange; none of the three is admitted.
- Qubic. Its identity is a FourQ point hashed with KangarooTwelve, so no Ed25519/SHA3 substitute is shipped: the profile and encoder were removed rather than returning a plausible-looking address.
- Flux. The MiningPoolStats snapshot of 2026-10-23 lists FLUX under GRAVEYARD, and graveyard identities are not admitted to production registries. The ZIP-243 engine remains in use for Zcash.
- TRON TRC-721/1155 transfers: the calldata decoder exists, but no NFT contract registration exists, so every request is refused instead of trusting an unregistered contract. Also batch NFT transfers, non-empty NFT callback data, multi-contract transactions, non-owner permissions, memos that are not printable ASCII or longer than 64 bytes, and `transferFrom` that debits a third party's balance. TRC-10 transfers, self-`transferFrom` and printable memos are reviewed and signed.
- Dash signing is done by a dedicated adapter, not the PSBT path: a plain Dash transaction is `nVersion` (type in the high 16 bits), `vin`, `vout`, `nLockTime` with no `extraPayload`, and the digest is Bitcoin's legacy algorithm over exactly those bytes. Both claims are pinned to two live mainnet transactions whose on-chain signatures verify against the digest this firmware computes. Type-0 P2PKH payments only; the special transaction types (`extraPayload`) are refused. InstantSend adds no bytes - it is a quorum lock on inputs - so the device signs the payment and the phone confirms the lock.
- Cosmos IBC packet/timeout messages, authz/feegrant and JSON/amino signing modes. Up to four bank sends per transaction, memos and non-native denoms are reviewed and signed; a denom without pinned metadata is displayed verbatim with the exact base-unit amount.
- Blind signing of unknown tokens by address. Any EVM transaction whose calldata is not a registered token call is reviewed as **raw bytes**: the screen shows the envelope, the full data hex, its keccak-256, the exact call value and, for creation, the address the deploy will produce. That is a deliberate "you are signing code, not a transfer" mode, not a decoded transfer. See [access-list policy](docs/evm-access-lists.md).
- Beam, Grin, MimbleWimbleCoin and Epic Cash as wallets. These are interactive Mimblewimble chains: there is no static UTXO address, and a spend needs a multi-round slate/transaction exchange. A base58 string there is a slatepack/BBS endpoint, not a normal wallet address, so none is exposed.
- Super Zero (SERO). Its 64/96-byte account identities are superzk public-key bundles, not a single-key address; no vetted encoder or signing path exists in this tree.
- Swap (XWP), Evolution (EVOX), VeriBlock (VBK). These chains have no SLIP-0044 coin type in the current registry. Reusing Bitcoin's coin type (or another chain's) would silently derive the same key material for two domains; until an upstream coin type and a vector-checked encoder exist, they stay out of the catalog.
- Aeternity, RyoCurrency and Zano transaction review/signing. Their address encoders are enabled and tested; the signing paths are not.

## Architecture

| Module | Responsibility |
| --- | --- |
| `WalletSecurity` | BIP39, BIP32, secp256k1, KDFs, zeroization |
| `WalletEngine` | Path construction, address derivation, custody-facing key material |
| `WalletNetworks` | Network profiles, address encoding, signing policy, Zcash branch policy |
| `WalletCatalog` | Strict user-facing wallet catalog |
| `WalletMiningCatalog` | MiningPoolStats coverage restricted to fully supported wallets |
| `WalletCli` | Authenticated serial CLI and approval flow |
| `WalletLink` | Phone link: pairing, Ed25519 handshake, session, replay protection |
| `WalletLinkCrypto` | HKDF-SHA256, ChaCha20, encrypt-then-MAC for the link |
| `WalletNfcApdu` | ISO 7816-4 APDU application that carries link frames |
| `WalletNfcPort` | PN7161 NCI port (card emulation), pin-gated |
| `WalletLinkService` | Link request dispatch: address, catalog, begin-sign, result |
| `WalletSigning` | Shared on-device review + approve + sign session |
| `WalletUi` | Trusted-display transaction review |
| `WalletCustody` | MCU vs secure-element capability policy |
| `SecureElementPort` | SE051 backend contract, custody gate, ISO 7816-3 CRC16/A + ATR, AES-128, AES-CMAC |
| `EinkPanel` | SSD1680 mono (1bpp, OTP partial waveform) and SSD1683-class four-color (2bpp, full refresh only) command sequences, damage policy |
| `QrCode` | Byte-mode QR v1-3 (L/M) encoder and 1bpp renderer |
| `CoinIcons` | 32x32 I1 coin marks for the review header, packed from CC0 artwork with no decoder in flash |
| `QrlOtsJournal` | Durable one-time-signature index reservation: two redundant slots, read-back proof, torn-write skip, refuse-when-unknown |
| `BitcoinTransaction` | PSBT v0, legacy/BIP143/fork-id sighash, serialization |
| `EvmTransaction` | RLP, EIP-155/EIP-1559, token-call review and signing |
| `KaspaTransaction` | BLAKE2b sighash, KIP-0009 mass, BIP340 signing, protobuf |
| `ZcashTransaction` | v4 transparent parser, ZIP-243 digest, t1 P2PKH and t3 P2SH-P2PK signing, t1/t3 output rendering |
| `DashTransaction` | type-0 plain payments, legacy digest pinned to live mainnet signatures, P2PKH/P2SH outputs |
| `CryptoNoteRingCt` | Monero hash-to-scalar, key derivation, one-time keys, key images, view tags, CLSAG sign/verify; key layer official vector-pinned |
| `CryptoNoteOutputScan` | On-device output ownership test with the view secret (no view-key export) |
| `CryptoNoteTransaction` | Strict RCT type-6 parse + byte-exact rewrite + commitment balance + CLSAG signing (`cryptonote_sign_input`) |
| `CryptoNoteSpend` | Device-side XMR send assembly: one-time outputs, amounts/commitments, solved pseudo-output masks, per-input CLSAG, serialization |
| `CryptoNoteReview` | Per-network policy (fee cap, ring size), key-offset/RCT binding, CLSAG `D` check, honest decoy caveat |
| `CryptoNoteSigning` | Host payload parse → review → per-input CLSAG → serialized transaction; session state and zeroization |
| `CryptoNoteMasari` | Legacy regression source; MSR is not exposed as a wallet |
| `MoneroTxVectorsTest.inc` | Real mainnet RCT type-6 transactions pinned for parse/rewrite/balance regression |
| `TokenCalldata` | ERC-20/721/1155/4626/777/3525/6551 and LayerZero ABI decoding; ERC-20 needs registered decimals, unique NFT selectors may be reviewed unregistered |
| `WalletTokens` | Registered EVM token metadata |
| `WalletCustomTokens` | User-declared tokens for EVM, TRON, Solana, Stellar and Starknet: one digest-checked blob, per-network key widths |
| `MlDsa87` | FIPS 204 ML-DSA-87 keygen/sign/verify, used by QRL v2 |
| `P256Sign` | NIST P-256 ECDSA with RFC 6979 nonces, low-S and strict DER; the ES256 primitive a CTAP2 authenticator needs |
| `src/EcdsaCurve.h` | One ECDSA engine for both 256-bit curves the wallet signs on — secp256k1 (`a = 0`) and secp256r1 (`a = -3`) — with RFC 6979, low-S, strict DER and a verifier. Runs on the host, so a produced signature can be checked without mbedtls; the Montgomery factors are derived from the modulus instead of being transcribed |
| `src/Secp256k1Sign.h` | secp256k1 ECDSA sign/verify through mbedtls, with RFC 6979 determinism, low-S and a self-check on the curve |
| `Ed25519` / X25519 | RFC 8032 Ed25519 (sign, verify, Edwards point/scalar arithmetic) plus RFC 7748 X25519, the iterated test, and the birational map from an Ed25519 identity to its Curve25519 public key |
| `Se051Apdu` | SE05x/SE051 applet command encoding: CLA/INS/P1/P2/TLV tables transcribed from NXP plug-and-trust, `CreateECCurve`/`SetECCurveParam`/`ReadECCurveList`, ECDSA/EdDSA signing, ECDH, the one-shot HMAC the in-card BIP32 design needs, and session commands |
| `QrlV2Transaction` | QRL v2 dynamic-fee envelope, keccak-256 digest, ML-DSA-87 signature |
| `AptosTransaction` | BCS `RawTransaction`, `APTOS::RawTransaction` domain hash, Ed25519 authenticator |
| `StarknetCrypto` | Stark curve field/point arithmetic, Pedersen, Poseidon, Stark ECDSA, SNIP-5 address, Cairo v3 hashes |
| `StarknetTransaction` | v3 `deploy_account`/`execute` review: address recomputation, per-call rows, ERC-20 decode |

## Serial CLI

Public metadata works while locked:

```text
help | status | coin list | coin search <text> | coin show <id>
mining stats | mining list [ASIC|GPU|CPU|HDD] [offset] | mining show <symbol>
token list [network] | token show <id>
```

Authenticated wallet and signing commands:

```text
auth provision <pin> <pin>
auth begin
auth unlock <proof-hex>
lock | selftest
wallet generate | wallet import <mnemonic>
wallet address <id> [index]
wallet custody <id>
wallet token <id> [index]
wallet addresses [index]
tx inspect [<coin>] <psbt-v0-hex> | tx sign <code>
evm inspect <network> <index> <unsigned-rlp-hex> | evm sign <code>
kaspa inspect <payload-hex> | kaspa sign <code>
zec inspect <ZEC4-payload-hex> | zec sign <code>
link status | link pair confirm | link pair reject
tx reject
```

`zec inspect` accepts `ZEC4` payloads and `ZEC5` payloads, which add the redeem script needed to spend a t3 P2SH-P2PK prevout; the layout is specified in [docs/chain-protocols.md](docs/chain-protocols.md). Build the payload on the host and compare the printed ZIP-243 digest against an independent implementation before signing.

## Build

Install `arduino-cli`, ESP32 core `3.3.10`, and LVGL `9.5.0`:

```powershell
arduino-cli core install esp32:esp32@3.3.10
git clone --depth 1 --branch v9.5.0 https://github.com/lvgl/lvgl.git "$HOME/Arduino/libraries/lvgl"
arduino-cli compile --fqbn esp32:esp32:esp32s3 `
  --library "$HOME/Arduino/libraries/lvgl" `
  --build-property compiler.cpp.extra_flags=-DLV_CONF_INCLUDE_SIMPLE `
  --build-property compiler.c.extra_flags=-DLV_CONF_INCLUDE_SIMPLE .
```

The headless build uses `-DHEXWALLET_BOARD=6 -DHEXWALLET_ENABLE_LVGL=0`. See `partitions/hexwallet-16mb-ota.csv` for the flash layout.

The ESP32-P4 hardware wallet (`--fqbn esp32:esp32:esp32p4`) selects its pin map with `-DHEXWALLET_BOARD=7`: 2.9" 128x296 e-paper on SPI, SE051C2HQ1 on `Wire1`, PN7161 on the shared SPI bus. `HEXWALLET_EPD_PROFILE` picks the panel (0 mono, 1 four-color, 2 mono V2) and `HEXWALLET_EPD_COLORS` must agree with it; partial refresh runs on the controller's OTP waveform, a board that needs its own waveform defines the 159-byte `HEXWALLET_EPD_PARTIAL_LUT`, and profile 1 additionally requires a `HEXWALLET_EPD_COLOR_INIT` register table because the driver refuses to guess four-color analogue settings. Every pin comes from the EasyEDA project nets; see [docs/display.md](docs/display.md) for the table and for what is deliberately not enabled yet.

## Verification

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1 -Target esp32p4
powershell -ExecutionPolicy Bypass -File tests/host/board_port_compile_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/qr_cross_check.ps1   # needs network once
powershell -ExecutionPolicy Bypass -File tests/host/build_chain_native.ps1   # needs build/chain-mbedtls
powershell -ExecutionPolicy Bypass -File tests/host/policy_check.ps1
```

Expected host results include:

```text
crypto-primitives=pass
alt-addresses=pass
blake2b=pass
cryptonote-ringct=pass
cryptonote-review=pass
cryptonote-signing=pass
masari=pass
networks=pass
sighash=pass
kaspa=pass
zcash=pass
catalog=pass
mining-catalog=pass
tokens=pass
link-crypto=pass
wallet-link=pass
nfc-apdu=pass
secure-element=pass
eink-panel=pass
qrcode=pass
qrl-ots=pass
ml-dsa-87=pass
solana=pass
starknet-crypto=pass
custom-tokens=pass
```

`run_zcash_sighash_self_tests()` checks the published ZIP-243 transparent vector and selected `zcash-test-vectors` rows covering shielded hashes, JoinSplits and ALL/NONE/SINGLE. `run_zcash_transaction_self_test()` runs the full ECDSA/scriptSig/round-trip path on the device.

`run_evm_derivation_self_test()` pins the official Conflux Ledger app vector (`m/44'/503'/0'/0/0`), including the uncompressed public key and `0x` address. `run_address_self_tests()` independently re-checks that address from the same public key on the host.

`run_cryptonote_ringct_self_tests()` pins selected `monero/tests/crypto/tests.txt` vectors for hash-to-scalar, key derivation, public/secret key derivation, key images and view tags. `run_cryptonote_clsag_self_test()` signs and verifies a deterministic 3-member ring and rejects tampered `s`, `I` and message. `run_cryptonote_review_self_tests()` rejects thirteen tampering classes against a proof generated by the pinned Monero reference build, and `run_cryptonote_signing_self_tests()` drives the whole payload → review → CLSAG → serialize path plus the subaddress spend path (the subaddress key pair is cross-checked against the pinned Monero subaddress addresses, and the standard spend secret must fail to sign a subaddress output). `run_masari_self_tests()` verifies the real upstream Masari transaction vector (`tests/fixtures/masari/tx2.bin`), an end-to-end synthetic RCT type-2 spend, and the fail-closed type-3 gate.

An offline signer cannot prove that ring decoys exist on chain; it proves ring consistency, ownership and offset binding only. The phone is trusted to supply live decoys, never amounts, fees or destination addresses. See [xmr-review.md](docs/chain-protocols.md) and [xmr-signing.md](docs/chain-protocols.md).

## Phone link (NFC / USB)

Sending is initiated by the phone. The wallet only reviews, authorizes and signs; it never builds the transaction and never talks to a node. The full wire format is in [docs/phone-link-protocol.md](docs/phone-link-protocol.md); the former Python phone reference client has been removed. The wire format and C++ host tests remain.

- Receive: the phone calls `ADDRESS`; the device returns the derived public address and path. No private material crosses the link.
- Send: `BEGIN_SIGN` → the device parses and validates the request (input ownership, change derivation, fee caps, token whitelist, CryptoNote ring/key-image/commitment binding) → the trusted display shows recipient/amount/fee with `APPROVE` / `REJECT` → after the physical press the phone calls `RESULT` and receives the signed transaction bytes.
- Request payloads are capped at 16 KiB so a CryptoNote transaction fits; the CryptoNote layout is documented in [phone-link-protocol.md](docs/phone-link-protocol.md#7-cryptonotexmr--msr).
- Pairing: the first connection shows a six-digit code plus the phone fingerprint on the device; the phone key is then pinned and any other phone is refused.
- Link protection: Ed25519-signed handshake plus ephemeral ECDH (HKDF-SHA256 session keys), ChaCha20 + HMAC-SHA256 per frame with a strictly increasing sequence number. Forged, replayed, reordered or tampered frames fail and destroy the session.
- USB data is **off by default**: long-press the BOOT/user button for three seconds to open a bounded window; another long press, the timeout, or a lock closes it and discards buffered input.
- NFC uses a PN7161 (NCI 2.0) ISO-DEP card-emulation port. Pins must come from the schematic (`HEXWALLET_NFC_PN7161` + `HEXWALLET_NFC_PIN_*`); without them `link status` reports `nfc=not-configured` and the firmware does not guess pins. The driver has not yet been validated on hardware.
- Boards without a display never review a transaction over the link (`unsupported`); there is no fallback to host-only confirmation.

## MiningPoolStats coverage

The shipped mining table lists only rows that resolve to a fully supported wallet. Against the 2026-10-23 MiningPoolStats snapshot it covers **111 / 518 active listings** (ASIC 62/212, GPU 30/181, CPU 19/121, HDD 0/4); the remaining listings are absent on purpose rather than shipped as placeholder wallets.

Adding a family is a protocol project, not a catalog edit: consensus transaction format, official vectors, review rules, signing, failure paths, and custody policy must all land together.

## Flash, OTA and eFuses

Secure Boot v2, Flash Encryption, and OTA rollback are documented in `partitions/`.  Do not burn eFuses until the recovery image, signing-key backup, and rollback path have been validated on a sacrificial board. A wrong eFuse cannot be fixed by OTA.

## License

HEXWALLET PERSONAL NON-COMMERCIAL SOURCE LICENSE. See `LICENSE`.
