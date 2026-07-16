# HexWallet (BETA)

HexWallet is an offline ESP32 wallet firmware foundation with an authenticated serial interface and an LVGL 9.5.0 interface. It is experimental and must not hold real funds until the board port, secure storage, firmware trust chain, and independent security review are complete.

## Implemented

- BIP39 English 24-word generation, validation, and PBKDF2-HMAC-SHA512 seed derivation.
- BIP32 private/public child derivation and extended-key serialization.
- Data-driven address derivation through `WalletNetworks`, `WalletCatalog`, and `WalletEngine`.
- Authenticated serial sessions with challenge-response, persistent retry counters, exponential backoff, timeout, and volatile wallet clearing.
- Searchable coin catalog in both the CLI and LVGL 9.5.0.
- Bitcoin mainnet BIP49 nested P2SH-P2WPKH and BIP84 native P2WPKH PSBT v0 review and signing.
- Startup known-answer tests for SHA-256, RIPEMD-160, legacy Keccak-256, BIP39, BIP32, address encoding, BIP143, and RFC6979 ECDSA.

The Bitcoin signer accepts only bounded PSBT v0 requests whose inputs are wallet-controlled BIP49 P2SH-P2WPKH or BIP84 P2WPKH outputs. It accepts only `SIGHASH_ALL`, verifies each master fingerprint, public key, derivation path, UTXO script, and BIP49 redeem script, parses every output, rejects unknown output scripts, checks totals and overflow, enforces fee limits, produces low-S RFC6979 secp256k1 signatures, verifies each signature before release, and clears the one-time review state after success or failure. There is no arbitrary-digest signing command.

## Capability Matrix

| Networks | Address | Transaction review | Signing |
| --- | --- | --- | --- |
| Bitcoin `m/84'/0'` | Native P2WPKH | PSBT v0, P2WPKH inputs | BIP143 ECDSA |
| Bitcoin `m/49'/0'` | P2SH-P2WPKH | PSBT v0, P2SH-P2WPKH inputs | BIP143 ECDSA |
| Bitcoin `m/44'/0'` | P2PKH | No | No |
| Litecoin, Dogecoin, Dash, Bitcoin Gold, Ravencoin | P2PKH | No | No |
| Ethereum, Ethereum Classic, Optimism, Polygon, Fantom, Base, Arbitrum, Avalanche C-Chain, BSC | EVM address | No | No |
| XRP Ledger | Classic address | No | No |
| TRON | Base58Check account address | No | No |

The searchable catalog also lists ADA, ALGO, APTOS, ATOM, BCH, BSV, CKB, CRO, DGB, DOT, EOS, FIL, HBAR, ICP, KAS, KSM, NEAR, SOL, SUI, TON, VET, XEC, XLM, XMR, XTZ, ZEC, and other common SLIP-0044 entries as explicitly unsupported. They are visible so the UI does not misrepresent catalog discovery as wallet support.

SLIP-0044 is used only for registered hardened coin types. It does not specify address formats, network prefixes, hashes, scripts, or transaction rules. MiningPoolStats was used only to discover candidate networks. A network is not enabled from either list without address and transaction specifications and test vectors.

## CLI

When the board port reports no display, the authenticated CLI remains fully available. Metadata commands work while locked; wallet, secret export, and signing commands require authentication.

```text
coin list
coin search <text>
coin show <id>
wallet generate
wallet import <24 words>
wallet address <id> [index]
wallet addresses [index]
wallet secret [index]
tx inspect <psbt-v0-hex>
tx sign <six-digit-confirmation>
```

`tx inspect` prints every output, ownership classification, totals, fee, estimated virtual size, fee rate, and review ID before issuing a two-minute one-time confirmation code. See [CLI_PROTOCOL.md](CLI_PROTOCOL.md).

## Build

Install Espressif ESP32 board support 3.3.10 or later and LVGL 9.5.0. `WalletBoardPort.cpp` intentionally returns no display until it is implemented for the exact panel, bus, GPIO, input device, and power sequence. `ESP32-S3N8` identifies a chip memory configuration, not a LilyGo board model: it is insufficient to select a display or touch driver. The exact LilyGo product name, panel controller, touch controller, and board revision are required before enabling an interactive display port. Do not use a serial confirmation code as a substitute for a physical confirmation input.

Verified on 2026-07-16 with ESP32 Core 3.3.10:

- CLI/no LVGL: 410,280 bytes Flash, 46,724 bytes global RAM.
- LVGL 9.5.0: 491,640 bytes Flash, 47,348 bytes global RAM.

## Security Limits

The current PIN verifier and wallet exist in ordinary ESP32 memory/NVS. Production hardware still requires encrypted storage or a reviewed secure element, Flash Encryption, Secure Boot, anti-rollback, authenticated firmware updates, physical confirmation buttons, a trusted display path, side-channel and fault-injection evaluation, recovery tests, reproducible builds, and an independent audit. A serial confirmation code protects against accidental signing but cannot protect against a host that controls the same authenticated serial session.

Bitcoin BIP49 P2SH-P2WPKH and BIP84 P2WPKH signing are implemented. Legacy P2PKH remains unavailable because a secure signer must validate the complete `non_witness_utxo` and its txid before trusting an input value. EVM, TRON, XRP, altcoin transaction formats, PSBT v2, Taproot, multisig, script-path spends, and arbitrary scripts are rejected or unavailable.
