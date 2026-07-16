# HexWallet

HexWallet is an offline ESP32 wallet firmware foundation. It derives addresses from a volatile BIP39 wallet, provides an authenticated serial interface, reviews bounded Bitcoin PSBT requests, and keeps network and token metadata in explicit registries. It is beta firmware, not a production hardware wallet, and must not hold real funds until the hardware port and security controls are complete.

## What Is Implemented

- BIP39 English 24-word generation, validation, and PBKDF2-HMAC-SHA512 seed derivation.
- BIP32 private and public child derivation, extended-key serialization, and startup known-answer tests.
- Bitcoin mainnet PSBT v0 review and signing for BIP84 P2WPKH and BIP49 P2SH-P2WPKH inputs using `SIGHASH_ALL`, BIP143, low-S RFC6979 ECDSA, fee limits, and one-time review confirmation.
- Strict EIP-155 legacy and EIP-1559 type-2 review/signing for registered EVM networks. Only native transfers and `transfer(address,uint256)` calls to registered ERC-20 contracts are accepted.
- Address derivation for Bitcoin, Litecoin, Dogecoin, Dash, Bitcoin Gold, Ravencoin, XRP Ledger, TRON, Monero, Masari, and the registered EVM networks in `WalletNetworks.cpp`.
- CryptoNote standard-address construction for Monero and Masari: Keccak scalar derivation, Edwards25519 public keys, network prefixes, block Base58, and checksums. Transaction parsing and signing are not enabled.
- Token metadata and account-address lookup for registered ERC-20 assets. An ERC-20 token uses the same EVM account address as its network; the registry records the contract address and decimal precision.
- A searchable SLIP-0044 catalog that distinguishes address support, token-account support, transaction review, and signing support.
- Authenticated CLI sessions with challenge-response authentication, persistent retry counters, exponential backoff, timeout, and volatile wallet clearing.

## Architecture

| Module | Responsibility |
| --- | --- |
| `WalletSecurity` | BIP39, BIP32, secp256k1 operations, KDFs, secure zeroization |
| `CryptoNoteAddress` | CryptoNote scalar derivation, Edwards25519 public keys, Base58 standard addresses |
| `EvmTransaction` | Canonical RLP parsing, EIP-155/EIP-1559 review, registered ERC-20 transfer signing |
| `WalletNetworks` | Native-chain metadata, registered SLIP-0044 type, derivation type, address encoding, EVM chain ID |
| `WalletTokens` | Token standard, owning network, contract or mint identifier, precision, real capability state |
| `WalletEngine` | Derivation path construction and address encoding |
| `WalletCatalog` | Searchable user-facing capability catalog |
| `BitcoinTransaction` | Strict PSBT v0 parser, transaction review, BIP143 signing, final serialization |
| `WalletCli` | Authenticated serial command parsing and output |
| `WalletBoardPort` | Board-specific display, input, and power integration |
| `WalletTransportPolicy` | Fail-closed Serial/BLE/Wi-Fi operation policy |

The registries are intentionally data-only. Adding a SLIP-0044 number does not enable a chain. A chain requires an address encoder, transaction parser, signing algorithm, serialization rules, and test vectors before its signing capability may be enabled.

## Derivation Policy

`NetworkProfile` stores both `slip44_coin_type` and `derivation_coin_type`.

- Native UTXO and non-EVM chains use their registered SLIP-0044 type as the derivation type.
- Registered EVM networks use `m/44'/60'/account'/change/index`. Their own SLIP-0044 type and EVM chain ID remain metadata. This gives Ethereum, EVM networks, and their ERC-20 tokens one standard account address for a given derivation index.
- Bitcoin selects BIP44, BIP49, or BIP84 through its explicit network profile.
- Monero and Masari derive a BIP32 child at `m/44'/coin'/account'/change/index`, then use that 32-byte child as input to CryptoNote's Keccak-and-reduce spend/view key derivation. This is HexWallet's deterministic BIP39 policy, not the Monero 25-word seed format or an assertion of compatibility with another hardware wallet.

Changing derivation policy changes derived addresses. Existing wallets should record the path used for every funded address.

## Networks And Tokens

The network registry includes Ethereum, Ethereum Classic, BSC, Polygon, Optimism, Arbitrum One, Base, Avalanche C-Chain, Fantom, Cronos, Gnosis Chain, Celo, Kava EVM, Core, Moonbeam, and Moonriver. These support addresses plus standard EIP-155/EIP-1559 native transfers and registered ERC-20 transfers. Contract creation, arbitrary calldata, unknown contracts, non-empty access lists, and typed transactions other than type 2 are rejected.

The token registry currently contains selected, fixed ERC-20 contracts for USDC, USDT, DAI, WBTC, and BUSD across supported EVM networks, plus a registered SPL USDC mint. Contract and mint identifiers are metadata, not balances. Always independently verify the identifier and network before using an asset.

Solana and SPL transfer support is not implemented. It requires Ed25519 HD derivation, Solana base58 account encoding, associated-token-account derivation, message parsing, and Ed25519 signing. The SPL entry remains explicitly unavailable rather than producing an incorrect address or signature.

Monero and Masari standard addresses are implemented, but RingCT/CLSAG transaction parsing, key images, decoy verification, subaddresses, multisig, and signing are not. Chia addresses and signing remain unavailable because the BLS12-381, CLVM puzzle, coin-spend parsing, and aggregate-signature stack has not been implemented and verified. Staking or validator messages are not accepted for any chain unless a chain-specific parser and review policy is explicitly listed as supported.

## Capability Matrix

| Capability | Current scope |
| --- | --- |
| Bitcoin signing | PSBT v0 BIP49 P2SH-P2WPKH and BIP84 P2WPKH, mainnet, `SIGHASH_ALL` only |
| Bitcoin addresses | BIP44 P2PKH, BIP49 P2SH-P2WPKH, BIP84 P2WPKH |
| EVM addresses | Registered network derivation policy (coin type 60 for Ethereum-compatible networks; 61 for Ethereum Classic) |
| EVM native signing | Canonical EIP-155 legacy and EIP-1559 type 2, bounded gas fee, simple transfer only |
| Monero/Masari addresses | CryptoNote mainnet standard addresses under the documented HexWallet BIP39 policy |
| Monero/Masari transaction signing | Not implemented |
| Chia address or signing | Not implemented |
| ERC-20 account address | Registered token metadata on supported EVM networks |
| ERC-20 transfer signing | Registered contracts only, exact `transfer(address,uint256)` calldata |
| Solana/SPL address or signing | Not implemented |
| Other SLIP-0044 entries | Cataloged only when no complete implementation exists |

## Serial Commands

Public metadata commands work while locked:

```text
help
status
coin list
coin search <text>
coin show <id>
token list [network]
token show <id>
```

After authentication and wallet loading:

```text
wallet generate
wallet import <24-word-mnemonic>
wallet address <network> [index]
wallet token <token-id> [index]
wallet addresses [index]
tx inspect <psbt-v0-hex>
tx sign <six-digit-confirmation>
evm inspect <network> <index> <unsigned-rlp-hex>
evm sign <six-digit-confirmation>
tx reject
```

`wallet token eth-usdc 0` returns the Ethereum BIP44 path and account address together with the registered contract. Transfers use the separate inspect/review/sign workflow. Secret export is disabled by default with `HEXWALLET_ENABLE_SECRET_EXPORT=0` and should remain disabled on production devices.

Authentication uses a one-use challenge and HMAC proof. Bitcoin inspection accepts bounded PSBT v0 requests only; every input must be a wallet-controlled BIP49 P2SH-P2WPKH or BIP84 P2WPKH output, with `SIGHASH_ALL` when present.

## Build

The current verified build target is Espressif ESP32 core 3.3.10 with FQBN `esp32:esp32:lilygo_t_display_s3`. The CLI-only firmware can be compiled with LVGL disabled:

```text
arduino-cli compile --fqbn esp32:esp32:lilygo_t_display_s3 \
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_ENABLE_LVGL=0 \
  --build-property compiler.c.extra_flags=-DHEXWALLET_ENABLE_LVGL=0 .
```

LVGL 9.5.0 is required when `HEXWALLET_ENABLE_LVGL=1`. `WalletBoardPort.cpp` deliberately fails closed until it is implemented for the exact board, display controller, touch controller, GPIO map, bus, and power sequence. `ESP32-S3N8` identifies a chip configuration, not a complete LilyGo product or a touch controller.

## Test And Verification

The firmware runs crypto, secp256k1, CryptoNote, BIP39, BIP32, address, EIP-155/EIP-1559, transport-policy, and Bitcoin transaction self-tests during startup when `HEXWALLET_RUN_SELF_TESTS=1`. The EIP-155 test matches the official unsigned RLP, signing hash, `v/r/s`, and signed transaction.

```text
clang++ -std=c++17 -Wall -Wextra -Werror tests/CryptoHashHostTest.cpp keccak256.cpp local_ripemd160.cpp -o crypto-test
./crypto-test
clang++ -std=c++17 -Wall -Wextra -Werror tests/CryptoNoteAddressHostTest.cpp keccak256.cpp -o cryptonote-test
./cryptonote-test
```

Compile success and self-tests do not replace protocol test vectors, hardware-in-the-loop tests, fuzzing, side-channel evaluation, or an independent security audit.

## Security Boundaries

The wallet mnemonic and PIN verifier currently use ordinary ESP32 RAM/NVS. Before any real-fund use, provide encrypted storage or a reviewed secure element, Secure Boot, Flash Encryption, anti-rollback, authenticated firmware updates, physical confirmation input, a trusted display path, fault-injection and side-channel evaluation, recovery testing, reproducible builds, and an independent audit.

A serial confirmation code protects against accidental commands only. By default the code is shown only on the trusted display and signing is refused when no display is available. Unknown Bitcoin scripts, PSBT v2, Taproot, multisig, arbitrary digests, arbitrary EVM calls, unknown token contracts, SPL transfers, and unsupported chains are rejected or unavailable by design.

`WalletTransportPolicy` permanently restricts Wi-Fi to public price and block-height operations; Wi-Fi signing requests, approvals, and secret export fail closed. The BLE driver and pairing storage are not implemented yet. Policy permits BLE signing/approval only after authentication, pairing, and trusted-display review, so adding a BLE characteristic alone cannot enable signing.

## License

Copyright (c) 2024-2026 Blueokanna. The project is source-available for individual personal non-commercial use only. Modified versions and derivative works remain non-commercial; use by an organization, for employment or clients, in a sold device, paid service, hosted wallet, custody/staking service, or any other direct or indirect commercial activity requires a separate written license from `blueokanna@gmail.com`. See `LICENSE`; its English text controls.
