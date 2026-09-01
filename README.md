# HexWallet

HexWallet is an offline ESP32 wallet firmware foundation. It derives addresses from a volatile BIP39 wallet, provides an authenticated serial interface, reviews bounded Bitcoin PSBT requests, keeps network and token metadata in explicit registries, and now drives real display hardware (RM67162 AMOLED, ST7789 parallel, and GxEPD2 e-paper) through a per-board LVGL port with resolution-adaptive layouts. It remains beta firmware, not a production hardware wallet, and must not hold real funds until the security controls listed under "Security Boundaries" are complete.

For the complete CLI workflow, including Arduino CLI build/upload, serial settings, challenge-response authentication, wallet lifecycle, address lookup, transaction review, signing restrictions, and troubleshooting, see the [detailed Chinese CLI guide](README-zh.md).

## What Is Implemented

- BIP39 English 24-word generation, validation, and PBKDF2-HMAC-SHA512 seed derivation.
- BIP32 private and public child derivation, extended-key serialization, and startup known-answer tests.
- Bitcoin mainnet PSBT v0 review and signing for BIP84 P2WPKH and BIP49 P2SH-P2WPKH inputs using `SIGHASH_ALL`, BIP143, low-S RFC6979 ECDSA, fee limits, and one-time review confirmation.
- Strict EIP-155 legacy and EIP-1559 type-2 review/signing for registered EVM networks. Only native transfers and `transfer(address,uint256)` calls to registered ERC-20 contracts are accepted.
- Address derivation for Bitcoin, Litecoin, Dogecoin, Dash, Bitcoin Gold, Ravencoin, XRP Ledger, TRON, Monero, Masari, and the registered EVM networks in `WalletNetworks.cpp`.
- CryptoNote standard-address construction for Monero and Masari: Keccak scalar derivation, Edwards25519 public keys, network prefixes, block Base58, and checksums. Transaction parsing and signing are not enabled.
- Chia standard addresses via the EIP-2333/ERC-2333 BLS12-381 key tree (`m/12381/8444/0/index`), CLVM `shatree` puzzle hashing, the default hidden puzzle (`ff0980`) and synthetic-offset public key, and `bech32m` encoding. The BLS12-381 G1 stack (field/group arithmetic, canonical generator, 48-byte ZCash-style compression) is implemented and verified against the official ERC-2333 test vectors and an independent reference oracle. Chia coin-spend parsing, aggregate signatures, and signing are not enabled.
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
| `WalletBoardPort` | Board profile (pins, panel driver, LVGL buffers, flush + touch callbacks, power sequencing) |
| `WalletBoardPins` | Verified per-board pin assignments for all five supported LilyGO boards |
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

Monero and Masari standard addresses are implemented, but RingCT/CLSAG transaction parsing, key images, decoy verification, subaddresses, multisig, and signing are not. Chia standard-address derivation is implemented and verified; Chia coin-spend parsing, aggregate signatures, and signing remain unavailable. Staking or validator messages are not accepted for any chain unless a chain-specific parser and review policy is explicitly listed as supported.

## Capability Matrix

| Capability | Current scope |
| --- | --- |
| Bitcoin signing | PSBT v0 BIP49 P2SH-P2WPKH and BIP84 P2WPKH, mainnet, `SIGHASH_ALL` only |
| Bitcoin addresses | BIP44 P2PKH, BIP49 P2SH-P2WPKH, BIP84 P2WPKH |
| EVM addresses | Registered network derivation policy (coin type 60 for Ethereum-compatible networks; 61 for Ethereum Classic) |
| EVM native signing | Canonical EIP-155 legacy and EIP-1559 type 2, bounded gas fee, simple transfer only |
| Monero/Masari addresses | CryptoNote mainnet standard addresses under the documented HexWallet BIP39 policy |
| Monero/Masari transaction signing | Not implemented |
| Chia addresses | EIP-2333/ERC-2333 key tree, BLS12-381 G1, CLVM shatree, bech32m — verified against official vectors |
| Chia transaction signing | Not implemented |
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

The verified build target is the Espressif ESP32 core 3.3.10 with FQBN `esp32:esp32:esp32s3` and LVGL 9.5.0. The target board is a compile-time choice via `HEXWALLET_BOARD` in `WalletConfig.h`:

| `HEXWALLET_BOARD` | Board | Panel | Controller | Interface | Resolution |
| --- | --- | --- | --- | --- | --- |
| `HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED` (default) | T-Display S3 AMOLED | RM67162 | RM67162 | SPI | 240×536 |
| `HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED_PLUS` | T-Display S3 AMOLED Plus | RM67162 | RM67162 | SPI | 240×536 |
| `HEXWALLET_BOARD_T_DISPLAY_S3` | T-Display S3 | ST7789 | ST7789 | 8-bit parallel | 170×320 |
| `HEXWALLET_BOARD_T_DECK_MAX` | T-Deck Max | GDEQ031T10 | UC8253 | SPI (e-paper) | 240×320 |
| `HEXWALLET_BOARD_T_ECHO_LITE` | T-Echo Lite Kit | e-paper | — | SPI (e-paper) | 176×192 |

Pin assignments live in `WalletBoardPins.h` and are taken from the official LilyGO pinout diagrams and factory code; the RM67162 init sequence and the ST7789 init sequence match the official LilyGO drivers byte for byte. Build for a specific board with `--build-property`:

```text
arduino-cli compile --fqbn esp32:esp32:esp32s3 \
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_BOARD=3 \
  --build-property compiler.c.extra_flags=-DHEXWALLET_BOARD=3 .
```

`HEXWALLET_BOARD=3` selects the T-Display S3; see `WalletConfig.h` for the values. The CLI-only firmware can be compiled with LVGL disabled:

```text
arduino-cli compile --fqbn esp32:esp32:esp32s3 \
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_ENABLE_LVGL=0 \
  --build-property compiler.c.extra_flags=-DHEXWALLET_ENABLE_LVGL=0 .
```

The port is fail-closed: a board with no display profile, or an e-paper profile without the `GxEPD2` library, prints the reason over Serial and runs the CLI only. The T-Echo Lite is an nRF52840 board (Adafruit nRF52 core, not ESP32); its pin profile is defined and the e-paper backend is shared with the T-Deck Max, but a separate nRF52 build target is required before it can run the full firmware.

## Test And Verification

The firmware runs crypto, secp256k1, CryptoNote, BIP39, BIP32, address, EIP-155/EIP-1559, transport-policy, and Bitcoin transaction self-tests during startup when `HEXWALLET_RUN_SELF_TESTS=1`. The EIP-155 test matches the official unsigned RLP, signing hash, `v/r/s`, and signed transaction.

The extended crypto stack (SHA-3, SHA-512/256, BLAKE2b, Ed25519, SLIP-10, EIP-2333/ERC-2333 BLS12-381, Chia addresses, and the alt-address encoders) is verified on the host by compiling every firmware source against the *exact* mbedtls headers bundled with the ESP32 Arduino core and running every embedded official vector:

```text
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
# expected: extended-crypto=pass  alt-addresses=pass
```

Verified against authoritative sources: RFC 8032 Ed25519 (TC1/TC2), SLIP-10, the official ERC-2333 test vectors (master SK, compressed Lamport PK, child SK), RFC 6979 low-S ECDSA, and an independent pure-Python BLS12-381/EIP-2333 oracle (Chia `v0`/`ones`/16-byte-seed addresses and the derived public key match byte-for-byte). A device-target smoke check additionally compiles the pure-C++ crypto core with the ESP32 Xtensa toolchain:

```text
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1
# expected: DEVICE COMPILE: all sources OK
```

Every board profile is compile-checked for the 32-bit target by compiling
`WalletBoardPort.cpp` and `WalletUi.cpp` for all five boards against the
Xtensa toolchain and a minimal LVGL/Arduino mock:

```text
powershell -ExecutionPolicy Bypass -File tests/host/board_port_compile_check.ps1
# expected: BOARD PORT COMPILE: all boards OK
```

CI (`.github/workflows/ci.yml`) runs all three host jobs plus a full
`arduino-cli` firmware build for the ESP32-S3 with LVGL 9.5.0.

Compile success and self-tests do not replace protocol test vectors, hardware-in-the-loop tests, fuzzing, side-channel evaluation, or an independent security audit.

## Security Boundaries

The wallet mnemonic and PIN verifier currently use ordinary ESP32 RAM/NVS. Before any real-fund use, provide encrypted storage or a reviewed secure element, Secure Boot, Flash Encryption, anti-rollback, authenticated firmware updates, physical confirmation input, a trusted display path, fault-injection and side-channel evaluation, recovery testing, reproducible builds, and an independent audit.

A serial confirmation code protects against accidental commands only. By default the code is shown only on the trusted display and signing is refused when no display is available. Unknown Bitcoin scripts, PSBT v2, Taproot, multisig, arbitrary digests, arbitrary EVM calls, unknown token contracts, SPL transfers, and unsupported chains are rejected or unavailable by design.

`WalletTransportPolicy` permanently restricts Wi-Fi to public price and block-height operations; Wi-Fi signing requests, approvals, and secret export fail closed. The BLE driver and pairing storage are not implemented yet. Policy permits BLE signing/approval only after authentication, pairing, and trusted-display review, so adding a BLE characteristic alone cannot enable signing.

## License

Copyright (c) 2024-2026 Blueokanna. The project is source-available for individual personal non-commercial use only. Modified versions and derivative works remain non-commercial; use by an organization, for employment or clients, in a sold device, paid service, hosted wallet, custody/staking service, or any other direct or indirect commercial activity requires a separate written license from `blueokanna@gmail.com`. See `LICENSE`; its English text controls.
