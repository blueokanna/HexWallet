# HexWallet

HexWallet is an offline ESP32 wallet firmware foundation. It derives addresses from a volatile BIP39 wallet, provides an authenticated serial interface, reviews bounded Bitcoin PSBT requests, keeps network and token metadata in explicit registries, and now drives real display hardware (RM67162 AMOLED, ST7789 parallel, and GxEPD2 e-paper) through a per-board LVGL port with resolution-adaptive layouts. It remains beta firmware, not a production hardware wallet, and must not hold real funds until the security controls listed under "Security Boundaries" are complete.

For the complete CLI workflow, including Arduino CLI build/upload, serial settings, challenge-response authentication, wallet lifecycle, address lookup, transaction review, signing restrictions, and troubleshooting, see the [detailed Chinese CLI guide](README_CN.md).

## What Is Implemented

- BIP39 English 24-word generation, validation, and PBKDF2-HMAC-SHA512 seed derivation.
- BIP32 private and public child derivation, extended-key serialization, and startup known-answer tests.
- Bitcoin and Bitcoin-family PSBT v0 review and signing: BIP84 P2WPKH, BIP49 P2SH-P2WPKH and BIP44 legacy P2PKH under `SIGHASH_ALL`, plus the `SIGHASH_FORKID` variant for BCH/eCash/BSV, with low-S RFC6979 ECDSA, fee limits, and one-time review confirmation.
- Strict EIP-155 legacy and EIP-1559 type-2 review/signing for registered EVM networks. Native transfers and whitelisted `ERC-20/721/1155/4626/777/3525/6551/OFT/ONFT` calldata are accepted after canonical ABI traversal; unknown selectors, non-canonical offsets, unreviewable nested calls and unregistered fungible contracts are rejected.
- Address derivation for Bitcoin, Litecoin, Dogecoin, Dash, Bitcoin Gold, Ravencoin, XRP Ledger, TRON, Monero, Masari, QRL, and the registered EVM networks in `WalletNetworks.cpp`.
- CryptoNote address construction for Monero and Masari: Keccak scalar derivation, Edwards25519 public keys, network prefixes, block Base58, and checksums. Monero also supports integrated addresses (8-byte payment ID) and MRL-0006 subaddresses (`m/0/account/change/index` key algebra with the `SubAddr` domain separator). RingCT/CLSAG parsing, key images, decoy verification, and signing are not enabled.
- QRL address derivation: XMSS with SHAKE-256, height 10, WOTS+ `w=16`, the QRL 3-byte descriptor, SHA-256 address commitment and checksum, verified against the QRL reference implementation's SHAKE-256 vector. XMSS signing (stateful BDS traversal) is not enabled, and the derivation is explicitly CPU-heavy.
- An explicit secure-element custody plan (`WalletCustody`) that separates keys the SE can hold from keys that must stay in MCU RAM. The conservative SE050C1H1 profile claims only secp256k1 + ECDSA + seed sealing; Monero/Masari, Kaspa Schnorr, QRL XMSS, BLS12-381, and (until the applet is validated on hardware) Ed25519 keys are planned as MCU-resident rather than pretending a generic ECC engine can sign them.
- Chia standard addresses via the EIP-2333/ERC-2333 BLS12-381 key tree (`m/12381/8444/0/index`), CLVM `shatree` puzzle hashing, the default hidden puzzle (`ff0980`) and synthetic-offset public key, and `bech32m` encoding. The BLS12-381 G1 stack (field/group arithmetic, canonical generator, 48-byte ZCash-style compression) is implemented and verified against the official ERC-2333 test vectors and an independent reference oracle. Chia coin-spend parsing, aggregate signatures, and signing are not enabled.
- Token metadata and account-address lookup for registered EVM assets. ERC-20/721/1155/4626/777 tokens use the same EVM account address as their network; the registry records contract identity, standard and decimal precision. Solana SPL remains account-address-only.
- A searchable SLIP-0044 catalog that distinguishes address support, token-account support, transaction review, and signing support.
- Authenticated CLI sessions with challenge-response authentication, persistent retry counters, exponential backoff, timeout, and volatile wallet clearing.

## Architecture

| Module | Responsibility |
| --- | --- |
| `WalletSecurity` | BIP39, BIP32, secp256k1 operations, KDFs, secure zeroization |
| `CryptoNoteAddress` | CryptoNote scalar derivation, Edwards25519 point algebra, Base58 standard/integrated/subaddress encodings |
| `QrlXmss` | QRL XMSS-SHAKE256 treehash, descriptor/public key, address encoding, progress hook |
| `WalletCustody` | Per-network key custody plan (SE-held vs MCU-held) and SE capability policy |
| `EvmTransaction` | Canonical RLP parsing, EIP-155/EIP-1559 review, whitelisted token-call review and signing |
| `TokenCalldata` | Selector whitelist and canonical ABI decoder for ERC-20/721/1155/4626/777/3525/6551 and LayerZero OFT/ONFT |
| `WalletNetworks` | Native-chain metadata, registered SLIP-0044 type, derivation type, address encoding, EVM chain ID |
| `WalletTokens` | Token standard, owning network, contract or mint identifier, precision, real capability state |
| `WalletEngine` | Derivation path construction and address encoding |
| `WalletCatalog` | Searchable user-facing capability catalog |
| `BitcoinTransaction` | Strict PSBT v0 parser (witness and non-witness UTXO), transaction review, legacy/BIP143/fork-id sighash, final serialization |
| `MoneroScan` | View-key output scanning, subaddress attribution, plain-amount recovery |
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
- Monero and Masari derive a BIP32 child at `m/44'/coin'/account'/change/index`, then use that 32-byte child as input to CryptoNote's Keccak-and-reduce spend/view key derivation. This is HexWallet's deterministic BIP39 policy, not the Monero 25-word seed format or an assertion of compatibility with another hardware wallet. Subaddress `(major, minor)` is rendered from the same child with `m = Hs("SubAddr" || view_secret || major || minor)`, `D = B + mG`, `C = view_secret * D`; `(0,0)` is the standard address.
- QRL has no BIP32 key tree. The BIP39 seed is expanded with SHAKE-256 and the domain string `HexWallet/QRL/v1` into the 48-byte XMSS seed, which is then used for the canonical height-10 tree. This is a HexWallet policy; QRL's native wallet uses its own 34-word mnemonic. QRL addresses are therefore not asserted to be restorable by another BIP39 wallet.
- Monero `(major, minor)` and QRL derivation index are surfaced through the existing `wallet address <id> <index>` argument; the QRL tree is generated once per request and never cached.

Changing derivation policy changes derived addresses. Existing wallets should record the path used for every funded address.

## Networks And Tokens

The network registry includes Ethereum, Ethereum Classic, Rootstock, BSC, Polygon, Optimism, Arbitrum One, Base, Avalanche C-Chain, Fantom, Cronos, Gnosis Chain, Celo, Kava EVM, Core, Moonbeam, and Moonriver. These support addresses plus standard EIP-155/EIP-1559 native transfers and the whitelisted token-call set above. Contract creation, arbitrary calldata, unknown selectors, non-empty access lists, and typed transactions other than type 2 are rejected. LayerZero OFT/ONFT are payable calls: the native value is reviewed as the cross-chain fee, `lzTokenFee` must be zero, and the native fee must cover `nativeFee`.

The token registry contains selected, fixed ERC-20 contracts for USDC, USDT, DAI, WBTC, and BUSD across supported EVM networks, plus a registered SPL USDC mint. NFT/4626/777/3525/6551/OFT/ONFT contracts can be reviewed through the unique-selector path; shared selectors such as `transferFrom(address,address,uint256)` require a registered contract standard. Contract and mint identifiers are metadata, not balances. Always independently verify the identifier and network before using an asset.

Solana and SPL transfer signing is not implemented. It requires Solana message parsing, recent-blockhash handling, compute-budget instructions and Ed25519 signing. The registered SPL mint now resolves to its associated token account address (`owner || Tokenkeg... || mint`, PDA with the `AToke...` program and the "ProgramDerivedAddress" marker); the owner address is still the plain Ed25519 base58 account. The SPL entry stays account-address-only rather than producing a fake transfer.

Monero and Masari standard addresses are implemented; Monero additionally supports integrated addresses and MRL-0006 subaddresses, all verified against independent Keccak/Edwards reference computations. RingCT/CLSAG transaction parsing, key images, decoy verification, multisig, and signing are not. QRL address derivation is implemented against the QRL reference SHAKE-256 vector, but XMSS signing (stateful BDS traversal and leaf-index persistence) is not. Chia standard-address derivation is implemented and verified; Chia coin-spend parsing, aggregate signatures, and signing remain unavailable. Staking or validator messages are not accepted for any chain unless a chain-specific parser and review policy is explicitly listed as supported.

### Coin coverage policy

Neither the BIP39 community list nor miningpoolstats is a specification. Both contain hundreds of chains, dead forks, and coins whose only "documentation" is an unmaintained explorer. HexWallet therefore does not ship a list of guesses.

A coin enters the signing-capable set only when all of the following exist: an address encoding with an independent reference vector, a derivation policy, a signature scheme the firmware can actually implement, and a custody plan. Coins that share a family (base58 versions, EVM chain ID, SLIP-0010, CryptoNote, XMSS) add data plus one vector, not new cryptography. Coins without a verifiable vector remain cataloged as unavailable with the exact missing piece in `WalletCatalog.cpp`; adding their SLIP-0044 number or ticker does not enable an address. This is why the catalog deliberately reports partial coverage instead of claiming "all miningpoolstats coins". Address-only compatibility profiles are a separate, explicitly labeled tier described below; they never inherit signing capability.

### Compatibility fork registry

`tools/fork_registry.json` contains 144 compatibility rows and generates 151 profiles (legacy, native SegWit and nested SegWit where the official chainparams declare a bech32 HRP). Run `python tools/generate_fork_profiles.py` to regenerate `WalletForkProfiles.inc` and `WalletForkCatalog.inc` in chain-name order. Rows carrying `source_verified` are marked as official-chainparams parameters; the rest are explicitly labelled imported metadata.

Imported profiles never enable signing. Historical `sighash` annotations are not consensus evidence and are ignored by the generator. Signing requires an explicitly reviewed policy and independent transaction fixtures. A repository's ancestry and an address prefix are insufficient to establish transaction format, replay protection or signature rules.

`tools/graveyard_registry.json` is the GRAVEYARD discovery and verification ledger. Of 148 discovered entries, 20 have readable official chainparams and are marked `verified`; the rest keep their exact refusal reason and generate no address profile. A missing GitHub repository or unreadable chainparams is a hard stop, not an invitation to guess parameters.

Every row's encoder is exercised with a fixed public key by `run_network_profile_self_tests()`, with exact vectors for Adcoin, ANON, DigiByte, Peercoin, Namecoin, BSV and Cosmos Hub. Verify the first receive address against the coin's own reference wallet before committing funds: a wrong version byte produces a valid-looking but unusable address.

## Capability Matrix

| Capability | Current scope |
| --- | --- |
| Bitcoin signing | PSBT v0: BIP84 P2WPKH, BIP49 P2SH-P2WPKH and BIP44 legacy P2PKH, `SIGHASH_ALL` only. Legacy inputs must carry `non_witness_utxo`, whose txid is verified against the outpoint |
| Bitcoin addresses | BIP44 P2PKH, BIP49 P2SH-P2WPKH, BIP84 P2WPKH |
| Bitcoin-family fork signing | Chains with a row in `kNetworkSigningPolicies` sign their inherited rule: Litecoin, Dogecoin, Dash, DigiByte, Bitcoin Gold, Peercoin, Namecoin, Vertcoin and Axe use the original legacy sighash; Sugarchain and Ravencoin Classic were source-verified as unchanged Bitcoin-0.16 forks; BCH, eCash and BSV use the BIP143 preimage with `SIGHASH_FORKID` (`0x41`) and the fork id in the sighash-type high bits |
| Bitcoin-family fork addresses | 151 generated profiles from `tools/fork_registry.json`, ordered by chain name |
| EVM addresses | Registered network derivation policy (coin type 60 for Ethereum-compatible networks; 61 for Ethereum Classic) |
| EVM native signing | Canonical EIP-155 legacy and EIP-1559 type 2, bounded gas fee, simple transfer only |
| Monero/Masari addresses | CryptoNote standard addresses, Monero integrated and MRL-0006 subaddresses, under the documented HexWallet BIP39 policy |
| Monero receive scanning | View-key scanning: `8*a*R` derivation, `Hs = sc_reduce32(keccak256(derivation || varint(index)))`, one-time key match against every tracked subaddress, and plain-amount recovery. RingCT commitments are flagged as undecoded rather than guessed |
| Kaspa signing | BLAKE2b-256 keyed sighash (`SIGHASH_ALL`), keyed transaction ID, KIP-0009 compute/transient/storage mass, BIP340 Schnorr signature, protobuf `TransactionMessage` encoding. Verified against the rusty-kaspa sighash vectors, its transaction ID, its mass parameters and a prost-encoded broadcast payload. Version 0 transactions only ? v1 compute-budget/covenant transactions are refused |
| Cosmos staking | `MsgDelegate` with `SIGN_MODE_DIRECT`: hand-written protobuf TxBody/Any/AuthInfo/SignDoc, SHA-256 digest for secp256k1 ECDSA. Verified byte-for-byte against a prost encoder |
| EVM token calldata | Whitelist of ERC-20, ERC-721, ERC-1155, ERC-4626, ERC-777, ERC-3525, ERC-6551 and LayerZero OFT/ONFT selectors, each recomputed from its signature at self-test time. ERC-2981/4337/3643/1400/1410/5528 remain explicit refusals; ERC-6551 batch execution, ERC-1155 batch transfers and non-empty ERC-721/1155/3525/777 callback hooks are refused because they are not faithfully reviewable on the trusted display |
| Monero/Masari transaction signing | Not implemented (RingCT/CLSAG) |
| Algorand / Tezos signing | Not implemented |
| QRL addresses | XMSS-SHAKE256 height 10, QRL descriptor + SHA-256 address commitment — verified against the QRL reference vector; key generation is CPU-heavy |
| QRL transaction signing | Not implemented (stateful XMSS BDS state and leaf-index persistence) |
| Secure-element custody | `WalletCustody` plan per network. SE050C1H1: secp256k1/ECDSA may live in the SE; Monero, Kaspa Schnorr, QRL, BLS12-381 and (pending hardware validation) Ed25519 remain MCU-resident |
| Chia addresses | EIP-2333/ERC-2333 key tree, BLS12-381 G1, CLVM shatree, bech32m — verified against official vectors |
| Chia transaction signing | Not implemented |
| ERC-20 account address | Registered token metadata on supported EVM networks |
| ERC-20 transfer signing | Registered contracts only, exact `transfer(address,uint256)` calldata |
| NFT / vault / OFT signing | Whitelisted selectors with canonical ABI traversal; `from`/`owner` must equal the derived wallet; OFT native-fee policy is enforced |
| Solana owner address | Ed25519 SLIP-0010, base58 account address |
| SPL associated token account | Registered mints only; PDA derivation, verified against an independent Solana-compatible curve/ATA oracle |
| Solana/SPL transfer signing | Not implemented |
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
wallet custody <network>
wallet token <token-id> [index]
wallet addresses [index]
tx inspect [<coin>] <psbt-v0-hex>
tx sign <six-digit-confirmation>
evm inspect <network> <index> <unsigned-rlp-hex>
evm sign <six-digit-confirmation>
tx reject
```

`wallet token eth-usdc 0` returns the Ethereum BIP44 path and account address together with the registered contract. Transfers use the separate inspect/review/sign workflow. `wallet custody <network>` prints the active secure-element profile (MCU-only until the board port registers a probed SE050), the key scheme, whether the key can live in the SE, whether the SE can produce the required signature, and the reason; it never touches key material. Secret export is disabled by default with `HEXWALLET_ENABLE_SECRET_EXPORT=0` and should remain disabled on production devices.

Authentication uses a one-use challenge and HMAC proof. Bitcoin inspection accepts bounded PSBT v0 requests only; every input must be a wallet-controlled BIP44 P2PKH, BIP49 P2SH-P2WPKH or BIP84 P2WPKH output, with `SIGHASH_ALL` (or `SIGHASH_FORKID` for fork-id chains) when present. `tx inspect <coin> <psbt>` selects the chain; the review prints the network and the exact sighash that will be produced.

## Build

The verified build target is the Espressif ESP32 core 3.3.10 with FQBN `esp32:esp32:esp32s3` and LVGL 9.5.0. The target board is a compile-time choice via `HEXWALLET_BOARD` in `WalletConfig.h`:

| `HEXWALLET_BOARD` | Board | Panel | Controller | Interface | Resolution |
| --- | --- | --- | --- | --- | --- |
| `HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED` (default) | T-Display S3 AMOLED | RM67162 | RM67162 | SPI | 240×536 |
| `HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED_PLUS` | T-Display S3 AMOLED Plus | RM67162 | RM67162 | SPI | 240×536 |
| `HEXWALLET_BOARD_T_DISPLAY_S3` | T-Display S3 | ST7789 | ST7789 | 8-bit parallel | 170×320 |
| `HEXWALLET_BOARD_T_DECK_MAX` | T-Deck Max | GDEQ031T10 | UC8253 | SPI (e-paper) | 240×320 |
| `HEXWALLET_BOARD_T_ECHO_LITE` | T-Echo Lite Kit | e-paper | — | SPI (e-paper) | 176×192 |
| `HEXWALLET_BOARD_HEADLESS` | Any MCU (no display) | — | — | Serial CLI | — |

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

### Headless (no display, pure Serial CLI)

For any board **without** a screen — a generic ESP32-S3 dev kit, a USB-stick
wallet, etc. — select the headless target. It compiles no display driver, no
touch driver and no LVGL, auto-sets `HEXWALLET_ENABLE_LVGL=0` and
`HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION=1`, and runs the authenticated Serial
CLI as the only interface (transaction approval prints a confirm code over
Serial).

```text
arduino-cli compile --fqbn esp32:esp32:esp32s3 \
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_BOARD=6 \
  --build-property compiler.c.extra_flags=-DHEXWALLET_BOARD=6 .
```

In the **Arduino IDE**, the same board pick is a plain `-D` flag. Create a
`build_opt.h` next to `HexWallet.ino` containing exactly:

```text
-DHEXWALLET_BOARD=6
```

The ESP32 core picks `build_opt.h` up automatically on every compile (delete
the file to go back to a display board). On boot the firmware prints
`INFO no display detected; authenticated CLI is the active interface` and
`help` lists every command.

## Test And Verification

The firmware runs crypto, secp256k1, CryptoNote (including subaddresses and integrated addresses), QRL XMSS, custody-plan, BIP39, BIP32, address, EIP-155/EIP-1559, transport-policy, and Bitcoin transaction self-tests during startup when `HEXWALLET_RUN_SELF_TESTS=1`. The EIP-155 test matches the official unsigned RLP, signing hash, `v/r/s`, and signed transaction.

The extended crypto stack (Keccak-512, SHAKE-256, SHA-3, SHA-512/256, BLAKE2b, Ed25519, SLIP-10, EIP-2333/ERC-2333 BLS12-381, Chia addresses, Monero subaddresses, QRL XMSS, and the alt-address encoders) is verified on the host by compiling every firmware source against the *exact* mbedtls headers bundled with the ESP32 Arduino core and running every embedded official vector:

```text
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
# expected: crypto-primitives=pass extended-crypto=pass alt-addresses=pass
#           cryptonote=pass qrl-xmss=pass custody=pass
```

Verified against authoritative sources: RFC 8032 Ed25519 (TC1/TC2), SLIP-10, the official ERC-2333 test vectors (master SK, compressed Lamport PK, child SK), RFC 6979 low-S ECDSA, the QRL reference `XmssBasicSHAKE256` vector (48 zero seed, height 4), the official rusty-kaspa mainnet address vectors, independent Monero key/subaddress/integrated-address reference computations, and an independent pure-Python BLS12-381/EIP-2333 oracle (Chia `v0`/`ones`/16-byte-seed addresses and the derived public key match byte-for-byte). A device-target smoke check additionally compiles the pure-C++ crypto core with the ESP32 Xtensa toolchain:

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

Crypto code is additionally rebuilt with clang-cl as an **optimizer
differential check** — MSVC sometimes "accidentally" produces the right
result for undefined behaviour while clang exposes it, so the two builds must
agree:

```text
powershell -ExecutionPolicy Bypass -File tests/host/build_clang_ubsan.ps1
# expected: extended-crypto=pass  alt-addresses=pass
```

This gate exists because a shift-count-overflow UB in the host SHA-512 shim
(writing the 128-bit length with `bits >> 120`) once corrupted the length
field under clang, failing Ed25519 TC1 and SLIP-10 on CI while every local
MSVC build stayed green.

CI (`.github/workflows/ci.yml`) runs all three host jobs plus a full
`arduino-cli` firmware build for the ESP32-S3 with LVGL 9.5.0.

Compile success and self-tests do not replace protocol test vectors, hardware-in-the-loop tests, fuzzing, side-channel evaluation, or an independent security audit.

## Flash Layout, Secure OTA And eFuses

`partitions/hexwallet-16mb-ota.csv` defines a 16 MB layout with a 3 MB
factory/recovery image, two 5 MB OTA slots and a 2.875 MB resource partition:

| Partition | Offset | Size | Purpose |
| --- | --- | --- | --- |
| `nvs` | `0x9000` | 24 KiB | PIN verifier, counters, provisioned flag |
| `otadata` | `0xF000` | 8 KiB | active OTA slot + rollback state |
| `phy_init` | `0x11000` | 4 KiB | RF calibration (unused when Wi-Fi/BLE are disabled) |
| `recovery` | `0x20000` | 3 MiB | factory/recovery image, never overwritten by OTA |
| `ota_0` | `0x320000` | 5 MiB | stable application slot |
| `ota_1` | `0x820000` | 5 MiB | staging slot |
| `storage` | `0xD20000` | 2.875 MiB | resources, labels, read-only data |

To use it with the Arduino core, copy it to the sketch root as `partitions.csv`
before `arduino-cli compile`; with ESP-IDF set
`CONFIG_PARTITION_TABLE_CUSTOM=y` and `CONFIG_PARTITION_TABLE_CUSTOM_FILENAME`.
The table is deliberately not active by default: an 8 MB S3 module cannot hold
two 5 MB slots, and silently changing the layout on an existing device can
brick the boot chain.

The update sequence is the only safe one:

1. Write the signed image into the inactive slot (`ota_1` while `ota_0` runs).
2. Verify the image hash/signature before `esp_ota_end()` returns success.
3. Call `esp_ota_set_boot_partition()` and reboot.
4. Let the new image call `esp_ota_mark_app_valid_cancel_rollback()` only
   after its own self-tests pass; otherwise the bootloader rolls back.

### Secure Boot v2 and Flash Encryption

- **Secure Boot v2** puts the RSA/ECDSA public key digest into eFuse and makes
  the bootloader reject any image without a valid signature. Keep the private
  signing key offline; the eFuse digest is a one-way write.
- **Flash Encryption** in release mode generates a per-device AES key in eFuse.
  The bootloader encrypts OTA writes as they land in flash, so the server
  publishes **one signed plaintext image**, not one encrypted image per device.
- Development mode can be reversed by reflashing; release mode cannot. Do not
  burn Secure Boot or Flash Encryption eFuses until the signing key backup,
  recovery image, rollback path and provisioning flow have been tested on a
  sacrificial module. A wrong eFuse write is not recoverable by OTA.

Hardware note: the ESP32-P4 target has no Wi-Fi/BLE; the OTA transport is USB-C
(from the desktop updater) or NFC. Neither transport is implemented in this
firmware yet; the partition table and rollback rules are transport-independent.

## Security Boundaries

The wallet mnemonic and PIN verifier currently use ordinary ESP32 RAM/NVS. `WalletCustody` makes the SE boundary explicit instead of hand-waving it: the SE050C1H1 profile can hold imported secp256k1 keys and run ECDSA, and can seal a seed with an AES key, but it has no BIP32 engine, no BIP340 Schnorr, no SHAKE-256/XMSS, no CryptoNote key algebra and no BLS12-381. Consequently Monero, Kaspa, QRL, Chia and (until the applet is validated) Ed25519 private keys are derived in MCU RAM and zeroized after use. A seed that must be unwrapped into MCU RAM is only as protected as the MCU; the SE improves key-at-rest and ECDSA isolation, not the software-derivation paths. Do not describe this design as "all keys protected by the SE050".

Before any real-fund use, provide the reviewed SE050 driver/SCP03 provisioning, Secure Boot, Flash Encryption, anti-rollback, authenticated firmware updates, physical confirmation input, a trusted display path, fault-injection and side-channel evaluation, recovery testing, reproducible builds, and an independent audit.

A serial confirmation code protects against accidental commands only. By default the code is shown only on the trusted display and signing is refused when no display is available. Unknown Bitcoin scripts, PSBT v2, Taproot, multisig, arbitrary digests, arbitrary EVM calls, unknown token contracts, SPL transfers, and unsupported chains are rejected or unavailable by design.

`WalletTransportPolicy` permanently restricts Wi-Fi to public price and block-height operations; Wi-Fi signing requests, approvals, and secret export fail closed. The BLE driver and pairing storage are not implemented yet. Policy permits BLE signing/approval only after authentication, pairing, and trusted-display review, so adding a BLE characteristic alone cannot enable signing.

## License

Copyright (c) 2024-2026 Blueokanna. The project is source-available for individual personal non-commercial use only. Modified versions and derivative works remain non-commercial; use by an organization, for employment or clients, in a sold device, paid service, hosted wallet, custody/staking service, or any other direct or indirect commercial activity requires a separate written license from `blueokanna@gmail.com`. See `LICENSE`; its English text controls.
