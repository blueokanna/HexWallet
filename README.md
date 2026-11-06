# HexWallet

HexWallet is a signing wallet that runs on the microcontroller, not next to it. The firmware
derives keys from a BIP39 seed, parses and reviews the transaction on the device, and signs only
after the confirmation is produced by the trusted display. The host never receives the seed or a
private key, and the firmware contains no socket, TLS or HTTP code.

It targets ESP32-S3 and ESP32-P4 boards. The same source builds a display wallet, an e-paper P4
board with an SE051 secure element, or a headless CLI for bench work.

## Status

Green host suite, unfinished product. Both statements are load-bearing.

- **Tested here:** 72 labelled host checks (`tests/host/build.ps1`), the ESP32-S3/P4 compile
  checks, the board-port compile matrix, and the policy gates. All of it runs in CI on every
  push.
- **Not tested here:** hardware acceptance. No board in this repository has a recorded
  flash-and-sign session against a live node, no chain has been accepted end to end, and there is
  no third-party audit.
- **Not finished:** secure-element custody. The SCP03 channel, APDU applet layer, curve mapping and
  provisioning path exist and are host-tested; the wallet still derives and signs in MCU RAM, so
  `HEXWALLET_REQUIRE_SECURE_CUSTODY=1` (the device default) compiles the session to refusals. In
  plain terms: **no device build can create, import or use a wallet today**. Only the host test
  build exercises the key path.
- Treat the whole tree as experimental. Do not put funds you cannot lose on it.

## Hardware

| `HEXWALLET_BOARD` | Target | Display | Notes |
| --- | --- | --- | --- |
| 1 (default) | LilyGO T-Display S3 AMOLED | 240x536 AMOLED, CST816S touch | ESP32-S3 |
| 2 | T-Display S3 AMOLED Plus | same panel, AXP313A PMU, microSD | ESP32-S3 |
| 3 | T-Display S3 | 170x320 ST7789, 8-bit parallel | ESP32-S3 |
| 4 | T-Deck Max | 240x320 UC8253 e-paper, partial refresh | ESP32-S3, no verified user button beyond BOOT |
| 5 | T-Echo Lite Kit | 176x192 e-paper | nRF52840; pin map only, this tree does not ship an nRF52 build target |
| 6 | Headless | none | any ESP32; Serial CLI only |
| 7 | HexWallet P4 rev A | 128x296 SSD1680 e-paper | ESP32-P4, SE051C2HQ1 on I2C, PN7161 on shared SPI |

Pin assignments live in `WalletBoardPins.h`, one block per board, each traceable to a schematic or
vendor pinout. Board 7 comes from the EasyEDA netlist `c26102103` and every pin comment names the
package pad it was taken from. Pins that are not in a verified netlist are not guessed: the NFC port
reports `not-configured` and the camera stays off.

## How a signature happens

1. The device unlocks with the PIN-derived key over an authenticated serial session, or with a
   paired phone over the link.
2. The host sends a transaction payload. The device parses it into a bounded review structure; an
   unsupported or malformed payload is refused here, before any key is touched.
3. Ownership checks run against the derived wallet keys: PSBT inputs must commit to wallet UTXOs,
   CryptoNote rings must bind key images and commitments to the wallet, EVM calldata must match a
   registered token call or be shown as raw bytes.
4. The review is rendered on the panel: recipient, amount, fee, chain-specific warnings. The
   approval is a button on that rendered frame, and it expires.
5. Only then is the signing key unsealed. The approval is consumed whether signing succeeds or
   fails.
6. A one-time-signature chain (QRL) reserves its leaf in durable storage *before* the signature
   exists, and verifies its own signature before releasing it.

There is no API to approve a request from code, and no path that signs an unreviewed buffer. See
[Security-Model](https://github.com/blueokanna/HexWallet/wiki/Security-Model).

## What is enforced

- **No secret export.** `HEXWALLET_ENABLE_SECRET_EXPORT` is not a runtime switch; setting it is a
  compile error (`WalletConfig.h`).
- **No network stack.** The policy gate fails the build if `WiFi`, `HTTPClient`, `esp_http_*`,
  `esp_wifi`, `lwip` or `mbedtls/ssl` appears in a firmware include.
- **Transport policy.** Signing and approval requests require an authenticated session and a
  trusted display, on every transport. A headless build can only sign when it is compiled with
  `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION=1`, and even then only over serial
  (`WalletTransportPolicy.cpp`).
- **Custody gate.** Five separate facts (backend registered, channel authenticated, user
  authenticated, keys non-exportable, wallet uses handles) must hold before secure custody is
  reported. One boolean set by an integration path is exactly how "hardware wallet" claims become
  marketing.
- **Randomness.** The firmware samples the SAR ADC entropy source before starting the battery ADC or worker tasks.
  It health-checks each block before seeding the HMAC-SHA256 DRBG. A failed sample prevents wallet startup.
  The device requires a reboot after 2²⁰ random requests to sample physical entropy again.
- **Boot trust.** `TrustAnchor` records the boot state; `HEXWALLET_REQUIRE_VERIFIED_BOOT=1` makes a
  build refuse to sign when secure boot or flash encryption is off.
- **Fail closed on parse errors.** Signing failures clear the caller's output buffer
  (`SigningOutputGuard`), review sessions are consumed on first use, and the CLI clears pending
  reviews on lock or timeout.

## Chain coverage

The catalog exposes 215 wallet entries over 247 compiled network profiles. "Entry" means a
derivation path plus a review/sign policy, not node acceptance.

| Family | What it does | Deliberate scope |
| --- | --- | --- |
| Bitcoin | PSBT v0 and v2, legacy / BIP143 / Taproot key-path (BIP86), `SIGHASH_DEFAULT`/`ALL` | No script-path spends, no multisig, no Lightning |
| UTXO forks | 105 generated profiles, policy family per chain: legacy, BIP143, `SIGHASH_FORKID`, Groestl-512, ZIP-243 | A fork is admitted only after its `chainparams` were checked; the Bitcoin signer is never used as a guess |
| EVM | 62 networks, EIP-155/2930/1559, 80 pinned token records, raw-calldata review with keccak-256 | Unknown calldata is shown as code, never decoded as a transfer |
| Monero | RCT type 6, CLSAG, Bulletproofs+, 16-member rings, subaddress spends | Decoys come from the phone; an offline device cannot prove they exist on chain |
| Native adapters | ADA, ALGO, APT, CKB, DCR, ERG, FIL, HBAR, HIVE, ICX, ICP, KSM, DOT, NEAR, QRL v1/v2, SC, SOL, STARK, SUI, TFUEL, TON, VET, XCH, XEM, XLM, XRP, XTZ, ZEC, TRX, KAS, DASH, AE, QUAI (Cyprus-1), ALPH, QTC (Quantus), ZEPH | Each adapter has its own payload format, review rules and refusal list |
| Address only | RyoCurrency, Zano | Encoders are tested; there is no signing path and the UI does not pretend otherwise |

Hive is review-and-sign only: an STM public key is not a receive address, so the entry has no
address capability. That asymmetry is in the catalog, not in a footnote.

The full per-chain matrix, including every refusal, is in
[Supported-Chains](https://github.com/blueokanna/HexWallet/wiki/Supported-Chains) and
[Admission-Policy](https://github.com/blueokanna/HexWallet/wiki/Admission-Policy).

## Refused on purpose

Short list; the wiki has the complete one.

- Zcash: shielded pools, JoinSplits, v5, and P2SH redeem scripts other than single-key `CHECKSIG`.
- Peercoin signing. PPC v<3 transactions carry `nTime`; the legacy signer would build an invalid
  transaction, so PPC stays an address primitive.
- Ethereum blind signing. Unknown calldata is displayed as raw bytes with its hash; it is not
  decoded into a transfer.
- TRON NFTs, batch calls, multi-contract transactions, non-owner permissions.
- Cosmos IBC, authz, feegrant, amino/JSON signing.
- Dash special transactions (`extraPayload`). Plain type-0 payments are signed, and InstantSend
  intent is shown on screen, but the lock itself is a quorum decision the device cannot verify.
- Stacks, Lightning, and Grin wallet flows.
- Beam has a native two-party transfer implementation for one standard input. Mainnet custody,
  node synchronization, and recovery still require integration. See the [Beam implementation notes](wiki/Beam-zh.md).
- AION, by decision. `policy_check.ps1` fails if the identity reappears in a profile, the catalog or
  the mining table.
- Qubitcoin, by decision. Its advertised site 404s and two unrelated projects publish under ticker
  QTC, so the owner dropped it from scope; the reasoning stays in
  [Admission-Policy](https://github.com/blueokanna/HexWallet/wiki/Admission-Policy#requested-chains-that-are-not-admitted).
- Any chain without an upstream SLIP-0044 type. Reusing another chain's coin type would derive the
  same key for two domains.

Native review and signing cover ordinary Zephyr, Alephium and Quantus transfers. Beam regular address encoding and two-party signing have independent reference tests. Xelis has native recovery, address and signature primitives. Physical key custody and Beam node messaging and synchronization are pending. See [chain payloads](wiki/Chain-Payloads.md).

## Interfaces

**Serial CLI** (`help` lists everything, and is the contract):

```text
public: help | status | coin list | coin search <text> | coin show <id> | coin why <id>
        mining stats | mining list [ASIC|GPU|CPU|HDD|MERGED] [offset] | mining show <id>
        token list [network] | token show <id>
auth:   auth provision <pin> <pin> | auth begin | auth unlock <proof-hex> | lock
wallet: wallet generate | wallet address <id> [index] | wallet custody <id>
        wallet token <id> [index] | wallet addresses [index]
tokens: token custom-list [network] | token custom-add <network> <id-hex> <symbol> <name> <decimals>
        token custom-add-stellar <issuer-hex> <code> <symbol> <name> <decimals>
        token custom-add-nft <network> <contract-hex> <erc721|erc1155> <symbol> <name>
        token custom-remove <network> <id-hex> | token custom-remove-stellar <issuer-hex> <code>
totp:   totp time [unix] | totp add <otpauth-uri> | totp list | totp show <slot> | totp remove <slot>
sign:   tx inspect [<coin>] <psbt-hex> | tx sign <code> | tx reject
        evm inspect <network> <index> <unsigned-rlp-hex> | evm sign <code>
        kaspa inspect <payload-hex> | kaspa sign <code>
        zec inspect <ZEC4|ZEC5-payload-hex> | zec sign <code>
        chain begin <network> <index> <payload-hex> | chain sign <code> | chain reject
link:   link status | link pair confirm | link pair reject
other:  selftest
```

The session locks after five minutes of inactivity. Provisioning stores
`salt` and `verifier = PBKDF2-SHA256(PIN, salt, 120000)`. `auth begin` returns the salt, the
iteration count and a fresh 32-byte nonce; `auth unlock` expects
`HMAC-SHA256(verifier, nonce)`, compares it in constant time, and backs off on repeated failures.

**USB data is off by default.** Long-press BOOT for three seconds to open a ten-minute window;
another long press, the window timeout, or `lock` closes it and discards buffered input.

**Phone link.** The phone starts every operation; the wallet only reviews, authorizes and signs.
The link runs protocol version 2: Ed25519 identity keys for pairing, an X25519 ephemeral exchange,
HKDF-SHA256 session keys, ChaCha20 with encrypt-then-MAC per frame, and a monotonic sequence
number. Replayed, reordered or forged frames destroy the session. See
[Phone-Link](https://github.com/blueokanna/HexWallet/wiki/Phone-Link).

**TOTP** secrets are stored on the device and never leave it; the CLI can print a code only inside
an authenticated session.

## Build

ESP32 core 3.3.10 and LVGL 9.5.0:

```powershell
arduino-cli core install esp32:esp32@3.3.10
git clone --depth 1 --branch v9.5.0 https://github.com/lvgl/lvgl.git "$HOME/Arduino/libraries/lvgl"
arduino-cli compile --fqbn esp32:esp32:esp32s3 `
  --library "$HOME/Arduino/libraries/lvgl" `
  --build-property compiler.cpp.extra_flags=-DLV_CONF_INCLUDE_SIMPLE `
  --build-property compiler.c.extra_flags=-DLV_CONF_INCLUDE_SIMPLE .
```

Board and feature selection are compile-time `-D` flags; all of them live in `WalletConfig.h`:

| Flag | Default | Meaning |
| --- | --- | --- |
| `HEXWALLET_BOARD` | 1 | board profile (see the table above) |
| `HEXWALLET_ENABLE_LVGL` | 1 | 0 builds the CLI-only image |
| `HEXWALLET_EPD_PROFILE` | 0 | 0 SSD1680 mono, 1 four-colour, 2 mono V2 (P4) |
| `HEXWALLET_REQUIRE_SECURE_CUSTODY` | 1 on device | refuse to open a wallet without SE custody |
| `HEXWALLET_REQUIRE_VERIFIED_BOOT` | 0 | refuse to sign unless secure boot + flash encryption are on |
| `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION` | 0 | allow serial approval on a display-less build |
| `HEXWALLET_DEVICE_SELF_TESTS` | 0 on device | run the vector suite on a bench unit (needs the DRAM headroom) |

The P4 profile is board 7 and must be selected explicitly when compiling for `esp32p4`:

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32p4 -DHEXWALLET_BOARD=7 ...
```

Flash layout is `partitions/hexwallet-16mb-ota.csv`. Read the secure-boot and flash-encryption
notes before burning any eFuse; a wrong eFuse cannot be fixed by an OTA update. See
[Build-and-Flash](https://github.com/blueokanna/HexWallet/wiki/Build-and-Flash).

## Test

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1            # host suite, 72 checks
powershell -ExecutionPolicy Bypass -File tests/host/policy_check.ps1     # firmware policy gates
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1 -Target esp32p4
powershell -ExecutionPolicy Bypass -File tests/host/board_port_compile_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/p4_runtime_compile_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/se051_port_check.ps1 -Device
powershell -ExecutionPolicy Bypass -File tests/host/ui_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/build_clang_ubsan.ps1
```

Some checks need network access or a checked-out dependency on first run: `qr_cross_check.ps1`
(nayuki QR reference), `build_chain_native.ps1` (mbedTLS 3.6.5 under `build/chain-mbedtls`),
`board_port_compile_check.ps1` and `epd_driver_compile_check.ps1` (LVGL 9.5 and GxEPD2). CI pins
each revision.

What the suite does and does not prove is listed in
[Testing](https://github.com/blueokanna/HexWallet/wiki/Testing). A passing vector suite proves the
implementation matches the vectors in this tree; it does not prove a transaction is accepted by a
network.

## Repository layout

| Path | Contents |
| --- | --- |
| `*.cpp`, `*.h` | firmware; the sketch root is the library root, so every translation unit sits here |
| `src/generated/` | generated catalogs and pinned vectors |
| `tests/host/` | host harness, probes, and the compile-check scripts |
| `tests/fixtures/` | upstream transaction fixtures and generated vectors |
| `tools/` | catalog generators and the reviewed MiningPoolStats mapping |
| `partitions/` | flash layout |
| `wiki/` | documentation source for the GitHub wiki (English + 中文) |

## Documentation

The wiki is the long form, published from `wiki/`:

- [Home](https://github.com/blueokanna/HexWallet/wiki/Home) · [中文](https://github.com/blueokanna/HexWallet/wiki/Home-zh)
- [Architecture](https://github.com/blueokanna/HexWallet/wiki/Architecture)
- [Security-Model](https://github.com/blueokanna/HexWallet/wiki/Security-Model) · [Threat-Model](https://github.com/blueokanna/HexWallet/wiki/Threat-Model)
- [Supported-Chains](https://github.com/blueokanna/HexWallet/wiki/Supported-Chains) · [Chain-Payloads](https://github.com/blueokanna/HexWallet/wiki/Chain-Payloads)
- [Admission-Policy](https://github.com/blueokanna/HexWallet/wiki/Admission-Policy)
- [Phone-Link](https://github.com/blueokanna/HexWallet/wiki/Phone-Link) · [Secure-Element](https://github.com/blueokanna/HexWallet/wiki/Secure-Element)
- [Boards-and-Display](https://github.com/blueokanna/HexWallet/wiki/Boards-and-Display)
- [Build-and-Flash](https://github.com/blueokanna/HexWallet/wiki/Build-and-Flash) · [Testing](https://github.com/blueokanna/HexWallet/wiki/Testing)
- [Registries](https://github.com/blueokanna/HexWallet/wiki/Registries) · [Audit-Records](https://github.com/blueokanna/HexWallet/wiki/Audit-Records)

## License

HexWallet Personal Non-Commercial Source License, version 1.0. Source-available, not open source:
personal, non-commercial use by an individual only, no commercial use without a signed license.
Read `LICENSE`; it is the whole agreement. Third-party material is listed in `NOTICE` and keeps its
own terms.

SPDX identifier for tooling: `LicenseRef-HexWallet-Personal-NonCommercial-1.0`.

Commercial licensing: blueokanna@gmail.com
