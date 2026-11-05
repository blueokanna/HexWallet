# HexWallet wiki

HexWallet signs on the microcontroller. Keys are derived from a BIP39 seed inside the device,
transactions are parsed and reviewed on the device, and the signature is released only after the
confirmation button on the trusted display is pressed. There is no network stack in the firmware.

**This wiki is the long form of [README.md](https://github.com/blueokanna/HexWallet#readme).**
Every page exists in English and Chinese; the `中文` link at the top of each page switches language.

## Read this first

The code is real, tested and unfinished. Specifically:

- The host suite passes (67 named checks) and CI compiles every board profile. That is what the
  green badges mean.
- No board in this repository has a recorded hardware acceptance run. No chain has been accepted
  against a live node. There is no third-party audit.
- Secure-element custody is implemented through SCP03/APDU but the wallet still derives and signs in
  MCU RAM, so device builds with `HEXWALLET_REQUIRE_SECURE_CUSTODY=1` compile the session to
  refusals. No device build can create, import or use a wallet today.
- Do not store funds you cannot afford to lose on any build from this tree.

## Start here

| If you want to… | Read |
| --- | --- |
| understand the moving parts | [Architecture](Architecture) |
| know what the device actually enforces | [Security-Model](Security-Model) |
| know which chains do what | [Supported-Chains](Supported-Chains) |
| write host-side tooling | [Chain-Payloads](Chain-Payloads) |
| integrate a phone | [Phone-Link](Phone-Link) |
| understand the SE051 status | [Secure-Element](Secure-Element) |
| build and flash | [Build-and-Flash](Build-and-Flash) |
| run the tests | [Testing](Testing) |
| see why a chain is or is not admitted | [Admission-Policy](Admission-Policy) |
| know what this design does not protect against | [Threat-Model](Threat-Model) |
| read the dated engineering records | [Audit-Records](Audit-Records) |

## Numbers that are checked, not claimed

These are produced from the compiled tables by `tests/host/catalog_dump.exe` and
`tools/generate_mining_catalog.py`, so they move when the code moves:

| Fact | Value |
| --- | --- |
| Wallet entries exposed by the catalog | 211 |
| Compiled network profiles | 243 |
| EVM networks | 63 |
| Generated UTXO fork profiles | 105 |
| Pinned token records | 78 |
| Native chain adapters | 22 |
| MiningPoolStats entries resolved | 115 of 520 active |

A catalog entry means "derivation path plus a review/sign policy". It does not mean the chain works
against a node, and it does not mean anybody has run it on hardware.

## Repository map

```text
HexWallet.ino      Arduino entry point (sketch root is also the library root)
WalletConfig.h     every compile-time switch, board selection, limits
WalletBoardPins.h  per-board pin maps, each traceable to a schematic
WalletSecurity.*   BIP39/BIP32, secp256k1, Ed25519, KDFs, zeroisation
WalletEngine.*     path construction and address derivation
WalletNetworks.*   network profiles, encodings, signing policies
WalletCatalog.*    the user-facing wallet list and its capability bits
WalletSigning.*    review → approve → sign session, one request at a time
WalletCli.*        authenticated serial console
WalletLink*.*      phone protocol, session crypto, NFC APDU transport
Se051*.*           secure-element APDU, SCP03, curves, provisioning
*Transaction.*     one parser/serialiser per chain family
tests/host/        host harness, probes and compile checks
tools/             catalog generators and reviewed mappings
wiki/              this documentation (source for the GitHub wiki)
```

## License

HexWallet Personal Non-Commercial Source License 1.0: source-available, personal
non-commercial use by an individual only. Commercial use needs a signed license. See `LICENSE`
in the repository. Third-party components keep their own terms (`NOTICE`).
