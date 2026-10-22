# HexWallet

> Production acceptance is incomplete; full XMR/MSR transfers are not implemented. See [AUDIT.md](AUDIT.md) for verified checks and remaining gaps, and [Arduino layout](docs/arduino-layout.md) for generated include files.

HexWallet is an offline-first hardware wallet for ESP32-S3. It derives keys from a BIP39 seed, builds and reviews transactions on the MCU, and signs only after a one-time confirmation on the trusted display. The host never receives the seed or private keys.

The public wallet catalog is filtered by the configured signing policies. This filter is not proof that every listed chain has passed independent consensus or hardware validation. Address-only profiles and MiningPoolStats listings without an adapter are not exposed as wallets. That is deliberate: a ticker in a catalog is not a wallet.

## Security model

- BIP39/BIP32 derivation and all signing happen on the device. Secret export is disabled by default (`HEXWALLET_ENABLE_SECRET_EXPORT=0`).
- Every signing request is parsed into a fixed review structure, displayed on the trusted UI, and bound to a six-digit one-time code with a 120-second lifetime.
- Bitcoin PSBT inputs must commit to wallet-owned UTXOs. Zcash payloads must carry every prevout value/script, and the signer re-derives and checks each P2PKH hash. Kaspa payloads are validated against BIP340 keys and KIP-0009 mass.
- Fee caps, amount bounds, duplicate-input checks, canonical encoding checks, and explicit refusal of unsupported transaction families are enforced before ECDSA/Schnorr.
- Host-only confirmation is disabled unless the firmware is built with `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION=1`. Production devices should use a trusted display.
- The boot self-test must pass before wallet services start. A failure disables the wallet instead of degrading silently.

## Supported wallets

| Family | Receive | Review + sign | Scope |
| --- | --- | --- | --- |
| Bitcoin | BIP44/BIP49/BIP84 | PSBT v0, `SIGHASH_ALL` | Native SegWit, nested SegWit, legacy P2PKH |
| Bitcoin-family forks | P2PKH / SegWit profiles | Legacy sighash or BIP143 + `SIGHASH_FORKID` | Litecoin, Dogecoin, Dash, DigiByte, Bitcoin Gold, Ravencoin, Namecoin, Vertcoin, Axe, BCH, BSV, XEC, Sugarchain, e-Gulden, LBRY, MazaCoin, Myriad, NewYorkCoin, Auroracoin, Bitcore, CPUchain, DigitalCoin, Einsteinium, Feathercoin, GoByte, Monacoin, Ritocoin, VIVO, and other source-verified generated profiles |
| EVM | BIP44 secp256k1 | EIP-155 / EIP-1559, native and whitelisted token calls | 45 registered networks |
| Kaspa | BIP44 secp256k1 | BIP340 Schnorr, v0 transactions | `SIGHASH_ALL`, KIP-0009 mass |
| Zcash | BIP44 secp256k1, t1/t3 addresses | ZIP-243, v4 transparent, NU6.2 | t1 P2PKH inputs; t1/t3 outputs |

The strict catalog is generated from `WalletForkCatalog.inc` and `WalletCatalog.cpp`. A profile whose network lacks a signing policy is internal test data, not a user wallet.

Generated fork profiles are admitted only after `tools/verify_utxo_sighash.py` confirms the upstream base58 versions, a legacy P2PKH sighash, and a transaction header without `nTime` or a wide `nType`. Fork-id, timestamp-sighash, and wide-type chains stay address-only: the Bitcoin legacy signer is never used as a guess.

## Deliberately unsupported

- Zcash shielded addresses, shielded spends/outputs, JoinSplits, and v3/v5 transactions.
- Spending t3 P2SH Zcash outputs. Sending to t3 is supported; the wallet does not implement P2SH redeem-script signing.
- Peercoin signing. PPC v<3 transactions serialize `nTime`; the Bitcoin legacy signer would build an invalid transaction. PPC is an internal address primitive, not a wallet, until a dedicated Peercoin sighash family with vectors lands.
- Monero/Masari transaction signing. The CryptoNote address layer and the RingCT key layer (hash-to-scalar, key derivation, one-time keys, key images, view tags) are implemented and pinned to official Monero vectors. CLSAG sign/verify and tamper rejection are implemented and self-tested, but Bulletproofs+, ECDH amount encoding, decoy selection and full transaction serialization are not complete. CLSAG is not yet pinned to an external Monero transaction vector, so no CryptoNote wallet is exposed.
- Ergo, Hathor, Quai, Chia, QRL, Solana, Cardano, Cosmos, Algorand, Tezos, Filecoin, XRP, and TRON transaction signing.
- Arbitrary EVM calldata, contract creation, unknown tokens, non-standard typed transactions, and non-empty access lists.

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
| `BitcoinTransaction` | PSBT v0, legacy/BIP143/fork-id sighash, serialization |
| `EvmTransaction` | RLP, EIP-155/EIP-1559, token-call review and signing |
| `KaspaTransaction` | BLAKE2b sighash, KIP-0009 mass, BIP340 signing, protobuf |
| `ZcashTransaction` | v4 transparent parser, ZIP-243 digest, t1 signing, t1/t3 output rendering |
| `CryptoNoteRingCt` | Monero hash-to-scalar, key derivation, one-time keys, key images, view tags, CLSAG sign/verify; key layer official vector-pinned |
| `CryptoNoteOutputScan` | On-device output ownership test with the view secret (no view-key export) |
| `CryptoNoteTransaction` | Strict RCT type-6 parse + byte-exact rewrite + commitment balance check (no Bulletproofs+ verification or CLSAG signing yet) |
| `TokenCalldata` | Whitelisted ERC-20/721/1155/4626/777/3525/6551 and LayerZero wrappers |
| `WalletTokens` | Registered EVM token metadata |

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

`zec inspect` accepts `ZEC4` payloads with one prevout record per input. `tools/build_zcash_review_payload.py` builds the payload and prints the independent ZIP-243 digest for auditing.

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

## Verification

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/board_port_compile_check.ps1
python tests/test_fork_registry.py
python tests/test_fork_address_vectors.py
python tests/test_mining_catalog.py
python tests/test_phone_link.py
python tools/verify_utxo_sighash.py   # network audit; use --apply only after review
```

Expected host results include:

```text
crypto-primitives=pass
alt-addresses=pass
blake2b=pass
cryptonote-ringct=pass
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
```

`run_zcash_sighash_self_tests()` checks the published ZIP-243 transparent vector and selected `zcash-test-vectors` rows covering shielded hashes, JoinSplits and ALL/NONE/SINGLE. `run_zcash_transaction_self_test()` runs the full ECDSA/scriptSig/round-trip path on the device.

`run_evm_derivation_self_test()` pins the official Conflux Ledger app vector (`m/44'/503'/0'/0/0`), including the uncompressed public key and `0x` address. `run_address_self_tests()` independently re-checks that address from the same public key on the host.

`run_cryptonote_ringct_self_tests()` pins selected `monero/tests/crypto/tests.txt` vectors for hash-to-scalar, key derivation, public/secret key derivation, key images and view tags. `run_cryptonote_clsag_self_test()` signs and verifies a deterministic 3-member ring and rejects tampered `s`, `I` and message. CLSAG still needs an external Monero transaction vector before it can gate a wallet.

## Phone link (NFC / USB)

Sending is initiated by the phone. The wallet only reviews, authorizes and signs; it never builds the transaction and never talks to a node. The full wire format is in [docs/phone-link-protocol.md](docs/phone-link-protocol.md); `tools/phone_link_reference.py` is a tested phone-side reference implementation (pairing, handshake, encrypted requests) driven by `tests/test_phone_link.py` against the real firmware code.

- Receive: the phone calls `ADDRESS`; the device returns the derived public address and path. No private material crosses the link.
- Send: `BEGIN_SIGN` → the device parses and validates the request (input ownership, change derivation, fee caps, token whitelist) → the trusted display shows recipient/amount/fee with `APPROVE` / `REJECT` → after the physical press the phone calls `RESULT` and receives the signed transaction bytes.
- Pairing: the first connection shows a six-digit code plus the phone fingerprint on the device; the phone key is then pinned and any other phone is refused.
- Link protection: Ed25519-signed handshake plus ephemeral ECDH (HKDF-SHA256 session keys), ChaCha20 + HMAC-SHA256 per frame with a strictly increasing sequence number. Forged, replayed, reordered or tampered frames fail and destroy the session.
- USB data is **off by default**: long-press the BOOT/user button for three seconds to open a bounded window; another long press, the timeout, or a lock closes it and discards buffered input.
- NFC uses a PN7161 (NCI 2.0) ISO-DEP card-emulation port. Pins must come from the schematic (`HEXWALLET_NFC_PN7161` + `HEXWALLET_NFC_PIN_*`); without them `link status` reports `nfc=not-configured` and the firmware does not guess pins. The driver has not yet been validated on hardware.
- Boards without a display never review a transaction over the link (`unsupported`); there is no fallback to host-only confirmation.

## MiningPoolStats coverage

`tools/miningpool_coverage.py` fetches the live MiningPoolStats list and compares it with the shipped mining table. `tools/generate_mining_catalog.py` emits only rows that resolve to a fully supported wallet; unsupported listings are counted by the audit tool but are not shipped as wallets. Current audit: **111 / 518 active listings** supported (ASIC 62/212, GPU 30/181, CPU 19/121, HDD 0/4). The gap is explicit, not hidden behind placeholder rows.

Adding a family is a protocol project, not a catalog edit: consensus transaction format, official vectors, review rules, signing, failure paths, and custody policy must all land together.

## Flash, OTA and eFuses

Secure Boot v2, Flash Encryption, and OTA rollback are documented in `partitions/` and the wiki. Do not burn eFuses until the recovery image, signing-key backup, and rollback path have been validated on a sacrificial board. A wrong eFuse cannot be fixed by OTA.

## License

MIT. See `LICENSE`.