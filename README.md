# HexWallet

> Production acceptance is incomplete. MSR support was withdrawn on 2026-10-24. Native SOL, SPL Token and Token-2022 TransferChecked are implemented; Token-2022 reviews carry an unverifiable-extension warning and ATA creation is rejected. TRX supports native transfers and registered TRC-20 contracts. Hardware and node acceptance remain pending. See [Solana scope and evidence](docs/solana-signing.md) and [TRON scope and evidence](docs/tron-signing.md).

HexWallet is an offline-first hardware wallet for ESP32-S3. It derives keys from a BIP39 seed, builds and reviews transactions on the MCU, and signs only after a one-time confirmation on the trusted display. The host never receives the seed or private keys.

The public wallet catalog is filtered by the configured signing policies. This filter is not proof that every listed chain has passed independent consensus or hardware validation. Address-only profiles and MiningPoolStats listings without an adapter are not exposed as wallets. That is deliberate: a ticker in a catalog is not a wallet.

## Security model

- BIP39/BIP32 derivation and all signing happen on the device. Secret export is disabled by default (`HEXWALLET_ENABLE_SECRET_EXPORT=0`).
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
| EVM | BIP44 secp256k1 | EIP-155 / EIP-1559, native and whitelisted token calls | 53 registered networks |
| XRP | BIP44 secp256k1, `m/44'/144'/0'/0/i` | Native Payment, canonical XRPL binary, SHA-512Half, secp256k1 DER | No issued currency, paths, memo, partial payments or multisig |
| TRON | BIP44 secp256k1, `m/44'/195'/0'/0/i` | Owner-permission `TransferContract`, registered TRC-20, and unique-selector TRC-721/1155 `safeTransferFrom` | No TRC-10, batch NFT, callback data, memo, multi-contract or multisig; unregistered NFT contracts are shown with a warning |
| Stellar | SEP-0005 Ed25519, `m/44'/148'/i'` | Public-network XDR Payment/CreateAccount, issued-asset issuer and memo review | Up to eight operations; G addresses; no fee bump, muxed accounts, Soroban or multisig |
| Solana | SLIP-0010 ed25519, `m/44'/501'/0'/0'/i'` | Legacy/v0, System Transfer, SPL and Token-2022 `TransferChecked` | Single payer; no ALTs, ATA creation, staking or extra token accounts |
| Cosmos SDK | BIP44 secp256k1, `m/44'/118'/0'/0/i` | Native `MsgSend`, `SIGN_MODE_DIRECT` | ATOM, OSMO, TIA; no IBC, memo, authz or multi-message |
| Algorand | SLIP-0010 Ed25519, `m/44'/283'/0'/0'/i'` | Canonical MessagePack `pay`/`axfer`, genesis/fee/round checks, ASA transfer and opt-in | Mainnet only; no groups, rekey, close, clawback, LogicSig or application calls |
| NEAR | SLIP-0010 Ed25519, `m/44'/397'/i'` | Borsh `TransactionV0`, 1–16 native Transfers, SHA-256/Ed25519 | Implicit accounts only; no FunctionCall, access keys, delegation or staking |
| Tezos | SLIP-0010 Ed25519, `m/44'/1729'/account'/change'/index'` | Manager operations, optional reveal, tz1–tz4 native transfers, BLAKE2b/Ed25519 | No KT1, Michelson, delegation or FA tokens; branch origin not authenticated |
| Kaspa | BIP44 secp256k1 | BIP340 Schnorr, v0 transactions | `SIGHASH_ALL`, KIP-0009 mass |
| Zcash | BIP44 secp256k1, t1/t3 addresses | ZIP-243, v4 transparent, NU6.2 | t1 P2PKH inputs; t1/t3 outputs |
| Monero | BIP44 ed25519, `m/44'/128'/0'/0/i` | RCT type 6, CLSAG, Bulletproofs+, 16-member rings | Standard and subaddress spending, account 0 |

The strict catalog is generated from `WalletForkCatalog.inc` and `WalletCatalog.cpp`. A profile whose network lacks a signing policy is internal test data, not a user wallet.

Generated fork profiles are admitted only after `tools/verify_utxo_sighash.py` confirms the upstream base58 versions, a legacy P2PKH sighash, and a transaction header without `nTime` or a wide `nType`. Fork-id, timestamp-sighash, and wide-type chains stay address-only: the Bitcoin legacy signer is never used as a guess.

## Deliberately unsupported

- Zcash shielded addresses, shielded spends/outputs, JoinSplits, and v3/v5 transactions.
- Spending t3 P2SH Zcash outputs. Sending to t3 is supported; the wallet does not implement P2SH redeem-script signing.
- Peercoin signing. PPC v<3 transactions serialize `nTime`; the Bitcoin legacy signer would build an invalid transaction. PPC is an internal address primitive, not a wallet, until a dedicated Peercoin sighash family with vectors lands.
- Sending or making change to XMR subaddresses. Subaddress inputs can be spent, but destination transaction public keys and receiver-scanning vectors are not complete; these outputs are rejected.
- Ergo, Hathor, Quai, Chia, QRL, Cardano, and Filecoin transaction signing.
- TRON TRC-10, `transferFrom` (shared with TRC-20), batch NFT transfers, non-empty NFT callback data, memo/data fields, multi-contract transactions, and non-owner permissions.
- Cosmos IBC transfers, memo, authz/feegrant, non-native denoms, JSON/amino signing modes and multi-message transactions.
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
| `CryptoNoteTransaction` | Strict RCT type-6 parse + byte-exact rewrite + commitment balance + CLSAG signing (`cryptonote_sign_input`) |
| `CryptoNoteSpend` | Device-side XMR send assembly: one-time outputs, amounts/commitments, solved pseudo-output masks, per-input CLSAG, serialization |
| `CryptoNoteReview` | Per-network policy (fee cap, ring size), key-offset/RCT binding, CLSAG `D` check, honest decoy caveat |
| `CryptoNoteSigning` | Host payload parse → review → per-input CLSAG → serialized transaction; session state and zeroization |
| `CryptoNoteMasari` | Legacy regression source; MSR is not exposed as a wallet |
| `MoneroTxVectorsTest.inc` | Real mainnet RCT type-6 transactions pinned for parse/rewrite/balance regression |
| `TokenCalldata` | ERC-20/721/1155/4626/777/3525/6551 and LayerZero ABI decoding; ERC-20 needs registered decimals, unique NFT selectors may be reviewed unregistered |
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
```

`run_zcash_sighash_self_tests()` checks the published ZIP-243 transparent vector and selected `zcash-test-vectors` rows covering shielded hashes, JoinSplits and ALL/NONE/SINGLE. `run_zcash_transaction_self_test()` runs the full ECDSA/scriptSig/round-trip path on the device.

`run_evm_derivation_self_test()` pins the official Conflux Ledger app vector (`m/44'/503'/0'/0/0`), including the uncompressed public key and `0x` address. `run_address_self_tests()` independently re-checks that address from the same public key on the host.

`run_cryptonote_ringct_self_tests()` pins selected `monero/tests/crypto/tests.txt` vectors for hash-to-scalar, key derivation, public/secret key derivation, key images and view tags. `run_cryptonote_clsag_self_test()` signs and verifies a deterministic 3-member ring and rejects tampered `s`, `I` and message. `run_cryptonote_review_self_tests()` rejects thirteen tampering classes against a proof generated by the pinned Monero reference build, and `run_cryptonote_signing_self_tests()` drives the whole payload → review → CLSAG → serialize path plus the subaddress spend path (the subaddress key pair is cross-checked against the pinned Monero subaddress addresses, and the standard spend secret must fail to sign a subaddress output). `run_masari_self_tests()` verifies the real upstream Masari transaction vector (`tests/fixtures/masari/tx2.bin`), an end-to-end synthetic RCT type-2 spend, and the fail-closed type-3 gate.

An offline signer cannot prove that ring decoys exist on chain; it proves ring consistency, ownership and offset binding only. The phone is trusted to supply live decoys, never amounts, fees or destination addresses. See [xmr-review.md](docs/xmr-review.md) and [xmr-signing.md](docs/xmr-signing.md).

## Phone link (NFC / USB)

Sending is initiated by the phone. The wallet only reviews, authorizes and signs; it never builds the transaction and never talks to a node. The full wire format is in [docs/phone-link-protocol.md](docs/phone-link-protocol.md); `tools/phone_link_reference.py` is a tested phone-side reference implementation (pairing, handshake, encrypted requests) driven by `tests/test_phone_link.py` against the real firmware code.

- Receive: the phone calls `ADDRESS`; the device returns the derived public address and path. No private material crosses the link.
- Send: `BEGIN_SIGN` → the device parses and validates the request (input ownership, change derivation, fee caps, token whitelist, CryptoNote ring/key-image/commitment binding) → the trusted display shows recipient/amount/fee with `APPROVE` / `REJECT` → after the physical press the phone calls `RESULT` and receives the signed transaction bytes.
- Request payloads are capped at 16 KiB so a CryptoNote transaction fits; the CryptoNote layout is documented in [phone-link-protocol.md](docs/phone-link-protocol.md#7-cryptonotexmr--msr).
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

HEXWALLET PERSONAL NON-COMMERCIAL SOURCE LICENSE. See `LICENSE`.
