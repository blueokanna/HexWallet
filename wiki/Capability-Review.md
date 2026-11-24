# Review of the four supplied screenshots

[中文](Capability-Review-zh) · [Home](Home) · [Validation records](validation)

As of 2026-11-24, Board 7 runs diagnostic firmware. Production wallet sessions return `CustodyUnavailable`. Host signing tests use public test credentials.

The current link audit found the four requirement screenshot files missing from this workspace. Their recorded dimensions and analysis are retained below. The newly rendered 88 firmware UI images are available in the [individual-frame gallery](UI-Gallery).

## Figure one — transaction support

Original screenshot, 1034 × 407; missing local file: `Review-Chain-Scope.png`.

| Item | Current evidence and limits |
| --- | --- |
| Zcash | Transparent NU7 v5 payments use ZIP-244. Zebra 7.1.0 confirmed two regtest payments at heights 106 and 107, including a transaction spending P2PKH and a single-key P2SH `CHECKSIG` output together. Shielded pools, JoinSplit and other redeem scripts remain outside the adapter. [Receipts](validation) |
| Peercoin | The `ppc` profile encodes P2PKH addresses. Dedicated sighash tests cover v1/v2 `nTime` and v3. A production signing policy, device review and node receipts remain open. |
| Ethereum unknown calldata | `evm_parse_for_review()` tries structured review first. Supported opaque payloads display the target, raw data, Keccak-256 and maximum fee. The native call value does not bound token movements or permissions. [Phone protocol](Phone-Link) |
| TRON | The adapter handles owner-authorized native, TRC-10 and registered TRC-20 transfers. NFTs, batches, multiple contracts and other permission IDs still need signing support. |
| Cosmos | Across six chains, 24 two-recipient direct `MsgSend` transactions matched CosmJS. The Hub and Osmosis profiles matched 10 additional signatures. Private Gaia and Osmosis nodes each executed an Amino payment, a limited bank-send grant and its revocation. Relaying native ICS-20 payments in both directions credited 1.234567 ATOM on Osmosis and 2.345678 OSMO on Gaia. Each source chain recorded the acknowledgement. [Payloads](Chain-Payloads#cosmos) · [Node receipts](validation) |
| Dash | Type-0 payments verify the funding transactions and compute the fee. InstantSend intent can be displayed. A node must verify the quorum lock. Special `extraPayload` transactions remain open. |
| Stacks, Lightning, Grin | STX payments, Lightning channel state and revocation, and Grin wallet payments lack adapters. Bitcoin multisig scripts and Beam interactive payments have separate support boundaries. |
| Beam | The CLI supports an interactive payment with one ordinary input. Independent reference tests cover addresses and transfers. Production custody, unspent output discovery, synchronization, chain recovery and a two-device node test remain open. [Beam record](Beam-zh) |
| AION and Qubitcoin | Both remain excluded by the recorded project decision. Registry policy checks cover their identities and distinguish projects sharing the QTC ticker. [Admission policy](Admission-Policy) |
| Coin types, Zephyr, Alephium, Quantus and Xelis | Coin types require documented provenance. Zephyr has an explicit exception for Monero's 128 and shares spend and view keys at the same path. Ordinary ZPH, Alephium P2PKH and Quantus transparent transfers have native review and signing. Xelis implements native recovery, addresses and signing primitives. Confidential balance synchronization, transfer proofs and production custody remain open. [Supported chains](Supported-Chains) |

## Figure two — wallet and peripherals

Original screenshot, 338 × 371; missing local file: `Review-Wallet-Features.png`.

| Item | Implemented or tested | Still open |
| --- | --- | --- |
| FIDO2 | CTAP HID framing, cancellation and timeout, ES256 known-answer tests | CTAP2 commands, credential storage, PIN/UV and browser registration and login |
| Camera and QR | OV9281 probing, QR output and fragment reassembly. ZXing decoded the receive address from both English and Chinese 296 × 128 landscape frames. Controller RAM is 128 × 296. [44 states in both languages](UI-Gallery) | CSI capture on the board and a camera scan through transaction import |
| NFC | The PN7161 and panel share GPIO7/8/9 with separate chip selects. The host checks that field loss cancels a review | Physical phone pairing and APDUs, field-strength changes and latency during shared-bus refresh |
| TOTP | Session accounts, local time-setting approval and display of codes | Trusted clock, protected persistence and complete standalone account management |
| Ryo | The release validator recognized standard addresses and subaddresses. The phone verified funding ownership, commitments and signed key images, then built v3 payments. The host firmware reviewed the recipient, change, fee and payment ID, verified the Bulletproof and signed after one-time panel approval. Stock `ryod` mined two payments on a private fork. The recipient scanned both. [Receipts](validation) | The release catalog exposes addresses. Physical panel approval, card-backed key-image export and signing, and end-to-end phone broadcast on mainnet remain open. |
| Zano | The daemon accepted phone-derived addresses. The phone verified all proofs on two existing v4 mainnet payments. It generated asset membership, aggregation, Bulletproof+ and balance proofs for two new native payments. Host firmware checked the recipient, change, fee and payment ID and signed all three inputs after simulated approval. A private testnet mined both payments. [Receipts](validation) | Physical panel approval, card-backed key images and signatures, a phone broadcast from real hardware, and GGXXG staking. The release catalog exposes addresses. |
| Xelis and Beam | The address, key and payment components in figure one | Real balance discovery, synchronization, restoration, card custody and full node interaction |
| NFTs, swaps, staking and DApps | A Chromium DApp discovered the Ethereum provider and submitted ETH, Lido, Uniswap V2 and ERC-721 transactions to an Anvil fork. Eight Solana LiteSVM executions include a single-supply SPL transfer, stake and specific swap programs | Arbitrary contract semantics, cross-chain batches, other NFT standards and a physical phone payment need individual acceptance. [Ledger results](validation) |

## Figure three — production and recovery

Original screenshot, 328 × 265; missing local file: `Review-Production.png`.

| Item | Evidence and outstanding work |
| --- | --- |
| Backup, recovery, migration and destruction | Host creation and import accept English BIP39 words and an ASCII passphrase of up to 128 bytes. The published `TREZOR` seed vector passes. The SE051 test checks the bytes of the object-to-object PBKDF2 command. Local mnemonic entry, protected BIP32, BIP38 and replacement-card recovery are pending. Simulated migration preserves credentials. QRL refuses to sign with an existing key if its XMSS index journal is lost. [Secure element](Secure-Element) |
| Manufacturing | SCP03 and some applet commands exist. Per-device key injection, backup, non-exportable derivation and real-card signing still require integration. [Secure element](Secure-Element) |
| Release and updates | The blank-board factory image is exactly 8,388,608 bytes. The layout includes two OTA slots and 24 MiB for assets. ELF hashes and simulated interrupted writes can be verified. Signed production releases, independent reproducible builds, update-key management and device anti-rollback await acceptance. [Build and flash](Build-and-Flash) |
| Long-running load | Host sanitizers, UI regressions, SPI handling and panel idle sleep are present. Physical heap growth, peak stack use, PSRAM headroom, temperature, current and battery life remain unmeasured. |
| Real funds | The diagnostic SDK disables Secure Boot, Flash Encryption and NVS Encryption. Production wallet sessions refuse to open. Vectors and local ledger receipts establish the specific transaction behavior exercised. |

## Figure four — security properties

Original screenshot, 333 × 243; missing local file: `Review-Physical-Security.png`.

| Item | Evidence and outstanding work |
| --- | --- |
| Parser and link fuzzing | Four Ryo fixtures each undergo every truncation, 10,000 deterministic mutations and 1,000 random inputs. Frame and state-machine regressions exercise the link. Continuous coverage-guided fuzzing across the parser and transport surfaces remains open. |
| Formal verification | Known-answer tests, independent comparisons and ledger receipts exist. The project has no formal correctness proof. |
| Constant time | Secret comparisons, parts of the curve implementation and temporary clearing have controls. Constant-time behavior across all MCU arithmetic and physical side-channel resistance remain unverified. |
| Fault injection | There is no board-level acceptance evidence for resistance to voltage or clock faults. |
| Panel and SE buses | Panel SPI lacks cryptographic integrity. The SCP03 implementation includes command and response MACs and encryption with host vector coverage. Provisioning, authentication and production operations on the target card need hardware evidence. |
| NFC relay | Pairing and frame authentication identify a peer. Local approval binds a transaction. Physical proximity and relay resistance remain unverified. |
| NVS PIN verifier | Salted PBKDF2 and online retry backoff protect PIN verification. A readable verifier permits offline guessing. The diagnostic SDK disables NVS encryption. |
| Coercion | Duress PIN, hidden wallets and plausible-deniability flows remain unimplemented. |
| Certification | The complete wallet has no recorded FIPS, Common Criteria or independent hardware security certification. An independent third-party security audit remains open. [Threat model](Threat-Model) |
