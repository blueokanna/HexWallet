# Audit records

[中文](Audit-Records-zh) · [Home](Home)

Engineering records are dated and are **not rewritten**. They are the evidence trail: what was
checked on a given day, what was found, what was left open. Current behaviour lives in the curated
pages; when a record and a curated page disagree, the curated page plus the generated matrix win,
and the record stays as-is so the change is visible.

## Curated documentation

| Page | Covers |
| --- | --- |
| [Architecture](Architecture) | execution model, session model, signing pipeline, module map |
| [Security-Model](Security-Model) | every enforced control and where it lives |
| [Threat-Model](Threat-Model) | adversaries, current status, surface inventory |
| [Supported-Chains](Supported-Chains) | what each family does and refuses |
| [Chain-Payloads](Chain-Payloads) | wire formats for host tooling |
| [Admission-Policy](Admission-Policy) | how a chain earns a `SIGN` row |
| [Phone-Link](Phone-Link) | protocol version 2 |
| [Secure-Element](Secure-Element) | SE051 status and custody gate |
| [Boards-and-Display](Boards-and-Display) | pins, panels, e-paper rules, QR, camera |
| [Build-and-Flash](Build-and-Flash) | toolchain, partitions, eFuse warnings |
| [Testing](Testing) | suites, oracles, what green does not prove |
| [Registries](Registries) | networks, tokens, mining identities |

## Generated artefacts

| File | Generator | Meaning |
| --- | --- | --- |
| `native-chain-capabilities.md` | `tools/native_coverage.ps1` | one row per compiled profile and its capability |
| `miningpoolstats-coverage.md` | `tools/generate_mining_catalog.py` | every listing and its resolution |

Both are checked in CI; editing them by hand fails the build.

## Dated records

| Record | Date | Content |
| --- | --- | --- |
| `record-security-review-2026-10-28.md` | 2026-10-28 | P4 + SE051 safety review, algorithm corrections, admission decisions of that day |
| `hardening-2026-10-30.md` | 2026-10-30 | fixed defects, reproducible checks, open items, PRL identity verification |
| `hardening-2026-10-31.md` | 2026-10-31 | second hardening round |
| `hardening-2026-10-31-tokens.md` | 2026-10-31 | token registry self-verification, new registry rows, custom assets |
| `independent-wallet-audit-2026-11-02.md` | 2026-11-02 | independent signing and network audit; findings that had to be fixed |
| `pearl-beam-audit-2026-11-03.md` | 2026-11-03 | Pearl and BEAM; what was admitted and what was not |
| `psbt-nft-validation-2026-11-02.md` | 2026-11-02 | PSBT and custom NFT validation fixes |
| `taproot-audit-2026-11-03.md` | 2026-11-03 | BIP341/BIP86 key-path audit, BIP371 behaviour |
| `validation-network-registry-2026-11-02.md` | 2026-11-02 | network registry validation findings |
| `validation.md` | living log | dated validation entries, newest first |
| `chain-gates.md` | living ledger | per-chain capability evidence and remaining gaps |
| `chain-protocols.md` | living notes | adapter-level implementation notes |
| `chain-support.md` | legacy matrix | superseded by Supported-Chains |
| `phone-link-protocol.md` | wire record | protocol detail, version 2 |
| `se051-integration.md` | SE record | APDU/SDK cross-check, custody gaps |
| `display.md` | panel record | e-paper profiles, camera, QR background |
| `authentication-status.md` | status record | display/TOTP/FIDO2 boundaries |
| `totp.md`, `dash.md`, `evm-access-lists.md`, `network-registry.md` | topic notes | implementation detail for one subsystem |

## Reading a record

Each record states its own scope and its own limits. A sentence like "no physical board was tested"
is part of the record, not a disclaimer to skip. If you need today's behaviour, use the curated
page and the generated matrix, then confirm against the code.

## Why keep them

Because the interesting part of a wallet is not the list of supported tickers; it is the trail of
what was rejected, why, and what changed afterwards. Deleting that trail would make the project
easier to describe and harder to trust.
