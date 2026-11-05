# Architecture

[中文](Architecture-zh) · [Home](Home)

The firmware is a single Arduino sketch. All translation units live at the repository root because
the sketch directory doubles as the library root; `src/` holds generated tables and the curve
abstraction, not application code.

## Execution model

| Context | Stack | Runs |
| --- | --- | --- |
| Arduino loop task (core 1) | 32 KiB (`SET_LOOP_TASK_STACK_SIZE`) | serial CLI, UI event loop, NFC, button polling |
| `hexwallet-crypto` worker (core 0) | 24 KiB | every long curve operation: ECDSA, Schnorr, CLSAG, ML-DSA, BLS, XMSS |
| host test harness | process stack | the same sources, compiled with `HEXWALLET_HOST_TEST=1` |

`wallet_worker_execute()` owns the handoff. It never kills a running job: a curve operation cannot
be cancelled safely, and returning while the worker still holds a pointer into the caller's stack or
transaction buffer is a use-after-free waiting to happen. Instead it drains the job, keeps servicing
the display meanwhile, and reports `TimedOut` only after the worker has actually finished and the
deadline had already passed. The caller must treat `TimedOut` as "no signature".

The host backend runs the job inline inside `wallet_worker_wait()` so the same call sites are
tested without FreeRTOS.

## Session model

`WalletSession` is the only owner of the mnemonic. It is compiled in two mutually exclusive shapes:

- **Host tests** (`HEXWALLET_HOST_TEST=1` and `HEXWALLET_REQUIRE_SECURE_CUSTODY=0`): a 256-byte
  mnemonic buffer, wiped on `wallet_session_clear()`, the platform session timeout, or `lock`.
- **Device** (everything else): no mnemonic store at all. `wallet_session_generate()`,
  `wallet_session_import()` and both load functions return `CustodyUnavailable`.

That second point is the honest state of the project: **current device firmware cannot create,
import or use a wallet**, because the only working key path is a plaintext seed in MCU RAM and that
is exactly what the custody policy forbids. Turning the SE051 channel into a signing backend is the
open work item, not a configuration flag.

## Signing pipeline

```text
flowchart TD
    %% Node Definitions
    Payload(["host/phone payload"])
    Parser["chain parser"]
    
    subgraph ReviewFlow ["Interactive Review Flow (UI)"]
        direction TB
        ReviewStruct["bounded review struct<br/><small>(ChainReview / PSBT review / EVM review)</small>"]
        Screen["display render + approval button"]
    end

    subgraph CheckFlow ["Security Verification Flow (Core)"]
        direction TB
        PolicyCheck["ownership + policy checks"]
    end

    SignFunc[["wallet_signing_sign()"]]
    Zeroize["buffers zeroed, approval consumed"]
    SignedTx(["signature / signed transaction"])

    %% Connections
    Payload --> Parser
    Parser --> ReviewStruct
    ReviewStruct --> Screen
    
    Parser --> PolicyCheck
    
    PolicyCheck -- "pass" --> SignFunc
    Screen -- "approved" --> SignFunc
    
    PolicyCheck -- "refusal" --> Zeroize
    Screen -. "rejected / timeout" .-> Zeroize
    
    SignFunc --> SignedTx

    %% Styling
    classDef ioNode fill:#f1f5f9,stroke:#475569,stroke-width:2px,color:#0f172a;
    classDef coreNode fill:#eff6ff,stroke:#2563eb,stroke-width:1.5px,color:#1e3a8a;
    classDef uiNode fill:#f0fdf4,stroke:#16a34a,stroke-width:1.5px,color:#14532d;
    classDef signNode fill:#faf5ff,stroke:#9333ea,stroke-width:2px,color:#581c87;
    classDef rejectNode fill:#fef2f2,stroke:#dc2626,stroke-width:1.5px,color:#991b1b;

    class Payload,SignedTx ioNode;
    class Parser,PolicyCheck coreNode;
    class ReviewStruct,Screen uiNode;
    class SignFunc signNode;
    class Zeroize rejectNode;
    
    style ReviewFlow fill:#f8fafc,stroke:#cbd5e1,stroke-dasharray: 5 5,color:#475569
    style CheckFlow fill:#f8fafc,stroke:#cbd5e1,stroke-dasharray: 5 5,color:#475569
```

Properties that follow from the shape:

- Parsing happens before key access. A malformed payload never reaches a curve operation.
- The review structure is copied into the signing session, re-derived from the payload, and compared
  field by field before signing. The bytes that are signed are the bytes that were displayed.
- `wallet_signing_sign()` consumes the approval first, then unseals the key. Any failure after that
  point still leaves the session unusable.
- `SigningOutputGuard` zeroes the caller's output buffer unless the producer explicitly commits a
  non-zero length that fits the caller's declared capacity.

## Module map

| Module | Responsibility | Depends on |
| --- | --- | --- |
| `WalletConfig.h` | every compile-time switch, limit and board id | nothing |
| `WalletBoardPins.h` | per-board pin constants | `WalletConfig.h` |
| `WalletBoardPort` | panel, touch, battery, button and USB-window hardware | pins |
| `WalletSecurity` | BIP39, BIP32, secp256k1/Ed25519 primitives, PBKDF2, HMAC, zeroisation | mbedTLS |
| `WalletEngine` | path construction, address derivation, custody-facing key material | networks, security |
| `WalletNetworks` | network profiles, address encodings, sighash policy, Zcash branch policy | addresses |
| `WalletCatalog` | user-facing wallet entries and capability bits | networks |
| `WalletTokens` | pinned token records and calldata registry | calldata |
| `WalletSigning` | review → approve → sign session, worker orchestration | adapters, UI, custody |
| `WalletUi` | trusted-display review, approval callback, review seal | board port |
| `WalletCli` | authenticated console, PIN verifier, retry backoff | session, signing |
| `WalletLink*` | pairing, X25519 + HKDF session, encrypted frames | crypto |
| `WalletNfcApdu` / `WalletNfcPort` | ISO 7816-4 applet and PN7161 NCI port | link |
| `Se051*` | APDU applet, SCP03, curve mapping, provisioning | secure element port |
| `*Transaction.*` | one parser/serialiser per chain family | crypto primitives |

Dependency direction is one-way: adapters do not call the UI, the UI does not parse payloads, and
the board port never sees key material. The only shared state between the display task and the
worker is the signing session, and it is single-consumer by construction.

## Data tables and generation

Compile-time tables are generated, not hand-maintained, and CI re-runs the generators with `--check`:

| Table | Source | Generator |
| --- | --- | --- |
| `src/generated/WalletForkProfiles.inc` | `tools/fork_registry.json` | reviewed by hand, one row per audited `chainparams` |
| `src/generated/WalletMiningCatalog.inc` | MiningPoolStats snapshot + reviewed mapping | `tools/generate_mining_catalog.py` |
| `src/generated/CoinIcons.inc` | CC0 artwork | `tools/pack_coin_icons.ps1` |
| `src/generated/MaidSprite.inc` | sprite sheet | `tools/pack_maid_sprite.ps1` |
| `wiki/miningpoolstats-coverage.md` | the same generator | `tools/generate_mining_catalog.py` |

`tools/native_coverage.ps1` dumps the resolved catalog into `wiki/native-chain-capabilities.md`, so
the published capability matrix is produced from the compiled objects rather than from prose.

## Memory and failure behaviour

- No STL containers, no `String`, no exceptions in firmware code. Buffers are fixed-size and
  length-checked at every boundary.
- Heap is used only for bounded, null-checked workspaces (ML-DSA-87, BLS12-381, base58 scratch).
  Nothing on the signing path grows with input size.
- Every subsystem has a typed error enum (`WalletError`, `ChainError`, `TransactionError`,
  `WalletSigningError`, `Se051Error`) with a fixed text mapping; callers cannot invent a success.
- Secrets live in `SensitiveValue<T>`, which is non-copyable and wiped at scope exit. That protects
  against early returns and stack reuse, not against a compromised MCU or copies inside a library.

## What the architecture does not do

- It does not run a node. Any value, fee, nonce, UTxO or decoy that a host supplies is trusted input
  for the review screen; the device checks it for internal consistency and ownership, not for
  existence on chain.
- It does not isolate chains from each other with an MPU. A memory-corruption bug in one parser can
  reach any other module.
- It does not protect the display bus or the MCU from physical access. See [Threat-Model](Threat-Model).
