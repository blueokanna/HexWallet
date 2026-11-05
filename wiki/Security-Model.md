# Security model

[中文](Security-Model-zh) · [Home](Home)

This page states what the code enforces and where. Every row names the file that implements the
control; if the file changes, this page is wrong and must be fixed with it.

## Assets and boundaries

| Asset | Lives in | Leaves the device? |
| --- | --- | --- |
| BIP39 mnemonic | `WalletSession` (host-test builds only) | never |
| Seed, BIP32 nodes, private keys | `SensitiveValue<T>` on the stack | never |
| PIN verifier (`PBKDF2-SHA256(PIN, salt)`) | NVS | never |
| Review text and approval | RAM + panel | only as the signed payload |
| Link identity key (Ed25519) | NVS | public half only, during pairing |
| Signed transaction | caller buffer | yes, that is the output |

Trust boundaries: the MCU is trusted; the host, the phone and everything arriving over serial, USB,
NFC or Bluetooth is untrusted input; the display and its button are trusted *only if* the review
seal proves the frame was committed and the approval is unused.

## Controls

| Control | Enforced in | Behaviour |
| --- | --- | --- |
| No secret export | `WalletConfig.h` | `#error` if `HEXWALLET_ENABLE_SECRET_EXPORT` is set; there is no runtime path |
| Authentication | `WalletCli.cpp` | PIN 8–64 chars; verifier = PBKDF2-SHA256, 120000 iterations, 32-byte random salt; unlock = `HMAC-SHA256(verifier, nonce)` compared in constant time; wrong proof clears every pending review and the wallet session |
| Retry backoff | `WalletCli.cpp` | failures persist in NVS; delay = `1 s << failures`, capped at 10 minutes; `auth begin` is refused while the backoff is active |
| Session lifetime | `WalletCli.cpp` | 5 minutes of inactivity; `lock` is immediate; both wipe the mnemonic and pending reviews |
| Transport policy | `WalletTransportPolicy.cpp` | signing/approval require authenticated session + trusted display on every transport; host-only approval exists only for serial and only when compiled in |
| Review integrity | `TrustAnchor.cpp` | `ReviewSeal` hashes the exact rendered text, is armed only when the panel reports the frame committed, is single-use, and expires with the review |
| Approval lifetime | `WalletSigning.cpp`, `WalletCli.cpp` | 120 s; expiry clears the session; a rejected review cannot be flipped back to approved |
| Approval consumption | `WalletSigning.cpp` | the approval is consumed before the key is unsealed; a failure after that point does not restore it |
| Output clearing | `SensitiveValue.h` | `SigningOutputGuard` zeroes the caller buffer unless the producer commits a valid, non-zero length |
| Custody gate | `WalletCustody.cpp` | five facts must all hold; a missing one yields a specific `CustodyBlocker`, never a silent fallback |
| Boot trust | `TrustAnchor.cpp` | `HEXWALLET_REQUIRE_VERIFIED_BOOT=1` refuses to sign when secure boot or flash encryption is off; "cannot tell" is reported separately from "off" |
| Randomness | `RandomSource.cpp` | per-block health tests + HMAC-SHA256 DRBG; a failed entropy block latches the wallet closed for the boot |
| One-time signatures | `QrlOtsJournal.cpp` | the OTS leaf is reserved in two redundant slots with read-back proof before signing; torn writes are skipped; unknown state refuses |
| No network stack | `tests/host/policy_check.ps1` | the build fails if a firmware file includes WiFi, HTTP, TLS, lwIP or esp_netif headers |

## Key handling

- BIP39: 24 English words, 256-bit entropy, empty passphrase. Word list is compiled in
  (`word_list.h`); there is no download and no locale switch.
- BIP32: hardened account level, then the network's own path. Every derivation writes into
  `SensitiveValue` storage and wipes intermediates.
- Curve operations run on the worker task so the UI stays alive; the worker holds borrowed
  pointers, so the caller never returns early (see [Architecture](Architecture)).
- Wiping uses `mbedtls_platform_zeroize` (or the host equivalent), which is not optimised away.
- The mnemonic buffer is 256 bytes; a longer import is rejected before anything is written.

## Display and approval

The approval is not a boolean set by the caller. It is produced by the panel callback:

1. `wallet_ui_show_transaction()` renders the review text and builds a `ReviewSeal` over it.
2. The panel driver reports the frame as committed; only then is the seal armed.
3. The user presses `APPROVE`; the callback marks the session approved.
4. `wallet_signing_sign()` re-checks the seal (fresh, matched, unused), consumes it, then unseals
   the key.

A build without a display therefore has no approval source. Signing over serial is possible only
with `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION=1`, and only for the serial transport; the phone link
still refuses, because a phone that approves its own request is not a trusted display.

## Secure element status

The SE051 path is implemented up to an authenticated channel and applet commands, and tested
against a mock transport. It is **not** a signing backend: `secure_custody_backend_ready()` is false
because `wallet_uses_handles` is false — derivation and signing still take a plaintext seed in MCU
RAM. With `HEXWALLET_REQUIRE_SECURE_CUSTODY=1` (device default), `WalletSession` compiles to
refusals, so no device build can generate, import or sign with a wallet today.

That is deliberate. A wallet that reports "secure element custody" while the seed sits in RAM is
worse than one that says it is unfinished.

## What is verified, and how

| Claim | Test |
| --- | --- |
| crypto primitives and KDFs | `tests/host/build.ps1` (`crypto-primitives`, `bip39`, `bip32`, …) |
| policy refuses WiFi/TLS includes | `policy_check.ps1` |
| transport matrix | `run_transport_policy_self_test()` |
| custody gate blocker order | `run_custody_self_tests()` |
| RNG health rules and DRBG separation | `run_random_source_self_tests()` |
| review seal single use | `run_trust_anchor_self_tests()` |
| output buffer cleared on failure | host signing tests in `host_test_main.cpp` |
| QRL one-time index reservation | `qrl-ots` checks in the host suite |

A green suite proves the code matches these tests. It does not prove the device resists a
physical attacker, and it does not prove a network accepts the transaction. Those limits are in
[Threat-Model](Threat-Model).
