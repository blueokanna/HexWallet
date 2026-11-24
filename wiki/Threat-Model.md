# Threat model

[中文](Threat-Model-zh) · [Home](Home)

What this device is supposed to survive, what it currently survives, and what it does not. The
"status" column describes the code in this tree, not an intention.

## Adversaries

| Adversary | Capability assumed |
| --- | --- |
| Malicious host or phone | full control of every byte sent to the device, unlimited retries |
| Network observer | sees the signed transaction after broadcast |
| Thief | has the device, no PIN, unlimited local time |
| Physical attacker | can open the case, probe buses, read flash, inject faults |
| Supply-chain attacker | can modify firmware before flashing or replace the hardware |
| Malicious insider in the toolchain | can alter generated tables or a dependency |

## Threats and current status

| # | Threat | Status | Residual risk |
| --- | --- | --- | --- |
| 1 | Host asks the device to sign something other than what the user approved | Mitigated | The device compares the re-derived review with the displayed one; the user can still misread a look-alike address |
| 2 | Host supplies a fee, value or nonce that is internally consistent but wrong on chain | Partially mitigated | Fee caps and ownership checks catch classes of abuse, not a wrong UTxO value; the phone is trusted for decoys, fees and change context |
| 3 | Replay of a previous approval or link frame | Mitigated | Review seals are single-use and expire; link frames carry a monotonic sequence and a per-frame MAC |
| 4 | Unpaired phone impersonates the paired one | Mitigated | Ed25519 identity keys pinned at pairing; a different key is refused |
| 5 | Thief brute-forces the PIN | Partially mitigated | PBKDF2-SHA256, 120000 iterations + exponential backoff. An attacker who dumps NVS can attack the verifier offline at full speed |
| 6 | Thief reads the seed from flash | Out of scope today | Device builds refuse to store a seed at all; when SE custody lands, the seed must never be in MCU flash |
| 7 | Firmware replacement | Board 7 requires verified boot for wallet operations | Its diagnostic SDK disables Secure Boot and Flash Encryption. Production provisioning and anti-rollback require hardware acceptance |
| 8 | Panel or SE bus access | Panel SPI has no cryptographic integrity. SCP03 protects authenticated SE commands and responses | Real-card provisioning and production custody over SCP03 are unverified |
| 9 | Fault injection (voltage/clock glitch) on the MCU | Not mitigated | No glitch detector, no redundant control-flow checks, no certified MCU |
| 10 | Side-channel leakage from curve operations | Partially mitigated | Constant-time comparisons and a DRBG are used; the bignum code is not uniformly constant-time, and the SE is not a signing backend yet |
| 11 | Entropy source fails silently | Mitigated | Continuous health tests; a failed block latches the wallet closed for the boot |
| 12 | Parser memory corruption | Fixed buffers, length checks, sanitizer runs and deterministic mutation tests | Continuous coverage-guided fuzzing across parsers and link framing, and formal verification, remain open |
| 13 | NFC relay attack | Not mitigated | Frames can be relayed; the signature still needs a physical press on a display that shows the real recipient |
| 14 | Compromised link identity key in NVS | Partially mitigated | An attacker can impersonate the device to the phone; they cannot sign, because signing needs the PIN session and the display |
| 15 | Malicious supply chain (fake board, altered SE firmware) | Out of scope | The firmware cannot prove the silicon is genuine |
| 16 | Coercion | Out of scope | There is no duress PIN and no hidden wallet |
| 17 | Rollback to an old signed firmware | Out of scope unless the bootloader enforces anti-rollback | The app reports `running_from_ota_slot`; it does not prevent downgrade |

## Explicit non-goals

- **No node validation.** The device never talks to a network. It cannot know whether a UTxO exists,
  whether a decoy is real, whether a nonce is unused, or whether a contract is what its name says.
- **Multi-party protocols.** Bitcoin has P2WSH multisig script and digest primitives. Its spending adapter still needs multisig review and witness assembly. Beam has a single-input interactive CLI payment. Lightning channel state and revocation, Grin and general threshold protocols need separate adapters. [Supported chains](Supported-Chains)
- **No plausible deniability.** One wallet, one PIN.
- **No hardware certification.** Nothing here is evaluated to FIPS 140-3, CC EAL or any smart-card
  protection profile.

## Attack surface inventory

| Surface | Entry point | Validation |
| --- | --- | --- |
| Serial CLI | `WalletCli.cpp` | length-bounded command buffer, hex decoders with exact lengths, authenticated session for everything that touches keys |
| USB APDU | `UsbApduFrame.h`, `WalletNfcApdu.cpp` | ISO 7816-4 framing, maximum fragment size, abort clears partial state |
| NFC | `WalletNfcPort.cpp` | NCI framing, 1-byte length + PBF chaining, no pin guessing |
| Link | `WalletLink.cpp` | version byte, exact frame length, HMAC before parse, sequence monotonicity, 4096-frame and 3-minute session limits |
| Chain parsers | `*Transaction.cpp` | per-format length and canonicality checks, refusal instead of truncation |
| Secure element | `Se051Apdu.cpp`, `Se051Scp03.cpp` | SCP03 authentication before any command that changes state |
| Token metadata | `WalletCustomTokens.cpp` | user-declared records are labelled as declared; they never change the signed bytes |

## How to make this page shorter

The list above shrinks when, in order:

1. SE custody becomes real: key derivation and signing move behind handles, and the seed stops
   existing in MCU RAM.
2. Secure boot and flash encryption become the shipped default, with anti-rollback.
3. A fuzz harness covers the parsers and the link frame decoder in CI.
4. The panel and SE buses get integrity protection, or the threat is accepted in writing.
