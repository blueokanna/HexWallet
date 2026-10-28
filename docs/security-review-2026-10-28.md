# ESP32-P4 + SE051C2HQ1: safety changes and remaining requirements

This is a source review and test record, not a security certification or a claim
of parity with Ledger, Trezor, SafePal, Tangem or Coldcard. No physical board was
tested, provisioned or flashed; no real keys were imported and no funds moved.

## Custody boundary

The board port only probes an I2C response at 0x48. It has no authenticated
T=1/APDU/SCP03 session, identity/OEF verification, sealed seed storage or usable
non-exportable signing-key backend. `active_secure_element_profile()` remains
MCU-only and cannot be promoted by a profile setter.

The target description now reflects SE051C2HQ1. NXP's
[AN12973, Table 3](https://www.nxp.com/docs/en/application-note/AN12973.pdf)
lists ECDSA/Koblitz and standard Ed25519. This does not mean Cardano expanded
Ed25519-BIP32, NEM Keccak-Ed25519, Ergo Sigma, BLS or XMSS can use the same
signature engine. Those schemes are now classified separately. All current
software derivation paths expose seed/child material to MCU RAM.

`HEXWALLET_REQUIRE_SECURE_CUSTODY=1` is the P4 default. Until the backend exists,
session generation/import and seed/master loading fail with `CustodyUnavailable`;
outputs are cleared and secret export is disabled at the session owner. A
deliberate development override is a software wallet configuration, not SE custody.
This restriction is tested in a separately compiled production-policy executable.

## Admission and algorithm corrections

- DOT/KSM historical SCALE code is not an authenticated modern runtime decoder.
  Production signing is disabled; SS58 addresses remain. Only the host regression
  target enables the explicitly named historical codec gate.
- ERG signing is disabled because multiple outputs/tokens were not fully reviewed
  and fee/context semantics remain incomplete.
- XCH signing is disabled because host AGG_SIG_ME data was not bound to the
  displayed CREATE_COIN outputs. Device address derivation is also blocked:
  current G1/G2 secret arithmetic uses variable-time MPI operations.
- Qubic's old Ed25519/SHA3 substitute cannot produce native FourQ/K12 identities.
  It now fails rather than returning a plausible-looking address. See the
  [Qubic technical whitepaper](https://whitepaper.qubic.org/file/qubic-whitepaper.pdf).
- QRL legacy XMSS public derivation is compared against qrllib. Index zero
  preserves the original v1 wallet tree; nonzero tree indices use a separate v2
  domain. Older builds ignored nonzero indices, so those paths recover at zero.
  No OTS reservation persistence or signing is implemented. Pure numeric
  high-water helpers do not prevent rollback or seed-restore index reuse.
- EVM signing failures now clear the caller's output range, including a partial
  serialization failure. Tampering/capacity regressions cover this behavior.
- Hive transfer serialization includes only transaction extensions; the compact
  signature is header followed by r/s. STM public keys are not receive addresses.
- CLVM reserves the zero sentinel plus its full node capacity and validates arena
  bounds before traversal. These parser repairs do not enable Chia signing.

## Trusted display and transport

Receive screens show the complete address and derivation path with wrapping.
Catalog descriptions no longer truncate capability limitations; account signing
does not imply a derived deposit address. Fee text wraps on small panels.
Single-address CLI and token-account requests now use the device address screen.

USB CLI, NFC signing, receive-address requests and phone pairing are mutually
excluded while another review owns the display. Production CLI cannot confirm
phone pairing; it requires the local UI decision. Embedded NUL coin identifiers
are rejected. Displaying an address is not proof that the user has compared it,
and this patch does not claim a separate physical address-approval handshake.

There is still no verified P4 display/touch board port. The default is HEADLESS,
which cannot approve signing. Existing S3 display profiles compiling successfully
does not validate P4 wiring or actual pixels on a device.

## Required hardware acceptance

Still required: exact P4 board schematic and panel/touch/controller pins, NXP SDK
integration, device identity and applet/OEF checks, authenticated provisioning,
per-device SCP03 keys, key policies, sealed storage and recovery design, verified
boot/flash encryption/debug policy, fault/side-channel testing, loss-of-power and
rollback tests, watchdog/stack/RAM benchmarks and physical display/input tests.
Never supply seed phrases, private keys or SCP03 secrets in chat or logs.

A software signature test does not demonstrate that an MCU key can never leak.
MCU algorithms need a reviewed implementation and hardware threat assessment;
they cannot inherit SE certification merely because a SE051 is on the board.
