# SE051C2HQ1 custody backend: what is shipped, what is missing

Status: **no backend is registered, so `secure_element_ready()` is false and the
wallet cannot claim secure-element custody.** This page exists so the gap is a
plan with acceptance criteria instead of a claim.

The reference implementation most people reach for is NXP's
[Plug & Trust middleware](https://github.com/NXP/plug-and-trust). It is
separately licensed, it is not vendored in this repository, and its host stack
is far larger than this firmware's entire crypto layer. Nothing below copies it;
the goal is a small, auditable backend that satisfies the same wire protocol.

## What landed

`SecureElementPort.h/.cpp`:

| Piece | Verified by |
| --- | --- |
| ISO/IEC 7816-3 CRC16/A (poly 0x1021, init 0xFFFF) | check value `0x29B1` for `"123456789"` |
| AES-128 forward cipher | FIPS-197 C.1 (`69c4e0d8…b4c55a`) |
| AES-128-CMAC | RFC 4493 §4, all four message lengths |
| Backend contract + gate | host self-tests: unregistered, incomplete, unauthenticated and authenticated paths |

The gate is the part that matters for custody:

- A backend must supply **all** of open, session_authenticated, sign_digest,
  public_key and close, or registration fails.
- Only one backend may be registered per boot.
- If `open()` returns success while `session_authenticated()` is false, the
  backend is **unregistered** and the gate stays closed. This is the exact shape
  of "the card answered but the static keys were wrong", and it must never
  produce a usable custody state.
- `active_secure_element_profile()` returns the SE051C2HQ1 profile only while a
  backend reports an authenticated session, so a profile setter cannot promote
  hardware custody (there is a regression test for that in
  `tests/host/chain/production_policy.cpp`).

## What is deliberately not written yet

| Missing piece | Why it is not here | Accept criteria |
| --- | --- | --- |
| SCP03 key derivation and ICV layout | The derivation-data layout and the command/response ICV conventions have to be validated against the licensed reference implementation or a real card; guessing them would produce a channel that looks right and fails in the field | Golden values for `INITIALIZE UPDATE` + `EXTERNAL AUTHENTICATE` from GPC's own test vectors or from a captured session on the target applet |
| T=1 over I2C framing | NAD/PCB/LEN conventions and the EDC mode are interface-profile facts for this part, not something I can assert from memory | Loopback test on the board: `t1_encode` → card → `t1_decode`, plus abort/resync paths |
| Applet command set (key generate, sign, delete) | This is the NXP applet's private API, not a public spec | Object IDs, key policy, access rules and the exact sign command documented and exercised on hardware |
| Provisioning and SCP03 static keys | Per-device secrets; must never be in git, in chat or in a build log | Factory step with a sealed key store, `HEXWALLET_REQUIRE_SECURE_CUSTODY=1` build, and a provisioning log that records only key IDs |
| Anti-rollback / sealed seed storage | Needs the applet's secure counter and file system | Test that a restored seed cannot reuse a QRL leaf index and that a wiped MCU cannot recover the seed from the card |

Until every row is done, the shipped, tested position stays what the security
review says: MCU-only derivation, `HEXWALLET_REQUIRE_SECURE_CUSTODY=1` refuses
session generation/import, and no coin capability is promoted.

## Wiring a backend (when the parts exist)

1. Implement `SecureElementBackend` in a new translation unit, e.g.
   `se051_backend.cpp`. Keep the static SCP03 keys in a sealed store, never in
   `constexpr` arrays that end up in flash images.
2. `open()` must: power/reset the card, read ATR, `INITIALIZE UPDATE`, verify
   the card cryptogram, `EXTERNAL AUTHENTICATE`, require `0x9000`. Return a
   short ASCII reason otherwise.
3. `session_authenticated()` must re-check the channel, not cache a bool set at
   open time, so a card reset or a failed MAC invalidates it.
4. `sign_digest()` must reject digests the applet policy does not allow, and
   must never return a signature when the card's status word is not `0x9000`.
5. Call `secure_element_register_backend(&backend)` exactly once during boot,
   before `secure_custody_backend_ready()` is consulted.
6. `run_secure_element_self_tests()` must keep passing, and the production
   policy binary must still refuse to open a session without the card.

## Field rules

- The card is the only secret store. The MCU never persists a seed when a
  backend is registered; `HEXWALLET_ENABLE_SECRET_EXPORT` is already forced to 0
  next to `HEXWALLET_REQUIRE_SECURE_CUSTODY`.
- No network code exists in the firmware, and `tests/test_asset_coverage.py`
  fails the build if a WiFi/HTTP/TLS header appears. Transaction data reaches
  the device only through the local USB serial CLI or the NFC phone link.
- Every signing decision is shown on the trusted display first. A card that
  signs whatever it is handed is not a hardware wallet; the review layer is what
  makes the SE useful, and it stays in MCU flash.
