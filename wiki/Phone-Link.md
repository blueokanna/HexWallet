# Phone link

[中文](Phone-Link-zh) · [Home](Home)

The phone starts every operation. The wallet reviews, authorizes and signs; it never builds a
transaction and never talks to a node. Protocol version is **2**; a v1 peer and a v2 device must
fail, because the ephemeral exchange changed from Ed25519-group ECDH to Curve25519 and would derive
different keys from the same transcript.

## Transport

| Transport | Default | How it is enabled |
| --- | --- | --- |
| NFC, PN7161 in card-emulation mode | board pins decide | `HEXWALLET_NFC_PN7161` plus `HEXWALLET_NFC_PIN_*` in the board profile |
| USB CDC, APDU-framed | **off** | long-press BOOT/user button for 3 s; closes on second press, lock, or after `HEXWALLET_USB_ENABLE_WINDOW_MS` (10 min) |

While USB data is closed the firmware discards serial input, including bytes already buffered. ROM
download mode is unaffected. USB and NFC carry the same APDU and link protocol, so the phone
implements it once.

### APDU mapping (ISO 7816-4)

| Command | CLA INS P1 P2 | Data | Reply |
| --- | --- | --- | --- |
| SELECT | `00 A4 04 00` | `06 F0 48 57 4C 4B 31` | `F0 <version>` + SW |
| WRITE | `80 10 <last> 00` | frame fragment | `last=1` processes the assembled frame |
| READ | `80 11 00 00` | none | up to 240 bytes, `SW=61xx` means more |
| ABORT | `80 12 00 00` | none | drops fragments and any buffered reply |
| STATUS | `80 13 00 00` | none | fragment/reply lengths, session and pairing flags |

USB wraps an APDU as `A5 5A <len_lo> <len_hi> <apdu…>`.

## Frame format

```text
"HWLK" | version(1)=2 | type(1) | 0 | 0 | session_id(4) | sequence(4)
       | payload_len(2) | payload | [tag(32)]
```

All integers are little-endian. `tag` is HMAC-SHA256 over the header, nonce and ciphertext, and is
present only on Request/Response frames. A length that does not match exactly is a rejection.

| type | Name | Direction |
| --- | --- | --- |
| 0x01 | PairRequest | phone → device |
| 0x02 | PairResponse | device → phone |
| 0x03 | HelloRequest | phone → device |
| 0x04 | HelloResponse | device → phone |
| 0x10 | Request (encrypted) | phone → device |
| 0x11 | Response (encrypted) | device → phone |

## Pairing (one time)

```text
PairRequest.payload  = PK_phone(32) | nonce_phone(32) | sig(64)
sig = Ed25519(sk_phone, "HWLK1-PAIR" | PK_phone | nonce_phone)
```

The device verifies the self-signature, refuses a second, different phone key, and — if it is not
paired yet — shows a 6-digit code on the trusted display. The code is the first 3 bytes of
`SHA256("HWLK1-PAIR-CODE" | PK_phone | PK_dev)`. Nothing is returned until the user presses APPROVE;
the same request only yields `pending-pairing`. The prompt expires after 60 seconds.

```text
PairResponse.payload = PK_dev(32) | nonce_phone(32) | nonce_dev(32) | sig(64)
sig = Ed25519(sk_dev, "HWLK1-PAIR-RESP" | PK_phone | PK_dev | nonce_phone | nonce_dev)
```

The phone pins `PK_dev` (TOFU plus fingerprint comparison) and must warn if it changes.

## Session handshake

```text
HelloRequest.payload  = PK_phone | PK_phone_eph | nonce_phone | sig(64)
sig = Ed25519(sk_phone, "HWLK1-HELLO" | PK_phone | PK_phone_eph | nonce_phone)
HelloResponse.payload = PK_dev | PK_dev_eph | nonce_dev | sig(64)
sig = Ed25519(sk_dev, "HWLK1-RESP" | PK_phone | PK_phone_eph | nonce_phone
                       | PK_dev | PK_dev_eph | nonce_dev)

transcript = "HWLK1-SESSION" | PK_phone | PK_phone_eph | nonce_phone
                            | PK_dev   | PK_dev_eph   | nonce_dev
hash       = SHA256(transcript)
scalar     = SHA512(seed_eph)[0..31]          // pre-key, not clamped here
shared     = X25519(scalar, peer_eph)         // RFC 7748 clamps internally
keys       = HKDF-SHA256(ikm=shared, salt=hash, info="HWLK1-KEYS", 64)
key_c2d    = keys[0..31]
key_d2c    = keys[32..63]
session_id = LE32(hash[0..3])
```

Identity keys stay Ed25519; only the ephemeral exchange is X25519. Each frame uses one direction
key and a 12-byte nonce: `session_id(4) | direction(1) | sequence(4) | 00 00 00`. Encryption is
ChaCha20 from counter 0, authentication is HMAC-SHA256 (encrypt-then-MAC).

The device enforces: matching `session_id`, strictly increasing `sequence`, immediate session
destruction on any authentication failure, 3 minutes of inactivity, and a 4096-frame session cap.
A lost SELECT or a missing fragment discards the partial frame.

## Application layer

```text
Request.payload  = request_id(4) | opcode(1) | arguments…
Response.payload = request_id(4) | status(1) | data…
```

| opcode | Name | Arguments | Reply |
| --- | --- | --- | --- |
| 0x01 | PING | — | — |
| 0x02 | INFO | — | version, flags (unlocked, review pending, session, pairing pending) |
| 0x03 | CATALOG | offset(2), limit(1) | total, offset, count, entries {id, symbol, caps} |
| 0x04 | ADDRESS | coin, account, change, index [, subaddress major/minor] | address, path |
| 0x05 | BEGIN_SIGN | coin, kind, address_index, payload | review_id(8) |
| 0x06 | RESULT | review_id(8) | `pending`, or status + length + signed transaction |
| 0x07 | CANCEL | review_id(8) | rejected |

`kind` selects the parser: 1 UTXO/PSBT, 2 EVM, 3 Kaspa, 4 Zcash, 5 CryptoNote (XMR), 6 Solana,
7 TRON, 8 Cosmos, 9 Stellar, 10 Algorand, 11 NEAR, 12 Tezos, 13 XRP, 14 Chain (VET, ICX, TON, DCR,
CKB, ADA, HIVE, SUI, FIL, DOT, KSM), 15 Dash. `BEGIN_SIGN` accepts up to 16384 bytes; anything
larger is `invalid`, never truncated. The review expires after 120 seconds.

Address derivation and signing need an unlocked wallet session. Unlock happens over the USB CLI
(`auth begin`, `auth unlock`); the link itself never carries a PIN. `ADDRESS` never returns a private
key, and adapters whose key generation is too expensive for the link are refused there.

## What the link protects

- A replaced phone: refused, the pinned key does not match.
- A forged handshake: both sides sign the transcript with Ed25519 identity keys.
- Replay, reordering, tampering: monotonic sequence, encrypt-then-MAC, session destruction on failure.
- Signing without a user action: impossible, the signature needs the on-device approval.

## Known limits

1. Identity keys and the pinned phone key live in NVS, not the secure element. A leaked identity key
   allows impersonating the device to the phone; it cannot sign.
2. There is no distance bounding. An NFC relay can forward frames; the signature still requires a
   physical press on a screen showing the real recipient.
3. The pairing code is 6 decimal digits plus the key fingerprint; compare both.
4. The PN7161 driver follows NCI CORE_RESET / CORE_INIT / RF_DISCOVER_MAP / RF_DISCOVER (NFC-A
   passive listen, 106 kbps) and has **not** been validated on hardware. Verify it with an EVK and a
   reader before trusting it.
5. Boards without a display never review over the link. There is no fallback to host confirmation.
