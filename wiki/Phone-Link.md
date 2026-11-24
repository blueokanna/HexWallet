# Phone link

[中文](Phone-Link-zh) · [Home](Home)

The phone starts every link operation and submits signed transactions to the node. The wallet parses or reconstructs the transaction according to its adapter, shows it for local approval and signs. Protocol version is **2**. A v1 peer and a v2 device must
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
Request.payload  = opcode(1) | request_id(4) | arguments…
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

For Ryo, omitting the optional subaddress pair preserves the legacy mapping from account and index. Explicit `(0, 0)` selects the standard address of that BIP32 child. When those choices give different addresses, the explicit standard address has `+0/0` in its displayed path. Zano uses a standard address at every BIP32 child and rejects a nonzero subaddress pair. An address request fails if its complete path exceeds the display field.

The release catalog exposes addresses for both currencies. The `TEST_RYO_PHONE_PAYMENTS=ON` host probe also accepts `BEGIN_SIGN` for `ryo`, kind `5`, with one external long standard address and optional change. Its 16-byte application header leaves 16,368 bytes for the payment. The payload contains version `1`, a little-endian 16-bit unsigned transaction length, the transaction bytes, a 32-byte transaction secret, the recipient's public spend and view keys, and one funding record per input. Each record contains the 16-bit real ring position, 64-bit funding output number, funding public key, 64-byte ECDH data, pseudo-output mask and the ring members. Each member consists of a 64-bit absolute output index, destination key and commitment.

The phone verifies input ownership and signed key images. The device checks the recipient, change, fee and full payment ID before enabling local approval. The fee cap is 0.1 RYO. `RESULT` returns the signed bytes once. The phone verifies them against the reviewed transaction and checks the mainnet genesis hash before broadcast. The private-fork test submits separately and a stock view-only wallet scans both receipts. [Receipts](validation)

The Zano host probe accepts an ordinary v4 native payment with one or two inputs, 16 members per ring and two outputs. It checks input ownership, reconstructs both outputs and displays the recipient, amount, change, fixed 0.01 ZANO fee and eight-byte payment ID. An exact spend splits the amount between two outputs to the same recipient. After one-time approval the phone verifies each CLSAG_GGX and all payment proofs. Its broadcast helper checks the mainnet genesis. The test harness submits to a private testnet. [Receipts](validation)

For Ethereum and Solana, encode `BEGIN_SIGN` arguments as `coin_length(1) | coin ASCII | kind(1) | address_index(4 LE) | payload_length(2 LE) | payload`. Ethereum (`eth`, kind 2) takes the unsigned EIP-155, EIP-2930 or EIP-1559 serialization. Mainnet Lido `submit(address)` and Uniswap V2 Router02 `swapExactETHForTokens` have dedicated reviews. Solana (`sol`, kind 6) takes serialized legacy or v0 **message** bytes with one signer and static accounts. The stake operations delegate or deactivate an existing stake account.

Classic swaps use the 10-account layout deployed by SPL Token Swap on devnet (`SwapsVeCiPHMUAtzQWZw7RjsKjgCjhwU55QGu4U1Szw`) and Orca V2 on mainnet (`9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP`). Supply the pool, pool authority, payer as transfer authority, source token account, input vault, output vault, destination token account, pool mint, fee account and classic SPL Token program, in that order. The review shows the account addresses, input and minimum output in raw units. The phone must resolve the two vaults on the intended cluster to identify the input and output mints. The 14-account Token-2022 layout and an extra host fee account are unsupported. [SPL deployments](https://spl.solana.com/token-swap) · [Orca SDK](https://github.com/orca-so/typescript-sdk)

Keep the authenticated link connected during review. Send `RESULT` with the eight-byte review ID until the device returns a terminal status. On success, send the returned signed transaction bytes to `eth_sendRawTransaction` or base64-encode them for Solana `sendTransaction` with `encoding: "base64"`. The phone checks the intended network, nonce or recent blockhash, and tracks the RPC receipt or signature status. Losing the NFC field clears the approval.

Install the adapter's pinned dependencies with `npm ci --prefix tools --ignore-scripts`. `tools/phone_broadcast.cjs` accepts `unsigned` from `BEGIN_SIGN`, `signed` from `RESULT`, and an `rpc(method, params)` callback that returns the JSON-RPC result. `broadcastEthereum` also takes the verified `sender` and `chainId`. `broadcastSolana` takes the verified `payer` and the intended cluster's `genesisHash`. Each returns the node-accepted transaction ID. Use `eth_getTransactionReceipt` or `getSignatureStatuses` to track inclusion and execution.

`kind` selects the parser: 1 UTXO/PSBT, 2 EVM, 3 Kaspa, 4 Zcash, 5 CryptoNote (XMR), 6 Solana,
7 TRON, 8 Cosmos, 9 Stellar, 10 Algorand, 11 NEAR, 12 Tezos, 13 XRP, 14 Chain (VET, ICX, TON, DCR,
CKB, ADA, HIVE, SUI, FIL, DOT, KSM), 15 Dash. `BEGIN_SIGN` accepts up to 16384 bytes; anything
larger is `invalid`, never truncated. The review expires after 120 seconds.

Kind 15 takes a `DAS2` or `DAS3` payload. Both must carry every input's funding transaction; `DAS3`
adds one flags byte whose bit 0 declares InstantSend intent. The device shows that declaration, says
the lock is a quorum decision it cannot verify, and produces the same signed bytes either way. See
[Chain-Payloads](Chain-Payloads#dash).

Address derivation and signing need an unlocked wallet session. Unlock happens over the USB CLI
(`auth begin`, `auth unlock`); the link itself never carries a PIN. `ADDRESS` never returns a private
key, and adapters whose key generation is too expensive for the link are refused there.

## Ethereum DApp connection

The phone creates one `createEthereumConnection({origin, approveOrigin, exchange, rpc, index})` from `tools/ethereum_provider.cjs` per authorized top-level HTTPS document. Obtain the origin from the wallet browser and check the calling frame on every bridge request. Keep the transport, permission prompt and RPC in the wallet. Expose the returned `provider` to the page through EIP-1193 and `announceEthereumProvider` through EIP-6963. `eth_requestAccounts` requests the device address at `m/44'/60'/0'/0/index`. `eth_sendTransaction` separately requires local review. This adapter is bound to Ethereum chain ID 1.

On navigation, field loss or lock, call `disconnect()`, close the paired session and remove the announcement listener. The bearer must honor the abort signal passed to `exchange`. A signed result is checked against the approved bytes, account and RPC chain before submission. The Chromium tests drive the firmware application callback with a public test seed. Physical phone pairing and SE051 signing await hardware acceptance. [Test evidence](validation)

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
