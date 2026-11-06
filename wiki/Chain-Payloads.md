# Chain payloads

[中文](Chain-Payloads-zh) · [Home](Home)

How a host hands a transaction to the device, and what comes back. Everything is hex on the CLI and
length-prefixed binary on the phone link; the parser is the same code in both cases.

## Zephyr, Alephium and Quantus

Zephyr uses phone link kind 5 with network ID `zeph`. Native ZPH inputs and tagged ZPH outputs are mandatory. Pricing height, burnt and minted amounts must be zero. The device verifies the prefix, BP+, ownership, change and CLSAG. The node checks UTXO state and ring membership. [Mainnet fixture](https://explorer.zephyrprotocol.com/tx/7e2f3d9d1b5deaf3db873d5fe5d6c54272d127a84aa04ddc18bd46e66a9a7c12)

Alephium accepts the SDK's mainnet P2PKH UnsignedTx bytes. Up to 16 inputs may use the same public key. One external recipient and optional wallet change are supported. The device rejects tokens, scripts, time locks, duplicate inputs and output messages, reviews the gas fee and returns a 64-byte low-S signature over the BLAKE2b-256 ID. [Official codec](https://github.com/alephium/alephium-web3/tree/c457e9f3959423b22ffa3e18dd0e14b1e26dcf20/packages/web3/src/codec)

Quantus accepts `call || extra || implicit` for mainnet spec 153 and transaction version 6. Balances transfers and keep-alive transfers are supported. The device reviews the account, amount, tip, nonce, era and checkpoint. The runtime calculates the base fee. The result is a complete, hedged ML-DSA-87 v4 extrinsic. [Official implementation](https://github.com/Quantus-Network/quantus-wasm/blob/04174ffca2e385ca64d45ee0c9523cc1dd36707d/src/ext.rs)

## Rules that apply everywhere

- The payload length must match exactly. Trailing bytes are an error, not padding.
- A payload the parser cannot fully validate is refused; nothing is truncated to fit.
- Limits: PSBT 4096 bytes (`HEXWALLET_MAX_PSBT_BYTES`), native adapter payload 2048 bytes
  (`kChainMaxPayload`), phone `BEGIN_SIGN` payload 16384 bytes.
- The device returns a signed transaction, never a bare signature, except where an adapter is
  defined that way (HIVE returns a 65-byte graphene signature, XRP returns the signed binary).
- Every value, fee and nonce is host-supplied. The device checks internal consistency and wallet
  ownership, not existence on chain.

## Beam

The authenticated serial CLI exchanges a 162-byte offer and a 902-byte receiver contribution. Both peers review their side on the trusted display. The sender returns a serialized Beam transaction after checking the payment confirmation, kernel signature and output balance. [Commands, scope and tests](Beam-zh)

## Xelis native accounts

English and Simplified Chinese recovery directly decodes the private scalar from 24 words and checks the optional 25th checksum word. The public key is `sk⁻¹·H`. The device command `xelis check-address <address>` validates the checksum and Ristretto point of an external mainnet address. The native Schnorr primitive has an independent signature vector. Production recovery, confidential balances and transfer proofs are pending. [Upstream recovery](https://github.com/xelis-project/xelis-blockchain/blob/db59b5c246ab0e40386d6c241dcd77f0aea84b10/xelis_wallet/src/mnemonics/mod.rs)

## Ethereum token approvals

The registered contract standard distinguishes ERC-20 allowance amounts from ERC-721 token IDs. Reviews identify the spender or operator and distinguish grants, unlimited allowances and revocations. The ENS Base Registrar and Name Wrapper were checked against the official deployment list and their ERC-165 interfaces at Ethereum block `0x1922794`. [ENS deployments](https://docs.ens.domains/learn/deployments/)

## Quai account transfers

`quai` accepts mainnet Cyprus-1 type 0 transfers. Supply the actual child index selected by quais.js for this zone. The device derives `m/44'/994'/0'/0/index` and checks that both addresses belong to the local Quai account ledger.

Submit the bytes of go-quai's `ProtoEncodeTxSigningData` with type, to, nonce, value, gas, data, chain_id, gas_price and access_list in field-number order. Type is 0 and chain_id is 9. Encode data and access_list as present, empty fields. Value and gas_price are minimal positive big-endian integers. The device displays the amount, nonce, gas limit, price and maximum fee. Approval returns 65 bytes of `r || s || yParity` for assembly by the host.

[go-quai](https://github.com/dominant-strategies/go-quai/blob/5917bf5e2ced1d3f1cafdde6bc6fa3345fb71c3e/core/types/transaction.go) · [Cyprus-1 type 0](https://quaiscan.io/tx/0x00060019fdf877647e4a9bab684b0c51732b590cb0ffebc058fb29702fe87f97)

## Bitcoin PSBT

`tx inspect [<coin>] <psbt-hex>` accepts PSBT v0 (BIP174) and v2 (BIP370). Global, input and output
maps are parsed with per-key rules; unknown proprietary keys are ignored, but a key that claims a
known type with the wrong length is a hard error. Inputs must commit to a wallet-owned UTXO through
`witness_utxo` or `non_witness_utxo`, and the derived script must match the wallet.

`tx sign <code>` returns a PSBT with the signatures merged in, so a coordinator can keep adding
signers. Signature types honoured: legacy, BIP143 and Taproot key-path; sighash `ALL`, plus
`SIGHASH_DEFAULT` for P2TR.

## EVM

`evm inspect <network> <index> <unsigned-rlp-hex>` takes an unsigned RLP envelope: legacy
(`nonce, gasPrice, gas, to, value, data, chainId, 0, 0`), EIP-2930 (type `0x01`) or EIP-1559
(type `0x02`). The `chainId` must match the network profile, or the request is refused before any
signing.

The review shows `to`, `value`, `gas`, the fee ceiling, and either a decoded registered token call or
the full calldata with its keccak-256. Contract creation shows the address it will produce.
`evm sign <code>` returns the signed RLP plus `tx-hash`.

There is no "trusted token list on the host" path: a token is decoded only if its contract is
registered in the firmware or declared by the user on the device.

## Kaspa

`kaspa inspect <payload-hex>` takes a compact review struct; all integers little-endian:

```text
u16 version
u64 lock_time
u8  payload_size + payload
u8  input_count
input_count * {
      txid[32], u32 index, u64 sequence, u64 value,
      u16 script_version, u8 script_size + script,
      u32 account_index, u8 change, u32 address_index,
      u8 sigop_count }
u8  output_count
output_count * { u64 value, u16 script_version, u8 script_size + script }
```

Each input carries the value and script of the prevout it spends, so the device can recompute the
fee and the KIP-0009 masses without a node. `kaspa sign <code>` returns the signed v0 transaction.

## Zcash

`zec inspect <payload-hex>` accepts two magics, `ZEC4` and `ZEC5`; integers little-endian:

```text
"ZEC4" | "ZEC5"
u32 branch_id
u32 unsigned_transaction_size
unsigned v4 transaction bytes        (every scriptSig must be empty)
u8  input_count                      (must equal the transaction's vin count)
input_count * {
      u64 value, u8 script_size + scriptPubKey,
      u32 account, u8 change, u32 address_index,
      [u8 redeem_size + redeem script]     // ZEC5 only, zero for P2PKH
    }
```

`ZEC4` cannot carry a P2SH prevout. `ZEC5` adds exactly one redeem record per input; the device
re-hashes it against the t3 address and accepts only a single-key `CHECKSIG` script. The payload
must end after the last input record. `zec sign <code>` returns the signed v4 transaction.

## CryptoNote (Monero)

`kind=5` on the phone link, or the CryptoNote path behind `BEGIN_SIGN`:

```text
u8  version = 1, 2 or 3
u16 tx_len
u8[] tx                      serialized unsigned transaction (RCT type 6)
u8[32] tx_secret             R = rG for standard, R = rD for a single subaddress
if version >= 3:
  u8   additional_tx_key_count
  u8[32] additional_tx_secret[count]
u8 input_count
u8 output_count
u8 flags                     reserved; must be zero
input[input_count]
output[output_count]
```

Each input record:

```text
u64 amount, u16 real_index, u16 ring_size, u8[32] original_tx_public,
u64 output_index, u8[32] pseudo_out_mask, u32 subaddress_major,
u32 subaddress_minor,
ring_size * u64 ring_offsets,
ring_size * { u8[32] dest, u8[32] mask }
```

Each output record:

```text
u8 out_flags (bit0 change, bit1 subaddress), u8[32] spend_public,
u8[32] view_public, u64 amount, u32 subaddress_major, u32 subaddress_minor,
[u8[32] mask]                // only when header flags bit0 is set
if version >= 3: u8 tx_key_index
```

`tx_key_index` belongs to the output record and must appear immediately after that record's `mask`;
it is 0 for the main transaction key and `i+1` for the i-th additional key. Device limits: XMR 8
inputs / 16 outputs, ring size 16, serialised transaction 6144 bytes; anything larger is
`unsupported`, never truncated.

## Native adapters (`chain begin`)

```text
chain begin <network> <index> <payload-hex>
chain sign <code>
chain reject
```

The envelope is defined per adapter, and the header next to the parser is the specification:

| Family | Payload convention |
| --- | --- |
| SUI | raw BCS `TransactionData`; returns 97 bytes: flag, signature, public key |
| FIL | raw CBOR `Message`; returns a complete signed CBOR message |
| ADA | raw Conway body CBOR; returns `[body, witness_set, true, null]` |
| DOT / KSM | `DOT2` payload with short-lived era and tip; returns a v4 signed extrinsic |
| XRP | 50-byte Payment review struct; returns the signed binary |
| THETA | 46-byte native `SendTx`; the same network id also serves EVM transfers |
| DASH | `DAS2`/`DAS3` review payload; see below |
| VET / ICX / TON / DCR / CKB / HIVE / SOL / TRX / XLM / XRP / ATOM… | family-specific compact struct, magic-prefixed where documented in `<Name>Transaction.h` |

`chain_sign_transaction()` re-runs the review and compares it with the stored one field by field
before signing. If the payload and the review disagree, nothing is signed.

## Dash

`DAS2` and `DAS3` differ by one trailing byte; both carry every input's funding transaction, which
is what makes the reviewed input amounts real rather than host text.

```text
"DAS2" | "DAS3"
u32 lock_time
u8  input_count
input_count * { u8[32] previous_txid, u32 previous_index, u32 sequence,
                u64 value, u8 script_size + script,
                u32 account, u8 change, u32 address_index }
u8  output_count
output_count * { u64 value, u8 script_size + script }
input_count * { u16 funding_size, funding_transaction }
u8  flags                     // DAS3 only; DAS2 implies 0
```

`flags` bit 0 declares InstantSend intent. Any other bit is refused with `unsupported`: a host
asking for behaviour the firmware does not implement has to learn that before review, not after.

Each funding transaction must be a type-0 Dash transaction whose double-SHA256 equals
`previous_txid`, with the output at `previous_index` paying exactly `value` to exactly `script`.
A mismatch is `WrongWallet`. The device then recomputes the fee from proven values, so a host
cannot inflate an input to bury a fee.

The legacy `DASH` payload has no funding proofs. It still parses, so an old host gets a precise
`missing-field`, and it can never be signed.

### InstantSend

InstantSend adds no bytes to a transaction: an LLMQ quorum locks the inputs after the signed bytes
exist. There is nothing for the device to sign and nothing it could check. So the claim is handled
as exactly that — a claim:

- with bit 0 set, the trusted screen says the host requested InstantSend, that the lock is a
  quorum decision made after broadcast, and that an unlocked transaction is not confirmed;
- the flag lives inside the hashed payload, so a phone cannot add or drop it after the device
  rendered the review;
- the signed bytes are identical with and without the flag, which is asserted by a test. A review
  flag must never be able to change what is broadcast.

The firmware never reports a Dash transaction as locked, confirmed or final.

## Status codes over the link

`0` ok · `1` pending · `2` rejected · `3` unknown-coin · `4` invalid · `5` expired ·
`6` unsupported · `8` not-approved · `9` locked · `10` fee-policy.

`7` is retired and never returned. A refusal never returns partial output.
