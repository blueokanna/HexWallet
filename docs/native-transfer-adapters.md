# Native transfer adapters: precise scope and verification

These are offline codecs/signers, not a network synchronization or broadcast
client. The production P4 target cannot load a wallet until secure custody is
implemented. A successful host signature is not a successful hardware or mainnet
test. All fixture seeds are public test inputs and must never receive funds.

| Route | Accepted operation | Key/address and signed output | Explicit exclusions |
|---|---|---|---|
| `xem`, chain kind 14 | NIS mainnet native transfer v1, printable memo up to 64 bytes | SLIP10 `44'/43'/0'/0'/index'`, Keccak-Ed25519, NEM address/checksum, 64-byte signature over full raw body | Mosaics, multisig, encrypted messages, Symbol; no broad restore-compatibility claim |
| `hive`, chain kind 14 | One transfer of HIVE or HBD, printable memo up to 64 bytes | secp256k1 `44'/3054'/0'/0/index`, `header+r+s` compact signature with canonical scalars | `STM…` is an active public key, NOT a receive account; host must check account authority and reference block; no encrypted memo |
| `sc`, chain kind 14 | Sia v2 PolicyPublicKey, one input, one recipient and optional owned change | Wallet-specific hardened SLIP10 `44'/1991'/0'/0'/index'`; v2 policy address, Ed25519 signature | No legacy seed import equivalence, contracts, tokens, multiple inputs; node must verify parent value, state proof and maturity |
| `icp`, chain kind 14 | `transfer` on `ryjl3-tyaaa-aaaaa-aaaba-cai`, default subaccount | Hardened SLIP10 `44'/223'/0'/0'/index'`, Ed25519 SPKI principal, ICP account ID, complete signed CBOR call | No arbitrary canisters, ICRC tokens, staking or Ledger secp256k1 restore compatibility; node checks ingress freshness and ledger state |
| `flow-evm`, EVM route | EIP-155 native FLOW transfer, chain 747, 18 decimals | Standard EVM `44'/60'/0'/0/index`, signed legacy RLP | Not Flow Cadence accounts or transactions; no blanket contract support |
| `eth-lsk`, token on `eth` | Registered ERC-20 `transfer` on Ethereum | Contract `0x6033F7f88332B8db6ad452B7C6D5bB643990aE3f`, 18 decimals; gas is ETH | Not old Lisk L1 transaction support or a claim that LSK is an EVM native gas asset |

Flow network values follow [Flow's official network page](https://developers.flow.com/build/evm/networks).
The LSK contract follows [Lisk's import guide](https://docs.lisk.com/guides/import-lsk/).
No live RPC call or funds movement is part of these tests.

## Compact transport payloads

`SCV2` uses integers in little endian:
`magic[4] | parent_id[32] | input_value_u128[16] | parent_policy_address[32] |
output_count_u8 | outputs{value_u128[16], address[32]} | miner_fee_u128[16]`.
Count is 1 or 2; the second output must return to the derived address. Values
must balance exactly. The signature follows Sia v2 input semantics; the full
transaction still requires parent state/proof data assembled and validated by
the host/node. SC uses 24 decimal places; the local maximum fee is 10 SC.

`ICP1` is exactly 76 bytes:
`magic[4] | destination_account[32] | amount_u64 | fee_u64 | memo_u64 |
created_at_time_ns_u64 | ingress_expiry_ns_u64` (integers little endian).
Destination CRC32 is checked, fee is pinned to 10,000 e8s, amount is positive,
and expiry must be after creation by at most 300 seconds. No authenticated
device clock is claimed. The canister, method, default subaccount and Candid
type table are fixed by firmware. The signature is over
`0x0a || "ic-request" || representation_independent_request_id`.

NEM accepts the raw serialized NIS body, including the signer and checked
recipient address. Hive's `HIV1` layout is in [chain-signing.md](chain-signing.md).

## Reproducible evidence

- `tests/reference/generate_native_remaining.cjs`: NEM SDK 1.6.11,
  dhive 1.3.6 and Sia Foundation SDK 0.5.0, 18 positive and 13 rejection fixtures.
  Hive signature validity, canonical form and recovered key are independently checked.
- `tests/reference/generate_icp_vectors.cjs`: ICP SDK core 6.1.1 and canisters
  4.0.0; 6 positive and 6 rejection fixtures. Decodes the returned CBOR and Candid,
  recomputes the request ID and compares the SDK signature and SPKI bytes.
- `tests/reference/generate_flow_lsk.cjs`: ethers 6.15.0; 6 positive and 6
  wrong-network fixtures. Parses the signed RLP and recovers the sender.
- `tests/reference/generate_qrl_vectors.cjs`: qrllib 1.3.2; 7 legacy XMSS public
  key/address cases, including preservation of the old zero-index tree. No signer.
- Python tests run these pinned fixtures through the real Mbed TLS firmware
  harness and reject altered reviews, hashes, payloads, indices and short buffers.
  The separate `production_policy` executable omits all host-only legacy gates.

The independent SDK generators have been run locally. New CI steps reproduce
them; this document does not claim a remote CI run has occurred.
