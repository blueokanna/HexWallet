# Admission policy

[中文](Admission-Policy-zh) · [Home](Home)

The rule is simple and it is enforced by review: **a `SIGN` row without a reproducible test is a
lie and gets reverted.** Everything else here is how that rule is applied.

## What a capability bit means

| Bit | Requirement |
| --- | --- |
| `address` | deterministic derivation, an encoder checked against independent vectors, and a test that pins them |
| `review` | a parser that reaches every field which changes the signed bytes, and refuses anything it cannot render in full |
| `sign` | the exact digest the chain verifies, produced from the reviewed payload, with a passing vector or an independent implementation agreeing byte for byte |
| `token-account` | a registry of contracts with a reviewed calldata subset; unknown calldata is shown as raw bytes |

A chain can be `address` only. That is a legitimate, documented state: Aeternity, RyoCurrency and
Zano are there today. What is not allowed is `sign` with a hand-written table and no test behind it.

## The gate, in order

1. **Upstream source pinned.** Consensus code or `chainparams` at a specific commit, quoted in
   `tools/fork_registry.json` for UTXO forks, or in the adapter's comments for native chains.
2. **A coin type.** SLIP-0044 must assign one. Borrowing another chain's coin type would derive the
   same key material for two domains, so a chain without one stays out entirely.
3. **Address encoding with vectors.** Either an upstream vector file or a second implementation that
   agrees byte for byte. Bech32m, cashaddr, CryptoNote prefixes and EIP-55 casing all get their own
   negative tests.
4. **Transaction format and digest.** Legacy sighash, BIP143, `SIGHASH_FORKID`, ZIP-243, BCS, CBOR,
   SCALE, protobuf — whichever it is, the repository holds a vector and a test that recomputes it.
5. **A review renderer with no truncation.** If an address or amount cannot be displayed in full,
   the request is refused. Truncating a recipient "for space" is how users lose funds.
6. **Ownership binding.** Inputs must be proven to belong to this wallet: PSBT `witness_utxo` /
   `non_witness_utxo`, CryptoNote key images and commitments, EVM token registry, Ergo P2PK preimage.
7. **Policy limits before crypto.** Fee caps, amount bounds, duplicate inputs, duplicate ring
   members, canonical encoding. These run before any curve operation, so an abusive payload costs
   nothing.
8. **Fail-closed output.** A signing error clears the output buffer; an approval is consumed even on
   failure; a partial serialisation is never returned.

## Evidence trail

| Evidence | Where |
| --- | --- |
| per-chain vector files | `src/generated/*VectorsTest.inc`, `tests/fixtures/` |
| fork admission rows (base58 versions, sighash, header shape) | `tools/fork_registry.json` |
| live-transaction pins (Dash, Groestlcoin, QRL, Pearl) | adapter comments plus a host test that recomputes the digest |
| capability matrix generated from compiled objects | `wiki/native-chain-capabilities.md` |
| MiningPoolStats resolution, one row per listing | `wiki/miningpoolstats-coverage.md` |
| dated engineering records | [Audit-Records](Audit-Records) |

## Withdrawal

Retired networks are excluded from the device catalog and transaction dispatcher.

Withdrawal is deliberately unglamorous: delete the catalog entry, delete the adapter, add a policy
test that the network id no longer resolves, and leave the record that says why.

## Admission by chain

The catalog records address generation and signing separately. WalletAdmission and the host policy tests enforce exclusions.

| Chain | SLIP-0044 | Model | Blocker |
| --- | --- | --- | --- |
| Beam | 1533 | Mimblewimble | Native single-input interactive BEAM transfers, complete output proofs and optional change are implemented. Generic wallet admission awaits secure custody, unspent-output tracking and two-device node acceptance. [Protocol and tests](Beam-zh) |
| Alephium | 1234 | sUTXO, group-sharded | Native ALPH P2PKH transfers with one recipient, optional wallet change and reviewed gas. The transaction ID and signature match Alephium SDK 3.0.5. |
| Iron Fish | 1338 | Sapling-style shielded notes | Note decryption, nullifier derivation and zk proof generation. Not viable on this MCU, and a signer without them is signing blind |
| Quai | 994 | Cyprus-1 account ledger | Mainnet type 0 transfers on chain ID 9 between local Quai accounts, with empty calldata and access list. [Signed fixture](https://quaiscan.io/tx/0x00060019fdf877647e4a9bab684b0c51732b590cb0ffebc058fb29702fe87f97) |
| Qubic | 83293 | FourQ + KangarooTwelve | KangarooTwelve is now in the tree ([KangarooTwelve.cpp](https://github.com/blueokanna/HexWallet/blob/main/KangarooTwelve.cpp), pinned to the official XKCP vectors including the 24 MB case), but identity is still a FourQ point hashed with K12 and signatures are SchnorrQ over FourQ. An Ed25519/SHA3 substitute produces a different key, so there is no honest shortcut; FourQ and SchnorrQ are still missing |
| Xelis | unverified | Confidential accounts | English and Simplified Chinese native recovery, Ristretto255 accounts and Schnorr primitives are implemented. The device can validate external mainnet addresses. Custody, confidential balance synchronization and transfer proofs are pending. |
| Quantus | 189189 | ML-DSA-87 | Mainnet runtime 153/6. Transparent ML-DSA-87 accounts, SS58 prefix 189 and signed v4 balances transfers with nonce, tip and era review. |
| Qubitcoin | — | Qtum fork (claimed) | Out of scope by owner decision. The advertised site returns 404 and two unrelated projects publish under the ticker QTC, so even the chain identity was unresolved; that decision is recorded here so it is not rediscovered as an open task |
| Aion | 425 | EVM-era L1 | Out of scope by decision; the chain is dormant |

The table is not only documentation: `coin why <id>` prints the same four fields from the device
(`OK refused id=beam name="Beam" slip44=1533` plus `blocker=` and `requires=`), so a support answer
cannot drift from the code. For a chain that is shipping, the same command reports
`OK supported id=...` and points at `coin show`.

The "no SLIP-0044" rows are refused by the same rule that keeps Swap, Evolution and VeriBlock out:
deriving a chain's keys from another chain's coin type silently puts two domains on one key. That
is not a compatibility shortcut, it is a collision.

A chain leaves this table only in the same commit that adds its adapter, its vectors and its
capability row — never by editing the catalog alone.

## Zephyr left this table

Zephyr is the first chain to be promoted out, and the record matters more than the row. What came
in: a network profile, a catalog entry, and the upstream address vector from `src/cryptonote_config.h`
(`prefix 0x6241d18c0`, 12 decimals) plus `tests/unit_tests/base58.cpp`, reproduced byte for byte by
`run_cryptonote_address_self_tests()` — 73 bytes, 101 characters, `ZEPHYR3baX…QuP1u4V`.

What did not come in: a coin type. Upstream SLIP-0044 does not list ZEPH, so the owner made the one
decision this table cannot make for them and accepted Monero's 128. That is a recorded trade-off,
not a precedent: account 0/index 0 yields the same spend and view keys as XMR, and only the prefix
makes the address different. The Zephyr adapter reviews native ZPH-only version 3 transactions and uses CLSAG. Its mainnet regression checks the exact wire bytes, transaction ID and balance. Conversions require separate review rules.

## What does not count as admission

- A ticker on a mining site, an exchange listing, or an "EVM compatible" claim.
- An address encoder with no signing path (that is an `address` row, not a wallet).
- A parser that can read a transaction but cannot prove ownership of an input.
- A signature that matches a self-generated vector only.
- Any change that adds `SIGN` without a test in the same commit.

The long-form ledger with per-chain gaps is `wiki/chain-gates.md`. It is a living record; this page
is the policy it follows.
