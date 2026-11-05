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

Chains get removed. MASARI (MSR) was withdrawn on 2026-10-24: it had a signing path, but the
subaddress and RCT type-3 semantics could not be tied to mainnet vectors, so the entries were pulled
instead of left in place with a warning. Qubic was removed outright rather than mapping its FourQ/K12
identity onto Ed25519, and Flux stays out because the MiningPoolStats snapshot lists it under
GRAVEYARD.

Withdrawal is deliberately unglamorous: delete the catalog entry, delete the adapter, add a policy
test that the network id no longer resolves, and leave the record that says why.

## What does not count as admission

- A ticker on a mining site, an exchange listing, or an "EVM compatible" claim.
- An address encoder with no signing path (that is an `address` row, not a wallet).
- A parser that can read a transaction but cannot prove ownership of an input.
- A signature that matches a self-generated vector only.
- Any change that adds `SIGN` without a test in the same commit.

The long-form ledger with per-chain gaps is `wiki/chain-gates.md`. It is a living record; this page
is the policy it follows.
