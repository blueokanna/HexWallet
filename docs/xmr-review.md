> 2026-10-24：MSR 已移除，不再接受地址或签名请求。下文 MSR 段落仅保留为历史协议记录；不代表当前支持。SOL 使用 kind=6，详见 [solana-signing.md](solana-signing.md)。

# Monero on HexWallet: what the device actually verifies

This is the trust model for XMR/MSR signing. It describes what runs on the
device, what comes from the phone, and what stops the phone from lying.

## Roles

The device never talks to a node. There is no network stack in this firmware and
no plan to add one. The phone does all chain I/O and hands the device two things:

1. a transaction to review, already serialized, plus the ring members and
   offsets it wants to spend;
2. the transaction secret key for that transaction.

Everything else the device derives itself from the wallet secrets. The phone is
treated as hostile.

## What `cryptonote_review_transaction` proves

Implemented in `CryptoNoteReview.cpp`; called before anything is displayed or
signed.

| # | Check | What it stops |
| --- | --- | --- |
| 1 | `version == 2`, `rct.type == 6`, counts match the payload | shape confusion, downgrade to a simpler RCT type |
| 2 | One leading `tx_extra` public key equals `tx_secret·G`; duplicate, additional and unknown keys rejected | inconsistent transaction keys that prevent the recipient from scanning outputs |
| 3 | For each output: one-time key, 8-byte amount ciphertext, view tag recomputed from `(tx_secret, recipient keys, index)` | showing one recipient/index while paying another |
| 4 | For each output: commitment recomputed from the **stated amount** and the derived mask, then compared to the wire commitment | displaying an amount the transaction does not commit to |
| 5 | Change outputs must derive from this wallet's own spend and view keys | claiming somebody else's output as change to hide fee inflation |
| 6 | Every Bulletproofs+ proof block verified over its own 16-output window | out-of-range outputs, which is how hidden inflation happens |
| 7 | `Σ pseudoOut == Σ outPk + fee·H` | value creation outside the fee |
| 8 | For each input: our output located at `real_index`, its one-time key and commitment rebuilt from the view secret, key image rebuilt from the **derived one-time secret** | spending an output we do not own, or a ring that does not contain our output |
| 9 | `pseudoOut_i == commit(c_out_i, amount_i)` for the phone-supplied mask | a pseudo output committing to a different amount than the one shown |
| 10 | `Σ inputs == Σ outputs + fee` | arithmetic that does not add up |
| 11 | CLSAG auxiliary key image `D = z·Hp(P)/8` recomputed and compared to the wire | a host choosing the `D` field that is not covered by the signing hash |
| 12 | Ring offsets in the host request must equal the serialized transaction and be strictly monotonic | reordering the ring or supplying a duplicate output |
| 13 | No repeated ring member inside one input; no repeated key image across inputs | a malformed ring that would make the CLSAG equation degenerate, or spending the same output twice |
| 14 | Destinations and change use standard addresses; subaddress output types and nonzero output indices are rejected | signing a subaddress output without its matching transaction public key |

Check 4 is the one that makes the display trustworthy: the amount shown is an
input to a Pedersen commitment that must match a byte on the wire. The phone
cannot show 1 XMR and commit to 100.

Check 8 uses `cryptonote_derive_secret_key`, so the master spend key is only
ever used as a derivation input; the scalar that signs is the per-output
one-time secret, and it is zeroized before the next input is examined.

## What the device then signs

`cryptonote_sign_input` produces the CLSAG for one input. The scalar it signs
with is `z = c_a − c_out` (real commitment mask minus pseudo output mask), which
is Monero's `zero_commit_sk` in `proveRctCLSAGSimple`. `CryptoNoteReviewResult`
carries that scalar per input, so the signer never recomputes it from untrusted
data.

## Signing is exposed

`WalletCatalog` now exposes XMR (and MSR) with address, review and signing
capabilities. `WalletSigning` has a `CryptoNote` request kind that keeps the
reviewed transaction and ring data until the on-screen APPROVE button is
pressed. The phone link uses `BEGIN_SIGN` kind 5; the serialized transaction
plus the host's ring data is capped at 16 KiB.

The review screen shows every output amount and destination, the change line,
the fee and the total spent. It also prints the honest caveat that ring decoys
were supplied by the phone and that their chain membership cannot be proven
offline.

The signing keys are the same BIP32 child that `derive_address()` used for the
displayed address (`m/44'/128'/0'/0/<address_index>` for XMR). They are not
derived from the BIP39 seed directly; the signer would otherwise sign with a
different view/spend pair than the one shown on screen. The BIP32 account and
change path components are fixed at zero. CryptoNote subaddress inputs derive
their own spend scalar from that account, as described below.

## Masari is a separate path

`CryptoNoteMasari.cpp` implements Masari's own historical RCT enum:

| type | name | range proof | signature | status |
| --- | --- | --- | --- | --- |
| 0 | RCTTypeNull | none | none | rejected (not a private spend) |
| 1 | RCTTypeFull | Borromean | one MLSAG over all inputs | implemented |
| 2 | RCTTypeSimple | Borromean | MLSAG per input | implemented; validated against the real `tests/data/fuzz/transaction/TX2` vector |
| 3 | RCTTypeBulletproof | Bulletproofs | MLSAG per input | parsed but disabled by `HEXWALLET_MSR_ENABLE_RCT_TYPE3` until a mainnet BP vector exists |

Masari uses the legacy 64-byte `ecdhInfo` tuple (`mask || amount` encrypted by
scalar addition, not ChaCha8) and MLSAG, so it never shares the Monero type-6
parser, CLSAG signer or compact-amount code.

The real TX2 vector (2 inputs, 2 outputs, ring size 3, fee 6076330000) is parsed
in the host self-test and must pass Borromean verification; flipping one proof
byte must fail. A synthetic type-2 spend is then reviewed and signed, and the
resulting MLSAG is verified against the ring.

## Subaddress spending

A subaddress output is spent with `b + Hs("SubAddr" || a || major || minor)`
instead of `b`, and the same substitution is applied per input, so one
transaction can mix standard and subaddress coins. `(0, 0)` means the standard
address and keeps the original path.

The payload carries `(major, minor)` per input. Output indices must be zero:
subaddress destinations and change are rejected until `rD` / additional
transaction public keys are bound and independently tested with recipient
scanning. Checking ownership of `(D, C)` alone does not establish that the
recipient can discover the output. This restriction applies to XMR and MSR.
Payload version 1 omits these indices and retains standard-address behavior.

## Fee ceiling

`cryptonote_review_fee_policy` rejects a fee above
`HEXWALLET_XMR_MAX_FEE_ATOMIC` (XMR) or `HEXWALLET_MSR_MAX_FEE_ATOMIC` (MSR),
both 0.1 coin by default, before any curve operation. This is a local firmware
policy, not a live fee estimate. Host requests cannot raise it.

## Ring data authenticity

The device verifies that the ring is internally consistent, that the offsets
match the serialized transaction byte for byte, that the offsets are monotonic,
and that the owned output sits at the claimed `real_index`. It cannot prove
that a decoy exists on chain without chain access. That is inherent to an
offline signer: the phone is trusted only for the **liveness of decoys**, never
for amounts, fees or destinations.

## Verification cost

Bulletproofs+ dominates review time. The padded scalar `mn` is
`64 * next_pow2(outputs)` (minimum 64), exactly like Monero, so a 16-output
proof needs 1024 multi-exponentiation terms while a 2-output proof needs 128.

Measured on the host suite (x86-64, MSVC `/O2`, `bp_plus_probe.exe --bench`):

| commitments | rounds | `mn` | per proof |
| --- | --- | --- | --- |
| 1 | 6 | 64 | 67 ms |
| 2 | 7 | 128 | 127 ms |
| 16 | 10 | 1024 | 932 ms |

Two changes got it there, both verified against the eight reference proofs, the
mainnet proof and the tamper tests:

* `point_mul8` now does its three doublings in extended coordinates
  (`ed25519_point_mul8_compressed`), one inversion instead of five. Every BP+
  generator needs it.
* The verifier accumulates in extended coordinates with a 3-bit window
  (`ed25519_extended_add_scaled`), so there is no inversion per term and no
  point re-encoding between terms. The window table is 2.5 KiB.
* The whole review runs on the 24 KiB crypto worker
  (`wallet_worker_begin` / `wallet_worker_wait`), because about 7 KiB of stack
  comes close to the 8 KiB Arduino loop task. LVGL stays on the calling task,
  which is not thread safe to share.

P4 latency and watchdog behavior have not been measured on the intended board.
Both review and signing now run on the crypto worker; the caller polls while
servicing LVGL and yielding. It does not process new host requests during that
wait. A deadline invalidates the result but does not cancel the task: borrowed
buffers remain alive until the task finishes, and a late signature is erased.
Worker startup failure rejects the operation instead of falling back to the
smaller Arduino loop stack.

## Test coverage

`run_cryptonote_review_self_tests()` builds a complete type-6 spend and requires
rejection for each tampering attempt: destination amount +1, change amount −1,
foreign change view key, fee +1, replaced key image, replaced pseudo output,
replaced `tx_extra` key, replaced phone-supplied `c_out`, swapped owned ring
slot, swapped output commitments, replaced auxiliary key image `D`, a ring order
that disagrees with the wire offsets, and a change output that claims a
subaddress without carrying its keys.

`run_cryptonote_signing_self_tests()` prepares the same transaction through the
host payload, checks the summary, signs every CLSAG with a fresh per-input
nonce and verifies the serialized result. `run_masari_self_tests()` covers
MLSAG sign/verify, legacy ECDH decode, the real TX2 Borromean vector and an
end-to-end type-2 review/sign.

The Monero fixture uses a valid proof generated by the isolated pinned Monero
reference build (`MoneroReviewProofTest.inc`). The Masari TX2 vector comes from
the upstream `masari-project/masari` fuzz corpus. Neither is a mainnet
acceptance run.

## Remaining limits

* Type-3 Masari (Bulletproofs) needs a mainnet proof vector before it can be
  enabled; the parser currently returns `unsupported` by default. Run
  `tools/fetch_masari_bulletproof_vector.py` against a Masari node to produce the
  vector, and the host self-test will require it to parse and reject single-byte
  edits before you build with `-DHEXWALLET_MSR_ENABLE_RCT_TYPE3=1`.
* XMR/MSR subaddress inputs are supported, but subaddress destinations and
  change are rejected pending independent transaction-key and scanning tests.
* There is no distance bounding on NFC; a relay can forward frames, but the
  on-device buttons and trusted display still gate every signature.
