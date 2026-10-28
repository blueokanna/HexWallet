# Crypto stack

The extended crypto stack lives in `Ed25519.cpp`, `BlsG1.cpp`,
`CryptoExtended.cpp`, `WalletAltAddresses.cpp`, and the encoder helpers
(`base58`, `local_bech32`, `local_segwit`, `keccak256`, `local_ripemd160`).
Every primitive is verified on the host against official vectors before the
firmware ever boots.

Strict-build note: CryptoNote, QRL, Chia/BLS and the other address-only
primitives are internal, vector-tested libraries. They are not exposed as
wallets unless a complete receive/review/sign path is shipped.

## Ed25519 (RFC 8032)

- Pure field/group arithmetic in `Ed25519.cpp`, no external bignum.
- The challenge scalar is the **full 64-byte** `SHA-512(R || A || M)` digest
  reduced mod the group order `L` — a classic bug source is reducing only the
  first 32 bytes. We reduce the whole 512-bit digest with a dedicated
  full-width reduction.
- Verified with RFC 8032 TC1 and TC2 (public key `d75a9801…`,
  signature `e5564300…`).

## SLIP-10 Ed25519

- `slip10_ed25519_derive(seed, seed_size, path, path_len, out)`.
- The seed length is an explicit parameter — silently assuming 32 bytes
  breaks the official 16-byte vector (`000102…0f` → child `0'`
  `68e0fe46…`).

## EIP-2333 / ERC-2333 (BLS12-381 key tree)

The Chia/BLS key tree. The spec was moved to ERC-2333; the details that
matter:

- `hkdf_mod_r`: `salt = "BLS-SIG-KEYGEN-SALT-"`, then the **salt loop**
  (`salt = H(salt)`), then `PRK = HKDF-Extract(salt, IKM || 0x00)` and
  `OKM = HKDF-Expand(PRK, I2OSP(48,2), 48)`; reduce mod the group order `r`.
- `parent_SK_to_lamport_PK`: `salt = I2OSP(index, 4)`;
  `lamport_0 = IKM_to_lamport_SK(parent_SK, salt)`;
  `not_IKM = flip_bits(parent_SK)`; `lamport_1 = IKM_to_lamport_SK(not_IKM, salt)`.
  **`IKM_to_lamport_SK` is ONE HKDF-Extract + HKDF-Expand with empty info,
  producing 255 × 32-byte chunks** — it is *not* 255 independent HMACs.
  Hash every chunk with SHA-256 (all `lamport_0` first, then all `lamport_1`),
  then SHA-256 the concatenation → 32-byte compressed Lamport PK.
- `derive_child_SK(parent, index) = hkdf_mod_r(compressed_lamport_PK)`.

Verified against the official ERC-2333 Test Case 0: master SK,
compressed Lamport PK (`dd635d27…`), and child SK all match.

## BLS12-381 G1

- `BlsG1.cpp` implements field/group arithmetic with the mbedtls bignum shim,
  the canonical generator (the root with the smaller `y`:
  `x = 17f1d3a7…`, `y = 08b3f481…`), and 48-byte ZCash-style compression
  (`C=0x80`, `I=0x40`, `S=0x20` when `y > p - y`).
- `bls pk(sk=1)` = `97f1d3a7…` and the derived-key public key
  `a5336788…` are checked against an independent pure-Python implementation.

### The bignum trap that bit us

`mbedtls_mpi_mod_mpi` must return the **least non-negative residue** for a
negative input (`A mod B` with `B > 0` → `[0, B)`). The point formulas
`x3 = λ² − x1 − x2` and `y3 = λ(x1 − x3) − y1` produce negative intermediates
all the time. If `mod` just returns the negative value (as a naive
`cmp(A,B) < 0 ? copy(A)` does), the point accumulator silently accumulates an
**unreduced 12-limb** coordinate, and the next `inv_mod(2y, p)` fails with
`NOT_ACCEPTABLE`. All the "positive only" unit tests (`3^100 mod 7`,
`P mod P`, `okm mod r`) pass while this is broken — only the full point
arithmetic exposes it. Fix: reduce `|A|`, then `B − |A|` when nonzero.

## Zcash transparent v4 / ZIP-243

- `ZcashTransaction` signs only Overwinter/Sapling v4 transparent t1 P2PKH
  inputs. Shielded spends/outputs, JoinSplits, v3/v5 and non-empty scriptSigs
  are rejected before any key is derived.
- The digest is BLAKE2b-256 personalized with `"ZcashSigHash" || branch_id_le`
  over the v4 header, `hashPrevouts`, `hashSequence`, `hashOutputs`,
  `hashJoinSplits`, `hashShieldedSpends`, `hashShieldedOutputs`, lock time,
  expiry height, value balance and hash type, followed by the per-input
  outpoint/scriptCode/amount/sequence. BLAKE2b personalization was added to
  `Blake2b`; keyed hashing is not a substitute.
- The mainnet branch id is an explicit network policy (`0x5437f330`, NU6.2),
  not a host-supplied free parameter. `zec inspect` reviews a compact payload
  with each prevout value and scriptPubKey; `zec sign` re-derives
  `m/44'/133'/account'/change/index`, verifies the prevout HASH160 and emits a
  v4 transaction plus txid.
- The boot self-test checks official ZIP-243 test vector 3
  (`f3148f80…`) and the parser/fee failure paths. The full signing path is
  exercised by `run_zcash_transaction_self_test()` on the device.

## CryptoNote (Monero / Masari)

- Spend key = `sc_reduce32(Keccak-256(seed))`; view key =
  `sc_reduce32(Keccak-256(spend))`, matching `crypto::generate_keys` for a
  32-byte seed.
- Public keys use the Edwards25519 group with Monero's encoding (little-endian
  `y` plus the sign bit of `x`). Point decompression, addition and scalar
  multiplication are implemented in `Ed25519.cpp` (`edwards_decompress`,
  `edwards_add`, `scalarmult_point`) so the firmware does not depend on an
  external bignum library for this curve.
- Subaddresses follow `device_default.cpp`: `m = sc_reduce32(Keccak-256(
  "SubAddr" ‖ view_secret ‖ major_le32 ‖ minor_le32))`, `D = B + mG`,
  `C = view_secret · D`; prefix `42` mainnet. Integrated addresses append the
  8-byte payment ID and use prefix `19`. `(0,0)` is the standard address.
- Scalar multiplication always performs the addition and selects the result
  with a constant-time mask, so the scalar bits do not steer control flow.
- Vectors: spend/view keys and the standard address for a zero seed, two
  subaddresses, the integrated address, and the existing synthetic base-point
  vector, all cross-checked against an independent Keccak/Edwards oracle.

## QRL XMSS-SHAKE256

- QRL has no BIP32 tree. `qrl_seed_from_bip39` expands the BIP39 seed with
  SHAKE-256 and the domain `HexWallet/QRL/v1` into 48 bytes.
- `qrl_xmss_public_key` performs the height-10 XMSS treehash: SHAKE-256
  expansion into `sk_seed ‖ sk_prf ‖ pub_seed`, WOTS+ `w=16` (67 chains),
  L-tree compression, and the Merkle stack. The public key is
  `descriptor ‖ root ‖ pub_seed` (67 bytes).
- The address is `Q` + hex of `descriptor ‖ SHA-256(pubkey) ‖
  SHA-256(descriptor ‖ hash)[-4:]` (39 bytes), matching
  `QRLHelper::getAddress`.
- Verified against qrllib's `XmssBasicSHAKE256` vector (48 zero seed, height
  4, address `Q0202000f9ec8…`). Production height 10 costs roughly three
  million SHAKE-256 calls; the progress hook exists so an MCU caller can feed
  its watchdog. Stateful signing is deliberately not implemented.

## Secure-element custody

`WalletCustody` maps each `AddressEncoding` to a `KeyScheme` and answers
whether the SE can hold the key and produce the exact signature. The active
profile is MCU-only until the board port probes the applet and calls
`set_active_secure_element_profile()`. The conservative SE050C1H1 target
profile claims secp256k1 + ECDSA + seed sealing only.
That means BTC/LTC/ETH-style keys can be imported and signed in the applet,
while Kaspa (BIP340 Schnorr) and the internal Ed25519/BLS/XMSS primitives stay
in MCU RAM until a verified applet path exists.
BIP32/SLIP-0010 derivation itself is always MCU-side because the SE050 has no
BIP32 engine. The plan is code, not marketing: `wallet custody <id>` prints
the decision and reason.

## Chia standard addresses

`chia_standard_address(seed, address_index)`:

1. `sk = master(seed)`; then `sk = child(sk, i)` for `i ∈ {12381, 8444, 0, index}`.
2. `pubkey = compress(sk · G)`.
3. `hidden_hash = shatree_pair(shatree_atom(0x09), shatree_atom(nil))`
   (the `ff0980` default hidden puzzle).
4. `offset = int(SHA256(pubkey ‖ hidden_hash)) mod r`.
5. synthetic pubkey = `(sk + offset) · G`, compressed.
6. `puzzle_hash = curry_and_treehash(P2_DELEGATED…, synthetic)` with the
   `e9aaa49f…` mod hash, using CLVM `shatree` rules (`0x01 ‖ atom`,
   `0x02 ‖ left ‖ right`).
7. `bech32m("xch", puzzle_hash)`.

Verified addresses (authoritative): seed `c55257…` (64 B) →
`xch1yvsm3y…`, and the 64×`0x01` seed → `xch14e2x9…`.
Vectors are generated with blspy: Chia HKDF uses the raw salt, not a prehashed one.

## Alt-address encoders

Solana (base58), Algorand, Tezos `tz1`, Qubic, cashaddr (BCH + eCash),
Avalanche `X-`, Cosmos bech32 (CRO/SEI), and Cardano base addresses are
implemented in `WalletAltAddresses.cpp` and pass the full `alt-addresses`
host suite.
