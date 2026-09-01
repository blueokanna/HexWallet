# Crypto stack

The extended crypto stack lives in `Ed25519.cpp`, `BlsG1.cpp`,
`CryptoExtended.cpp`, `WalletAltAddresses.cpp`, and the encoder helpers
(`base58`, `local_bech32`, `local_segwit`, `keccak256`, `local_ripemd160`).
Every primitive is verified on the host against official vectors before the
firmware ever boots.

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
`xch1sqh8a9…`, the 64×`0x01` seed → `xch1wv0k6…`, and the 16-byte
`000102…0f` seed → `xch14jaaa4…`.

## Alt-address encoders

Solana (base58), Algorand, Tezos `tz1`, Qubic, cashaddr (BCH + eCash),
Avalanche `X-`, Cosmos bech32 (CRO/SEI), and Cardano base addresses are
implemented in `WalletAltAddresses.cpp` and pass the full `alt-addresses`
host suite.

## Lessons learned (bignum hygiene)

- Never let `mod` return a negative or unreduced value; canonicalize to
  `[0, B)`.
- Long division must be exact for dividends with ~2× the divisor limb count.
- Alias handling (`X == A`) in add/mul/mod is required — point arithmetic
  aliases constantly.
- When a scalarmult fails "randomly" at a high bit, suspect the accumulator's
  *sign*, not the scalar.
