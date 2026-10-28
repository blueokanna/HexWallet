# Account-model chain signing (VET / ICX / TON / DCR / CKB)

`ChainTransaction` is the shared envelope for account-model adapters that do
not need a dedicated `WalletSigningKind`. The host sends a compact review
payload; the firmware parses it, derives the sender address from the wallet,
shows the destination/amount on the trusted display, and signs a digest that it
recomputes from the payload. The host cannot submit an opaque digest.

Link transaction kind: `14` (`kTxChain`). The `coin_id` selects the adapter and
the payload starts with the adapter's own magic. Firo, Qtum and Flux do **not**
use this path: they are served by the Bitcoin/Zcash engines.

## VeChain (VET)

Payload (80 bytes, integers little-endian unless noted):

| Offset | Field |
| --- | --- |
| 0 | `"VET1"` |
| 4 | `u32 chain_tag` (mainnet `0x27`) |
| 8 | `u8 block_ref[8]` |
| 16 | `u32 expiration` (blocks, 1..86400) |
| 20 | `u32 gas_price_coef` (0..255) |
| 24 | `u64 gas` (21000..10000000) |
| 32 | `u8 clause_count` (must be 1) |
| 33 | `u8 to_size` (must be 20) |
| 34 | `u8 to[20]` |
| 54 | `u8 value_be[16]` (wei, big-endian, non-zero) |
| 70 | `u16 data_size` (must be 0) |
| 72 | `u64 nonce` (non-zero) |

The device builds the canonical 9-field RLP transaction, hashes it with
BLAKE2b-256, signs it with secp256k1 (recoverable, low-S) and returns the
complete 10-field signed RLP transaction. The signature byte is
`r || s || recovery_id` (65 bytes), matching `thor-devkit`.

Rejected: multiple clauses, contract data, VIP-191 delegation, non-zero
`reserved`, wrong chain tag, zero value or zero destination.

Vector: `thor-devkit 1.0.14`, private key 1, digest
`903afbc4ae9b959f2bfbc873af93e736ab94c7157be2165a8bcd7cd4f87340fd`,
unsigned RLP
`f52784a1b2c3d48202d0e0df9411…88112210f47de9811580808252088084075bcd15c0`.

## ICON (ICX)

Payload (69 bytes):

| Offset | Field |
| --- | --- |
| 0 | `"ICX1"` |
| 4 | `u32 nid` (mainnet 1) |
| 8 | `u64 nonce` |
| 16 | `u64 step_limit` (10000..10000000) |
| 24 | `u64 timestamp_us` |
| 32 | `u8 value_be[16]` (loop, big-endian, non-zero) |
| 48 | `u8 to_size` (must be 20) |
| 49 | `u8 to[20]` |

The device renders the canonical
`icx_sendTransaction.<sorted key>.<value>` string with the wallet-derived
`from` address, hashes it with SHA3-256, and returns the 65-byte recoverable
`r || s || recovery_id` signature. The phone attaches it as the transaction
`signature`.

Rejected: non-mainnet `nid`, zero value, zero destination, out-of-range step
limit, and any payload with a different length. SCORE calls and data payloads
are not admitted.

Vector: `iconsdk`/`coincurve`, private key 1, hash
`a1fb011a254cc10d250dbaf9a2a3fd04761dcd6a76f0402a21e8493bdae3d016`.

## Polkadot / Kusama (DOT / KSM) — historical codec only

Production admission is disabled. The codec below hardcodes pallet/call indices
and accepts host runtime versions without authenticating runtime metadata or the
complete signed extension set. Historical vectors do not establish current
relay-chain or Asset Hub compatibility. It is reachable only with BOTH
`HEXWALLET_HOST_TEST` and `HEXWALLET_LEGACY_SUBSTRATE_TEST_ONLY`.

Payload `DOT1` (130 bytes, big-endian amount; other integers little-endian):

| Offset | Field |
| --- | --- |
| 0 | `"DOT1"` |
| 4 | `u8 network` (0 Polkadot, 2 Kusama) |
| 5 | `u8 call` (0 `transfer`, 3 `transferKeepAlive`) |
| 6 | `u8 recipient[32]` (AccountId32) |
| 38 | `u8 amount_planck_be[16]` |
| 54 | `u32 nonce` |
| 58 | `u32 spec_version` |
| 62 | `u32 transaction_version` |
| 66 | `u8 genesis_hash[32]` |
| 98 | `u8 block_hash[32]` (must equal genesis: immortal era only) |

Payload `DOT2` (156 bytes):

| Offset | Field |
| --- | --- |
| 0 | `"DOT2"` |
| 4–65 | identical to `DOT1` (`network`, `call`, recipient, amount, nonce, spec, tx version) |
| 66 | `u8 tip_be[16]` (SCALE-compacted on the wire) |
| 82 | `u8 era_period_log` (0 = immortal, 2..16 = `log2(period)`) |
| 83 | `u8 reserved` (must be `0`) |
| 84 | `u64 era_block` (block number used to derive the era phase) |
| 92 | `u8 genesis_hash[32]` |
| 124 | `u8 era_block_hash[32]` (genesis when immortal, otherwise the era-start block hash) |

The era period must be a power of two in `[4, 65536]`. `encode_era` implements
substrate's SCALE `Era` rule
`(period.trailing_zeros() - 1) | ((block % period / max(period >> 12, 1)) << 4)`
and is pinned by vectors cross-checked against `scalecodec`
(`(64, 12345678) → e500`, `(4, 100) → 0100`, `(4096, 999999) → fb23`,
`(65536, 123456789) → 1fcd`).

The device builds the SCALE call (`pallet 5`, `MultiAddress::Id`, compact
amount), the signing payload
`call || era || compact nonce || compact tip || spec_version ||
transaction_version || genesis || era_block_hash`, plus — for `DOT2` only — the
`CheckMetadataHash` implicit `Option<[u8;32]>` byte `0x00` (mode Disabled, which
is a historical codec assumption, not a current-network compatibility claim). It then hashes with
BLAKE2b-256 and signs with the ed25519 child key. The output is the complete
signed extrinsic v4 with the compact length prefix:

`0x84 || 0x00 || pubkey || 0x00 || signature || era || compact(nonce) ||
compact(tip) || call`

The review screen shows `ERA IMMORTAL` or `ERA MORTAL <period>` + `BLOCK <n>`,
the `TIP` amount, `SPEC VERSION`/`TX VERSION`, and for `DOT2`
`EXT CHECKMETADATAHASH DISABLED` so the signed extension set is never implicit.

The genesis hash is pinned per network, so a Polkadot payload cannot be signed
on Kusama or vice versa.

Vectors: `substrate-interface` ed25519 keypair from seed `00..1f`, recipient
`0x11` × 32, amount `1234567890123` planck, nonce 7, spec 1005000, tx version
26. `DOT1` digest
`9523c647c331ba4a0f50e83ebef28d673c729d34f768c4c984eefff5d3e2414b`. `DOT2`
(era period 64, block 12345678, tip 0) digest
`0ba4998c5380ac1b14e6f527717297c4582d9765ab19c63e9f53cd9f3a9bc74f`,
reproduced independently with Python `hashlib.blake2b(digest_size=32)` over the
documented byte layout.

Rejected: any call other than balances transfer/transferKeepAlive,
wrong genesis, zero amount, zero recipient, an era period that is not a power of
two in `[4, 65536]`, a non-zero reserved byte, an immortal era whose block hash
differs from genesis, and any mismatch between the reviewed and re-parsed
payload.

## TON

Payload (66 bytes, little-endian integers unless noted):

| Offset | Field |
| --- | --- |
| 0 | `"TON1"` |
| 4 | `u32 wallet_id` (must be the v4R2 subwallet id) |
| 8 | `u32 valid_until` |
| 12 | `u32 seqno` |
| 16 | `u8 send_mode` (must be 3) |
| 17 | `u8 bounce` (0 bounceable, 1 non-bounceable) |
| 18 | `u8 recipient[32]` |
| 50 | `u8 amount_nanoton_be[16]` |

The device builds the v4R2 `internal_transfer` message with an empty body,
computes the signing-message cell hash and signs it with the wallet's Ed25519
key. The output is `signature(64) || signing_hash(32)`; the phone builds the
external message and BoC. Comments, jettons, multi-message orders and custom
wallet ids are rejected.

Vectors: `tonsdk` v4R2 wallet id `698983191`, private seed `00..1f`,
recipient `0x22` × 32, amount `123456789` nanoton, valid until `1700000000`,
seqno 7; signing hash
`294f1fdafb26b51766f923781359feee4c3b9f242dc277e121a0f892ab7a104f`
and signature `4cd9a447...0dc50d`. The separate address vector for public key
`0x01` × 32 is
`UQDy/zN0Mel7MItGcTQr0kxEJxa7dg/+OGv7/XToTMTKT1Cz`.

## Decred (DCR)

Payload (up to 148 bytes):

| Offset | Field |
| --- | --- |
| 0 | `"DCR1"` |
| 4 | `u8 prev_txid[32]` (dcrd wire byte order) |
| 36 | `u32 prev_index` |
| 40 | `u8 tree` (must be 0, regular tree) |
| 41 | `u32 sequence` |
| 45 | `u32 lock_time` |
| 49 | `u32 expiry` |
| 53 | `u64 input_value` (atoms) |
| 61 | `u8 output_count` (1..2) |
| 62 | outputs: `u64 value`, `u8 script_size`, `script` |

The device computes the Decred legacy prefix/witness sighash
(`BLAKE-256(hash_type || prefix_hash || witness_hash)`), identifies an
optional wallet-owned P2PKH change output and signs with secp256k1. The
returned bytes are the complete signed transaction with the P2PKH signature
script.
Stake tickets, treasury and mix transactions are not admitted.

Vector: dcrd's official sighash test (three inputs, two outputs, hash type 1,
input 0) →
`4ce2cd042d64e35b36fdbd16aff0d38a5abebff0e5e8f6b6b31fcd4ac6957905`.
The compressed-key P2PKH address vector is
`DsmcYVbP1Nmag2H4AS17UTvmWXmGeA7nLDx`. `input_value` is supplied by the
phone because the device has no UTXO database; the phone must verify it
against the previous output before broadcast.

## Nervos CKB (CKB)

Payload (up to 114 bytes):

| Offset | Field |
| --- | --- |
| 0 | `"CKB1"` |
| 4 | `u8 input_count` (must be 1) |
| 5 | input: `tx_hash[32]`, `u32 index`, `u64 since`, `u64 capacity` |
| 61 | `u8 output_count` (1..2) |
| 62 | outputs: `u64 capacity`, `lock_args[20]` |

The device serializes the Molecule `RawTransaction` with the mainnet
SECP256K1/blake160 dep group, hashes it with BLAKE2b-256 personalized by
`ckb-default-hash`, then builds the `secp256k1_blake160_sighash_all` message:
`tx_hash || u64(witness_len) || WitnessArgs(lock = 65 zero bytes)`. It signs
that digest with secp256k1 and returns the 65-byte recoverable
`r || s || recovery_id`. Output 0 is the recipient; output 1, when present,
must be the wallet's own change cell and is shown as change. Both outputs must
meet the 61 CKB minimum cell capacity and the fee is capped at 10 CKB. Type
scripts, DAO operations and UDTs are rejected.

Vectors: the CKB RFC-0021 address vector
(`b39bbc0b3673c7d36450bc14cfcdad2d559c6c64` →
`ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v`), and mainnet transaction
`f2851617d2f9b7bd099fcb2076e948212ac0bb7254e19600e3267a9cb547addd`
whose signing digest is
`0d7c50bc1e4f99e49ba13e0519d8da2f608289347bddf8463b5caf69d63bb68f`
(recovered signer lock args `87c713e60afa56ca8711942fc57e9666d7474694`).
As with DCR, `capacity` for the input is supplied by the phone; the device
cannot prove it from the out point.

## Flux (FLUX)

Flux reuses the Zcash v4 transparent ZIP-243 engine with the Flux branch id
`0x76b809bb`, SLIP-0044 coin type `19167`, and t1/t3 base58 prefixes
`0x1cb8`/`0x1cbd`. The phone-link kind is `4` with `coin_id=flux`; the payload
is the existing `ZEC4` review structure. The device prints FLUX on the review
screen and returns the complete signed v4 transaction. Shielded components
and FluxNode-specific transaction types are rejected. The transparent supply
cap is 440,000,000 FLUX.

Vector: derived address for the test seed index 0 is
`t1YEDM4VMCkUMnjRRZeTScifJcJrGyXKBuG`; the native probe verifies the
secp256k1 signature against the ZIP-243 digest with the Flux branch id.

| Chain | Encoding | Path |
| --- | --- | --- |
| VET | `0x` + keccak256(uncompressed pubkey)[12..31] | `m/44'/818'/0'/0/index` |
| ICX | `hx` + sha3-256(uncompressed pubkey)[12..31] | `m/44'/74'/0'/0/index` |
| DOT | SS58 prefix 0 of the ed25519 public key | `m/44'/354'/0'/0'/index'` |
| KSM | SS58 prefix 2 of the ed25519 public key | `m/44'/434'/0'/0'/index'` |
| TON | v4R2 user-friendly address of the ed25519 public key | `m/44'/607'/0'/0'/index'` |
| DCR | base58check `0x073f` of RIPEMD160(BLAKE256(pubkey)) | `m/44'/42'/0'/0/index` |
| CKB | bech32 `ckb` + `0x01 0x00` + blake160(pubkey) | `m/44'/309'/0'/0/index` |
| FLUX | t1/t3 base58check `0x1cb8`/`0x1cbd` | `m/44'/19167'/0'/0/index` |
| ADA | Ledger CIP-1852 base address | `m/1852'/1815'/account'/role/index` |
| HIVE | `"STM" + base58(pubkey ‖ RIPEMD160(pubkey)[0..3])` | `m/44'/3054'/0'/0/index` |
| ICP | `SHA-224(pubkey) ‖ 0x02` as dash-grouped base32 with a CRC-32 prefix | `m/44'/223'/0'/0'/index'` |

The encoders are pinned in `run_alt_address_self_tests()` against external
vectors, including VET `0x7e5f...`, ICX `hx0502...`, TON
`UQDy/zN0Mel7MItGcTQr0kxEJxa7dg/+OGv7/XToTMTKT1Cz`, DCR
`DsmcYVbP1Nmag2H4AS17UTvmWXmGeA7nLDx`, and CKB
`ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v`.

`tests/host/chain` links the real `WalletSecurity.cpp` (Mbed TLS) and
`Ed25519.cpp`, so TON, DCR and CKB are exercised through derivation, trusted
review, digest and signature. `tests/test_chain_adapters.py` also checks
truncation, trailing bytes, review/digest/payload substitution and output
buffer guards for these adapters.

Cardano now uses Ledger-style CIP-1852 BIP32-Ed25519 derivation rather than the
old all-hardened SLIP-0010 path. `run_cardano_derivation_self_tests()` pins the
payment/stake public keys and full `addr1...` address against Ledger
app-cardano mock vectors.

The transaction path accepts a raw Conway body CBOR (`payload` is the body, not
a custom envelope), enforces one recipient plus optional wallet change, ADA-only
outputs, a positive fee capped at 10 ADA, and signs `blake2b-256(body)` with the
Ledger expanded payment key. The returned transaction is
`[body, witness_set, valid, auxiliary_data]`. The body contains only out
points, so the device cannot prove UTxO ownership or input values; the phone
must have the node verify those before broadcast. Tokens, scripts, staking and
governance fields are rejected.

## Hive (HIVE)

Payload (up to 194 bytes):

| Offset | Field |
| --- | --- |
| 0 | `"HIV1"` |
| 4 | `u16 ref_block_num` |
| 6 | `u32 ref_block_prefix` |
| 10 | `u32 expiration` |
| 14 | `u8 from_size` + `from` (3..16, graphene account name) |
| — | `u8 to_size` + `to` |
| — | `u8 amount_size` + amount (`"1.234 HIVE"` or `"1.234 HBD"`) |
| — | `u8 memo_size` + printable memo (0..64) |

The device serializes one `transfer_operation` (`varint op_count=1 ‖ varint op_id=2 ‖
from ‖ to ‖ asset ‖ memo ‖ varint tx_extensions=0`),
where `asset` is the graphene wire form `i64 amount_le ‖ u8 precision ‖
char symbol[7]` (legacy `STEEM`/`SBD`, zero padded — Hive kept the legacy wire
symbols while JSON uses `HIVE`/`HBD`). It hashes
`sha256(chain_id ‖ serialized)` with the Hive mainnet chain id `beeab0de…`, and
signs it with a **graphene-canonical** signature: RFC 6979 nonces are ground
with an extra-entropy counter until both DER integers are exactly 32 bytes. The
output is `27+4+recid ‖ r(32) ‖ s(32)`.

Transfer has no operation-level extensions field. Exactly one empty transaction
extensions vector terminates this preimage. Adding another zero changes the digest.

Hive account names are not derived from the key, so the device shows the
derived `STM…` public key as the provable sender and labels the account name as
host-provided. Encrypted memos (`#…`) are rejected because the device cannot
display their content.

Vectors: `tests/reference/generate_native_remaining.cjs` uses
`@hiveio/dhive 1.3.6` for transaction digests, signature verification and public-key
recovery. The catalog does not advertise a derived Hive receive address.

## Ergo and Chia — production admission disabled

The experimental Ergo parser accepts multiple outputs and tokens while its
review only covers the first non-change recipient; fee handling also needs the
actual miner-fee output semantics. Complete Sigma context/reduction and an
independent signed transaction execution check remain required.

The experimental Chia path signs host-supplied `agg_sig_data` independently of
the displayed CREATE_COIN conditions. Hashing a supplied reveal does not establish
standard-puzzle ownership or execution. The current BLS code uses variable-time
MPI operations on secret scalars. Accordingly, neither chain has a production
signing route; XCH secret-derived addresses are also disabled in device builds.
The sources and self-tests are research code, not evidence of safe authorization.

## ESP32-P4 + SE051C2HQ1 custody

NXP AN12973 Table 3 lists ECDSA/Koblitz and standard Ed25519 for SE051C2.
It does not establish wallet-specific BIP32/Cardano/NEM/Sigma/BLS/XMSS support.
The active backend here is MCU-only: an I2C ACK or target profile cannot change
that. The P4 default requires secure custody and rejects sessions until an actual
authenticated key-handle/sealed-state implementation replaces the software APIs.
See [security-review-2026-10-28.md](security-review-2026-10-28.md).

## QRL — legacy XMSS addresses, no signing

`tests/reference/generate_qrl_vectors.cjs` compares legacy SHAKE256 XMSS public
keys and addresses against qrllib 1.3.2 for public test seeds and heights 4/6.
`qrl_ots_next_high_water` is only a numerical rule. There is no durable,
rollback-resistant reservation backend and no production signer. Never treat
an NVS counter or a host-supplied index as sufficient protection against WOTS reuse.

The original `HexWallet/QRL/v1` mapping is preserved at tree index zero. Original
builds ignored all indices; recovering one of those paths requires tree zero.
Nonzero tree indices now use the `v2` domain and are NOT OTS indices. This
wallet-specific BIP39-seed mapping does not promise QRL mnemonic compatibility.
Account/change values other than zero are rejected. Failure and cancellation
clear public outputs and wipe expanded secret workspaces. No P4 runtime or
physical side-channel timing claim follows from the host tests.

## Additional transfer adapters

See [native-transfer-adapters.md](native-transfer-adapters.md) for NEM, Sia, ICP,
Flow EVM and Ethereum LSK. None of these adapters claims all transaction types,
mainnet broadcast acceptance, complete backup compatibility or hardware certification.
