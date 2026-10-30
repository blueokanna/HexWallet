# HexWallet - chain-protocols

> **Tooling note (2026-10-28).** The Python/Node oracle harness (	ests/*.py, 	ests/reference/*, 	ools/*.py) was removed at the owner's request: this repository now needs exactly two toolchains, Arduino/xtensa for the device and MSVC or clang plus PowerShell for the host. Every vector those harnesses produced is still pinned in `src/generated/*.inc` and executed by `tests/host/host_test.exe`, so the checks still run on every build. The prose below records the original independent-SDK comparisons; bring the SDKs back if you need to regenerate a fixture.

## Account-model chain signing (VET / ICX / TON / DCR / CKB)

*Merged from docs/chain-signing.md.*

`ChainTransaction` is the shared envelope for account-model adapters that do
not need a dedicated `WalletSigningKind`. The host sends a compact review
payload; the firmware parses it, derives the sender address from the wallet,
shows the destination/amount on the trusted display, and signs a digest that it
recomputes from the payload. The host cannot submit an opaque digest.

Link transaction kind: `14` (`kTxChain`). The `coin_id` selects the adapter and
the payload starts with the adapter's own magic. Firo and Qtum do **not** use
this path: they are served by the Bitcoin engine, and ZEC by the Zcash engine.

### VeChain (VET)

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

### ICON (ICX)

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

### Polkadot / Kusama (DOT / KSM) — historical codec only

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

### TON

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

### Decred (DCR)

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

### Nervos CKB (CKB)

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

### Dash (DASH)：普通支付、InstantSend 与实测过的字节

DASH 现在是 **SIGN**（普通 type-0 支付），走的是专用适配器而不是 PSBT。这条路径的每一个
格式结论都来自链上真实交易，而不是文档转述：

- 抓取主网区块 2563353 / 2563352 的原始交易后逐字节解析确认，Dash 普通交易的序列化就是
  `int32 nVersion`（`nType` 在**高 16 位**，普通支付恒为 0）→ `vin` → `vout` →
  `uint32 nLockTime`，**之后没有 `extraPayload` 字段**。v3 与 v2 两种版本都在主网同时存在，
  解析器两者都收，签名器统一产出 v3。
- `extraPayload` 只出现在 `nType != 0` 的特殊交易（ProRegTx/ProUp*、CbTx、quorum commitment、
  asset lock/unlock）里。这类交易设备无法解码其负载，也就无法诚实地显示收付双方，因此**一律
  拒绝**（`DashError::Unsupported`），而不是"签个前缀"。
- 摘要算法是 Bitcoin 的 legacy 算法套在上述序列化上：复制交易、把待签输入的 scriptSig 换成
  该输入的 P2PKH scriptCode、其余置空、追加 4 字节哈希类型、双 SHA-256。仓库里 pin 了两笔
  真实主网交易的摘要（`b8d9df9a…`、`c647adb1…`），它们各自与链上签名验证通过，这就是
  "不造假"的证据；`run_dash_self_tests()` 每次构建都会重新校验这两笔（以及 4 组拒绝路径）。

设备侧的签名请求是一段紧凑审阅结构（magic `DASH`）：

```
u8[4] "DASH" | u32 lock_time | u8 input_count
input_count × { u8[32] prev_txid, u32 prev_index, u32 sequence, u64 value,
                u8 script_size + P2PKH scriptPubKey,
                u32 account, u8 change, u32 address_index }
u8 output_count
output_count × { u64 value, u8 script_size + scriptPubKey }
```

每个输入的 prevout 脚本必须是 25 字节的规范 P2PKH；设备按 `m/44'/5'/account'/change/index`
重新派生密钥、比对 HASH160 后才签名，因此主机无法让设备"为一个自己并不拥有的脚本"签名。
输出只接受 P2PKH/P2SH，地址由脚本反解得出，屏幕上看到的就是被签的字节。手续费上限
`HEXWALLET_MAX_DASH_FEE_DUFFS`（0.01 DASH）与 `HEXWALLET_MAX_DASH_FEE_RATE`（500 duffs/vB）。

InstantSend 仍然**不改变交易字节**：它是主网 quorum 对输入达成的锁（islock），由节点广播。
所以"支持 InstantSend"的真实含义只有两条：

1. 设备产出字节完全正确的 Dash 交易——这一条现在由主网摘要向量保证；
2. 这笔能否被即时锁（输入成熟度、quorum 可用性）是**手机/节点侧**的判断，设备不持有链上状态，
   屏幕上的审阅文案明确写出这一点，绝不伪造锁状态。

仍然不支持、并且不会假装支持：特殊交易类型、混币（PrivateSend）流程、`nLockTime` 之外的时间锁语义、
P2SH 多签花费（设备只持有一把钥匙）。

### Zcash (ZEC)

The Zcash v4 transparent ZIP-243 engine runs with the mainnet NU6.2 branch id
`0x5437f330`, SLIP-0044 coin type `133`, and t1/t3 base58 prefixes
`0x1cb8`/`0x1cbd`. The phone-link kind is `4` with `coin_id=zec`; the payload is
the `ZEC4`/`ZEC5` review structure documented below, built by the phone or by any
host that reproduces this layout. The device prints ZCASH on the review screen
and returns the complete signed v4 transaction. Shielded components and non-v4
transaction versions are rejected, and the transparent supply cap is 21,000,000
ZEC.

Signed inputs are t1 P2PKH and t3 P2SH whose redeem script is exactly
`<0x21> <33-byte compressed pubkey> OP_CHECKSIG` holding this wallet's key. For a
t3 input, ZIP-243 commits the **redeem script** as `scriptCode`, the scriptSig is
`push(sig + hashtype) push(redeem)`, and the fee budget is reserved with the
bigger scriptSig (151 vbytes per input instead of 149). The device re-hashes the
redeem script against the prevout hash and re-derives the key, so a t3 address
can only be spent by the key its script commits to. Every P2SH input is also
rendered as `P2SH INPUT <t3 address>` on the trusted display; a review that
cannot show all of them is refused rather than signed partially blind.

Refused: P2SH multisig or any other redeem form, a t3 prevout without its redeem
script (`ZEC4` cannot express one), a canonical redeem script belonging to
another key, duplicate out points, an existing scriptSig, shielded spends and
outputs, JoinSplits, and v3/v5 transactions.

Payload layout (little-endian; `ZEC5` appends the bracketed redeem record):

```
magic "ZEC4" | "ZEC5"
u32  branch_id
u32  unsigned_transaction_size
u8[] unsigned v4 transaction (every scriptSig must be empty)
u8   input_count
input_count * { u64 value, u8 script_size + scriptPubKey,
                u32 account, u8 change, u32 address_index
                [, u8 redeem_size + redeem script] }
```

Evidence: `run_zcash_sighash_self_tests()` pins official ZIP-243 vector 3, the
published `zcash-test-vectors` rows, and a P2SH `scriptCode` digest produced by a
separate Python BLAKE2b implementation of ZIP-243 that first reproduces the
official vector byte for byte. The redeem/address binding rule is additionally
pinned on the host with synthetic key material. The full signer also runs on the
host with real BIP32/ECDSA through `chain_probe zcash-sign-selftest`
(`tests/host/build_chain_native.ps1`): it signs a t3 spend, re-parses it, checks
the scriptSig is exactly `push(sig) push(redeem)` and verifies the DER signature
against the redeem `scriptCode`.

Flux used to share this engine with the Flux branch id `0x76b809bb`. It was
withdrawn on 2026-10-28: the MiningPoolStats snapshot of 2026-10-23 lists FLUX
in its GRAVEYARD category, and the project rules forbid graveyard identities in
production registries. ZEC keeps the engine, so no signing code was lost.

| Chain | Encoding | Path |
| --- | --- | --- |
| VET | `0x` + keccak256(uncompressed pubkey)[12..31] | `m/44'/818'/0'/0/index` |
| ICX | `hx` + sha3-256(uncompressed pubkey)[12..31] | `m/44'/74'/0'/0/index` |
| DOT | SS58 prefix 0 of the ed25519 public key | `m/44'/354'/0'/0'/index'` |
| KSM | SS58 prefix 2 of the ed25519 public key | `m/44'/434'/0'/0'/index'` |
| TON | v4R2 user-friendly address of the ed25519 public key | `m/44'/607'/0'/0'/index'` |
| DCR | base58check `0x073f` of RIPEMD160(BLAKE256(pubkey)) | `m/44'/42'/0'/0/index` |
| CKB | bech32 `ckb` + `0x01 0x00` + blake160(pubkey) | `m/44'/309'/0'/0/index` |
| ZEC | t1/t3 base58check `0x1cb8`/`0x1cbd` | `m/44'/133'/0'/0/index` |
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

### Hive (HIVE)

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

### Ergo and Chia — production admission disabled

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

### ESP32-P4 + SE051C2HQ1 custody

NXP AN12973 Table 3 lists ECDSA/Koblitz and standard Ed25519 for SE051C2.
It does not establish wallet-specific BIP32/Cardano/NEM/Sigma/BLS/XMSS support.
The active backend here is MCU-only: an I2C ACK or target profile cannot change
that. The P4 default requires secure custody and rejects sessions until an actual
authenticated key-handle/sealed-state implementation replaces the software APIs.
See [security-review-2026-10-28.md](security.md).

### QRL — legacy XMSS addresses, and what the reservation layer now guarantees

`tests/reference/generate_qrl_vectors.cjs` compares legacy SHAKE256 XMSS public
keys and addresses against qrllib 1.3.2 for public test seeds and heights 4/6.

An XMSS leaf may be used once. Signing it twice publishes two signatures over one
WOTS+ key and the account is gone — no recovery, no rotation, and the network
cannot reject the second signature in time. The device therefore refuses to sign
anything it cannot prove is unreserved, and `QrlOtsJournal` is that proof:

- **Two redundant slots, same record.** A reservation writes
  `magic "QOT1" | account tag | index | sequence | CRC-32` to *both* slots,
  reads both back byte for byte, re-derives the mark from storage, and only
  then returns the index. Redundancy is what makes one corrupt slot harmless:
  whichever record survives proves the same mark, so the counter cannot regress.
- **Torn write skips a leaf, never reuses one.** If slot 0 commits and slot 1
  fails, the caller is told `StorageFailure` and receives no index, but the
  committed copy has already moved the mark. One of 1024 signatures is wasted;
  nothing is reused.
- **Unknown means refuse.** Both slots unreadable or corrupt ⇒
  `QrlOtsError::Unknown` and no index. Re-initialising is a one-way door that
  refuses whenever any valid record exists, of any account, so a live counter
  cannot be reset by the initialiser.
- **Account binding.** Records carry a 16-byte tag; a journal that belongs to
  another account returns `WrongAccount` instead of adopting or resetting it.

Still missing, and stated plainly because the reservation alone is not a signer:
the WOTS+ signature itself and the BDS traversal state that lets the device
produce the next authentication path without rebuilding the whole tree per
signature. QRL stays ADDRESS until those land with qrllib-pinned signature
vectors. The residual risk the journal cannot close is also documented in the
header: a blank journal is indistinguishable from a wiped one, so the custody
layer must treat "account exists in the secure element, journal blank" as a
recovery event rather than initialising it.

The original `HexWallet/QRL/v1` mapping is preserved at tree index zero. Original
builds ignored all indices; recovering one of those paths requires tree zero.
Nonzero tree indices now use the `v2` domain and are NOT OTS indices. This
wallet-specific BIP39-seed mapping does not promise QRL mnemonic compatibility.
Account/change values other than zero are rejected. Failure and cancellation
clear public outputs and wipe expanded secret workspaces. No P4 runtime or
physical side-channel timing claim follows from the host tests.

### Aeternity, RyoCurrency and Zano — address profiles only

These three rows exist to answer a narrow question honestly: "can the device
derive the correct receive address for this chain?" They do not claim review or
signing, and the catalog marks them `ADDRESS` only.

| Chain | Path | Encoder | Pinned evidence |
|---|---|---|---|
| Aeternity (AE) | SLIP-0010 `m/44'/457'/0'/0'/i'` | `ak_` + base58(ed25519 pubkey \|\| SHA-256d(pubkey)[0..3]) | `aeserialization/src/aeser_api_encoder.erl` (`base58_check/1` hashes the payload twice with SHA-256); the 32-byte-key + 4-byte-checksum vector is in `run_alt_address_self_tests()` |
| RyoCurrency (RYO) | BIP44 `m/44'/382'/0'/0/i` | CryptoNote two-key body with the 3-byte varint prefix `0x2ce192` | `ryo-currency/ryo-currency/src/cryptonote_config.h` (`RYO_LONG_ADDRESS_BASE58_PREFIX`); the encoder reproduces the official Monero/Masari vectors, and the Ryo vector is pinned in `run_cryptonote_self_tests()` |
| Zano (ZANO) | BIP44 `m/44'/1018'/0'/0/i` | CryptoNote two-key body with prefix `0xc5` | `hyle-team/zano/tests/unit_tests/base58.cpp` vector `ZxDqHy6WnyYY...` is reproduced byte-for-byte by `cryptonote_address_from_public_keys()` |

Ryo and Zano use the same `CryptoNoteAddressProfile` structure as Monero, but
their prefixes are stored as 64-bit values in the network table because a
single-byte or 16-bit field would truncate the varint. Zano publishes no
standard subaddress prefix; `derive_cryptonote_subaddress()` returns
`InvalidArgument` instead of emitting a guessed prefix.

Why the other names from the mining-pool screenshot are not in the catalog:

- **Beam / Grin / MimbleWimbleCoin / Epic Cash** have no static UTXO address.
  Their base58 strings are slatepack/BBS endpoints, and a spend is an
  interactive multi-round exchange. Showing one as a normal wallet address
  would be a category error, and a hardware signer needs the whole slate state
  machine.
- **Super Zero (SERO)** uses 64/96-byte superzk public-key bundles. There is no
  single-key encoder in this tree, and a plausible-looking base58 string would
  not be spendable by the derived key.
- **Swap (XWP), Evolution (EVOX), VeriBlock (VBK)** have no SLIP-0044 coin type
  in the current registry. Reusing another chain's coin type would derive the
  same private key material in two domains. They stay out until an upstream
  coin type and independent address vectors exist.
- **Veil (VEIL)** is already present as a source-verified Bitcoin-family fork
  (`fork_utxo_veil`), not as a new privacy-chain adapter. Its Zerocoin/ring
  privacy transactions remain unsupported; only transparent P2PKH is signed.

No address from these profiles is labeled as signable. A signing request for
them is rejected by the signing dispatcher; it is never converted into a
locally invented transaction.

What a future signing port must add, in order, is not a new address encoder:

1. **Ryo / Zano**: their RingCT transaction versions, ring/key-image rules,
   fee policy and a set of independently generated signed-transaction vectors.
   Reusing Monero's RCT type-6 parser would produce a plausible but invalid
   transaction.
2. **Beam / Grin / MWC / Epic**: the complete slate/BBS exchange state machine,
   kernel and bulletproof construction, and a receiver-side scan path. An
   address string without this is only an endpoint hint.
3. **VeriBlock**: the PoP publication fields and the exact X.509/SHA-256 address
   derivation, plus a signed transaction vector. A Bitcoin PSBT path is not a
   substitute.
4. **Swap / Evolution / SERO**: an upstream SLIP-0044 (or equivalent) coin type
   and a reviewed address/transaction format. Without a coin type the same seed
   would derive keys shared with another chain.

### Additional transfer adapters

See [native-transfer-adapters.md](chain-protocols.md) for NEM, Sia, ICP,
Flow EVM and Ethereum LSK. None of these adapters claims all transaction types,
mainnet broadcast acceptance, complete backup compatibility or hardware certification.

## Native transfer adapters: precise scope and verification

*Merged from docs/native-transfer-adapters.md.*

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

### Compact transport payloads

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
recipient address. Hive's `HIV1` layout is in [chain-signing.md](chain-protocols.md).

### Reproducible evidence

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

## Algorand 签名边界

*Merged from docs/algorand-signing.md.*

设备只接收未签名的 canonical MessagePack 交易字节，自行解析、显示并签名；它不连接 algod，也不参与交易组装或广播。当前只支持主网 `mainnet-v1.0`。手机链路使用 `BEGIN_SIGN kind=10`，`coin_id=algo`。

### 接受的交易

| 项 | 规则 |
| --- | --- |
| 编码 | canonical MessagePack map，键必须严格升序且唯一；只接受短字符串（≤31 字节）、`bin8/bin16` 和最短形式非零整数 |
| 必填字段 | `fee`、`fv`、`gen`、`gh`、`lv`、`snd`、`type` 及对应金额/收款字段 |
| 网络 | `gen = "mainnet-v1.0"`，`gh` 必须等于主网 genesis hash `c061…8adf` |
| 类型 | `pay`（原生 ALGO）或 `axfer`（ASA） |
| 费用 | 1,000–1,000,000 microAlgo |
| 有效期 | `lv ≥ fv` 且 `lv - fv ≤ 1000` 轮 |
| 发送方 | `snd` 必须等于设备当前 Ed25519 公钥 |
| ASA opt-in | `axfer` 金额为 0 时要求 `snd == arcv`；非零金额为转账 |
| note / lease | note ≤1024 字节、lease 为 32 字节且非全零；两者均完整显示为十六进制 |

以下字段或交易形态一律拒绝：`grp`（原子组）、`rekey`、`close`/`aclose`（关户/强制转出）、`asnd`（clawback）、LogicSig、应用调用、资产创建/销毁、未知键和非 canonical 编码。

### 签名与 txID

- 待签消息：`"TX" || unsigned_msgpack`。
- 交易 ID：`SHA-512/256("TX" || unsigned_msgpack)`，设备以十六进制显示。
- 签名：Ed25519，输出 `{"sig": <64-byte bin>, "txn": <unsigned msgpack>}` 的 canonical MessagePack。
- 审阅字段在签名前由原始字节重新解析并逐项比较；任一显示字段、金额、地址或 txID 不一致即拒绝。

### 派生与地址

- 路径：`m/44'/283'/account'/change'/index'`，本钱包固定 `account = change = 0`，`index` 为地址序号；使用 SLIP-0010 Ed25519。
- 这是本钱包的密钥策略，不是对 Ledger 或 BIP32-Ed25519 种子兼容性的声明。
- 地址：`base32(pubkey || SHA-512/256(pubkey)[28..32])`，58 个字符。

### 已知缺口

- 不支持 ASA 的 clawback/freeze 管理交易、原子组、智能合约调用和再密钥。
- 设备没有可信时钟，只检查轮次窗口，不判断当前轮次是否已过期；过期交易由节点拒绝。
- 尚未执行主网 algod 提交、ASA opt-in 实测或整机按键验收。

### 验证证据

- `tests/fixtures/algorand-sdk.json`：由 `py-algorand-sdk` 2.11.1 生成，种子为公开 TEST ONLY 值；11 组合格、12 组拒绝。
- `tests/host/algorand_probe.cpp` 逐组比较设备输出的签名字节、txID、发送/接收地址、金额、费用、note 与 lease；`tests/test_algorand.py` 另用派生公钥独立验签。
- 启动自检比较 `src/generated/AlgorandVectorsTest.inc` 中的完整 SDK 签名结果，并验证错误 owner 被拒绝。
- 修复了 SHA-512/256 多分块路径未清零 128 位长度字段高半部的问题；此前 ≥126 字节的 Algorand 交易会显示错误 txID。`extended-crypto` 自检现已包含 128 字节分块向量。

## Cosmos SDK 原生 MsgSend（ATOM / OSMO / TIA）

*Merged from docs/cosmos-signing.md.*

实现位于 `CosmosTransaction.cpp`，接入 `WalletSigning` 与手机链路 `BEGIN_SIGN kind=8`。
币种为 `atom`、`osmo`、`tia`，路径 `m/44'/118'/0'/0/<index>`，地址为
`bech32(hash160(compressed secp256k1 pubkey))`。设备返回**完整 `TxRaw` protobuf**，手机直接广播。

### 覆盖范围

| 网络 | HRP | chain-id 前缀 | 原生 denom | 精度 |
| --- | --- | --- | --- | --- |
| atom | `cosmos` | `cosmoshub-` | `uatom` | 6 |
| osmo | `osmo` | `osmosis-` | `uosmo` | 6 |
| tia | `celestia` | `celestia` | `utia` | 6 |

每条交易 1..4 条 `MsgSend`（v3 payload）。`SIGN_MODE_DIRECT`，单签名者，无 tip、无 feegrant、
无 authz、无 IBC 报文。denom 默认是链的原生 denom；v2 payload 可以指定其他 denom（含
`ibc/<64 hex>` 形式的凭证 denom），但只有链自身的 denom 有固定精度。`chain-id` 由手机
提供但必须匹配网络前缀，并且完整显示在屏幕上；账户号与 sequence 也显示，批准前必须核对。

denom 显示策略：

- 原生 denom（`uatom`/`uosmo`/`utia`）→ 使用固定 symbol 与 6 位精度；
- 其他 denom → 屏幕上原样显示 denom 字符串，金额显示为**精确 base unit 整数**并标注
  `NO PINNED PRECISION`。离线设备无法验证发行方精度，任何小数点都是编造。
- 手续费永远使用链的原生 denom。

memo（v2）会完整显示在审阅页，并写入 `TxBody.memo`（field 2），因此进入 `SignDoc` 摘要；
1..64 字节可打印 ASCII，超长或不可打印一律拒绝。

### 审阅 payload（大端）

```
u8   version = 1, 2 或 3
u8   chain_id_len;  chain_id bytes        (1..32, [A-Za-z0-9._-])
u64  account_number
u64  sequence
-- v1 / v2：单条消息 --
u64  amount            (base units, > 0)
u64  fee               (base units, <= 10 000 000)
u64  gas_limit         (1..2 000 000)
u8   to_len;        to bytes              (小写 bech32, 20 字节 payload)
if version == 2:
  u8  denom_len;   denom bytes            (1..68, [A-Za-z0-9/._:-])
  u8  memo_len;    memo bytes             (0..64, 可打印 ASCII)
else:                                     (v1 无法提交 memo，非零即拒绝)
  u8  memo_len = 0
-- v3：多消息（1..4 条），费用与 denom 对整笔生效 --
u64  fee
u64  gas_limit
u8   denom_len;   denom bytes
u8   memo_len;    memo bytes
u8   message_count                     (1..4)
message_count * { u64 amount, u8 to_len; to bytes }
```

v3 的每条消息都有自己的收款地址与金额，设备逐条显示为独立行，汇总行显示总额；
存在任何一条零金额、自转账、非法 bech32 或行数超限的请求都整体拒绝，绝不"只显示前几条"。

接收地址必须是正确 HRP、BECH32（非 bech32m）校验和、20 字节 payload，且重新编码后
与原串完全一致；大小写混合或非规范填充会被拒绝。`to` 不能等于本机地址。本机地址必须
与设备私钥的 `hash160(pubkey)` 一致，否则 `WrongWallet`。

### 设备构建的 protobuf

设备不解析手机提供的交易结构，而是自己构建并签名：

- `MsgSend{from_address, to_address, Coin{denom, amount}}`
- `TxBody{messages=[Any("/cosmos.bank.v1beta1.MsgSend", msg)], memo?}`
- `AuthInfo{signer_infos=[{public_key=Any("/cosmos.crypto.secp256k1.PubKey", key),
  mode_info={single:{mode=SIGN_MODE_DIRECT}}, sequence}],
  fee={amount=[Coin{denom, fee}], gas_limit}}`
- `SignDoc{body_bytes, auth_info_bytes, chain_id, account_number}` → `SHA-256`
- 签名：low-S secp256k1，64 字节 `r||s`
- `TxRaw{body_bytes, auth_info_bytes, signatures=[signature]}`

字段按升序、默认值省略编码；`body_bytes`/`auth_info_bytes` 与 `TxRaw` 中完全一致。
签名前重新构建 `SignDoc` 并比较摘要；批准后无法替换内容。

### 证据

`src/generated/CosmosVectorsTest.inc` 是入库的固定向量表，三组 v1 向量来自外部 Python/OpenSSL
生成器（`body`/`auth_info`/`SignDoc` 摘要/签名/`TxRaw` 全部固定）。新增的 v2 向量由本次独立的
Python protobuf + RFC 6979 实现在**先逐字节复现 v1 三组固定值**之后生成，因此生成器本身已被
既有独立向量校验。

`tests/host/cosmos_probe.cpp` 输出 C++ 实际构建的 `body`/`auth_info`/`SignDoc` 摘要，供与独立实现
比对；拒绝侧覆盖版本、chain-id 前缀、HRP、校验和、大小写、自转账、零金额、手续费与 gas 上限、
v1 携带 memo、v2 缺 denom、非法 denom 字符、不可打印 memo、超长 memo、尾随字节以及所有采样截断。

`run_cosmos_signature_self_test()` 需要真实 secp256k1，因此由 `chain_probe cosmos-sign-selftest`
（`tests/host/build_chain_native.ps1`，链接固件密码学）与设备执行：逐条签名并与固定 `TxRaw`
逐字节比较，同时验证错误私钥必须拒绝。

多消息向量（v3）同样由上述独立实现生成：两笔 `MsgSend` 在一笔 body 内，`TxBody.messages`
重复字段、汇总金额、逐行文案与 `TxRaw` 全部固定，并由 `chain_probe cosmos-sign-selftest`
在真实曲线下逐字节复验。

未实现：IBC 报文与超时消息、authz/feegrant、EIP-191/JSON 与 amino 签名模式、
链上账户号/sequence 查询与广播。屏幕按键、SE050 托管和主网节点验收仍需独立证据。

## NEAR 签名边界

*Merged from docs/near-signing.md.*

设备只解析 Borsh 编码的 `TransactionV0` 原始字节，审阅后签名；不连接 RPC，不组装交易，不广播。当前只支持原生 NEAR Transfer。手机链路使用 `BEGIN_SIGN kind=11`，`coin_id=near`。

### 接受的交易

| 项 | 规则 |
| --- | --- |
| 结构 | `signer_id`、`public_key`（enum 0 = ED25519 + 32 字节）、`nonce` (u64)、`receiver_id`、`block_hash` [32]、`actions` 向量 |
| 动作 | 1–16 个 `Transfer`（enum 3），金额为 u128 小端；任一金额为 0 即拒绝 |
| 总额 | 逐笔累加到 128 位，溢出即拒绝，并显示格式化总额 |
| 签名者 | 必须是由设备当前 Ed25519 公钥推导出的 64 位十六进制隐式账户 |
| 公钥 | 必须与设备 owner 公钥完全一致 |
| 收款方 | 合法 NEAR 账户 ID；隐式账户按 64 位十六进制校验 |
| 交易大小 | ≤512 字节；签名输出 ≤577 字节 |

以下动作或形态一律拒绝：`FunctionCall`、`AddKey`/`DeleteKey`、`Stake`、`DeployContract`、`Delegate`、`DeleteAccount`、零金额，以及任何未识别的 action enum。

### 签名与输出

- 签名摘要：`SHA-256(borsh_transaction)`。
- 签名：Ed25519 对 32 字节摘要签名。
- 输出：`unsigned_borsh || 0x00 || signature[64]`，其中 `0x00` 是 `Signature::ED25519` 枚举值。
- 签名前重新解析原始字节，逐项比较 signer、receiver、public key、block hash、nonce、动作数和金额；比较失败即拒绝。

### 派生与地址

- 路径：`m/44'/397'/index'`，使用 SLIP-0010 Ed25519；这是 near-slip10 的默认层级，也是本钱包的密钥策略。
- 隐式账户地址：owner 公钥的 64 位小写十六进制。
- 设备不能离线证明 `block_hash` 属于当前最长链；手机必须提供近期区块哈希，用户应在设备上核对显示值。

### 已知缺口

- 不支持命名账户的链上所有权证明、FunctionCall、访问密钥管理和质押。
- 交易本身不包含手续费字段；gas 由签名者账户扣除，设备无法离线显示准确费用。
- 尚未执行 NEAR 主网 RPC 提交或节点验收。

### 验证证据

- `tests/fixtures/near-sdk.json`：由 `near-api-js` 5.1.1 生成，公开 TEST ONLY 种子；11 组合格、16 组拒绝。
- `tests/host/near_probe.cpp` 比较设备签名输出、交易哈希、signer、receiver、public key、block hash、nonce、动作数和总额；`tests/test_near.py` 独立验签。
- 启动自检比较 `src/generated/NearVectorsTest.inc` 中的完整 SDK 签名结果，并验证错误 owner 被拒绝。

## Solana、SPL Token 与 Token-2022 转账

*Merged from docs/solana-signing.md.*

实现位于 `SolanaTransaction.cpp`，通过 `WalletSigning` 的设备批准流程接入。手机使用 `BEGIN_SIGN kind=6`、币种 `sol`，payload 为**原始序列化 message**，不是 JSON，也不是带签名的 transaction。`RESULT` 返回完整的 `shortvec(1) || signature || message`，广播由手机完成。

接收地址与签名共用 `SolanaDerivation.h` 的路径 `m/44'/501'/0'/0'/index'`，沿用工程既有地址路径。不能无提示地改成其他钱包常用的四级路径，否则同一助记词会得到不同账户。

### 已接入范围

- Legacy 和 v0 message；v0 的地址查找表数量必须为零。
- 单签名者，付款账户和转账授权者必须是当前设备派生的账户；原生 SOL 和经典 SPL 转账合计最多 16 条，完整交易不超过 1232 字节。
- System Program 的 Transfer 指令。每条接收地址和 lamports 从原始字节解析，在设备显示后才允许签名。
- 经典 Token Program `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` 与 Token-2022 Program `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` 的 `TransferChecked`。不要求 mint 预先登记，所以可处理这两个程序下未登记的代币；这不表示支持任意区块链或任意自定义程序。
- Token-2022 的 mint 扩展无法离线核验：转账税会让收款方实际到账少于显示金额，transfer hook 可能在转账中执行额外程序。审阅页对每条 Token-2022 转账显示独立的 `TOKEN-2022` 标签和警告；要求额外 hook 账户的指令一律拒绝（账户数必须恰好为 4），`TransferCheckedWithFee`、unchecked `Transfer`、confidential transfer 等其余指令全部拒绝。
- SPL 指令必须严格为 `[source, mint, destination, authority]`，source/destination 可写、mint 只读、authority 为设备账户，不接受额外账户。同一 mint 的精度必须一致，同一代币账户不能在同一交易里被声明为不同 mint。
- 屏幕显示完整 mint、来源代币账户、目的代币账户、精确数量、原始整数数量及签入的 decimals。未知代币仅标为 `token`，不使用手机提供的名称、符号或价格。精度 0–19 用整数运算显示小数，20–255 显示精确的 `整数 x 10^-精度`，没有浮点舍入。
- 不同 mint 的数量不会相加；`TOTAL` 只统计原生 SOL 转账和预计 SOL 费用。SPL 数量单列。
- 可选的 Compute Budget limit/price 必须各有一条，且位于所有转账之前。优先费按 `ceil(limit × price / 1000000)` 计算，检查乘法溢出及本地费用上限。
- 签名前再次解析消息，比较付款账户、来源、目的账户、mint、精度、转账类型、金额、原生总额和费用摘要。失败、拒绝或超时均不能继续使用批准。

拒绝额外签名者、非规范 shortvec、重复账户、越界索引、未使用账户、未知指令、未知版本、ALTs、耐久 nonce、质押及任意程序调用。两个 Token Program 的 unchecked Transfer、Approve、SetAuthority、Burn、CloseAccount、ATA 创建、批量指令与多签账户均拒绝。Token-2022 的扩展语义不做猜测：设备只按 `TransferChecked` 的精确字节签名，并明确告知扩展风险。

### 接收与账户身份

现有 SOL 接收地址是设备派生的 owner 地址。接收经典 SPL 时，发送方或手机需要为这个 owner 和指定 mint 查询或创建代币账户；链上建账户和广播均由外部主机完成。当前设备不签 ATA 创建交易，首次发送前目的代币账户必须已存在。

`TransferChecked` 绑定 mint 和精度，由链上 Token Program 检查账户状态。消息没有携带目的代币账户的 owner，离线设备不能把手机声称的 owner 当作已验证的钱包地址。本实现显示的是**目的代币账户本身**，不显示虚构的接收人 owner，也不将其标为已验证 ATA。必须按完整 mint 与完整目的代币账户核对收款信息；设备暂不提供独立 ATA 派生/确认接口。

### 离线边界

基础费 5000 lamports 是当前离线费率假设，不是交易内签入的上限。屏幕使用 `EST. FEE`，不能伪称节点确认的实际费用。节点费率、付款账户状态、区块哈希有效期及目标 cluster 由手机验证；Solana message 本身不包含主网/测试网标识。

固件不请求 RPC、不下载元数据，也不查询余额、冻结状态或 mint 状态。无效账户状态可能导致已签交易被节点拒绝并收取网络费。显示、批准及签名都不能证明代币的市场价值或发行方身份。

### 证据

`tests/reference/generate_solana_vectors.py` 使用固定的 solders 0.26.0 生成 `tests/fixtures/solana-sdk.json`；不调用钱包代码。使用公开测试种子及合成 blockhash，**禁止收款，也不代表节点验收**。

`tests/test_solana.py` 对真实 C++ 适配器检查：6 组完整交易字节和显示字段、所有截断位置、错误所有者、批准摘要篡改、短输出缓冲、未知程序、非法账户权限、费用溢出和未解析查找表。Python 测试调用 `solana_probe.exe`；UBSan 构建可通过 `HEXWALLET_SOLANA_PROBE` 指向 `solana_probe_clang.exe`。

`tests/reference/generate_spl_vectors.py` 独立使用 solana-py 0.36.6 编码 SPL 指令、solders 0.26.0 编译并签名；输出 `tests/fixtures/spl-sdk.json`，记录生成器哈希、版本、公开测试种子和合成账户来源。`tests/test_spl.py` 比较 16 组合法交易的完整签名字节及全部审阅字段，覆盖 legacy/v0、多个 mint、SOL 混合转账、16 条转账、uint64 最大值及精度边界。另检查 25 组拒绝案例、每个截断位置、批准后 mint/来源/目的/精度/类型/数量篡改。

`tools/generate_spl2022_vectors.py` 只用 vendored solders 0.28.0（`build/spl-svm-reference`）编译消息、派生 ATA 并签名，输出 `tests/fixtures/spl-2022-sdk.json`；签名由 SDK 完成，不调用固件。`tests/test_spl2022.py` 校验 5 组合法交易的完整签名字节与全部审阅字段（含 legacy/v0、优先级费、0/18 位精度、经典与 Token-2022 混合），以及 7 组拒绝指令（unchecked Transfer、`TransferCheckedWithFee`、hook 额外账户、只读来源、零金额、同 mint 冲突精度、payer 作为来源）、全截断和批准后篡改。`--check` 可验证仓库产物未过期。

`tests/reference/verify_spl_execution.py` 在 solders 0.28.0 自带 LiteSVM 中执行 **C++ 固件实际签出的交易**，保持签名和 blockhash 检查开启。两组正常交易验证扣账、到账和实际费用；七组异常覆盖精度、授权、mint 不匹配、冻结、余额及签名损坏。测试注入账户初始状态，记录 Token Program 内容哈希及执行结果到 `build/spl-svm-execution.json`；CI 保存这个文件。它是独立虚拟机执行证据，不是主网节点验收。

审阅文本使用固定大小的主循环专用缓冲，结束后清空；mint 和来源地址独立渲染并允许换行，避免通用摘要缓冲截断关键身份字段。此处尚无实机帧率或栈余量测量，不能把编译结果当成性能验收。

协议依据：[Solana transactions](https://solana.com/docs/core/transactions)、[fees](https://solana.com/docs/core/fees)、[TransferChecked](https://solana.com/docs/tokens/basics/transfer-tokens)、[经典 Token Program v9.0.0](https://github.com/solana-program/token/tree/program%40v9.0.0)、[Token-2022 extensions](https://spl.solana.com/token-2022/extensions)。整机触屏、SE050 保护和新签交易的节点验收仍需独立证据。

## Stellar 离线签名

*Merged from docs/stellar-signing.md.*

`BEGIN_SIGN kind=9, coin_id=xlm` 接入 Stellar public network。固件不访问 Horizon、RPC 或互联网。主机准备请求并广播结果；设备负责派生密钥、解析 XDR、展示审阅数据、取得本机批准和签名。

### 地址与账户

采用 [SEP-0005](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md) 的 SLIP-0010 Ed25519 路径 `m/44'/148'/x'`。协议的 `address_index` 对应 `x`，通用地址接口的 `account` 和 `change` 必须为零。G 地址编码为版本字节、32 字节公钥和小端 CRC16-XModem 的 RFC 4648 base32。地址显示与签名共用派生路径函数。

### 请求和结果

请求 payload 为：

```
SHA256("Public Global Stellar Network ; September 2015") [32 bytes]
TransactionEnvelope XDR                                [variable]
```

XDR 必须是 `ENVELOPE_TYPE_TX=2`，尾部 signatures 数组长度为零。签名域是网络哈希、envelope 类型和完整 Transaction 的串联；不包含 signatures 数组。设备用 Ed25519 签署该串联的 SHA-256，再返回带一条 DecoratedSignature 的完整 TransactionEnvelope 原始字节。主机可以将其 base64 编码后广播。签名 hint 取发送方公钥末四字节。

字段布局依据 [stellar-xdr](https://github.com/stellar/stellar-xdr/blob/master/Stellar-transaction.x)。不接受主机提供的预计算摘要或解码后的金额。网络哈希不同直接拒绝，不能把 testnet 请求送来后静默改签主网。

### 已开放范围

- 每笔 1–8 个 Payment 或 CreateAccount，所有金额为正的有符号 64 位整数，精度固定为七位。
- Payment 支持原生 XLM 及 alphanum4/alphanum12 资产。设备逐项显示资产代码和发行者 G 地址；同名资产不视为同一资产。
- CreateAccount 显示为创建账户，并审阅初始余额。
- 交易和操作使用普通 G 账户。操作 source 可省略；显式 source 必须等于本机签名账户。
- memo 支持 NONE、ASCII TEXT（最多 28 字节）、uint64 ID、HASH、RETURN HASH。哈希完整显示为十六进制；拒绝 NUL、控制字符和非 ASCII 文本，避免显示与签名字节不一致。
- 必须有 `PRECOND_TIME`，且 `maxTime > minTime`、`maxTime != 0`。显示原始 Unix 秒，不信任手机时钟。设备不证明请求当前有效，账本负责执行有效期规则。
- 手续费下限为每操作 100 stroops，上限为每笔 1 XLM。这是设备策略；网络拥堵时的实际最低费用仍由账本决定。屏幕标为最大费用。

明确拒绝：V0、fee bump、muxed M 地址、PreconditionsV2、已有签名、多签收集、Soroban、DEX/path payment、授权/信任线修改、账户合并、未知扩展以及超过设备上限的交易。拒绝不影响这些功能后续以独立审阅规则接入。

### 批准与验证

沿用设备的两分钟审阅会话和单次批准。签名前重新派生发送方、重新解析原始请求，并逐字段比较来源、目的地、发行者、资产、金额、费用、序列号、有效期、memo 和签名摘要。私钥只在签名期间进入 worker，返回前擦除。任何失败都不返回可用签名。

独立证据由 `tests/reference/generate_stellar_vectors.py` 使用 `stellar-sdk==13.1.0` 生成，存入 `tests/fixtures/stellar-sdk.json`。测试比较固件产生的完整签名 envelope、交易哈希及所有显示字段；同时验证官方 SEP-0005 地址、实际 `derive_address` 路径、13 组 SDK 拒绝向量、逐字节截断、XDR union/填充错误、审阅字段篡改和短输出缓冲区。

SDK 只属于开发端测试依赖，不进入固件。向量使用公开测试助记词和合成账本状态，不能用于存放资产，也不代表主网节点验收。尚需整机显示/按键验收、节点提交验证和独立安全审计。离线设备无法自行验证余额、最低准备金、信任线、发行者授权状态或收款账户的 memo 要求。

## SUI / FIL 原生转账适配器

*Merged from docs/sui-filecoin-signing.md.*

本轮按用户后续指示集中处理 SUI/FIL；其他适配器由另一会话继续。
这里的完成范围是固件地址派生、原生交易解析、审阅、批准后重新校验和签名，
以及独立 SDK 对照。尚未完成真机 NFC/屏幕操作及节点接收验收，不代表所有硬件钱包的全部功能。

### 设备与手机接口

地址请求沿用手机协议的 `ADDRESS`，`coin_id=sui` 或 `fil`。
签名使用 `BEGIN_SIGN kind=14`，`address_index` 选择设备地址，账户和 change 均为 0。
payload 是下面定义的原始 BCS/CBOR 字节，不是哈希，也不带 `SUI1`/`FIL1` 自定义前缀。
最多 2048 字节。手机负责查询链状态、构建未签名交易、收集签名、组装 RPC 请求及广播；
私钥和种子在设备中派生，不通过手机协议输出。

设备从 payload 中解析收款人、金额和费用，校验发送人与本机派生地址一致，
显示发送地址、地址索引及交易明细。用户在设备批准后，签名器重新派生并重解析
相同 payload，对比审阅字段和摘要。篡改审阅、摘要、payload 或索引都会被拒绝。
签名失败时返回长度为 0，并清除调用者提供范围内的输出缓冲区。

### SUI

路径为 `m/44'/784'/0'/0'/index'`，SLIP-0010 Ed25519。
地址为 `0x || hex(BLAKE2b-256(0x00 || public_key))`。

支持的原生 BCS `TransactionData::V1`：

1. `ProgrammableTransaction`，恰好两个 Pure input：input 0 为 8 字节 LE 的 MIST 数额，input 1 为 32 字节目的地址。
2. 恰好两个 command：`SplitCoins(GasCoin, [Input(0)])`，然后 `TransferObjects([NestedResult(0,0)], Input(1))`。
3. 发送人与 gas owner 必须为本机地址；gas payment 为 1–8 个不重复的 ObjectRef，每个 digest 恰好 32 字节。
4. 正 gas price、正 gas budget；设备当前将 budget 上限限制为 100 SUI。显示签入交易的最大费用。
5. expiration 为 None 或 Epoch；所有其他 envelope、参数顺序、命令、额外字节均拒绝。

签名摘要为 `BLAKE2b-256(0x00 0x00 0x00 || TransactionData)`，
使用纯 Ed25519 签该摘要。返回 97 字节 `0x00 || signature[64] || public_key[32]`；
手机将其 Base64 编码，连同原始交易 bytes 提交 Sui RPC。

不支持任意 Move 调用、SPL/ERC 代币、Sui token/NFT、赞助 gas、多接收人、
整枚 gas coin 转移、其他签名方案或其他 PTB 结构。BCS 中没有可供本适配器验证的 chain ID；
网络选择、对象存在性/余额和 gas price 必须由手机与目标节点核实。

实现依据：[Sui 密钥和签名说明](https://docs.sui.io/develop/transactions/transaction-auth/auth-overview)、
[官方 BCS 定义](https://github.com/MystenLabs/ts-sdks/blob/main/packages/sui/src/bcs/bcs.ts)。
测试使用 `@mysten/sui 1.45.2` 独立构建交易及签名。

### FIL

路径为 `m/44'/461'/0'/0/index`，BIP32 secp256k1。
修正了旧编码器使用压缩公钥、缺失前缀/校验和的问题：

```
payload = BLAKE2b-160(uncompressed_SEC1_public_key[65])
checksum = BLAKE2b-32(0x01 || payload)
address = "f1" || base32_lower_no_padding(payload || checksum)
```

旧版本产生的 `ae...`/`ah...` 字符串不是合法 Filecoin f1 地址。派生路径和私钥保持不变，
修复的是公钥序列化和地址编码；新结果已与 Zondax SDK 在多个索引逐字节对照。

输入为 canonical CBOR 10 项 Message：

```
[0, To, From, Nonce, Value, GasLimit, GasFeeCap, GasPremium, 0, h'']
```

发送方仅支持 f1；接收方支持 f1、f3，以及 actor ID >=100 的 f0。
只支持 Send(method 0)、空 params、正 value。金额与 fee cap/premium 最多 128 位，
使用 Filecoin 符号字节加最短大端整数的 bigint 编码。拒绝负数、前导零、
非最短 CBOR 整数、无限长容器、尾随字节、gas premium 高于 fee cap 及总额溢出。
gas limit 为 1..10,000,000,000。设备显示 `GasLimit × GasFeeCap` 的最大 FIL 费用。

摘要与输出：

```
CID = 01 71 a0 e4 02 20 || BLAKE2b-256(MessageCBOR)
signing_digest = BLAKE2b-256(CID)
signature = secp256k1_recoverable_low_S(signing_digest)
SignedMessageCBOR = [Message, bytes(0x01 || r[32] || s[32] || recovery_id)]
```

返回完整 SignedMessage CBOR。使用 Lotus JSON RPC 的手机端必须将其解码为 Message
和 `Signature { Type: 1, Data: base64(r||s||recovery_id) }` 后提交 `MpoolPush`；
不能把整段 CBOR 当作 JSON 的 Signature.Data。

不支持 actor 调用、f2/f4 收款地址、BLS 发送方、FEVM、multisig actor 或其他方法。
消息字节不含 `f`/`t` 网络前缀或 chain ID；前缀不能提供密码学上的主测试网隔离。
nonce、余额、base fee 和目标链仍需节点验证。

实现依据：[Lotus Message 编码](https://github.com/filecoin-project/lotus/blob/master/chain/types/cbor_gen.go)、
[Lotus secp 签名](https://github.com/filecoin-project/lotus/blob/master/lib/sigs/secp/init.go)。
独立签名测试使用 `@zondax/filecoin-signing-tools 2.4.3`。

### 可重复验证

`tests/host/chain` 将真实 `WalletSecurity.cpp` 与 Mbed TLS 3.6.5 链接；
只替换 Arduino Serial 和平台随机数入口，主机随机数使用 Windows BCrypt。
它不链接 `host_security.cpp` 中的 BIP32/secp256k1 失败桩。

```powershell
git clone --depth 1 --branch mbedtls-3.6.5 --recurse-submodules --shallow-submodules https://github.com/Mbed-TLS/mbedtls.git build/chain-mbedtls
powershell -ExecutionPolicy Bypass -File tests/host/build_chain_native.ps1
python -m unittest discover -s tests -p test_sui_filecoin.py
python tools/generate_chain_selftest.py --check
```

构建脚本验证 Mbed TLS commit 为 `e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df`。
SUI/FIL 专用 SDK fixture 和生成器位于 `tests/fixtures/sui-filecoin-sdk.json`、
`tests/reference/generate_chain_vectors.mjs`；只使用明确标注 TEST ONLY 的公开种子。
共享的 `chain-sdk.json` 中其他链向量由其他适配器测试使用，不扩大本次验收范围。

生成器也构建其他链的参考值，因此需将共享 `chain-sdk.json` 中 `sdk` 列出的全部
精确依赖版本安装到 `build/chain-sdk`，再运行以下只比较 SUI/FIL 的命令：

```powershell
node tests/reference/generate_chain_vectors.mjs --sui-filecoin --check
```

独立的 SUI/FIL 回归包含 12 组正向 SDK 向量、75 组拒绝向量、完整截断遍历、
尾随字节、非规范编码、异账户/异索引、审阅替换，以及短缓冲/精确长度缓冲保护。

### 尚需真机验收

仍需在实际板卡验证恢复同一测试种子后的地址、NFC 分包、完整地址显示、批准/拒绝、
超时/锁定/断电，以及将设备输出提交目标链节点后确认接收/执行。
源码和主机回归不能证明 SE050 非导出密钥托管、可信启动或物理攻击防护。

## Tezos 签名边界

*Merged from docs/tezos-signing.md.*

设备解析并签名 Tezos manager operation 的原始字节，或由手机提供的紧凑审阅结构；不连接
节点、不组装 Michelson、不广播。当前只支持主网 `tz1` 源地址。

### 支持范围

- 可选的首个 Ed25519 reveal（tag `0x6b`），无 BLS proof；
- 1–16 个 transaction（tag `0x6c`），仅原生 XTZ 转账到隐式 `tz1`–`tz4`；
- 金额非零，counter 连续，总 fee ≤ 1 XTZ，gas ≤ 1,040,000，storage ≤ 60,000；
- 无 KT1 调用、无参数、无委托、无 FA token、无批量提案/投票。

### 签名

- 待签摘要：`BLAKE2b-256(0x03 || forged_operation)`；
- 签名：Ed25519，输出 `forged_operation || signature`；
- 审阅包含 source、public key、branch、逐笔 recipient/amount/fee/counter/gas/storage；
- 签名前重新解析并逐项比较 source、public key、branch、操作数、金额和摘要；任何不一致拒绝。

### 地址与派生

- 路径：`m/44'/1729'/account'/change'/index'`，全部 hardened，SLIP-0010 Ed25519；
- 地址：`base58check(0x06a19f || BLAKE2b-160(pubkey))`，显示为 `tz1...`；
- branch 只作为 32 字节值审阅，设备不断言它属于当前最长链。

### 证据与验证

- `tests/fixtures/tezos-sdk.json` 与 `src/generated/TezosVectorsTest.inc` 由独立 SDK/Python
  生成；通过 `tezos_probe` 与 `tests/test_tezos.py` 比较完整签名操作、审阅字段和拒绝向量；
- 启动自检比较 SDK 生成的 signed operation（`tezos=pass`）；
- 未执行主网 injection、baker 费市场验收或整机按键验收。

## TRON 原生转账、TRC-10、TRC-20 与 NFT 签名

*Merged from docs/tron-signing.md.*

实现位于 `TronTransaction.cpp`，通过 `WalletSigning` 的设备审批流程接入。手机使用
`BEGIN_SIGN kind=7`、币种 `trx`，payload 为**原始 `raw_data` protobuf 字节**，不是完整
Transaction，也不是 JSON。设备返回 65 字节 `r || s || v`（`v = 27 + recovery id`，low-S）
签名；手机把签名装回 `Transaction.signature` 后自行广播。

路径为 `m/44'/195'/0'/0/<index>`，与地址派生共用 `WalletEngine::derive_address()`。设备先
把派生出的 21 字节地址与 payload 中的 `owner_address` 做常量时间比较，任何不一致都在显示
前拒绝。

### 支持范围

- 原生 TRX：`TransferContract`，金额为 1..2^63-1 sun。
- TRC-10：`TransferAssetContract`，字段为 `asset_name(1)`、`owner_address(2)`、
  `to_address(3)`、`amount(4)`。主网在该字段里放的是链上分配的数字 id（例如
  `1002000` = BTT），节点按这些**字节**解析资产，因此设备原样显示标识符：
  ASCII 直接显示，非 ASCII 以 `0x` 十六进制逐字节显示，绝不用近似字形代替。
  - 已登记 id 使用 `WalletTokens.cpp` 中的 abbr 与精度（BTT `1002000`/6、
    JST `1003000`/6、SEED `1000001`/0，全部由 `wallet/getassetissuebyid` 的发行记录
    回读核对）。
  - 未登记 id 仍然可以签名，但金额按**精确 base unit 整数**显示，并显示
    `ASSET NOT REGISTERED`：发行方自定精度无法离线验证，任何小数点都等于编造。
  - `TransferAssetContract` 不消耗 `fee_limit`，因此出现非零 `fee_limit` 即拒绝。
- TRC-20：`TriggerSmartContract`，接受 `transfer(address,uint256)`（selector
  `a9059cbb`）与 `transferFrom(address,address,uint256)`（selector `0x23b872dd`，
  calldata 恰好 100 字节），且 `call_value == 0`、`call_token_value == 0`、
  `token_id == 0`。`transferFrom` 的 `from` 必须等于本机 owner：与 ERC-721
  `transferFrom` 共享 selector，未登记合约会在随后的注册表检查中被拒绝；同时设备不
  会为“扣第三方余额”的授权调用签名。设备显示 `METHOD` 行区分两种入口。
- TRC-20 合约必须已在 `WalletTokens.cpp` 注册（当前为 Tether 官方公布的
  `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` / USDT，6 位小数）。未注册合约直接拒绝，
  因为离线设备无法可信地获得 symbol 与 decimals。
- TRC-721/1155：`safeTransferFrom`（`0x42842e0e` / `0xf242432a`）的结构化解码器已实现，
  但**当前没有任何 NFT 合约注册记录**，因此所有 TRC-721/1155 请求都以
  `unknown-token` 拒绝。离线设备无法验证合约身份、升级状态和元数据，未经注册就放行等于
  盲签；登记表落地前，这条路径上的显示代码只是待用代码，不构成支持声明。
- 批量转移与任何其他 selector 一律拒绝。
- `owner_permission` 只接受 0（缺省）。`permission_id != 0`、`auths`、`provider`、
  `ContractName` 一律拒绝。
- `raw_data.data`（memo）会完整显示在可信屏幕上：仅接受 1..64 字节可打印 ASCII，
  重复字段、超长或不可打印内容一律拒绝（签名未显示的内容等于盲签）。
- 原生/TRC-10 转账的 `fee_limit` 必须缺省或 0；TRC-20/NFT 的 `fee_limit` 必须在
  (0, 100 TRX] 内。上限见 `kTronMaxFeeLimitSun`。
- `expiration` 与 `timestamp` 都必须存在，且 `0 < expiration - timestamp <= 24h`。
- 金额为 256 位大端字，按注册精度完整格式化；零金额、自转账、全零黑洞地址、非 `0x41`
  前缀地址、截断、多余字节、重复字段、非最短 varint、未知字段全部拒绝。

### 协议字节

`raw_data` 只允许以下字段：

| 字段 | 含义 | 约束 |
| --- | --- | --- |
| 1 | `ref_block_bytes` | 长度 2 |
| 4 | `ref_block_hash` | 长度 8 |
| 8 | `expiration` | int64 毫秒 |
| 10 | `data`（memo） | 1..64 字节可打印 ASCII |
| 11 | `contract` | 恰好 1 条 |
| 14 | `timestamp` | int64 毫秒 |
| 18 | `fee_limit` | int64 sun |

`contract.parameter.type_url` 必须与 `contract.type` 严格对应：
`TransferContract` → `type.googleapis.com/protocol.TransferContract`，
`TransferAssetContract` → `type.googleapis.com/protocol.TransferAssetContract`，
`TriggerSmartContract` → `type.googleapis.com/protocol.TriggerSmartContract`。

签名对象是 `SHA-256(raw_data)`；设备在签名前会重新计算并与审阅时保存的 txID 做常量时间
比较，因此批准后无法替换字节。

### 可信显示

屏幕显示收款地址（Base58Check）、金额（原生 `TRX`、注册代币符号与精度，或 TRC-10 的精确
base unit）、TRC-20 的 `METHOD`、TRC-10 的 `TRC-10 ASSET ID` 与 `PRECISION`、合约地址、
`FEE LIMIT`、`MEMO`（若存在）、过期时间（毫秒）与 txID 前 8 字节。未登记 TRC-10 资产额外
显示 `ASSET NOT REGISTERED`。备注写明：过期时间、ref block、带宽/能量状态由手机侧校验；
离线设备不声称知道链上实际手续费。

### 证据与局限

`src/generated/TronVectorsTest.inc` 是**入库的固定向量表**，每条都注明来源：

- `chain`：`raw_data_hex`、txid 与签名由 TRON 主网 `wallet/gettransactionbyid` 回读，
  自检会用 `sha256(raw_data)` 重新推导 txid 后才使用；
- `derived`：把主网 `raw_data` 逐字段改写并重算 txid，用于覆盖主网流量少见的形态
  （自转 `transferFrom`、memo、未登记 TRC-10 标识符）；没有可复现签名的条目
  `signature_hex` 为 `nullptr`，只证明解析、txid 绑定与显示金额。

启动自检覆盖：TRX、TRC-20 `transfer`、TRC-20 `transferFrom`、TRC-10（BTT 两个真实交易
＋未登记 id）、带 memo 的原生转账；拒绝侧覆盖零金额、`fee_limit` 出现在 TRC-10、
不可打印 memo、超长/重复 TRC-10 标识符、第三方扣款 `transferFrom`、未登记合约、
非法 selector、多合约、截断与多余字节。真实 mbedtls 上启动自检会对本机 owner 的向量比较
**完整 65 字节签名**；主网向量还额外验证 r||s 与 recovery 字节（主网同时存在
`0/1` 与 `27/28` 两种写法）。

未实现、也不得宣传为已支持：多合约交易、`auths`/多签与自定义权限、批量 NFT 转移、
`transferFrom` 扣第三方余额、能量/带宽估算、事件日志解析、广播与节点验收。整机触屏按键、
SE050 托管与主网广播仍需独立证据。

## XRP Payment 签名边界

*Merged from docs/xrp-signing.md.*

设备从手机接收 50 字节紧凑审阅结构，自行构建 XRPL Payment 的规范二进制字段并用
secp256k1 签名；不连接 rippled，不查询账户，不广播。

### 紧凑 payload（大端）

| 偏移 | 内容 |
| --- | --- |
| 0 | version = 1 |
| 1 | has_destination_tag = 0/1 |
| 2 | amount (u64, drops) |
| 10 | fee (u64, drops) |
| 18 | sequence (u32) |
| 22 | last_ledger_sequence (u32) |
| 26 | destination_tag (u32；has_tag=0 时必须为 0) |
| 30 | destination account id (20 bytes) |

设备重新计算 source account（`hash160(compressed pubkey)`），拒绝：
零/超上限金额、fee < 10 或 > 2,000,000 drops、sequence=0、last ledger=0、全零目的账户、
自转账、错误版本/标志、错误 payload 长度。

### 二进制编码

只生成以下字段，按 XRPL 规范顺序：

```
TransactionType (Payment=0), Flags (0x80000000), Sequence,
[DestinationTag], LastLedgerSequence, Amount, Fee, SigningPubKey,
Account, Destination
```

- Amount/Fee：`0x4000000000000000 | drops` 的 8 字节大端；
- Account/Destination：type 8 字段 + `0x14` + 20 字节；
- SigningPubKey：type 7 field 3 + `0x21` + 33 字节压缩公钥；
- 签名摘要：`SHA-512Half(0x53545800 || unsigned_fields)`；
- 签名：secp256k1，低 S，DER 编码后作为 `0x74` (TxnSignature) 字段插入；
- 返回完整 signed binary（不含 `0x53545800` 前缀）。

### 地址

- classic r-address：`Ripple-base58check(0x00 || hash160(compressed pubkey))`；
- 不使用 Bitcoin base58 字母表；固定向量为
  `rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH`；
- destination 由主机提供 20 字节 account id，设备重新编码并显示完整 r-address。

### 证据与限制

- `tests/fixtures/xrp-sdk.json` 由 `xrpl-py` 的 binary codec 生成，覆盖无 tag、tag、零 tag
  三个合格用例和 10 个拒绝用例；`tests/test_xrp.py` 独立重算 unsigned/hash 并驱动 C++ 探针。
- 设备启动自检比较固定 Payment 的 source r-address 与 SHA-512Half；主机无法模拟
  secp256k1，签名路径由设备编译/运行验收。
- 不支持 X-address、issued currency、path、memo、invoice id、partial payment、多签名或
  AccountDelete/TrustSet 等交易；sequence 与 last ledger 的链上新鲜度无法离线断言。
- 尚未执行 rippled 提交、主网序列/费用实测或整机按键验收。

## ERG / XCH review-to-signature binding

*Merged from docs/erg-xch-review-binding.md.*

Both chains were closed while the signature could cover data the screen never
showed. This note records what changed, how it is verified, and what still
blocks admission.

### Chia (XCH): the AGG_SIG_ME data field is now computed on the device

chia-blockchain's `make_aggsig_final_message` signs

```
condition_data || coin_name || genesis_challenge      (raw, unhashed)
```

and the standard puzzle fills `condition_data` with
`sha256tree(delegated_puzzle)`. The payload used to carry that value, which meant
a host could hand over a hash for a *different* condition list and the device
would still show — and sign — its own nicely rendered payment.

`ChiaTransaction.cpp` now builds the delegated puzzle itself as
`(q . conditions)` from the CREATE_COIN recipients and amounts it displays,
hashes it with the verified CLVM tree hasher, and uses that hash as the data
field. The payload field was removed (`XCH1` is 141 fixed bytes + reveal +
conditions), so there is no channel left to substitute another condition list.

Verification (all independently computed, then diffed against the firmware):

| Item | Oracle |
| --- | --- |
| `sha256tree((q . conditions))` | `clvm` package tree hash + `chia/wallet/util/curry_and_treehash.py` |
| 96-byte AGG_SIG_ME message | byte-for-byte against the concatenation rule |
| 96-byte signature | `AugSchemeMPL.sign` with the blspy EIP-2333 key |
| coin id, solution, address | blspy + independent bech32m encoder |
| fitness for the probe | `tests/fixtures/chain-sdk.json` case `xch-0` |

**Still closed for signing**: the BLS secret-scalar arithmetic runs on
variable-time `mbedtls_mpi`, so no constant-time backend exists yet. The catalog
therefore keeps XCH at address capability only; the code path is reachable for
tests, not for the UI.

### Ergo (ERG): the review now covers every output and every token

`ergo_review_payload()` used to show one output chosen by a heuristic and a bare
token *count*, so extra outputs and token attachments could be signed unseen.

The rule is now:

* exactly one output may pay a different address; it is the recipient the screen
  names together with its ERG value;
* every token on that output is printed as `T <id8> <amount>`; if the list does
  not fit the 192-byte review area the call fails with `BufferTooSmall` rather
  than truncating;
* a second external output fails with `Unsupported`;
* outputs back to the sending address are summarised as `CHG n`;
* the fee stays `host input total − outputs` and is labelled `HOST`, because an
  offline device cannot know input values — BitTorrent-style UTXO adapters have
  the same property.

Regression payloads in `run_ergo_self_tests()`: the original happy path, a
two-external-output transaction (refused), a payment carrying one token (shown),
and a payment carrying sixteen maximum-size tokens (refused for lack of room).

### QRL: address indices no longer collide

`qrl_seed_from_bip39()` ignored the address index, so every index produced the
same QRL address. The index is now folded into the domain separator
(`HexWallet/QRL/v2`, index as four big-endian bytes) and the self-test asserts
that index 0 and index 1 give different seeds **and** different addresses.

This changes every QRL address derived by this firmware; the previous values were
index-independent and had to be replaced. QRL signing remains unimplemented for
the reasons listed in the QRL section of `chain-signing.md`: no durable
anti-rollback ledger, no BDS state, no independent signature vector.

## EVM 网络与代币证据表

*Merged from docs/evm-network-evidence.md.*

本文件记录 `WalletNetworks.cpp` / `WalletTokens.cpp` 中 EVM 行的数据来源。原则：
**链 ID 与代币合约必须能指回公开来源**；无法指回的行不应当作生产支持宣传。代币精度以发行方
合约表或链上 token API 为准，不能凭常见值猜测。

### 链 ID

| Network | chain id | 来源 |
| --- | --- | --- |
| Ethereum | 1 | EIP-155 / 链规范 |
| Ethereum Classic | 61 | 链规范 |
| Unichain | 130 | Uniswap Unichain 官方文档（network information） |
| Monad | 143 | Monad 官方文档（network information） |
| Plasma | 9745 | Plasma 官方文档（connect-to-plasma） |
| Berachain | 80094 | Berachain 官方文档（connect-to-berachain） |
| Arc | 5042 | Circle Arc 官方文档（connect-to-arc） |
| X Layer | 196 | chainid.network（链上 EIP-155 注册表）；OKX 官方文档当前不可达 |
| zkSync Era | 324 | chainid.network（EIP-155 注册表）；官方文档未提供稳定直链 |
| OKT Chain | 66 | chainid.network（EIP-155 注册表） |

其余历史 EVM profile（BSC 56、Polygon 137、Avalanche 43114、Arbitrum 42161、Optimism 10、
Base 8453、Linea 59144、Scroll 534352、Blast 81457、Mantle 5000、opBNB 204、Polygon zkEVM 1101、
Aurora 1313161554、Metis 1088、Kaia 8217、Astar 592、Canto 7700、Dogechain 2000、Fuse 122、
Evmos 9001、Harmony 1666600000、Telos 40、Sei EVM 1329、EthereumPoW 10001、Callisto 820、
Etho 1313114、OctaSpace 800001、Etica 61803、Aves 33333、Canxium 3003、Bitnet 210、
Larissa 9898、VirBiCoin 329、Cronos 25、Kava 2222、Gnosis 100、Fantom 250、Core 1116、
Conflux eSpace 1030、Moonbeam 1284、Moonriver 1285、Rootstock 30、Celo 42220）来自各自上线时
核对过的官方网络文档。

### 代币

| Token | Network | 合约 | 精度 | 来源 |
| --- | --- | --- | --- | --- |
| USDC | Unichain | `0x078D782b760474a361dDA0AF3839290b0EF57AD6` | 6 | Circle USDC contract table |
| USDC | Monad | `0x754704Bc059F8C67012fEd69BC8A327a5aafb603` | 6 | Circle USDC contract table |
| USDC | Plasma | `0x2d661C89D812261039AF9764eceaAee884f5F67F` | 6 | Circle USDC contract table |
| USDC | X Layer | `0xB6CEceAB302E2E4948951eE7843FC24E92933061` | 6 | Circle USDC contract table |
| USDC | zkSync Era | `0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4` | 6 | Circle USDC contract table |
| XAUT | Ethereum | `0x68749665FF8D2d112Fa859AA293F07A622782F38` | 6 | Tether supported protocols + Blockscout token API; 2026-10-24 `symbol()`/`decimals()` RPC check |
| PAXG | Ethereum | `0x45804880De22913dAFE09f4980848ECE6EcbAf78` | 18 | Paxos PAX Gold contract; 2026-10-24 `symbol()`/`decimals()` RPC check |
| MANA | Ethereum | `0x0F5D2fB29fb7d3CFeE444a200298f468908cC942` | 18 | Decentraland contract; 2026-10-24 `symbol()`/`decimals()` RPC check |
| MANA | Polygon | `0xA1c57f48F0Deb89f569dFbE6E2B7f46D33606fD4` | 18 | Decentraland Polygon deployment; 2026-10-24 `symbol()`/`decimals()` RPC check |
| USDT | Ethereum / BSC / Arbitrum | 见表内注释 | 6 / 18 / 6 | Tether 官方 supported-protocols 表；BSC 为 Binance-Peg |
| USDC | Ethereum / Base / Arbitrum / Optimism / Polygon / Avalanche | 见表内注释 | 6 | Circle USDC contract table（含 Polygon `USDC.e`） |
| DAI / BTCB / ETH | BSC / Polygon / Arbitrum | 见表内注释 | 18 | 2026-10-24 公开 RPC `symbol()`/`decimals()` 复核 |
| WBNB / CAKE / FDUSD / TUSD / LINK / DOT / ADA / XRP / DOGE / SHIB / UNI / AAVE / ATOM / XVS / BSW / ANKR / COMP / BETH / AVAX / PENDLE | BSC | `WalletTokens.cpp` 的 `bsc-*` 行 | 18（DOGE 8） | 2026-10-28 对 `https://bsc-dataseed.binance.org` 逐合约 `eth_call(symbol, decimals)`；CAKE 的链上 symbol 为 `Cake` |

`USDT0` 行（`xlayer` / `monad` / `plasma` / `bera` / `opt`）按部署地址登记；本文件**未**独立
核实其发行方公告，因此在正式资金路径启用前必须由部署方公告或链上合约再次确认。未确认前
不应把它们称为“USDT”。

### 非 EVM（不要伪装成 EVM）

Starknet 使用 Cairo VM 与 Cairo 交易；Aptos、Sui、TON、NEAR 也不是 EVM。它们需要独立的
交易序列化、签名与审阅适配器，不能通过增加 chain id 来“支持”。同理，TRON 使用 protobuf
与 65 字节 recoverable 签名，已经由 `TronTransaction.cpp` 单独实现。

## 

*Merged from docs/xmr-review.md.*

> 2026-10-24：MSR 已移除，不再接受地址或签名请求。下文 MSR 段落仅保留为历史协议记录；不代表当前支持。SOL 使用 kind=6，详见 [solana-signing.md](chain-protocols.md)。

## Monero on HexWallet: what the device actually verifies

This is the trust model for XMR/MSR signing. It describes what runs on the
device, what comes from the phone, and what stops the phone from lying.

### Roles

The device never talks to a node. There is no network stack in this firmware and
no plan to add one. The phone does all chain I/O and hands the device two things:

1. a transaction to review, already serialized, plus the ring members and
   offsets it wants to spend;
2. the transaction secret key for that transaction.

Everything else the device derives itself from the wallet secrets. The phone is
treated as hostile.

### What `cryptonote_review_transaction` proves

Implemented in `CryptoNoteReview.cpp`; called before anything is displayed or
signed.

| # | Check | What it stops |
| --- | --- | --- |
| 1 | `version == 2 or 3`, `rct.type == 6`, counts match the payload | shape confusion, downgrade to a simpler RCT type |
| 2 | One leading `tx_extra` public key equals `tx_secret·G` (or `tx_secret·D` for the one-output subaddress form); the optional additional-key vector is canonical, length-bound and checked against supplied secrets | inconsistent transaction keys that prevent the recipient from scanning outputs |
| 3 | For each output: one-time key, 8-byte amount ciphertext, view tag recomputed from the selected primary/additional transaction secret, recipient keys and index | showing one recipient/index while paying another |
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
| 14 | Standard outputs and owned change use the primary transaction key; subaddress destinations use the single-destination `rD` form or the output-index-bound additional key | signing a subaddress output without its matching transaction public key |

Check 4 is the one that makes the display trustworthy: the amount shown is an
input to a Pedersen commitment that must match a byte on the wire. The phone
cannot show 1 XMR and commit to 100.

Check 8 uses `cryptonote_derive_secret_key`, so the master spend key is only
ever used as a derivation input; the scalar that signs is the per-output
one-time secret, and it is zeroized before the next input is examined.

### What the device then signs

`cryptonote_sign_input` produces the CLSAG for one input. The scalar it signs
with is `z = c_a − c_out` (real commitment mask minus pseudo output mask), which
is Monero's `zero_commit_sk` in `proveRctCLSAGSimple`. `CryptoNoteReviewResult`
carries that scalar per input, so the signer never recomputes it from untrusted
data.

### Signing is exposed

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

### Masari is a separate path

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

### Subaddress spending

A subaddress output is spent with `b + Hs("SubAddr" || a || major || minor)`
instead of `b`, and the same substitution is applied per input, so one
transaction can mix standard and subaddress coins. `(0, 0)` means the standard
address and keeps the original path.

The payload carries `(major, minor)` per input. XMR output support follows
Monero's construction rules:

- a transaction with exactly one external subaddress destination may use the
  primary secret as `R = rD` and payload version 2;
- a mixed or multi-destination transaction uses payload version 3, with one
  additional secret per output and a canonical `tx_extra` additional-public-key
  vector of the same length;
- for output `i`, a subaddress destination must select additional key `i+1`;
  standard destinations and all change outputs select the primary key (`0`);
- the device verifies `s_i*C_i` for subaddress destinations and `s_i*G` for
  standard destinations, then recomputes the one-time key, amount ciphertext,
  view tag and commitment with the selected derivation;
- external subaddress records carry the spend/view public keys but no claimed
  `(major, minor)` index. Only change may carry indices, and those indices are
  re-derived from the wallet keys before the change label is shown.

MSR remains standard-address-only because its legacy RCT path has no Monero
additional-key construction. Payload version 1 omits subaddress fields and
retains standard-address behavior. Checking ownership of `(D, C)` alone is
not sufficient; the transaction-key binding and output-scanning derivation
must agree as well.

### Fee ceiling

`cryptonote_review_fee_policy` rejects a fee above
`HEXWALLET_XMR_MAX_FEE_ATOMIC` (XMR) or `HEXWALLET_MSR_MAX_FEE_ATOMIC` (MSR),
both 0.1 coin by default, before any curve operation. This is a local firmware
policy, not a live fee estimate. Host requests cannot raise it.

### Ring data authenticity

The device verifies that the ring is internally consistent, that the offsets
match the serialized transaction byte for byte, that the offsets are monotonic,
and that the owned output sits at the claimed `real_index`. It cannot prove
that a decoy exists on chain without chain access. That is inherent to an
offline signer: the phone is trusted only for the **liveness of decoys**, never
for amounts, fees or destinations.

### Verification cost

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

### Test coverage

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

### Remaining limits

* Type-3 Masari (Bulletproofs) needs a mainnet proof vector before it can be
  enabled; the parser currently returns `unsupported` by default. Run
  `tools/fetch_masari_bulletproof_vector.py` against a Masari node to produce the
  vector, and the host self-test will require it to parse and reject single-byte
  edits before you build with `-DHEXWALLET_MSR_ENABLE_RCT_TYPE3=1`.
* XMR/MSR subaddress inputs are supported, but subaddress destinations and
  change are rejected pending independent transaction-key and scanning tests.
* There is no distance bounding on NFC; a relay can forward frames, but the
  on-device buttons and trusted display still gate every signature.

## 

*Merged from docs/xmr-signing.md.*

> 2026-10-24：MSR 已移除，不再接受地址或签名请求。下文 MSR 段落仅保留为历史协议记录；不代表当前支持。SOL 使用 kind=6，详见 [solana-signing.md](chain-protocols.md)。

## XMR / MSR 签名与离线边界

### 设备不联网

硬件只通过 NFC 或用户主动开启的 USB 数据通道接收候选交易，在本机审阅并签名。区块下载、节点查询、广播和节点验收由手机或电脑完成。固件没有 WiFi/HTTP/以太网客户端；PC 侧开发工具访问参考实现或节点，不属于固件联网能力。

### 现在开放的路径

`WalletCatalog` 已开放 XMR 与 MSR 的地址、审阅和签名。链路使用 `BEGIN_SIGN` 的 `kind=5`，请求体携带序列化交易、交易密钥、每个输入的本机输出位置、ring、key offsets 与主机提供的伪输出掩码。请求上限 16 KiB。

审阅通过后：

- 屏幕显示每个输出的金额与地址、找零、手续费和总支出；
- 屏幕明确注明 ring 诱饵由手机提供、离线设备无法证明其链上存在；
- 用户必须按设备上的 APPROVE，手机不能代替按键；
- 签名只在这次批准后执行一次，随后会话清零。

### 地址与签名密钥必须同源

地址派生使用 BIP32 子密钥作为 CryptoNote 种子：

```
m/44'/128'/0'/0/<address_index>  -> child.private_key -> Hs() -> spend, Hs(spend) -> view
```

签名也必须使用同一个子密钥。早期实现直接从 BIP39 种子派生签名密钥，会导致屏幕地址与签名密钥不一致；现在 `derive_cryptonote_keys()` 复用 `derive_address()` 的同一条路径。

#### 子地址消费

XMR 子地址已开放消费：

```
m               = Hs("SubAddr" || a || major || minor)
spend_secret    = b + m
spend_public    = B + m·G
view_public     = a·spend_public        (Monero 的 C = a·D)
```

- 每个输入携带自己的 `(major, minor)`，设备用该子地址的 spend secret 派生一次性私钥并签名；`(0,0)` 就是标准地址，路径不变。
- XMR 单一子地址目的地使用已绑定的 `R = rD`；混合/多目的地使用 payload v3 的每输出 additional transaction public key。设备按输出索引验证秘密、公钥、one-time key、金额密文、view tag 和 commitment，避免签出收款方无法扫描的输出。
- `cryptonote_subaddress_keys()` 的输出与地址编码器 `cryptonote_subaddress_public_keys()` 在同一自检里交叉验证，并对齐 Monero 固定的子地址地址向量 `8AGiXjGVUbB7…`(0,1) 与 `8AGDdrcnAd7R…`(1,0)。
- 自检还证明：用标准 spend secret 无法对子地址输出签出有效 CLSAG（`cryptonote_clsag_sign` 内部要求 `p·G == dest`），只有 `b + m` 可以。
- Masari 的子地址输入采用相同的密钥派生；子地址发送和子地址找零仍关闭，因为 legacy 路径没有 XMR additional-key 语义。

### Monero（XMR）

- RCT type 6、CLSAG、Bulletproofs+、16 成员 ring。
- 每个输出：一次性公钥、8 字节金额密文、view tag、承诺全部重算；显示金额是承诺的输入。
- 每个输入：本机输出在 ring 中的位置、一次性密钥、承诺、key image 全部重算。
- `pseudoOut_i == commit(c_out_i, amount_i)`，`Σ pseudoOut == Σ outPk + fee·H`。
- CLSAG 辅助 key image `D = z·Hp(P)/8` 与线上字节比对。
- ring offsets 必须与序列化交易逐字节一致且严格递增。
- 手续费上限 `HEXWALLET_XMR_MAX_FEE_ATOMIC`（默认 0.1 XMR）在任何曲线运算前拒绝超限。

#### CLSAG 消息哈希

`Keccak(prefix_hash || rct_base_hash || proof_fields_hash)`

`proof_fields_hash` 按 Monero v0.18.4.0 `get_pre_mlsag_hash` 的顺序包含每个 BP+ 的 A、A1、B、r1、s1、d1、L、R；不加入向量长度、V 或 pseudoOut。这是共识消息构造，**不是 BP+ 证明验证**。

#### 签名前不变量

- 全部输入的 key image 与 key offsets 必须在任何一个输入签名前确定；签名函数核对既定 key image，不在签名途中修改 prefix。双输入回归用最终 prefix 校验两个签名，避免单输入自测掩盖问题。
- 构造器要求传入已经确定的证明字节；不能先生成 CLSAG 再补证明。
- `CryptoNoteSpendInput` 含设备内部秘密，不是手机请求格式，禁止直接把手机输入反序列化成该结构。手机格式由 `cryptonote_signing_prepare` 独立解析并核验所有权后才生成内部结构。

### Masari（MSR）

Masari 使用自己的历史 RCT 枚举与 legacy ECDH，不能复用 type-6：

| 类型 | 范围证明 | 签名 | 状态 |
| --- | --- | --- | --- |
| 1 RCTTypeFull | Borromean | 全输入一个 MLSAG | 已实现 |
| 2 RCTTypeSimple | Borromean | 每输入一个 MLSAG | 已实现；用上游真实 TX2 向量验证 Borromean |
| 3 RCTTypeBulletproof | Bulletproofs | 每输入一个 MLSAG | 验证器已实现；默认 `HEXWALLET_MSR_ENABLE_RCT_TYPE3=0`，缺主网向量时返回 `unsupported` |

类型 3 的验证器不是“写完就算”：它必须有链上向量才能启用。流程是

```
python tools/fetch_masari_bulletproof_vector.py --hash <txid> --url <masari-daemon>
```

该工具把节点返回的原始交易写成 `tests/fixtures/masari/tx3.bin` 与 `tx3.json`（记录 txid、来源与 SHA-256）。主机自检一旦看到这个文件就会解析它、校验其中的标准 Bulletproof，并要求单字节篡改被拒绝；没有文件时自检反而要求 type 3 继续 fail-closed。通过后才用 `-DHEXWALLET_MSR_ENABLE_RCT_TYPE3=1` 构建发行固件。

legacy ECDH 为标量加法：`mask + Hs(shared)`、`amount + Hs(Hs(shared))`，不是 ChaCha8，也不是 compact amount。MLSAG 消息为 `Keccak(prefix_hash || rct_base_hash || proofs_hash)`。手续费上限 `HEXWALLET_MSR_MAX_FEE_ATOMIC` 默认 0.1 MSR。

### 性能（可信数字，不夸大）

Bulletproofs+ 验证是审阅阶段的主要成本。`mn`（填充后的标量数量）为 `64 * next_pow2(输出数)`，与 Monero 一致：16 个输出对应 1024 项多指数运算，2 个输出对应 128 项。

主机实测（x86-64，MSVC `/O2`，`bp_plus_probe.exe --bench`）：

| 输出数 | rounds | `mn` | 单证明耗时 |
| --- | --- | --- | --- |
| 1 | 6 | 64 | 67 ms |
| 2 | 7 | 128 | 127 ms |
| 16 | 10 | 1024 | 932 ms |

两项优化把耗时降到原来的约 1/2.2，且结论都通过了 8 份参考证明、真实主网证明与全部篡改测试：

- `point_mul8` 改为扩展坐标下三次倍增（`ed25519_point_mul8_compressed`），一次求逆代替五次；每个 BP+ 生成元都要用它。
- 验证器用扩展坐标累加 + 3 位窗口（`ed25519_extended_add_scaled`），每项不再求逆、不再反复重编码点；窗口表只有 2.5 KiB，验证器整体仍能装进调用方栈。

Bulletproofs+ 验证需要约 7 KiB 栈，接近 Arduino 主循环任务的 8 KiB 上限，因此 CryptoNote 审阅在 24 KiB 的加密 worker 任务上执行（`wallet_worker_begin` / `wallet_worker_wait`），LVGL 更新仍留在调用任务上（LVGL 不是线程安全的）。

尚无这块 ESP32-P4 实机的延迟、栈水位和看门狗数据，不能从主机成绩推算设备性能。审阅与签名均在加密 worker 上执行；调用任务轮询完成状态、刷新 LVGL 并让出 CPU，不处理新的主机请求。启动 worker 失败会拒绝请求，不回退到较小的主循环栈。

任务超过截止时间后，结果失效；调用方仍等到任务实际结束才清除它借用的请求、密钥和缓冲区，避免超时导致悬空指针。超时签名的输出会清零并拒绝返回。此处不是强制取消：如果 worker 不结束，仍需硬件看门狗/复位策略，不能宣称已完成异常实机验收。

### 仍然存在的边界

- **诱饵真实性**：设备能证明 ring 内部一致、包含本机输出、offsets 与交易一致，但无法证明诱饵真的在链上。离线签名器没有链访问；手机只被信任“提供活跃诱饵”，永远不被信任金额、手续费或目的地址。设备额外强制：同一 ring 内成员不得重复、不同输入的 key image 不得重复。
- **Masari type 3**：验证器已实现且默认关闭；用 `tools/fetch_masari_bulletproof_vector.py` 取到主网向量并通过自检后才可启用。
- **子地址目的地址/找零**：XMR 的 `R=rD` 单目的地和 payload v3 additional-key 目的地会验证；MSR 仍拒绝。XMR 找零仍必须是设备重新派生并核对的本钱包地址；子地址输入消费与目的地址构造是不同路径。
- **主网接收验收**：本地审查/签名回归不等于全节点会接收；广播后仍需手机侧节点验收。

### 自测

- `run_cryptonote_review_self_tests()`：额外公钥字段、交易公钥和输出绑定的篡改拒绝。
- `run_cryptonote_signing_self_tests()`：完整请求 -> 审阅 -> 逐输入 CLSAG -> 序列化 -> 验证，另含子地址消费路径（与固定的 Monero 子地址向量交叉验证）。
- `run_masari_self_tests()`：MLSAG 签名/验证、legacy ECDH 解码、真实 TX2 Borromean、type-2 端到端审阅/签名，以及 type 3 的 fail-closed 门禁（有向量时必须通过并拒绝篡改）。
- 主机 `tests/host/build.ps1` 与设备 `device_compile_check.ps1` / `p4_runtime_compile_check.ps1` 都必须通过。

不要把 `cryptonote-signing=pass` 或 `masari=pass` 解释为主网收发已验收。

来源：[Monero v0.18.4.0 rctSigs.cpp](https://github.com/monero-project/monero/blob/v0.18.4.0/src/ringct/rctSigs.cpp)、[masari-project/masari](https://github.com/masari-project/masari)。

## Monero Bulletproofs+ 独立回归

*Merged from docs/xmr-bulletproofs-plus.md.*

参考版本固定为 Monero `v0.18.4.0`，提交 `f1311d4237404ab7da76241dbf10e92a65132cc4`。来源文件及 SHA-256 位于 `tests/reference/monero-reference.json`。参考程序只在开发电脑运行；固件不下载源码、不连接节点。

### 证据与边界

`tests/reference/monero_reference.cpp` 编译固定提交的 `bulletproofs_plus.cc`、`multiexp.cc`、`crypto-ops.c`、`crypto-ops-data.c` 和 `keccak.c`。它不包含、不链接 HexWallet 密码学实现。`adapter/` 提供最小数据类型、RingCT 调用封装、Windows 平台适配和公开的确定性测试随机流。这是隔离的参考算法构建，不是完整 Monero 节点构建；替换项见 `tests/reference/README.md`。

`tests/fixtures/monero-bp-plus/` 保存：

- 1、2、3、4、5、8、9、16 输出的证明，包含零金额、最大 uint64 金额及补齐边界。
- 对应的 V、链上承诺、公开测试金额和掩码、预期接受结果及文件校验和。
- transcript 初始值、V 哈希、各次更新、y/z/e、每轮挑战、sum_y 和实际 multiexp 返回值。
- 2048 个生成元编码。
- 27 个经参考程序拒绝的字段替换、承诺替换、非法点、越界标量、负零点编码和截断样本。
- `review.json`：由参考实现独立派生测试输出掩码并生成的支付/找零证明，用于完整 review 回归。

C++ 主机回归逐项比对证明及中间值；Python 回归核对校验和、所有生成元和无效样本。真实主网证明接受现在是主机测试的必过条件。钱包自测生成的签名不能替代独立证明证据。

### 已修正的兼容性问题

1. 从链上 outPk 重建 `V = outPk * INV_EIGHT` 后再构造 transcript。
2. 挑战展开按折叠树从高位到低位读取索引。
3. `sum_y` 使用 y¹ 至 yᴹᴺ，不包含常数项。
4. Ed25519 压缩点的符号位取规约后 x 的奇偶位，避免把单位元编码成负零。

标量乘法改为标准扩展 Edwards 坐标的固定 256 位循环，最终仅做一次仿射转换求逆。该优化接受同一批独立回归检查；主机耗时不能当作 ESP32-P4 实测性能或侧信道审计结论。

### 复现

首次在开发电脑运行 `tests/reference/fetch_reference.ps1 -Fetch` 下载固定提交文件，之后构建均核验 SHA-256。运行 `generate_bp_plus_fixtures.ps1`、`generate_negative_fixtures.ps1` 和 `generate_review_fixture.ps1` 重建证据；`tools/generate_bp_plus_fixtures.py` 只把既有证据转换成 `BulletproofPlusReferenceTest.inc`。

运行 `tests/host/build.ps1`，再运行 `python -m unittest discover -s tests -p "test_*.py"`。固定材料可离线消费。参考构建使用 MSVC；证据生成不进入正常固件构建。

### 仍不是完整生产钱包

这些结果证明所测 BP+ 样本与固定 Monero 参考算法兼容。它们不等于完成手机协议、可信屏幕授权、SE050C1 解封策略、节点验收、实机故障注入或安全审计。CryptoNote 对外签名仍受目录门禁保护。MSR 不能套用 XMR type-6 路径。

## Monero 主网交易回归

*Merged from docs/xmr-mainnet-vectors.md.*

固定交易：`05357a30c183be26e3b683fd83d8dc0c1c50b1ec01154bbeadd6d1ab027b5676`，高度 3789700，2 输入、4 输出、16 成员环、RCT type 6，序列化长度 2558 字节。

原始字段及来源 URL 保存在 `tools/monero_tx_vectors.json`。`tools/fetch_monero_vector.py` 在开发电脑上从这些字段重建 wire blob，必须同时匹配外部交易 ID 和长度才能写入 `src/generated/MoneroTxVectorsTest.inc`。

Monero v2 的交易 ID 是：

```
Keccak(Keccak(prefix) || Keccak(RCT base) || Keccak(RCT prunable))
```

哈希按原字节顺序显示，不反转。旧工具错误地把反转的前缀哈希当成交易 ID，现已修正。长度相等不能证明字段顺序正确。

`cryptonote_transaction_hash` 与主网 ID 对齐；解析/重写逐字节一致，并校验承诺守恒和 BP+。回归还要求所有截断前缀被固件解析器拒绝。

CLSAG 的签名消息与交易 ID 不同：它使用前缀哈希、RCT base 哈希以及不带长度前缀的 BP+ 字段哈希。不可用完整交易 ID 替代签名消息。

这条历史交易提供真实数据兼容性证据，不等于新构建交易已被节点接收。新交易广播及节点验收只能在手机/电脑完成；设备保持离线。仍需独立主网环成员数据验证 CLSAG，并完成新的有效花费交易的节点验收。
