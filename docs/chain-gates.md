# 能力门槛台账（Chain gates）

这张表存在的唯一理由：**目录里写着 SIGN 的链路必须有可复现的证据，写着 ADDRESS 的链路必须写清缺什么。**
老牌硬件钱包的差距不在"支持多少条链"，而在"每条链的能力边界是否被钉死、是否可审计"。这里逐条列出当前边界、
已完成的证据、以及要把 ADDRESS 变成 SIGN 还差的那一个原语和它的权威验证源。

更新规则：任何一个条目从 ADDRESS 变 SIGN，必须在同一提交里补上对应的验收测试，否则 `policy_check.ps1` 之外
还会有一条人工原则——**没有验收测试的 SIGN 一律视为造假，直接回退。**

## 一、已达成 SIGN 的链路（有独立证据）

| 链路 | 证据类型 | 位置 |
|---|---|---|
| BTC / LTC / DOGE / DGB / BTG / NMC 等 UTXO | PSBT + legacy/BIP143/fork-id 摘要，官方向量 | `bitcoin-sighash`、`run_bitcoin_sighash_self_tests()` |
| DASH | **两笔真实主网交易**的链上签名对本固件算出的摘要验签通过；合成向量逐字节复现 | `chain_probe dash-sign-selftest` |
| ZEC (t1/t3) | 官方 ZIP-243 向量 + 真实 BIP32/ECDSA 签名 | `chain_probe zcash-sign-selftest` |
| XMR / MSR | 官方/独立向量 + CLSAG、金额、view tag | `cryptonote-*` 系列 |
| TRON / TRC-10 / TRC-20 | 主网交易样本 + `transferFrom` + memo | `tron` |
| Cosmos (ATOM/OSMO/TIA) | 独立 protobuf+RFC6979 生成器复现全部旧向量后产出 v2/v3 | `chain_probe cosmos-sign-selftest` |
| SOL / XLM / ALGO / NEAR / XTZ / XRP / KAS / EVM 系 | 各自的向量 + 签名自检 | 见 `docs/validation.md` |
| **QRL**（XMSS/SHAKE-256） | 与 qrllib `src/xmss-alt` 的 `xmss_Signmsg` 在 h=4/6/10、索引 0/1/末叶**逐字节相同**；设备端在释放签名前用独立验证器重建根自检 | `tests/host/qrl_oracle_check.ps1`、`chain.qrl` |
| **XCH**（Chia） | AGG_SIG_ME 消息由设备自建 `sha256tree((q . conditions))`；G1/G2 走仓库内的 BLS12-381 实现（`Bls12381.cpp`，32-bit limb，宿主机与 MCU 同一份代码，不链接第三方配对库），blspy 向量与 RFC 9380 J.10.1 通过 | `chain.bls-g2`、`chain.chia` |
| **DOT / KSM** | 签名载荷布局由 `blake2b-256` 摘要锚定：已知摘要 + 完整 `kExpectedSigned` 逐字节比对，独立 Python 复现同一摘要；runtime 版本钉死 | `chain.polkadot` |
| **APT**（Aptos） | 地址、`RawTransaction` BCS 摘要、Ed25519 authenticator 与 Python `sha3_256` + libsodium 独立实现逐字节一致 | `chain.aptos` |
| **STRK**（Starknet） | Pedersen/Poseidon/Stark ECDSA 与 StarkWare、`@scure/starknet` 公开向量一致；地址、v3 `invoke`/`deploy_account` 哈希与签名与独立 Python 参考实现逐字节一致 | `starknet-crypto`、`chain.starknet` |

### QRL v2（Zond，ML-DSA-87）— 已准入

- **实现位置**：`MlDsa87.cpp`（FIPS 204，参数集 ML-DSA-87：k=8、l=7、η=2、τ=60、γ1=2^19、
  γ2=(q−1)/32、ω=75）、`QrlV2Transaction.cpp`（账户与交易适配器）、`WalletNetworks.cpp` 的 `qrl2`
  profile（BIP44，coin type 238）。
- **地址**：BIP32 `m/44'/238'/account'/change/index` 的子私钥作 ML-DSA 种子；地址 =
  `SHAKE256(01 00 00 ‖ pk, 64)`，显示为 `Q` + 128 位十六进制并按 EIP-55 式规则用第二块 SHAKE256
  决定大小写。自检里钉死了两组独立生成的校验和向量（64×0xAB、0..63 计数器）。
- **交易**：只签 `0x02` 动态费信封
  `rlp([chain_id, nonce, tip_cap, fee_cap, gas, to, value, data, access_list, descriptor, extra])`。
  `chain_id` 必须是主网 1；`descriptor` 必须是 `01 00 00`；`extra_params` 必须为空；`to` 只能是
  64 字节账户或空（合约创建）；费用上限不小于小费上限。设备对**收到的原始字节**做 keccak256，
  再按 FIPS 204 的 `M' = 00 08 "ZOND" 01 01 00 00 ‖ digest` 签名（hedged），返回
  `signature(4627) ‖ public_key(2592)`，签名前先自验。
- **KAT**：keygen 与 sign 与 NIST ACVP（keyGen tc51、sigGen tc61）逐字节一致；verify 的
  `pk` 由签名私钥反推后再验 ACVP 签名，篡改签名/错误消息必须拒绝。
- **内存**：一次 keygen 或 sign 需要约 140 KB 连续堆（`MlDsa87.cpp` 的 workspace）；分配失败
  直接返回 `CryptoFailure`，不会降级、分片或把中间密钥留在栈上。worker 任务超时为 120 s。
- **边界**：只覆盖原生转账与 QRL v2 自身的合约调用信封；代币、质押、多签、跨链消息不在内。QRL v1
  继续走 `qrl`（XMSS），两者目录 ID 不同（`qrl` / `qrl2`），共享 ticker 时按 ID 查找。

### Starknet（STRK）— 已准入

- **实现位置**：`StarknetCrypto.cpp`（Stark 曲线 `y²=x³+x+β`，p=2^251+17·2^192+1；Montgomery 8×32-bit
  域运算；Pedersen 252-bit 子集和；Poseidon Hades rate-2/capacity-1；RFC 6979 Stark ECDSA，含
  `r,w < 2^251−256` 约束且不做 low-S 归一；SNIP-5 地址；Cairo v3 交易哈希）、
  `StarknetTransaction.cpp`（账户与交易适配器）、`WalletNetworks.cpp` 的 `stark` profile
  （BIP44，coin type 9004）、`WalletCustody.cpp` 的 `StarkEcdsa` 托管方案。
- **密钥**：BIP32 子私钥经 `grindKey`（`SHA-256(child‖counter)` 落入 `[1,n)`）得到 Stark 标量，
  账户公钥是其与 G 相乘的 x 坐标。地址行显示 0x + 64 位十六进制**账户公钥**；真正的账户地址是
  合约地址，随 class hash/constructor 变化，因此不预置固定值——由适配器在每笔交易里现算。
- **地址**：`address = pedersen_many([0x5354…4553, 0, salt, class_hash, pedersen_many([pubkey])])
  mod (2^251 − 256)`。适配器只接受单公钥构造账户（`ctor_count == 1`）且 `ctor[0]` 必须等于本机
  Stark 公钥：多签/会话密钥账户在这台设备上无法证明归属，直接拒绝而不是信任手机给的地址。
- **交易**：只签 Cairo v3 两种类型
  `invoke`（账户 `execute` 入口、恰一笔 ERC-20 `transfer`）与 `deploy_account`。
  摘要为 Starknet v3 公式：`Poseidon` 版本的
  `[sn_short("invoke"|"deploy_account"), 3, sender/contract, tip+资源上界哈希, paymaster 空哈希,
  sn_short("SN_MAIN"), nonce, (nonce_da<<32)+fee_da, …]`，链 ID 钉死主网。
  `invoke` 的 calldata 按 Cairo 序列化解析：调用数组长度与头部一致、每笔 span 长度必须是 3、行内数组与
  尾部 span 必须逐 felt 相同，因此屏上每一行就是签名摘要覆盖的那一笔。
- **显示**：账户 class hash（地址就是它的函数，配套 App 只能对照设备显示值核对）、每笔的代币合约与
  收方、nonce、DA 模式、最大费用（`tip + Σ max_amount×max_price`，以 STRK 18 位精确显示）。
  代币金额默认按 base unit 原文显示并标注 `raw`：设备无法证明任意 ERC-20 的小数位，替用户重新标点
  等于伪造精度。只有用户在设备上登记过该合约（`token custom-add stark …`）才按记录换算，并标注
  `USER-DECLARED` / `UNVERIFIED`——记录只是标签，参与签名的仍是 base unit 整数。
- **批量**：一次 `invoke` 最多 4 笔 `transfer`，每笔一行；第 5 笔起直接 `unsupported`，不折叠成摘要。
- **自定义代币**：`WalletCustomTokens` 把 Starknet 键定义为 32 字节合约地址（不是截断的 20 字节），
  与 EVM / TRON / Solana / Stellar 共用一张带 SHA-256 的表。同一笔交易在“有记录 / 无记录”两种状态下
  v3 摘要必须逐字节相同，`chain.starknet` 里比对的就是这一点。
- **KAT**：`StarknetCrypto.cpp` 内嵌 StarkWare `pedersen_params.json` 常量点与公开向量
  （Stark key、Pedersen、Poseidon pair/single、RFC 6979 签名、`grindKey`）；
  `chain.starknet` 进一步钉死账户地址、`execute`/`transfer` 选择子、单笔与两笔（20 felt 批量）
  两种 v3 摘要与 r/s 签名，全部由独立 Python 参考实现产出；拒绝路径覆盖 17 类：伪造构造参数、
  未知 kind、多公钥构造、非法 DA、错误入口、错误选择子、span 不一致、零金额、零代币地址、
  零收方、零 gas 上限、零调用、超过四笔、截断、错误魔数、错误钱包、缓冲区不足。
- **派生验收**：`chain_probe stark-selftest` 用真实 Mbed TLS 的 BIP32 走
  `m/44'/9004'/0'/0/0`，校验 profile→编码器映射（地址必须等于该子密钥的 Stark 公钥）
  以及同一密钥在 class hash/salt 变化时得到不同 SNIP-5 地址。主机套件不派生密钥，
  这一步只在原生链探针里跑，避免把主机 shim 的行为当成真机结论。
- **边界**：不支持 `declare`、`deploy`（非账户）、paymaster 付费、多签/会话密钥账户、
  超过四笔的批量、测试网与其它 L2；`execute` 之外的入口（包括 `__execute__` 旧账户）一律拒绝。

## 二、仍是 ADDRESS / ABSENT 的链路：缺什么、由谁证明

### THETA

- **核实结论**：治理币 THETA **不在 EVM 上**。theta-go 的 `ledger/types/eth_tx_utils.go` 在把以太坊交易
  翻译成 `SmartContractTx` 时写死 `ThetaWei = 0`、`TFuelWei = value`，所以 EVM 交易只能搬 TFUEL；
  原生 THETA 转账必须走 Theta 自己的 `SendTx`（`Fee`/`Inputs`/`Outputs` 的 RLP，`SignBytes` 前置
  `chainID` 编码并加 `addPrefixForSignBytes` 前缀）。
- **仍缺**：`Coins` 的 RLP 布局、`addPrefixForSignBytes` 的前缀字节、以及一条真实主网 `SendTx` 作为
  oracle（反推 `SignBytes` 并验签）。
- **不能做的事**：把 THETA 登记成 EVM profile。那会让用户以为屏上的 THETA 转账被签名，实际签出的是一笔
  TFUEL 交易。

### BEAM

- 交互式 Mimblewimble：没有静态收款地址，花费需要 slate/BBS 多轮交换，签名是内核 Schnorr 签名加上
  rangeproof 与内核承诺。缺的是整个 slate 状态机，不是"再写点序列化"。

### PRL（Pearl）

- 官方 `pearl-research-labs/pearl` 是 Taproot-only 的 Bitcoin 分叉，主网 HRP `prl`，仓库内自带 XMSS 实现。
- **仍缺**：以官方 wallet/node 为 oracle 固定密钥派生、Taproot tweak、sighash、完整签名交易与 XMSS 状态
  管理。只改 Bitcoin 地址前缀不是"支持 PRL"。

## 三、这份台账怎么用

1. 新增链路：先写下"权威验证源"和"验收测试"，再写实现。写不出验证源，就不要写实现。
2. 任何 SIGN 声明都必须能被 `run_catalog_self_tests()` 与上表某一行对上，对不上就是回归。
3. 本文档与 `docs/chain-support.md` 冲突时，以本文档为准并当场修正 `chain-support.md`。
