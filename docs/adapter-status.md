# 多链与资产接入状态

目录、地址编码、ABI 解码和可批准签名是不同能力。当前真实目录由 `tools/coin_coverage_report.py` 调用编译后的 catalog 导出；新增链只有在交易签名域、显示语义、设备入口和独立向量全部接通后，才登记签名能力。

生产目标 ESP32-P4 默认要求真实安全托管后端。当前没有该后端，因此拒绝导入/生成会话、装载种子和签名；下表描述的是适配器代码能力，不能当作整机可交付证明。见 [security-review-2026-10-28.md](security-review-2026-10-28.md)。

## 已核查的网络与代币

| 网络 / 标准 | 当前实际路径 | 缺口 |
| --- | --- | --- |
| TRON / TRC-20 / NFT | 独立 protobuf、txID、owner 签名；原生 TRX、已登记 TRC-20、唯一 selector 的 TRC-721/1155 safeTransferFrom | 非通用 TRON 合约调用；未登记 NFT 合约只显示警告，不验证身份/元数据；批量转移和回调数据拒绝 |
| BNB Smart Chain / BEP-20 | `bsc` 的 EIP-155 legacy 与已登记合约；当前策略拒绝 type-2 | 不等于旧 BNB Beacon Chain 的 BEP-2 |
| Polygon | `matic` profile，chain ID 137，原生 POL 与已登记 ERC-20 | MATIC 是历史名称；不是缺少整个网络 |
| Arbitrum One | `arb1` profile，chain ID 42161 与已登记 ERC-20 | 未证明全部合约调用和桥接场景 |
| KAIA | `kaia` 的以太坊兼容交易 | 不含所有 Kaia 原生特殊交易类型 |
| Solana | SOL、SPL/Token-2022 TransferChecked | 不含 Metaplex/pNFT、ATA 创建和完整 NFT 生命周期 |
| TON | 独立 v4R2 cell/BoC 序列化、Ed25519 签名、user-friendly 地址 | 仅空 body 原生转账；无 jetton、comment、多消息订单。见 [erg-xch-review-binding.md](erg-xch-review-binding.md) |
| Alephium | 尚无交易适配器 | 不能借 EVM/SPL 路径代替 |
| Stellar | 独立 XDR Payment/CreateAccount、SEP-0005 地址、memo 和发行者审阅 | 具体边界见 [stellar-signing.md](stellar-signing.md) |
| Algorand | 独立 canonical MessagePack、`pay`/`axfer`、ASA 转账与 opt-in、主网 genesis 绑定、note/lease 显示 | 不含 group、rekey、close、clawback、LogicSig、应用调用；具体边界见 [algorand-signing.md](algorand-signing.md) |
| NEAR | 独立 Borsh `TransactionV0`、1–16 个原生 Transfer、Ed25519 隐式账户 | 不含命名账户所有权、FunctionCall、访问密钥/委托；无法离线断言 block hash 来自当前分叉；边界见 [near-signing.md](near-signing.md) |
| Tezos | 严格 manager operation、可选 Ed25519 reveal、tz1–tz4 原生转账、BLAKE2b/Ed25519 | 不含 KT1、Michelson、委托、FA token；branch 来源无法离线断言；边界见 [tezos-signing.md](tezos-signing.md) |
| XRP | 独立 Payment 二进制编码、SHA-512Half、secp256k1 DER 签名；classic r-address | 仅原生 XRP Payment；不支持 issued currency、path、memo、partial payment、多签名；sequence/last ledger 由手机提供且无法离线断言 |
| VET | 独立 compact payload、canonical RLP、BLAKE2b-256、secp256k1 recoverable 签名、完整 signed RLP 输出 | 仅单 clause 原生 VET 转账、空 data、主网 chain tag；无合约调用、多 clause、VIP-191 委托；gas base cost 无法离线断言。见 [erg-xch-review-binding.md](erg-xch-review-binding.md) |
| ICX | 独立 `icx_sendTransaction` canonical 序列化、SHA3-256、secp256k1 recoverable 签名 | 仅原生 ICX 转账；无 SCORE 调用；nid/nonce/timestamp 由手机提供且需节点校验。见 [erg-xch-review-binding.md](erg-xch-review-binding.md) |
| DOT / KSM | Ed25519 SS58 地址；生产签名入口关闭 | 历史 SCALE 编解码保留测试；没有可信 runtime metadata / signed extensions 校验，不能声明当前主网转账可用 |
| DCR | 独立 BLAKE-256、legacy prefix/witness sighash、P2PKH 地址、secp256k1 签名 | 仅单输入透明 P2PKH 转账；无 stake ticket、treasury、mix。见 [erg-xch-review-binding.md](erg-xch-review-binding.md) |
| CKB | Molecule `RawTransaction`、`ckb-default-hash` BLAKE2b、SECP256K1/blake160 lock、recoverable 签名 | 仅单输入、1–2 个输出、无 type script；无 DAO/UDT。见 [erg-xch-review-binding.md](erg-xch-review-binding.md) |
| SUI | 独立 BCS split-gas 原生 SUI 转账、Ed25519 地址与签名；真实固件代码通过官方 SDK 对照 | 无 Move 调用、赞助交易或代币；真机与节点验收待完成。见 [sui-filecoin-signing.md](sui-filecoin-signing.md) |
| FIL | 修正 f1 地址编码；独立 CBOR `Send`、CID 签名、f1 发送方；真实固件代码通过 SDK 对照 | f0/f1/f3 接收方；无 actor 调用、BLS 签名；真机与节点验收待完成。见 [sui-filecoin-signing.md](sui-filecoin-signing.md) |
| FIRO | 透明 P2PKH 地址与 Bitcoin legacy sighash PSBT 签名 | 不含 Lelantus/Spark 隐私交易；仅透明 UTXO |
| QTUM | P2PKH 地址与 Bitcoin/BIP143 PSBT 签名 | 不含 Qtum EVM 合约调用；仅透明 UTXO |
| HIVE | 单 transfer，二进制 Asset、Graphene compact 规范签名，独立 dhive 对照 | STM 是公钥而非收款地址；账户名及 active authority 需节点验证；不含加密 memo |
| ICP | 默认 ICP ledger account；固定 ledger canister 的 Candid transfer、请求 ID、Ed25519 签名及 CBOR envelope | 官方 SDK 6 组对照；非任意 canister、ICRC、staking；自定义 SLIP10 路径不等于 Ledger 恢复兼容 |
| ADA | Ledger 风格 CIP-1852/BIP32-Ed25519、原生 ADA body CBOR 审阅、Ed25519-BIP32 签名 | 仅主网原生 ADA；body 不含 input value/owner，UTxO 所有权与余额必须由节点校验；无 token/script/staking。见 [erg-xch-review-binding.md](erg-xch-review-binding.md) |
| ERG | P2PK（ProveDlog）生产签名：设备重建交易 ID 预映像、生成 56 字节 Schnorr 证明并返回完整签名交易。审核现在把**唯一对外输出**与它的**每一个代币**都显示出来：出现第二个对外输出、或代币列表放不下时直接拒绝签名（`Unsupported`/`BufferTooSmall`），退回本钱包的输出只汇总为 `CHG n` | 生产可用。手续费由主机提供（屏上标注 `HOST`，离线设备无法自证输入金额）；脚本输入、多签与非 P2PK 一律拒绝。见 [erg-xch-review-binding.md](erg-xch-review-binding.md) |
| XCH | Chia 地址已与 blspy 逐字节一致（EIP-2333 原始盐、权威 curry、独立 bech32m）。AGG_SIG_ME 的 data 字段改为**设备自算** `sha256tree((q . conditions))`，签名与屏上收款内容绑定；CLVM 树哈希、coin id、solution、签名均有独立向量 | 只登记地址。签名仍关闭：BLS 私密标量运算使用变时 MPI，尚无可信常数时间实现；修复绑定后该问题成为唯一阻塞项。见 [erg-xch-review-binding.md](erg-xch-review-binding.md) |
| QRL | 旧版 XMSS/SHAKE256 公钥/地址；与 qrllib 1.3.2 对照 | 不提供签名；OTS helper 只是数值规则，不是持久化防回滚。零号树保留 v1 恢复，其余索引采用钱包自定义 v2 域；不声明官方助记词兼容 |

## NFT 的实际边界

`TokenCalldata.cpp` 已有 ERC-721/1155 等 ABI 解析器。ERC-721 `safeTransferFrom`（`0x42842e0e`）与 ERC-1155 `safeTransferFrom`（`0xf242432a`）的 selector 唯一，设备可以在没有 NFT 合约注册记录时解析并显示合约地址、标准和未登记警告；但无法离线验证合约身份、升级状态或元数据。与 ERC-20 共享 selector 的 `transferFrom`、批量转移和 receiver hook 被拒绝，未知 calldata 不允许盲签。因此这是“可审阅的标准转移”，不是“全量 NFT 生命周期支持”。

Ethereum、BSC、Polygon、Arbitrum 和 KAIA 的 ERC-721/1155 唯一 selector 转移已可审阅，但合约身份、升级状态、链上元数据和余额无法离线核实；TRON 的 TRC-721/1155 走同一唯一 selector 子集并显示未登记警告。TON、Solana、Alephium 的 NFT 还需要各自的消息格式和所有权/转移语义。主机提供的名称、图片和 ticker 不能作为安全审阅依据。

## 尚未完成的独立适配器

新增转账子集：SC v2 单输入 PolicyPublicKey、XEM 原生 v1 transfer、ICP 固定 ledger transfer、Flow EVM 原生转账、Ethereum LSK ERC-20。它们均不等于全功能链适配；Flow Cadence、旧 Lisk L1、多签、staking、任意合约等仍未接入。DOT/KSM 与 XCH 不准入生产签名（ERG 的 P2PK 路径已准入）。详细格式及证据见 [native-transfer-adapters.md](native-transfer-adapters.md)。

## 已撤回或从未成立的准入

| 名称 | 原因 | 当前状态 |
| --- | --- | --- |
| QUBIC | Qubic 身份是 FourQ 曲线 + KangarooTwelve，不是 Ed25519/SHA3。旧实现用 Ed25519 公钥的 SHA3/base26 结果冒充地址，会产出不可花费的身份 | 网络 profile、`AddressEncoding::QubicBase26`、base26 编码器和自检向量已整体删除；`find_network_profile("qubic")` 必须返回 `nullptr`（生产策略测试断言）。没有 FourQ/K12 实现与独立向量前不得重新登记 |
| FLUX | 2026-10-23 的 MiningPoolStats 快照把 FLUX 归入 GRAVEYARD；项目规则禁止 GRAVEYARD 身份进入生产注册表（与 MSR 同样处理） | 目录条目、网络 profile、ZIP-243 签名策略与分支 ID 已移除。ZIP-243 引擎仍由 ZEC 使用并有独立向量；FLUX 在 `tools/coin_coverage_report.py` 中保留为 REQUESTED，报告显示 `ABSENT` |
| MSR | Masari 已不在活跃列表 | 仅保留底层算法回归材料；无 profile、无目录条目、无签名入口 |

`tests/test_graveyard.py` 现在同时检查 `WalletNetworks.cpp`、`WalletCatalog.cpp`、
三个生成文件与 `tools/fork_registry.json`，并断言 FLUX/MSR/QUBIC 不会回流；矿池表
的每一行还必须指向目录里真实存在的条目，否则测试失败。

## 只登记地址的链：还差什么

DOT/KSM、XCH、QRL 只登记地址。把它们变成“可发送”，需要下面这些**缺一不可**的
工程件；只加一条 `SIGN` 标记会让用户在不知情的情况下签出无效交易，所以不做。

| 链 | 缺的东西 | 验收标准 |
| --- | --- | --- |
| DOT / KSM | 可信 runtime metadata：需要在构建期固定一份 metadata 及其哈希，并要求签名载荷携带 `CheckMetadataHash`（mode 1）与该哈希一致；同时固定 spec_version 与交易版本 | 设备能拒绝任何 `spec_version`/metadata 哈希不符的载荷；`transfer_keep_alive` 与 `transfer_allow_death` 的字段有 upstream 向量；mortal era 与 tip 的显示经过审阅 |
| XCH | BLS12-381 私密标量的常数时间运算（当前 G1/G2 使用变时 MPI），以及 AGG_SIG_ME 与输出绑定的完整覆盖（已完成） | 常数时间实现的独立评审 + 侧信道测试；签名只对屏上显示的 `CREATE_COIN` 生效 |
| QRL | XMSS 一次性签名的持久化预留与防回滚：需要至少两个独立存储槽 + 单调计数器，能抵抗掉电与种子恢复后的索引复用 | 掉电测试（写一半断电）、恢复测试（同一种子重新导入必须从高水位继续或拒绝签名）、以及 OTS 索引在屏上显示 |

这三项都不是“再接一条链”，而是各自独立的密码学/存储工程；在没有硬件与上游
向量的情况下写出来只会是“看起来支持”。

每条链仍需确定支持的交易类型、派生路径、网络域、序列化规则、签名算法、设备显示字段、费用/重放策略和上游独立向量，再完成链路集成及节点验收。不能仅增加 ticker、复用 Bitcoin sighash 或套用 EVM profile。

目前没有证据支持“对标所有厂商的全部能力”“生产级安全认证”或“零漏洞”这样的结论。验收记录只陈述实际运行过的检查；整机、密钥托管和物理安全边界见 [hardware-readiness.md](hardware-readiness.md)。
