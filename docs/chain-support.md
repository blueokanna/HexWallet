# HexWallet - chain-support

> **Tooling note (2026-10-28).** The Python/Node oracle harness (	ests/*.py, 	ests/reference/*, 	ools/*.py) was removed at the owner's request: this repository now needs exactly two toolchains, Arduino/xtensa for the device and MSVC or clang plus PowerShell for the host. Every vector those harnesses produced is still pinned in `src/generated/*.inc` and executed by `tests/host/host_test.exe`, so the checks still run on every build. The prose below records the original independent-SDK comparisons; bring the SDKs back if you need to regenerate a fixture.

## 多链与资产接入状态

*Merged from docs/adapter-status.md.*

目录、地址编码、ABI 解码和可批准签名是不同能力。当前真实目录由 `tools/coin_coverage_report.py` 调用编译后的 catalog 导出；新增链只有在交易签名域、显示语义、设备入口和独立向量全部接通后，才登记签名能力。

生产目标 ESP32-P4 默认要求真实安全托管后端。当前没有该后端，因此拒绝导入/生成会话、装载种子和签名；下表描述的是适配器代码能力，不能当作整机可交付证明。见 [security-review-2026-10-28.md](security.md)。

### 已核查的网络与代币

| 网络 / 标准 | 当前实际路径 | 缺口 |
| --- | --- | --- |
| TRON / TRC-10 / TRC-20 | 独立 protobuf、txID、owner 签名；原生 TRX、TRC-10（`TransferAssetContract`，已登记 id 显示精度、未登记 id 显示精确 base unit）、已登记 TRC-20 `transfer` 与自转 `transferFrom`、≤64 字节可打印 memo | 非通用 TRON 合约调用；TRC-721/1155 只有解码器、无合约注册表，请求一律拒绝；批量转移、多合约与第三方扣款 `transferFrom` 拒绝 |
| BNB Smart Chain / BEP-20 | `bsc` 的 EIP-155 legacy 与已登记合约；当前策略拒绝 type-2。新增 WBNB、CAKE、FDUSD、TUSD、LINK、DOT、ADA、XRP、DOGE、SHIB、UNI、AAVE、ATOM、XVS、BSW、ANKR、COMP、BETH、AVAX、PENDLE 等 20 个合约，symbol/decimals 均经 BSC RPC `eth_call` 核对 | 不等于旧 BNB Beacon Chain 的 BEP-2；未登记合约仍拒绝盲签 |
| Polygon | `matic` profile，chain ID 137，原生 POL 与已登记 ERC-20 | MATIC 是历史名称；不是缺少整个网络 |
| Arbitrum One | `arb1` profile，chain ID 42161 与已登记 ERC-20 | 未证明全部合约调用和桥接场景 |
| KAIA | `kaia` 的以太坊兼容交易 | 不含所有 Kaia 原生特殊交易类型 |
| Solana | SOL、SPL/Token-2022 TransferChecked | 不含 Metaplex/pNFT、ATA 创建和完整 NFT 生命周期 |
| TON | 独立 v4R2 cell/BoC 序列化、Ed25519 签名、user-friendly 地址 | 仅空 body 原生转账；无 jetton、comment、多消息订单。见 [erg-xch-review-binding.md](chain-protocols.md) |
| Alephium | 尚无交易适配器 | 不能借 EVM/SPL 路径代替 |
| Stellar | 独立 XDR Payment/CreateAccount、SEP-0005 地址、memo 和发行者审阅 | 具体边界见 [stellar-signing.md](chain-protocols.md) |
| Algorand | 独立 canonical MessagePack、`pay`/`axfer`、ASA 转账与 opt-in、主网 genesis 绑定、note/lease 显示 | 不含 group、rekey、close、clawback、LogicSig、应用调用；具体边界见 [algorand-signing.md](chain-protocols.md) |
| NEAR | 独立 Borsh `TransactionV0`、1–16 个原生 Transfer、Ed25519 隐式账户 | 不含命名账户所有权、FunctionCall、访问密钥/委托；无法离线断言 block hash 来自当前分叉；边界见 [near-signing.md](chain-protocols.md) |
| Tezos | 严格 manager operation、可选 Ed25519 reveal、tz1–tz4 原生转账、BLAKE2b/Ed25519 | 不含 KT1、Michelson、委托、FA token；branch 来源无法离线断言；边界见 [tezos-signing.md](chain-protocols.md) |
| XRP | 独立 Payment 二进制编码、SHA-512Half、secp256k1 DER 签名；classic r-address | 仅原生 XRP Payment；不支持 issued currency、path、memo、partial payment、多签名；sequence/last ledger 由手机提供且无法离线断言 |
| VET | 独立 compact payload、canonical RLP、BLAKE2b-256、secp256k1 recoverable 签名、完整 signed RLP 输出 | 仅单 clause 原生 VET 转账、空 data、主网 chain tag；无合约调用、多 clause、VIP-191 委托；gas base cost 无法离线断言。见 [erg-xch-review-binding.md](chain-protocols.md) |
| ICX | 独立 `icx_sendTransaction` canonical 序列化、SHA3-256、secp256k1 recoverable 签名 | 仅原生 ICX 转账；无 SCORE 调用；nid/nonce/timestamp 由手机提供且需节点校验。见 [erg-xch-review-binding.md](chain-protocols.md) |
| DOT / KSM | Ed25519 SS58 地址；生产签名入口关闭 | 历史 SCALE 编解码保留测试；没有可信 runtime metadata / signed extensions 校验，不能声明当前主网转账可用 |
| DCR | 独立 BLAKE-256、legacy prefix/witness sighash、P2PKH 地址、secp256k1 签名 | 仅单输入透明 P2PKH 转账；无 stake ticket、treasury、mix。见 [erg-xch-review-binding.md](chain-protocols.md) |
| CKB | Molecule `RawTransaction`、`ckb-default-hash` BLAKE2b、SECP256K1/blake160 lock、recoverable 签名 | 仅单输入、1–2 个输出、无 type script；无 DAO/UDT。见 [erg-xch-review-binding.md](chain-protocols.md) |
| SUI | 独立 BCS split-gas 原生 SUI 转账、Ed25519 地址与签名；真实固件代码通过官方 SDK 对照 | 无 Move 调用、赞助交易或代币；真机与节点验收待完成。见 [sui-filecoin-signing.md](chain-protocols.md) |
| FIL | 修正 f1 地址编码；独立 CBOR `Send`、CID 签名、f1 发送方；真实固件代码通过 SDK 对照 | f0/f1/f3 接收方；无 actor 调用、BLS 签名；真机与节点验收待完成。见 [sui-filecoin-signing.md](chain-protocols.md) |
| FIRO | 透明 P2PKH 地址与 Bitcoin legacy sighash PSBT 签名 | 不含 Lelantus/Spark 隐私交易；仅透明 UTXO |
| QTUM | P2PKH 地址与 Bitcoin/BIP143 PSBT 签名 | 不含 Qtum EVM 合约调用；仅透明 UTXO |
| HIVE | 单 transfer，二进制 Asset、Graphene compact 规范签名，独立 dhive 对照 | STM 是公钥而非收款地址；账户名及 active authority 需节点验证；不含加密 memo |
| ICP | 默认 ICP ledger account；固定 ledger canister 的 Candid transfer、请求 ID、Ed25519 签名及 CBOR envelope | 官方 SDK 6 组对照；非任意 canister、ICRC、staking；自定义 SLIP10 路径不等于 Ledger 恢复兼容 |
| ADA | Ledger 风格 CIP-1852/BIP32-Ed25519、原生 ADA body CBOR 审阅、Ed25519-BIP32 签名 | 仅主网原生 ADA；body 不含 input value/owner，UTxO 所有权与余额必须由节点校验；无 token/script/staking。见 [erg-xch-review-binding.md](chain-protocols.md) |
| ERG | P2PK（ProveDlog）生产签名：设备重建交易 ID 预映像、生成 56 字节 Schnorr 证明并返回完整签名交易。审核现在把**唯一对外输出**与它的**每一个代币**都显示出来：出现第二个对外输出、或代币列表放不下时直接拒绝签名（`Unsupported`/`BufferTooSmall`），退回本钱包的输出只汇总为 `CHG n` | 生产可用。手续费由主机提供（屏上标注 `HOST`，离线设备无法自证输入金额）；脚本输入、多签与非 P2PK 一律拒绝。见 [erg-xch-review-binding.md](chain-protocols.md) |
| XCH | Chia 地址已与 blspy 逐字节一致（EIP-2333 原始盐、权威 curry、独立 bech32m）。AGG_SIG_ME 的 data 字段改为**设备自算** `sha256tree((q . conditions))`，签名与屏上收款内容绑定；CLVM 树哈希、coin id、solution、签名均有独立向量 | 只登记地址。签名仍关闭：BLS 私密标量运算使用变时 MPI，尚无可信常数时间实现；修复绑定后该问题成为唯一阻塞项。见 [erg-xch-review-binding.md](chain-protocols.md) |
| QRL | 旧版 XMSS/SHAKE256 公钥/地址；与 qrllib 1.3.2 对照。一次性索引的持久化预留已实现（`QrlOtsJournal`：双槽冗余写入 + 回读校验 + 高水位恢复，掉电/单槽损坏都不会倒退） | 仍不提供签名：XMSS 的 WOTS+ 签名与 BDS 遍历状态尚未实现，没有它就没有可签的东西，预留层单独存在不构成签名能力。零号树保留 v1 恢复，其余索引采用钱包自定义 v2 域；不声明官方助记词兼容 |
| AE | SLIP-0010 `m/44'/457'/0'/0'/i'`，`ak_` + base58(pubkey‖SHA-256d 校验)；固定向量在 `run_alt_address_self_tests()` | 仅地址；没有经过审计的原生 spend 交易、费用策略和签名路径 |
| RYO | BIP44 `m/44'/382'/0'/0/i`，CryptoNote 双密钥 long address，varint 前缀 `0x2ce192`；编码器复用 Monero/Masari 向量并通过 Ryo 向量 | 仅地址；Ryo 的 RingCT/交易格式未接入，不能声明收付可用 |
| ZANO | BIP44 `m/44'/1018'/0'/0/i`，CryptoNote 双密钥 `Zx` 地址，前缀 `0xc5`；与 zano `tests/unit_tests/base58.cpp` 向量逐字节一致 | 仅地址；没有标准子地址前缀，子地址 API 返回 `InvalidArgument`；签名关闭 |

### 未接入的截图币种（明确原因）

| 币种 | 原因 |
| --- | --- |
| Beam / Grin / MimbleWimbleCoin / Epic Cash | 交互式 Mimblewimble，没有静态链上收款地址；收款/花费需要 slate/BBS 多轮状态机，不能把 slatepack 端点伪装成地址 |
| Super Zero (SERO) | 64/96 字节 superzk 公钥包，不是单密钥地址；本仓库没有经过审计的编码与签名路径 |
| Swap (XWP) / Evolution (EVOX) / VeriBlock (VBK) | 当前 SLIP-0044 没有对应 coin type；复用其它链的 coin type 会造成跨域密钥复用，必须等上游注册与独立向量 |
| Veil (VEIL) | 已作为 Bitcoin-family fork 接入透明 P2PKH 签名；Zerocoin/环签名隐私交易不支持 |

### NFT 的实际边界

`TokenCalldata.cpp` 已有 ERC-721/1155 等 ABI 解析器。ERC-721 `safeTransferFrom`（`0x42842e0e`）与 ERC-1155 `safeTransferFrom`（`0xf242432a`）的 selector 唯一，设备可以在没有 NFT 合约注册记录时解析并显示合约地址、标准和未登记警告；但无法离线验证合约身份、升级状态或元数据。与 ERC-20 共享 selector 的 `transferFrom`、批量转移和 receiver hook 被拒绝，未知 calldata 不允许盲签。因此这是“可审阅的标准转移”，不是“全量 NFT 生命周期支持”。

Ethereum、BSC、Polygon、Arbitrum 和 KAIA 的 ERC-721/1155 唯一 selector 转移已可审阅，但合约身份、升级状态、链上元数据和余额无法离线核实。TRON 的 TRC-721/1155 只有解码器，没有合约注册表，请求一律以 `unknown-token` 拒绝。TON、Solana、Alephium 的 NFT 还需要各自的消息格式和所有权/转移语义。主机提供的名称、图片和 ticker 不能作为安全审阅依据。

### 尚未完成的独立适配器

新增转账子集：SC v2 单输入 PolicyPublicKey、XEM 原生 v1 transfer、ICP 固定 ledger transfer、Flow EVM 原生转账、Ethereum LSK ERC-20。它们均不等于全功能链适配；Flow Cadence、旧 Lisk L1、多签、staking、任意合约等仍未接入。DOT/KSM 与 XCH 不准入生产签名（ERG 的 P2PK 路径已准入）。详细格式及证据见 [native-transfer-adapters.md](chain-protocols.md)。

### 已撤回或从未成立的准入

| 名称 | 原因 | 当前状态 |
| --- | --- | --- |
| QUBIC | Qubic 身份是 FourQ 曲线 + KangarooTwelve，不是 Ed25519/SHA3。旧实现用 Ed25519 公钥的 SHA3/base26 结果冒充地址，会产出不可花费的身份 | 网络 profile、`AddressEncoding::QubicBase26`、base26 编码器和自检向量已整体删除；`find_network_profile("qubic")` 必须返回 `nullptr`（生产策略测试断言）。没有 FourQ/K12 实现与独立向量前不得重新登记 |
| FLUX | 2026-10-23 的 MiningPoolStats 快照把 FLUX 归入 GRAVEYARD；项目规则禁止 GRAVEYARD 身份进入生产注册表（与 MSR 同样处理） | 目录条目、网络 profile、ZIP-243 签名策略与分支 ID 已移除。ZIP-243 引擎仍由 ZEC 使用（含 t3 P2SH-P2PK 花费）并有独立向量；FLUX 在 `tools/coin_coverage_report.py` 中保留为 REQUESTED，报告显示 `ABSENT` |
| MSR | Masari 已不在活跃列表 | 仅保留底层算法回归材料；无 profile、无目录条目、无签名入口 |

`tests/test_graveyard.py` 现在同时检查 `WalletNetworks.cpp`、`WalletCatalog.cpp`、
三个生成文件与 `tools/fork_registry.json`，并断言 FLUX/MSR/QUBIC 不会回流；矿池表
的每一行还必须指向目录里真实存在的条目，否则测试失败。

### 只登记地址的链：还差什么

DOT/KSM、XCH、QRL 只登记地址。把它们变成“可发送”，需要下面这些**缺一不可**的
工程件；只加一条 `SIGN` 标记会让用户在不知情的情况下签出无效交易，所以不做。

| 链 | 缺的东西 | 验收标准 |
| --- | --- | --- |
| DOT / KSM | 可信 runtime metadata：需要在构建期固定一份 metadata 及其哈希，并要求签名载荷携带 `CheckMetadataHash`（mode 1）与该哈希一致；同时固定 spec_version 与交易版本 | 设备能拒绝任何 `spec_version`/metadata 哈希不符的载荷；`transfer_keep_alive` 与 `transfer_allow_death` 的字段有 upstream 向量；mortal era 与 tip 的显示经过审阅 |
| XCH | BLS12-381 私密标量的常数时间运算（当前 G1/G2 使用变时 MPI），以及 AGG_SIG_ME 与输出绑定的完整覆盖（已完成） | 常数时间实现的独立评审 + 侧信道测试；签名只对屏上显示的 `CREATE_COIN` 生效 |
| QRL | XMSS WOTS+ 签名 + BDS 遍历状态（每签一次要能推出下一棵认证路径，否则只能每次从头重算整棵树）。持久化预留层已完成并通过掉电/损坏测试，剩下的就是签名算法本身 | 与 qrllib 的 XMSS 签名向量逐字节比对；同一种子重新导入时必须从高水位继续或直接拒绝签名；OTS 索引在屏上显示 |

这三项都不是“再接一条链”，而是各自独立的密码学/存储工程；在没有硬件与上游
向量的情况下写出来只会是“看起来支持”。

每条链仍需确定支持的交易类型、派生路径、网络域、序列化规则、签名算法、设备显示字段、费用/重放策略和上游独立向量，再完成链路集成及节点验收。不能仅增加 ticker、复用 Bitcoin sighash 或套用 EVM profile。

目前没有证据支持“对标所有厂商的全部能力”“生产级安全认证”或“零漏洞”这样的结论。验收记录只陈述实际运行过的检查；整机、密钥托管和物理安全边界见 [hardware-readiness.md](security.md)。

## 币种覆盖（由 `tools/coin_coverage_report.py` 生成）

*Merged from docs/coin-coverage.md.*

数据来源：`tests/host/catalog_dump.exe (resolved catalog)`。

`SIGN` 表示代码目录声明签名能力，不等同于节点验收、全部交易类型或生产安全认证。
`TOKEN` 是已登记的 EVM/TRC-20 代币合约，前提是所属网络本身可签名。
`ADDRESS` 只能派生地址；`ABSENT` 表示这棵树里没有对应适配器。
原链清单来自本脚本的 `REQUESTED`；资产与网络组合来自 `tools/requested_asset_networks.json`。
MSR 已按用户要求移除；SOL 支持原生转账、SPL Token 与 Token-2022 TransferChecked（Token-2022 显示扩展风险警告，拒绝 ATA 创建）；TRX 支持原生 TRX、TRC-10（已登记 id 带精度，未登记 id 只显示精确 base unit）、已登记 TRC-20 `transfer`/自转 `transferFrom`、≤64 字节可打印 memo（仅 owner 权限）；ATOM/OSMO/TIA 支持 Cosmos SDK 单笔 1..4 条 MsgSend（可选 memo、任意 denom；无固定精度的 denom 显示精确 base unit；无 IBC 报文/authz）；ZEC 仅透明地址 v4（t1 P2PKH 与 t3 P2SH-P2PK 输入，多签与其它 redeem 形式拒绝）。SIGN 不代表该链全部交易类型。
Starknet 使用 Cairo 而非 EVM，Aptos/Sui/TON/NEAR 也不是 EVM；它们需要各自独立的交易适配器，不应以 EVM profile 冒充。
XLM 已接入主网 XDR Payment/CreateAccount、SEP-0005 地址和 memo/发行者审阅；范围见 stellar-signing.md。NFT ABI 解析器不等于已准入 NFT 合约，实际缺口见 adapter-status.md。

| Ticker | 状态 | 目录条目 / 说明 |
| --- | --- | --- |
| XMR | SIGN | xmr |
| XCH | ADDRESS | xch |
| ZEC | SIGN | zec |
| DASH | SIGN | dash（type-0 P2PKH 普通支付，主网摘要向量锚定；特殊交易类型与 InstantSend 锁状态由手机侧判断） |
| RVN | SIGN | rvn |
| BTC | SIGN | btc, btc44, btc49 |
| BCH | SIGN | bch |
| ADA | SIGN | ada |
| AVAX | SIGN | avaxc |
| ATOM | SIGN | atom |
| CKB | SIGN | ckb |
| XEC | SIGN | xec |
| CRO | SIGN | cro |
| XAUT | TOKEN | eth:eth-xaut |
| ARB | ABSENT | no profile in this tree |
| DCR | SIGN | dcr |
| ALGO | SIGN | algo |
| ETH | SIGN | aurora, blast, eth, linea, scroll, unichain, zkevm, zksync |
| SOL | SIGN | sol |
| FLR | ABSENT | no profile in this tree |
| DOGE | SIGN | doge, dogechain |
| LTC | SIGN | ltc, ltc49, ltc84 |
| FIRO | SIGN | firo |
| FLUX | ABSENT | no profile in this tree |
| BTG | SIGN | btg, btg49, btg84 |
| AION | ABSENT | no Aion adapter |
| USDT | TOKEN | eth:eth-usdt, bsc:bsc-usdt, arb1:arb-usdt, avaxc:avaxc-usdt, opt:opt-usdt, kaia:kaia-usdt, celo:celo-usdt, trx:trx-usdt |
| USDC | SIGN | arc |
| BNB | SIGN | bsc |
| ETC | SIGN | etc |
| DOT | ADDRESS | dot |
| FIL | SIGN | fil |
| FTM | SIGN | ftm |
| KAS | SIGN | kas |
| KSM | ADDRESS | ksm |
| MNT | SIGN | mantle |
| NEAR | SIGN | near |
| POL | SIGN | matic |
| SFP | ABSENT | no EVM profile for this chain id |
| SUI | SIGN | sui |
| TON | SIGN | ton |
| TRX | SIGN | trx |
| VET | SIGN | vet |
| XLM | SIGN | xlm |
| XPL | SIGN | plasma |
| XRP | SIGN | xrp |
| LINK | ABSENT | no profile in this tree |
| DAI | TOKEN | eth:eth-dai, matic:matic-dai, bsc:bsc-dai, arb1:arb-dai |
| PYUSD | ABSENT | no profile in this tree |
| AAVE | ABSENT | no profile in this tree |
| PAXG | TOKEN | eth:eth-paxg |
| MANA | TOKEN | eth:eth-mana, matic:matic-mana |
| ASTER | ABSENT | no profile in this tree |
| ONE | SIGN | harmony |
| BSV | SIGN | bsv |
| ERG | SIGN | erg |
| DGB | SIGN | dgb, dgb49, dgb84 |
| KDA | ABSENT | no Kadena adapter |
| XTZ | SIGN | xtz |
| CFX | SIGN | cfx |
| KAIA | SIGN | kaia |
| FLOW | SIGN | flow-evm |
| BERA | SIGN | bera |
| TIA | SIGN | tia |
| OSMO | SIGN | osmo |
| AXL | ABSENT | no Cosmos SDK protobuf signer |
| ZETA | ABSENT | no Cosmos SDK protobuf signer |
| GLMR | SIGN | glmr |
| HBAR | SIGN | hbar |
| SEI | SIGN | seievm |
| IOTA | ABSENT | no IOTA adapter |
| XDC | ABSENT | no XinFin adapter |
| LUNA | ABSENT | no Terra adapter |
| LUNC | ABSENT | no Terra adapter |
| XRD | ABSENT | no Radix adapter |
| TEL | ABSENT | no Telos EVM profile registered |
| ROSE | ABSENT | no Oasis adapter |
| ZEN | ABSENT | no Horizen fork profile admitted |
| SCRT | ABSENT | no Secret Network adapter |
| DERO | ABSENT | no Dero adapter |
| TAO | ABSENT | no Bittensor adapter |
| THETA | ABSENT | no Theta adapter |
| POKT | ABSENT | no Pocket adapter |
| ICP | SIGN | icp |
| SC | SIGN | sc |
| ICX | SIGN | icx |
| QTUM | SIGN | qtum |
| HIVE | SIGN | hive |
| LSK | TOKEN | eth:eth-lsk |
| XEM | SIGN | xem |

合计：SIGN 56 / REVIEW 0 / ADDRESS 3 / TOKEN 6 / ABSENT 25（共 90 个）

目录声明签名入口：XMR, ZEC, RVN, BTC, BCH, ADA, AVAX, ATOM, CKB, XEC, CRO, DCR, ALGO, ETH, SOL, DOGE, LTC, FIRO, BTG, USDC, BNB, ETC, FIL, FTM, KAS, MNT, NEAR, POL, SUI, TON, TRX, VET, XLM, XPL, XRP, ONE, BSV, ERG, DGB, XTZ, CFX, KAIA, FLOW, BERA, TIA, OSMO, GLMR, HBAR, SEI, ICP, SC, ICX, QTUM, HIVE, XEM


### 本次要求的资产与网络组合

REGISTERED 表示已登记并连接现有签名路径；不是主网验收结果。MISSING 不可作为完整收发功能使用。
原生 ETH 不是 ERC-20；Lightning 需要独立通道状态协议，不能视为 Bitcoin 普通转账。

| 资产 | 网络 | 状态 | 对应代码条目 |
| --- | --- | --- | --- |
| USDT | X Layer | MISSING | 未完成/未核实具体资产部署 |
| USDT | Ethereum | REGISTERED | eth-usdt |
| USDT | TRON | REGISTERED | trx-usdt |
| USDT | Aptos | MISSING | 未完成/未核实具体资产部署 |
| USDT | Arbitrum One | REGISTERED | arb-usdt |
| USDT | BNB Smart Chain | REGISTERED | bsc-usdt |
| USDT | Avalanche C-Chain | REGISTERED | avaxc-usdt |
| USDT | Berachain | MISSING | 未完成/未核实具体资产部署 |
| USDT | Monad | MISSING | 未完成/未核实具体资产部署 |
| USDT | Optimism | REGISTERED | opt-usdt |
| USDT | Plasma | MISSING | 未完成/未核实具体资产部署 |
| USDT | Polygon | MISSING | 未完成/未核实具体资产部署 |
| USDT | Solana | MISSING | 未完成/未核实具体资产部署 |
| USDT | Tempo | MISSING | 未完成/未核实具体资产部署 |
| USDT | TON | MISSING | 未完成/未核实具体资产部署 |
| USDT | Unichain | MISSING | 未完成/未核实具体资产部署 |
| USDT | OKT Chain | MISSING | 未完成/未核实具体资产部署 |
| USDC | X Layer | REGISTERED | xlayer-usdc |
| USDC | Ethereum | REGISTERED | eth-usdc |
| USDC | TRON | MISSING | 未完成/未核实具体资产部署 |
| USDC | Aptos | MISSING | 未完成/未核实具体资产部署 |
| USDC | Arbitrum One | REGISTERED | arb-usdc |
| USDC | Arc | REGISTERED | arc (native) |
| USDC | Avalanche C-Chain | REGISTERED | avaxc-usdc |
| USDC | Base | REGISTERED | base-usdc |
| USDC | Monad | REGISTERED | monad-usdc |
| USDC | Optimism | REGISTERED | opt-usdc-native |
| USDC | Polygon | REGISTERED | matic-usdc |
| USDC | Solana | MISSING | 未完成/未核实具体资产部署 |
| USDC | Sui | MISSING | 未完成/未核实具体资产部署 |
| USDC | Unichain | REGISTERED | unichain-usdc |
| USDC | OKT Chain | MISSING | 未完成/未核实具体资产部署 |
| USDC | BNB Smart Chain | REGISTERED | bsc-usdc |
| USDC.e | Polygon | REGISTERED | matic-usdc-e |
| DAI | Ethereum | REGISTERED | eth-dai |
| DAI | Polygon | REGISTERED | matic-dai |
| DAI | Arbitrum One | REGISTERED | arb-dai |
| XAUT | Ethereum | REGISTERED | eth-xaut |
| USDG | X Layer | MISSING | 未完成/未核实具体资产部署 |
| USDG | Ethereum | MISSING | 未完成/未核实具体资产部署 |
| USDG | Solana | MISSING | 未完成/未核实具体资产部署 |
| USDG | Robinhood Chain | MISSING | 未完成/未核实具体资产部署 |
| BTC | X Layer | MISSING | 未完成/未核实具体资产部署 |
| BTC | Bitcoin | REGISTERED | btc (native) |
| BTC | Lightning | MISSING | 未完成/未核实具体资产部署 |
| xBTC | Aptos | MISSING | 未完成/未核实具体资产部署 |
| xBTC | Sui | MISSING | 未完成/未核实具体资产部署 |
| xBTC | Solana | MISSING | 未完成/未核实具体资产部署 |
| ETH | X Layer | MISSING | 未完成/未核实具体资产部署 |
| ETH | Ethereum | REGISTERED | eth (native) |
| ETH | Arbitrum One | REGISTERED | arb1 (native) |
| ETH | Base | REGISTERED | base (native) |
| ETH | Linea | REGISTERED | linea (native) |
| ETH | Optimism | REGISTERED | opt (native) |
| ETH | Robinhood Chain | MISSING | 未完成/未核实具体资产部署 |
| ETH | Starknet | MISSING | 未完成/未核实具体资产部署 |
| ETH | Unichain | REGISTERED | unichain (native) |
| ETH | zkSync Era | REGISTERED | zksync (native) |
| ETH | OKT Chain | MISSING | 未完成/未核实具体资产部署 |

