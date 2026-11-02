# HexWallet - chain-support

> 当前增量状态见 [2026-10-30 修复记录](hardening-2026-10-30.md) 和从编译目录生成的 [原生网络清单](native-chain-capabilities.md)。下文合并表包含历史快照，不能作为当前总数或主网验收证据。

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
| DOT / KSM | Ed25519 SS58 地址；生产签名：`balances.transfer`/`transferKeepAlive`，mortal era + tip，`CheckMetadataHash` 以 mode 0（显式关闭）进入签名载荷 | signed extensions 与 `spec_version`/`transaction_version` 钉死在 `PolkadotTransaction.cpp`（DOT 2005002/26、KSM 2005001/26），genesis 固定；任何不符的载荷在解析阶段就以 `RuntimeMismatch` 拒绝。runtime 升级需要发新固件——这是设备无法在线解析 metadata 的代价，换来的是“载荷布局与扩展列表一定对得上”。历史 DOT1 布局只在宿主测试构建中可见 |
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
| XCH | 生产签名。BLS12-381 的私密标量运算走**仓库内实现**（`Bls12381.cpp`，强制 32-bit limb，宿主机与 MCU 同一份代码；无 `third_party` 依赖），签名前设备自建 `(q . conditions)`、自算 `sha256tree`、自组 AGG_SIG_ME 消息并验签；EIP-2333 派生、权威 curry、bech32m 地址与 blspy 逐字节一致 | 只准入**标准 coin 花费**：每个 `CREATE_COIN` 都在屏上显示，receipt/change 计费与总额对账；CAT/NFT、plot-NFT、offer、多 coin 合并、AggregateSignature 一律拒绝。见 [erg-xch-review-binding.md](chain-protocols.md) |
| QRL | 生产签名，两代账户分别准入。**v1**：XMSS/SHAKE-256（h=10, w=16）完整签名，签名前把一次性叶持久预留到 NVS 双槽记录并回读证明，与 qrllib `xmss_alt` 在 h=4/6/10、索引 0/1/末叶逐字节比对通过。**v2（Zond）**：`qrl2` 用 BIP44 `m/44'/238'/account'/change/index` 子私钥作 ML-DSA-87 种子，地址 `SHAKE256(01 00 00‖pk)` 显示为 `Q`+128 hex；只签 `0x02` 动态费信封，keygen/sign 与 NIST ACVP tc51/tc61 逐字节一致 | v1 只准入原生转账；v2 只准入主网 chain id 1 的动态费信封（`descriptor=010000`、`extra_params` 为空、`to` 为 64 字节账户或空）。两代都不含代币、质押、多签或跨链消息 |
| APT | 生产签名。Ed25519 账户地址 `sha3-256(pk‖0x00)`；设备自建 `RawTransaction` BCS（`0x1::aptos_account::transfer`），签名 `sha3-256("APTOS::RawTransaction"‖BCS)`，输出 `0x00‖sig‖pk` authenticator | 仅原生 APT 转账；无 EntryFunction 任意调用、多签、赞助交易、fa 代币。向量由 Python `sha3_256` + libsodium 独立生成 |
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

新增转账子集：SC v2 单输入 PolicyPublicKey、XEM 原生 v1 transfer、ICP 固定 ledger transfer、Flow EVM 原生转账、Ethereum LSK ERC-20。它们均不等于全功能链适配；Flow Cadence、旧 Lisk L1、多签、staking、任意合约等仍未接入。DOT/KSM、XCH、QRL（v1 XMSS 与 v2 ML-DSA-87）与 APT 的原生转账路径已准入（都只覆盖屏上能显示的那一种交易；QRL v2 另含 `0x02` 动态费信封）。详细格式及证据见 [native-transfer-adapters.md](chain-protocols.md)。

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

THETA、BEAM、PRL 只登记地址（或不登记）。把它们变成“可发送”，需要下面这些**缺一不可**的
工程件；只加一条 `SIGN` 标记会让用户在不知情的情况下签出无效交易，所以不做。

| 链 | 缺的东西 | 验收标准 |
| --- | --- | --- |
| THETA | THETA（治理币）**不是 EVM 资产**：theta-go 的 `eth_tx_utils.go` 把以太坊交易翻译成 `SmartContractTx` 时 `ThetaWei = 0`、`TFuelWei = value`，也就是说 EVM 交易只能搬 TFUEL。原生 THETA 转账必须走 Theta 自己的 `SendTx`（`Fee`/`Inputs`/`Outputs` 的 RLP + `chainID` 前缀的 `SignBytes` + `addPrefixForSignBytes`）。而 TFUEL 可以由现有 EVM 适配器签 | 用一条真实主网 `SendTx` 的原始 RLP 反推 `SignBytes` 并验签通过；`Coins` 的 RLP 布局与 `addPrefixForSignBytes` 前缀字节以官方实现为准逐字节比对 |
| BEAM | 交互式 Mimblewimble：花费要经过 slate/BBS 多轮状态机，链上没有静态收款地址；签名是 Schnorr 内核签名 + rangeproof + 内核承诺，需要对方 slate 才能构造 | 用官方 wallet 做 oracle 完成一次 slate 交换并验证内核签名；在此之前连“地址”都不成立 |
| PRL（Pearl） | 官方 `pearl-research-labs/pearl` 是 Taproot-only 的 Bitcoin 分叉，并在仓库内自带 XMSS 实现；主网 HRP 为 `prl`。接入需要以官方 wallet/node 为 oracle 固定：密钥派生、Taproot tweak、sighash、完整签名交易以及 XMSS 状态管理 | 用官方 wallet 生成地址与签名交易逐字节复现；没有这些，只改 Bitcoin 地址前缀就是假的 |

这三项都不是“再接一条链”，而是各自独立的密码学/协议工程；在没有硬件与上游
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
Starknet 使用 Cairo 而非 EVM，Aptos/Sui/TON/NEAR 也不是 EVM；它们需要各自独立的交易适配器，不应以 EVM profile 冒充。Starknet 已接入自研 Stark 曲线、Pedersen/Poseidon、Stark ECDSA 与 Cairo v3 交易哈希（`StarknetCrypto.cpp`），并由 `StarknetTransaction.cpp` 只准入 `deploy_account` 与「单笔 ERC-20 `transfer`」两种 v3 交易：账户地址由设备用 class hash、salt 与单公钥构造参数重算 SNIP-5 地址，链 ID 钉死 `SN_MAIN`，多调用账户、`declare`、paymaster、多签与非主网一律拒绝。
XLM 已接入主网 XDR Payment/CreateAccount、SEP-0005 地址和 memo/发行者审阅；范围见 stellar-signing.md。NFT ABI 解析器不等于已准入 NFT 合约，实际缺口见 adapter-status.md。

自定义代币覆盖 EVM ERC-20、TRON TRC-20、Solana SPL、Stellar 发行资产与 Starknet ERC-20：每条记录绑定链上原生标识（20/21/32 字节合约或 mint、32 字节 issuer + 资产代码、32 字节 Starknet 合约地址），键宽由网络决定，注册表优先、自定义表其次，屏上固定标注 `USER-DECLARED`/`UNVERIFIED`。记录只影响显示，参与签名的始终是 base unit 整数；没有记录时按原文显示（`1500000 raw`）。入口是设备 CLI 的 `token custom-add*`，整表 blob 带 SHA-256 校验，v1 EVM-only 记录自动升级。

| Ticker | 状态 | 目录条目 / 说明 |
| --- | --- | --- |
| XMR | SIGN | xmr |
| XCH | SIGN | xch（标准 coin 花费；CAT/NFT/offer 拒绝） |
| QRL | SIGN | qrl（v1 原生转账；一次一叶，NVS 预留）、qrl2（v2 动态费信封，ML-DSA-87） |
| APT | SIGN | apt（原生转账；BCS RawTransaction） |
| STRK | SIGN | stark（Stark 曲线账户；Cairo v3 `deploy_account` 与 1–4 笔 ERC-20 `transfer`，地址按 SNIP-5 用 class hash/constructor 现算；金额默认 base unit 原文，登记过的代币才换算并标注未核验） |
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
| ARB | TOKEN | arb1:arb-arb（Arbitrum One 上的 ARB 治理代币） |
| DCR | SIGN | dcr |
| ALGO | SIGN | algo |
| ETH | SIGN | aurora, blast, eth, linea, scroll, unichain, zkevm, zksync |
| SOL | SIGN | sol |
| FLR | SIGN | flare（EVM chain 14，原生 FLR；Flare 官方 RPC eth_chainId 回验） |
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
| DOT | SIGN | dot（balances.transfer / transferKeepAlive，mortal era + tip；signed extensions 钉死在 runtime 2005002/26，genesis 固定，CheckMetadataHash 以显式 disabled 模式上链） |
| FIL | SIGN | fil |
| FTM | SIGN | ftm |
| KAS | SIGN | kas |
| KSM | SIGN | ksm（同 DOT，runtime 钉死 2005001/26） |
| MNT | SIGN | mantle |
| NEAR | SIGN | near |
| POL | SIGN | matic |
| SFP | TOKEN | bsc:bsc-sfp, eth:eth-sfp（SafePal 的 BEP-20 / ERC-20 部署） |
| SUI | SIGN | sui |
| TON | SIGN | ton |
| TRX | SIGN | trx |
| VET | SIGN | vet |
| XLM | SIGN | xlm |
| XPL | SIGN | plasma |
| XRP | SIGN | xrp |
| LINK | TOKEN | eth:eth-link（18 位，链上 symbol/decimals 回验） |
| DAI | TOKEN | eth:eth-dai, matic:matic-dai, bsc:bsc-dai, arb1:arb-dai |
| PYUSD | TOKEN | eth:eth-pyusd（6 位，链上 symbol/decimals 回验） |
| AAVE | TOKEN | eth:eth-aave（18 位，链上 symbol/decimals 回验） |
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
| XDC | SIGN | xdc（EVM chain 50，原生 XDC；官方 RPC eth_chainId 回验） |
| LUNA | ABSENT | no Terra adapter |
| LUNC | ABSENT | no Terra adapter |
| XRD | ABSENT | no Radix adapter |
| TEL | ABSENT | no Telos EVM profile registered |
| KAVA | SIGN | `kava`（Cosmos，`kava_2222-N`、`ukava`）与 `kavaevm`（EVM chain 2222）分开登记，两个都能签 |
| LUNA | SIGN | `terra`（Cosmos，`phoenix-N`、`uluna`）；CW20 与 wasm execute 一律拒绝 |
| LUNC | SIGN | `terraclassic`（Cosmos，`columbus-N`、`uluna`）；同上 |
| ROSE | SIGN | rose（Oasis Sapphire EVM chain 23294，原生 ROSE） |
| ZEN | SIGN | zen（Horizen EON EVM chain 7332，原生 ZEN） |
| SCRT | ABSENT | no Secret Network adapter |
| DERO | ABSENT | no Dero adapter |
| TAO | ABSENT | no Bittensor adapter |
| GRS | 地址与签名可用 | `grs`（SLIP-44 17、version 0x24、bech32 `grs`）。**legacy sighash 已解封**：预映像与 Bitcoin 的 `CTransactionSignatureSerializer` 逐字节相同，但摘要是**单次 SHA-256**——Groestlcoin Core 的 `HashWriter::GetHash()` 只 Finalize 一次（`src/hash.h`，第二次那行被注释掉了），这也是同一个链上 txid = `SHA256(raw)` 而不是 `SHA256d(raw)` 的原因；该链**没有 SIGHASH_FORKID**。判定不是靠推理：块 6324419 的交易 `b566ddf7…5f6c92` 里那段 scriptSig 的 DER 签名，对本实现算出的 `df00bdc1…11b3be` 验签通过，对双 SHA-256 的 `eb2479aa…a79f0d` 验签失败（libsecp256k1 独立复核同样结论）。地址侧不变：base58check 校验和是 **Groestl-512 做两次取前 4 字节**，`review` 走 `address_from_script_groestl`，否则屏上会显示一条链上不存在的地址。范围仍限 P2PKH legacy 输入单笔转账 |
| THETA（原生） | 已接入 `ChainFamily::Theta` | `ThetaTransaction` 逐字节复现主网 `0x1ccc4b6e…063e17bca`（block 1000000）的 `SignBytes` 与 `keccak-256` 摘要 `03490f71…e01cbe`，该交易的 65 字节签名在 chain id `mainnet` 下正好恢复出输入地址。设备请求是 46 字节固定布局（版本/链选择/收款方/金额/手续费/sequence），发送方一律取派生地址，签名输出 `r‖s‖recovery`。网络 id 仍是 `theta`：EVM 转账走 EVM 适配器，原生 SendTx 走这个 family，由载荷格式决定；签名本身在主机自检里只验证拒绝路径，真正的签名由设备/原生探针覆盖 |
| RON | SIGN | `ronin`（EVM chain 2020，原生 RON；未列入 EIP-1559 名单，只签 legacy） |
| ACA | TOKEN | `acalaevm`（Acala EVM chain 787，只签 EVM 侧原生转账）。Substrate 侧 Acala 代币、跨链 XCM 未接入 |
| POKT | ABSENT | no Pocket adapter |
| ICP | SIGN | icp |
| SC | SIGN | sc |
| ICX | SIGN | icx |
| QTUM | SIGN | qtum |
| HIVE | SIGN | hive |
| LSK | TOKEN | eth:eth-lsk |
| XEM | SIGN | xem |

合计：SIGN 60 / REVIEW 0 / ADDRESS 3 / TOKEN 11 / ABSENT 16（共 90 个）

目录声明签名入口：XMR, ZEC, RVN, BTC, BCH, ADA, AVAX, ATOM, CKB, XEC, CRO, DCR, ALGO, ETH, SOL, DOGE, LTC, FIRO, BTG, USDC, BNB, ETC, FIL, FTM, KAS, MNT, NEAR, POL, SUI, TON, TRX, VET, XLM, XPL, XRP, ONE, BSV, ERG, DGB, XTZ, CFX, KAIA, FLOW, BERA, TIA, OSMO, GLMR, HBAR, SEI, ICP, SC, ICX, QTUM, HIVE, XEM, FLR, XDC, ZEN, ROSE


### 本次要求的资产与网络组合

REGISTERED 表示已登记并连接现有签名路径；不是主网验收结果。MISSING 不可作为完整收发功能使用。
原生 ETH 不是 ERC-20；Lightning 需要独立通道状态协议，不能视为 Bitcoin 普通转账。


| 资产 | 网络 | 状态 | 对应代码条目 / 未登记原因 |
| --- | --- | --- | --- |
| SFP | BNB Smart Chain | REGISTERED | bsc-sfp（BEP-20，18 位；issuer 公布地址 + BSC RPC 回验） |
| SFP | Ethereum | REGISTERED | eth-sfp（ERC-20，18 位；同上） |
| USDT | Ethereum | REGISTERED | eth-usdt |
| USDT | TRON | REGISTERED | trx-usdt |
| USDT | BNB Smart Chain | REGISTERED | bsc-usdt（Binance-Peg BSC-USD，18 位；Tether 官方列表不含 BSC 原生 USDT） |
| USDT | Avalanche C-Chain | REGISTERED | avaxc-usdt |
| USDT | Optimism | REGISTERED | opt-usdt |
| USDT | Arbitrum One | REGISTERED | arb-usdt（该地址已被 Tether 原地升级为 USD-T0，链上 symbol 现为 USD-T0，位数仍 6） |
| USDT0 | X Layer | REGISTERED | xlayer-usdt0（Tether 的 USD-T0，6 位） |
| USDT0 | Monad | REGISTERED | monad-usdt0 |
| USDT0 | Plasma | REGISTERED | plasma-usdt0 |
| USDT0 | Berachain | REGISTERED | bera-usdt0 |
| USDT0 | Optimism | REGISTERED | opt-usdt0 |
| USDT0 | Unichain | REGISTERED | unichain-usdt0 |
| USDT0 | Polygon | REGISTERED | matic-usdt0 |
| USDT | X Layer / Berachain / Monad / Plasma / Unichain | NOT DEPLOYED | 这些链上的 Tether 美元是 USD-T0；原生 USDT 没有可核实的部署，登记成 USDT 会显示错误的资产 |
| USDT | Polygon | MISSING | 0xc2132… 是 PoS 桥接资产，权威来源只能取 Polygon 桥文档；未取证前不登记 |
| USDT | Solana | MISSING | 固件没有 SPL 注册表，代币转移路径不存在（原生 SOL 路径不受影响） |
| USDT | TON / Aptos | MISSING | 适配器只有原生转账，没有 jetton / fungible-asset 路径 |
| USDT | OKT Chain / Tempo | MISSING | OKT Chain profile 存在但部署未取证；Tempo 没有网络 profile |
| USDC | Ethereum | REGISTERED | eth-usdc |
| USDC | Arbitrum One | REGISTERED | arb-usdc |
| USDC | Base | REGISTERED | base-usdc |
| USDC | Optimism | REGISTERED | opt-usdc-native |
| USDC | Polygon | REGISTERED | matic-usdc |
| USDC | Avalanche C-Chain | REGISTERED | avaxc-usdc |
| USDC | BNB Smart Chain | REGISTERED | bsc-usdc（Binance-Peg，18 位） |
| USDC | X Layer | REGISTERED | xlayer-usdc |
| USDC | Unichain | REGISTERED | unichain-usdc |
| USDC | Monad | REGISTERED | monad-usdc |
| USDC | Plasma | REGISTERED | plasma-usdc |
| USDC | zkSync Era | REGISTERED | zksync-usdc |
| USDC | Linea | REGISTERED | linea-usdc（Circle 官方地址表 + Linea RPC 回验，6 位） |
| USDC | Celo | REGISTERED | celo-usdc（同上，6 位） |
| USDC | Cronos | REGISTERED | cro-usdc（同上，6 位） |
| USDC | Arc | REGISTERED | arc（USDC 即原生 gas 资产） |
| USDC.e | Polygon | REGISTERED | matic-usdc-e（桥接资产，链上 symbol 仍为 USDC） |
| USDC.e | Optimism | REGISTERED | opt-usdc（同上） |
| USDC | TRON | MISSING | Circle 的地址表没有 TRON 行，未取证不登记 |
| USDC | Solana / Sui / Aptos | MISSING | 没有 SPL / Sui coin / Aptos FA 注册表 |
| USDC | OKT Chain | MISSING | 网络 profile 存在，但 OKT Chain 上的 USDC 部署未取证 |
| USDG | Ethereum | REGISTERED | eth-usdg（Global Dollar，6 位，链上回验） |
| USDG | X Layer | REGISTERED | xlayer-usdg |
| USDG | Arbitrum One | REGISTERED | arb-usdg |
| USDG | Mantle | REGISTERED | mantle-usdg |
| USDG | Solana | MISSING | 没有 SPL 注册表 |
| USDG | Robinhood Chain | MISSING | 网络 profile 已登记（chain 4663），但 USDG 在该链的部署地址尚未取证 |
| DAI | Ethereum / Polygon / Arbitrum One | REGISTERED | eth-dai / matic-dai / arb-dai |
| LINK | Ethereum | REGISTERED | eth-link（18 位，链上 symbol/decimals 回验） |
| PYUSD | Ethereum | REGISTERED | eth-pyusd（6 位，链上回验） |
| AAVE | Ethereum | REGISTERED | eth-aave（18 位，链上回验） |
| ARB | Arbitrum One | REGISTERED | arb-arb（18 位，链上回验） |
| XAUT | Ethereum | REGISTERED | eth-xaut（6 位） |
| PAXG | Ethereum | REGISTERED | eth-paxg（18 位） |
| BTC | Bitcoin | REGISTERED | btc（原生） |
| BTC | X Layer | MISSING | X Layer 上的 BTC 是桥接封装，合约地址未取证 |
| BTC | Lightning | MISSING | 需要通道状态协议，不是普通转账 |
| xBTC | Aptos / Sui / Solana | MISSING | 三条链都没有自研代币注册表 |
| ETH | Ethereum / Arbitrum / Base / Linea / Optimism | REGISTERED | eth / arb1 / base / linea / opt（原生） |
| ETH | X Layer | MISSING | 桥接封装地址未取证 |
| ETH | Robinhood Chain | REGISTERED | robinhood（chain 4663，原生 ETH；Arbitrum Orbit L2） |
| ETH | Starknet | MISSING | Starknet 本身已可 SIGN（STRK 账户 + 单笔 ERC-20 transfer）；该行的 ETH 是 Starknet 上的 ERC-20 部署，合约地址尚未取证，故不登记 |
| ETH | OKT Chain | MISSING | OKT Chain 的 profile 已存在，但原生资产是 OKT；桥接 ETH 地址未取证 |

登记行的可复核方式：`tools/token_audit.ps1` 对每条 EVM 代币行调用链上 `symbol()` / `decimals()` / `name()`，位数不符即失败，仅标签漂移只告警（issuer 会原地改名，例如 USDT → USD-T0）。审计只证明"链上这个合约是这些值"，不证明发行方身份；发行方地址一律取自其官方发布页。
