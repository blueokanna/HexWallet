# 链支持

[English](Supported-Chains) · [首页](Home-zh)

固件内置 246 个网络配置，钱包目录对外提供 214 个条目。逐链节点回执及 SDK 比对结果见[验证记录](validation)。

能力位是字面意思：`address` 能派生并显示地址，`review` 能把载荷解析成可审查字段，`sign` 能产出签名，
`token-account` 表示该网络有代币登记表。RyoCurrency 和 Zano 仅开放收款地址。Hive 提供账户密钥签名，没有收款地址。

## UTXO 及同类

| 条目                                                                             | 路径                    | 范围                                                                                                                                                  |
| -------------------------------------------------------------------------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `btc`                                                                            | BIP84 `m/84'/0'/0'/0/i` | PSBT v0/v2、P2WPKH、BIP143                                                                                                                            |
| `btc49`                                                                          | BIP49                   | P2SH-P2WPKH、BIP143                                                                                                                                   |
| `btc44`                                                                          | BIP44                   | P2PKH、legacy sighash，legacy 输入需要 `non_witness_utxo`                                                                                             |
| `btc86`                                                                          | BIP86                   | P2TR key-path、`SIGHASH_DEFAULT`/`ALL`、无脚本树                                                                                                      |
| `prl`                                                                            | BIP86                   | Pearl 主网，只支持 Taproot key-path；不做 P2MR、XMSS 或脚本路径                                                                                       |
| `zec` | BIP44 | NU7 v5 透明交易、ZIP-244、t1 P2PKH 与 t3 P2SH-P2PK |
| `dash`                                                                           | BIP44                   | 专用适配器：type-0 普通支付、legacy 摘要、P2PKH/P2SH 输出；每个输入带资助交易，手续费是算出来的而不是主机给的；InstantSend 意图会显示，锁离线不可验证 |
| `kas`                                                                            | BIP44                   | BIP340 Schnorr、v0 交易、`SIGHASH_ALL`、KIP-0009 mass                                                                                                 |
| `ltc`、`ltc49`、`ltc84`、`doge`、`rvn`、`vtc*`、`btg*`、`dgb*`、`grs*`、`axe` 等 | 各自配置                | 核对过 sighash 家族的 UTXO 分叉：legacy、BIP143、`SIGHASH_FORKID`、Groestl-512                                                                        |

105 个分叉配置由 `tools/fork_registry.json` 生成。准入条件是上游 `chainparams` 里 base58 版本对应
legacy P2PKH sighash，且交易头没有 `nTime`、没有宽 `nType`。带时间戳 sighash 或宽交易头的链一律不进：
Bitcoin legacy 签名器绝不用来猜。

## EVM

62 条网络共用一个签名器：EIP-155，需要访问列表的链走 EIP-2930，支持的链走 EIP-1559。原生转账、
已登记 token 调用、任意 calldata、合约创建都可以签；不是已登记 token 调用的 calldata 会以原始字节
加 keccak-256 显示，绝不解码成转账。

| 区块链/货币名称         | 缩写代号 (Symbol) | 描述                                                                                             |
| ----------------------- | ----------------- | ------------------------------------------------------------------------------------------------ |
| **Acala EVM**           | ACA               | 波卡 (Polkadot) 生态的去中心化金融 (DeFi) 中心及稳定币平台，兼容 EVM。                           |
| **Arbitrum One**        | ARB (ETH\*)       | 基于 Optimistic Rollup 技术的以太坊头部 Layer 2 扩容网络。                                       |
| **Arc**                 | ARC               | 兼容 EVM 的区块链网络，致力于去中心化应用 (DApp) 与 Web3 基础设施开发。                          |
| **Astar**               | ASTR              | 波卡生态的多链智能合约平台，同时支持 EVM 和 WASM 虚拟机。                                        |
| **Aurora**              | AURORA (ETH\*)    | 构建在 NEAR 协议上的以太坊虚拟机 (EVM)，为 NEAR 提供以太坊生态兼容性。                           |
| **Avalanche C-Chain**   | AVAX              | 雪崩协议 (Avalanche) 的智能合约链，专注于高吞吐量、低延迟的 EVM 应用。                           |
| **Aves**                | AVS               | 基于工作量证明 (PoW) 且兼容 EVM 的独立第一层 (Layer 1) 区块链网络。                              |
| **Base**                | ETH\*             | 由 Coinbase 孵化、基于 OP Stack 构建的以太坊 Layer 2 网络（无独立原生代币）。                    |
| **Berachain**           | BERA              | 基于流动性证明 (Proof-of-Liquidity) 共识机制的高性能 EVM 等效 Layer 1 区块链。                   |
| **Binance Smart Chain** | BNB               | 币安智能链（现称 BNB Chain），由币安推出的高吞吐量、低手续费 EVM 兼容公链。                      |
| **Bitlayer**            | BTC\*             | 基于 BitVM 范式构建的比特币 Layer 2 网络，具备图灵完备的智能合约且兼容 EVM。                     |
| **Bitnet**              | BTN               | 兼容 EVM 的独立公链网络，旨在提供低成本的交易与去中心化应用部署环境。                            |
| **Blast**               | BLAST (ETH\*)     | 为 ETH 和稳定币提供原生收益 (Native Yield) 的以太坊 Optimistic Rollup Layer 2 网络。             |
| **Canto**               | CANTO             | 基于 Cosmos SDK 构建的 EVM 兼容公链，主打“免费公共基础设施”(FPI) 的 DeFi 生态。                  |
| **Canxium**             | CAU               | 主打离线挖矿机制与水电驱动概念的 EVM 兼容区块链。                                                |
| **Celo**                | CELO              | 专注于移动端普及、微支付和现实世界资产 (RWA) 的碳中和 EVM 兼容网络（现已向以太坊 L2 演进）。     |
| **Conflux eSpace**      | CFX               | 树图区块链 (Conflux) 的全兼容 EVM 子空间，结合树图共识实现高吞吐量。                             |
| **Core**                | CORE              | 结合比特币工作量证明与委托权益证明的“中本聪加号”(Satoshi Plus) 共识 EVM 公链。                   |
| **Cronos**              | CRO               | 由 Crypto.com 推出的 EVM 兼容公链，基于 Cosmos SDK 构建，聚焦 DeFi 与链游。                      |
| **Dogechain EVM**       | DOGE / DC         | 基于 Polygon Edge 构建的独立 EVM 链，旨在为狗狗币 (Dogecoin) 引入智能合约与 DeFi 场景。          |
| **Ethereum**            | ETH               | 全球最大的去中心化智能合约平台，也是所有 EVM 兼容链的技术标准源头。                              |
| **Ethereum Classic**    | ETC               | 以太坊原链，在 2016 年 The DAO 硬分叉事件后坚持“代码即法律”并保持 PoW 共识。                     |
| **EthereumPoW**         | ETHW              | 以太坊在 2022 年转向权益证明 (PoS) 后，由矿工社区分叉并保留工作量证明 (PoW) 的公链。             |
| **Etho Protocol**       | ETHO              | 结合以太坊智能合约与去中心化存储 (IPFS) 节点的 EVM 兼容网络。                                    |
| **Etica**               | EGAZ              | 专注于开放源医学研究资助、无专利医药研发的去中心化 PoW 区块链。                                  |
| **Evmos EVM**           | EVMOS             | Cosmos 生态的 EVM 枢纽，通过跨链通信协议 (IBC) 将以太坊资产与应用引入 Cosmos。                   |
| **Fantom**              | FTM (S)           | 采用 Lachesis 异步拜占庭容错共识的高速 DAG 智能合约平台（近期已升级为 Sonic）。                  |
| **Flare**               | FLR               | 专注于数据获取的 EVM 兼容 Layer 1 区块链，内置预言机与跨链数据互操作协议。                       |
| **Flow EVM**            | FLOW              | 著名 NFT 与消费级公链 Flow 推出的 EVM 等效环境，实现 Cadence 与 Solidity 生态互通。              |
| **Fuse**                | FUSE              | 专注于移动支付、稳定币结算和商业高频微交易的轻量级 EVM 兼容公链。                                |
| **Gnosis Chain**        | xDAI (GNO)        | 以太坊的长期生态侧链（原 xDai 链），使用稳定币 xDAI 作为原生 Gas 费代币，由 GNO 负责治理与质押。 |
| **Harmony EVM**         | ONE               | 采用有效权益证明 (EPoS) 和分片技术的高扩展性、低成本 EVM 兼容公链。                              |
| **Kaia**                | KAIA              | 由韩国巨头 Kakao 旗下的 Klaytn 与 LINE 旗下的 Finschia 合并而成的亚洲旗舰级 EVM 公链。           |
| **Kava EVM**            | KAVA              | 采用“共链”(Co-Chain) 架构的 Layer 1 公链，将 Cosmos 的速度与以太坊 EVM 的开发生态结合。          |
| **Larissa Chain**       | LRS               | 采用工作量证明 (PoW) 并结合去中心化节点架构的 EVM 兼容公链。                                     |
| **Linea**               | ETH\*             | 由以太坊基础设施巨头 Consensys 研发的 zkEVM Layer 2 扩容网络。                                   |
| **Mantle**              | MNT               | 采用模块化架构、由大型去中心化自治组织 (DAO) 驱动的以太坊 Layer 2 网络。                         |
| **Merlin Chain**        | MERL (BTC\*)      | 专注于赋能比特币原生资产（如铭文、BRC-20）与生态的 ZK-Rollup 比特币 Layer 2 网络。               |
| **Metis Andromeda**     | METIS             | 主打去中心化排序器 (Decentralized Sequencer) 与链上自治组织 (DAC) 的以太坊 Layer 2 网络。        |
| **Monad**               | MON               | 主打并行执行 (Parallel Execution) 与超高性能（目标 10,000 TPS）的新一代 EVM 兼容 Layer 1 公链。  |
| **Moonbeam**            | GLMR              | 波卡 (Polkadot) 主网上的完全兼容以太坊的智能合约平行链。                                         |
| **Moonriver**           | MOVR              | Moonbeam 的姊妹网络，部署在波卡先行网 Kusama 上的 EVM 兼容平行链。                               |
| **Oasis Sapphire**      | ROSE              | Oasis Network 推出的业界首个机密 EVM (Confidential EVM) 运行环境，专为隐私智能合约设计。         |
| **OctaSpace**           | OCTA              | 结合分布式云计算、渲染、VPN 服务与 GPU 算力租赁的 EVM 兼容区块链。                               |
| **OKT Chain**           | OKT               | 由 OKX 交易所推出的基于 Cosmos 架构且 100% 兼容 EVM 的高性能公链（原 OKExChain）。               |
| **opBNB**               | BNB\*             | 基于 OP Stack 构建的 BNB Chain 高性能 Layer 2 扩容网络，主打游戏与高频交易。                     |
| **Optimism**            | OP (ETH\*)        | 以太坊 Optimistic Rollup 扩容方案的先驱，也是 OP Stack 超级链 (Superchain) 生态的核心。          |
| **Plasma**              | PLASMA            | 经典的区块链二层扩容架构概念，或指专注稳定币零手续费结算与高吞吐的专用 EVM 网络。                |
| **Polygon**             | POL (原 MATIC)    | 最主流的以太坊扩容与基础设施平台之一（PoS 侧链），现已向 Polygon 2.0 聚合网络升级。              |
| **Polygon zkEVM**       | ETH\* (POL)       | Polygon 推出的基于零知识证明 (ZK-Rollup) 技术的以太坊 Layer 2 EVM 等效网络。                     |
| **Robinhood Chain**     | ETH\* / TBD       | 知名互联网券商 Robinhood 基于 Arbitrum Orbit 技术栈推出的兼容 EVM 的二层网络。                   |
| **Ronin**               | RON               | 由 Sky Mavis（Axie Infinity 开发商）专门为 Web3 游戏生态量身定制的 EVM 兼容链。                  |
| **Rootstock**           | RBTC (RIF)        | 历史悠久的比特币智能合约侧链，通过双向锚定与合并挖矿将 EVM 引入比特币生态。                      |
| **Scroll**              | SCR (ETH\*)       | 致力于在字节码级别实现完全 EVM 等效的社区驱动型以太坊 zkEVM Layer 2 网络。                       |
| **Sei EVM**             | SEI               | 最初为交易优化的 Cosmos 链，在 V2 升级后成为首个支持并行化 EVM 的高性能公链。                    |
| **Telos EVM**           | TLOS              | 构建在 Telos 网络之上、主打无抢跑交易 (No Front-running) 与极高吞吐量的 EVM 执行层。             |
| **Theta**               | THETA (TFUEL)     | 专注于去中心化视频流媒体传输、边缘计算与 AI 算力共享的兼容 EVM 双代币公链。                      |
| **Unichain**            | ETH\* (UNI)       | 由去中心化交易所龙头 Uniswap 基于 OP Stack 推出的专为 DeFi 流动性优化的 Layer 2 网络。           |
| **VirBiCoin**           | VBC               | 早期基于以太坊代码分叉的兼容 EVM 工作量证明 (PoW) 区块链网络。                                   |
| **X Layer**             | OKB               | 由 OKX 基于 Polygon CDK 技术构建的以太坊 ZK-Rollup 二层网络，使用 OKB 作为原生 Gas 代币。        |
| **XinFin Network**      | XDC               | 即 XDC Network，专注于国际贸易融资、企业级应用与现实世界资产代币化的混合型 EVM 区块链。          |
| **zkSync Era**          | ZK (ETH\*)        | 由 Matter Labs 研发、基于零知识证明技术构建的头部以太坊 Layer 2 网络。                           |

> **注：** 缩写代号中带有 `*` 号的（如 `ETH*`、`BTC*`、`BNB*`），代表该二层网络（Layer 2）直接使用对应一层主网的原生代币作为交易手续费（Gas 费），括号外或括号内的另一个代号则为该网络的生态治理代币。

Theta 是唯一有两条路径的网络：TFUEL 转账走 EVM 适配器，原生 `SendTx` 走 Theta 适配器，载荷格式决定走哪条。

19 个网络共内置 80 条代币记录（`WalletTokens.cpp`）。用户可在设备上登记自定义代币，审阅界面会标注
"自加"，而且它们永远不改变被签名的字节。

## 原生适配器

这些链通过 `chain begin <network> <index> <payload-hex>` 接收各自格式的载荷。具体封装见
[载荷格式](Chain-Payloads-zh)。

| 条目                                                   | 范围说明                                                                                                                                                           |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `xmr`                                                  | RCT type 6、CLSAG、Bulletproofs+、16 成员环、子地址花费；诱饵由手机提供                                                                                            |
| `alph`                                                 | P2PKH 原生 ALPH 转账。检查每个输入的公钥或复用前一解锁脚本，审阅一个外部收款方、可选本机找零及 gas 费用。测试与 Alephium 官方 SDK 3.0.5 的交易哈希和签名字节一致。 |
| `quantus`                                              | 主网 runtime 153/6。透明账户使用 ML-DSA-87 和 SS58 前缀 189，支持普通余额转账。设备审阅收款方、金额、小费、nonce 和有效期，生成完整 v4 extrinsic。                 |
| `zeph`                                                 | ZPH 原生普通转账，v3 前缀、RingCT type 6、16 成员 CLSAG 环。按既定策略与 XMR 共用派生密钥，审阅按 Zephyr 的地址前缀和资产字段执行。                                |
| `trx`                                                  | owner 权限转账、TRC-10、已登记 TRC-20、可打印 memo ≤ 64 字节；不做 NFT、批量、多合约                                                                               |
| `xlm`                                                  | SEP-0005、主网 XDR Payment/CreateAccount、发行资产与 memo 审查；最多 8 个操作                                                                                      |
| `sol`                                                  | Legacy/v0、System Transfer、SPL 与 Token-2022 `TransferChecked`、精确 mint/账户审查；不做 ALT、不建 ATA                                                            |
| `xrp`                                                  | 原生 Payment、规范 XRPL 二进制、SHA-512Half；不做发行货币、path、memo、部分支付、多签                                                                              |
| `atom`、`osmo`、`tia`、`kava`、`terra`、`terraclassic` | 1–4 条 direct `MsgSend`，可选 memo。`cosmoshub-4` 与 `osmosis-1` 另支持固定通道的原生 ICS-20、限额银行转账授权及撤销、单笔原生 legacy Amino `MsgSend`。[载荷](Chain-Payloads-zh#cosmos) |
| `ada`                                                  | Conway body 审查与 Ed25519-BIP32 签名；body 不带输入金额/所有者，余额需要节点                                                                                      |
| `algo`                                                 | 规范 MessagePack `pay`/`axfer`、genesis/手续费/轮次校验、ASA opt-in；仅主网                                                                                        |
| `apt`                                                  | Aptos 转账载荷，Ed25519 认证密钥派生                                                                                                                               |
| `ckb`                                                  | secp256k1 sighash 与 Molecule 序列化                                                                                                                               |
| `dcr`                                                  | BLAKE-256、legacy prefix/witness sighash、P2PKH                                                                                                                    |
| `erg`                                                  | P2PK ProveDlog：设备自己重建 tx-id 原像并返回完整证明交易                                                                                                          |
| `fil`                                                  | CBOR `Send`、CID 摘要、f1 发送方                                                                                                                                   |
| `hbar`                                                 | Hedera 转账 body 签名                                                                                                                                              |
| `hive`                                                 | 只能审查 + 签名：STM 公钥不是收款地址，所以这个条目没有地址能力                                                                                                    |
| `icp`                                                  | Ed25519 请求签名与 IC principal 派生                                                                                                                               |
| `vet`                                                  | 紧凑载荷、规范 RLP、BLAKE2b-256、可恢复签名；只支持单 clause VET                                                                                                   |
| `icx`                                                  | `icx_sendTransaction` 规范文本、SHA3-256；只支持原生 ICX                                                                                                           |
| `dot`、`ksm`                                           | `DOT2` 载荷、钉死的 runtime `spec_version`/`transaction_version`、短命期 era + tip；历史 DOT1 布局只在 host 测试里存在                                             |
| `qrl`                                                  | XMSS/SHAKE-256，树高 10；签名前先把叶子写进持久存储，设备在释放签名前验证自己的签名                                                                                |
| `qrl2`                                                 | ML-DSA-87 账户、SHAKE-256 校验和的 `Q` 地址、keccak-256 信封；只支持主网 chain id 1                                                                                |
| `stark`                                                | Stark 曲线密钥、Cairo v3 `deploy_account` 与一次 ERC-20 `transfer`（走 `execute`）；只支持 `SN_MAIN`                                                               |
| `theta`                                                | 原生 46 字节 `SendTx` 载荷；TFUEL 的 EVM 转账走 EVM 条目                                                                                                           |
| `ton`                                                  | Wallet v4R2 cell/BoC 序列化、user-friendly 地址、空 body                                                                                                           |
| `sui`                                                  | BCS 分离 gas 的原生转账、Ed25519；不做 Move 调用、赞助或 token                                                                                                     |
| `xch`                                                  | 只支持 Chia `CREATE_COIN`；BLS12-381 G1 密钥                                                                                                                       |
| `xem`                                                  | NEM 的 Keccak-Ed25519 变体，不是 RFC 8032 Ed25519                                                                                                                  |

## 仅地址

| 条目   | 原因                               |
| ------ | ---------------------------------- |
| `ryo`  | CryptoNote 长地址，前缀 `0x2ce192` |
| `zano` | CryptoNote `Zx` 地址，前缀 `0xc5`  |

## 尚未完成的原生能力

以下是当前代码的实际边界。地址生成、摘要原语、交易解析和可用的硬件钱包签名是不同的验收项，不能互相替代。

| 链或协议 | 当前实现与缺口 |
| --- | --- |
| RyoCurrency | 发布目录开放长地址。专用主机探针支持单个外部收款人和可选找零。手机侧构建 v3 付款，固件经一次性模拟按键批准后签名。官方 `ryod` 在隔离分叉确认单输入和双输入各一笔。实板和卡内托管仍待验收。[验证记录](validation) |
| Zano | 手机逐字节重编码并验证两笔已有主网付款。专用主机探针审阅和签署了两笔新建的普通 v4 原生资产付款，每个输入的环有 16 个成员，两笔均在隔离测试链确认。发布目录开放标准地址，卡内签名及 GGXXG 质押待验收。[验证记录](validation) |
| Monero | 已有受限的 RingCT type-6、CLSAG、Bulletproof+、子地址审查与签名；不代表所有交易形式均已适配。 |
| Zcash | 已有透明交易签名；屏蔽交易、笔记同步与零知识证明流程未完成。 |
| Beam / 其他 Mimblewimble 链 | Beam 有 CLI 单输入交互转账和范围证明；通用钱包准入、未花费输出发现与双实机节点验收未完成。Grin 等链没有钱包适配器。 |
| Peercoin | 已有地址与专用 sighash 测试；尚未接通原生交易解析、设备审查、签名和广播流程。 |
| TRON NFT / 批量调用 | 部分 NFT ABI 可以解析，但后续合约准入会拒绝；因此当前没有可用 NFT 签名。批量调用未开放。 |
| Cosmos IBC / authz / amino | Hub `transfer/channel-141` 与 Osmosis `transfer/channel-0` 的限时 ICS-20 已通过 CosmJS 对照和隔离双链中继、到账及确认。两链也已执行单笔原生 Amino 付款、带正额度与到期时间的 `SendAuthorization` 和对 `MsgSend` 的撤销。其他路由、任意授权、feegrant 和通用 Amino 仍待适配。[验证记录](validation) |
| Dash 特殊交易 | 当前仅 type-0 支付；ProRegTx 等特殊交易未实现。 |
| EVM 未解码调用 | 有原始 calldata、哈希与费用审查；原始字节展示不提供合约执行语义保证。 |
| Lightning / Stacks | 未实现通道状态与撤销协议，也没有 STX 原生交易适配器。 |

这些缺口不会因增加目录条目或开放签名开关而消失。准入要求见 [准入策略](Admission-Policy-zh)。

## 机器生成的矩阵

- `wiki/native-chain-capabilities.md` —— 每个编译进来的配置一行，由 `tools/native_coverage.ps1`
  从编译产物生成。
- `wiki/miningpoolstats-coverage.md` —— MiningPoolStats 每条列表及其解析状态，由
  `tools/generate_mining_catalog.py` 生成。
- `wiki/chain-support.md` 与 `wiki/chain-protocols.md` —— 详细的实现记录。

如果某一页和生成的矩阵冲突，以矩阵为准，那一页就是 bug。
