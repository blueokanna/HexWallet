# 准入策略

[English](Admission-Policy) · [首页](Home-zh)

规则只有一条，而且靠评审执行：**没有可复现测试的 `SIGN` 行就是造假，直接回退。** 下面写的是这条规则怎么落地。

## 能力位的含义

| 能力位 | 要求 |
| --- | --- |
| `address` | 确定性派生；编码器对过独立向量；有测试把它们钉住 |
| `review` | 解析器能触达每一个会影响签名字节的字段；显示不全就拒绝 |
| `sign` | 产出链真正验证的摘要，来源是审查过的载荷；向量通过，或有独立实现逐字节一致 |
| `token-account` | 有合约登记表与核对过的 calldata 子集；未知 calldata 按原始字节显示 |

一条链可以只有 `address`。这是合法且写清楚的状态：现在有 Aeternity、RyoCurrency、Zano。
不允许的是"手写一张表、背后没有测试"的 `sign`。

## 门槛，按顺序

1. **上游源码钉死。** 共识代码或 `chainparams` 指定到具体 commit；UTXO 分叉记在
   `tools/fork_registry.json`，原生链记在适配器注释里。
2. **有 coin type。** 必须由 SLIP-0044 分配。借用别家的 coin type 会让两个域派生同一份密钥材料，
   所以没有编号的链完全不进。
3. **地址编码带向量。** 要么上游向量文件，要么第二个实现逐字节一致。bech32m、cashaddr、CryptoNote 前缀、
   EIP-55 大小写都有各自的负向测试。
4. **交易格式与摘要。** legacy sighash、BIP143、`SIGHASH_FORKID`、ZIP-243、BCS、CBOR、SCALE、protobuf，
   不管是哪种，仓库里都要有向量和会重算它的测试。
5. **审查渲染不允许截断。** 地址或金额显示不全就拒绝。"为了排版"截断收款地址，是用户丢钱的标准路径。
6. **归属绑定。** 输入必须证明属于本钱包：PSBT 的 `witness_utxo`/`non_witness_utxo`、CryptoNote 的
   key image 与承诺、EVM 的 token 登记表、Ergo 的 P2PK 原像。
7. **先策略后密码学。** 手续费上限、金额边界、重复输入、重复环成员、编码规范性，全部在曲线运算之前跑完，
   所以恶意载荷不花任何算力。
8. **失败就清零。** 签名出错清零输出缓冲；失败也消耗批准；绝不返回部分序列化结果。

## 证据链

| 证据 | 位置 |
| --- | --- |
| 每条链的向量文件 | `src/generated/*VectorsTest.inc`、`tests/fixtures/` |
| 分叉准入行（base58 版本、sighash、交易头形态） | `tools/fork_registry.json` |
| 真实交易锚点（Dash、Groestlcoin、QRL、Pearl） | 适配器注释 + 会重算摘要的 host 测试 |
| 从编译产物生成的能力矩阵 | `wiki/native-chain-capabilities.md` |
| MiningPoolStats 逐条解析结果 | `wiki/miningpoolstats-coverage.md` |
| 带日期的工程记录 | [审计记录](Audit-Records-zh) |

## 撤链

退出准入的网络同时移除目录、签名入口和专用适配器。

撤链刻意做得很朴素：删目录条目、删适配器、加一条"这个网络 id 不再解析"的策略测试，并留下说明原因的记录。

## 各链准入范围

目录按能力区分收款地址和签名。尚未准入的链由设备端 WalletAdmission 和主机策略测试共同检查。

| 链 | SLIP-0044 | 模型 | 阻塞点 |
| --- | --- | --- | --- |
| Beam | 1533 | Mimblewimble | [原生交互转账](Beam-zh)已接入单输入、收款输出及找零。设备生成完整范围证明并核对对手方签名。通用钱包准入仍需安全托管、链上未花费输出跟踪和双机节点验收。 |
| Alephium | 1234 | sUTXO、分组分片 | P2PKH 原生 ALPH 转账。检查每个输入的公钥或复用前一解锁脚本，审阅一个外部收款方、可选本机找零及 gas 费用。测试与 Alephium 官方 SDK 3.0.5 的交易哈希和签名字节一致。 |
| Iron Fish | 1338 | Sapling 式屏蔽票据 | 票据解密、nullifier 派生、zk 证明生成。这颗 MCU 上不可行，没有这些的签名器等于盲签 |
| Quai | 994 | Cyprus-1 账户链 | 支持主网 type 0 普通转账，链 ID 9，同区 Quai 账户，空 calldata 和访问列表。[签名向量](https://quaiscan.io/tx/0x00060019fdf877647e4a9bab684b0c51732b590cb0ffebc058fb29702fe87f97) |
| Qubic | 83293 | FourQ + KangarooTwelve | KangarooTwelve 已经进树（[KangarooTwelve.cpp](https://github.com/blueokanna/HexWallet/blob/main/KangarooTwelve.cpp)，钉住 XKCP 官方向量，含 24 MB 那一例），但身份仍是被 K12 哈希的 FourQ 点，签名是 FourQ 上的 SchnorrQ。用 Ed25519/SHA3 顶替会得到另一把钥匙，没有诚实的捷径；FourQ 与 SchnorrQ 仍然缺 |
| Xelis | 待核实 | 机密账户 | 已实现英、中原生助记词恢复、Ristretto255 地址和 Schnorr 签名原语。设备可检查外部主网地址。密钥托管、密文余额、转账证明及链上恢复待接入。 |
| Quantus | 189189 | ML-DSA-87 | 主网 runtime 153/6。透明账户使用 ML-DSA-87 和 SS58 前缀 189，支持普通余额转账。设备审阅收款方、金额、小费、nonce 和有效期，生成完整 v4 extrinsic。 |
| Qubitcoin | — | 声称是 Qtum 分叉 | 按 owner 决定移出范围。宣传站点返回 404，而且两个互不相关的项目共用 QTC 这个 ticker，连链身份都没确定；把决定记在这里，别让它以后又被当成待办捡回来 |
| Aion | 425 | EVM 时代 L1 | 按决定排除，链已停摆 |

"无 SLIP-0044"这几行遵循与 Swap、Evolution、VeriBlock 相同的规则：用别家 coin type 派生本链密钥，
等于把两个域放到同一把钥匙上。这不是兼容捷径，是碰撞。

一条链只有在同一个提交里带来适配器、向量和能力行时才能离开这张表——绝不能只靠改目录。

## Zephyr 已经离开这张表

Zephyr 是第一条被准入出去的链，记录比那一行更重要。带进来的东西：网络配置、目录条目，以及上游
`src/cryptonote_config.h`（前缀 `0x6241d18c0`、12 位小数）与 `tests/unit_tests/base58.cpp` 的地址向量，
由 `run_cryptonote_address_self_tests()` 逐字节复现——73 字节、101 字符、`ZEPHYR3baX…QuP1u4V`。

没带进来的是 coin type。上游 SLIP-0044 没有 ZEPH，所以这里由 owner 做了这张表替不了的决定：用
Monero 的 128。这是有记录的取舍，不是先例——account 0/index 0 得到的 spend、view key 与 XMR 完全
相同，只有前缀让地址不同。设备按 Zephyr v3 解析原生 ZPH 交易，验证输出、费用及 CLSAG。资产转换不会进入这条签名路径。

可推广的结论：缺 coin type 是该上报的决策点，不是可以造一个出来的障碍。

## 什么不算准入

- 矿池网站上的 ticker、交易所上架、"EVM 兼容"这种说法。
- 只有地址编码器、没有签名路径（那是 `address` 行，不是钱包）。
- 能读交易、但证明不了输入归属的解析器。
- 只对得上自己生成的向量。
- 任何"加了 `SIGN` 但同一个提交里没有测试"的改动。

逐链缺口的长台账在 `wiki/chain-gates.md`。那是活记录，这一页是它遵循的规则。
