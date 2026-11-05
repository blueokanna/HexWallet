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

链是会被撤掉的。MASARI（MSR）在 2026-10-24 撤出：它本来有签名路径，但子地址和 RCT type-3 语义无法用主网
向量钉死，于是整条撤掉，而不是留着加个警告。Qubic 直接把 profile 删了，没有把 FourQ/K12 身份硬套到
Ed25519 上；Flux 留在外面，因为 MiningPoolStats 快照把它列在 GRAVEYARD。

撤链刻意做得很朴素：删目录条目、删适配器、加一条"这个网络 id 不再解析"的策略测试，并留下说明原因的记录。

## 什么不算准入

- 矿池网站上的 ticker、交易所上架、"EVM 兼容"这种说法。
- 只有地址编码器、没有签名路径（那是 `address` 行，不是钱包）。
- 能读交易、但证明不了输入归属的解析器。
- 只对得上自己生成的向量。
- 任何"加了 `SIGN` 但同一个提交里没有测试"的改动。

逐链缺口的长台账在 `wiki/chain-gates.md`。那是活记录，这一页是它遵循的规则。
