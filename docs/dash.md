# Dash 原生支付适配器

适配器生成 Dash Core v3、type 0 的普通支付，使用 P2PKH 输入、P2PKH/P2SH 输出与 `SIGHASH_ALL`。最多 4 个输入、8 个输出；每个输入都必须属于 `m/44'/5'/account'/change/index`。可以发送多笔收款、合并 UTXO 或转回自己的地址；所有输出逐项显示，不由主机声明某个输出是找零。

这不是 Dash 全类型支持。ProRegTx、ProUpServTx、ProUpRegTx、ProUpRevTx、CbTx、QcTx、MnHfTx、AssetLockTx、AssetUnlockTx 的创建/签名均拒绝；CoinJoin 协作与 Platform 交易没有实现。InstantSend 不改变支付序列化，固件不宣称自己已观察到网络锁定。

## 输入金额必须有依据

Dash 的 legacy sighash 不包含输入金额。仅接受主机提供的 `value` 会让恶意主机伪报手续费，因此签名前必须取得每个输入的完整前序交易。固件计算 SHA256d，与输入 outpoint 的 txid 原始字节比较，再校验索引、金额和脚本。批准前核对一次，签名时再核对一次；本地推算手续费后执行绝对值和费率上限。

前序交易允许 v1–v3 type 0，或 v3 type 1–9 的带 extraPayload 交易；后者只用于证明被花费的输出，完整 extraPayload 进入 txid 哈希，不代表固件会签署同类特殊交易。前序交易上限 1024 字节，超限明确拒绝。该证明能绑定交易内容，但不能证明主链确认、UTXO 未花费或 coinbase 成熟度，这些由节点检查。

## 手机协议

`BeginTransaction` 使用 transaction type `15`、network id `dash`。外层 `address_index` 不参与派生，各输入携带自己的路径索引。沿用现有传输上限，不扩大通用缓冲区。

`DAS2` payload 全部整数采用 little-endian：

| 字段 | 编码 |
| --- | --- |
| magic | 4 字节 `DAS2` |
| lock_time | u32，最大 `0x7fffffff` |
| input_count | u8，1–4 |
| 每个 input | txid[32]、u32 output_index、u32 sequence、u64 value、u8 script_size、script、u32 account、u8 change、u32 address_index |
| output_count | u8，1–8 |
| 每个 output | u64 value、u8 script_size、script |
| 每个 input 的前序交易，按 input 顺序 | u16 byte_length、完整 raw transaction |

txid 是 outpoint 中的字节顺序，不是区块浏览器显示字符串的顺序。输入脚本必须为标准 25 字节 P2PKH，输出仅为标准 P2PKH/P2SH。禁止重复 outpoint、尾随字节、金额超范围及非规范 CompactSize。`DASH` 旧格式仍可由底层解析器读取用于诊断，但不可进入批准流程，签名函数返回 `MissingField`。

审核完整展示所有输出金额与地址、输入金额与地址、派生路径、sequence、版本、lock_time 和手续费。密钥操作在 crypto worker 执行；签名复用钱包公共 secp256k1 实现，使用确定性 nonce、随机盲化、low-S 规范化与签后验证。签名输出失败时清零；生产托管与可信显示准入保持有效。

## 回归依据

`src/generated/DashVectorsTest.inc` 保留两条现有主网交易的摘要及签名材料（v2、v3 各一条），并添加含前序交易的合成 funding/spend 向量。`tools/generate_dash_vectors.py` 生成合成向量并独立验证 ECDSA；它是测试工具，不进入固件。`chain_probe dash-sign-selftest` 运行真实 WalletSecurity/BIP32/Mbed TLS 的签名与固定字节比较。拒绝用例覆盖金额、txid、索引、script、尾部、截断、重复输入、缺前序交易、手续费与非 ALL sighash。

协议依据：[Dash DIP2](https://github.com/dashpay/dips/blob/master/dip-0002-special-transactions.md)、[Dash 特殊交易格式](https://docs.dash.org/en/stable/docs/core/reference/transactions-special-transactions.html)、[Dash 交易指南](https://docs.dash.org/en/stable/docs/core/guide/transactions.html)。这些资料规定序列化和交易类型；本仓库的节点广播与硬件验收不能由文档或主机测试代替。
