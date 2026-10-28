# Monero 主网交易回归

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
