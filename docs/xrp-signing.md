# XRP Payment 签名边界

设备从手机接收 50 字节紧凑审阅结构，自行构建 XRPL Payment 的规范二进制字段并用
secp256k1 签名；不连接 rippled，不查询账户，不广播。

## 紧凑 payload（大端）

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

## 二进制编码

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

## 地址

- classic r-address：`Ripple-base58check(0x00 || hash160(compressed pubkey))`；
- 不使用 Bitcoin base58 字母表；固定向量为
  `rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH`；
- destination 由主机提供 20 字节 account id，设备重新编码并显示完整 r-address。

## 证据与限制

- `tests/fixtures/xrp-sdk.json` 由 `xrpl-py` 的 binary codec 生成，覆盖无 tag、tag、零 tag
  三个合格用例和 10 个拒绝用例；`tests/test_xrp.py` 独立重算 unsigned/hash 并驱动 C++ 探针。
- 设备启动自检比较固定 Payment 的 source r-address 与 SHA-512Half；主机无法模拟
  secp256k1，签名路径由设备编译/运行验收。
- 不支持 X-address、issued currency、path、memo、invoice id、partial payment、多签名或
  AccountDelete/TrustSet 等交易；sequence 与 last ledger 的链上新鲜度无法离线断言。
- 尚未执行 rippled 提交、主网序列/费用实测或整机按键验收。
