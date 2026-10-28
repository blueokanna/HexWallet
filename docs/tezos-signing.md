# Tezos 签名边界

设备解析并签名 Tezos manager operation 的原始字节，或由手机提供的紧凑审阅结构；不连接
节点、不组装 Michelson、不广播。当前只支持主网 `tz1` 源地址。

## 支持范围

- 可选的首个 Ed25519 reveal（tag `0x6b`），无 BLS proof；
- 1–16 个 transaction（tag `0x6c`），仅原生 XTZ 转账到隐式 `tz1`–`tz4`；
- 金额非零，counter 连续，总 fee ≤ 1 XTZ，gas ≤ 1,040,000，storage ≤ 60,000；
- 无 KT1 调用、无参数、无委托、无 FA token、无批量提案/投票。

## 签名

- 待签摘要：`BLAKE2b-256(0x03 || forged_operation)`；
- 签名：Ed25519，输出 `forged_operation || signature`；
- 审阅包含 source、public key、branch、逐笔 recipient/amount/fee/counter/gas/storage；
- 签名前重新解析并逐项比较 source、public key、branch、操作数、金额和摘要；任何不一致拒绝。

## 地址与派生

- 路径：`m/44'/1729'/account'/change'/index'`，全部 hardened，SLIP-0010 Ed25519；
- 地址：`base58check(0x06a19f || BLAKE2b-160(pubkey))`，显示为 `tz1...`；
- branch 只作为 32 字节值审阅，设备不断言它属于当前最长链。

## 证据与验证

- `tests/fixtures/tezos-sdk.json` 与 `src/generated/TezosVectorsTest.inc` 由独立 SDK/Python
  生成；通过 `tezos_probe` 与 `tests/test_tezos.py` 比较完整签名操作、审阅字段和拒绝向量；
- 启动自检比较 SDK 生成的 signed operation（`tezos=pass`）；
- 未执行主网 injection、baker 费市场验收或整机按键验收。
