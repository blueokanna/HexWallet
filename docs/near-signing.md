# NEAR 签名边界

设备只解析 Borsh 编码的 `TransactionV0` 原始字节，审阅后签名；不连接 RPC，不组装交易，不广播。当前只支持原生 NEAR Transfer。手机链路使用 `BEGIN_SIGN kind=11`，`coin_id=near`。

## 接受的交易

| 项 | 规则 |
| --- | --- |
| 结构 | `signer_id`、`public_key`（enum 0 = ED25519 + 32 字节）、`nonce` (u64)、`receiver_id`、`block_hash` [32]、`actions` 向量 |
| 动作 | 1–16 个 `Transfer`（enum 3），金额为 u128 小端；任一金额为 0 即拒绝 |
| 总额 | 逐笔累加到 128 位，溢出即拒绝，并显示格式化总额 |
| 签名者 | 必须是由设备当前 Ed25519 公钥推导出的 64 位十六进制隐式账户 |
| 公钥 | 必须与设备 owner 公钥完全一致 |
| 收款方 | 合法 NEAR 账户 ID；隐式账户按 64 位十六进制校验 |
| 交易大小 | ≤512 字节；签名输出 ≤577 字节 |

以下动作或形态一律拒绝：`FunctionCall`、`AddKey`/`DeleteKey`、`Stake`、`DeployContract`、`Delegate`、`DeleteAccount`、零金额，以及任何未识别的 action enum。

## 签名与输出

- 签名摘要：`SHA-256(borsh_transaction)`。
- 签名：Ed25519 对 32 字节摘要签名。
- 输出：`unsigned_borsh || 0x00 || signature[64]`，其中 `0x00` 是 `Signature::ED25519` 枚举值。
- 签名前重新解析原始字节，逐项比较 signer、receiver、public key、block hash、nonce、动作数和金额；比较失败即拒绝。

## 派生与地址

- 路径：`m/44'/397'/index'`，使用 SLIP-0010 Ed25519；这是 near-slip10 的默认层级，也是本钱包的密钥策略。
- 隐式账户地址：owner 公钥的 64 位小写十六进制。
- 设备不能离线证明 `block_hash` 属于当前最长链；手机必须提供近期区块哈希，用户应在设备上核对显示值。

## 已知缺口

- 不支持命名账户的链上所有权证明、FunctionCall、访问密钥管理和质押。
- 交易本身不包含手续费字段；gas 由签名者账户扣除，设备无法离线显示准确费用。
- 尚未执行 NEAR 主网 RPC 提交或节点验收。

## 验证证据

- `tests/fixtures/near-sdk.json`：由 `near-api-js` 5.1.1 生成，公开 TEST ONLY 种子；11 组合格、16 组拒绝。
- `tests/host/near_probe.cpp` 比较设备签名输出、交易哈希、signer、receiver、public key、block hash、nonce、动作数和总额；`tests/test_near.py` 独立验签。
- 启动自检比较 `src/generated/NearVectorsTest.inc` 中的完整 SDK 签名结果，并验证错误 owner 被拒绝。
