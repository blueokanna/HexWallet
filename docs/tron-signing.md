# TRON 原生转账、TRC-20 与 NFT 签名

实现位于 `TronTransaction.cpp`，通过 `WalletSigning` 的设备审批流程接入。手机使用
`BEGIN_SIGN kind=7`、币种 `trx`，payload 为**原始 `raw_data` protobuf 字节**，不是完整
Transaction，也不是 JSON。设备返回 65 字节 `r || s || v`（`v = 27 + recovery id`，low-S）
签名；手机把签名装回 `Transaction.signature` 后自行广播。

路径为 `m/44'/195'/0'/0/<index>`，与地址派生共用 `WalletEngine::derive_address()`。设备先
把派生出的 21 字节地址与 payload 中的 `owner_address` 做常量时间比较，任何不一致都在显示
前拒绝。

## 支持范围

- 原生 TRX：`TransferContract`，金额为 1..2^63-1 sun。
- TRC-20：`TriggerSmartContract`，仅接受 `transfer(address,uint256)`（selector
  `a9059cbb`）且 `call_value == 0`、`call_token_value == 0`、`token_id == 0`。
- TRC-20 合约必须已在 `WalletTokens.cpp` 注册（当前为 Tether 官方公布的
  `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` / USDT，6 位小数）。未注册合约直接拒绝，
  因为离线设备无法可信地获得 symbol 与 decimals。
- TRC-721：仅接受 `safeTransferFrom(address,address,uint256)`（`0x42842e0e`），
  calldata 恰好 100 字节，calldata 中的 `from` 必须等于本机 owner。
- TRC-1155：仅接受 `safeTransferFrom(address,address,uint256,uint256,bytes)`
  （`0xf242432a`）且 `bytes` 尾为空（offset `0xa0`、length `0`），金额非零。
- NFT 合约不要求注册：selector 唯一，设备显示合约地址、`TRC-721`/`TRC-1155`、token id
  和明确的“UNREGISTERED”警告；合约身份、元数据和所有权无法离线验证。
- 与 TRC-20 共享 selector `0x23b872dd` 的 `transferFrom`、批量转移、
  `safeTransferFrom` 非空回调数据以及任何其他 selector 一律拒绝。
- `owner_permission` 只接受 0（缺省）。`permission_id != 0`、`auths`、`provider`、
  `ContractName` 一律拒绝。
- 原生转账的 `fee_limit` 必须缺省或 0；TRC-20 的 `fee_limit` 必须在
  (0, 100 TRX] 内。上限见 `kTronMaxFeeLimitSun`。
- `expiration` 与 `timestamp` 都必须存在，且 `0 < expiration - timestamp <= 24h`。
- 金额为 256 位大端字，按注册精度完整格式化；零金额、自转账、全零黑洞地址、非 `0x41`
  前缀地址、截断、多余字节、重复字段、非最短 varint、未知字段（包括 memo/`data`）全部拒绝。

## 协议字节

`raw_data` 只允许以下字段：

| 字段 | 含义 | 约束 |
| --- | --- | --- |
| 1 | `ref_block_bytes` | 长度 2 |
| 3 | `ref_block_num` | 可缺省，仅接受 varint |
| 4 | `ref_block_hash` | 长度 8 |
| 8 | `expiration` | int64 毫秒 |
| 11 | `contract` | 恰好 1 条 |
| 14 | `timestamp` | int64 毫秒 |
| 18 | `fee_limit` | int64 sun |

`contract.parameter.type_url` 必须与 `contract.type` 严格对应：
`TransferContract` → `type.googleapis.com/protocol.TransferContract`，
`TriggerSmartContract` → `type.googleapis.com/protocol.TriggerSmartContract`。

签名对象是 `SHA-256(raw_data)`；设备在签名前会重新计算并与审阅时保存的 txID 做常量时间
比较，因此批准后无法替换字节。

## 可信显示

屏幕显示收款地址（Base58Check）、金额（原生 `TRX`、注册代币符号与精度，或
`TRC-721`/`TRC-1155` 的 token id 与数量）、合约地址、`FEE LIMIT`、过期时间（毫秒）与
txID 前 8 字节。NFT 审阅额外显示未登记警告。备注写明：过期时间、ref block、带宽/能量
状态由手机侧校验；离线设备不声称知道链上实际手续费。

## 证据与局限

`tools/generate_tron_vectors.py` 用纯 Python 实现 protobuf 编码、BIP32、RFC 6979 与
secp256k1，生成 `tests/fixtures/tron-vectors.json` 与
`src/generated/TronVectorsTest.inc`；每条签名都由 OpenSSL（`cryptography`）独立验签后
才写入。`tests/test_tron.py` 驱动真实 C++ `tron_probe.exe` 覆盖：完整字段、4 组合格向量
（TRX、TRC-20、TRC-721、TRC-1155）、19 组拒绝向量、
按位置的截断、外部 owner 地址；设备启动自检在真实 mbedtls 上对同一组向量比较**完整 65
字节签名**。生成器可用 `--check` 验证仓库内产物未过期。

未实现、也不得宣传为已支持：TRC-10、TRC-721/1155、多合约交易、memo/`data`、多签与自定义
权限、能量/带宽估算、事件日志解析、广播与节点验收。整机触屏按键、SE050 托管与主网广播仍
需独立证据。
