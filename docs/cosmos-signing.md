# Cosmos SDK 原生 MsgSend（ATOM / OSMO / TIA）

实现位于 `CosmosTransaction.cpp`，接入 `WalletSigning` 与手机链路 `BEGIN_SIGN kind=8`。
币种为 `atom`、`osmo`、`tia`，路径 `m/44'/118'/0'/0/<index>`，地址为
`bech32(hash160(compressed secp256k1 pubkey))`。设备返回**完整 `TxRaw` protobuf**，手机直接广播。

## 覆盖范围

| 网络 | HRP | chain-id 前缀 | 原生 denom | 精度 |
| --- | --- | --- | --- | --- |
| atom | `cosmos` | `cosmoshub-` | `uatom` | 6 |
| osmo | `osmo` | `osmosis-` | `uosmo` | 6 |
| tia | `celestia` | `celestia` | `utia` | 6 |

每条交易恰好一条 `MsgSend`，只发送链的原生 denom。`SIGN_MODE_DIRECT`，单签名者，
无 tip、无 feegrant、无 authz、无 memo、无 IBC、无多消息。`chain-id` 由手机提供但必须匹配
网络前缀，并且完整显示在屏幕上；账户号与 sequence 也显示，批准前必须核对。

## 审阅 payload（大端）

```
u8   version = 1
u8   chain_id_len;  chain_id bytes        (1..32, [A-Za-z0-9._-])
u64  account_number
u64  sequence
u64  amount            (base units, > 0)
u64  fee               (base units, <= 10 000 000)
u64  gas_limit         (1..2 000 000)
u8   to_len;        to bytes              (小写 bech32, 20 字节 payload)
u8   memo_len = 0
```

接收地址必须是正确 HRP、BECH32（非 bech32m）校验和、20 字节 payload，且重新编码后
与原串完全一致；大小写混合或非规范填充会被拒绝。`to` 不能等于本机地址。本机地址必须
与设备私钥的 `hash160(pubkey)` 一致，否则 `WrongWallet`。

## 设备构建的 protobuf

设备不解析手机提供的交易结构，而是自己构建并签名：

- `MsgSend{from_address, to_address, Coin{denom, amount}}`
- `TxBody{messages=[Any("/cosmos.bank.v1beta1.MsgSend", msg)]}`
- `AuthInfo{signer_infos=[{public_key=Any("/cosmos.crypto.secp256k1.PubKey", key),
  mode_info={single:{mode=SIGN_MODE_DIRECT}}, sequence}],
  fee={amount=[Coin{denom, fee}], gas_limit}}`
- `SignDoc{body_bytes, auth_info_bytes, chain_id, account_number}` → `SHA-256`
- 签名：low-S secp256k1，64 字节 `r||s`
- `TxRaw{body_bytes, auth_info_bytes, signatures=[signature]}`

字段按升序、默认值省略编码；`body_bytes`/`auth_info_bytes` 与 `TxRaw` 中完全一致。
签名前重新构建 `SignDoc` 并比较摘要；批准后无法替换内容。

## 证据

`tools/generate_cosmos_vectors.py` 用纯 Python 实现 protobuf、bech32、BIP32、RFC 6979 与
secp256k1，生成 `tests/fixtures/cosmos-vectors.json` 与 `src/generated/CosmosVectorsTest.inc`；
每条签名先由 OpenSSL（`cryptography`）验签。`tests/test_cosmos.py` 驱动真实
`cosmos_probe.exe` 比较 C++ 实际构建的 `body`/`auth_info`/`SignDoc` 摘要与三组独立向量，
并覆盖 12 组拒绝 payload、所有采样截断、外部 owner、外部公钥。设备启动自检使用同一组
私钥/向量，在真实 mbedtls 上签名并逐字节比较完整 `TxRaw`。生成器支持 `--check`。

未实现：IBC、多消息、memo、authz/feegrant、非原生 denom、EIP-191/JSON 签名模式、
Ledger 兼容的 amino 模式、链上账户号/sequence 查询与广播。屏幕按键、SE050 托管和主网
节点验收仍需独立证据。
