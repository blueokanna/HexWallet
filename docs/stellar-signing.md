# Stellar 离线签名

`BEGIN_SIGN kind=9, coin_id=xlm` 接入 Stellar public network。固件不访问 Horizon、RPC 或互联网。主机准备请求并广播结果；设备负责派生密钥、解析 XDR、展示审阅数据、取得本机批准和签名。

## 地址与账户

采用 [SEP-0005](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md) 的 SLIP-0010 Ed25519 路径 `m/44'/148'/x'`。协议的 `address_index` 对应 `x`，通用地址接口的 `account` 和 `change` 必须为零。G 地址编码为版本字节、32 字节公钥和小端 CRC16-XModem 的 RFC 4648 base32。地址显示与签名共用派生路径函数。

## 请求和结果

请求 payload 为：

```
SHA256("Public Global Stellar Network ; September 2015") [32 bytes]
TransactionEnvelope XDR                                [variable]
```

XDR 必须是 `ENVELOPE_TYPE_TX=2`，尾部 signatures 数组长度为零。签名域是网络哈希、envelope 类型和完整 Transaction 的串联；不包含 signatures 数组。设备用 Ed25519 签署该串联的 SHA-256，再返回带一条 DecoratedSignature 的完整 TransactionEnvelope 原始字节。主机可以将其 base64 编码后广播。签名 hint 取发送方公钥末四字节。

字段布局依据 [stellar-xdr](https://github.com/stellar/stellar-xdr/blob/master/Stellar-transaction.x)。不接受主机提供的预计算摘要或解码后的金额。网络哈希不同直接拒绝，不能把 testnet 请求送来后静默改签主网。

## 已开放范围

- 每笔 1–8 个 Payment 或 CreateAccount，所有金额为正的有符号 64 位整数，精度固定为七位。
- Payment 支持原生 XLM 及 alphanum4/alphanum12 资产。设备逐项显示资产代码和发行者 G 地址；同名资产不视为同一资产。
- CreateAccount 显示为创建账户，并审阅初始余额。
- 交易和操作使用普通 G 账户。操作 source 可省略；显式 source 必须等于本机签名账户。
- memo 支持 NONE、ASCII TEXT（最多 28 字节）、uint64 ID、HASH、RETURN HASH。哈希完整显示为十六进制；拒绝 NUL、控制字符和非 ASCII 文本，避免显示与签名字节不一致。
- 必须有 `PRECOND_TIME`，且 `maxTime > minTime`、`maxTime != 0`。显示原始 Unix 秒，不信任手机时钟。设备不证明请求当前有效，账本负责执行有效期规则。
- 手续费下限为每操作 100 stroops，上限为每笔 1 XLM。这是设备策略；网络拥堵时的实际最低费用仍由账本决定。屏幕标为最大费用。

明确拒绝：V0、fee bump、muxed M 地址、PreconditionsV2、已有签名、多签收集、Soroban、DEX/path payment、授权/信任线修改、账户合并、未知扩展以及超过设备上限的交易。拒绝不影响这些功能后续以独立审阅规则接入。

## 批准与验证

沿用设备的两分钟审阅会话和单次批准。签名前重新派生发送方、重新解析原始请求，并逐字段比较来源、目的地、发行者、资产、金额、费用、序列号、有效期、memo 和签名摘要。私钥只在签名期间进入 worker，返回前擦除。任何失败都不返回可用签名。

独立证据由 `tests/reference/generate_stellar_vectors.py` 使用 `stellar-sdk==13.1.0` 生成，存入 `tests/fixtures/stellar-sdk.json`。测试比较固件产生的完整签名 envelope、交易哈希及所有显示字段；同时验证官方 SEP-0005 地址、实际 `derive_address` 路径、13 组 SDK 拒绝向量、逐字节截断、XDR union/填充错误、审阅字段篡改和短输出缓冲区。

SDK 只属于开发端测试依赖，不进入固件。向量使用公开测试助记词和合成账本状态，不能用于存放资产，也不代表主网节点验收。尚需整机显示/按键验收、节点提交验证和独立安全审计。离线设备无法自行验证余额、最低准备金、信任线、发行者授权状态或收款账户的 memo 要求。
