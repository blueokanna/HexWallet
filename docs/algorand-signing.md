# Algorand 签名边界

设备只接收未签名的 canonical MessagePack 交易字节，自行解析、显示并签名；它不连接 algod，也不参与交易组装或广播。当前只支持主网 `mainnet-v1.0`。手机链路使用 `BEGIN_SIGN kind=10`，`coin_id=algo`。

## 接受的交易

| 项 | 规则 |
| --- | --- |
| 编码 | canonical MessagePack map，键必须严格升序且唯一；只接受短字符串（≤31 字节）、`bin8/bin16` 和最短形式非零整数 |
| 必填字段 | `fee`、`fv`、`gen`、`gh`、`lv`、`snd`、`type` 及对应金额/收款字段 |
| 网络 | `gen = "mainnet-v1.0"`，`gh` 必须等于主网 genesis hash `c061…8adf` |
| 类型 | `pay`（原生 ALGO）或 `axfer`（ASA） |
| 费用 | 1,000–1,000,000 microAlgo |
| 有效期 | `lv ≥ fv` 且 `lv - fv ≤ 1000` 轮 |
| 发送方 | `snd` 必须等于设备当前 Ed25519 公钥 |
| ASA opt-in | `axfer` 金额为 0 时要求 `snd == arcv`；非零金额为转账 |
| note / lease | note ≤1024 字节、lease 为 32 字节且非全零；两者均完整显示为十六进制 |

以下字段或交易形态一律拒绝：`grp`（原子组）、`rekey`、`close`/`aclose`（关户/强制转出）、`asnd`（clawback）、LogicSig、应用调用、资产创建/销毁、未知键和非 canonical 编码。

## 签名与 txID

- 待签消息：`"TX" || unsigned_msgpack`。
- 交易 ID：`SHA-512/256("TX" || unsigned_msgpack)`，设备以十六进制显示。
- 签名：Ed25519，输出 `{"sig": <64-byte bin>, "txn": <unsigned msgpack>}` 的 canonical MessagePack。
- 审阅字段在签名前由原始字节重新解析并逐项比较；任一显示字段、金额、地址或 txID 不一致即拒绝。

## 派生与地址

- 路径：`m/44'/283'/account'/change'/index'`，本钱包固定 `account = change = 0`，`index` 为地址序号；使用 SLIP-0010 Ed25519。
- 这是本钱包的密钥策略，不是对 Ledger 或 BIP32-Ed25519 种子兼容性的声明。
- 地址：`base32(pubkey || SHA-512/256(pubkey)[28..32])`，58 个字符。

## 已知缺口

- 不支持 ASA 的 clawback/freeze 管理交易、原子组、智能合约调用和再密钥。
- 设备没有可信时钟，只检查轮次窗口，不判断当前轮次是否已过期；过期交易由节点拒绝。
- 尚未执行主网 algod 提交、ASA opt-in 实测或整机按键验收。

## 验证证据

- `tests/fixtures/algorand-sdk.json`：由 `py-algorand-sdk` 2.11.1 生成，种子为公开 TEST ONLY 值；11 组合格、12 组拒绝。
- `tests/host/algorand_probe.cpp` 逐组比较设备输出的签名字节、txID、发送/接收地址、金额、费用、note 与 lease；`tests/test_algorand.py` 另用派生公钥独立验签。
- 启动自检比较 `src/generated/AlgorandVectorsTest.inc` 中的完整 SDK 签名结果，并验证错误 owner 被拒绝。
- 修复了 SHA-512/256 多分块路径未清零 128 位长度字段高半部的问题；此前 ≥126 字节的 Algorand 交易会显示错误 txID。`extended-crypto` 自检现已包含 128 字节分块向量。
