> Wire-level protocol record. Current documentation: [Phone-Link](Phone-Link) / [Phone-Link-zh](Phone-Link-zh). Protocol version is 2.


# 手机 ↔ 硬件钱包链路协议（v1）

本文描述 HexWallet 把手机当作“发请求的一方”、把硬件钱包当作“只做审阅与签名的一方”的完整协议。
手机只拿到**公钥/地址**和**已签名的交易字节**；私钥、助记词、种子永不离开设备。

> 现状：BTC/LTC/RVN 家族的 UTXO（PSBT）、EVM（EIP-155/1559 + 白名单合约）、Kaspa（BIP340 v0）、
> Zcash（v4 透明 ZIP-243）以及 XMR（CryptoNote type-5/`kind=5`）已经走通
> “手机请求 → 设备审阅 → 按键批准 → 设备签名 → 返回给手机”。

## 1. 传输层

| 传输 | 默认 | 开启方式 | 说明 |
| --- | --- | --- | --- |
| NFC（PN7161，NCI 2.0，ISO-DEP 卡模拟） | 取决于板级引脚 | 在板级 profile 定义 `HEXWALLET_NFC_PN7161` 与 `HEXWALLET_NFC_PIN_*` | 手机作为读卡器；设备作为标签 |
| USB（CDC，APDU 封装） | **关闭** | 长按 BOOT/用户按键 3 秒；或窗口超时/再次长按/上锁 | 每次开启只持续 `HEXWALLET_USB_ENABLE_WINDOW_MS`（默认 10 分钟），复位后恢复关闭 |

USB 关闭时，固件丢弃串口输入（包括残留字节），只保留只读启动日志；ROM 下载模式（烧录）不受影响。
USB 与 NFC 共用同一套 APDU/链路协议，因此手机端只需要实现一次。

### 1.1 APDU 映射（ISO 7816-4）

| 命令 | CLA INS P1 P2 | 数据 | 说明 |
| --- | --- | --- | --- |
| SELECT | `00 A4 04 00` | `06 F0 48 57 4C 4B 31` | 选择应用，返回 `F0 <version>` + SW |
| WRITE | `80 10 <last> 00` | 链路帧分片 | `last=1` 表示最后一包，设备处理并缓存回复 |
| READ | `80 11 00 00` | 空 | 每次最多返回 240 字节，`SW=61xx` 表示还有数据 |
| ABORT | `80 12 00 00` | 空 | 丢弃未完成的分片与回复 |
| STATUS | `80 13 00 00` | 空 | 返回分片/回复长度与 `session`/`pairing` 标志 |

### 1.2 USB 封装

```
A5 5A <len_lo> <len_hi> <APDU...>       手机 → 设备
A5 5A <len_lo> <len_hi> <APDU 响应...>  设备 → 手机
```

## 2. 链路帧

```
"HWLK" | version(1) | type(1) | 0 | 0 | session_id(4) | sequence(4)
       | payload_len(2) | payload | [tag(32)：仅 Request/Response]
```

所有整数小端。`tag` 是 32 字节 HMAC-SHA256；长度必须精确匹配，多余或缺失字节一律拒绝。

| type | 名称 | 方向 |
| --- | --- | --- |
| 0x01 | PairRequest | 手机 → 设备 |
| 0x02 | PairResponse | 设备 → 手机 |
| 0x03 | HelloRequest | 手机 → 设备 |
| 0x04 | HelloResponse | 设备 → 手机 |
| 0x10 | Request（加密） | 手机 → 设备 |
| 0x11 | Response（加密） | 设备 → 手机 |

## 3. 配对（一次性）

手机生成长期身份密钥 `sk_phone`（Ed25519），设备持有身份密钥 `sk_dev`。

```
PairRequest.payload  = PK_phone(32) | nonce_phone(32) | sig(64)
sig = Ed25519(sk_phone, "HWLK1-PAIR" | PK_phone | nonce_phone)
```

设备收到后：

1. 验证自签名（防止别人用你的公钥伪造）；
2. 若已配对且公钥不同 → 直接拒绝；若相同 → 继续；
3. 若尚未配对 → 在**可信屏幕**显示 6 位配对码（由 `SHA256("HWLK1-PAIR-CODE" | PK_phone | PK_dev)` 前 3 字节计算）与手机指纹，
   用户必须按 APPROVE。未确认前同一请求只返回 `pending-pairing`，不会给出任何响应。

```
PairResponse.payload = PK_dev(32) | nonce_phone(32) | nonce_dev(32) | sig(64)
sig = Ed25519(sk_dev, "HWLK1-PAIR-RESP" | PK_phone | PK_dev | nonce_phone | nonce_dev)
```

手机应把 `PK_dev` 固定保存（TOFU + 指纹核对），后续握手若设备公钥变化必须报警。

## 4. 会话握手

```
HelloRequest.payload  = PK_phone | PK_phone_eph | nonce_phone | sig(64)
sig = Ed25519(sk_phone, "HWLK1-HELLO" | PK_phone | PK_phone_eph | nonce_phone)
```

设备验证签名与配对公钥一致后，生成临时密钥对 `sk_dev_eph` 与 `nonce_dev`：

```
HelloResponse.payload = PK_dev | PK_dev_eph | nonce_dev | sig(64)
sig = Ed25519(sk_dev, "HWLK1-RESP" | PK_phone | PK_phone_eph | nonce_phone
                       | PK_dev | PK_dev_eph | nonce_dev)
```

双方计算：

```
transcript      = "HWLK1-SESSION" | PK_phone | PK_phone_eph | nonce_phone
                                | PK_dev   | PK_dev_eph   | nonce_dev
transcript_hash = SHA256(transcript)
scalar          = SHA512(seed_eph)[0..31]              // 未 clamp 的预密钥
shared          = X25519(scalar, peer_eph)             // RFC 7748，内部 clamp
keys            = HKDF-SHA256(ikm=shared, salt=transcript_hash, info="HWLK1-KEYS", 64)
key_c2d         = keys[0..31]
key_d2c         = keys[32..63]
session_id      = LE32(transcript_hash[0..3])
```

`PK_*_eph` 是 **Curve25519 的 u 坐标**，不是 Ed25519 点。身份密钥仍然是 Ed25519（签名用），
只有临时交换换成了 X25519：协议版本因此从 1 升到 2，v1 手机与 v2 设备必须直接失败，
否则两端会对同一段 transcript 派生出不同的共享密钥。X25519 的贡献是对端库只要会
"curve25519/x25519" 就能互通，不必实现 Ed25519 群上的 ECDH 约定。

每帧一个方向键、一个 12 字节 nonce：`session_id(4) | direction(1) | sequence(4) | 00 00 00`。
加密为 ChaCha20（计数器从 0 起），认证为 HMAC-SHA256（Encrypt-then-MAC），
MAC 输入为 `header | nonce | ciphertext`。

设备侧强制：

- 只处理 `session_id` 匹配、`sequence` 严格递增的帧；重复帧返回 `replay`；
- 任何认证失败立即销毁会话密钥（下次必须重新握手）；
- 会话 3 分钟无活动、或超过 4096 帧自动失效；
- 一次 SELECT/字段丢失即清空未完成分片。

## 5. 应用层请求

`Request.payload` 明文格式：

```
request_id(4) | opcode(1) | 参数...
```

`Response.payload` 明文格式：

```
request_id(4) | status(1) | 数据...
```

| opcode | 名称 | 参数 | 回复数据 |
| --- | --- | --- | --- |
| 0x01 | PING | 无 | 无 |
| 0x02 | INFO | 无 | version(1)、flags(1)：bit0 钱包已解锁、bit1 有待审阅、bit2 会话、bit3 配对中 |
| 0x03 | CATALOG | offset(2)、limit(1) | total(2)、offset(2)、count(1)、count × {id 文本, symbol 文本, caps(1)} |
| 0x04 | ADDRESS | coin_len(1)、coin、account(4)、change(4)、index(4)、可选 major(4)、minor(4) | address 文本、path 文本 |
| 0x05 | BEGIN_SIGN | coin_len(1)、coin、kind(1)、address_index(4)、payload_len(2)、payload | review_id(8) |
| 0x06 | RESULT | review_id(8) | 未批准时 `pending`；批准后 status + len(2) + 已签名交易 |
| 0x07 | CANCEL | review_id(8) | rejected |

`BEGIN_SIGN` 的 `kind` 取值为 1=UTXO/PSBT、2=EVM、3=Kaspa、4=Zcash、5=CryptoNote（`xmr` 或 `zeph`），
6=Solana，7=TRON（payload 为 `raw_data`，返回 `r||s||v` 65 字节签名），
8=Cosmos（ATOM/OSMO/TIA，payload 为 [Cosmos 范围与证据](chain-protocols.md) 定义的紧凑结构：
v1 为原生 denom、无 memo，v2 追加 denom 与 memo，返回完整 `TxRaw`），9=Stellar（`coin_id=xlm`，主网网络哈希与 unsigned envelope XDR，返回完整 signed envelope；详见 [stellar-signing.md](chain-protocols.md)），
10=Algorand（`coin_id=algo`，payload 为 canonical unsigned MessagePack，返回 `{sig, txn}`；详见 [algorand-signing.md](chain-protocols.md)），
11=NEAR（`coin_id=near`，payload 为 unsigned Borsh `TransactionV0`，返回 `tx || 0x00 || sig`；详见 [near-signing.md](chain-protocols.md)），
12=Tezos（`coin_id=xtz`，payload 为 manager operation 原始字节，返回 `forged || signature`；详见 [tezos-signing.md](chain-protocols.md)），
13=XRP（`coin_id=xrp`，payload 为 50 字节 Payment 审阅结构，返回完整 signed binary；详见 [xrp-signing.md](chain-protocols.md)），
15=Dash（`coin_id=dash`，payload 为紧凑审阅结构，返完整签名交易，详见 [chain-protocols.md](chain-protocols.md)）。14=Chain（`coin_id=vet|icx|ton|dcr|ckb|ada|hive|sui|fil|dot|ksm`。SUI 的 payload 是原始 BCS TransactionData，返回 97 字节 `flag||signature||public_key`；FIL 的 payload 是原始 CBOR Message，返回完整 SignedMessage CBOR；ADA 的 payload 是原始 Conway body CBOR，返回 `[body, witness_set, true, null]`，三者都不带自定义 magic，详见 [sui-filecoin-signing.md](chain-protocols.md) 与 [chain-signing.md](chain-protocols.md)。其他 payload 以各链 magic 开头；VET 返回完整 signed RLP，ICX/TON/DCR/CKB 返回各自签名或完整签名交易，HIVE 返回 65 字节 graphene 签名，详见 [chain-signing.md](chain-protocols.md)；DOT/KSM 使用 `DOT2` payload（短命期 era + tip），返回 v4 signed extrinsic，详见 [chain-signing.md](chain-protocols.md)）。

状态字节：`0` ok、`1` pending（等待按键）、`2` rejected、`3` unknown-coin、`4` invalid、
`5` expired、`6` unsupported、`8` not-approved、`9` **locked**（设备已配对但钱包未解锁，RAM 里没有任何密钥）、
`10` **fee-policy**（手续费超过该网络上限，在任何曲线运算前拒绝）。
`7` 已废弃并保留，不再返回。

`BEGIN_SIGN` 的 `payload_len` 上限为 16384 字节（CryptoNote 交易远大于 UTXO 请求），
APDU/链路分片已按此调整；超过上限返回 `invalid`，不会截断解析。
`address_index` 同时用于派生地址与派生签名密钥，两者必须同源（`m/44'/128'/0'/0/<index>`），
子地址输入消费已接入；XMR 子地址目的地只接受本节定义的 `R=rD` 或
payload v3 additional-key 绑定，拒绝未绑定输出。

`ADDRESS` 只返回公钥/地址，永远不返回私钥；`QrlXmss` 等密钥生成代价高的网络在链路上直接拒绝。
末尾追加 `major(4)、minor(4)` 时返回 CryptoNote 子地址（`path` 会带 `+major/minor` 后缀）；旧客户端不带这两个字段，行为保持不变。

### 5.0 解锁前置条件

链路本身不保存也不需要任何私钥，但 **派生地址与签名都需要设备处于已解锁会话**（种子在 RAM 中）。
当前解锁通过 USB CLI 完成：

1. 长按 BOOT 键 3 秒打开 USB 数据（默认 10 分钟窗口）；
2. `auth begin` / `auth unlock <proof-hex>`，然后 `wallet import` 或 `wallet generate`；
3. 手机即可在会话有效期内一直通过 NFC 请求地址与签名。

会话超时（默认 5 分钟无操作）或 `lock` 会清空 RAM，链路随后返回 `locked`。
这保证「设备离线、密钥只在解锁后的 RAM 中存在」，而不是把种子常驻。

### 5.1 发送（签名）时序

1. 手机构造未签名交易（PSBT / EIP-155 原始 RLP / Kaspa review payload / ZEC4 或 ZEC5 payload / CryptoNote payload），
   通过 `BEGIN_SIGN` 发出。
2. 设备解析并按自身策略校验：输入必须属于本钱包、找零与地址重新派生校验、手续费上限、重复输入、金额范围、
   合约白名单与 ABI 子集。任何一项失败都不会进入审阅界面。
3. 设备在**可信屏幕**显示收款地址、金额、手续费，并给出 `APPROVE` / `REJECT` 触摸按钮；
   `review_id` 用于把手机的下一次 `RESULT` 绑定到这一次审阅。
4. 用户按键后，手机再次碰触/发送 `RESULT`：
   - 未按键 → `pending`；
   - 按了拒绝 → `rejected`；
   - 按了同意 → 设备在本次调用内派生私钥、签名、立即清零，并把**已签名交易字节**返回。
5. 手机广播交易。设备不联网，也不保存交易。

审阅有效期 2 分钟；超时自动清空，手机必须重新发起。

## 6. 安全性质与已知限制

已防护：

- 未配对/被替换的手机：拒绝（公钥固定）。
- 伪造握手：Ed25519 签名 + 会话密钥来自临时 ECDH，攻击者无法离线伪造。
- 重放/乱序/篡改：sequence 严格递增、Encrypt-then-MAC、认证失败即销毁会话。
- 未经用户按键的签名：设备只在 `APPROVE` 之后生成签名；串口/手机都无法代替按键。
- USB 常开风险：默认关闭，仅物理长按开启并有时间窗；上锁立即关闭并丢弃残留输入。
- 无显示屏的板子：审阅链路直接失败（`unsupported`），不会退化成“主机确认”。

已知限制（必须如实告知用户）：

1. **链路身份密钥与配对公钥保存在 NVS**，不是 SE050。泄露身份密钥只能冒充“设备对手机”，
   不能签名任何交易；后续应迁移到安全芯片。
2. 没有距离边界（distance bounding），NFC 中继攻击理论上可转发帧；但签名仍要求现场按键，且屏幕显示真实收款信息。
3. 配对码只显示 6 位十进制，配合指纹字符串核对；请对照手机端显示的公钥指纹。
   配对提示 60 秒后自动作废，且第三方无法取消你已经确认到一半的配对。
4. NFC 控制器的具体引脚必须来自原理图；未定义时 NFC 端口报告 `not-configured`，不会猜测引脚。
5. PN7161 驱动按 NCI 的 CORE_RESET / CORE_INIT / RF_DISCOVER_MAP（NFC-A passive listen → ISO-DEP）
   / RF_DISCOVER（`0x02` = NFC-A passive listen，106 kbps）流程实现，DATA 包按 1 字节长度与
   PBF 分片处理，连接 ID 取 RF_INTF_ACTIVATED_NTF 的最后一个字节。
   **尚未在实机上做射频与协议一致性验证**；上板前必须用 PN7161 EVK 与读卡器逐项核验。
   如果模组的 NFCC 固件需要开机补丁，需先用厂商工具刷入，然后本驱动才能通信。

## 7. CryptoNote

手机通过 `kind=5` 和 `coin_id` 选择网络。设备按币种解释交易前缀，验证输出归属、找零、矿工费和签名。线格式和测试向量见[链交易载荷](Chain-Payloads-zh.md)。
