# 手机链路

[English](Phone-Link) · [首页](Home-zh)

所有操作由手机发起。钱包只做审查、授权和签名，它不构造交易，也不连节点。协议版本是 **2**：
v1 的对端和 v2 的设备必须直接失败，因为临时密钥交换从 Ed25519 群上的 ECDH 换成了 Curve25519，
同一段 transcript 会派生出不同的密钥。

## 传输层

| 传输 | 默认 | 开启方式 |
| --- | --- | --- |
| NFC，PN7161 卡模拟 | 由板级引脚决定 | 板级配置里定义 `HEXWALLET_NFC_PN7161` 和 `HEXWALLET_NFC_PIN_*` |
| USB CDC，APDU 封装 | **关闭** | 长按 BOOT/用户键 3 秒；再次长按、上锁、或超过 `HEXWALLET_USB_ENABLE_WINDOW_MS`（10 分钟）自动关闭 |

USB 数据关闭时，固件丢弃串口输入，包括已经缓冲的字节。ROM 下载模式不受影响。USB 和 NFC 走同一套
APDU 与链路协议，手机端只需实现一次。

### APDU 映射（ISO 7816-4）

| 命令 | CLA INS P1 P2 | 数据 | 回复 |
| --- | --- | --- | --- |
| SELECT | `00 A4 04 00` | `06 F0 48 57 4C 4B 31` | `F0 <version>` + SW |
| WRITE | `80 10 <last> 00` | 链路帧分片 | `last=1` 时处理拼好的帧 |
| READ | `80 11 00 00` | 空 | 最多 240 字节，`SW=61xx` 表示还有 |
| ABORT | `80 12 00 00` | 空 | 丢弃分片和已缓冲回复 |
| STATUS | `80 13 00 00` | 空 | 分片/回复长度、会话与配对标志 |

USB 上的封装是 `A5 5A <len_lo> <len_hi> <apdu…>`。

## 帧格式

```text
"HWLK" | version(1)=2 | type(1) | 0 | 0 | session_id(4) | sequence(4)
       | payload_len(2) | payload | [tag(32)]
```

整数全部小端。`tag` 是对 header、nonce 和密文做的 HMAC-SHA256，只有 Request/Response 帧带。
长度不精确匹配一律拒绝。

| type | 名称 | 方向 |
| --- | --- | --- |
| 0x01 | PairRequest | 手机 → 设备 |
| 0x02 | PairResponse | 设备 → 手机 |
| 0x03 | HelloRequest | 手机 → 设备 |
| 0x04 | HelloResponse | 设备 → 手机 |
| 0x10 | Request（加密） | 手机 → 设备 |
| 0x11 | Response（加密） | 设备 → 手机 |

## 配对（一次性）

```text
PairRequest.payload  = PK_phone(32) | nonce_phone(32) | sig(64)
sig = Ed25519(sk_phone, "HWLK1-PAIR" | PK_phone | nonce_phone)
```

设备验证自签名，拒绝第二把不同的手机公钥；如果尚未配对，就在可信屏幕上显示 6 位配对码。配对码是
`SHA256("HWLK1-PAIR-CODE" | PK_phone | PK_dev)` 的前 3 字节。用户按 APPROVE 之前不返回任何东西，
同一请求只会得到 `pending-pairing`。配对提示 60 秒后作废。

```text
PairResponse.payload = PK_dev(32) | nonce_phone(32) | nonce_dev(32) | sig(64)
sig = Ed25519(sk_dev, "HWLK1-PAIR-RESP" | PK_phone | PK_dev | nonce_phone | nonce_dev)
```

手机固定保存 `PK_dev`（TOFU + 指纹比对），一旦变化必须报警。

## 会话握手

```text
HelloRequest.payload  = PK_phone | PK_phone_eph | nonce_phone | sig(64)
sig = Ed25519(sk_phone, "HWLK1-HELLO" | PK_phone | PK_phone_eph | nonce_phone)
HelloResponse.payload = PK_dev | PK_dev_eph | nonce_dev | sig(64)
sig = Ed25519(sk_dev, "HWLK1-RESP" | PK_phone | PK_phone_eph | nonce_phone
                       | PK_dev | PK_dev_eph | nonce_dev)

transcript = "HWLK1-SESSION" | PK_phone | PK_phone_eph | nonce_phone
                            | PK_dev   | PK_dev_eph   | nonce_dev
hash       = SHA256(transcript)
scalar     = SHA512(seed_eph)[0..31]          // 预密钥，此处不 clamp
shared     = X25519(scalar, peer_eph)         // RFC 7748 内部 clamp
keys       = HKDF-SHA256(ikm=shared, salt=hash, info="HWLK1-KEYS", 64)
key_c2d    = keys[0..31]
key_d2c    = keys[32..63]
session_id = LE32(hash[0..3])
```

身份密钥仍然是 Ed25519，只有临时交换是 X25519。每帧用一个方向键和一个 12 字节 nonce：
`session_id(4) | direction(1) | sequence(4) | 00 00 00`。加密是 ChaCha20（计数器从 0 开始），
认证是 HMAC-SHA256（encrypt-then-MAC）。

设备强制：`session_id` 必须匹配、`sequence` 严格递增、任何认证失败立刻销毁会话、空闲 3 分钟失效、
单会话最多 4096 帧。SELECT 丢失或分片缺失都会丢弃半成品帧。

## 应用层

```text
Request.payload  = request_id(4) | opcode(1) | 参数…
Response.payload = request_id(4) | status(1) | 数据…
```

| opcode | 名称 | 参数 | 回复 |
| --- | --- | --- | --- |
| 0x01 | PING | 无 | 无 |
| 0x02 | INFO | 无 | version、flags（已解锁、有待审阅、有会话、配对中） |
| 0x03 | CATALOG | offset(2)、limit(1) | total、offset、count、条目 {id, symbol, caps} |
| 0x04 | ADDRESS | coin、account、change、index [、子地址 major/minor] | address、path |
| 0x05 | BEGIN_SIGN | coin、kind、address_index、payload | review_id(8) |
| 0x06 | RESULT | review_id(8) | `pending`，或 status + 长度 + 已签名交易 |
| 0x07 | CANCEL | review_id(8) | rejected |

`kind` 决定解析器：1 UTXO/PSBT、2 EVM、3 Kaspa、4 Zcash、5 CryptoNote（XMR）、6 Solana、7 TRON、
8 Cosmos、9 Stellar、10 Algorand、11 NEAR、12 Tezos、13 XRP、14 Chain（VET、ICX、TON、DCR、CKB、ADA、
HIVE、SUI、FIL、DOT、KSM）、15 Dash。`BEGIN_SIGN` 最多 16384 字节，超出返回 `invalid`，绝不截断。
审查有效期 120 秒。

kind 15 接收 `DAS2` 或 `DAS3` 载荷。两者都必须带每个输入的资助交易；`DAS3` 多一个 flags 字节，
bit0 表示 InstantSend 意图。设备会显示这个声明，说明锁是它无法验证的 quorum 决定，并且两种情况
签出的字节完全相同。见 [载荷格式](Chain-Payloads-zh#dash)。

派生地址和签名都要求钱包会话已解锁。解锁走 USB CLI（`auth begin`、`auth unlock`），链路本身永远不传 PIN。
`ADDRESS` 永远不返回私钥；密钥生成代价太高的适配器在链路上直接拒绝。

## 链路保护了什么

- 被替换的手机：拒绝，固定公钥对不上。
- 伪造握手：双方用 Ed25519 身份密钥签 transcript。
- 重放、乱序、篡改：序号单调、encrypt-then-MAC、认证失败即销毁会话。
- 没有用户动作就签名：做不到，签名需要设备上的批准。

## 已知限制

1. 身份密钥和手机固定公钥存在 NVS，不在安全芯片里。身份密钥泄漏后可以冒充"设备对手机"，但签不了名。
2. 没有距离绑定。NFC 中继可以转发帧；但签名仍需要在显示真实收款信息的屏幕上物理按键。
3. 配对码只有 6 位十进制，必须配合公钥指纹一起核对。
4. PN7161 驱动按 NCI 的 CORE_RESET / CORE_INIT / RF_DISCOVER_MAP / RF_DISCOVER（NFC-A 被动监听，
   106 kbps）实现，**尚未在硬件上验证**。上板前请用 EVK 和读卡器逐项核验。
5. 无屏板永远不在链路上做审查，也没有"退回主机确认"这条路。
