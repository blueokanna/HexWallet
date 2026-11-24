# 手机链路

[English](Phone-Link) · [首页](Home-zh)

链路操作由手机发起，已签交易也由手机提交节点。钱包按适配器解析或重建交易，供本机审阅、批准和签名。协议版本是 **2**。
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
Request.payload  = opcode(1) | request_id(4) | 参数…
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

Ryo 省略可选子地址参数时，按原有规则将账户和索引映射为地址。显式 `(0, 0)` 选择该 BIP32 子密钥的标准地址。如果两种请求得到的地址不同，显式标准地址的显示路径带 `+0/0` 后缀。Zano 在每个 BIP32 子密钥上使用标准地址，并拒绝非零子地址参数。完整路径超出显示字段容量时请求失败。

发布目录对两种币开放地址。`TEST_RYO_PHONE_PAYMENTS=ON` 主机探针还接受 `ryo`、类型 `5` 的 `BEGIN_SIGN`，支持一个外部长标准地址和可选找零。16 字节应用头后可放 16,368 字节。载荷依次为版本 `1`、小端 16 位未签交易长度、交易字节、32 字节交易私钥、收款人公开花费与查看密钥，以及每个输入的资金记录。记录包含 16 位真实环位置、64 位资金输出序号、资金交易公钥、64 字节 ECDH 数据、伪输出掩码和环成员。每个环成员含 64 位绝对输出索引、一次性公钥与承诺。

手机核对输入归属和带签名的 key image。设备核对收款、找零、费用和完整 payment ID，再接受本地批准。每笔费用上限为 0.1 RYO。`RESULT` 只返回一次签名字节，手机复核交易并校验主网创世哈希后广播。隔离链测试由脚本提交，官方只读钱包独立扫出两笔收款。[回执](validation)

Zano 专用主机探针接受一至两个输入、每环 16 个成员、两个输出的普通 v4 原生资产付款。固件检查输入归属，重建两个输出，显示收款人、金额、找零、固定费用 0.01 ZANO 及八字节 payment ID。恰好花完时两个输出均付给同一收款人。一次性批准后，手机验证每个 CLSAG_GGX 签名及整笔付款证明。广播函数核对主网创世哈希，隔离测试链由脚本另行提交。[回执](validation)

ETH 和 SOL 的 `BEGIN_SIGN` 参数顺序为 `币种名长度(1) | ASCII 币种名 | kind(1) | 地址索引(4，小端) | 载荷长度(2，小端) | 载荷`。ETH 使用 `eth` 和 kind 2，载荷为未签名的 EIP-155、2930 或 1559 交易。以太坊主网 Lido `submit(address)` 和 Uniswap V2 Router02 `swapExactETHForTokens` 有专用审阅页。SOL 使用 `sol` 和 kind 6，载荷为单签名者、静态账户的 legacy 或 v0 消息。原生质押支持委托和停用已有质押账户。

经典兑换支持 devnet 的 SPL Token Swap（`SwapsVeCiPHMUAtzQWZw7RjsKjgCjhwU55QGu4U1Szw`）和主网的 Orca V2（`9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP`）。指令依次传入池、池授权地址、付款人兼转账授权人、付款代币账户、输入金库、输出金库、收款代币账户、池代币 mint、手续费账户和经典 SPL Token 程序，共 10 个账户。设备显示这些地址，以及按最小单位计的投入量和最低收取量。手机需在目标集群查询两侧金库，核对输入及输出代币的 mint。14 账户的 Token-2022 格式和额外的主机手续费账户均不在支持范围内。[SPL 部署表](https://spl.solana.com/token-swap) · [Orca SDK](https://github.com/orca-so/typescript-sdk)

审阅期间保持认证连接。手机用八字节审阅 ID 调用 `RESULT` 取回签名交易，NFC 离场会撤销批准。运行 `npm ci --prefix tools --ignore-scripts` 安装广播适配器的锁定依赖。`tools/phone_broadcast.cjs` 接收 `BEGIN_SIGN` 的原始字节、`RESULT` 返回的字节和手机的 RPC 回调。ETH 适配器核对发送方和链 ID，SOL 适配器核对付款人、集群创世哈希和近期区块哈希。返回值是节点受理的交易 ID。手机可用 `eth_getTransactionReceipt` 或 `getSignatureStatuses` 跟踪执行结果。

`kind` 决定解析器：1 UTXO/PSBT、2 EVM、3 Kaspa、4 Zcash、5 CryptoNote（XMR）、6 Solana、7 TRON、
8 Cosmos、9 Stellar、10 Algorand、11 NEAR、12 Tezos、13 XRP、14 Chain（VET、ICX、TON、DCR、CKB、ADA、
HIVE、SUI、FIL、DOT、KSM）、15 Dash。`BEGIN_SIGN` 最多 16384 字节，超出返回 `invalid`，绝不截断。
审查有效期 120 秒。

kind 15 接收 `DAS2` 或 `DAS3` 载荷。两者都必须带每个输入的资助交易；`DAS3` 多一个 flags 字节，
bit0 表示 InstantSend 意图。设备会显示这个声明，说明锁是它无法验证的 quorum 决定，并且两种情况
签出的字节完全相同。见 [载荷格式](Chain-Payloads-zh#dash)。

派生地址和签名都要求钱包会话已解锁。解锁走 USB CLI（`auth begin`、`auth unlock`），链路本身永远不传 PIN。
`ADDRESS` 永远不返回私钥；密钥生成代价太高的适配器在链路上直接拒绝。

## Ethereum DApp 连接

手机钱包为每个获准的 HTTPS 顶层页面调用 `tools/ethereum_provider.cjs` 的 `createEthereumConnection({origin, approveOrigin, exchange, rpc, index})`。从钱包浏览器取得 origin，每次桥接请求都核对调用方页面。配对传输、授权弹窗和 RPC 保留在钱包端。页面使用 EIP-1193 `provider`，通过 `announceEthereumProvider` 参与 EIP-6963 发现。`eth_requestAccounts` 请求 `m/44'/60'/0'/0/index` 的地址，`eth_sendTransaction` 另需设备审阅。该适配器绑定 Ethereum 链 ID 1。

页面导航、NFC 离场或钱包锁定时调用 `disconnect()`，关闭配对会话并移除公告监听器。传输实现须处理传给 `exchange` 的中止信号。手机在广播前核对签名交易的原始字节、付款账户和 RPC 链 ID。Chromium 回归使用公开测试种子与固件应用回调。实体手机配对和 SE051 实卡签名仍待验收。[测试证据](validation)

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
