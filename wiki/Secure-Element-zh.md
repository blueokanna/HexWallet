# 安全芯片（SE051C2HQ1）

[English](Secure-Element) · [首页](Home-zh)

现状：实现到"认证通道 + applet 命令"为止，用 mock 传输做了 host 测试，**没有实卡验证，也不是签名后端**。
钱包仍在 MCU RAM 里派生和签名，所以托管门保持关闭，设备构建拒绝持有钱包。

## 已经有的

| 组件 | 文件 | 状态 |
| --- | --- | --- |
| NXP Plug & Trust 的 Arduino I²C 端口（`axI2CInit/Read/Write/Term`、计时） | `Se051ArduinoPort.cpp` | 按 NXP 固定提交 `7102413e0457d3dfa4fc4be686ca8ec50bd9f5e2` 核对 |
| SCP03：AES-CMAC KDF、卡/主机 cryptogram、C-MAC 包裹、R-MAC 校验、计数推进 | `Se051Scp03.cpp` | 对着独立 Python AES-128/CMAC 实现做过 host 验证；五类拒绝路径有测试 |
| APDU 编码（CLA/INS/P1/P2、TLV、曲线 id） | `Se051Apdu.cpp` | 每条帧逐字节钉死，例如 `CreateECCurve(secp256k1)` = `80 01 0B 04 03 41 01 10` |
| 曲线装载（CreateECCurve + 五条 SetECCurveParam） | `Se051Curves.cpp`、`Se051Provisioning.cpp` | 参数从 `src/EcdsaCurve.h` 反算后逐字节比对 |
| PIN 会话（CreateSession、policy、VerifySessionUserID、`0x63Cx` 次数） | `Se051Apdu.cpp`、`Se051PinSession` | 状态机有 host 测试；未认证会话在本地就拒绝 HMAC |
| 托管门 | `WalletCustody.cpp` | 五个独立事实，每个都有自己的 blocker 文案 |

几个值得记住的常量：applet AID 是
`A0 00 00 03 96 54 53 00 00 00 01 03 00 00 00 00`；曲线 id 有 `NIST_P256=0x03`、
`Secp256k1=0x10`、`ECC_ED_25519=0x40`、`ECC_MONT_DH_25519=0x41`；曲线 id 放在 TLV tag `0x41` 里，
不在 P1/P2。

## 托管门

`secure_custody_backend_ready()` 不是一个常量，它是五个事实的合取：

| 事实 | 来源 | 谁能让它成立 |
| --- | --- | --- |
| `backend_registered` | `secure_element_name()` | 链接进来的后端自己注册 |
| `channel_authenticated` | `secure_element_ready()` | SCP03 握手成功 |
| `user_authenticated` | `secure_element_user_authenticated()` | 卡内 PIN 会话 |
| `keys_non_exportable` | `secure_element_keys_non_exportable()` | 后端承诺密钥不出卡 |
| `wallet_uses_handles` | `WalletSession` 注册的查询 | 派生和签名真的走句柄 |

`custody_gate_blocker()` 返回第一个不成立的事实，`custody <coin>` 会把它打出来。自检会逐条伪证：
每次打掉一个事实，blocker 必须落到对应那一条；同时打掉两个，必须报修复顺序更靠前的那一个。
不存在"改一个 `return true`"就能开门。

SCP03 认证的是**主机**，PIN 认证的是**人**。分开是刻意的："线插上了"不等于"主人在场"。

## 还缺什么

| 缺口 | 为什么挡住托管 |
| --- | --- |
| 实卡互验 | 这些字节和公开 SDK 一致，不等于某张 SE051C2 会接受；`0x9000` 之外的状态字、policy 语义、按料号的曲线授权都在未公开规范里 |
| 会话接续 | 真卡在 `CreateSession` 里返回 session id；PIN 失败后该会话还能不能用取决于 applet policy，所以这里不猜 |
| PIN 派生 | 把 PIN 经 PBKDF2/加密送进卡里的流程还没实现 |
| 卡内 BIP32 | 需要 HMAC-SHA512 **加上** `(I_L + k_par) mod n`、无效子节点检查、非导出对象创建；单条 HMAC APDU 不等于 BIP32 |
| 句柄化钱包 | 派生、审查、签名都必须停止接收明文种子或私钥 |
| 设备唯一密钥 | 主机密钥保护和产线配钥不在树里 |

## 刻意拒绝的做法

- 创建了但参数没写全的曲线报 **Absent**，不报可用。半装载曲线签出固件验不过的签名，是最坏的失败模式。
- 只有在"装载一次 → 立即重试一次"这条路径上，`0x6A80`/`0x6A88` 才表示"曲线未安装"；其它状态字一律算错误。
- 驱动不会为四色屏编造模拟参数，也不会编造局刷波形，更不会猜 SE 引脚。
- 没有明文回退：要求托管却不可用时，钱包操作返回 `CustodyUnavailable`，不降级。

## 复现

```powershell
git clone https://github.com/NXP/plug-and-trust build/nxp-plug-and-trust
git -C build/nxp-plug-and-trust checkout 7102413e0457d3dfa4fc4be686ca8ec50bd9f5e2
powershell -ExecutionPolicy Bypass -File tests/host/se051_port_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/se051_port_check.ps1 -Device
```

SCP03 的向量来自一份独立 Python 实现，那份实现先用 FIPS-197 C.1 和 RFC 4493 自证。被篡改、被截断、
超长、无会话、缓冲不足的响应都必须拒绝。

包含 EasyEDA 审阅哈希的完整工程记录在 `wiki/se051-integration.md`。
