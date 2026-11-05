> Dated status record. Current documentation: [Security-Model](Security-Model) / [Security-Model-zh](Security-Model-zh).

# 认证与传输验收状态

2026-11-01。编译成功不等于硬件验收。

| 项目 | 当前实现 | 还缺什么 |
| --- | --- | --- |
| 2.9 寸黑白屏 | SSD1680 1bpp，局刷窗口、旧帧基线、局刷预算；局刷用控制器 OTP 波形，板级可选自带 LUT | 确认实物型号；温度、残影、掉电与 BUSY 故障测试 |
| 2.9 寸四色屏 | SSD1683 类 128×296 独立初始化、2bpp 全刷与深睡；禁止局刷 | 确认是否就是该型号；四色和时序实测 |
| TOTP | 八个会话账户、严格 URI 导入、本机批准、屏幕出码、到期及锁定清除 | 安全持久存储、可信 RTC、无主机的完整管理入口 |
| USB 钱包协议 | 默认关闭的应用门控、窗口超时、单帧读取、异常关闭、锁定撤销状态 | 物理数据开关或验证过的 USB detach；当前不是物理隔离 |
| NFC 钱包协议 | 私有 ISO-DEP/APDU 协议；与 USB 互斥占用会话 | PN7161 实机手机互通及异常场强测试 |
| FIDO2/passkey | `P256Sign`（RFC 6979 nonce、low-S、严格 DER、RFC 6979 A.2.5 KAT 钉死的 ES256 原语）与 `CtapHid` 分帧、INIT/PING、取消、超时、keepalive、异步请求令牌 | CTAP2 CBOR 命令、`makeCredential`/`getAssertion`、凭据后端、PIN/UV、USB HID 描述符、标准 NFC FIDO AID 与浏览器验收 |
| 摄像头 Airgap | OV9281 SCCB 探测和 QR 输出 | 当前板级接线确认、CSI 收流、图像 QR 解码、分片交易接收与完整导入路径 |
| 钱包安全托管 | 未就绪时拒绝载入/签名 | SE051 经过认证的密钥托管后端及设备 provisioning |

`CtapHid` 是传输模块，不是已经可用的 FIDO2 认证器。默认不宣告 CBOR 能力；没有挂接到 USB
描述符，也没有宣称浏览器可以注册 passkey。私有钱包 NFC AID 不是标准 FIDO AID。摄像头扫码
同样不会自动使设备具备 WebAuthn 支持。

ES256 原语本身已经落地在 [src/P256Sign.h](../src/P256Sign.h)：P-256 的 Montgomery 域运算、
Jacobian 点加/倍、double-and-add-always 标量乘、RFC 6979 确定性 nonce、low-S 归一与严格
DER 编码。验收用 RFC 6979 A.2.5 逐字节钉死 `r`/`s`，并验证 RFC 原文的高 `s`、篡改签名、
零 `s`、错误摘要、私钥 `0` 与私钥 `n` 的拒绝路径。这套 KAT 曾抓出两个真 bug（模加进位分支、
`s = (e+rd)/k` 写成了乘法），因此不能把它当成“写过就算”的模块。

曲线覆盖面见 [src/EcdsaCurve.h](../src/EcdsaCurve.h)：它把 secp256k1（`a = 0`）与 secp256r1
（`a = -3`）放进同一个引擎，主机上可跑，因此主机测试第一次能对“产出的签名”本身做独立验签，
而不是只验证拒绝路径。它的 KAT 一半来自外部（RFC 6979 A.2.5、libsecp256k1 与 python-ecdsa
互相一致的一对 `r`/`s`、一条 GRS 主网交易的链上签名），一半来自自证（`n·G` 等于无穷远点）。
X25519 与 Ed25519→Curve25519 的双有理映射在 `Ed25519.cpp` 里实现了 RFC 7748 全套向量，
包括 1000 次迭代那条。secp256k1 的**生产**签名仍走 mbedtls（有 RNG 盲化），in-tree 引擎用于
验签与主机可测性。

回归入口：`tests/host/build.ps1`（含 `p256-ecdsa=pass`、`eink-panel=pass`），以及
`cmake -S tests/host/auth -B build/auth-native -A x64 && cmake --build build/auth-native
--config Release && build/auth-native/Release/auth_test.exe`（TOTP 生命周期、传输冲突、
面板用例，482 项检查）。

本轮修复了 NFC SELECT 响应缓冲区越界、USB 连续帧吞帧、半帧无期限占用、关闭后残留命令，
以及 USB/NFC 共用传输上下文的问题。只有成功 SELECT 的传输能继续读写该会话，另一侧返回
`6985`；断场只撤销 NFC 所属会话。锁定撤销全部传输、配对、签名和 TOTP 状态。

USB 门控关闭时仍可能枚举，启动日志仍存在，ROM 下载模式也不受应用门控控制。原生 CDC 的
软件复位触发已禁用；不能把这些行为写成“USB 物理断开”。

P4 验证包括真实 Arduino/ESP-IDF 头文件下的运行时模块、三种面板配置和真实 LVGL，另测
`HEXWALLET_ENABLE_CLI=0`。驱动等待有上限，但墨水屏刷新目前仍同步阻塞调用任务；要达到同时
处理 NFC/FIDO 的低延迟目标，还需要独立显示任务、SPI 仲裁与实机负载测试。不能仅凭双核配置
宣称已经利用了 P4 的并行能力。

标准依据：[CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)。
