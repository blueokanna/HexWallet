# SE051C2HQ1：实现与验收边界

当前固件不能作为已验收的生产钱包交付。板子尚未打样、配钥或完成实机测试；SE051 的安全通道也没有与钱包的派生、恢复和交易签名贯通。

## 已实现

`Se051ArduinoPort.cpp` 实现 NXP Plug & Trust 的 `axI2CInit/Read/Write/Term` 和计时接口，替代官方 Linux 平台端口。接口按 [NXP 官方源码](https://github.com/NXP/plug-and-trust/tree/7102413e0457d3dfa4fc4be686ca8ec50bd9f5e2) 核对，固定提交为 `7102413e0457d3dfa4fc4be686ca8ec50bd9f5e2`。

- 专用 Wire1，100 kHz，单次总线操作超时 100 ms。
- 上游使用 8 位地址 `0x90`，Arduino Wire 使用 7 位地址 `0x48`。
- 缓冲至少 260 字节；一个 T=1 帧只发起一次 I²C 事务。
- 短写清空发送缓冲；短读清空接收输出。数据 NACK、超时或不完整帧会使端口失效，必须关闭并重新建立安全会话。
- 同一会话只允许创建它的任务操作。板级诊断不再读取任意 I²C 字节并伪称 ATR，也不会重置 SDK 已占用的总线。初始化、诊断和关闭仍须由同一串行执行路径调度。

端口默认不启用。启用需要 `HEXWALLET_ENABLE_NXP_SE051=1`、板型 7、官方 SDK 的 `T1oI2C` 配置与头文件搜索路径。不能同时链接 SDK 的 Linux `i2c_a7.c` 或通用 `sm_timer.c`。本仓库没有打包完整的 Arduino SSS 库，也没有用默认测试密钥自动打开 SCP03；打开该宏本身不足以完成固件集成。

`SecureElementPort` 现在会清理打开失败时的半初始化状态，会话失去认证后必须重新打开。假后端生命周期测试只在主机测试构建中存在，设备自检不会替换真实后端。

`WalletCustody` 区分“认证通道”和“钱包密钥托管”。现有 `WalletSession` 仍返回 MCU 明文 seed，交易模块仍接收 MCU 私钥，因此即使通道认证成功，生产托管门也保持关闭。这是未完成的架构工作，不能通过返回 `true` 或增加能力标志解决。

## SCP03 安全通道（本轮新增，已主机验证，未实卡验证）

`Se051Scp03.cpp` 按 GlobalPlatform SCP03 实现：AES-CMAC KDF（label 0x04/0x06/0x07，context =
host challenge ‖ card challenge）、卡与主机 cryptogram（label 0x01/0x02）、命令包裹（CLA 置 SM
位、ISO 7816-4 填充、`S-ENC` CBC 加密、C-MAC 覆盖 `chain‖header‖Lc‖data'`、链值推进）、响应解包
（先校验 8 字节 R-MAC 再解密，MAC 错即清会话）。`SecureElementPort` 补了 AES-128 逆密码
（FIPS-197 加密向量反向验证），响应解密需要它。

主机自检的数值对照来自一份独立实现（纯 Python 的 AES-128/CMAC，先用 FIPS-197 C.1 与
RFC 4493 向量自证），钉死的内容包括：派生出的 S-ENC/S-MAC/S-RMAC、两个 cryptogram、一条
21 字节载荷的命令密文与 C-MAC、一条响应的 R-MAC。另有篡改、截断、超长、无会话、缓冲不足
五类拒绝路径。

这些只证明代码与规范一致，**不证明某张真实 SE051 接受它**。实卡验收前不要把它写进任何
"已支持"表述。

## 曲线装载与卡内派生

SE051 出厂可能没有装载 secp256k1 域参数。`Se051Provisioning.h` 把
`0x6A80`/`0x6A88` 明确归类为"曲线未装载"，并且只允许：装载一次 → 立即重试一次；重试仍报
缺曲线就判死，不再循环。其它状态字一律不当成缺曲线，避免把真实故障当成"再写一次就好"。

## Applet 命令字节（本轮新增，按 NXP 公开源码逐项核对）

之前这里写的是"`WriteECCurve` 的 APDU 字节没有可核对的来源"。这个结论**只对了一半**：
`SE05x/SE051 APDU Specification` 本身未公开，但 NXP 的
[plug-and-trust](https://github.com/NXP/plug-and-trust) 携带了**生成后的 APDU 层**，命令的
CLA/INS/P1/P2 与 TLV 布局都能逐行核对。`Se051Apdu.h/.cpp` 就是照这些文件写的：

| 用途 | 出处 | 结论 |
| --- | --- | --- |
| CLA | `hostlib/hostLib/inc/se05x_tlv.h:30` | 命令 CLA `0x80`；`0x84` 是 GP SCP03 自己的 APDU（`nxScp03_Const.h` 的 `CLA_GP_SECURITY_BIT`），不用于 applet 命令 |
| INS | `se05x_enums.h:96-123` | **没有逐命令的 INS 枚举**。INS 是位域：`0x01 WRITE`、`0x02 READ`、`0x03 CRYPTO`、`0x04 MGMT`，另加 `0x20 ATTEST`、`0x40 AUTH_OBJECT`、`0x80 TRANSIENT`。"CreateECCurve" 就是 `INS_WRITE` + `P1_CURVE` |
| P1/P2 | `se05x_enums.h:125-256` | `P1_CURVE=0x0B`、`P1_SIGNATURE=0x0C`、`P1_MAC=0x0D`、`P1_EC=0x01`、`P1_KEY_PAIR=0x60`；`P2_CREATE=0x04`、`P2_PARAM=0x40`、`P2_LIST=0x25`、`P2_SIGN=0x09`、`P2_DH=0x0F`、`P2_GENERATE_ONESHOT=0x45`、`P2_SESSION_CREATE=0x1B`、`P2_SESSION_POLICY=0x1F`、`P2_SESSION_UserID=0x2C`、`P2_VERSION=0x20`、`P2_RANDOM=0x49` |
| 命令数据 | `se05x_APDU_impl.h` 每个 `Se05x_API_*` 里的 `tlvHeader_t hdr` 行 | 曲线 id **在数据里**（TLV tag `0x41`），不在 P1/P2 |
| TLV 编码 | `se05x_tlv.c` `tlvSet_u8buf` | tag 1 字节、短格式长度（<0x80 一字节，`0x81`+1 字节，`0x82`+2 字节）、值 |
| 标签表 | `se05x_enums.h:285-319` | `0x41`…`0x4B` 是 TAG_1..TAG_11；`0x10` 会话、`0x11` policy、`0x12` MaxAttempts |
| AID | `sm_const.h:28-36` | `A0 00 00 03 96 54 53 00 00 00 01 03 00 00 00 00`（SE051 用同一个 applet） |
| 曲线 id | `se05x_enums.h:506-533` | `NIST_P256=0x03`、`Secp256k1=0x10`、`ECC_ED_25519=0x40`、`ECC_MONT_DH_25519=0x41` |
| 曲线参数类型 | `se05x_enums.h:546-555` | `A=0x01`、`B=0x02`、`G=0x04`、`N=0x08`、`PRIME=0x10` |

因此现在**有**字节可发，并且主机自检把每条命令的完整帧逐字节钉死（例如
`CreateECCurve(secp256k1)` = `80 01 0B 04 03 41 01 10`、`SetECCurveParam` 的 Lc 由三个 TLV
算出、`Sign` 是 `80 03 0C 09 … 00`、`ECDH` 走扩展 Le 所以末尾是 `00 00`）。同时钉死的还有
长度规则与拒绝路径：超过 255 字节的命令、写不下的 TLV、截断的响应一律失败，不截断也不猜。

三条仍然成立的边界，写清楚以免被当成已验收：

- **实卡没有互验。** 这些字节与规范一致，不等于某张 SE051C2 接受它们。`0x9000` 之外的
  状态字、policy 语义、每个料号的曲线授权都在未公开的 APDU 规范里。
- **空命令的长度字段**（`GetVersion` / `ReadECCurveList`）按 ISO 7816-4 case 2 编码为
  `CLA INS P1 P2 Le`，依据是 SDK 把空缓冲折叠掉、`DoAPDUTxRx_s_Case4` 的 `hasle=0` 只产生
  一个 Le 字节。第一次上实卡应优先复核这两帧。
- **曲线参数数值**（A/B/G/N/PRIME 的 32/65 字节块）没有写进仓库：`se05x_ECC_curves.c` 里那是
  一整张表，而多数料号出厂已带 secp256k1/P-256，`ReadECCurveList` 会直接告诉我们。要用
  `SetECCurveParam` 才需要那张表。

`se051_apdu_hmac()` 对应的就是下面这段卡内派生设计要用的单次 HMAC 命令
（`INS_CRYPTO` + `P1_MAC` + `P2_GENERATE_ONESHOT`），所以"缺 applet 的 HMAC 命令"这一条
现在只剩 PIN 会话接续和实卡验证。

卡内 BIP32 派生的设计是：主种子前 32 字节作 `k_par`、后 32 字节作 `c_par`，`c_par` 写入
`P1_HMAC_KEY` 并绑定 UserID（PIN 认证对象），每次派生子密钥前先 `VerifySessionUserID` 再用
`INS_CRYPTO` 做 HMAC-SHA512；PIN 错误次数由卡片硬件计数，超过 `MaxAttempts` 锁死槽位。
命令帧已经具备（`se051_apdu_session_create`、`se051_apdu_session_policy`、
`se051_apdu_verify_session_user_id`、`se051_apdu_hmac`），还缺的是 PIN 会话接续与实卡互验，
所以当前派生仍在 MCU 内完成——这正是 `WalletCustody` 仍拒绝声明"生产托管"的原因。

## 原理图记录

审阅输入是用户提供的 `ProPrj_c26102103_2026-10-28.epro2`，SHA-256：

`0450e8c5148747dbb9ec6f1bcf37d7583e2c402c492193a84cdcff53a8d2619d`

压缩包内的 EPRU 包含 `SE051C2HQ1/Z01XDZ` 器件与 `050_SDA`、`050_SCL`、`050_RST` 网络。现有板级配置使用 GPIO10/11/12。这里只确认项目内容和软件配置，不把网络名、器件库或编译成功当作电气、焊接和时序验收。

## 尚未完成

| 项目 | 必须补齐的实际工作 |
| --- | --- |
| SSS/SCP03 | SCP03 通道已实现并主机自检（KDF、卡/主机 cryptogram、C-MAC 包裹、R-MAC 校验与解锁、计数推进、篡改即清会话）；缺的是 applet 的 INS 表与实卡互验、设备独有配钥、主机密钥保护、完整 Arduino 库链接 |
| 曲线装载 | 帧已按 plug-and-trust 逐字节实现并自检（`Se051Apdu`：`CreateECCurve`、5 个 `SetECCurveParam`、`ReadECCurveList`）；`Se051Provisioning` 仍负责"只在本机配一次、失败立即重试一次、再失败即判死"的策略。缺的是实卡互验与（如果料号未预置曲线）A/B/G/N/PRIME 参数块 |
| 卡内派生 | 设计已定：BIP32 子密钥由 SE051 用 HMAC-SHA512 在卡内完成，主种子前 32 字节作 `k_par`、后 32 字节作 `c_par`，`c_par` 进 `P1_HMAC_KEY` 并绑定 UserID；命令帧已具备（会话创建/策略/`VerifySessionUserID`/单次 HMAC），缺 PIN 会话接续与实卡验证，因此当前仍由 MCU 派生，托管门保持关闭 |
| 钱包托管 | 非导出对象句柄贯通派生、签名与恢复；禁止回退到明文 MCU 私钥；签名前绑定已审阅交易 |
| Chia | 替换 G1/G2 和标量运算的可变时间路径；验证 EIP-2333、synthetic key、AugScheme 与标准 puzzle 的上游向量；P4 侧信道和资源验证 |
| QRL | 完整 XMSS 签名及交易编码；按公钥绑定的不可回滚 OTS 预留；预留先于签名，取消、断电与结果丢失均不归还叶索引；跨设备恢复防重用 |
| DOT/KSM | 可信 runtime metadata 来源、版本和扩展绑定；验证 SCALE、extrinsic、metadata hash 与审阅字段；升级或未知调用默认拒绝 |
| 生产设备 | Secure Boot、Flash Encryption、调试口策略、可信显示/物理批准、掉电故障注入、签名独立验证与全节点接收测试 |

普通 Flash/NVS 的双副本或校验和只能处理部分掉电损坏，不能证明 QRL 状态不可回滚。离线设备仍可能收到恶意 USB/NFC 数据；只要秘密进入已被攻破的 MCU RAM，就不能保证秘密不被读取。SE051 的加密算法能力也不等于支持 BLS、XMSS 或整套链上交易语义。

## 可重复检查

开发电脑准备上述固定提交的 NXP 仓库后运行：

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/se051_port_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/se051_port_check.ps1 -Device
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
powershell -ExecutionPolicy Bypass -File tests/host/build_chain_native.ps1
powershell -ExecutionPolicy Bypass -File tests/host/policy_check.ps1
```

前两项分别验证故障行为和真实 P4/Arduino 头文件编译，不包含 SCP03 实机验收。`policy_check.ps1 -RegistryOnly` 仅检查注册表与源文件网络头文件；缺少生产策略可执行文件时，完整检查必须失败。
