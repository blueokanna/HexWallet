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

## 原理图记录

审阅输入是用户提供的 `ProPrj_c26102103_2026-10-28.epro2`，SHA-256：

`0450e8c5148747dbb9ec6f1bcf37d7583e2c402c492193a84cdcff53a8d2619d`

压缩包内的 EPRU 包含 `SE051C2HQ1/Z01XDZ` 器件与 `050_SDA`、`050_SCL`、`050_RST` 网络。现有板级配置使用 GPIO10/11/12。这里只确认项目内容和软件配置，不把网络名、器件库或编译成功当作电气、焊接和时序验收。

## 尚未完成

| 项目 | 必须补齐的实际工作 |
| --- | --- |
| SSS/SCP03 | 真实 applet/OEF 识别；设备独有配钥；主机密钥保护；认证、命令/响应 MAC、重连与错误状态验证；完整 Arduino 库链接 |
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
