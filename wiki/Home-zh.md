# HexWallet wiki（中文）

HexWallet 的签名发生在单片机内部：助记词在设备里派生成密钥，交易在设备上解析和审查，只有按下可信屏幕上的
确认键之后才会释放签名。固件里没有网络栈。

**本 wiki 是 [README](https://github.com/blueokanna/HexWallet/blob/main/README_CN.md) 的长文档版本。**
每一页都有英文和中文两个版本，页面顶部的 `English` 链接用于切换。

## 先看这里

代码是真的，测试过，但没做完。具体来说：

- host 套件全绿（72 项具名检查），CI 编译了所有板型。这就是"绿灯"的全部含义。
- 仓库里没有任何一块板子的硬件验收记录，没有任何一条链在真实节点上通过验收，也没有第三方审计。
- 安全芯片托管做到了 SCP03/APDU 这一层，但钱包层仍在 MCU RAM 里派生和签名。设备默认的
  `HEXWALLET_REQUIRE_SECURE_CUSTODY=1` 会把钱包会话编译成一律拒绝。现在的设备固件无法创建、导入或使用钱包。
- 不要在这棵代码树的任何构建上存你赔不起的钱。

## 从这里开始

| 你想做什么 | 看哪一页 |
| --- | --- |
| 搞清楚模块怎么分工 | [Architecture](Architecture-zh) |
| 知道设备到底强制了什么 | [Security-Model](Security-Model-zh) |
| 查每条链的真实能力 | [Supported-Chains](Supported-Chains-zh) |
| 写主机侧工具 | [Chain-Payloads](Chain-Payloads-zh) |
| 接手机 App | [Phone-Link](Phone-Link-zh) |
| 了解 SE051 现在到哪一步 | [Secure-Element](Secure-Element-zh) |
| 编译和刷机 | [Build-and-Flash](Build-and-Flash-zh) |
| 跑测试 | [Testing](Testing-zh) |
| 弄明白某条链为什么没进目录 | [Admission-Policy](Admission-Policy-zh) |
| 知道这套设计防不住什么 | [Threat-Model](Threat-Model-zh) |
| 看带日期的工程记录 | [Audit-Records](Audit-Records-zh) |

## 这些数字是算出来的

下表中的数字由 `tests/host/catalog_dump.exe` 和 `tools/generate_mining_catalog.py` 从编译进去的表里生成，
代码一改数字就变：

| 项目 | 数值 |
| --- | --- |
| 目录对外的钱包条目 | 215 |
| 编译进来的网络配置 | 247 |
| EVM 网络 | 63 |
| 生成的 UTXO 分叉配置 | 105 |
| 固定 token 记录 | 78 |
| 原生链接适配器 | 24 |
| 已解析的 MiningPoolStats 条目 | 520 个活跃条目中的 121 个 |

"目录条目"的含义是"派生路径 + 审查/签名策略"，不是"这条链在节点上能用"，更不是"有人在硬件上跑过"。

## 仓库地图

```text
HexWallet.ino      Arduino 入口（sketch 目录同时是库根）
WalletConfig.h     全部编译期开关、板型选择、上限
WalletBoardPins.h  各板引脚表，每个都对齐原理图
WalletSecurity.*   BIP39/BIP32、secp256k1、Ed25519、KDF、清零
WalletEngine.*     路径构造与地址派生
WalletNetworks.*   网络配置、编码方式、签名策略
WalletCatalog.*    面向用户的钱包列表和能力位
WalletSigning.*    "审查 → 批准 → 签名"会话，一次只处理一笔
WalletCli.*        需要认证的串口控制台
WalletLink*.*      手机协议、会话加密、NFC APDU 传输
Se051*.*           安全芯片 APDU、SCP03、曲线、个人化
*Transaction.*     每条链一个解析/序列化模块
tests/host/        host 测试框架、探针、编译检查
tools/             目录生成器与人工核对过的映射
wiki/              本文档（GitHub wiki 的源文件）
```

## 许可证

HexWallet Personal Non-Commercial Source License 1.0：source-available，仅限个人非商业使用；
商业使用需另行签署授权。以仓库里的 `LICENSE` 全文为准。第三方组件保留各自条款（`NOTICE`）。
