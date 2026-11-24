# HexWallet 使用文档

[English](Home)

HexWallet 在离线设备上解析交易，向用户展示收款人、金额和费用，由用户本地确认。钱包目录提供 214 个条目。生产设备会话当前返回 `CustodyUnavailable`。硬件验收还需要完成 SE051C2HQ1 开卡、不可导出密钥派生与签名句柄集成、可信启动，以及从实物审阅到广播的交易测试。[安全芯片](Secure-Element-zh) · [安全模型](Security-Model-zh)

| 任务 | 对应文档 |
| --- | --- |
| 选择板型，核对 rev A 串口接线，查看 296 × 128 横屏墨水屏画面 | [板卡与显示](Boards-and-Display-zh) |
| 构建固件，迁移已有凭据的设备 | [构建与刷写](Build-and-Flash-zh) |
| 查询某个网络可以审阅的交易类型 | [逐链能力](Supported-Chains-zh) · [登记表](Registries-zh) · [准入策略](Admission-Policy-zh) |
| 对接手机或主机软件 | [手机协议](Phone-Link-zh) · [交易载荷](Chain-Payloads-zh) |
| 查询 SDK 对照、原生节点回执和复验方法 | [验证记录](validation) · [测试方法](Testing-zh) |
| 按四张原图查找已修正的说法及尚缺的验收 | [逐项核对](Capability-Review-zh) |
| 审阅架构、安全假设和工程记录 | [架构](Architecture-zh) · [威胁模型](Threat-Model-zh) · [审计索引](Audit-Records-zh) |

本次记录涵盖 172 项 PSBT 检查、Ryo/Zano 上游验证器对照和三幅固件渲染的审阅画面。较早记录列出了逐链验收所用的节点、交易及执行环境。[验证记录](validation)
