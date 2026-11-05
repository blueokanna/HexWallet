# 审计记录

[English](Audit-Records) · [首页](Home-zh)

工程记录带日期，而且**不会被改写**。它们是证据链：某一天查了什么、发现了什么、留下什么没做。
当前行为写在整理过的页面里；记录和整理页冲突时，以整理页和生成的矩阵为准，记录保持原样，这样变化才看得见。

## 整理过的文档

| 页面 | 内容 |
| --- | --- |
| [架构](Architecture-zh) | 执行模型、会话模型、签名流水线、模块分工 |
| [安全模型](Security-Model-zh) | 每条强制控制及其实现位置 |
| [威胁模型](Threat-Model-zh) | 对手、现状、攻击面清单 |
| [链支持](Supported-Chains-zh) | 每个家族做什么、拒绝什么 |
| [载荷格式](Chain-Payloads-zh) | 主机工具需要的线格式 |
| [准入策略](Admission-Policy-zh) | 一条链怎么挣到 `SIGN` 行 |
| [手机链路](Phone-Link-zh) | 协议版本 2 |
| [安全芯片](Secure-Element-zh) | SE051 现状与托管门 |
| [板卡与显示](Boards-and-Display-zh) | 引脚、面板、墨水屏规则、QR、摄像头 |
| [编译与刷机](Build-and-Flash-zh) | 工具链、分区、eFuse 警告 |
| [测试](Testing-zh) | 套件、参照实现、全绿不代表什么 |
| [登记表](Registries-zh) | 网络、token、矿池身份 |

## 生成矩阵

| 文件 | 生成器 | 含义 |
| --- | --- | --- |
| `native-chain-capabilities.md` | `tools/native_coverage.ps1` | 每个编译进来的配置一行及其能力 |
| `miningpoolstats-coverage.md` | `tools/generate_mining_catalog.py` | 每条列表及其解析结果 |

两者都在 CI 里校验；手改会让构建失败。

## 带日期的记录

| 记录 | 日期 | 内容 |
| --- | --- | --- |
| `record-security-review-2026-10-28.md` | 2026-10-28 | P4 + SE051 安全评审、算法修正、当天的准入决定 |
| `hardening-2026-10-30.md` | 2026-10-30 | 已修缺陷、可复现检查、未完成项、PRL 身份核实 |
| `hardening-2026-10-31.md` | 2026-10-31 | 第二轮加固 |
| `hardening-2026-10-31-tokens.md` | 2026-10-31 | token 登记自证、新增登记行、自定义资产 |
| `independent-wallet-audit-2026-11-02.md` | 2026-11-02 | 独立签名与网络审计；必须修复的发现 |
| `pearl-beam-audit-2026-11-03.md` | 2026-11-03 | Pearl 与 BEAM：准入什么、不准入什么 |
| `psbt-nft-validation-2026-11-02.md` | 2026-11-02 | PSBT 与自定义 NFT 的验证修复 |
| `taproot-audit-2026-11-03.md` | 2026-11-03 | BIP341/BIP86 key-path 审计、BIP371 行为 |
| `validation-network-registry-2026-11-02.md` | 2026-11-02 | 网络登记验证发现 |
| `validation.md` | 活日志 | 按日期排的验证条目 |
| `chain-gates.md` | 活台账 | 逐链能力证据与剩余缺口 |
| `chain-protocols.md` | 活笔记 | 适配器层实现细节 |
| `chain-support.md` | 旧矩阵 | 已被 Supported-Chains 取代 |
| `phone-link-protocol.md` | 线格式记录 | 协议细节，版本 2 |
| `se051-integration.md` | SE 记录 | APDU/SDK 逐条核对、托管缺口 |
| `display.md` | 面板记录 | 墨水屏档位、摄像头、QR 背景 |
| `authentication-status.md` | 状态记录 | 显示/TOTP/FIDO2 边界 |
| `totp.md`、`dash.md`、`evm-access-lists.md`、`network-registry.md` | 专题笔记 | 单个子系统的实现细节 |

## 怎么读记录

每条记录都写了自己的范围和限制。"没有在实物板上测过"这种句子是记录的一部分，不是可以跳过的免责声明。
需要知道今天的行为，就看整理页和生成的矩阵，然后回头对代码。

## 为什么留着

因为钱包真正有价值的部分不是"支持多少 ticker"，而是"拒绝过什么、为什么拒绝、后来改了什么"这条痕迹。
删掉它，项目会更好描述，也更难被信任。
