# 2026-11-15 签名边界审计

本轮修复了已复现的 XRP/Kaspa 内存边界、审阅绑定和 Kaspa 广播编码错误。**全仓库审计和全链生产验收尚未完成。** 下列结果针对明确的代码路径，不是“零漏洞”证明，也不把地址能力或环签名原语算作完整硬件钱包支持。

## 已修复

| 位置 | 复现结果 | 修复 |
| --- | --- | --- |
| `XrpTransaction.cpp` | 签名前使用未校验的 `unsigned_size` 复制到固定栈数组；异常长度被 ASan 捕获。修改缓存金额、费用或收款人不会阻止签名。 | 保留原始 50 字节请求；先检查长度，再使用实际签名公钥重新构建全部审阅和交易字节。核对显示文本、签名插入点、摘要和字段；拒绝存在数值却没有 presence 标志的 destination tag。 |
| `KaspaTransaction.cpp` | `input_count=255` 使公开 sighash API 越过 8 项数组，UBSan 报错。修改审阅费用仍会签名；原 FNV 指纹既不完整，也没有在签名前核对。 | 所有公开交易原语先检查数组、脚本和 payload 边界。签名前重算审阅，以域分离 BLAKE2b-256 绑定完整请求、派生路径、显示地址、金额、费用和质量；32 位指纹仅用于显示。 |
| Kaspa 广播编码 | 签名脚本缺少压栈字节，输入没有 sigop 字段，本地子网被编码为空消息，storage mass 未写入。旧固定向量同时包含这些错误。 | 按固定上游 schema 写出 66 字节签名脚本、v0 `compute_commit`、20 字节 native subnetwork 和 storage mass。固定向量改由独立 Protobuf 编码器生成。 |
| Kaspa 摘要与质量 | 非空 payload 的交易 ID 重复写入长度；质量估算漏算 payload hash，重复计算前序锁定脚本，并少计签名脚本一字节。 | 按上游 v0 规则重算；4 组独立交易验证 ID、质量和全部六种 sighash。 |
| Kaspa 派生及失败路径 | 接受 hardened address index；派生循环的临时私钥节点未擦除；部分失败可能留下输出。 | 拒绝非标准分支/地址索引与不匹配的 sigop；擦除临时私钥节点。XRP/Kaspa 的失败签名与 Kaspa 失败编码统一清零输出及返回长度。 |

内存问题通过构造异常内部请求结构复现；现有紧凑载荷解析器通常会限制这些长度。本轮没有证明它们可由外部请求直接触发，不能将 API 缺陷夸大为已经验证的远程利用。

Kaspa 签名暂不接受非空 payload，因为审批界面没有审阅其内容。这是当前钱包的策略边界，不是声称 Kaspa 共识禁止 native payload。返回的广播字节是 P2P `TransactionMessage`，不是 gRPC `RpcTransaction`，接入方必须正确转换。

## 验证

- 真实 Mbed TLS 构建：XRP 22 项、Kaspa 29 项审阅篡改全部拒绝；合法签名继续成功。覆盖异常计数、脚本长度、payload 长度和输出容量；失败输出清零，缓冲区末端哨兵不变。
- 独立 Kaspa 参考：4 组交易编码、72 个 sighash、交易 ID 和质量一致；独立 secp256k1 验证器接受真实固件签名，拒绝修改摘要后的签名。编码器逐一检查所有不足容量。参考版本与复现命令见 [Kaspa 夹具](https://github.com/blueokanna/HexWallet/blob/main/tests/fixtures/kaspa/README.md)。
- 上述回归通过 ASan/UBSan。初次失败日志与修复后日志分别保存在本地 `build/audit-logs`，没有覆盖初次复现证据。
- 主机套件、真实密码库链回归和策略检查通过；P4 32 位源码编译和 Arduino 头文件兼容检查通过。Kaspa 签名函数静态栈帧为 5104 字节，XRP 为 912 字节；静态单帧数字不代表运行时调用链峰值。
- P4 电子纸配置（board 7、PSRAM enabled、min_spiffs）完整编译、链接通过：程序 1,402,770 字节，静态 RAM 234,700 字节。未刷写设备；这不构成实机验收。尚未接入命令入口的 Ryo/Zano 后端不能据此宣称已在生产流程中启用。

新增回归已接入 `build_chain_native.ps1` 和 CI；测试依赖固定在 `tests/host/reference-requirements.txt`。

## Ryo 原生交易验证进展

`RyoTransaction.cpp/.h` 增加了借用只读缓冲区的 type-3 解析与验证层，无堆分配。支持 v2/v3 前缀、旧版 64 字节 ECDH、固定 u32 证明计数、一个原始 Bulletproof 和双行 MLSAG；边界是 8 输入、16 输出、241 成员环、128 KiB 交易字节。该字节上限是底层解析限制，现有设备传输协议并未因此扩容。

v3 前缀摘要使用上游要求的 `ryo-currency` 域标识。交易 ID 绑定前缀、RingCT base 和完整 prunable 段；签名摘要按协议单独计算证明字段哈希。验证层重建 `outPk / 8`，检查原始 Bulletproof、伪输出与输出/费用的承诺平衡，并以交易派生的摘要验证每个输入的 MLSAG。新借用签名视图避免在 MCU 栈上复制约 15 KiB 的签名结构。

4 组独立合成交易通过 214 次验证调用，以及全部截断位置、40,000 次定向变异和 4,000 组随机输入的解析压力测试；同套测试通过 ASan/UBSan。正常案例覆盖 v2/v3、25/241 成员环、8 输入和 16 输出。签名由独立 Python 生成并先经固定上游 MLSAG 验证器验证；固件再完成交易级摘要、范围证明、平衡与验签。向量不是主网交易，未声称经过节点接收。

P4 静态栈报告中，摘要计算辅助函数为 512 字节（优化前 2192），交易证明/平衡验证为 1152 字节，逐输入验签为 704 字节。Ryo/Zano 环签名上游交叉验证重新运行，11 组案例、337 次固件调用通过。

这层没有把 `tx_extra` 当作已审阅内容，也没有验证接收地址、原始 UTXO 归属、支付 ID 或物理批准。`verify_semantics` 的范围仅为头文件注明的密码学检查；分叉准入、区块链状态与钱包审阅仍需独立处理。

## 仍未达到的生产条件

Ryo MLSAG、Zano CLSAG_GGX 和 Ryo 旧版 Bulletproof 验证已有实现与独立上游交叉测试，但 **Ryo/Zano 完整交易签名尚未完成**。Ryo 已补原生交易解析与密码学验证，仍缺发送交易构建、输入/输出归属、金额与支付 ID 审阅及设备确认接入；Zano 还缺资产、范围和平衡证明、完整交易流程及质押适配。它们的生产交易签名准入仍关闭。

Monero 的交易类型限制、Zcash 屏蔽交易、Beam/Mimblewimble、Peercoin、TRON NFT/批量调用、Cosmos IBC/authz/amino、Dash 特殊交易、Lightning 和 Stacks 的具体缺口见[链能力边界](Supported-Chains-zh.md#尚未完成的原生能力)。这些需求没有因本轮修复变成已实现。

安全芯片托管仍是全局阻塞：`WalletSession.cpp` 的生产创建、导入与密钥加载路径返回 `CustodyUnavailable`。本轮没有绕开这项保护，也没有完成安全芯片实机、物理批准、断电恢复、节点接收或侧信道验收。部署前必须完成这些条件，不能以主机测试通过代替。
