# 固件修复记录 · 2026-10-30

本轮围绕交易审阅和签名边界修复实际问题。以下“通过”指仓库中的主机测试或交叉编译；没有连接实体钱包，也没有广播交易。未满足托管条件的生产构建仍拒绝装载种子和签名。

## 已修复

| 范围 | 变化 |
| --- | --- |
| Dash | `DAS2` 提交完整前序交易，设备核对 txid、索引、金额、脚本及密钥所属；所有输出均显示。接入手机协议 type 15 和 crypto worker。拒绝旧无证明格式进入批准、非 ALL sighash、特殊交易创建；签名失败清除输出。 |
| EVM | Ethereum 主网新增 EIP-2930 type-1，复用现有 RLP/access-list/费用/签名实现。统一 CLI 与手机审阅字段，显示完整合约、chain ID、nonce、gas、发送方和 access list。签名前比较解析字段及定长字符串，拒绝未终止字符串。 |
| Bitcoin 系列 | 重建前序 SegWit txid 时保留输入数量字段；允许单输入前序交易，拒绝无实际见证的 witness envelope。legacy P2PKH 必须有完整 `non_witness_utxo`，拒绝主机仅用 `witness_utxo` 伪报输入金额；解析和签名前均拒绝重复 outpoint。修正最大 DER 签名加 sighash 字节的缓冲区及手续费尺寸估算。 |
| Peercoin | 新增 v1/v2 含 nTime、v3 不含 nTime 的 P2PKH / witness-v0 `SIGHASH_ALL`；共用有界序列化器。12 组独立 PowerShell/.NET 固定摘要及时间戳变异检查。仅完成摘要层，未开放 PPC 设备发送。 |
| 网络选择 | 精确 network ID 优先于 ticker；共享 ticker 有歧义时拒绝。修复 `eth` 被排在前面的 zkSync `ETH` 条目截获的问题。目录原生币符号统一使用 network profile，校正 ETH、POL、AVAX、BNB 的显示。 |
| 审阅凭据 | 从实际 LVGL labels 收集完整文字，覆盖 ownership、details、fee label、note 和确认码。改用增量 SHA-256，最多 80 条、单条 4096 字节、总文字 32768 字节；超限、截断、熵失败或构建失败均撤销授权。 |
| 启动信任 | ESP32-P4 使用公开 eFuse API 读取 `SECURE_BOOT_EN`。读取失败或其他目标仅有编译配置时，不评级为 `Verified`；没有执行 eFuse 写入或烧录。 |
| 宠物与 LVGL | 修复动画 pending 标记卡死和切页后悬空指针，复用 1bpp canvas；增加代码生成的状态效果。审阅页禁止宠物动画；无已验证局刷能力时保持静态。 |

## 可重复验证

| 命令 | 本轮结果 / 验证边界 |
| --- | --- |
| `tests/host/build.ps1` | 主机自检通过；包括 Peercoin 摘要、Bitcoin、审阅 seal、宠物和现有链回归。 |
| `chain_probe dash-sign-selftest` | 真实 BIP32/Mbed TLS 签名与固定字节比较通过。 |
| `chain_probe evm-sign-selftest` | 真实 EVM 签名自检通过。 |
| `tests/host/evm_access_list_check.ps1` | 502 项检查通过，oracle 为 ethers 6.15.0 固定向量；包含正向、截断、篡改与输出边界。 |
| `tests/host/ui_check.ps1` | 真实 LVGL 9.5 对象上的动画、删除生命周期、完整审阅文字与授权失效回归通过。 |
| `tests/host/device_compile_check.ps1 -Target esp32p4` | P4 源文件交叉编译通过；不是完整固件链接或实机测试。 |
| `tests/host/p4_runtime_compile_check.ps1` | signing、link service、CLI、worker 与草图编译通过。 |
| `tests/host/policy_check.ps1` / `policy_check_test.ps1` | 策略检查与拒绝路径回归通过。 |

主机对象目录按进程隔离，避免并行构建覆盖链接中的 `.obj`。固定向量在正常构建中直接运行；Node/ethers 仅用于重生成 EVM oracle，不进入固件。

## 仍未完成

- Dash 特殊交易、CoinJoin 协作和 Platform 交易；Zcash shielded / v5；EVM 任意未知 calldata 与合约创建。
- Aptos、BEAM、THETA 和 PRL 原生签名。AVAX 的 C-Chain 路径不等于 X/P-Chain，Cronos EVM 路径不等于全部 CRO 网络。
- Chia 的常数时间 BLS 后端、DOT/KSM 的可信 runtime metadata、QRL 的生产签名及跨恢复防 OTS 复用验收。
- 安全托管、量产 secure boot/eFuse、面板波形、按键/NFC、断电恢复、侧信道及真实节点验收。

原生网络清单由 [native-chain-capabilities.md](native-chain-capabilities.md) 从编译后目录生成，不读取 token 合约表。目录中的 `SIGN` 仅表示已登记的代码入口；不能当作该链所有交易类型或当前主网验收结论。

## PRL 身份核实

用户给出的项目是 [Pearl Research 的 Pearl Protocol](https://pearlresearch.ai/network)，原生资产符号为 PRL。官方仓库为 [pearl-research-labs/pearl](https://github.com/pearl-research-labs/pearl)。其 [mainnet 参数](https://github.com/pearl-research-labs/pearl/blob/master/node/chaincfg/params.go) 指定 `prl` HRP，并描述 Taproot-only 钱包；官方仓库还包含 XMSS 实现。因此不能把它登记为同名 ERC-20，或只改 Bitcoin 的地址前缀就宣称完成。

接入需要以官方 wallet/node 为 oracle，验证密钥派生、Taproot tweak、sighash、完整签名交易以及 XMSS 状态管理。当前没有这些适配器，不将 PRL 放入可签名目录。

Peercoin 时间戳规则来自官方 [transaction.h](https://github.com/peercoin/peercoin/blob/master/src/primitives/transaction.h) 与 [interpreter.cpp](https://github.com/peercoin/peercoin/blob/master/src/script/interpreter.cpp)。EVM 依据与向量再生成步骤见 [evm-access-lists.md](evm-access-lists.md)，Dash 字段和前序证明格式见 [dash.md](dash.md)。
