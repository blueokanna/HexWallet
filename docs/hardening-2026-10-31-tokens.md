# 固件修复记录 · 2026-10-31（第二轮）

这是当日的历史记录。后续的 64 条自定义资产容量、跨网络身份校验和矿币清单核验见 [网络与代币登记](network-registry.md)。下文的 8 条、EVM-only 范围不代表当前实现。

本轮只做一件事：把"代币与链的登记"从纸面清单变成**可复核的数据**，并给用户一个受控的
自定义代币入口。所有结论都来自链上调用或发行方官方发布页；没有实机、没有广播。

## 1. 代币登记现在可以自证

新增 `tools/token_audit.ps1`：对 `WalletTokens.cpp` 里每条 EVM/BEP-20 行直接 `eth_call`
`symbol()` / `decimals()` / `name()`，并区分两类结果：

- **位数不符 = 失败**。位数决定金额显示，错了就是转错数目。
- **标签漂移 = 告警**。发行方会原地改名（Tether 把 Arbitrum 上的 USDT 合约升级成 USD-T0，
  合约地址和 6 位小数都没变），桥接资产在链上仍叫 `USDC` 而固件显示 `USDC.e`。这类差异
  记下来，不当作错误。

本轮实测：62 条可达行 **0 条位数错误**、2 条标签漂移（桥接 USDC.e）、8 条因公共 RPC 不可达
或限流未能验证（明确列出，不冒充通过）。审计脚本的退出码只看位数错误。

## 2. 新增/修正的登记行

| 变更 | 依据 |
| --- | --- |
| `linea-usdc`、`celo-usdc`、`cro-usdc` 新增（均 6 位） | Circle 官方 USDC 合约地址表 + 对应链 RPC 回验 |
| `bsc-sfp`、`eth-sfp` 新增（18 位） | SafePal 公布的合约地址 + BSC/Ethereum RPC 回验（`symbol=SFP`、`name=SafePal Token`） |
| `eth-usdg`、`xlayer-usdg`、`arb-usdg`、`mantle-usdg` 新增（均 6 位） | Global Dollar 的部署地址 + 各链 RPC 回验（`name=Global Dollar`） |
| `arb-usdt` 改为 `USDT0` / `USD-T0 (migrated USDT)` | 链上该地址现在的 `symbol` 是 `USD-T0`：Tether 原地升级了合约，地址和位数不变。旧标签会让屏上显示一个链上已不存在的名字 |
| `celo-usdt`、`opt-usdt0`、`unichain-usdt0`、`xlayer-usdt0` 保留原显示名 | 链上 symbol 用的是 `₮` 连字（U+20AE）；审计按折叠规则比较，显示名保持 ASCII |

未登记的 MISSING 行在 `docs/chain-support.md` 里逐条写明原因，分三类：**没有代币转移路径**
（Solana SPL 注册表、TON jetton、Aptos FA、Sui coin、Stellar issued asset）、**没有网络
profile**（OKT Chain、Robinhood Chain、Tempo）、**权威地址未取证**（Polygon 的桥接 USDT、
X Layer 上的封装 BTC/ETH）。不把"地址贴上去"当成支持。

## 3. 自定义代币（新模块）

`WalletCustomTokens.{h,cpp}` + `WalletCustomTokensNvs.cpp`：

- 表很小（8 条），每条绑定 **一个 EVM 网络 + 一个 20 字节合约地址**，带用户声明的
  symbol / name / decimals。非 EVM 网络直接拒绝（没有 ERC-20 编码路径）。
- 持久化是一个整块 blob（magic + version + count + records + SHA-256 前 8 字节）。
  写入失败就回滚内存，绝不出现"屏上显示已添加、重启后消失"。
- 整块坏了就当作空表，不做半截解析——半个代币表比没有代币表更危险。
- EVM 解析器只在**内置注册表未命中后**才查它，因此自定义条目永远不能遮蔽已验证的合约。
  命中后审阅页会多出一段 `UNVERIFIED CUSTOM TOKEN` + symbol/decimals + 一句
  "这个合约是在设备上录入的，设备无法确认它就是它自称的代币"。

边界说明（不粉饰）：登记入口目前只有设备 API（`custom_token_add` / `custom_token_remove`），
手机协议与 CLI 命令还没接；也就是说现在能"读到并用"，还不能"从手机加"。下一步是给
`WalletLinkService` 加一条受认证的配置命令，再做手机端选择网络的界面。

## 4. 可重复验证

| 命令 | 本轮结果 |
| --- | --- |
| `tests/host/build.ps1` | 退出码 0；`tokens=pass`、新增 `custom-tokens=pass`、`chain=pass` |
| `tests/host/evm_access_list_check.ps1` | 502 项通过（EVM 审阅路径未被自定义代币改动破坏） |
| `tests/host/build_chain_native.ps1` | `chain_probe` + `production_policy` 通过 |
| `tests/host/device_compile_check.ps1 -Target esp32p4` | 全部源 + `WalletCustomTokens.cpp` + 以真实 Arduino 头文件编译的 `WalletCustomTokensNvs.cpp` 通过 |
| `tests/host/policy_check.ps1` | 143 个 graveyard 身份、五张注册表、无界字符串基线通过 |
| `tools/token_audit.ps1` | 62 条已验证、0 位数错误、2 标签漂移、8 不可达 |
