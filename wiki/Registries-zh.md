# Registries

[English](Registries) · [首页](Home-zh)

四张编译期表决定设备"知道"什么。四张都在仓库里生成或人工核对，运行时不去取任何东西。

| 登记表 | 规模 | 来源 | 生成 / 检查 |
| --- | --- | --- | --- |
| 网络配置 | 243 | `WalletNetworks.cpp` + `src/generated/WalletForkProfiles.inc` | `tools/fork_registry.json`，由 `policy_check.ps1` 校验 |
| 钱包目录 | 211 条 | `WalletCatalog.cpp` + 生成的分叉目录 | `tests/host/catalog_dump.exe` |
| Token 记录 | 18 条网络共 78 条 | `WalletTokens.cpp` | `tools/token_audit.ps1`、`tests/host/evm_access_list_check.ps1` |
| 矿池身份 | 520 条列表中的 115 条 | `src/generated/WalletMiningCatalog.inc` | `tools/generate_mining_catalog.py --check` |

## 网络与目录

网络配置 = 一种地址编码 + 一套签名策略。目录条目 = 用户看到的东西：id、ticker、名称、coin type、
能力位和一行状态说明。多个条目可以共用同一个配置家族（`btc`、`btc49`、`btc44`、`btc86`）。

目录不会宣称策略不授予的能力：`resolved_entry()` 只有在 `find_network_signing_policy()` 返回策略时，
才会把 review/sign 位加上。

加一条网络 = 加配置、需要签名就加策略、加目录行，再加测试。流程见 [准入策略](Admission-Policy-zh)。

## Token

- **固定记录**（`WalletTokens.cpp`）：合约地址、精度、符号、名称；18 条网络共 78 条。合约逐字节匹配
  才会解码该调用。
- **用户自加记录**：最多 64 个资产（`kCustomTokenMax`），以 `HXCT` 版本 2 + 摘要存进 NVS。
  审查界面会标注"自加"，而且它们永远不改变被签名的字节。EVM、Stellar、NFT 都可以声明；
  但 NFT 声明不会打开 NFT 转账，因为根本没有 NFT 合约登记表。
- **不接受主机提供的精度。** 未知 token 显示精确 base unit，例如 `1500000 raw`，不猜小数点。

## 矿池身份

`tools/miningpoolstats_snapshot.json` 钉死来源和 SHA-256；`miningpoolstats_mapping.json` 是人工核对过的
"来源 id → 钱包配置"映射。生成器遇到快照哈希变化会拒绝，遇到 GRAVEYARD 不一致也会拒绝，然后同时写出
C++ 表和公开覆盖报告。

当前数字：520 条活跃列表，115 条已映射，94 个不同钱包配置，其中 91 个有签名路径。其余是有意不映射的：
矿池网站列出来，不等于钱包支持。

## 改哪里

| 任务 | 改什么 | 然后跑什么 |
| --- | --- | --- |
| 加一个 UTXO 分叉 | `tools/fork_registry.json` | 重新生成配置、`policy_check.ps1` |
| 加一条 EVM 网络 | `WalletNetworks.cpp` | `catalog_dump.exe`、`policy_check.ps1` |
| 固定一个 token | `WalletTokens.cpp` | `tests/host/build.ps1`、`token_audit.ps1` |
| 更新矿池数据 | 替换快照和映射 | `generate_mining_catalog.py`、`mining_catalog_test.py` |
| 加一条原生链 | 新适配器 + 配置 + 策略 | 向量、目录行、准入测试 |

不要手改生成文件。CI 会用 `--check` 跑每个生成器，文件过期就构建失败。
