> Registry notes. Current documentation: [Registries](Registries) / [Registries-zh](Registries-zh).

# 网络与代币登记

本轮合并尚未验收：`WalletMiningCatalog.cpp` 在验证期间被并发写入者反复还原。查询修复候选保存在工作区的 `build/network-registry-backup/WalletMiningCatalog.pending.cpp`，替换该编译单元后的目录与 token 自检通过；主工作区的全量测试仍失败，不能用于发布。以下记录登记设计与已经完成的存储修改。

钱包的支持范围由地址格式、签名域、交易解析、设备审阅和签名实现共同决定。挖矿算法、币种简称、EVM 地址外观都不能证明两个网络可以共用签名器。

## 矿币目录

当前来源是 MiningPoolStats 公开清单的 2026-11-02 核对快照。完整逐项结果在 [miningpoolstats-coverage.md](miningpoolstats-coverage.md)。算法变体是独立网站条目，不能重复计算成区块链数量；`SIGN` 只表示编译后的注册表声明了签名路径，具体范围以同一行的说明为准。

登记流程由三份数据组成：

- `tools/miningpoolstats_coin_list.json`：网站数据，不执行网站脚本。
- `tools/miningpoolstats_snapshot.json`：来源、核对日期和规范化 JSON 的 SHA-256。规范化使用 ASCII JSON、键排序及无空白分隔符，避免 Git 换行转换影响检查。
- `tools/miningpoolstats_mapping.json`：网站 source ID 到钱包 network ID 的显式绑定，同时固定币名和简称。生成器不按简称猜测网络，也不自动把新增项目变成可签名项目。

`tools/generate_mining_catalog.py` 读取新编译的 `catalog_dump.exe --native`。来源身份变化、GRAVEYARD 回流、目标缺失和原生资产不一致都会失败。`--check` 还会检查固件表和覆盖文档是否与输入一致。CI 离线验证固定快照；网站随后发生的变化需要重新抓取、复核和测试。

2026-11-02 修正了三种错误绑定：BIT / BitNet 到 BTN / Bitnet Money、ETI 到 EGAZ、Conflux Core Space 到 eSpace。Conflux 官方明确说明两个空间需要跨空间调用，不能直接互转：[CrossSpaceCall](https://doc.confluxnetwork.org/docs/espace/build/cross-space-bridge/)。这些条目不再借用另一个网络的能力。

Callisto、Dogecoinev、Actinium、AIPowerGrid、CPUchain 已进入本次 GRAVEYARD 快照，相应生产 profile 和签名策略已撤下，包括 Actinium 的 SegWit 地址变体。保留底层通用算法不代表恢复这些网络。

CLI 的 `mining show <source-id-or-symbol>` 优先匹配精确、区分大小写的 source ID；简称和名称可以忽略大小写，但指向多个网络时必须拒绝。歧义表涵盖所有活跃项目，包括尚无适配器的项目。`BIT` 不会误选 source ID 为 `bit`、简称为 `B1T` 的另一个项目；`BTG` 也不会忽略 BitGem 而直接选择 Bitcoin Gold。`mining stats` 分别报告网站条目数和去重的钱包 profile 数。

## Token

内置 token 使用网络 ID 与链上标识共同定位；同一合约地址出现在不同网络时属于不同资产。同一网络重复登记同一 EVM 合约，即使地址大小写不同，也会触发自检失败。签名能力还要检查网络是否存在、标准与网络编码是否匹配、合约格式以及该网络是否具备审阅和签名路径。

自定义表支持 **64 个资产**，独立于内置部署表。现有数据模型涵盖 EVM ERC-20、TRON TRC-20、Solana SPL、Stellar classic asset 和 Starknet ERC-20。它们仍是用户声明的元数据，不能变成发行方认证、任意 ABI 授权或额外的协议能力。

持久化仍兼容版本 1 和版本 2；未改变记录布局。完整版本 2 表上限为 8,526 字节，NVS 临时缓冲区使用可失败的堆分配，不占用同等大小的任务栈。内存不足、NVS 写入或提交失败都会返回失败，现有增删接口恢复原内存状态。实机还需要验证 NVS 空间、掉电行为和堆余量。

加载时重新验证网络、标准、标识长度、TRON 前缀、显示文字和资产唯一性。Stellar classic asset 固定七位小数，资产代码为 1–12 位字母或数字，依据 [Stellar 资产定义](https://developers.stellar.org/docs/learn/fundamentals/stellar-data-structures/assets)。任何无效记录会使整表加载失败。尾部摘要用于发现损坏，不能抵抗能重写存储并重新计算摘要的攻击者。

验证入口：

```text
tests/host/catalog_dump.exe --selftest
python tests/host/mining_catalog_test.py
python tools/generate_mining_catalog.py --check
powershell -ExecutionPolicy Bypass -File tests/host/policy_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/p4_runtime_compile_check.ps1
```

主机测试和目标编译不等于全网节点验收、完整固件链接或实机安全认证。未映射项目需要自己的协议实现与独立交易向量，不能通过补名称或改能力位完成。
