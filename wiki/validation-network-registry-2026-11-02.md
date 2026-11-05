> Dated validation record (2026-11-02). Kept as the evidence trail.

# 网络登记验证记录 · 2026-11-02

## 已验证

- `tests/host/mining_catalog_test.py`：8 项通过，覆盖同名资产、来源身份变化、GRAVEYARD 回流、重复 JSON 键、重复 catalog ID、不一致能力位，以及快照摘要的换行稳定性。
- `tools/generate_mining_catalog.py --check`：通过。520 条活跃网站条目，115 条显式映射，405 条未映射；映射到 94 个 wallet profile，其中 91 个声明签名代码路径。这些数字不等于完整区块链支持数量。
- `tests/host/policy_check.ps1 -RegistryOnly`：通过，167 个去重的 GRAVEYARD 身份、五个注册表及无界字符串基线；未以此代替生产 custody 验证。
- 主机当前 token 测试：`tokens=pass`、`custom-tokens=pass`。编译注册表为 78 条内置 token 部署，自定义表容量 64。满容量、版本 1 迁移、写入失败回滚、重新计算摘要后的网络错配与重复资产拒绝均通过。
- ESP32-P4 真实 Arduino 头文件编译：`WalletTokens.cpp`、`WalletCustomTokens.cpp`、`WalletCustomTokensNvs.cpp`、CLI、相关运行时以及三个显示 profile 编译通过。不是完整固件链接或实机测试。
- 保存的矿币查询候选 `build/network-registry-backup/WalletMiningCatalog.pending.cpp` 单独编译，并替换主机目录测试中的相应目标文件后，`catalog=pass mining=pass tokens=pass custom-tokens=pass`。

## 未通过与冲突

全量主机运行仍返回失败：`sighash=FAIL`、`mining-catalog=FAIL`。测试前后输入摘要确认 `WalletMiningCatalog.cpp` 在构建期间发生变化，之后又观察到 source ID 查询与歧义检查被还原。未用候选版本的通过结果替代主工作区的失败结果。

本轮 CMake native-chain 构建在沙箱中的 MSBuild 阶段没有继续输出，已中断；没有记为通过。P4 编译器因沙箱 DLL relocation 无法启动，改在批准的沙箱外执行后编译通过。

诊断文件保存在 `build/mining-host-build-final.log`、`build/mining-input-changes.txt`、`build/mining-p4-compile.log`。候选源和验证后的目录可执行文件位于 `build/network-registry-backup/`。这些是当前工作区产物，不是发布固件。

需要先停止对同一 checkout 的并发修改，再合并查询候选、定位 sighash 失败并重跑全量测试。没有硬件或节点验收结论。
