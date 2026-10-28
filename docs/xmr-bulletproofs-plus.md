# Monero Bulletproofs+ 独立回归

参考版本固定为 Monero `v0.18.4.0`，提交 `f1311d4237404ab7da76241dbf10e92a65132cc4`。来源文件及 SHA-256 位于 `tests/reference/monero-reference.json`。参考程序只在开发电脑运行；固件不下载源码、不连接节点。

## 证据与边界

`tests/reference/monero_reference.cpp` 编译固定提交的 `bulletproofs_plus.cc`、`multiexp.cc`、`crypto-ops.c`、`crypto-ops-data.c` 和 `keccak.c`。它不包含、不链接 HexWallet 密码学实现。`adapter/` 提供最小数据类型、RingCT 调用封装、Windows 平台适配和公开的确定性测试随机流。这是隔离的参考算法构建，不是完整 Monero 节点构建；替换项见 `tests/reference/README.md`。

`tests/fixtures/monero-bp-plus/` 保存：

- 1、2、3、4、5、8、9、16 输出的证明，包含零金额、最大 uint64 金额及补齐边界。
- 对应的 V、链上承诺、公开测试金额和掩码、预期接受结果及文件校验和。
- transcript 初始值、V 哈希、各次更新、y/z/e、每轮挑战、sum_y 和实际 multiexp 返回值。
- 2048 个生成元编码。
- 27 个经参考程序拒绝的字段替换、承诺替换、非法点、越界标量、负零点编码和截断样本。
- `review.json`：由参考实现独立派生测试输出掩码并生成的支付/找零证明，用于完整 review 回归。

C++ 主机回归逐项比对证明及中间值；Python 回归核对校验和、所有生成元和无效样本。真实主网证明接受现在是主机测试的必过条件。钱包自测生成的签名不能替代独立证明证据。

## 已修正的兼容性问题

1. 从链上 outPk 重建 `V = outPk * INV_EIGHT` 后再构造 transcript。
2. 挑战展开按折叠树从高位到低位读取索引。
3. `sum_y` 使用 y¹ 至 yᴹᴺ，不包含常数项。
4. Ed25519 压缩点的符号位取规约后 x 的奇偶位，避免把单位元编码成负零。

标量乘法改为标准扩展 Edwards 坐标的固定 256 位循环，最终仅做一次仿射转换求逆。该优化接受同一批独立回归检查；主机耗时不能当作 ESP32-P4 实测性能或侧信道审计结论。

## 复现

首次在开发电脑运行 `tests/reference/fetch_reference.ps1 -Fetch` 下载固定提交文件，之后构建均核验 SHA-256。运行 `generate_bp_plus_fixtures.ps1`、`generate_negative_fixtures.ps1` 和 `generate_review_fixture.ps1` 重建证据；`tools/generate_bp_plus_fixtures.py` 只把既有证据转换成 `BulletproofPlusReferenceTest.inc`。

运行 `tests/host/build.ps1`，再运行 `python -m unittest discover -s tests -p "test_*.py"`。固定材料可离线消费。参考构建使用 MSVC；证据生成不进入正常固件构建。

## 仍不是完整生产钱包

这些结果证明所测 BP+ 样本与固定 Monero 参考算法兼容。它们不等于完成手机协议、可信屏幕授权、SE050C1 解封策略、节点验收、实机故障注入或安全审计。CryptoNote 对外签名仍受目录门禁保护。MSR 不能套用 XMR type-6 路径。
