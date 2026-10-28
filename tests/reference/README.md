# 独立 Monero 参考构建

参考提交和每个下载文件的 SHA-256 见 `monero-reference.json`。`fetch_reference.ps1` 的下载是显式开发操作，普通构建只读取并核验缓存；任何摘要不一致都会失败。

`build_reference.ps1` 将上游 BP+ prover/verifier、multiexp、曲线/标量和 Keccak 实现编译为独立可执行程序。不链接钱包对象文件，也不调用钱包生成器。通过包装上游 multiexp 调用记录实际返回点，不修改其算术。

为避免引入整个节点依赖图，adapter 提供：

- rct::key/BulletproofPlus 的最小非序列化数据类型及常量。
- RingCT 哈希/曲线封装，调用上游 Keccak 与 crypto-ops。
- std::mutex 替代 Boost 锁，Windows 对齐分配、无日志计时宏。
- 公开可复现的 skGen 流：Keccak(固定标签 + 十进制计数器) 后模 l 规约。每个进程重新计数，严禁生产使用。
- crypto_verify_32 的测试比较实现；这里不作侧信道安全声明。

这些替代项公开保存在 adapter/，不能把该程序描述成未改动的完整 Monero 节点。上游许可保存在 MONERO-LICENSE.txt；参考文件保留其原有许可。这里使用参考协议，不改变 Monero 密码学协议。

生成顺序：`generate_bp_plus_fixtures.ps1`、`generate_negative_fixtures.ps1`、`generate_review_fixture.ps1`，再运行 `tools/generate_bp_plus_fixtures.py` 更新 C++ 数据。所有输出均为测试材料，包含公开的金额、掩码和测试秘密，不能用于真实资产。

旧 bp_plus_inputs.py 与 bp_plus_reference.ps1 仅检查三个曲线映射值，且曾下载 master；它们已由固定版本的完整证明基线替代并删除。
