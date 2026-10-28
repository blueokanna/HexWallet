# SUI/FIL 验证记录 — 2026-10-26

按用户后续要求，本会话集中 SUI/FIL；其他会话正在继续修改同一工作区的其他链。
本记录不对并发产生的其他适配器作完整性结论。

## 已完成

- SUI Ed25519 地址派生、原生 BCS 两命令转账解析与 97 字节签名输出。
- FIL f1 地址编码修复：未压缩公钥、`f1` 前缀与 BLAKE2b 校验和。
- FIL canonical CBOR Send、发送人归属校验、CID 签名域与 SignedMessage CBOR 输出。
- 签名入口容量传递、失败清除输出、批准后重解析/对比；屏幕审阅增加发送人和地址索引。
- SUI/FIL 接入既有 `kind=14` 设备签名入口、网络/目录、密钥类型与构建清单。
- 增加真实 `WalletSecurity.cpp` + Mbed TLS 3.6.5 主机探针，CI 构建步骤及独立 SDK fixture。

## 实际运行结果

| 检查 | 结果 | 范围 |
| --- | --- | --- |
| 原主机回归 `tests/host/build.ps1` | 通过 | 执行时的整个工作区；不能覆盖随后其他会话的修改 |
| 真实密钥/签名探针构建 | 通过 | MSVC + 固件 WalletSecurity.cpp + Mbed TLS；平台 RNG 使用 BCrypt |
| `test_sui_filecoin.py` | 6 个测试组通过 | 12 个 SDK 正向向量、75 个拒绝向量；另含完整截断、尾随字节、非规范格式、异账户、批准内容替换与缓冲区边界 |
| SUI/FIL SDK fixture 重生成 `--sui-filecoin --check` | 通过 | 专用 fixture 与 SDK 重新生成的结果一致 |
| 嵌入的 SDK 自测向量 `generate_chain_selftest.py --check` | 通过 | 生成文件未发生漂移 |
| 相关已跟踪文件 `git diff --check` | 通过 | 无补丁空白错误 |
| ESP32-P4 目标编译 | 未执行 | 自动审批服务额度耗尽，无法完成该命令的自动审核；不是编译失败，也不是判定命令不安全 |
| 真机地址/屏幕/NFC/批准/锁定/断电 | 未执行 | 尚无本会话的设备操作证据 |
| 节点接收/广播/执行 | 未执行 | SDK 离线一致性不等于节点验收 |

因此，这次完成了限定交易类型的固件实现和主机独立验证，不能称为
“所有硬件钱包全部功能完成”或“所有主网交易均已可用”。

接口、支持子集、手机广播适配及构建命令见 [sui-filecoin-signing.md](sui-filecoin-signing.md)。
审批可用后，仍需执行：

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1 -Target esp32p4
```
