# 2026-10-23 验证记录

本次检查针对当前工作区，不能替代完整固件链接、实机测试或新签交易的节点验收。设备代码未增加联网客户端；参考实现下载和广播属于电脑/手机侧工作。

## 已执行

| 检查 | 结果 | 范围 |
| --- | --- | --- |
| `tests/host/build.ps1` | 退出码 0 | 加密、交易、目录、NFC 协议自检及 worker 生命周期回归 |
| `python -m unittest discover -s tests -p "test_*.py"` | 33 项通过 | 生成物、独立 Monero 证据、篡改拒绝、链路与覆盖报告 |
| `tests/host/build_clang_ubsan.ps1` | 退出码 0 | 启用 undefined-behavior sanitizer，出错即停止 |
| `tests/host/device_compile_check.ps1 -Target esp32p4` | 退出码 0 | P4 32 位目标的加密与交易模块编译 |
| `tests/host/p4_runtime_compile_check.ps1` | 退出码 0 | 使用真实 P4 Arduino/FreeRTOS 头文件编译 worker、签名调度和草图 |

主机使用 MSVC/Clang；目标 SDK 为 Arduino ESP32 3.3.10。CI 已加入 P4 运行流程编译检查，但本次没有提交或执行 GitHub Actions。

## 修复与拒绝边界

- worker 超时不会释放仍被任务借用的栈对象、密钥或交易缓冲区。结果过期后等待任务结束，再清除数据；超时签名不会返回给手机。等待期间服务 UI，不接收新的签名请求。
- XMR/MSR 签名也在 worker 执行。worker 不可用时拒绝请求，不在主循环的小栈上重试。
- 新的签名请求先使旧批准失效；拒绝时清除请求内容。无效参数会清除 CryptoNote 签名状态。
- 无法生成完整目的地址时不显示批准按钮；签名输出数量不能超过显示容量。
- 审阅检查完整 `extra`，拒绝重复交易公钥、附加公钥、未知字段、重复 nonce、截断字段和非法填充。
- 当前标准地址输出使用 `R = rG`。XMR/MSR 子地址目的地址和子地址找零尚未完成 `rD` / 附加交易公钥绑定与独立接收扫描测试，因此拒绝这些输出。子地址输入消费保留。

## 尚未完成

币种范围以 `coin-coverage.md` 为准。SIGN 只表示目录声明签名入口，并不表示全部交易类型可用。SOL、ADA、DOT、FIL、XCH、DCR、FIRO、FLUX 等仍缺已接入的交易适配器；不能用地址原语代替发送支持。

MSR RCT type 3 默认关闭。Monero 的独立 BP+ 基线和历史主网交易向量已进入回归，但新签交易仍需手机/电脑侧节点验收。SE050 安全会话、秘密解封策略、PN7161 实际连线、可信显示、看门狗、断电恢复与整机性能尚无这块硬件的完整验收证据。当前工程不能称为已完成生产验证的百链硬件钱包。
