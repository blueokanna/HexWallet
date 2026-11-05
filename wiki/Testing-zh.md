# 测试

[English](Testing) · [首页](Home-zh)

这一页背后只有一条规则：没有可失败测试的断言，不算断言。下面所有命令都能在本地跑，CI 跑的是同一套。

## 主 host 套件

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
```

用 MSVC 配合"指定版本 ESP32 core 的 mbedTLS 头文件"编译固件源码，然后跑 `host_test.exe`。
67 项具名检查各打一行，例如：

```text
crypto-primitives=pass      bip39=pass              bip32=pass
bip84=pass                  evm-derive=pass         address=pass
sighash=pass                kaspa=pass              zcash=pass
dash=pass                   cryptonote-clsag=pass   bulletproof-plus=pass
cryptonote-review=pass      cryptonote-signing=pass cryptonote-mainnet=pass
qrl-xmss=pass               qrl-ots=pass            ml-dsa-87=pass
starknet-crypto=pass        solana=pass             xrp=pass
cosmos=pass                 stellar=pass            algorand=pass
near=pass                   tezos=pass              totp=pass
link-crypto=pass            wallet-link=pass        nfc-apdu=pass
se051-apdu=pass             scp03=pass              trust-anchor=pass
random-source=pass          catalog=pass            mining-catalog=pass
```

套件还会编出 `link_pipe.exe`（手机链路夹具）、`nfc_port_test.exe`、`worker_execution_test.exe`、
`catalog_dump.exe` 和逐链探针。失败会以非零退出并点名是哪一项。

| 套件 | 证明什么 |
| --- | --- |
| `build_clang_ubsan.ps1` | 同一份源码在 clang + UBSan 下能编；跑到的路径里出现未定义行为会被报出来 |
| `build_chain_native.ps1` | 链代码链接的是真正的 mbedTLS 3.6.5，不是 host shim |
| `device_compile_check.ps1` | 每个纯 C++ 固件文件都能为 Xtensa（S3）编译；加 `-Target esp32p4` 则编 RISC-V |
| `p4_runtime_compile_check.ps1` | worker 与签名编排在 P4 上能编 |
| `board_port_compile_check.ps1` | `WalletBoardPort.cpp` + `WalletUi.cpp` 在所有板型上对真实 LVGL 9.5 头文件编译 |
| `epd_driver_compile_check.ps1` | GxEPD2 路径能对固定提交编译 |
| `se051_port_check.ps1`（及 `-Device`） | SE051 传输故障行为，然后用真实 P4/Arduino 头文件编译 |
| `ui_check.ps1` | LVGL 对象生命周期、审查渲染、精灵动画回归 |
| `qr_cross_check.ps1` | 所有版本/等级/掩码矩阵与 nayuki/QR-Code-generator 一致 |
| `evm_access_list_check.ps1` | 独立生成的 EIP-2930 向量 |
| `policy_check.ps1` | GRAVEYARD 排除、撤链钉死、mining 解析、无网络栈、托管拒绝、无界拷贝基线 |
| `policy_check_test.ps1` | 策略检查器本身在应该失败时会失败 |
| `tests/host/auth`（CMake） | TOTP、传输矩阵与本地批准 |
| `mining_catalog_test.py` | 钉死的 MiningPoolStats 身份映射 |
| `generate_mining_catalog.py --check` | 提交的表和报告与生成器一致 |
| `native_coverage.ps1` | 从编译产物重新生成能力矩阵 |

## 独立审计夹具

这些夹具把固件和不属于固件的东西对比：

| 夹具 | 参照实现 |
| --- | --- |
| `tests/host/psbt_audit/run.ps1` | BIP32/Schnorr、BIP371 v0/v2 解析、找零归属、最终 witness 验证 |
| `tests/host/taproot_audit/run.ps1` | 公开的 BIP341 wallet 向量，外加本地推导的 annex 长度用例；运行器记录源码哈希，测试期间源码变了就判失败 |
| `tests/host/pearl_audit/run.ps1` | 固定提交的 pearl-research-labs/pearl，用 Go 跑；六个公开夹具、两种 PSBT、含负向用例 |
| `tests/host/qrl_oracle_check.ps1` | qrllib 的 `xmss_Signmsg` 逐字节对比 |
| `tests/host/qr_cross_check.cpp` | nayuki QR 参考实现 |

## 全绿说明什么

它说明代码与本仓库的向量、参照实现一致。它**不**说明：

- 节点会接受这笔交易；这棵树里没有任何测试会广播；
- 设备能挡住物理攻击者；
- 真实 SE051 会接受这些 APDU；
- 你的板子上屏幕、触摸、NFC 前端、摄像头真的能用；
- 这些字节序列没有侧信道泄漏。

正因为这些缺口，[首页](Home-zh) 把项目定性为"未完成硬件验收"。

## 怎么加测试

1. 把向量放进 `src/generated/` 或 `tests/fixtures/`，写清来源和哈希。
2. 写一个 `run_*_self_tests()`，第一处不一致就返回 false；在 host 夹具里加一行具名输出。
3. 如果代码能从主机输入触达，补一条畸形输入的拒绝测试，而不是只测好路径。
4. 提交 PR 前跑 `build.ps1` 和 `policy_check.ps1`。
