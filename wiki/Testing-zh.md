# 测试

[English](Testing) · [首页](Home-zh)

这一页背后只有一条规则：没有可失败测试的断言，不算断言。下面所有命令都能在本地跑，CI 跑的是同一套。

## 主 host 套件

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
```

用 MSVC 配合"指定版本 ESP32 core 的 mbedTLS 头文件"编译固件源码，然后跑 `host_test.exe`。
72 项具名检查各打一行，例如：

```text
crypto-primitives=pass      bip39=pass              bip32=pass
bip84=pass                  evm-derive=pass         address=pass
sighash=pass                kaspa=pass              zcash=pass
dash=pass                   cryptonote-clsag=pass   bulletproof-plus=pass
cryptonote-review=pass      cryptonote-signing=pass cryptonote-mainnet=pass
blake3=pass                 blake2b=pass            groestl512=pass
cli-policy=pass             battery=pass            kangarootwelve=pass
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
| `device_compile_check.ps1` | 每个纯 C++ 固件文件都能为 Xtensa（S3）编译；加 `-Target esp32p4` 则编 RISC-V；加 `-StackBudget 5120` 时，跑在 32 KB Arduino loop 任务上的帧一旦超过该栈的六分之一就失败；同时检查生产版 CLI 目标文件里不再引用任何自检代码（这个引用过去把 546 KB 测试缓冲区留在 `.bss` 里） |
| `p4_runtime_compile_check.ps1` | worker 与签名编排在 P4 上能编 |
| `board_port_compile_check.ps1` | `WalletBoardPort.cpp` + `WalletUi.cpp` 在所有板型上对真实 LVGL 9.5 头文件编译 |
| `epd_driver_compile_check.ps1` | GxEPD2 路径能对固定提交编译 |
| `se051_port_check.ps1`（及 `-Device`） | SE051 传输故障行为，然后用真实 P4/Arduino 头文件编译 |
| `ui_check.ps1` | LVGL 对象生命周期、审查渲染、精灵动画回归 |
| `qr_cross_check.ps1` | 所有版本/等级/掩码矩阵与 nayuki/QR-Code-generator 一致 |
| `evm_access_list_check.ps1` | 独立生成的 EIP-2930 向量 |
| `policy_check.ps1` | 已撤回资产 排除、撤链钉死、mining 解析、无网络栈、托管拒绝、无界拷贝基线 |
| host 套件里的 `admission=` | `WalletAdmission.cpp` 里被拒绝的身份，不会解析出网络配置或目录条目；开机自检同样会跑 |
| `policy_check_test.ps1` | 策略检查器本身在应该失败时会失败 |
| `tests/host/auth`（CMake） | TOTP、传输矩阵与本地批准 |
| `mining_catalog_test.py` | 钉死的 MiningPoolStats 身份映射 |
| `generate_mining_catalog.py --check` | 提交的表和报告与生成器一致 |
| `native_coverage.ps1` | 从编译产物重新生成能力矩阵 |

## 签名前的审查一致性回归

`build_chain_native.ps1` 会运行 `cosmos-sign-selftest` 与 `cryptonote-sign-selftest`，使用真实 Mbed TLS 后端。

Cosmos 保留原始请求，签名前重新生成审查字段和 protobuf。测试逐项篡改收款人、金额、费用、memo、链参数、长度与交易字节，要求拒签、返回长度为零且不写输出；合法夹具的完整 TxRaw 必须保持逐字节一致。解析测试还覆盖嵌入 NUL 的 chain-id/地址、截断载荷、无效 denom，以及失败后清除旧状态。

Monero/Zephyr 在签名前再次验证输入归属、输出派生、金额承诺、范围证明和费用，并核对缓存摘要与签名掩码。回归篡改金额、收款公钥、找零、费用、输入/输出计数和掩码，要求不输出签名且清零签名状态；合法交易仍需通过解析和 CLSAG 验证。

XRP/Kaspa 的 `chain_probe signing-audit all` 使用真实密码库，覆盖 22/29 项审阅篡改、数组越界和短输出缓冲区。XRP 从保留的原始载荷重新构建完整审阅；Kaspa 重算费用、地址与质量，并用 256 位摘要绑定所有已审阅字段和派生路径。失败时签名输出清零。

`kaspa_reference.py` 使用固定上游 schema 和 Google Protobuf 独立比较 4 组广播编码、72 个 sighash、交易 ID 与质量；另外独立验证真实固件生成的 Schnorr 签名。安装 `tests/host/reference-requirements.txt` 后运行；`build_chain_native.ps1` 和 CI 已接入。来源、校验和及边界见 [Kaspa 参考测试](../tests/fixtures/kaspa/README.md)。

这些测试验证指定代码路径。它们没有完成 Ryo/Zano 签名适配，也不能替代 MCU 实机时延、断电恢复、节点接收与独立安全审计。新增复核会增加设备计算时间，发布前必须测量 worker 栈高水位和最坏执行时间。

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

## Ryo / Zano 签名内核回归

`tests/host/privacy/privacy_interop.py` 校验固定向量、独立签名的验签、错误见证、非规范标量、低阶点、重复环成员、签名篡改及失败输出清零。`build_chain_native.ps1` 自动执行这组回归。夹具只包含公开测试密钥和环签名，不是链上交易。

`bulletproof_interop.py` 验证 Ryo 的旧版 64 位 Bulletproof。13 组向量包含上游固定有效/无效证明、零金额、`2^64−1`，以及 1/2/3/4/5/8/9/16 输出形状。独立生成的证明同时通过固定上游 `bulletproof_VERIFY` 和固件验证器；两个验证方也都拒绝各组成项的篡改。

传入 `--oracle` 时，脚本执行双向交叉验证：上游验证固件签名，固件验证独立生成的签名；额外重构测试密钥对应的真实 nonce，检查重复熵跨消息、跨环使用时没有 nonce 重用。上游库使用固定源码中的原始 `MLSAG_Ver` / `verify_CLSAG_GGX` 函数及上游 ref10、Keccak，不链接固件密码学代码。源码版本、校验和与复现命令见 [独立验证器说明](../tests/host/privacy/README.md)。

这组测试证明的是签名内核的协议兼容性，不覆盖完整交易广播、设备上的侧信道或故障注入。Ryo/Zano 的交易签名准入仍保持关闭。

`ryo_transaction_interop.py` 在其上验证 Ryo 原生 type-3 交易：4 组固定合成交易、214 次调用，对比前缀/base/prunable/交易/签名摘要，并验证范围证明、承诺平衡和逐输入 MLSAG。解析压力测试覆盖每个截断位置、40,000 次定向变异、4,000 组随机输入，失败时视图和摘要清零。此脚本已接入 native 构建；它不验证钱包归属、支付 ID、设备批准或节点接收。
