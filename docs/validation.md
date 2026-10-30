# HexWallet - validation

## 2026-10-29：access list、安全托管边界与显示修正

- `evm_access_list_check.ps1`：201 项检查通过。六组有效交易与 ethers 6.15.0
  的完整签名和摘要一致，另含完整审阅文本、结构错误、截断、变造与输出清零检查。
  具体协议边界见 [EVM access list](evm-access-lists.md)。
- `build.ps1`：退出码 0，含密码核心、链解析、托管、宠物行为和 QR 自检。
  该套测试使用 host crypto shim；原生 Mbed TLS 的 chain-selftest 和 EVM 独立向量另行通过。
- P4 核心编译、真实 P4 Arduino 签名编排编译，以及六种板型的真实 LVGL 9.5
  头文件编译通过。编译成功不代表已经完成固件整包链接、真实显示或烧录测试。
- `policy_check.ps1`：143 个 graveyard 身份、五张注册表检查通过，名单日期仍为
  2026-10-23。递归扫描漏检和缺少生产策略二进制时错误放行的回归检查通过。
- NXP 固定版本的 Arduino Wire 端口已通过故障注入单测和 P4 编译；这不包括
  实际 SCP03 配钥、applet 会话或非导出钱包密钥托管。详见 [SE051 状态](se051-integration.md)。

单色 QR 和宠物缓冲都为调色板保留八字节，像素跟随实际 stride。宠物素材由
`pack_maid_sprite.ps1` 转为八张 64×64 位图，确认和拒绝交易均不影响亲密度。
新增加的 Node 脚本只用于复现独立 ethers 向量，正常测试与固件都不依赖 Node。

> **Tooling note (2026-10-28).** The Python/Node oracle harness (	ests/*.py, 	ests/reference/*, 	ools/*.py) was removed at the owner's request: this repository now needs exactly two toolchains, Arduino/xtensa for the device and MSVC or clang plus PowerShell for the host. Every vector those harnesses produced is still pinned in `src/generated/*.inc` and executed by `tests/host/host_test.exe`, so the checks still run on every build. The prose below records the original independent-SDK comparisons; bring the SDKs back if you need to regenerate a fixture.

## 2026-10-28 地址扩展与 BEP-20 验证

本轮只增加**可证明**的能力，没有把“看起来像地址”的字符串塞进目录。

| 检查 | 结果 | 说明 |
| --- | --- | --- |
| `tests/host/build.ps1` | 退出码 0 | 新增 `aeternity`、`ryo`、`zano` 地址向量与 20 个 BEP-20 profile 全部通过 |
| `tests/host/device_compile_check.ps1 -Target esp32p4` | 退出码 0 | 32 位 P4 编译，`NetworkProfile` 新增 64 位 CryptoNote profile 指针未破坏布局 |
| `tests/host/build_clang_ubsan.ps1` | 退出码 0 | 补上 CameraPort/TrustAnchor/Mascot 三个源文件后，UBSan 链接与全部自检通过 |
| `tests/host/build_chain_native.ps1` | 退出码 0 | 链接真实 BIP32/ECDSA，执行 `chain_probe zcash-sign-selftest`：ZEC t1 P2PKH 与 t3 P2SH-P2PK 的完整签名、scriptSig 结构与 DER 验签；并执行 `chain_probe dash-sign-selftest`：Dash 先用两笔真实主网交易的摘要锚定序列化与 legacy sighash，再用 RFC 6979 生成的向量逐字节比对设备产出的签名交易，并从 scriptSig 反解 DER 与公钥做曲线验签 |
| `tests/host/build_chain_native.ps1` | 退出码 0 | `chain_probe cosmos-sign-selftest`：逐条签名 Cosmos v1/v2 固定向量并与 `TxRaw` 逐字节比较，同时验证错误私钥被拒绝 |
| `tests/host/policy_check.ps1` | 退出码 0 | 新增“助记词/私钥不得进入任何输出路径”的静态门禁与 `HEXWALLET_ENABLE_SECRET_EXPORT` 编译期拒绝检查 |
| `tests/host/board_port_compile_check.ps1` | 退出码 0 | 真实 LVGL 9.5 下 `WalletUi.cpp` / `WalletBoardPort.cpp` 全板卡编译 |
| `tests/host/p4_runtime_compile_check.ps1` | 退出码 0 | `WalletCli` / `WalletSigning` / `WalletLinkService` / `.ino` 使用真实 P4 头文件编译 |
| BSC RPC `eth_call(symbol, decimals)` | 20/20 匹配 | WBNB、CAKE、FDUSD、TUSD、LINK、DOT、ADA、XRP、DOGE、SHIB、UNI、AAVE、ATOM、XVS、BSW、ANKR、COMP、BETH、AVAX、PENDLE；CAKE 链上 symbol 为 `Cake` |

证据边界：

- **Aeternity**：`ak_` 地址 = `base58(ed25519_pubkey || SHA-256d(pubkey)[0..3])`，来源是 `aeserialization/src/aeser_api_encoder.erl`；固定 Ed25519 公钥向量在 `run_alt_address_self_tests()`。
- **RyoCurrency**：CryptoNote long address 的 3 字节 varint 前缀 `0x2ce192` 已用官方 `cryptonote_config.h` 和 dev-fund 地址逐字节复核；`RYoL...` 向量在 `run_cryptonote_self_tests()`。
- **Zano**：直接复现 `hyle-team/zano/tests/unit_tests/base58.cpp` 的 `ZxDqHy6...` 向量；`0xc5` 前缀和双密钥 body 一致。
- 这三条链**没有**交易审阅/签名路径，目录能力只有 `ADDRESS`。不要把地址可用当成收付可用。
- Beam / Grin / MimbleWimbleCoin / Epic Cash 没有静态链上地址；SERO 是 superzk 公钥包；Swap / Evolution / VeriBlock 没有 SLIP-0044 coin type。原因与拒绝策略见 [chain-protocols.md](chain-protocols.md#aeternity-ryocurrency-和-zano--address-profiles-only)。

## 2026-10-23 验证记录

*Merged from docs/validation-2026-10-23.md.*

本次检查针对当前工作区，不能替代完整固件链接、实机测试或新签交易的节点验收。设备代码未增加联网客户端；参考实现下载和广播属于电脑/手机侧工作。

### 已执行

| 检查 | 结果 | 范围 |
| --- | --- | --- |
| `tests/host/build.ps1` | 退出码 0 | 加密、交易、目录、NFC 协议自检及 worker 生命周期回归 |
| `python -m unittest discover -s tests -p "test_*.py"` | 33 项通过 | 生成物、独立 Monero 证据、篡改拒绝、链路与覆盖报告 |
| `tests/host/build_clang_ubsan.ps1` | 退出码 0 | 启用 undefined-behavior sanitizer，出错即停止 |
| `tests/host/device_compile_check.ps1 -Target esp32p4` | 退出码 0 | P4 32 位目标的加密与交易模块编译 |
| `tests/host/p4_runtime_compile_check.ps1` | 退出码 0 | 使用真实 P4 Arduino/FreeRTOS 头文件编译 worker、签名调度和草图 |

主机使用 MSVC/Clang；目标 SDK 为 Arduino ESP32 3.3.10。CI 已加入 P4 运行流程编译检查，但本次没有提交或执行 GitHub Actions。

### 修复与拒绝边界

- worker 超时不会释放仍被任务借用的栈对象、密钥或交易缓冲区。结果过期后等待任务结束，再清除数据；超时签名不会返回给手机。等待期间服务 UI，不接收新的签名请求。
- XMR/MSR 签名也在 worker 执行。worker 不可用时拒绝请求，不在主循环的小栈上重试。
- 新的签名请求先使旧批准失效；拒绝时清除请求内容。无效参数会清除 CryptoNote 签名状态。
- 无法生成完整目的地址时不显示批准按钮；签名输出数量不能超过显示容量。
- 审阅检查完整 `extra`，拒绝重复交易公钥、重复附加公钥向量、未知字段、重复 nonce、截断字段和非法填充；XMR payload v3 会继续逐项验证 additional public key 与秘密、公钥和输出索引的绑定。
- XMR 标准输出和找零使用 `R = rG`；单一子地址目的地使用已绑定的 `R = rD`，混合/多目的地使用 payload v3 的逐输出 additional transaction-key 绑定。设备核对 `tx_extra` 公钥、输出索引、金额密文、view tag 和 commitment；MSR 子地址输出仍拒绝。子地址输入消费保留。

### 尚未完成

币种范围以 `coin-coverage.md` 为准。SIGN 只表示目录声明签名入口，并不表示全部交易类型可用。SOL、ADA、DOT、FIL、XCH、DCR、FIRO、FLUX 等仍缺已接入的交易适配器；不能用地址原语代替发送支持。

MSR RCT type 3 默认关闭。Monero 的独立 BP+ 基线和历史主网交易向量已进入回归，但新签交易仍需手机/电脑侧节点验收。SE050 安全会话、秘密解封策略、PN7161 实际连线、可信显示、看门狗、断电恢复与整机性能尚无这块硬件的完整验收证据。当前工程不能称为已完成生产验证的百链硬件钱包。

## 2026-10-24 变更与验收范围

*Merged from docs/validation-2026-10-24.md.*

MSR 不再作为 GRAVEYARD 例外：网络配置、设备目录、主机签名选择及设备启动自检均已移除。底层遗留 Masari 回归材料仍保留供历史算法检查，不表示产品支持。XMR 保留。

SOL 转账新增真实消息解析、费用计算、可信显示数据、单次批准签名和完整交易输出。范围扩展为单付款账户的 legacy/v0 System Transfer、经典 SPL 与 Token-2022 TransferChecked；不含 ATA 创建、质押和地址查找表。Token-2022 会显示“扩展不可离线核验”警告，要求额外 hook 账户的指令在解析阶段即被拒绝。未登记 mint 可通过精确 mint/代币账户/数量审阅转账，但不信任手机提供的代币名称或账户 owner。协议与离线限制见 [solana-signing.md](chain-protocols.md)。

本机 MSVC 主机自检通过，45 项 Python 测试通过；P4 加密模块和使用真实 Arduino/FreeRTOS 头文件的签名、链路及 worker 编译检查通过。SOL 独立向量来自 solders 0.26.0，SPL 指令由 solana-py 0.36.6 编码，包含完整预期签名交易字节，未使用待测钱包生成期望值。

经典 SPL 新增 16 组合法 SDK 向量、26 组拒绝案例、legacy/v0 全截断和批准摘要篡改检查。固件实际签出的交易在 solders 0.28.0 LiteSVM 中通过 9 项执行检查：2 项成功转账验证资产变动及费用，7 项错误状态/签名验证拒绝且代币账户不变。签名及 blockhash 验证开启；初始账户是明确注入的测试状态。记录见 `build/spl-svm-execution.json`，CI 已增加对应执行步骤及证据上传，尚未远程触发 Actions。

Clang UBSan 主机自检及 11 项 SOL/SPL Python 测试通过；真实 LVGL 9.5.0 头文件下的全部既有屏幕配置编译检查通过。主机构建仍有既有 mbedtls 测试兼容层和 Bitcoin 模块的整数窄化警告，不能称为全仓零警告。

尚未执行整机烧录、屏幕按键验收、NFC 电气/时序测量、SE050 解封或链上广播。SDK 向量使用合成 blockhash，不能作为全节点验收证据。

SE050 目前仍只有探测与能力规划，`WalletSession.cpp` 的助记词保存在 MCU RAM；不能称为已由安全芯片托管。接入前需要完整芯片料号、Applet 版本、设备独立 SCP03 配置方式以及板级连线。不要把生产密钥写进代码或提交到仓库，也不要用 NXP 默认演示凭据宣称完成保护。

ADA、DOT、FIL、CHIA、DCR、FIRO、FLUX 等交易适配器尚未补齐。当前完成度以 [coin-coverage.md](chain-support.md) 为准，不将目录或地址生成能力视作完整链支持。

### 同日追加：TRON、Token-2022 与 EVM 网络扩展

- 原生 TRX 与已登记 TRC-20 的 `raw_data` 严格解析、owner 权限校验、SHA-256 txID 绑定和 65 字节 `r||s||v` 签名接入 `BEGIN_SIGN kind=7`；范围与限制见 [tron-signing.md](chain-protocols.md)。
- TRON 向量由 `tools/generate_tron_vectors.py` 用纯 Python 实现 protobuf/BIP32/RFC 6979/secp256k1 生成，每条签名先经 OpenSSL 独立验签；`tests/test_tron.py` 用真实 C++ probe 覆盖完整字段、14 组拒绝、截断与外部 owner。设备启动自检在真实 mbedtls 上比较完整签名。
- Token-2022 使用 vendored solders 0.28.0 生成独立向量；`tests/test_spl2022.py` 比较完整签名字节、5 组合法交易、7 组拒绝指令与全截断。经典 SPL 夹具中“Token-2022 必须拒绝”的旧断言已移除，改由新夹具覆盖。
- 新增 EVM 网络 Unichain(130)、Monad(143)、Plasma(9745)、Berachain(80094)、Arc(5042)，链 ID 取自各自官方网络文档；USDC 合约取自 Circle 官方合约表，XAUT 取自 Tether 官方协议表且精度经链上 API 核实。Arc 的原生气体质押代币是 18 位 USDC，因此只登记网络、不重复登记代币合约。
- 当前主机自检 59 项 Python 测试通过；ESP32-S3/ESP32-P4 纯 C++ 编译与 P4 运行时签名/链路/ino 编译检查通过。
- 仍未执行 TRON 主网广播、能量/带宽实测、整机按键验收或 Token-2022 扩展的链上执行验证。

### 同日追加：Cosmos SDK 原生 MsgSend

- ATOM/OSMO/TIA 接入 `BEGIN_SIGN kind=8`：设备自行构建 `MsgSend`、`TxBody`、`AuthInfo`（`SIGN_MODE_DIRECT`）、`SignDoc` 与 `TxRaw`；手机只提供紧凑审阅字段，不提供交易结构。
- 严格校验 chain-id 前缀、bech32 HRP/校验和/20 字节 payload、本机地址与公钥绑定、原生 denom、单消息、无 memo、fee ≤ 10 枚、gas ≤ 2,000,000；签名前重建 `SignDoc` 并比较摘要。
- `tools/generate_cosmos_vectors.py` 用独立 Python 实现 protobuf/bech32/BIP32/RFC 6979/secp256k1，签名经 OpenSSL 验签；`tests/test_cosmos.py` 比较 C++ 实际构建的 `body`/`auth_info`/摘要与三组向量，并覆盖 12 组拒绝、采样截断、外部 owner/公钥。
- 顺带修复设备端 `EvmTransaction.cpp` 的 `evm_same_review` 未定义导致 ESP32-S3/P4 编译失败的问题：新增对审阅字段的显式比较（类型、网络、代币、金额、收款方、calldata 与全部显示文本）。
- 当前 67 项 Python 测试通过；ESP32-S3/ESP32-P4 编译与 P4 运行时检查通过。尚未执行 Cosmos 主网广播或节点验收。

### 同日追加：EVM 网络与证据整理

- X Layer(196)、zkSync Era(324)、OKT Chain(66) 通过 `chainid.network` 的 EIP-155 注册表加入；
  X Layer 与 zkSync Era 的 USDC 使用 Circle 官方合约表，OKT 暂不登记代币。
- 清理并发修改产生的重复 `xlayer`/`zksync` profile、catalog 行与 EIP-1559 名单重复项；
  重复 id 会让 `run_network_profile_self_tests()` 失败。
- 新增 `docs/chain-protocols.md` 记录链 ID 与代币来源；Starknet（Cairo）、Aptos、Sui、
  TON、NEAR 明确不是 EVM，不能用 EVM profile 冒充。
- `USDT0` 行按部署地址登记，尚未由本仓库独立核实发行方公告；正式资金路径前必须再次确认。

### 同日追加：Stellar XDR 与能力声明修正

- 新增 `StellarTransaction`：SEP-0005 派生和 G 地址、主网签名域、严格 XDR 解析、1–8 个 Payment/CreateAccount、原生/发行资产、memo、有限有效期和费用策略。接入 `BEGIN_SIGN kind=9`、设备审阅和单次批准；签名前逐字段重验。设备不增加网络访问。
- 固件启动自检比较官方 SEP-0005 地址及独立 SDK 生成的完整签名 envelope。测试同时经过实际 `WalletEngine::derive_address`，检查收款地址、派生路径、签名者和 Ed25519 托管类型一致。
- 固定 `stellar-sdk==13.1.0` 的 12 组合格交易和 13 组拒绝向量已生成并独立重生成一致；覆盖金额边界、全部 memo 类型、发行者、多个操作、截断、XDR 填充、错误网络/账户及签名前审阅篡改。CI 已添加 SDK 重生成校验，未远程执行。
- 修复主机测试退出码漏算 TRON/Cosmos 自检结果的问题；新增 Stellar 的结果也参与总判定。修正 EVM 目录和中文说明：NFT ABI 解析器存在，但当前未登记 NFT 合约，不能宣称已完成 NFT 转账。
- MSVC 主机自检通过；74 项 Python 测试全部通过、无跳过。ESP32-S3/P4 模块编译及 P4 运行时签名/链路/ino 编译通过。本机日志位于 `build/stellar-*.log`。
- Clang UBSan 主机自检通过，7 项 Stellar 专项测试在 UBSan probe 上通过，无未定义行为诊断；已有其他模块的编译警告仍存在，不宣称全仓零警告。
- 这仍不是全链实现或生产验收。未执行 Stellar 节点提交、整机屏幕/按键验收及物理安全验证。剩余适配器和 NFT 缺口见 [adapter-status.md](chain-support.md)，XLM 精确边界见 [stellar-signing.md](chain-protocols.md)。

### 同日追加：Algorand / NEAR 适配器与 SHA-512/256 修复

- Algorand 与 NEAR 均已接入独立解析、设备审阅、Ed25519 签名和 `BEGIN_SIGN` 分发；两者不访问网络，交易由手机或桌面端组装，设备只接受原始未签名字节。
- **关键修复**：`CryptoExtended.cpp` 的 SHA-512/256 单次实现对 ≥126 字节消息复用了上一分块，未清零 128 位长度字段的高 64 位，导致 Algorand 交易 txID 错误（真实支付交易均超过该长度）。现已清零整个尾块并写入高位长度，新增 128 字节分块 KAT；`extended-crypto` 启动自检通过。
- Algorand：严格 canonical MessagePack，主网 genesis 绑定，仅 `pay`/`axfer`；拒绝 group、rekey、close、clawback、LogicSig 和应用调用；fee 1,000–1,000,000 microAlgo，有效期窗口 ≤1000 轮；输出 canonical `{sig, txn}`。
- NEAR：严格 Borsh `TransactionV0`，仅 1–16 个原生 Transfer；128 位总额溢出拒绝；签名 SHA-256 摘要；输出 `tx || 0x00 || sig`；不声称命名账户所有权或 block hash 的链上新鲜性。
- 新增 `tests/fixtures/algorand-sdk.json`（py-algorand-sdk 2.11.1，11 合格/12 拒绝）与 `tests/fixtures/near-sdk.json`（near-api-js 5.1.1，11 合格/16 拒绝）；`algorand_probe`、`near_probe` 在 MSVC 与 Clang UBSan 下逐组匹配全部字段和签名字节，Python 测试用派生公钥独立验签。
- 新增 `src/generated/AlgorandVectorsTest.inc`、`NearVectorsTest.inc` 与对应 `--check` 生成器；固件启动自检比较完整 SDK 签名并验证错误 owner 被拒绝。`HexWallet.ino` 自检清单加入 algorand/near。
- 结果：86 项 Python 测试通过；MSVC 主机自检 `algorand=pass`、`near=pass`；Clang UBSan 主机自检通过；ESP32-S3、ESP32-P4 模块编译及 P4 运行时（WalletWorker/WalletSigning/WalletLinkService/ino）编译通过。
- 边界与缺口见 [algorand-signing.md](chain-protocols.md)、[near-signing.md](chain-protocols.md)。尚未执行主网广播、节点验收或整机物理安全测试；ADA、DOT/KSM、XRP、TON、SUI 等仍未实现，不以地址编码或原语存在冒充完整适配器。

### 同日追加：Algorand / NEAR 签名入口实现

- 补齐 `wallet_signing_begin_algorand`、`wallet_signing_begin_near` 及审阅 UI、签名分发和 worker 签名任务；`WalletLinkService` 的 kind=10/11 不再引用未定义符号。
- 审阅显示：Algorand 的发送方、收款方、金额/ASA id、费用、有效轮次、lease、完整 note hex 与路径；NEAR 的 signer、public key、block hash、nonce、逐笔金额、总额与路径。NEAR 无交易内手续费字段，UI 不伪造费用。
- 两个入口均先校验网络、catalog 签名能力和本机 owner，再解析；签名前由 `algorand_sign_transaction`/`near_sign_transaction` 重新解析并逐字段比较。P4 运行时编译通过，`HexWallet.ino` 自检包含 algorand/near。

### 同日追加：PAXG/XAUT/MANA、离线 TOTP、TRC-721/1155 与 EPD 刷新

- 代币登记：新增 Ethereum PAXG（`0x45804880De22913dAFE09f4980848ECE6EcbAf78`，18 位）、
  Ethereum MANA（`0x0F5D2fB29fb7d3CFeE444a200298f468908cC942`，18 位）和 Polygon MANA
  （`0xA1c57f48F0Deb89f569dFbE6E2B7f46D33606fD4`，18 位）。三者与既有 XAUT 均通过公开 RPC
  的 `symbol()`/`decimals()` 复核；PAXG、MANA 已进入 `coin-coverage` 的 TOKEN 行。
- TRON：`TronTransaction` 新增唯一 selector 的 TRC-721 `safeTransferFrom(0x42842e0e)` 与
  TRC-1155 `safeTransferFrom(0xf242432a，空 bytes 尾)`；校验 calldata `from == owner`，
  拒绝共享 selector 的 `transferFrom`、批量转移和回调数据。NFT 合约未登记时仍可审阅，但
  设备显示合约地址、标准、token id 与 UNREGISTERED 警告。生成器扩为 4 组合格/19 组拒绝，
  `tests/test_tron.py` 与设备启动自检均覆盖。
- TOTP：新增 `Totp.cpp`，严格 Base32、HMAC-SHA1/256/512、RFC 4226 动态截断、6–8 位、
  可配置周期；`millis()` 锚点时钟对回绕安全、对倒退 fail-closed。认证 CLI 提供
  `totp time <unix>` / `totp <base32> [digits] [period] [sha1|sha256|sha512]`，密钥不回显、
  不落盘。自检覆盖 RFC 6238 的 18 个向量、RFC 2202 HMAC-SHA1 与 RFC 4648 Base32；
  `tests/test_totp.py` 用 hashlib/hmac 独立复算并由 C++ 探针比对。
- EPD：LVGL 全帧 flush 改为 dirty 标记 + 120 ms 合并提交；每次提交使用完整刷新
  (`refresh(false)`)，写屏前 `powerOn()`、刷新后 `powerOff()`，修正了此前直接局刷和
  4×4 Bayer 阈值方向的问题。`board_display_colors()` 暴露 1/3/4 色能力；当前后端仍只有
  1bpp，若把 `HEXWALLET_EPD_COLORS` 设为 3/4 而没有匹配的 GxEPD2 3C/4C 驱动类，初始化
  会明确失败，不会用黑白类冒充彩色。具体面板型号/控制器/BUSY 极性未提供，三色/四色驱动
  仍未实现（边界见 `epd-lvgl.md`）。
- 结果：92 项 Python 测试通过；MSVC 主机自检 `totp=pass`、`tron=pass`、`tokens=pass`；
  Clang UBSan 主机自检通过；ESP32-S3/P4 模块编译、P4 运行时（含 `WalletCli.cpp`/`Totp.cpp`）
  与全板卡 `WalletBoardPort`/`WalletUi` 编译检查通过。
- 本轮未新增 ADA、DOT/KSM、XRP、TON、SUI、FIL 等原生适配器；没有独立序列化/签名向量
  就不写入占位实现。列表与缺口仍以 `adapter-status.md` 为准。
- 三色/四色 EPD 仍缺具体面板型号、控制器与排线，当前只验证 1bpp；把
  `HEXWALLET_EPD_COLORS` 设为 3/4 会 fail-closed，不会静默按黑白驱动。

### 同日追加：EinkFrame 与 128×296/四色 UI 准备

- 新增 `EinkFrame.cpp`：RGB565 → 1bpp/2bpp 原生帧转换，支持 1/3/4 色；红色先于亮度
  分类（纯红亮度仅 76，不能先判黑），2bpp 按 MSB-first 每字节四像素；3 色面板将黄色降级
  为白色。启动自检覆盖黑/白/红/黄、字节交换、容量与非法深度，`eink=pass`。
- `WalletBoardPort.cpp` 的 1bpp 转换改用该模块，移除本地 Bayer 表。
- `WalletUi.cpp`：128 px 宽目标使用 12 px 字体、缩放下限 0.45；3/4 色主题的标题、费用、
  确认码改用主题色（红/黄），不再硬编码绿色/深红。
- 新增 `docs/hardware-e029a182.md`，记录照片可确认的 ESP32-S3、四按键、128×296 EPD、
  USB-C 与缺失的网表/面板 datasheet。E029A182/SSD1680/四色三项在公开资料上不完全一致，
  未拿到厂商 demo 前不写驱动。

### 同日追加：Tezos 验证与 XRP r-address 修复

- Tezos（XTZ）：确认 `TezosTransaction` 已接入 `BEGIN_SIGN kind=12`、catalog、WalletEngine 与启动自检；7 项 `tests/test_tezos.py` 全部通过，主机 `tezos=pass`。边界与证据补入 `tezos-signing.md`。
- XRP：发现并修复地址层错误——旧 `xrp` profile 用 Bitcoin base58 字母表生成 P2PKH，得到的是 `16...` 而不是合法的 `r...`。新增 `AddressEncoding::Ripple` 与 `address_ripple()`（Ripple base58 + hash160 + double-SHA256 校验），已知向量得到 `rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH`；catalog 只声明地址能力，Payment 二进制/签名仍未接入，避免把错误地址当收款地址。
- 结果：104 项 Python 测试通过；ESP32-S3 模块编译（含 Tezos/EinkFrame/Totp）、P4 runtime 与全板卡 UI 编译通过。XRP 仍不可发送，coverage 显示 ADDRESS，不是 SIGN。

### 同日追加：XRP Payment 收发签名接入

- 新增 `XrpTransaction`：设备从 50 字节紧凑审阅结构构建规范 XRPL Payment 二进制，校验 amount/fee/sequence/last ledger/destination tag、目的账户与 source 绑定；签名摘要为 `SHA-512Half(0x53545800 || unsigned)`，签名以低 S secp256k1 DER 插入 `0x74` TxnSignature 字段。
- 修复 XRP 地址层：旧 profile 误用 Bitcoin base58，现为 Ripple base58 + hash160；固定向量 `rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH`，接入 `address_ripple()`、`AddressEncoding::Ripple`、catalog 与 WalletEngine。
- 接入 `BEGIN_SIGN kind=13`、设备审阅（source/destination/r-address、金额、fee、sequence、last ledger、tag、hash）、worker 签名、catalog 签名能力与启动自检 `xrp`。
- `tests/fixtures/xrp-sdk.json` 由 xrpl-py binary codec 生成：3 组合格（无 tag、tag、零 tag）、10 组拒绝；`xrp_probe` 与 `tests/test_xrp.py` 独立比较 unsigned/hash/字段。
- 结果：107 项 Python 测试通过；主机 `xrp=pass`、`tezos=pass`、`extended-crypto=pass`；S3 编译与 Clang UBSan 通过；P4 runtime 编译通过。
- 未执行 rippled 提交、主网 sequence/费用实测或硬件按键验收；不支持 issued currency、path、memo、partial payment、多签名。

## SUI/FIL 验证记录 — 2026-10-26

*Merged from docs/sui-filecoin-validation-2026-10-26.md.*

按用户后续要求，本会话集中 SUI/FIL；其他会话正在继续修改同一工作区的其他链。
本记录不对并发产生的其他适配器作完整性结论。

### 已完成

- SUI Ed25519 地址派生、原生 BCS 两命令转账解析与 97 字节签名输出。
- FIL f1 地址编码修复：未压缩公钥、`f1` 前缀与 BLAKE2b 校验和。
- FIL canonical CBOR Send、发送人归属校验、CID 签名域与 SignedMessage CBOR 输出。
- 签名入口容量传递、失败清除输出、批准后重解析/对比；屏幕审阅增加发送人和地址索引。
- SUI/FIL 接入既有 `kind=14` 设备签名入口、网络/目录、密钥类型与构建清单。
- 增加真实 `WalletSecurity.cpp` + Mbed TLS 3.6.5 主机探针，CI 构建步骤及独立 SDK fixture。

### 实际运行结果

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

接口、支持子集、手机广播适配及构建命令见 [sui-filecoin-signing.md](chain-protocols.md)。
审批可用后，仍需执行：

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1 -Target esp32p4
```
