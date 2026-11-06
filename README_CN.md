# HexWallet

HexWallet 是一台跑在单片机上的签名钱包：密钥派生、交易解析、交易审查和签名全部在设备内完成，
主机拿不到助记词，也拿不到私钥。固件里没有 socket、TLS、HTTP 代码，联网这件事从编译期就被排除。

当前支持 ESP32-S3 与 ESP32-P4。同一份源码可以编译成带屏钱包、带 SE051 安全芯片的 P4 墨水屏板，
或者一块只跑串口 CLI 的无屏开发板。

## 项目状态

Host 测试全绿，产品没做完。两句话都是重点。

- **这里验证过的**：72 项带名字的 host 检查（`tests/host/build.ps1`）、ESP32-S3/P4 编译检查、
  全板型驱动编译矩阵、固件策略门禁。CI 每次 push 都会跑。
- **这里没验证的**：硬件验收。仓库里没有一块板子的"刷机—连接节点—真实签名"完整记录，
  没有任何一条链通过端到端验收，也没有第三方审计。
- **没做完的**：安全芯片托管。SCP03 安全通道、APDU applet 层、曲线映射、个人化流程都已经实现并做了
  host 测试，但钱包层仍然在 MCU RAM 里派生和签名。设备默认的 `HEXWALLET_REQUIRE_SECURE_CUSTODY=1`
  会把会话编译成一律拒绝。说直白点：**现在的设备固件无法创建、导入或使用钱包**，只有 host 测试构建
  会跑通密钥路径。
- 整个代码树按实验品对待。不要放你赔不起的钱。

## 硬件

| `HEXWALLET_BOARD` | 目标板 | 显示 | 说明 |
| --- | --- | --- | --- |
| 1（默认） | LilyGO T-Display S3 AMOLED | 240x536 AMOLED，CST816S 触摸 | ESP32-S3 |
| 2 | T-Display S3 AMOLED Plus | 同面板，AXP313A 电源管理，microSD | ESP32-S3 |
| 3 | T-Display S3 | 170x320 ST7789，8 位并口 | ESP32-S3 |
| 4 | T-Deck Max | 240x320 UC8253 墨水屏，支持局部刷新 | ESP32-S3，除 BOOT 外没有已验证的按键 |
| 5 | T-Echo Lite Kit | 176x192 墨水屏 | nRF52840；这里只有引脚表，没有 nRF52 编译目标 |
| 6 | 无屏 | 无 | 任意 ESP32，只能用串口 CLI |
| 7 | HexWallet P4 rev A | 128x296 SSD1680 墨水屏 | ESP32-P4，SE051C2HQ1 走 I2C，PN7161 走共享 SPI |

引脚定义在 `WalletBoardPins.h`，一块板一段，全部对齐原理图或厂家引脚图。7 号板取自 EasyEDA 工程
`c26102103`，注释里写明每个网络落在哪个封装焊盘上。没有可靠网络表的引脚一律不猜：NFC 端口会报
`not-configured`，摄像头保持关闭。

## 一次签名经历什么

1. 用 PIN 派生的密钥解锁串口会话，或用已配对的手机通过链路解锁。
2. 主机把交易载荷送进来。设备解析成有界的审查结构；格式不对或不支持的交易在这里就被拒，密钥还没被碰过。
3. 做归属校验：PSBT 输入必须指向钱包自己的 UTXO；CryptoNote 环签名必须把 key image 和承诺绑定到钱包；
   EVM calldata 必须命中已登记 token 调用，否则按原始字节显示。
4. 审查结果画在屏上：收款地址、金额、手续费、以及该链特有的风险提示。批准来自这一帧画面上的按键，
   并且会过期。
5. 只有到这一步才解封签名密钥。无论签名成功还是失败，这次批准都会被消耗掉。
6. 一次性签名链（QRL）在签名产生**之前**先把叶子写进持久存储，并在释放签名前验证自己算出的签名。

代码里没有"用代码批准交易"的接口，也没有任何路径能签一个没审查过的缓冲区。细节见
[Security-Model](https://github.com/blueokanna/HexWallet/wiki/Security-Model-zh)。

## 强制执行的约束

- **助记词与私钥不可导出。** `HEXWALLET_ENABLE_SECRET_EXPORT` 不是运行时开关，打开它直接编译失败
  （`WalletConfig.h`）。
- **没有网络栈。** 固件源码里一旦出现 `WiFi`、`HTTPClient`、`esp_http_*`、`esp_wifi`、`lwip`、
  `mbedtls/ssl`，策略门禁直接失败。
- **传输策略。** 签名请求和批准响应要求"已认证会话 + 可信显示"，对任何传输方式一视同仁。
  无屏固件只有显式编入 `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION=1` 才能在串口上批准，而且只限串口
  （`WalletTransportPolicy.cpp`）。
- **托管门禁。** 后端已注册、通道已认证、用户已认证、密钥不可导出、钱包层走句柄，五个事实同时成立才算
  安全托管。一个由集成代码随手置位的布尔量，正是"硬件钱包"变成营销话术的方式。
- **随机数。** 固件在电池 ADC 和工作任务启动前独占 SAR ADC 熵源。每个采样块通过健康测试后才用于初始化 HMAC-SHA256 DRBG。取熵失败会阻止钱包启动。一次开机最多提供 2²⁰ 次随机请求，达到上限后需重启取熵。
- **启动信任。** `TrustAnchor` 记录启动状态；`HEXWALLET_REQUIRE_VERIFIED_BOOT=1` 时，安全启动或
  Flash 加密关着的设备拒绝签名。
- **解析失败就失败。** 签名出错会清零调用方的输出缓冲区（`SigningOutputGuard`）；审查会话一次即废；
  上锁或超时会清掉挂起审查。

## 链支持范围

目录对外暴露 215 个钱包条目，覆盖 247 个编译进来的网络配置。"条目"指的是派生路径加上审查/签名策略，
不是节点验收结论。

| 家族 | 已实现 | 明确不做 |
| --- | --- | --- |
| Bitcoin | PSBT v0/v2、legacy/BIP143/Taproot key-path（BIP86）、`SIGHASH_DEFAULT`/`ALL` | 脚本路径、多签、Lightning |
| UTXO 分叉 | 105 个生成配置，按链选择 legacy、BIP143、`SIGHASH_FORKID`、Groestl-512、ZIP-243 | 只有核对过 `chainparams` 的分叉才准入；绝不拿 Bitcoin 签名器去猜 |
| EVM | 62 条网络、EIP-155/2930/1559、80 条固定 token 记录、未识别 calldata 按原始字节加 keccak-256 显示 | 未知 calldata 只当代码显示，绝不解码成转账 |
| Monero | RCT type 6、CLSAG、Bulletproofs+、16 成员环、子地址花费 | 诱饵由手机提供；离线设备无法证明它们真的在链上 |
| 原生适配器 | ADA、ALGO、APT、CKB、DCR、ERG、FIL、HBAR、HIVE、ICX、ICP、KSM、DOT、NEAR、QRL v1/v2、SC、SOL、STARK、SUI、TFUEL、TON、VET、XCH、XEM、XLM、XRP、XTZ、ZEC、TRX、KAS、DASH、AE、QUAI（Cyprus-1）、ALPH、QTC（Quantus）、ZEPH | 每个适配器有独立载荷格式、审查规则和拒绝清单 |
| 仅地址 | RyoCurrency、Zano | 编码器有测试；没有签名路径，界面也不会假装有 |

HIVE 只能审查和签名：STM 公钥不是收款地址，所以这个条目没有地址能力。这种不对称写在目录数据里，
不是脚注。

逐链矩阵和完整拒绝清单位于
[Supported-Chains](https://github.com/blueokanna/HexWallet/wiki/Supported-Chains-zh) 和
[Admission-Policy](https://github.com/blueokanna/HexWallet/wiki/Admission-Policy-zh)。

## 明确拒绝的用法

这里只列一部分，完整清单在 wiki。

- Zcash：屏蔽池、JoinSplit、v5，以及除单钥 `CHECKSIG` 之外的 P2SH redeem script。
- Peercoin 签名。PPC v<3 交易带 `nTime`，legacy 签名器会拼出一笔无效交易，所以 PPC 只保留地址能力。
- 以太坊盲签。未知 calldata 显示为原始字节和哈希，不会被解码成转账。
- TRON NFT、批量调用、多合约交易、非 owner 权限。
- Cosmos IBC、authz、feegrant、amino/JSON 签名。
- Dash 特殊交易（`extraPayload`）。普通 type-0 支付可以签，InstantSend 意图会显示在屏上，但锁本身是
  设备无法验证的 quorum 决定。
- Stacks、Lightning 和 Grin 的钱包收付流程。
- Beam 已实现单个普通输入的原生双向协商转账。主网资产托管、节点同步和链上恢复仍待接入。见 [Beam 实现说明](wiki/Beam-zh.md)。
- AION：按决定排除。它一旦重新出现在网络配置、目录或矿池表里，`policy_check.ps1` 直接失败。
- Qubitcoin：按决定排除。官配站点是 404，而且两个互不相关的项目共用 QTC 这个 ticker，所以 owner
  把它移出范围；理由留在
  [准入策略](https://github.com/blueokanna/HexWallet/wiki/Admission-Policy-zh#被要求但未准入的链) 里。
- 没有上游 SLIP-0044 编号的链。借用别家 coin type 等于给两个域派生同一把钥匙。

Zephyr、Alephium 和 Quantus 的普通转账已接入原生审阅和签名。Beam 的双方签名流程和普通地址编码已通过独立参考测试，节点消息、链上同步和安全密钥托管有待接入。Xelis 已实现原生恢复、地址和签名原语。生产实机上的密钥托管仍未开放。详见[链交易载荷](wiki/Chain-Payloads-zh.md)。

## 接口

**串口 CLI**（`help` 是契约，列全所有命令）：

```text
public: help | status | coin list | coin search <text> | coin show <id> | coin why <id>
        mining stats | mining list [ASIC|GPU|CPU|HDD|MERGED] [offset] | mining show <id>
        token list [network] | token show <id>
auth:   auth provision <pin> <pin> | auth begin | auth unlock <proof-hex> | lock
wallet: wallet generate | wallet address <id> [index] | wallet custody <id>
        wallet token <id> [index] | wallet addresses [index]
tokens: token custom-list [network] | token custom-add <network> <id-hex> <symbol> <name> <decimals>
        token custom-add-stellar <issuer-hex> <code> <symbol> <name> <decimals>
        token custom-add-nft <network> <contract-hex> <erc721|erc1155> <symbol> <name>
        token custom-remove <network> <id-hex> | token custom-remove-stellar <issuer-hex> <code>
totp:   totp time [unix] | totp add <otpauth-uri> | totp list | totp show <slot> | totp remove <slot>
sign:   tx inspect [<coin>] <psbt-hex> | tx sign <code> | tx reject
        evm inspect <network> <index> <unsigned-rlp-hex> | evm sign <code>
        kaspa inspect <payload-hex> | kaspa sign <code>
        zec inspect <ZEC4|ZEC5-payload-hex> | zec sign <code>
        chain begin <network> <index> <payload-hex> | chain sign <code> | chain reject
link:   link status | link pair confirm | link pair reject
other:  selftest
```

会话空闲五分钟自动上锁。个人化时保存 `salt` 和 `verifier = PBKDF2-SHA256(PIN, salt, 120000)`。
`auth begin` 返回盐、迭代次数和一个新的 32 字节 nonce；`auth unlock` 接受
`HMAC-SHA256(verifier, nonce)`，常量时间比较，连续失败会退避。

**USB 数据默认关闭。** 长按 BOOT 三秒打开十分钟窗口；再长按、窗口到期或执行 `lock` 都会关闭窗口并丢弃
已缓冲输入。

**手机链路。** 所有操作由手机发起，钱包只负责审查、授权和签名。协议版本 2：Ed25519 身份密钥配对，
X25519 临时密钥交换，HKDF-SHA256 会话密钥，ChaCha20 加密后逐帧 HMAC，序号单调递增。重放、乱序、
伪造的帧都会直接销毁会话。见 [Phone-Link](https://github.com/blueokanna/HexWallet/wiki/Phone-Link-zh)。

**TOTP** 密钥只存在设备上，不出设备；只有已认证会话才能让 CLI 打印验证码。

## 编译

需要 ESP32 core 3.3.10 和 LVGL 9.5.0：

```powershell
arduino-cli core install esp32:esp32@3.3.10
git clone --depth 1 --branch v9.5.0 https://github.com/lvgl/lvgl.git "$HOME/Arduino/libraries/lvgl"
arduino-cli compile --fqbn esp32:esp32:esp32s3 `
  --library "$HOME/Arduino/libraries/lvgl" `
  --build-property compiler.cpp.extra_flags=-DLV_CONF_INCLUDE_SIMPLE `
  --build-property compiler.c.extra_flags=-DLV_CONF_INCLUDE_SIMPLE .
```

板型和功能全部是编译期 `-D` 参数，集中在 `WalletConfig.h`：

| 宏 | 默认值 | 含义 |
| --- | --- | --- |
| `HEXWALLET_BOARD` | 1 | 板型编号，见上表 |
| `HEXWALLET_ENABLE_LVGL` | 1 | 0 表示只编 CLI 镜像 |
| `HEXWALLET_EPD_PROFILE` | 0 | 0 SSD1680 单色、1 四色、2 单色 V2（P4） |
| `HEXWALLET_REQUIRE_SECURE_CUSTODY` | 设备上为 1 | 没有安全芯片托管就拒绝打开钱包 |
| `HEXWALLET_REQUIRE_VERIFIED_BOOT` | 0 | 安全启动 + Flash 加密未开启时拒绝签名 |
| `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION` | 0 | 允许无屏固件在串口上批准 |
| `HEXWALLET_DEVICE_SELF_TESTS` | 设备上为 0 | 在样机上跑向量套件（吃 DRAM） |

`esp32p4` 必须显式指定 7 号板：

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32p4 -DHEXWALLET_BOARD=7 ...
```

Flash 分区表是 `partitions/hexwallet-16mb-ota.csv`。烧 eFuse 之前先读安全启动和 Flash 加密的说明：
eFuse 烧错，OTA 救不回来。详见
[Build-and-Flash](https://github.com/blueokanna/HexWallet/wiki/Build-and-Flash-zh)。

## 测试

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1            # host 套件，72 项
powershell -ExecutionPolicy Bypass -File tests/host/policy_check.ps1     # 固件策略门禁
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1 -Target esp32p4
powershell -ExecutionPolicy Bypass -File tests/host/board_port_compile_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/p4_runtime_compile_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/se051_port_check.ps1 -Device
powershell -ExecutionPolicy Bypass -File tests/host/ui_check.ps1
powershell -ExecutionPolicy Bypass -File tests/host/build_clang_ubsan.ps1
```

有几个脚本第一次跑要联网或先拉依赖：`qr_cross_check.ps1`（nayuki QR 参考实现）、
`build_chain_native.ps1`（`build/chain-mbedtls` 下的 mbedTLS 3.6.5）、`board_port_compile_check.ps1`
和 `epd_driver_compile_check.ps1`（LVGL 9.5 与 GxEPD2）。CI 里每个版本都是钉死的。

套件证明了什么、没证明什么，写在 [Testing](https://github.com/blueokanna/HexWallet/wiki/Testing-zh)。
向量全过只说明实现和本仓库的向量一致，不说明网络会接受这笔交易。

## 仓库结构

| 路径 | 内容 |
| --- | --- |
| `*.cpp`、`*.h` | 固件；Arduino 以 sketch 目录为库根，所以所有编译单元都在根目录 |
| `src/generated/` | 生成的目录表与钉死的向量 |
| `tests/host/` | host 测试框架、探针、编译检查脚本 |
| `tests/fixtures/` | 上游交易样本与生成的向量 |
| `tools/` | 目录生成器与人工核对过的 MiningPoolStats 映射 |
| `partitions/` | Flash 分区表 |
| `wiki/` | GitHub wiki 的源文件（英文 + 中文） |

## 文档

wiki 是长文档，由 `wiki/` 发布：

- [Home](https://github.com/blueokanna/HexWallet/wiki/Home-zh) · [English](https://github.com/blueokanna/HexWallet/wiki/Home)
- [Architecture](https://github.com/blueokanna/HexWallet/wiki/Architecture-zh)
- [Security-Model](https://github.com/blueokanna/HexWallet/wiki/Security-Model-zh) · [Threat-Model](https://github.com/blueokanna/HexWallet/wiki/Threat-Model-zh)
- [Supported-Chains](https://github.com/blueokanna/HexWallet/wiki/Supported-Chains-zh) · [Chain-Payloads](https://github.com/blueokanna/HexWallet/wiki/Chain-Payloads-zh)
- [Admission-Policy](https://github.com/blueokanna/HexWallet/wiki/Admission-Policy-zh)
- [Phone-Link](https://github.com/blueokanna/HexWallet/wiki/Phone-Link-zh) · [Secure-Element](https://github.com/blueokanna/HexWallet/wiki/Secure-Element-zh)
- [Boards-and-Display](https://github.com/blueokanna/HexWallet/wiki/Boards-and-Display-zh)
- [Build-and-Flash](https://github.com/blueokanna/HexWallet/wiki/Build-and-Flash-zh) · [Testing](https://github.com/blueokanna/HexWallet/wiki/Testing-zh)
- [Registries](https://github.com/blueokanna/HexWallet/wiki/Registries-zh) · [Audit-Records](https://github.com/blueokanna/HexWallet/wiki/Audit-Records-zh)

## 许可证

HexWallet Personal Non-Commercial Source License 1.0。这是 source-available，不是开源：
只允许个人非商业使用，商业使用必须另行签署授权。以 `LICENSE` 全文为准。第三方材料列在 `NOTICE`，
各自保留原许可证。

给工具链用的 SPDX 标识：`LicenseRef-HexWallet-Personal-NonCommercial-1.0`。

商业授权联系：blueokanna@gmail.com
