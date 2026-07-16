# HexWallet

HexWallet 是 ESP32 离线钱包固件的基础工程。它从临时 BIP39 钱包派生地址，提供经过认证的串口接口，审核受限的 Bitcoin PSBT，并使用独立的网络与 Token 注册表管理元数据。

这是 Beta 固件，不是生产级硬件钱包。在完成板级适配、可信显示与确认链路、密钥存储保护和独立安全审计之前，禁止存放真实资产。

## 已实现能力

- BIP39 英文 24 词助记词生成、校验及 PBKDF2-HMAC-SHA512 种子派生。
- BIP32 私钥和公钥子密钥派生、扩展密钥序列化、启动已知答案自检。
- Bitcoin 主网 PSBT v0 审核与签名：BIP84 P2WPKH 和 BIP49 P2SH-P2WPKH 输入，限定 `SIGHASH_ALL`、BIP143、RFC6979 low-S ECDSA、费用限制和一次性确认码。
- 已登记 EVM 网络的严格 EIP-155 legacy 与 EIP-1559 type-2 审核/签名；只接受原生币转账和对已登记 ERC-20 合约的 `transfer(address,uint256)`。
- Bitcoin、Litecoin、Dogecoin、Dash、Bitcoin Gold、Ravencoin、XRP Ledger、TRON、Monero、Masari 及已登记 EVM 网络的地址派生。
- Monero 与 Masari 的 CryptoNote 标准地址：Keccak 标量派生、Edwards25519 公钥、网络前缀、分块 Base58 和校验和；交易解析与签名尚未开放。
- 已登记 ERC-20 Token 的合约地址、精度和账户地址查询。ERC-20 使用其所属 EVM 网络的同一个账户地址。
- 通过本地 `slip-0044.md` 的编号建立可搜索目录，并清晰区分“地址”“Token 账户”“交易审核”“签名”和“未实现”。
- 串口挑战应答认证、失败退避、会话超时和易失性钱包清除。

## 架构

| 模块 | 责任 |
| --- | --- |
| `WalletSecurity` | BIP39、BIP32、secp256k1、KDF、安全清零 |
| `CryptoNoteAddress` | CryptoNote 标量派生、Edwards25519 公钥和 Base58 标准地址 |
| `EvmTransaction` | canonical RLP、EIP-155/EIP-1559 审核和已登记 ERC-20 转账签名 |
| `WalletNetworks` | 链的 SLIP-0044 编号、派生编号、地址编码和 EVM chain ID |
| `WalletTokens` | Token 标准、所属网络、合约或 mint、精度、真实能力状态 |
| `WalletEngine` | 路径生成和地址编码 |
| `WalletCatalog` | 面向 CLI/UI 的能力目录 |
| `BitcoinTransaction` | 严格 PSBT v0 解析、审核、BIP143 签名和交易序列化 |
| `WalletCli` | 认证后的串口命令与输出 |
| `WalletBoardPort` | 特定硬件的屏幕、输入、电源时序 |
| `WalletTransportPolicy` | Serial/BLE/Wi-Fi 的 fail-closed 操作策略 |

`SLIP-0044` 只规定 BIP44 的 hardened coin type，不能规定地址格式、交易序列化、签名算法或 Token 规则。因此把一个条目加入 `slip-0044.md` 或目录，不代表该链可以派生地址、签名或转账。未实现链必须保持未实现状态，不能伪造支持。

## 派生策略

`NetworkProfile` 同时保存 `slip44_coin_type` 与 `derivation_coin_type`。

- UTXO 和非 EVM 网络使用它们注册的 SLIP-0044 编号。
- 已登记 EVM 网络统一使用 `m/44'/60'/account'/change/index`，其自身的 SLIP-0044 编号和 EVM chain ID 仍保留为元数据。这样同一助记词和索引可在 Ethereum、EVM 网络及 ERC-20 Token 中得到同一个标准账户地址。
- Bitcoin 通过独立 Profile 选择 BIP44、BIP49 或 BIP84。
- Monero 与 Masari 先按 `m/44'/coin'/account'/change/index` 得到 BIP32 子私钥，再将该 32 字节作为 CryptoNote Keccak-and-reduce 支付/查看私钥派生的输入。这是 HexWallet 自己明确规定的 BIP39 确定性策略，不是 Monero 官方 25 词种子格式，也不承诺兼容其他硬件钱包。

修改派生策略会改变地址。任何已有资产都必须记录实际使用的派生路径。

## 网络与 Token

当前 EVM 支持覆盖 Ethereum、Ethereum Classic、BSC、Polygon、Optimism、Arbitrum One、Base、Avalanche C-Chain、Fantom、Cronos、Gnosis Chain、Celo、Kava EVM、Core、Moonbeam、Moonriver。它们支持标准 EIP-155/EIP-1559 原生转账和已登记 ERC-20 转账；合约创建、任意 calldata、未知合约、非空 access list 及 type 2 之外的 typed transaction 会被拒绝。

Token 注册表含有部分经过固定登记的 USDC、USDT、DAI、WBTC、BUSD ERC-20 合约，以及一个已登记但未实现的 SPL USDC mint。合约或 mint 只是静态元数据，不是余额，不会自动发现资产。使用资产前必须自行核验网络和合约地址。

Solana/SPL 转账没有实现。它需要 Ed25519 HD 派生、Solana Base58 地址、关联 Token 账户派生、消息解析和 Ed25519 签名。当前 SPL 条目会明确返回不可用，不会生成错误地址或签名。

Monero 与 Masari 已实现主网标准地址，但 RingCT/CLSAG 交易解析、key image、诱饵校验、子地址、多签与签名尚未实现。Chia 的 BLS12-381、CLVM puzzle、coin spend 解析和聚合签名栈尚未实现和验证，因此 XCH 地址与签名保持不可用。任何链的质押/验证者消息只有在目录明确列出对应的专用解析器和审核策略后才允许签名。

## 能力矩阵

| 能力 | 当前范围 |
| --- | --- |
| Bitcoin 签名 | 主网 PSBT v0、BIP49 P2SH-P2WPKH、BIP84 P2WPKH、`SIGHASH_ALL` |
| Bitcoin 地址 | BIP44 P2PKH、BIP49 P2SH-P2WPKH、BIP84 P2WPKH |
| EVM 地址 | 已登记网络的派生策略（Ethereum 兼容网络使用 coin type 60，Ethereum Classic 使用 61） |
| EVM 原生币签名 | canonical EIP-155 legacy 和 EIP-1559 type 2，仅简单转账并限制最大 gas 费用 |
| Monero/Masari 地址 | 文档所述 HexWallet BIP39 策略下的 CryptoNote 主网标准地址 |
| Monero/Masari 交易签名 | 未实现 |
| Chia 地址或签名 | 未实现 |
| ERC-20 Token 账户地址 | 已登记 Token 的网络、合约、精度与账户地址 |
| ERC-20 转账签名 | 仅已登记合约和精确的 `transfer(address,uint256)` calldata |
| Solana/SPL 地址与签名 | 未实现 |
| 其他 SLIP-0044 条目 | 仅目录登记，直至存在完整实现和测试向量 |

## 串口命令

锁定时可查询公开元数据：

```text
help
status
coin list
coin search <text>
coin show <id>
token list [network]
token show <id>
```

认证并加载钱包后可执行：

```text
wallet generate
wallet import <24-word-mnemonic>
wallet address <network> [index]
wallet token <token-id> [index]
wallet addresses [index]
tx inspect <psbt-v0-hex>
tx sign <six-digit-confirmation>
evm inspect <network> <index> <unsigned-rlp-hex>
evm sign <six-digit-confirmation>
tx reject
```

例如 `wallet token eth-usdc 0` 会返回 Ethereum 的 BIP44 路径、账户地址、USDC 合约和精度；转账必须经过独立的 inspect/review/sign 流程。`wallet secret` 默认由 `HEXWALLET_ENABLE_SECRET_EXPORT=0` 在编译期关闭，生产设备应保持关闭。

## 构建

已验证目标为 Espressif ESP32 core 3.3.10 和 FQBN `esp32:esp32:lilygo_t_display_s3`。无 LVGL 的 CLI 固件可使用：

```text
arduino-cli compile --fqbn esp32:esp32:lilygo_t_display_s3 \
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_ENABLE_LVGL=0 \
  --build-property compiler.c.extra_flags=-DHEXWALLET_ENABLE_LVGL=0 .
```

启用 `HEXWALLET_ENABLE_LVGL=1` 需要 LVGL 9.5.0。`WalletBoardPort.cpp` 在未知道准确板型、显示控制器、触摸控制器、GPIO、总线和电源时序时会 fail-closed。`ESP32-S3N8` 只表示芯片配置，不是完整的 LilyGo 板型或触摸控制器型号。

## 测试与安全边界

当 `HEXWALLET_RUN_SELF_TESTS=1` 时，启动会运行加密、secp256k1、CryptoNote、BIP39、BIP32、地址、EIP-155/EIP-1559、传输策略和 Bitcoin 交易自检。EIP-155 自检逐字节匹配官方 unsigned RLP、签名哈希、`v/r/s` 和 signed transaction。

编译通过和自检通过不等于生产安全。真实资产前必须具备加密存储或经过审计的安全元件、Secure Boot、Flash Encryption、防回滚、认证固件更新、实体确认输入、可信显示链路、故障注入和侧信道测试、恢复测试、可复现构建和独立审计。

串口确认码只能降低误操作风险。默认构建只在可信屏幕显示确认码，没有屏幕时拒绝签名。未知 Bitcoin 脚本、PSBT v2、Taproot、多签、任意摘要、任意 EVM 调用、未知 Token 合约、SPL 转账和未实现链会被拒绝或保持不可用。

`WalletTransportPolicy` 将 Wi-Fi 永久限制为公开价格和区块高度操作；Wi-Fi 签名请求、批准响应和秘密导出都会 fail-closed。BLE 驱动和配对密钥存储尚未实现；策略只允许已经认证、已配对且经过可信屏幕审核的 BLE 请求/批准，因此仅添加 BLE characteristic 不能启用签名。

## 许可证

Copyright (c) 2024-2026 Blueokanna。本项目只向自然人授予个人非商业使用许可。修改版和衍生版仍不得商用；组织使用、雇佣或客户工作、出售或预装硬件、收费或托管服务、代管/质押服务及任何直接或间接商业活动，都必须事先联系 `blueokanna@gmail.com` 取得单独的书面商业授权。完整条款见 `LICENSE`，发生解释差异时以其中英文原文为准。
