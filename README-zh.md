# HexWallet（BETA）

HexWallet 是面向 ESP32 的离线钱包固件基础，提供经过认证的串口界面和 LVGL 9.5.0 图形界面。当前项目仍处于实验阶段；在完成真实板级适配、安全存储、固件信任链和独立安全审计前，不能保存真实资产。

## 已实现

- BIP39 英文 24 词生成、校验和 PBKDF2-HMAC-SHA512 种子派生。
- BIP32 私钥/公钥子密钥派生和扩展密钥序列化。
- 由 `WalletNetworks`、`WalletCatalog` 和 `WalletEngine` 驱动的统一地址派生。
- 串口挑战应答认证、持久化失败计数、指数退避、会话超时和易失钱包清除。
- CLI 与 LVGL 9.5.0 共用的可搜索币种目录。
- Bitcoin 主网原生 P2WPKH PSBT v0 审核和签名。
- SHA-256、RIPEMD-160、legacy Keccak-256、BIP39、BIP32、地址、BIP143 和 RFC6979 ECDSA 启动自检。

Bitcoin 签名器只接受有边界限制的 PSBT v0。所有输入必须是当前钱包 BIP84 路径控制的原生 P2WPKH，只允许 `SIGHASH_ALL`。签名前会校验每个输入的公钥、脚本和派生路径，解析每个输出，拒绝未知脚本，检查金额溢出和费用策略。签名使用 RFC6979 secp256k1 ECDSA、low-S，并在输出签名前再次验签。工程中不存在“任意 32 字节摘要签名”接口。

## 能力矩阵

| 网络 | 地址 | 交易审核 | 签名 |
| --- | --- | --- | --- |
| Bitcoin `m/84'/0'` | 原生 P2WPKH | PSBT v0、P2WPKH 输入 | BIP143 ECDSA |
| Bitcoin `m/44'/0'` | P2PKH | 无 | 无 |
| Litecoin、Dogecoin、Dash、Bitcoin Gold、Ravencoin | P2PKH | 无 | 无 |
| Ethereum、Ethereum Classic、Optimism、Polygon、Fantom、Base、Arbitrum、Avalanche C-Chain、BSC | EVM 地址 | 无 | 无 |
| XRP Ledger | Classic 地址 | 无 | 无 |
| TRON | Base58Check 账户地址 | 无 | 无 |

可搜索目录还会显示 BCH、BSV、XEC、DGB、PPC、NMC、XMR、ZEC、KAS、ERG、CKB、FLUX 和 XCH，但明确标记为不支持。这样可以避免把“发现了币种名称”伪装成“已经实现钱包”。

SLIP-0044 只用于注册的 hardened `coin_type`，不定义地址格式、网络前缀、哈希、脚本或交易规则。MiningPoolStats 只用于发现候选网络。没有官方规范和测试向量的网络不会启用。

## 终端界面

没有屏幕时，经过认证的 CLI 仍可完整使用。币种元数据可在锁定状态查询；钱包、秘密导出和签名必须先认证。

```text
coin list
coin search <文本>
coin show <id>
wallet generate
wallet import <24 个单词>
wallet address <id> [index]
wallet addresses [index]
wallet secret [index]
tx inspect <psbt-v0-hex>
tx sign <六位确认码>
```

`tx inspect` 会先显示每个输出、归属分类、输入/输出总额、费用、估算虚拟字节、费率和审核 ID，然后生成两分钟有效的一次性确认码。详细协议见 [CLI_PROTOCOL.md](CLI_PROTOCOL.md)。

## 构建与安全限制

安装 Espressif ESP32 Core 3.3.10 或更新版本以及 LVGL 9.5.0。`WalletBoardPort.cpp` 在没有为具体屏幕、总线、GPIO、输入设备和供电时序完成适配前会主动报告无屏幕。

2026-07-16 实际编译结果：无 LVGL 版本占用 410,280 字节 Flash、46,724 字节静态 RAM；LVGL 9.5.0 版本占用 491,640 字节 Flash、47,348 字节静态 RAM。

当前 PIN verifier 和钱包仍位于普通 ESP32 内存/NVS。生产硬件还必须具备加密存储或经过审计的安全元件、Flash Encryption、Secure Boot、防回滚、认证固件更新、实体确认按键、可信显示链路、侧信道和故障注入评估、恢复测试、可复现构建及独立审计。串口确认码能防止误操作，但不能抵御已经控制同一认证串口会话的主机。

目前只有 Bitcoin 原生 P2WPKH 签名。EVM、TRON、XRP、Bitcoin legacy、其他币种交易、PSBT v2、Taproot、多签、P2SH-P2WPKH 和任意脚本均未实现或会被拒绝。
