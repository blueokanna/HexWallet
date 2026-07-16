# HexWallet CLI 使用与构建指南

HexWallet 是运行在 ESP32-S3 上的离线钱包固件基础工程。它提供 BIP39/BIP32 密钥派生、地址生成、受限的 Bitcoin PSBT 审查、受限的 EVM 交易审查，以及经过认证的 USB 串口 CLI。

本文档以实际源码中的命令和安全策略为准，目标是让你可以从编译、刷写、打开串口，到完成认证、生成或导入钱包、查询地址和执行交易审查。命令必须逐行发送，并以换行结束。

> 重要：当前工程仍是 Beta 固件，不是经过独立审计的生产级硬件钱包。钱包只保存在 RAM 中，设备重启、复位、锁定或会话超时都会清除钱包。不要在未经硬件适配、安全审计、Secure Boot、Flash Encryption、可信显示器和恢复流程验证的情况下存放真实资产。

## 目录

1. [功能边界](#功能边界)
2. [硬件和软件要求](#硬件和软件要求)
3. [使用 Arduino CLI 编译](#使用-arduino-cli-编译)
4. [刷写固件和打开串口](#刷写固件和打开串口)
5. [启动自检](#启动自检)
6. [CLI 的状态模型](#cli-的状态模型)
7. [首次配置认证](#首次配置认证)
8. [计算认证 proof](#计算认证-proof)
9. [解锁会话](#解锁会话)
10. [生成和导入钱包](#生成和导入钱包)
11. [查询网络和 Token](#查询网络和-token)
12. [生成地址](#生成地址)
13. [Bitcoin PSBT 审查和签名](#bitcoin-psbt-审查和签名)
14. [EVM 交易审查和签名](#evm-交易审查和签名)
15. [锁定、超时和清除](#锁定超时和清除)
16. [完整操作示例](#完整操作示例)
17. [常见错误](#常见错误)
18. [安全边界](#安全边界)

## 功能边界

当前固件可以执行以下操作：

- 生成和校验英文 BIP39 助记词。
- 使用 PBKDF2-HMAC-SHA512 派生 BIP39 seed。
- 使用 BIP32 派生私钥、公钥和扩展密钥。
- 为已实现的 Bitcoin、EVM、TRON、XRP、Litecoin、Dogecoin、Dash、Bitcoin Gold、Ravencoin、Monero 和 Masari 网络生成地址。
- 查询已登记 Token 的合约地址、精度和账户地址。
- 审查并签名受限的 Bitcoin PSBT v0。
- 审查并签名已登记 EVM 网络上的原生转账和已登记 ERC-20 的精确 `transfer(address,uint256)` 调用。

以下能力明确不可用：

- Monero/Masari RingCT、CLSAG、key image、子地址、多签和交易签名。
- Solana/SPL 的地址派生、关联 Token 账户和签名。
- Chia、Cardano、Cosmos、Polkadot、Aptos、Sui 等目录项的交易能力。
- 任意 EVM calldata、合约创建、未知 Token、非标准 typed transaction、非空 access list。
- 未实现网络的地址或签名。
- 默认配置下的助记词、seed、私钥和 xprv 导出。

目录中的网络或 Token 条目不等于完整实现。执行操作前必须检查 `coin show`、`token show` 输出的 `capabilities` 和 `status`。

## 硬件和软件要求

### 硬件

- ESP32-S3 开发板。
- USB 数据线，而不是只能充电的 USB 线。
- 能够识别串口的 Windows、Linux 或 macOS 主机。
- 进行交易签名时，必须使用已经正确适配的可信显示器；没有可信显示器时，默认策略会拒绝签名。

`ESP32-S3N8` 只表示芯片和 Flash/PSRAM 配置，不等于具体的开发板型号。显示器控制器、触摸控制器、GPIO、I2C/SPI 总线和供电时序必须与 `WalletBoardPort.cpp` 的适配一致。

### 软件

- Arduino CLI。
- Espressif ESP32 Arduino Core 3.3.10。
- 如果启用 LVGL，需要安装项目要求的 LVGL 9.5.0。
- Windows 下可以使用 PowerShell；Linux/macOS 下可以使用等价的 Python、OpenSSL 或系统加密工具计算认证 proof。

## 使用 Arduino CLI 编译

### 安装和初始化 Arduino CLI

先确认 Arduino CLI 可执行：

```powershell
arduino-cli version
```

初始化配置并安装 ESP32 平台：

```powershell
arduino-cli config init
arduino-cli core update-index
arduino-cli core install esp32:esp32@3.3.10
```

确认已安装版本：

```powershell
arduino-cli core list
```

输出中应包含 `esp32:esp32` 的 `3.3.10`。

### 查找串口和 FQBN

连接开发板后执行：

```powershell
arduino-cli board list
```

也可以搜索所有 ESP32-S3 板型：

```powershell
arduino-cli board listall esp32:esp32 | Select-String -Pattern 'S3|s3|LilyGo'
```

本仓库文档验证过的目标是：

```text
esp32:esp32:lilygo_t_display_s3
```

如果你的板子不是 LilyGo T-Display S3，不能盲目使用这个 FQBN。应选择与你的实际板型、Flash、PSRAM、USB 模式和分区表匹配的 FQBN。例如，通用 ESP32-S3 开发板可能使用：

```text
esp32:esp32:esp32s3
```

具体应以 `arduino-cli board list` 和板卡资料为准。

### CLI-only 编译

没有 LVGL 或暂时只验证串口 CLI 时，关闭 LVGL 编译：

```powershell
arduino-cli compile `
  --fqbn esp32:esp32:lilygo_t_display_s3 `
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_ENABLE_LVGL=0 `
  --build-property compiler.c.extra_flags=-DHEXWALLET_ENABLE_LVGL=0 `
  .
```

编译成功不代表显示器、触摸、供电和签名安全链路已经适配。CLI-only 构建可以用于地址和协议测试，但没有可信显示器时默认不能签名。

### 启用 LVGL 编译

安装并确认 LVGL 9.5.0 后，使用实际板型编译：

```powershell
arduino-cli compile --fqbn esp32:esp32:lilygo_t_display_s3 .
```

如果出现：

```text
LVGL is enabled. Install LVGL 9.5.0 or build with HEXWALLET_ENABLE_LVGL=0.
```

说明 LVGL 依赖不存在，先安装依赖，或按上一节关闭 LVGL。不要通过删除 `WalletConfig.h` 中的错误检查来绕过依赖。

### 推荐编译选项

生产测试建议保持：

```text
HEXWALLET_RUN_SELF_TESTS=1
HEXWALLET_ENABLE_SECRET_EXPORT=0
HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION=0
```

不要为了让程序启动而关闭自检，也不要在没有可信显示器时打开 `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION`。

## 刷写固件和打开串口

假设串口为 `COM7`，实际端口请替换：

```powershell
arduino-cli upload `
  -p COM7 `
  --fqbn esp32:esp32:lilygo_t_display_s3 `
  .
```

如果上传失败：

1. 关闭 Arduino IDE、串口监视器和其他占用 COM 口的程序。
2. 按住 BOOT，再按一下 RESET，然后重新上传。
3. 确认设备管理器中的端口没有变化。
4. 确认选择了正确的 FQBN。
5. 确认 USB 线支持数据传输。

使用 Arduino CLI 打开串口监视器：

```powershell
arduino-cli monitor -p COM7 -c baudrate=115200
```

串口参数：

- 波特率：`115200`。
- 换行：`LF` 或 `CRLF` 都可以；固件会忽略 `CR`。
- 每次只发送一条命令，并以换行结束。
- 不要把串口日志公开上传，其中可能包含地址、交易数据或认证失败信息。

## 启动自检

启动后先等待自检完成。成功输出应类似：

```text
SELFTEST crypto=pass cryptonote=pass evm=pass bip39=pass bip32=pass address=pass networks=pass tokens=pass transport=pass bitcoin=pass
```

只有所有项目都是 `pass`，钱包服务才会初始化。任何一项失败都会输出：

```text
FATAL: cryptographic self-test failed; wallet services disabled
```

此时不要继续生成钱包或签名，应保存完整日志并修复失败项。

如果 BIP32 失败，固件可能额外输出 `BIP32_DETAIL` 阶段状态；它不会输出密钥材料。

## CLI 的状态模型

CLI 有四个需要区分的状态：

| 状态 | 含义 |
| --- | --- |
| 未配置认证 | NVS 中没有有效的 PIN verifier，必须执行 `auth provision` |
| 已配置但未解锁 | 可以查询公开目录，但钱包和签名命令返回 `ERR locked` |
| 已认证但钱包为空 | 可以执行钱包命令，但地址命令返回 `ERR wallet-empty` |
| 已认证且钱包已加载 | 可以执行地址查询和允许的交易审查流程 |

锁定状态下可以执行：

```text
help
status
coin list
coin search <text>
coin show <id>
token list
token list <network>
token show <id>
```

认证后才可以执行：

```text
wallet generate
wallet import <24-word-mnemonic>
wallet address <id> [index]
wallet token <token-id> [index]
wallet addresses [index]
tx inspect <psbt-v0-hex>
tx sign <six-digit-confirmation>
evm inspect <network> <index> <unsigned-rlp-hex>
evm sign <six-digit-confirmation>
tx reject
selftest
```

## 首次配置认证

查看当前状态：

```text
status
```

未配置时通常显示：

```text
OK provisioned=no authenticated=no display=absent wallet=empty pending-tx=no
```

已配置但未解锁时通常显示：

```text
OK provisioned=yes authenticated=no display=absent wallet=empty pending-tx=no
```

仅在 `provisioned=no` 时配置 PIN：

```text
auth provision <PIN> <PIN>
```

当前策略：

- 长度为 8 到 64 个字符。
- 两次输入必须完全一致。
- PIN 不应包含空格，因为 CLI 按空格分割参数。
- 固件保存随机 salt 和 PBKDF2 verifier，不保存明文 PIN。
- 配置成功不会自动解锁，必须继续执行 challenge-response。

成功输出：

```text
OK provisioned; run auth begin and auth unlock <proof-hex>
```

已经是 `provisioned=yes` 时不要重复配置，直接进入解锁流程。

## 计算认证 proof

获取一次性 challenge：

```text
auth begin
```

典型格式：

```text
OK challenge salt=<32-hex-chars> iterations=120000 nonce=<64-hex-chars>
```

proof 的精确定义：

```text
verifier = PBKDF2-HMAC-SHA256(PIN, salt, iterations, 32 bytes)
proof = HMAC-SHA256(verifier, nonce)
```

最后把 32 字节 proof 编码成 64 个小写十六进制字符，再执行：

```text
auth unlock <proof-hex>
```

### Windows PowerShell 示例

下面脚本使用交互式输入，不把 PIN 写入命令行历史。只在可信、离线的管理主机上执行：

```powershell
function Convert-HexToBytes([string] $Hex) {
    if ([string]::IsNullOrWhiteSpace($Hex) -or
        ($Hex.Length % 2) -ne 0 -or
        $Hex -notmatch '^[0-9a-fA-F]+$') {
        throw 'Invalid hexadecimal input'
    }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return $bytes
}

$pin = Read-Host 'PIN'
$saltHex = Read-Host 'salt hex'
$iterations = [int](Read-Host 'iterations')
$nonceHex = Read-Host 'nonce hex'

$salt = Convert-HexToBytes $saltHex
$nonce = Convert-HexToBytes $nonceHex
$password = [System.Text.Encoding]::UTF8.GetBytes($pin)
$kdf = $null
$hmac = $null

try {
    $kdf = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $password, $salt, $iterations,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $verifier = $kdf.GetBytes(32)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($verifier)
    $proof = $hmac.ComputeHash($nonce)
    -join ($proof | ForEach-Object { $_.ToString('x2') })
}
finally {
    if ($hmac -ne $null) { $hmac.Dispose() }
    if ($kdf -ne $null) { $kdf.Dispose() }
    [Array]::Clear($password, 0, $password.Length)
    $pin = $null
}
```

把脚本输出的 64 个十六进制字符发送为 `auth unlock` 参数。不要保存 PIN、verifier、proof 或完整串口日志。

## 解锁会话

完整顺序：

```text
status
auth begin
auth unlock <proof-hex>
wallet generate
```

成功解锁会输出：

```text
OK unlocked
```

认证失败会记录次数并执行指数退避，最大退避约 10 分钟。失败后重新执行 `auth begin` 获取新 nonce，不要重复使用旧 proof。

## 生成和导入钱包

### 生成钱包

认证后执行：

```text
wallet generate
```

成功输出：

```text
OK wallet-generated-in-volatile-memory
```

该命令不会把助记词打印到串口，原因是串口日志可能被终端软件或主机保存。当前生成钱包只存在 RAM：

- 不写入 NVS。
- 重启、复位、锁定或会话超时后消失。
- 默认没有安全的助记词导出路径。
- 没有可信显示器和可靠备份流程时，不应转入真实资产。

### 导入钱包

认证后可以导入已有英文 BIP39 助记词：

```text
wallet import word1 word2 word3 ... word24
```

注意：

- 助记词会经过串口输入，终端可能记录完整内容。
- 当前钱包使用空 BIP39 passphrase 派生 seed。
- 错误输入会返回 `ERR import invalid-mnemonic` 或其他错误。
- 导入成功后仍只存在 RAM 中。

成功输出：

```text
OK wallet-imported-in-volatile-memory
```

## 查询网络和 Token

查看网络目录：

```text
coin list
coin search ethereum
coin search bitcoin
coin show eth
coin show btc
coin show xmr
```

每行的 `id` 用于 CLI，`slip44` 是目录编号，`capabilities` 表示实际能力，`status` 表示限制。目录项不等于可签名网络。

查看 Token：

```text
token list
token list eth
token list matic
token show eth-usdc
token show matic-usdc
```

`asset` 是已登记的合约地址，`decimals` 是精度。Token 合约地址不是账户收款地址，使用前必须独立核对网络和合约。

## 生成地址

先认证并生成或导入钱包：

```text
wallet address btc 0
wallet address btc49 0
wallet address btc44 0
wallet address eth 0
wallet address bsc 0
wallet address xmr 0
wallet address trx 0
```

输出包含：

```text
network=eth symbol=ETH path=m/44'/60'/0'/0/0 address=0x...
```

查询下一个地址：

```text
wallet address eth 1
wallet address btc 1
```

当前账户和 change 固定为 `0`，一般路径为：

```text
m/<purpose>'/<coin-type>'/0'/0/<index>
```

EVM 网络通常使用 coin type `60`，Ethereum Classic 使用 `61`。修改派生策略会改变地址，已有资金必须记录实际路径。

查询所有已实现网络：

```text
wallet addresses 0
```

查询 Token 账户地址：

```text
wallet token eth-usdc 0
wallet token matic-usdc 0
wallet token arb-usdc 0
```

ERC-20 Token 使用所属 EVM 网络的同一个账户地址，不要把 Token 合约地址当作收款账户地址。

## Bitcoin PSBT 审查和签名

前置条件：

- 已认证并加载钱包。
- 输入是十六进制 PSBT v0。
- 网络为 Bitcoin mainnet。
- 输入属于支持的 BIP49 或 BIP84 地址。
- 交易满足金额、费率、输入输出和 `SIGHASH_ALL` 限制。
- 默认需要可信显示器。

审查：

```text
tx inspect <psbt-v0-hex>
```

审查输出会包含输入总额、输出金额、地址、wallet/change/external 归属、review ID 和一次性确认码。必须在可信显示器上核对地址、找零、金额、手续费和网络，不能只检查 review ID。

确认：

```text
tx sign <six-digit-confirmation>
```

拒绝：

```text
tx reject
```

确认码默认约 120 秒有效。错误、过期或不匹配都会清除待签名交易。没有可信显示器时默认返回：

```text
ERR trusted-display-required-for-signing
```

不要为了绕过该错误而打开 `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION`。

## EVM 交易审查和签名

当前只接受已登记网络上的 EIP-155 legacy、EIP-1559 type-2 原生转账，以及已登记 ERC-20 的精确 `transfer(address,uint256)`。任意 calldata、合约创建、未知合约、非空 access list 和未实现 typed transaction 会被拒绝。

审查 unsigned RLP：

```text
evm inspect eth 0 <unsigned-rlp-hex>
evm inspect bsc 0 <unsigned-rlp-hex>
evm inspect matic 1 <unsigned-rlp-hex>
```

`index` 是钱包地址索引，不是 nonce。审查输出包括 from、recipient、asset、amount、contract、nonce、gas limit、maximum fee 和 review ID。必须核对所有字段及网络 chain ID。

确认：

```text
evm sign <six-digit-confirmation>
```

成功输出：

```text
OK signed-transaction=<hex>
tx-hash=0x<keccak256>
```

确认码默认约 120 秒有效，只对应最近一次审查。任何失败都会清除待签名交易，必须重新 `evm inspect`。

## 锁定、超时和清除

立即锁定：

```text
lock
```

锁定会清除认证状态、challenge、待签名交易、确认码和 RAM 中的助记词。默认会话超时为 5 分钟，由 `HEXWALLET_CLI_SESSION_TIMEOUT_MS` 控制。重启和断电也会清除 RAM 钱包。

超时输出：

```text
INFO session-expired-and-wallet-cleared
```

超时后必须重新认证，并重新生成或导入钱包。

## 完整操作示例

首次初始化：

```text
status
auth provision <PIN> <PIN>
auth begin
auth unlock <proof-hex>
status
```

导入钱包并查询地址：

```text
wallet import <24-word-mnemonic>
wallet address btc 0
wallet address eth 0
wallet token eth-usdc 0
```

测试生成路径：

```text
lock
auth begin
auth unlock <proof-hex>
wallet generate
status
```

生成的助记词不会显示，锁定后会永久丢失。不要在没有可靠备份和恢复验证的情况下向该钱包转入资金。

运行认证后的自检：

```text
selftest
```

任何 `FAIL` 都表示不能继续密钥操作或签名。

## 常见错误

| 输出 | 原因 | 处理 |
| --- | --- | --- |
| `ERR locked` | 未完成认证 | 执行 `auth begin`、计算 proof、执行 `auth unlock` |
| `ERR not-provisioned` | 尚未配置 PIN | 执行 `auth provision <PIN> <PIN>` |
| `ERR already-provisioned` | 已配置 PIN | 不要重复配置，直接解锁 |
| `ERR challenge-required` | 没有有效 challenge | 重新执行 `auth begin` |
| `ERR authentication-failed` | proof 错误或 challenge 失效 | 等待 backoff，获取新 challenge |
| `ERR wallet-empty` | RAM 中没有钱包 | 执行 `wallet generate` 或 `wallet import` |
| `ERR trusted-display-required-for-signing` | 没有可信显示器 | 连接并正确适配显示器 |
| `ERR invalid-index` | 索引无效 | 使用非强化索引范围内的十进制数 |
| `ERR unknown-coin` | 网络 ID 不存在 | 先执行 `coin list` |
| `ERR address-unsupported` | 网络没有地址实现 | 查看 `coin show <id>` |
| `ERR unknown-token` | Token 不在登记表 | 先执行 `token list` |
| `ERR invalid-evm-transaction-hex` | unsigned RLP 非法 | 使用连续、不带 `0x` 的十六进制 |
| `ERR no-reviewed-evm-transaction` | 没有待确认审查结果 | 先执行 `evm inspect` |
| `ERR line-too-long` | 命令超过缓冲区 | 检查 PSBT/交易大小限制 |
| `FATAL: cryptographic self-test failed` | 启动自检失败 | 保存完整日志并修复失败模块 |

如果看到乱码，检查波特率 `115200`、终端 UTF-8、正确 USB CDC 端口，并关闭其他串口监视器。

如果 `wallet generate` 返回 `ERR locked`，这是预期的安全行为，正确顺序是：

```text
auth begin
auth unlock <proof-hex>
wallet generate
```

## 安全边界

- 不要把 PIN、助记词、seed、私钥、xprv、proof 或完整串口日志提交到 Git。
- 不要在公共电脑、远程桌面录屏、云同步终端或共享串口上执行 `wallet import`。
- 不要把 `wallet generate` 的成功输出理解为助记词已备份。
- 不要通过关闭 `HEXWALLET_RUN_SELF_TESTS` 解决自检错误。
- 不要通过打开 `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION` 绕过可信显示器要求。
- 不要向只有 `address` 能力的网络发送交易。
- 不要把 Token 合约地址当作账户收款地址。
- 编译通过和自检通过都不等于生产安全认证。
- 使用真实资产前，必须完成板级测试、恢复测试、故障注入、固件升级保护、Secure Boot、Flash Encryption、可信显示器和独立安全审计。

## 项目结构

| 模块 | 责任 |
| --- | --- |
| `WalletSecurity` | BIP39、BIP32、secp256k1、KDF、敏感数据清零 |
| `CryptoPrimitives` | SHA、HMAC、PBKDF2、Hash160、Keccak |
| `WalletSession` | RAM 中的助记词会话 |
| `WalletCli` | 认证状态、串口命令、审查和确认流程 |
| `WalletEngine` | 派生路径和地址生成 |
| `WalletNetworks` | 网络、派生类型、地址编码、EVM chain ID |
| `WalletTokens` | 已登记 Token、合约地址、精度和能力 |
| `BitcoinTransaction` | PSBT v0 解析、审查、BIP143 签名 |
| `EvmTransaction` | EIP-155、EIP-1559、原生转账和登记 ERC-20 |
| `WalletBoardPort` | 板级显示器、输入和电源适配 |
| `WalletTransportPolicy` | Serial、BLE、Wi-Fi 的 fail-closed 策略 |

## 许可证

许可证和使用限制以仓库中的 `LICENSE` 为准。当前项目不应被当作已完成安全认证的商业硬件钱包使用。
