# HexWallet CLI 使用与构建指南

> 当前版本尚未完成生产验收，XMR/MSR 完整收发未实现。验证结果与未完成项见 [AUDIT.md](AUDIT.md)；Arduino 目录说明见 [docs/arduino-layout.md](docs/arduino-layout.md)。

HexWallet 是运行在 ESP32-S3 上的离线钱包固件基础工程。它提供 BIP39/BIP32 密钥派生、地址生成、受限的 Bitcoin PSBT 审查、受限的 EVM 交易审查，以及经过认证的 USB 串口 CLI。

本文档以实际源码中的命令和安全策略为准，目标是让你可以从编译、刷写、打开串口，到完成认证、生成或导入钱包、查询地址和执行交易审查。命令必须逐行发送，并以换行结束。

> 重要：当前工程仍是 Beta 固件，不是经过独立审计的生产级硬件钱包。钱包只保存在 RAM 中，设备重启、复位、锁定或会话超时都会清除钱包。不要在未经硬件适配、安全审计、Secure Boot、Flash Encryption、可信显示器和恢复流程验证的情况下存放真实资产。

## 目录

1. [功能边界](#功能边界)
2. [手机 App 连接（NFC / USB）](#手机-app-连接nfc--usb)
3. [硬件和软件要求](#硬件和软件要求)
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
- 为 Bitcoin 系、45 个 EVM 网络、Kaspa 和 Zcash transparent 生成地址；只有这些链会出现在钱包目录中。
- 显式的安全芯片托管策略 `WalletCustody`：SE050C1H1 目标只声明 secp256k1 + ECDSA + seed 封装能力（SCP03/applet 驱动尚未实现）；Kaspa Schnorr 和 Ed25519/BLS/XMSS 私钥保留在 MCU RAM。
- 查询已登记 EVM Token 的合约地址、精度和账户地址。
- 审查并签名受限的 Bitcoin PSBT v0。
- 审查并签名 Zcash Overwinter/Sapling v4 透明交易（t1 P2PKH 输入、t1/t3 输出）：`zec inspect <ZEC4-payload-hex>` / `zec sign <code>`，ZIP-243 BLAKE2b-256 摘要、主网 NU6.2 分支 ID `0x5437f330`、`SIGHASH_ALL`。屏蔽交易、JoinSplit、v3/v5 和带已有 scriptSig 的请求一律拒绝；官方 ZIP-243 透明测试向量在启动自检中校验。
- 审查并签名已登记 EVM 网络上的原生转账，以及白名单内的 ERC-20/721/1155/4626/777/3525/6551/OFT/ONFT 调用。选择器由固件用 Keccak-256 现场重算；ABI 必须严格符合规范偏移，未知选择器、非规范偏移、无法审阅的嵌套批量调用和未登记的 ERC-20 合约一律拒绝。

以下能力明确不可用，也不会出现在钱包目录中：

- Monero/Masari 交易签名：CryptoNote 地址层与 RingCT key 层（hash-to-scalar、key derivation、一次性公钥、key image、view tag）已实现并固定 Monero 官方向量；CLSAG 签名/验证和篡改拒绝已实现并自测，但 Bulletproofs+、ECDH 金额编码、decoy 选择和完整交易序列化尚未完成。CLSAG 还没有固定到外部 Monero 交易向量，因此不进入钱包目录。
- Ergo、Hathor、Quai、Chia、QRL、Solana、Cardano、Cosmos、Algorand、Tezos、Filecoin、XRP、TRON 的交易签名。
- Zcash shielded、JoinSplit、v3/v5，以及 t3 P2SH 花费。
- Peercoin 交易签名：PPC v<3 交易在版本号后序列化 `nTime`，Bitcoin legacy 签名器会构造无效交易；在独立的 Peercoin sighash 模块和向量完成前，PPC 只作为内部地址原语，不进入钱包目录。
- Kaspa v1 计算预算/covenant 交易；v0 的 `kaspa inspect` / `kaspa sign` 已实现。
- 任意 EVM calldata、合约创建、未知 Token、非标准 typed transaction、非空 access list。
- 默认配置下的助记词、seed、私钥和 xprv 导出。

严格规则：只有同时具备地址、审查、签名、官方/独立向量和失败路径的链才会进入 `WalletCatalog`。仅地址 profile 只作为内部测试数据存在，不是钱包。

### 关于“支持所有币”

BIP39 社区列表和 miningpoolstats 都不是协议规范：其中包含大量已停止维护的分叉、只有区块浏览器而无地址规范的币种。HexWallet 不会用猜测填表。一个币种进入“可签名”集合的前提是：有独立参考向量的地址编码、明确的派生策略、固件实际可实现的签名算法，以及对应的托管策略。同一地址族（base58 版本、EVM chain ID、SLIP-0010、CryptoNote、XMSS）只需增加数据和一组向量，不需要新增密码学实现；没有可验证向量的币种不会进入钱包目录，只在 `tools/fork_registry.json` 和内部 profile 中保留地址原语，绝不会生成带签名的假钱包。

`tools/fork_registry.json` 保留 104 行有官方来源或仍在 MiningPoolStats 活跃列表中的 Bitcoin 系参数，生成 130 个内部 profile；`WalletForkCatalog.inc` 只暴露其中 82 个同时通过地址来源核对和 legacy sighash 审计的 profile。其余 profile 仍用于地址向量测试，但不是用户钱包。`WalletForkAddressVectors.inc` 用独立的 base58check/hash160 固定了 97 个 P2PKH 向量。`python tools/verify_utxo_sighash.py` 逐个读取上游 `chainparams.cpp`、`script/interpreter.cpp` 和 `primitives/transaction.h`：base58 版本不一致、存在活动 fork-id 代码、legacy serializer 写入 `nTime`、交易头额外序列化 `nTime`、或使用宽 `nType` 的链一律不进入签名目录；Ravencoin Classic（fork-id）、TrezarCoin/PulsarCoin/DeepOnion/Verge（`nTime` sighash）因此只保留内部地址 profile。运行 `python tools/generate_fork_profiles.py` 重新生成 profile、catalog、签名策略和向量。`run_network_profile_self_tests()` 会跑通每一条编码器和这些向量；首次收款前仍应使用该币种自己的参考钱包核对地址。

没有 SLIP-0044 coin type、可读官方 chainparams 或受支持地址编码的币种已从钱包删除，不再生成占位目录项。重新加入必须附官方证据，不能猜 version byte。

`tools/build_utxo_candidates.py` 会抓取每个 MiningPoolStats 币页面的官方 GitHub 仓库，解析主网 `chainparams.cpp`，拒绝 CashAddr、Zcash、fork-id 和多字节前缀，再与 SLIP-0044 匹配。候选只写入 `tools/utxo_candidates.json`，不会直接进入钱包：必须先通过 `tools/verify_utxo_sighash.py` 的地址版本和 sighash 审计，再人工确认派生路径、费用上限和托管策略。

`python tools/miningpool_coverage.py` 拉取 MiningPoolStats 当前列表，按 ASIC/GPU/CPU/HDD 统计固件已支持的行数与缺口；它只审计，不把尚未实现的币写进钱包。当前审计：**518 个活跃条目中支持 111 个**（ASIC 62/212，GPU 30/181，CPU 19/121，HDD 0/4）。缺口是显式的，不用占位行伪装。

`python tools/generate_mining_catalog.py` 生成随固件发布的 `WalletMiningCatalog.inc`，只保留能解析到完整签名钱包的行。未支持条目保留在 `tools/miningpoolstats_coin_list.json` 供后续按家族扩展，不进入固件。CLI 提供 `mining stats`、`mining list [ASIC|GPU|CPU|HDD] [offset]` 和 `mining show <symbol>`。

### SE050 托管边界

`WalletCustody` 把“哪些密钥能放进安全芯片”写成代码，而不是宣传语。默认的活动配置是纯 MCU；`wallet custody <id>` 会先打印 SE050 I2C 探测结果（`not-configured`、`no-response`、`present-unverified`）。只有在板级移植建立 SCP03 并认证 applet 后调用 `set_active_secure_element_profile()`，才会显示 secp256k1/ECDSA 可以由 SE 托管；仅检测到 0x48 有器件不会启用“密钥在 SE 内”的声明。保守的 SE050C1H1 目标配置只声明 secp256k1、ECDSA 和 seed 封装：BIP32 派生仍在 MCU 完成，secp256k1 子密钥经 SCP03 导入后可以留在 applet 内做 ECDSA。Kaspa 的 BIP340 Schnorr 以及内部保留的 Ed25519/BLS/XMSS 原语都不是 SE050 原语，私钥只能在 MCU RAM 中派生并在使用后清零。需要解密到 RAM 的 seed 只受 MCU 保护；SE 提升的是静态密钥和 ECDSA 隔离，不等于“所有私钥都由 SE050 保护”。

## 手机 App 连接（NFC / USB）

HexWallet 的“发送”由手机发起：手机构造未签名交易，硬件钱包只做**审阅 + 授权 + 签名**，然后把已签名字节交回手机广播。设备不联网，也不保存交易。完整线格式见 [docs/phone-link-protocol.md](docs/phone-link-protocol.md)，手机端参考实现见 `tools/phone_link_reference.py`。

- **接收**：手机通过链路调用 `ADDRESS`，设备派生并返回地址（仅公钥/地址，不含私钥）。
- **发送**：手机调用 `BEGIN_SIGN` → 设备解析并校验（输入归属、找零派生、手续费上限、合约白名单）→ 在可信屏幕显示收款地址/金额/手续费并给出 `APPROVE` / `REJECT` 按钮 → 用户按键后，手机再次调用 `RESULT` 取回签名。
- **配对**：首次连接在设备屏幕显示 6 位配对码与手机指纹，必须现场确认。手机公钥被固定，之后换成其他手机一律拒绝。
- **链路保护**：握手是 Ed25519 双向签名 + 临时 ECDH（HKDF-SHA256 派生会话密钥）；每帧 ChaCha20 加密 + HMAC-SHA256 认证，并带单调递增序号。伪造、重放、乱序、篡改都会失败并销毁会话。
- **USB 默认关闭**：只有长按 BOOT/用户按键 3 秒才开启（默认 10 分钟窗口），再次长按、超时、上锁都会关闭；关闭时丢弃一切串口输入。
- **NFC**：PN7161（NCI 2.0）ISO-DEP 卡模拟，手机作为读卡器。引脚必须来自原理图，在板级 profile 中定义 `HEXWALLET_NFC_PN7161` 与 `HEXWALLET_NFC_PIN_*`；未定义时 `link status` 显示 `nfc=not-configured`，固件不会猜测引脚。该驱动尚未在实机上做射频一致性验证。
- **无显示屏的板子**：不提供签名审阅，链路会返回 `unsupported`，不会退化成“主机确认”。

CLI 辅助命令（需解锁）：

```text
link status          # link/nfc/usb-data 状态
link pair confirm    # 等价于在屏幕上按 APPROVE（无屏幕调试用）
link pair reject
```

## 硬件和软件要求

### 硬件

- ESP32-S3 开发板。
- USB 数据线，而不是只能充电的 USB 线。
- 能够识别串口的 Windows、Linux 或 macOS 主机。
- 进行交易签名时，必须使用已经正确适配的可信显示器；没有可信显示器时，默认策略会拒绝签名。

`ESP32-S3N8` 只表示芯片和 Flash/PSRAM 配置，不等于具体的开发板型号。支持的板卡在 `WalletBoardPins.h` 中声明（引脚取自官方 LilyGO 引脚图和工厂代码），`WalletBoardPort.cpp` 实现了 RM67162 SPI、ST7789 8 位并行与 GxEPD2 电子纸三套真实驱动；选择不支持的板型或缺少 GxEPD2 时会明确报错并 fail-closed。

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

本仓库验证的编译目标是 ESP32 core 3.3.10 + FQBN `esp32:esp32:esp32s3` + LVGL 9.5.0。目标板卡通过 `WalletConfig.h` 里的 `HEXWALLET_BOARD` 在编译期选择：

| `HEXWALLET_BOARD` | 板卡 | 面板 | 控制器 | 接口 | 分辨率 |
| --- | --- | --- | --- | --- | --- |
| `HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED`（默认） | T-Display S3 AMOLED | RM67162 | RM67162 | SPI | 240×536 |
| `HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED_PLUS` | T-Display S3 AMOLED Plus | RM67162 | RM67162 | SPI | 240×536 |
| `HEXWALLET_BOARD_T_DISPLAY_S3` | T-Display S3 | ST7789 | ST7789 | 8 位并行 | 170×320 |
| `HEXWALLET_BOARD_T_DECK_MAX` | T-Deck Max | GDEQ031T10 | UC8253 | SPI（电子纸） | 240×320 |
| `HEXWALLET_BOARD_T_ECHO_LITE` | T-Echo Lite Kit | 电子纸 | — | SPI（电子纸） | 176×192 |

引脚定义在 `WalletBoardPins.h`，取自官方 LilyGO 引脚图与工厂代码；RM67162 与 ST7789 的初始化序列与官方驱动逐字节一致。选择具体板卡：

```powershell
arduino-cli compile `
  --fqbn esp32:esp32:esp32s3 `
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_BOARD=3 `
  --build-property compiler.c.extra_flags=-DHEXWALLET_BOARD=3 `
  .
```

`HEXWALLET_BOARD=3` 对应 T-Display S3，取值见 `WalletConfig.h`。通用 ESP32-S3 开发板用 `esp32:esp32:esp32s3`，具体以 `arduino-cli board list` 和板卡资料为准。

### CLI-only 编译

没有 LVGL 或暂时只验证串口 CLI 时，关闭 LVGL 编译：

```powershell
arduino-cli compile `
  --fqbn esp32:esp32:esp32s3 `
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_ENABLE_LVGL=0 `
  --build-property compiler.c.extra_flags=-DHEXWALLET_ENABLE_LVGL=0 `
  .
```

编译成功不代表显示器、触摸、供电和签名安全链路已经验证通过。CLI-only 构建可以用于地址和协议测试，但没有可信显示器时默认不能签名。

### 启用 LVGL 编译

安装并确认 LVGL 9.5.0 后，使用实际板型编译：

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32s3 .
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
  --fqbn esp32:esp32:esp32s3 `
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
SELFTEST crypto=pass extended=pass cryptonote=pass cryptonote-ringct=pass qrl=pass custody=pass catalog=pass evm=pass bip39=pass bip32=pass bip84=pass evm-derive=pass bip340=pass address=pass networks=pass sighash=pass kaspa=pass calldata=pass tokens=pass transport=pass bitcoin=pass zcash-sighash=pass zcash=pass
```

`evm-derive` 使用 Conflux 官方 Ledger app 的 `m/44'/503'/0'/0/0` 向量，同时校验未压缩公钥和 `0x` 地址；host 侧 `address` 自检会用同一公钥独立重算地址。

`cryptonote-ringct` 固定 Monero `tests/crypto/tests.txt` 的 hash_to_scalar、generate_key_derivation、derive_public_key、derive_secret_key、generate_key_image 和 derive_view_tag 向量。CLSAG 另有 3 成员确定性环的签名/验证与 `s`、`I`、message 篡改拒绝自测；它仍需要外部 Monero 交易向量才能在钱包目录中启用。

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
tx inspect [<coin>] <psbt-v0-hex>
tx sign <six-digit-confirmation>
evm inspect <network> <index> <unsigned-rlp-hex>
evm sign <six-digit-confirmation>
zec inspect <ZEC4-payload-hex>
zec sign <six-digit-confirmation>
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
wallet address zec 0
wallet address kas 0
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

钱包目录现在只暴露完整收/发/签名链。Monero、QRL、Chia 等仅地址 profile 不再出现在 `coin list` / `wallet address` 中；它们的编码器只作为内部测试原语保留。

当前账户和 change 固定为 `0`，一般路径为：

```text
m/<purpose>'/<coin-type>'/0'/0/<index>
```

EVM 网络通常使用 coin type `60`，Ethereum Classic 使用 `61`，Conflux eSpace 按官方 Ledger app 使用 `503`。修改派生策略会改变地址，已有资金必须记录实际路径。

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
- 网络必须在 `kNetworkSigningPolicies` 中有显式签名策略行（Bitcoin、Litecoin、Dogecoin、Dash、DigiByte、Bitcoin Gold、Ravencoin、Namecoin、Vertcoin、Axe、BCH、eCash、BSV、Sugarchain、e-Gulden、LBRY、MazaCoin、Myriad、NewYorkCoin、Auroracoin、Bitcore、CPUchain、DigitalCoin、Einsteinium、Feathercoin、GoByte、Monacoin、Ritocoin、VIVO，以及各自的 SegWit profile）。生成器只接受带 `sighash_source`、且上游 `chainparams.cpp` 与 `script/interpreter.cpp` 已通过 `tools/verify_utxo_sighash.py` 核对的 `legacy` 行；fork-id 和 `nTime` sighash 链不会套用 Bitcoin legacy 签名。共享的 legacy/BIP143 算法由 Bitcoin 向量覆盖，但策略行不代表已经在对应主网广播验证。
- 输入属于该网络支持的 BIP44 P2PKH、BIP49 P2SH-P2WPKH 或 BIP84 P2WPKH 地址。
- legacy 输入必须带 `non_witness_utxo`，其 txid 会与 outpoint 校验。这是 BIP-174 的强制要求；缺少它，恶意 PSBT 可以伪造被花费金额，从而污染手续费审查。
- 交易满足金额、费率、输入输出和 sighash 限制（Bitcoin 系为 `SIGHASH_ALL`，BCH/eCash/BSV 为 `SIGHASH_FORKID`）。
- 默认需要可信显示器。

审查：

```text
tx inspect [<coin>] <psbt-v0-hex>
```

省略 `<coin>` 时按 Bitcoin 处理；其他链必须显式给出，例如 `tx inspect ltc <hex>`、`tx inspect bch <hex>`。审查首行会打印 `network=` 与实际使用的 sighash；BCH 类链的地址按 CashAddr 渲染，不会伪装成 base58。

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

## Kaspa 交易审查和签名

`kaspa inspect <payload-hex>` 使用紧凑的小端 review payload：`u16 version, u64 lock_time, u8 payload_len + payload, u8 input_count, {txid[32], u32 index, u64 sequence, u64 value, u16 script_version, u8 script_len + script, u32 account_index, u8 change, u32 address_index, u8 sigop_count}*, u8 output_count, {u64 value, u16 script_version, u8 script_len + script}*`。解析器先调用 `kaspa_review()` 计算输入/输出总额、手续费、KIP-0009 mass 和输出地址，再进入确认码流程；`kaspa sign <code>` 只接受 version 0，v1 计算预算/covenant 交易拒绝。签名输出是 gRPC `SubmitTransaction` 使用的 protobuf `TransactionMessage`。

## Zcash 透明交易审查和签名

`zec inspect <payload-hex>` 使用 `magic "ZEC4", u32 branch_id, u32 unsigned_transaction_size, unsigned_v4_transaction, u8 input_count, {u64 value, u8 script_len + scriptPubKey, u32 account, u8 change, u32 address_index}*`。交易必须是透明-only v4，且所有 scriptSig 为空；任何 valueBalance、shielded spend/output 或 JoinSplit 都会返回 `unsupported`，不会降级成“看起来像透明交易”的签名。`tools/build_zcash_review_payload.py` 可以从未签名 v4 交易生成该 payload，并为每个输入打印 ZIP-243 摘要，供独立实现交叉核对。

审查界面显示分支 ID、输入/输出总额、手续费、估计 vbytes、expiry height、lock time 和每个 t1/t3 输出地址。`zec sign <code>` 会从设备种子重新推导 `m/44'/133'/account'/change/index`，校验 prevout 的 P2PKH 哈希，再用 ZIP-243 摘要生成 ECDSA DER 签名并输出完整 v4 交易和 `txid`。签名只使用 `SIGHASH_ALL`；分支 ID 固定在 `WalletNetworks` 的主网 NU6.2 策略 `0x5437f330`，升级网络时必须发布新固件并补充官方向量，不能由主机任意指定。

## EVM 交易审查和签名

当前接受已登记网络上的 EIP-155 legacy、经链策略允许的 EIP-1559 type-2 原生转账，以及白名单内的 ERC-20/721/1155/4626/777/3525/6551/OFT/ONFT 调用。45 个 EVM profile 都支持 legacy；type-2 只对 `eth`、`matic`、`opt`、`arb1`、`base`、`avaxc`、`xdai`、`glmr`、`movr`、`cro`、`kava`、`core` 开放，ETC/BSC/Rootstock/Celo/Fantom/Conflux eSpace 保持 legacy-only。合约创建、未知选择器、非规范 ABI 偏移、未登记的 ERC-20 合约、非空 access list、ERC-1155 批量转移、ERC-6551 批量执行、ERC-721/1155/3525/777 的非空回调数据以及未实现 typed transaction 会被拒绝。OFT/ONFT 允许携带原生跨链费，但 `lzTokenFee` 必须为 0 且原生 value 不得低于 `nativeFee`；NFT 转移中的 `from`、金库的 `owner` 以及 `operatorSend` 的 from 必须等于本钱包地址（operator 是交易发送者，不是 calldata 参数）。

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

## Flash 分区、Secure OTA 与 eFuse

`partitions/hexwallet-16mb-ota.csv` 是 16 MB 布局：3 MB recovery、两个 5 MB OTA 槽、2.875 MB 资源分区。

| 分区 | 偏移 | 大小 | 用途 |
| --- | --- | --- | --- |
| `nvs` | `0x9000` | 24 KiB | PIN verifier、计数器、provisioned 标记 |
| `otadata` | `0xF000` | 8 KiB | 当前 OTA 槽与回滚状态 |
| `phy_init` | `0x11000` | 4 KiB | RF 校准（关闭 Wi-Fi/BLE 后不使用） |
| `recovery` | `0x20000` | 3 MiB | factory/recovery 镜像，OTA 不会覆盖 |
| `ota_0` | `0x320000` | 5 MiB | 稳定应用槽 |
| `ota_1` | `0x820000` | 5 MiB | 新固件暂存槽 |
| `storage` | `0xD20000` | 2.875 MiB | 资源、标签、只读数据 |

Arduino 构建时把该文件复制到 sketch 根目录并命名为 `partitions.csv`；ESP-IDF 构建设置 `CONFIG_PARTITION_TABLE_CUSTOM=y` 和 `CONFIG_PARTITION_TABLE_CUSTOM_FILENAME`。该表默认不启用：8 MB 的 S3 模块放不下两个 5 MB 槽，静默改分区会破坏已有设备的启动链。

安全更新顺序只有一个：写入非活动槽 → 校验镜像哈希/签名 → `esp_ota_set_boot_partition()` → 重启 → 新固件自检通过后才调用 `esp_ota_mark_app_valid_cancel_rollback()`；否则 bootloader 自动回滚。

- **Secure Boot v2** 把签名公钥摘要写进 eFuse，bootloader 拒绝无效签名镜像。私钥离线保存，eFuse 摘要不可逆。
- **Flash Encryption** release 模式为每台设备生成 eFuse AES 密钥；OTA 写入时由 bootloader 自行加密，所以服务器只发布**一份签名的明文镜像**，不需要为每台设备生成不同固件。
- development 模式可以重刷恢复，release 模式不能。签名私钥备份、recovery 镜像、回滚路径和产线 provisioning 没有在 sacrificial 模块上验证之前，不要烧 Secure Boot / Flash Encryption eFuse。烧错 eFuse 不能靠 OTA 救回。

ESP32-P4 没有 Wi-Fi/BLE，OTA 传输层是 USB-C 桌面工具或 NFC；这两个传输层当前都未实现，分区和回滚规则与传输层无关。

## 安全边界

- 不要把 PIN、助记词、seed、私钥、xprv、proof 或完整串口日志提交到 Git。
- 不要在公共电脑、远程桌面录屏、云同步终端或共享串口上执行 `wallet import`。
- 不要把 `wallet generate` 的成功输出理解为助记词已备份。
- 不要通过关闭 `HEXWALLET_RUN_SELF_TESTS` 解决自检错误。
- 不要通过打开 `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION` 绕过可信显示器要求。
- 不要绕过可信显示器审查，也不要在没有确认码的情况下签名。
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
| `WalletCatalog` | 严格钱包目录：只暴露完整收/发/签名链 |
| `WalletMiningCatalog` | 仅包含完整支持链的 MiningPoolStats 覆盖表 |
| `WalletTokens` | 已登记 EVM Token、合约地址、精度和能力 |
| `WalletUi` | 可信显示器的交易审查界面 |
| `WalletCustody` | MCU/SE 托管策略 |
| `BitcoinTransaction` | PSBT v0 解析（witness/non-witness UTXO）、审查、legacy/BIP143/fork-id sighash、最终序列化 |
| `ZcashTransaction` | v4 透明交易、ZIP-243、t1 签名、t1/t3 输出 |
| `CryptoNoteRingCt` | Monero hash-to-scalar、key derivation、一次性公钥、key image、view tag、CLSAG 签名/验证；key 层官方向量固定 |
| `CryptoNoteOutputScan` | 用 view secret 在设备内判定输出归属，不导出查看密钥 |
| `CryptoNoteTransaction` | RCT type 6 严格解析/逐字节重写 + 承诺平衡校验（尚不含 Bulletproofs+ 验证与 CLSAG 签名接入） |
| `WalletBoardPort` | 板卡配置（引脚、面板驱动、LVGL 缓冲、flush/触摸回调、供电时序） |
| `WalletBoardPins` | 全部五块受支持 LilyGO 板卡的逐引脚定义 |
| `EvmTransaction` | EIP-155、EIP-1559、原生转账和白名单 Token 调用 |
| `TokenCalldata` | ERC-20/721/1155/4626/777/3525/6551 与 LayerZero OFT/ONFT 的选择器白名单和规范 ABI 解码 |
| `WalletBoardPort` | 板级显示器、输入和电源适配 |
| `WalletLink` | 手机链路：配对、Ed25519 握手、会话、重放防护 |
| `WalletLinkCrypto` | 链路的 HKDF-SHA256、ChaCha20、Encrypt-then-MAC |
| `WalletNfcApdu` | 承载链路帧的 ISO 7816-4 APDU 应用 |
| `WalletNfcPort` | PN7161 NCI 卡模拟端口（需板级引脚） |
| `WalletLinkService` | 链路请求分发：地址、目录、开始签名、取签名 |
| `WalletSigning` | 设备内共享的“审阅 → 授权 → 签名”会话 |
| `WalletTransportPolicy` | Serial、NFC、BLE、Wi-Fi 的 fail-closed 策略 |

## 许可证

许可证和使用限制以仓库中的 `LICENSE` 为准。当前项目不应被当作已完成安全认证的商业硬件钱包使用。
