# 主机测试

固件的密码学在接触硬件之前必须先被证明正确。验证体系分三层。

## 1. MSVC 主机自测套件

`tests/host/build.ps1` 用 MSVC `cl.exe` 编译每个固件 `.cpp`，头文件使用
**ESP32 Arduino core 自带的 mbedtls 头文件**（与设备构建完全一致），
链接 `tests/host/mbedtls_host.c` 运行时 shim 后运行 `host_test.exe`。

```text
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
```

期望输出：

```text
extended-crypto=pass
alt-addresses=pass
```

`mbedtls_host.c` shim 实现了固件用到的 mbedtls 子集（SHA-256/512、HMAC、
PBKDF2、64 位 limb 大数及 `mod_mpi`/`inv_mod`/`exp_mod`），目的是让 API
面与设备一致，而无需真实设备。

### 注意事项

- 重建前先结束并删除 `host_test.exe`（和 `diag.exe`），否则链接器报
  "另一个程序正在使用此文件"，并可能运行**过期二进制**——它会在你面前
  静默撒谎。过期二进制曾让我们"修复"一个并不存在的 bug。
- 输出通过 `cmd /c "… > %TEMP%\file.txt 2>&1"` 读取；PowerShell 的
  `2>nul` 会被误解析为设备重定向。

## 2. 独立 Python oracle

`CryptoExtended.cpp`/`BlsG1.cpp` 的结果与纯 Python 实现（`sha256`/`hmac`
+ 任意精度整数，无外部加密库）交叉校验：

- 官方 ERC-2333 Test Case 0（主私钥、Lamport 公钥、子私钥）；
- `bls pk(sk=1)`；
- Chia `v0` / `ones` / 16 字节种子地址及派生公钥。

两边都与**官方**向量一致才是最终真相；当 C++ 与（首个有 bug 的）Python
不一致时，C++ 是对的，Python 漏了 `IKM ‖ 0x00`、salt 循环、单次
HKDF-Lamport 这几步。

## 3. 设备端编译检查

`tests/host/device_compile_check.ps1` 用 ESP32 **Xtensa g++**
（`esp-x32` 工具链）配合精选的 ESP-IDF include 集合编译每个纯 C++ 固件
源文件，在烧录前捕获 32 位专属假设。

```text
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1
# 期望：DEVICE COMPILE: all sources OK
```

需要 `Arduino.h` + ESP-IDF（如 `WalletSecurity.cpp` → `esp_fill_random`）
或 LVGL 配置的文件由 CI 的 `arduino-cli` 构建负责。Xtensa g++ 的
`@file` 响应文件处理会弄坏带反斜杠的 `-I` 路径，所以 include 参数直接传递。

## 4. 板级端口编译检查（所有板卡配置）

`tests/host/board_port_compile_check.ps1` 针对**每一个支持的板卡配置**
（AMOLED、AMOLED Plus、T-Display S3、T-Deck Max、T-Echo Lite）用 Xtensa
工具链编译 `WalletBoardPort.cpp` 与 `WalletUi.cpp`。`tests/host/mock/`
用一套小而确定的表面遮蔽 `Arduino.h`、`SPI.h`、`Wire.h` 与 `lvgl.h`
（`soc/` 提供 ESP32-S3 寄存器宏），从而在主机上完成驱动语法与 LVGL API
用法的类型检查，无需引入完整的 ESP-IDF 依赖图。

```text
powershell -ExecutionPolicy Bypass -File tests/host/board_port_compile_check.ps1
# 期望：BOARD PORT COMPILE: all boards OK
```

寄存器名与真实 Arduino/LVGL API 由 CI 的 `arduino-cli` 固件构建负责验证；
mock 只用于廉价、确定地捕获驱动层错误。

## 5. 优化器差异检查（clang-cl）

`tests/host/build_clang_ubsan.ps1` 用 **clang-cl**（VS 自带 LLVM）以相同
源文件重新构建 `host_test_clang.exe` 并运行。不同优化器对 C/C++ **未定义
行为**的处理不一致：MSVC 经常"侥幸"产出正确结果，而 clang 会暴露它。
只要两份输出不一致，就说明代码里有 UB——哪怕 MSVC 全绿。

```text
powershell -ExecutionPolicy Bypass -File tests/host/build_clang_ubsan.ps1
# 期望：extended-crypto=pass / alt-addresses=pass
```

历史教训：`mbedtls_host.c` 的 `sha512_finish` 曾用 `bits >> (120 - i*8)`
编码 128 位长度——对 64 位计数器移位 ≥ 64 是 UB，clang 把长度高半填充成
垃圾字节，导致 SHA-512 输出错误，进而让 Ed25519 TC1 公钥/签名与 SLIP-10
派生在 CI 的 MSVC 上偶发失败（本地 MSVC 版本恰好掩码了移位量而通过）。
修复：长度高半恒为零，只写低 8 字节（`len[i+8] = bits >> (56 - i*8)`）。
同源问题：`Ed25519.cpp` 进位链对负数左移（`carry << 26`）也是 UB，改为
`carry * (1 << 26)`。

因此本工具是**加密代码的必检关卡**：任何涉及移位/符号/溢出敏感代码的
改动，都应同时通过 MSVC 与 clang-cl 两份构建。

## CI

`.github/workflows/ci.yml`：

- **host-tests**（windows）：安装 `arduino-cli` 1.5.1（使用带版本的资产
  URL，裸 `latest` 别名会 404），安装 `esp32:esp32@3.3.10`，把
  `HEXWALLET_ESP32_LIBS` 指向自带的 mbedtls 头文件，依次运行
  `build.ps1`、`device_compile_check.ps1`、`board_port_compile_check.ps1`。
- **firmware-build**（ubuntu）：完整 `arduino-cli compile --fqbn
  esp32:esp32:esp32s3` 并带 LVGL 9.5.0。

`build.ps1` / `build_diag.ps1` 读取 `HEXWALLET_ESP32_LIBS`
（`esp32-libs` 工具的 `include\mbedtls` 目录），否则回退到本地
Arduino15 默认路径。
