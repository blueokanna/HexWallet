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

`WalletEngine.cpp`、`EvmTransaction.cpp`、`BitcoinTransaction.cpp` 也在此
列表中——一次 `derive_address()` 签名重构曾静默破坏 `EvmTransaction.cpp`，
只有设备构建能抓到；因此任何能用精选 include 集编译的源都保留在此。需要
`Arduino.h` + 完整 ESP-IDF 图（如 `WalletSecurity.cpp` → `esp_fill_random`）
或 LVGL 配置的文件由 CI 的 `arduino-cli` 构建负责。Xtensa g++ 的
`@file` 响应文件处理会弄坏带反斜杠的 `-I` 路径，所以 include 参数直接传递。

## 4. 板级端口编译检查（所有板卡配置）

`tests/host/board_port_compile_check.ps1` 针对**每一个支持的板卡配置**
（AMOLED、AMOLED Plus、T-Display S3、T-Deck Max、T-Echo Lite）用 Xtensa
工具链和**真实 LVGL 9.5 检出**（`tests/host/lvgl_real` 或
`$env:HEXWALLET_LVGL_DIR`）编译 `WalletBoardPort.cpp` 与 `WalletUi.cpp`。
mock/ 目录只遮蔽 `Arduino.h`、`SPI.h`、`Wire.h` 与 ESP32-S3 寄存器宏
（`soc/`）；`lvgl.h` 本身始终来自真实源码树，因此检查永远不会对着过期的
API 表面验证。这一点很关键：LVGL 9.5 移除了 v8 时代的 `lv_disp_drv_t` /
`lv_indev_drv_t` 注册 API，改用 `lv_display_create()` / `lv_indev_create()`，
旧 API 曾静默炸掉设备构建。

```text
git clone --depth 1 --branch v9.5.0 https://github.com/lvgl/lvgl.git tests/host/lvgl_real
powershell -ExecutionPolicy Bypass -File tests/host/board_port_compile_check.ps1
# 期望：[lv_conf] lv_mem_core_builtin.c => rc=0
#       BOARD PORT COMPILE: all boards OK
```

该检查还会以 C 模式（与 arduino-cli 构建编译 LVGL 的方式一致）编译一个
真实的 LVGL 实现单元（`lv_mem_core_builtin.c`）来验证 `lv_conf.h` 本身
——空的 `LV_MEM_POOL_INCLUDE` 曾在该文件内展开成裸 `#include` 并炸掉设备
构建，而所有仅查头文件的检查都保持绿灯。

## CI

`.github/workflows/ci.yml`：

- **host-tests**（windows）：安装 `arduino-cli` 1.5.1（使用带版本的资产
  URL，裸 `latest` 别名会 404），安装 `esp32:esp32@3.3.10`，把
  `HEXWALLET_ESP32_LIBS` 指向自带的 mbedtls 头文件，依次运行
  `build.ps1`、`device_compile_check.ps1`，再克隆 LVGL 9.5.0 并运行
  `board_port_compile_check.ps1`。
- **firmware-build**（ubuntu）：用官方安装脚本安装 `arduino-cli` 1.5.1
  （脚本拒绝自行创建 `$BINDIR`，因此先 `mkdir ~/bin`），安装
  `esp32:esp32@3.3.10`，克隆 LVGL 9.5.0，以 `arduino-cli compile --fqbn
  esp32:esp32:esp32s3` 编译，并传入 `LV_CONF_INCLUDE_SIMPLE` 以使用
  草图根目录的 `lv_conf.h`。

`build.ps1` / `build_diag.ps1` 读取 `HEXWALLET_ESP32_LIBS`
（`esp32-libs` 工具的 `include\mbedtls` 目录），否则回退到本地
Arduino15 默认路径。
