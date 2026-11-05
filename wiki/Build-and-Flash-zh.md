# 编译与刷机

[English](Build-and-Flash) · [首页](Home-zh)

## 工具链

| 工具 | 这里使用的版本 |
| --- | --- |
| arduino-cli | 1.5.1 |
| esp32 core | 3.3.10 |
| LVGL | 9.5.0（`v9.5.0`） |
| Python | 3.x，只用于生成器和 mining 测试 |
| Visual Studio 2022 C++ 工具 | host 测试套件（MSVC `cl.exe`） |
| mbedTLS | `build/chain-mbedtls` 下的 3.6.5，用于原生链测试 |

```powershell
arduino-cli core install esp32:esp32@3.3.10
git clone --depth 1 --branch v9.5.0 https://github.com/lvgl/lvgl.git "$HOME/Arduino/libraries/lvgl"
```

## 编译

带屏钱包（1 号板，默认）：

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32s3 `
  --library "$HOME/Arduino/libraries/lvgl" `
  --build-property compiler.cpp.extra_flags=-DLV_CONF_INCLUDE_SIMPLE `
  --build-property compiler.c.extra_flags=-DLV_CONF_INCLUDE_SIMPLE .
```

P4 墨水屏钱包（`esp32p4` 上必须显式指定 7 号板）：

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32p4 `
  --library "$HOME/Arduino/libraries/lvgl" `
  --build-property compiler.cpp.extra_flags="-DLV_CONF_INCLUDE_SIMPLE -DHEXWALLET_BOARD=7" `
  --build-property compiler.c.extra_flags="-DLV_CONF_INCLUDE_SIMPLE -DHEXWALLET_BOARD=7" .
```

无屏 CLI（不要 LVGL，不要面板）：

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32s3 `
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_BOARD=6 `
  --build-property compiler.c.extra_flags=-DHEXWALLET_BOARD=6 .
```

`arduino-cli compile` 没有 `-D` 选项，所有宏都必须走 `--build-property compiler.{cpp,c}.extra_flags`。
在 Arduino IDE 里则把同样的宏写进 `HexWallet.ino` 旁边的 `build_opt.h`。

最关键的三个宏：

| 宏 | 作用 |
| --- | --- |
| `HEXWALLET_BOARD` | 选择引脚、面板和默认值 |
| `HEXWALLET_ENABLE_LVGL` | `0` 时整个 UI 不编译；6 号板自动如此 |
| `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION` | `1` 时无屏构建可在串口批准；仍然只限串口 |

## Flash 分区

`partitions/hexwallet-16mb-ota.csv` 是 16 MB 布局，含恢复镜像和两个 5 MB OTA 槽：

| 分区 | 偏移 | 大小 |
| --- | --- | --- |
| nvs | 0x9000 | 24 KiB |
| otadata | 0xF000 | 8 KiB |
| recovery（factory） | 0x20000 | 3 MiB |
| ota_0 | 0x320000 | 5 MiB |
| ota_1 | 0x820000 | 5 MiB |
| storage（spiffs） | 0xD20000 | 2.875 MiB |

ESP32 core 只认 sketch 根目录的 `partitions.csv`，不认 `partitions/` 子目录。编发布镜像前先复制：

```powershell
Copy-Item partitions\hexwallet-16mb-ota.csv partitions.csv
```

不要在 8 MB 模组上用这张表。

## 刷机

```powershell
arduino-cli upload -p COM7 --fqbn esp32:esp32:esp32s3 .
```

串口控制台：115200 8N1。开机会打印板名、自检结果，最后是
`HexWallet authenticated CLI ready; use help`。

## 安全启动、Flash 加密、eFuse

动 eFuse 之前先读完：

- 先在牺牲板上验证恢复镜像、签名密钥备份和回滚路径。烧错的 eFuse 不能靠 OTA 救回来。
- 这棵树里安全启动和 Flash 加密**默认关闭**。`HEXWALLET_REQUIRE_VERIFIED_BOOT=1` 会让任一未开启时拒绝签名；
  不设它时，设备只报告信任状态，仍然签名。
- 只开 Flash 加密不开安全启动，保护的是静态数据，不是代码真实性。
- 应用会报告 `running_from_ota_slot`，但不实现防回滚；防回滚是 bootloader 的设置。

## 尺寸

完整向量套件默认不编进设备镜像（`HEXWALLET_DEVICE_SELF_TESTS=0`）：461 KiB 的 `.bss` 在 320 KiB DRAM
段里放不下。CI 在 host 上跑这些向量。样机上要用就加 `-DHEXWALLET_DEVICE_SELF_TESTS=1`，镜像会很大。

加密 worker 的栈是 24 KiB，单任务超时 120 秒；loop 任务 32 KiB。改大缓冲区之后，用
`wallet_worker_stack_free()` 看高水位，别凭感觉。
