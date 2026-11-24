# 编译与刷机

[English](Build-and-Flash) · [首页](Home-zh)

## 工具链

| 工具 | 这里使用的版本 |
| --- | --- |
| arduino-cli | 1.5.1 |
| esp32 core | 7 号板使用 3.3.13，其余档位使用 3.3.10 |
| LVGL | 9.5.0（`v9.5.0`） |
| Python | 3.x，用于 7 号板镜像检查、生成器和主机测试 |
| Visual Studio 2022 C++ 工具 | host 测试套件（MSVC `cl.exe`） |
| mbedTLS | `build/chain-mbedtls` 下的 3.6.5，用于原生链测试 |

```powershell
arduino-cli core install esp32:esp32@3.3.10
git clone --depth 1 --branch v9.5.0 https://github.com/lvgl/lvgl.git "$HOME/Arduino/libraries/lvgl"
powershell -ExecutionPolicy Bypass -File tools/prepare_lvgl.ps1 -Directory "$HOME/Arduino/libraries/lvgl"
```

准备脚本修复 LVGL 9.5.0 的五个软件遮罩回调签名：它们必须与回调类型的 `void *` 参数一致，不能通过强制转换函数指针调用。脚本校验修改前后的 SHA-256，可重复执行；遇到不同版本或本地改动会停止。Linux/macOS 使用 `pwsh -File` 执行同一脚本。

## 编译

带屏钱包（1 号板，默认）：

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32s3:PartitionScheme=min_spiffs,PSRAM=opi `
  --library "$HOME/Arduino/libraries/lvgl" `
  --build-property compiler.cpp.extra_flags=-DLV_CONF_INCLUDE_SIMPLE `
  --build-property compiler.c.extra_flags=-DLV_CONF_INCLUDE_SIMPLE .
```

P4 墨水屏钱包（`esp32p4` 上必须显式指定 7 号板）：

```powershell
arduino-cli core install esp32:esp32@3.3.13
./tools/build_p4_board.ps1
```

无屏 CLI（不要 LVGL，不要面板）：

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32s3:PartitionScheme=min_spiffs `
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_BOARD=6 `
  --build-property compiler.c.extra_flags=-DHEXWALLET_BOARD=6 .
```

`arduino-cli compile` 没有 `-D` 选项，所有宏都必须走 `--build-property compiler.{cpp,c}.extra_flags`。
在 Arduino IDE 里则把同样的宏写进 `HexWallet.ino` 旁边的 `build_opt.h`。

P4 无屏版将最后一个命令的目标改为 `esp32p4`，仍使用 6 号板。CI 完整构建 S3 显示、S3 无屏、P4 电子纸、P4 无屏四种组合。无屏版的 BOOT 引脚按目标选择：S3 为 GPIO0，P4 为 GPIO35；不同接线可显式定义 `HEXWALLET_PIN_USER_BUTTON`。

显示版命令同时启用 PSRAM：P4 使用 `PSRAM=enabled`，1 号 S3 AMOLED 使用 `PSRAM=opi`。P4 的 RGB565 完整帧需要 75,776 字节；板级分配器优先把显示缓冲放入 PSRAM，保留内部 RAM 给任务栈等用途。不能仅凭编译器的静态 RAM 统计判断运行时余量；实机仍需确认 PSRAM 初始化、最小空闲堆和任务栈高水位。无屏配置不依赖 PSRAM。

上述命令保留 core 的 UART 串口配置。使用芯片原生 USB 接口运行 CLI 时，须在构建和上传的 FQBN 中追加 `CDCOnBoot=cdc`，并按实际 USB 控制器选择 `USBMode`。UART 构建成功不等于原生 USB CDC 已启用。

最关键的三个宏：

| 宏 | 作用 |
| --- | --- |
| `HEXWALLET_BOARD` | 选择引脚、面板和默认值 |
| `HEXWALLET_ENABLE_LVGL` | `0` 时整个 UI 不编译；6 号板自动如此 |
| `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION` | `1` 时无屏构建可在串口批准；仍然只限串口 |

## Flash 分区

7 号板使用 `partitions/hexwallet-p4-32mb.csv`，要求物理 Flash 为 32 MiB。Arduino-ESP32 3.3.13 的 post-v3 构建面向 P4 v3.1–v3.99。`tools/build_p4_board.ps1` 生成恰好 8,388,608 字节的出厂镜像，写入起点为 `0x0`。两个 OTA 槽分别从 `0x10000` 和 `0x410000` 开始，每槽 3,932,160 字节。`assets` 占用 `0x800000` 至 `0x1ffffff`，共 24 MiB，其中一部分用于 LittleFS 元数据。当前应用在此保存最多 64 条用户声明的代币记录。预编译 SDK 产出诊断镜像，此镜像禁止写入认证凭据。

出厂镜像在 NVS、NVS 密钥和旧 SPIFFS 的位置也有填充字节，适用于空板。使用旧表的 32 MiB 板迁移时应保留这三个分区，在一次维护操作中分别写入 `0x2000` 的引导程序、`0x8000` 的分区表、`0xe000` 的 OTA 初始化数据和 `0x10000` 的应用。旧版第二槽从 `0x1f0000` 开始，仅 OTA 更新应用无法完成布局迁移。已启用安全启动或加密的设备须使用其配置对应的升级流程。迁移后的常规 OTA 只写非活动应用槽。若币种数据文件尚不存在，钱包读取旧 NVS 代币表，下次修改时写入 LittleFS。挂载失败时，仅在逐字节确认整个分区均已擦除后才会自动格式化。

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

同时在构建和上传的 FQBN 中设置 `FlashSize=16M`。不要在 8 MB 模组上用这张表。根目录存在 `partitions.csv` 时，它会覆盖菜单选择的分区；需要回到本页的 4 MB 构建时，先将该文件移出 sketch 根目录。

## 刷机

7 号板的 ROM 下载和首启日志使用 3.3 V UART0。将 USB 转串口适配器的 RX 接板上 `TX`（GPIO37），TX 接板上 `RX`（GPIO38），并共地。主 PCB 的 `USB1` 数据线接 GPIO22/23。首次连接可在 ROM 下载模式执行 `esptool --chip esp32p4 --port COMx chip-id` 和 `esptool --chip esp32p4 --port COMx flash-id`，核对硅片修订及 Flash 容量后再选择镜像。

```powershell
arduino-cli upload -p COM7 --fqbn esp32:esp32:esp32s3:PartitionScheme=min_spiffs,PSRAM=opi .
```

这个上传命令对应上面的 S3 显示版。上传其他配置时使用与其编译命令完全一致的 FQBN 和构建产物。

串口控制台：115200 8N1。开机会打印板名、自检结果，最后是
`HexWallet authenticated CLI ready; use help`。

## 安全启动、Flash 加密、eFuse

动 eFuse 之前先读完：

- 先在牺牲板上验证恢复镜像、签名密钥备份和回滚路径。烧错的 eFuse 不能靠 OTA 救回来。
- `HEXWALLET_REQUIRE_VERIFIED_BOOT` 默认是 0；设为 1 后，固件会拒绝未满足安全启动和 Flash 加密要求的操作。该宏不负责烧写 eFuse，也不替代密钥托管和本地审阅门禁。当前托管后端尚未接通，不能据此认为关闭启动检查就能使用钱包。
- 只开 Flash 加密不开安全启动，保护的是静态数据，不是代码真实性。
- 应用会报告 `running_from_ota_slot`，但不实现防回滚；防回滚是 bootloader 的设置。

## 尺寸

完整向量套件默认不编进设备镜像（`HEXWALLET_DEVICE_SELF_TESTS=0`）：461 KiB 的 `.bss` 在 320 KiB DRAM
段里放不下。CI 在 host 上跑这些向量。样机上要用就加 `-DHEXWALLET_DEVICE_SELF_TESTS=1`，镜像会很大。

加密 worker 的栈是 24 KiB，单任务超时 120 秒；loop 任务 32 KiB。改大缓冲区之后，用
`wallet_worker_stack_free()` 看高水位，别凭感觉。
