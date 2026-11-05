# Build and flash

[中文](Build-and-Flash-zh) · [Home](Home)

## Toolchain

| Tool | Version used here |
| --- | --- |
| arduino-cli | 1.5.1 |
| esp32 core | 3.3.10 |
| LVGL | 9.5.0 (`v9.5.0`) |
| Python | 3.x, only for the generators and the mining test |
| Visual Studio 2022 C++ tools | host test suite (MSVC `cl.exe`) |
| mbedTLS | 3.6.5 checkout in `build/chain-mbedtls` for the native chain tests |

```powershell
arduino-cli core install esp32:esp32@3.3.10
git clone --depth 1 --branch v9.5.0 https://github.com/lvgl/lvgl.git "$HOME/Arduino/libraries/lvgl"
```

## Compile

Display wallet (board 1, the default):

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32s3 `
  --library "$HOME/Arduino/libraries/lvgl" `
  --build-property compiler.cpp.extra_flags=-DLV_CONF_INCLUDE_SIMPLE `
  --build-property compiler.c.extra_flags=-DLV_CONF_INCLUDE_SIMPLE .
```

P4 e-paper wallet (board 7 must be selected explicitly on `esp32p4`):

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32p4 `
  --library "$HOME/Arduino/libraries/lvgl" `
  --build-property compiler.cpp.extra_flags="-DLV_CONF_INCLUDE_SIMPLE -DHEXWALLET_BOARD=7" `
  --build-property compiler.c.extra_flags="-DLV_CONF_INCLUDE_SIMPLE -DHEXWALLET_BOARD=7" .
```

Headless CLI (no LVGL, no panel):

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32s3 `
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_BOARD=6 `
  --build-property compiler.c.extra_flags=-DHEXWALLET_BOARD=6 .
```

`arduino-cli compile` has no `-D` option; every define goes through `--build-property
compiler.{cpp,c}.extra_flags`. In the Arduino IDE, put the same flags in `build_opt.h` next to
`HexWallet.ino` instead.

The three flags that matter most:

| Flag | Effect |
| --- | --- |
| `HEXWALLET_BOARD` | selects pins, panel and defaults |
| `HEXWALLET_ENABLE_LVGL` | `0` drops the whole UI; implied by board 6 |
| `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION` | `1` lets a display-less build approve over serial; still serial-only |

## Flash layout

`partitions/hexwallet-16mb-ota.csv` is a 16 MB layout with a recovery image and two 5 MB OTA slots:

| Partition | Offset | Size |
| --- | --- | --- |
| nvs | 0x9000 | 24 KiB |
| otadata | 0xF000 | 8 KiB |
| recovery (factory) | 0x20000 | 3 MiB |
| ota_0 | 0x320000 | 5 MiB |
| ota_1 | 0x820000 | 5 MiB |
| storage (spiffs) | 0xD20000 | 2.875 MiB |

The ESP32 core looks for `partitions.csv` in the sketch root, not in `partitions/`. Copy the layout
you want before compiling a release image:

```powershell
Copy-Item partitions\hexwallet-16mb-ota.csv partitions.csv
```

Do not use this table on an 8 MB module.

## Flash

```powershell
arduino-cli upload -p COM7 --fqbn esp32:esp32:esp32s3 .
```

Serial console: 115200 baud, 8N1. On boot the firmware prints the board name, the self-test
results and `HexWallet authenticated CLI ready; use help`.

## Secure boot, flash encryption, eFuses

Read this before touching eFuses:

- Validate the recovery image, the signing-key backup and the rollback path on a sacrificial board
  first. A wrong eFuse cannot be undone by an OTA update.
- Secure boot and flash encryption are **off by default** in this tree. `HEXWALLET_REQUIRE_VERIFIED_BOOT=1`
  makes signing refuse when either is off; without it, the device reports trust state but keeps signing.
- Flash encryption without secure boot protects data at rest, not code authenticity.
- The app reports `running_from_ota_slot` but does not implement anti-rollback; that is a bootloader
  setting.

## Sizing notes

The full vector suite is compiled out of device images by default (`HEXWALLET_DEVICE_SELF_TESTS=0`):
461 KiB of `.bss` does not fit a 320 KiB DRAM segment alongside the wallet. CI runs those vectors on
the host. On a bench unit, enable them with `-DHEXWALLET_DEVICE_SELF_TESTS=1` and expect a large
image.

The crypto worker gets a 24 KiB stack and a 120 s job timeout; the loop task gets 32 KiB. If you
raise a buffer, check the high-water mark via `wallet_worker_stack_free()` rather than guessing.
