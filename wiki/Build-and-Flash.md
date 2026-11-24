# Build and flash

[中文](Build-and-Flash-zh) · [Home](Home)

## Toolchain

| Tool | Version used here |
| --- | --- |
| arduino-cli | 1.5.1 |
| esp32 core | 3.3.13 for board 7, 3.3.10 for the other profiles |
| LVGL | 9.5.0 (`v9.5.0`) |
| Python | 3.x for the Board 7 image check, generators and host tests |
| Visual Studio 2022 C++ tools | host test suite (MSVC `cl.exe`) |
| mbedTLS | 3.6.5 checkout in `build/chain-mbedtls` for the native chain tests |

```powershell
arduino-cli core install esp32:esp32@3.3.10
git clone --depth 1 --branch v9.5.0 https://github.com/lvgl/lvgl.git "$HOME/Arduino/libraries/lvgl"
powershell -ExecutionPolicy Bypass -File tools/prepare_lvgl.ps1 -Directory "$HOME/Arduino/libraries/lvgl"
```

The preparation script fixes five LVGL 9.5.0 mask callbacks whose function signatures did not match the callback's `void *` parameter. It verifies the source SHA-256 before and after editing, accepts an already patched file, and refuses unknown source. Use `pwsh -File` on Linux/macOS.

## Compile

Display wallet (board 1, the default):

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32s3:PartitionScheme=min_spiffs,PSRAM=opi `
  --library "$HOME/Arduino/libraries/lvgl" `
  --build-property compiler.cpp.extra_flags=-DLV_CONF_INCLUDE_SIMPLE `
  --build-property compiler.c.extra_flags=-DLV_CONF_INCLUDE_SIMPLE .
```

P4 e-paper wallet (board 7 must be selected explicitly on `esp32p4`):

```powershell
arduino-cli core install esp32:esp32@3.3.13
./tools/build_p4_board.ps1
```

Headless CLI (no LVGL, no panel):

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32s3:PartitionScheme=min_spiffs `
  --build-property compiler.cpp.extra_flags=-DHEXWALLET_BOARD=6 `
  --build-property compiler.c.extra_flags=-DHEXWALLET_BOARD=6 .
```

`arduino-cli compile` has no `-D` option; every define goes through `--build-property
compiler.{cpp,c}.extra_flags`. In the Arduino IDE, put the same flags in `build_opt.h` next to
`HexWallet.ino` instead.

For P4 headless, change the last command's target to `esp32p4` and retain board 6. CI builds all four S3/P4 display/headless combinations. The headless BOOT input defaults to GPIO0 on S3 and GPIO35 on P4; different wiring requires an explicit `HEXWALLET_PIN_USER_BUTTON` override.

The three flags that matter most:

| Flag | Effect |
| --- | --- |
| `HEXWALLET_BOARD` | selects pins, panel and defaults |
| `HEXWALLET_ENABLE_LVGL` | `0` drops the whole UI; implied by board 6 |
| `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION` | `1` lets a display-less build approve over serial; still serial-only |

## Flash layout

Select the Board 7 partition table by installed NOR capacity. The default is 32 MiB. The original PCB specifies a 64 Mbit WT25Q64X at U7, which takes the 8 MiB profile when populated. Build for that part and native USB Serial/JTAG with `./tools/build_p4_board.ps1 -FlashSizeMiB 8 -UsbSerialJtag`. Both profiles produce an 8,388,608-byte factory image for address zero. The OTA slots at `0x10000` and `0x410000` each hold 3,932,160 bytes. LittleFS occupies 128 KiB at `0x7d0000` on the 8 MiB board and 24 MiB at `0x800000` on the 32 MiB board. The stock SDK produces a diagnostic image with credential provisioning disabled.

With U7 unpopulated, the P4 ROM can still load a diagnostic into internal SRAM over USB. Persistent boot of the wallet image requires external flash. See the [SRAM probe](../tools/p4_ram_probe/README.md) for P4 v3.1–v3.99.

The factory image includes padding over NVS, its keys and the legacy SPIFFS volume. Use it on blank hardware. For an existing 32 MiB board using the older table, preserve these partitions and use the individual bootloader at `0x2000`, table at `0x8000`, OTA initialization data at `0xe000` and application at `0x10000` together in a maintenance session. The old second slot starts at `0x1f0000` and an app-only OTA cannot migrate the table. Secure-boot or encrypted devices need their provisioning-specific update procedure. Once migrated, an ordinary OTA writes the inactive app slot. The token store reads the existing NVS table when no asset file exists, then commits subsequent changes to LittleFS. A volume that fails to mount is formatted automatically only if every byte is erased.

Display builds also enable PSRAM: `PSRAM=enabled` for P4 and `PSRAM=opi` for the board 1 S3 AMOLED. The P4 RGB565 frame requires 75,776 bytes; the board allocator prefers PSRAM for display buffers, preserving internal RAM for task stacks and other allocations. Static RAM usage from the linker is not a runtime heap budget. Verify PSRAM initialization, minimum free heap and task stack high-water marks on the board. Headless configurations do not require PSRAM.

These commands retain the core's UART serial configuration. For a CLI over the chip's native USB port, add `CDCOnBoot=cdc` to both build and upload FQBNs and select `USBMode` for the actual controller. A successful UART build does not enable native USB CDC.

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

Also set `FlashSize=16M` in both build and upload FQBNs. Do not use this table on an 8 MB module. A root-level `partitions.csv` overrides the menu's partition selection; move it out of the sketch root before returning to the 4 MB builds documented here.

## Flash

Use a 3.3 V UART0 adapter for board 7 ROM downloads and boot logs. Connect adapter RX to board `TX` (GPIO37), adapter TX to board `RX` (GPIO38), and join the grounds. The primary PCB routes the `USB1` data lines to GPIO22/23. In ROM download mode, `esptool --chip esp32p4 --port COMx chip-id` and `esptool --chip esp32p4 --port COMx flash-id` identify the silicon and flash before image selection.

```powershell
arduino-cli upload -p COM7 --fqbn esp32:esp32:esp32s3:PartitionScheme=min_spiffs,PSRAM=opi .
```

This upload command matches the S3 display build above. For another profile, use exactly the same FQBN and artifacts as its compile command.

Serial console: 115200 baud, 8N1. On boot the firmware prints the board name, the self-test
results and `HexWallet authenticated CLI ready; use help`.

## Secure boot, flash encryption, eFuses

Read this before touching eFuses:

- Validate the recovery image, the signing-key backup and the rollback path on a sacrificial board
  first. A wrong eFuse cannot be undone by an OTA update.
- `HEXWALLET_REQUIRE_VERIFIED_BOOT` defaults to 0. Setting it to 1 enforces the secure-boot and flash-encryption checks; it does not burn eFuses or replace custody and local-review checks. The custody backend remains unintegrated, so disabling boot checks does not make device wallet operations available.
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
