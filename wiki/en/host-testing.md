# Host testing

The firmware's crypto must be correct before it ever touches hardware. The
verification rig has three layers.

## 1. MSVC host self-test suite

`tests/host/build.ps1` compiles every firmware `.cpp` with MSVC `cl.exe`
against the **exact mbedtls headers bundled with the ESP32 Arduino core**
(the same headers the device build uses), links them with the
`tests/host/mbedtls_host.c` runtime shim, and runs `host_test.exe`.

```text
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
```

Expected result:

```text
extended-crypto=pass
alt-addresses=pass
```

The `mbedtls_host.c` shim implements the small mbedtls subset the firmware
uses (SHA-256/512, HMAC, PBKDF2, and a 64-bit-limb bignum with
`mod_mpi`/`inv_mod`/`exp_mod`). It exists so the API surface matches the
device without needing the device.

### Gotchas

- Kill and delete `host_test.exe` (and `diag.exe`) before rebuilding, or the
  linker reports "another program is using this file" and you run a **stale
  binary** that silently lies. A stale binary once made us "fix" a bug that
  did not exist.
- Read output through `cmd /c "… > %TEMP%\file.txt 2>&1"`; PowerShell `2>nul`
  is misparsed as a device redirect.

## 2. Independent Python oracle

`CryptoExtended.cpp`/`BlsG1.cpp` results are cross-checked against a pure
Python implementation (`sha256`/`hmac` + arbitrary-precision integers, no
external crypto libs):

- official ERC-2333 Test Case 0 (master SK, Lamport PK, child SK);
- `bls pk(sk=1)`;
- Chia `v0` / `ones` / 16-byte-seed addresses and the derived public key.

Both sides agreeing on the *official* vectors is the ground truth; when C++
and the (buggy) first Python attempt disagreed, the C++ was right and the
Python was missing the `IKM || 0x00` / salt-loop / single-HKDF-Lamport steps.

## 3. Device-target compile check

`tests/host/device_compile_check.ps1` compiles every pure-C++ firmware source
with the ESP32 **Xtensa g++** (`esp-x32` toolchain) using a curated ESP-IDF
include set, catching 32-bit-only assumptions before flashing.

```text
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1
# expected: DEVICE COMPILE: all sources OK
```

`WalletEngine.cpp`, `EvmTransaction.cpp` and `BitcoinTransaction.cpp` are in
this list too — a `derive_address()` signature refactor once broke
`EvmTransaction.cpp` and only the device build caught it, so any source that
compiles with the curated include set is kept here. Files that need
`Arduino.h` + the full ESP-IDF graph (e.g. `WalletSecurity.cpp` →
`esp_fill_random`) or LVGL config are owned by the CI `arduino-cli` build
instead. The Xtensa g++ `@file` response-file handling mangles backslash `-I`
paths, so the include flags are passed directly.

## 4. Board port compile check (all board profiles)

`tests/host/board_port_compile_check.ps1` compiles `WalletBoardPort.cpp` and
`WalletUi.cpp` for **every supported board profile** (AMOLED, AMOLED Plus,
T-Display S3, T-Deck Max, T-Echo Lite) against the Xtensa toolchain and the
**real LVGL 9.5 checkout** (`tests/host/lvgl_real` or `$env:HEXWALLET_LVGL_DIR`).
The mock/ directory only shadows `Arduino.h`, `SPI.h`, `Wire.h` and the
ESP32-S3 register macros (`soc/`); `lvgl.h` itself always comes from the real
tree so the check cannot validate against a stale API surface. This matters:
LVGL 9.5 removed the v8-era `lv_disp_drv_t` / `lv_indev_drv_t` registration
API in favor of `lv_display_create()` / `lv_indev_create()`, and the old API
broke the device build silently.

```text
git clone --depth 1 --branch v9.5.0 https://github.com/lvgl/lvgl.git tests/host/lvgl_real
powershell -ExecutionPolicy Bypass -File tests/host/board_port_compile_check.ps1
# expected: [lv_conf] lv_mem_core_builtin.c => rc=0
#           BOARD PORT COMPILE: all boards OK
```

The check also compiles a real LVGL implementation TU (`lv_mem_core_builtin.c`,
as C, the way the arduino-cli build compiles LVGL) to validate `lv_conf.h`
itself — an empty `LV_MEM_POOL_INCLUDE` once expanded into a bare `#include`
inside that file and broke the device build while every header-only check
stayed green.

## CI

`.github/workflows/ci.yml`:

- **host-tests** (windows): installs `arduino-cli` 1.5.1 (versioned asset URL;
  the bare `latest` alias 404s), installs `esp32:esp32@3.3.10`, points
  `HEXWALLET_ESP32_LIBS` at the bundled mbedtls headers, runs `build.ps1`,
  `device_compile_check.ps1`, clones LVGL 9.5.0, then runs
  `board_port_compile_check.ps1` against it.
- **firmware-build** (ubuntu): installs `arduino-cli` 1.5.1 via the official
  install script (the script refuses to create `$BINDIR` itself, so `~/bin` is
  created first), installs `esp32:esp32@3.3.10`, clones LVGL 9.5.0, and runs
  `arduino-cli compile --fqbn esp32:esp32:esp32s3` with
  `LV_CONF_INCLUDE_SIMPLE` so the sketch-root `lv_conf.h` is used.

`build.ps1` / `build_diag.ps1` read `HEXWALLET_ESP32_LIBS` (the `esp32-libs`
tool's `include\mbedtls` dir) and fall back to the local Arduino15 default.
