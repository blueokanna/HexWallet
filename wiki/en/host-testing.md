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

Files that need `Arduino.h` + ESP-IDF (e.g. `WalletSecurity.cpp` →
`esp_fill_random`) or LVGL config are owned by the CI `arduino-cli` build
instead. The Xtensa g++ `@file` response-file handling mangles backslash `-I`
paths, so the include flags are passed directly.

## 4. Board port compile check (all board profiles)

`tests/host/board_port_compile_check.ps1` compiles `WalletBoardPort.cpp` and
`WalletUi.cpp` for **every supported board profile** (AMOLED, AMOLED Plus,
T-Display S3, T-Deck Max, T-Echo Lite) against the Xtensa toolchain.
`tests/host/mock/` shadows `Arduino.h`, `SPI.h`, `Wire.h` and `lvgl.h` with a
small deterministic surface (and `soc/` with the ESP32-S3 register macros), so
driver syntax and LVGL API usage are type-checked on the host without pulling
in the full ESP-IDF graph.

```text
powershell -ExecutionPolicy Bypass -File tests/host/board_port_compile_check.ps1
# expected: BOARD PORT COMPILE: all boards OK
```

Register names and the real Arduino/LVGL APIs are validated for real by the
`arduino-cli` firmware build in CI; the mock exists to catch driver-level
errors cheaply and deterministically.

## CI

`.github/workflows/ci.yml`:

- **host-tests** (windows): installs `arduino-cli` 1.5.1 (versioned asset URL;
  the bare `latest` alias 404s), installs `esp32:esp32@3.3.10`, points
  `HEXWALLET_ESP32_LIBS` at the bundled mbedtls headers, runs `build.ps1`,
  `device_compile_check.ps1`, then `board_port_compile_check.ps1`.
- **firmware-build** (ubuntu): full `arduino-cli compile --fqbn
  esp32:esp32:esp32s3` with LVGL 9.5.0.

`build.ps1` / `build_diag.ps1` read `HEXWALLET_ESP32_LIBS` (the `esp32-libs`
tool's `include\mbedtls` dir) and fall back to the local Arduino15 default.
