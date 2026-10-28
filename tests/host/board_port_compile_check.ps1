# Compiles the board-port and UI layers for every supported board profile
# against the real ESP32-S3 headers and the REAL LVGL 9.5 checkout, so driver
# syntax/type errors and LVGL API drift are caught on the host before
# hardware is involved. The LVGL v8-era API (lv_disp_drv_t / lv_indev_drv_t)
# is gone in 9.5; only a real checkout catches that class of breakage.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tests/host/board_port_compile_check.ps1
#
# Requires:
#   - the esp32 core 3.3.10 under Arduino15 (same layout as device_compile_check.ps1)
#   - a real LVGL 9.5 checkout at tests/host/lvgl_real (or $env:HEXWALLET_LVGL_DIR):
#       git clone --depth 1 --branch v9.5.0 https://github.com/lvgl/lvgl.git tests/host/lvgl_real
#
# This check does NOT link anything; it only proves the sources compile for
# the 32-bit target.
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot "esp32_paths.ps1")

$defaultS3Libs = Join-Path (Split-Path (Split-Path $espLibsRoot -Parent) -Parent) "esp32s3-libs\$coreVersion"
$libs = $espLibsRoot
$s3libs = if ($env:HEXWALLET_ESP32_S3_LIBS) { $env:HEXWALLET_ESP32_S3_LIBS } else { $defaultS3Libs }
$core = $coreCandidate
$toolRoot = Join-Path (Split-Path (Split-Path $espLibsRoot -Parent) -Parent) "esp-x32"

$gcc = Get-ChildItem $toolRoot -Recurse -Filter "xtensa-esp32s3-elf-g++.exe" -ErrorAction SilentlyContinue |
       Select-Object -First 1 -ExpandProperty FullName
if (-not $gcc) {
  $gcc = Get-ChildItem $toolRoot -Recurse -Filter "xtensa-esp32-elf-g++.exe" -ErrorAction SilentlyContinue |
         Select-Object -First 1 -ExpandProperty FullName
}
if (-not $gcc) { throw "xtensa-esp32(s3) g++ not found; is the ESP32 core installed?" }

# Prefer the real LVGL checkout. The mock/ directory still shadows the
# Arduino core (Arduino.h, SPI.h, Wire.h) and provides the register-access
# macros (REG_WRITE, GPIO_*) under mock/soc, but lvgl.h itself must come from
# the real tree so the check never validates against a stale API surface.
$lvglDir = if ($env:HEXWALLET_LVGL_DIR) { $env:HEXWALLET_LVGL_DIR }
           else { Join-Path $PSScriptRoot "lvgl_real" }
if (-not (Test-Path (Join-Path $lvglDir "src\lvgl.h"))) {
  Write-Output "ERROR: LVGL checkout not found at $lvglDir"
  Write-Output "Clone it first:"
  Write-Output "  git clone --depth 1 --branch v9.5.0 https://github.com/lvgl/lvgl.git tests/host/lvgl_real"
  Write-Output "or set HEXWALLET_LVGL_DIR to a LVGL 9.5 checkout."
  exit 2
}

$includes = @(
  $root,
  (Join-Path $lvglDir "src"),
  (Join-Path $PSScriptRoot "mock"),
  (Join-Path $s3libs "include"),
  (Join-Path $libs "include"),
  $mbedtlsInclude,
  $mbedtlsPort,
  (Join-Path $libs "include\xtensa\include"),
  (Join-Path $libs "dio_qspi\include")
)
$incArgs = foreach ($i in $includes) { "-I$i" }
# lv_conf.h lives at the sketch root; LV_CONF_INCLUDE_SIMPLE makes lvgl find it.
$extraDefines = @("-DLV_CONF_INCLUDE_SIMPLE")

# The C compiler (xtensa-esp32-elf-gcc.exe sits next to g++). Used to validate
# lv_conf.h against a real LVGL implementation TU compiled as C (the way the
# arduino-cli build compiles LVGL), which catches config bugs that only appear
# inside LVGL's own .c files (e.g. an empty LV_MEM_POOL_INCLUDE breaking
# `#include LV_MEM_POOL_INCLUDE` in lv_mem_core_builtin.c).
$gccC = Get-ChildItem $toolRoot -Recurse -Filter "xtensa-esp32-elf-gcc.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
if (-not $gccC) { throw "xtensa-esp32-elf-gcc.exe not found; is the ESP32 core installed?" }

$boards = @(
  @{ Name = "amoled";    Define = "-DHEXWALLET_BOARD=1" },
  @{ Name = "amoled_plus"; Define = "-DHEXWALLET_BOARD=2" },
  @{ Name = "tdisplay_s3"; Define = "-DHEXWALLET_BOARD=3" },
  @{ Name = "tdeck_max"; Define = "-DHEXWALLET_BOARD=4" },
  @{ Name = "t_echo_lite"; Define = "-DHEXWALLET_BOARD=5" },
  # Board 7 targets the ESP32-P4, but the Arduino/SPI/Wire API surface used by
  # the board port is identical, so the Xtensa headers still type-check it.
  @{ Name = "esp32p4_eink"; Define = "-DHEXWALLET_BOARD=7" }
)

$sources = @("WalletBoardPort.cpp", "WalletUi.cpp")
$objDir = Join-Path $PSScriptRoot "obj-board"
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

$fail = 0

# --- lv_conf.h validation: compile a real LVGL implementation TU as C ------
$confTu = Join-Path $lvglDir "src\stdlib\builtin\lv_mem_core_builtin.c"
if (Test-Path $confTu) {
  $confLog = Join-Path $objDir "lv_conf_check.log"
  & $gccC -std=c11 -fsyntax-only -Wno-unused-parameter $extraDefines $incArgs $confTu *> $confLog
  $confRc = $LASTEXITCODE
  Write-Output ("  [lv_conf] lv_mem_core_builtin.c => rc={0}" -f $confRc)
  if ($confRc -ne 0) {
    $fail++
    Write-Output "----- lv_conf.h / LVGL config -----"
    Get-Content $confLog -Encoding Unicode | Select-Object -First 40 | ForEach-Object { Write-Output $_ }
  }
} else {
  Write-Output "WARN: $confTu not found; skipping lv_conf.h validation"
}

foreach ($b in $boards) {
  foreach ($s in $sources) {
    $src = Join-Path $root $s
    $obj = Join-Path $objDir ("{0}_{1}.o" -f ($s -replace '\.cpp$', ''), $b.Name)
    $log = Join-Path $objDir ("{0}_{1}.log" -f ($s -replace '\.cpp$', ''), $b.Name)
    & $gcc -std=c++17 -O2 -Wall -Wno-unused-parameter $b.Define $extraDefines $incArgs -c $src -o $obj *> $log
    $rc = $LASTEXITCODE
    Write-Output ("  [{0}] {1} => rc={2}" -f $b.Name, $s, $rc)
    if ($rc -ne 0) {
      $fail++
      Write-Output "----- $s [$($b.Name)] -----"
      Get-Content $log -Encoding Unicode | Select-Object -First 40 | ForEach-Object { Write-Output $_ }
    }
  }
}
if ($fail -gt 0) {
  Write-Output "BOARD PORT COMPILE: $fail failure(s)"
  exit 1
}

# --- NFC port: force the PN7161 implementation to compile ----------------
# Without a real pin map the whole NCI implementation is #if'd out, which
# means a syntax/type error there would only show up on the one board that
# defines it. Compile it here with a synthetic pin map so the code is always
# type-checked, while the shipped boards stay NotConfigured.
$nfcPins = @(
  "-DHEXWALLET_NFC_PN7161=1",
  "-DHEXWALLET_NFC_PIN_SCK=12",
  "-DHEXWALLET_NFC_PIN_MOSI=13",
  "-DHEXWALLET_NFC_PIN_MISO=14",
  "-DHEXWALLET_NFC_PIN_CS=15",
  "-DHEXWALLET_NFC_PIN_IRQ=16",
  "-DHEXWALLET_NFC_PIN_VEN=17"
)
$nfcLog = Join-Path $objDir "WalletNfcPort_nfc.log"
& $gcc -std=c++17 -O2 -Wall -Wno-unused-parameter "-DHEXWALLET_BOARD=1" @nfcPins $extraDefines $incArgs -c (Join-Path $root "WalletNfcPort.cpp") -o (Join-Path $objDir "WalletNfcPort_nfc.o") *> $nfcLog
$nfcRc = $LASTEXITCODE
Write-Output ("  [nfc] WalletNfcPort.cpp => rc={0}" -f $nfcRc)
if ($nfcRc -ne 0) {
  $fail++
  Write-Output "----- WalletNfcPort.cpp [synthetic pins] -----"
  Get-Content $nfcLog -Encoding Unicode | Select-Object -First 40 | ForEach-Object { Write-Output $_ }
}

# --- NFC port on the real P4 profile -------------------------------------
# Board 7 is the only profile that ships a PN7161 pin map, so compile it there
# too: the synthetic run above proves the code type-checks, this one proves the
# shipped pin map is complete.
$nfcRealLog = Join-Path $objDir "WalletNfcPort_board7.log"
& $gcc -std=c++17 -O2 -Wall -Wno-unused-parameter "-DHEXWALLET_BOARD=7" $extraDefines $incArgs -c (Join-Path $root "WalletNfcPort.cpp") -o (Join-Path $objDir "WalletNfcPort_board7.o") *> $nfcRealLog
$nfcRealRc = $LASTEXITCODE
Write-Output ("  [nfc board7] WalletNfcPort.cpp => rc={0}" -f $nfcRealRc)
if ($nfcRealRc -ne 0) {
  $fail++
  Write-Output "----- WalletNfcPort.cpp [board 7 pins] -----"
  Get-Content $nfcRealLog -Encoding Unicode | Select-Object -First 40 | ForEach-Object { Write-Output $_ }
}

# --- Camera port on a synthetic SCCB pin map ------------------------------
# The OV9281 branch is #if'd out for every shipped profile (the current PCB has
# no camera nets), so compile it once with pins to keep the SCCB transport
# type-checked instead of discovering a mistake when the sensor is wired.
$cameraDefines = @(
  "-DHEXWALLET_BOARD=7",
  "-DHEXWALLET_CAMERA_SCCB_SDA=4",
  "-DHEXWALLET_CAMERA_SCCB_SCL=5"
)
$cameraLog = Join-Path $objDir "WalletBoardPort_camera.log"
& $gcc -std=c++17 -O2 -Wall -Wno-unused-parameter @cameraDefines $extraDefines $incArgs -c (Join-Path $root "WalletBoardPort.cpp") -o (Join-Path $objDir "WalletBoardPort_camera.o") *> $cameraLog
$cameraRc = $LASTEXITCODE
Write-Output ("  [camera] WalletBoardPort.cpp => rc={0}" -f $cameraRc)
if ($cameraRc -ne 0) {
  $fail++
  Write-Output "----- WalletBoardPort.cpp [camera SCCB pins] -----"
  Get-Content $cameraLog -Encoding Unicode | Select-Object -First 40 | ForEach-Object { Write-Output $_ }
}

if ($fail -gt 0) {
  Write-Output "BOARD PORT COMPILE: $fail failure(s)"
  exit 1
}
Write-Output "BOARD PORT COMPILE: all boards OK"
exit 0