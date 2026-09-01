# Compiles the board-port and UI layers for every supported board profile
# against the real ESP32-S3 headers plus a small LVGL API mock, so driver
# syntax/type errors are caught on the host before hardware is involved.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tests/host/board_port_compile_check.ps1
#
# Requires the esp32 core 3.3.10 under Arduino15 (same layout as
# device_compile_check.ps1). This check does NOT link anything; it only
# proves the sources compile for the 32-bit target.
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$defaultLibs = "C:\Users\blueo\AppData\Local\Arduino15\packages\esp32\tools\esp32-libs\3.3.10"
$defaultS3Libs = "C:\Users\blueo\AppData\Local\Arduino15\packages\esp32\tools\esp32s3-libs\3.3.10"
$defaultCore = "C:\Users\blueo\AppData\Local\Arduino15\packages\esp32\hardware\esp32\3.3.10"
$libs = if ($env:HEXWALLET_ESP32_LIBS) { $env:HEXWALLET_ESP32_LIBS } else { $defaultLibs }
$s3libs = if ($env:HEXWALLET_ESP32_S3_LIBS) { $env:HEXWALLET_ESP32_S3_LIBS } else { $defaultS3Libs }
$core = if ($env:HEXWALLET_ESP32_CORE) { $env:HEXWALLET_ESP32_CORE } else { $defaultCore }

$gcc = Get-ChildItem "$env:LOCALAPPDATA\Arduino15\packages\esp32\tools\esp-x32" -Recurse -Filter "xtensa-esp32s3-elf-g++.exe" -ErrorAction SilentlyContinue |
       Select-Object -First 1 -ExpandProperty FullName
if (-not $gcc) {
  $gcc = Get-ChildItem "$env:LOCALAPPDATA\Arduino15\packages\esp32\tools\esp-x32" -Recurse -Filter "xtensa-esp32-elf-g++.exe" -ErrorAction SilentlyContinue |
         Select-Object -First 1 -ExpandProperty FullName
}
if (-not $gcc) { throw "xtensa-esp32(s3) g++ not found; is the ESP32 core installed?" }

# The mock directory shadows the real Arduino core so the driver/UI sources
# type-check against a small, deterministic Arduino+LVGL surface. Register
# access macros (REG_WRITE, GPIO_*) come from mock/soc headers; the real
# arduino-cli device build in CI validates them against genuine ESP-IDF.
$includes = @(
  $root,
  (Join-Path $PSScriptRoot "mock"),
  (Join-Path $s3libs "include"),
  (Join-Path $libs "include"),
  (Join-Path $libs "include\mbedtls\mbedtls\include"),
  (Join-Path $libs "include\mbedtls\port\include"),
  (Join-Path $libs "include\xtensa\include"),
  (Join-Path $libs "dio_qspi\include")
)
$incArgs = foreach ($i in $includes) { "-I$i" }

$boards = @(
  @{ Name = "amoled";    Define = "-DHEXWALLET_BOARD=1" },
  @{ Name = "amoled_plus"; Define = "-DHEXWALLET_BOARD=2" },
  @{ Name = "tdisplay_s3"; Define = "-DHEXWALLET_BOARD=3" },
  @{ Name = "tdeck_max"; Define = "-DHEXWALLET_BOARD=4" },
  @{ Name = "t_echo_lite"; Define = "-DHEXWALLET_BOARD=5" }
)

$sources = @("WalletBoardPort.cpp", "WalletUi.cpp")
$objDir = Join-Path $PSScriptRoot "obj-board"
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

$fail = 0
foreach ($b in $boards) {
  foreach ($s in $sources) {
    $src = Join-Path $root $s
    $obj = Join-Path $objDir ("{0}_{1}.o" -f ($s -replace '\.cpp$', ''), $b.Name)
    $log = Join-Path $objDir ("{0}_{1}.log" -f ($s -replace '\.cpp$', ''), $b.Name)
    & $gcc -std=c++17 -O2 -Wall -Wno-unused-parameter $b.Define $incArgs -c $src -o $obj *> $log
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
Write-Output "BOARD PORT COMPILE: all boards OK"
exit 0
