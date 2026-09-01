# Device-side compile smoke check.
#
# Compiles every firmware C++ source (excluding the Arduino-sketch-only files)
# with the ESP32 Xtensa toolchain that the ESP32 Arduino core 3.3.10 bundles,
# to prove the code compiles for the 32-bit target (catches 64-bit-only
# assumptions, non-portable printf formats, etc.) before flashing hardware.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1
#
# Requires the esp32 core 3.3.10 installed under Arduino15. Override the
# toolchain/include roots with HEXWALLET_ESP32_LIBS (esp32-libs tool dir) and
# HEXWALLET_ESP32_CORE (core hardware dir) if they are not at the defaults.
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$defaultLibs  = "C:\Users\blueo\AppData\Local\Arduino15\packages\esp32\tools\esp32-libs\3.3.10"
$defaultCore  = "C:\Users\blueo\AppData\Local\Arduino15\packages\esp32\hardware\esp32\3.3.10"
$libs = if ($env:HEXWALLET_ESP32_LIBS) { $env:HEXWALLET_ESP32_LIBS } else { $defaultLibs }
$core = if ($env:HEXWALLET_ESP32_CORE) { $env:HEXWALLET_ESP32_CORE } else { $defaultCore }

# Locate the xtensa compiler inside the esp-x32 toolchain.
$gcc = Get-ChildItem "$env:LOCALAPPDATA\Arduino15\packages\esp32\tools\esp-x32" -Recurse -Filter "xtensa-esp32-elf-g++.exe" -ErrorAction SilentlyContinue |
       Select-Object -First 1 -ExpandProperty FullName
if (-not $gcc) {
  # Fall back to any xtensa g++ under the tools dir.
  $gcc = Get-ChildItem "$env:LOCALAPPDATA\Arduino15\packages\esp32\tools" -Recurse -Filter "*esp32*g++.exe" -ErrorAction SilentlyContinue |
         Select-Object -First 1 -ExpandProperty FullName
}
if (-not $gcc) { throw "xtensa-esp32 g++ not found; is the ESP32 core installed?" }

$includes = @(
  $root,
  (Join-Path $core "cores\esp32"),
  (Join-Path $libs "include"),
  (Join-Path $libs "include\mbedtls\mbedtls\include"),
  (Join-Path $libs "include\mbedtls\port\include")
)
# Curated include set mirroring the esp32 Arduino build (the full ESP-IDF graph
# cannot be hand-replicated; the arduino-cli firmware-build CI job owns that).
$includes = @(
  $root,
  (Join-Path $core "cores\esp32"),
  (Join-Path $libs "include"),
  (Join-Path $libs "include\mbedtls\mbedtls\include"),
  (Join-Path $libs "include\mbedtls\port\include"),
  (Join-Path $libs "include\xtensa\include"),
  (Join-Path $libs "dio_qspi\include")
)

# Firmware sources that are pure C++ (no Arduino.h / ESP-IDF / LVGL).
# WalletSecurity.cpp needs Arduino.h + esp_system.h (esp_fill_random) and
# WalletUi/WalletBoardPort/WalletCli/WalletEngine/WalletTransportPolicy need
# Arduino + LVGL configuration; those are exercised by the full arduino-cli
# build in CI.  This check covers the crypto core for the 32-bit target.
$sources = @(
  "CryptoPrimitives.cpp", "CryptoExtended.cpp", "Ed25519.cpp", "BlsG1.cpp",
  "base58.cpp", "local_bech32.cpp", "local_segwit.cpp", "keccak256.cpp",
  "local_ripemd160.cpp", "WalletAddresses.cpp", "WalletAltAddresses.cpp",
  "CryptoNoteAddress.cpp", "WalletNetworks.cpp",
  "WalletTokens.cpp", "WalletCatalog.cpp", "WalletSession.cpp"
)

$objDir = Join-Path $PSScriptRoot "obj-device"
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

# Include flags are passed directly (the curated set is small; the xtensa g++
# response-file handling mishandles backslash -I paths, so avoid @file).
$incArgs = foreach ($i in $includes) { "-I$i" }
$log = Join-Path $objDir "compile.log"
$fail = 0
foreach ($s in $sources) {
  $src = Join-Path $root $s
  if (-not (Test-Path $src)) { Write-Output "SKIP (missing): $s"; continue }
  $obj = Join-Path $objDir ($s -replace '\.cpp$', '.o')
  & $gcc -std=c++17 -O2 -Wall -Wno-unused-parameter -DMBEDTLS_ALLOW_PRIVATE_ACCESS $incArgs -c $src -o $obj *> $log
  $rc = $LASTEXITCODE
  Write-Output ("  {0} => rc={1}" -f $s, $rc)
  if ($rc -ne 0) {
    $fail++
    Write-Output "----- $s compiler output -----"
    Get-Content $log -Encoding Unicode | Select-Object -First 30 | ForEach-Object { Write-Output $_ }
  }
}
if ($fail -gt 0) {
  Write-Output "DEVICE COMPILE: $fail source(s) FAILED"
  exit 1
}
Write-Output "DEVICE COMPILE: all sources OK"
exit 0
