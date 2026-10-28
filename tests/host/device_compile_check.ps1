# Device-side compile smoke check.
#
# Compiles every firmware C++ source (excluding the Arduino-sketch-only files)
# with the selected Xtensa or P4 RISC-V toolchain from Arduino core 3.3.10,
# to prove the code compiles for the 32-bit target (catches 64-bit-only
# assumptions, non-portable printf formats, etc.) before flashing hardware.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1
#
# Requires the esp32 core 3.3.10 installed under Arduino15. Override the
# toolchain/include roots with HEXWALLET_ESP32_LIBS (esp32-libs tool dir) and
# HEXWALLET_ESP32_CORE (core hardware dir) if they are not at the defaults.
param([ValidateSet("esp32", "esp32p4")][string]$Target = "esp32")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot "esp32_paths.ps1")
$libs = $espLibsRoot
if ($Target -eq "esp32p4") {
  $libs = Join-Path (Split-Path (Split-Path $espLibsRoot -Parent) -Parent) "esp32p4-libs\$coreVersion"
  if (-not (Test-Path $libs)) { throw "P4 SDK not found: $libs" }
  $mbedtlsInclude = Join-Path $libs "include\mbedtls\mbedtls\include"
  $mbedtlsPort = Join-Path $libs "include\mbedtls\port\include"
}
$core = $coreCandidate

# Never fall back to a different architecture when a compiler is absent.
$toolName = if ($Target -eq "esp32p4") { "esp-rv32" } else { "esp-x32" }
$compilerName = if ($Target -eq "esp32p4") { "riscv32-esp-elf-g++.exe" } else { "xtensa-esp32-elf-g++.exe" }
$toolRoot = Join-Path (Split-Path (Split-Path $espLibsRoot -Parent) -Parent) $toolName
$gcc = Get-ChildItem $toolRoot -Recurse -Filter $compilerName |
       Select-Object -First 1 -ExpandProperty FullName
if (-not $gcc) { throw "$compilerName not found" }
$architectureFlags = if ($Target -eq "esp32p4") {
  @("-march=rv32imafc_zicsr_zifencei_xesploop_xespv", "-mabi=ilp32f", "-DARDUINO_ARCH_ESP32")
} else { @() }

$includes = @(
  $root,
  (Join-Path $PSScriptRoot "mock"),
  $PSScriptRoot,
  (Join-Path $core "cores\esp32"),
  (Join-Path $libs "include"),
  (Join-Path $libs "include\esp_hw_support\include"),
  $mbedtlsInclude,
  $mbedtlsPort,
  (Join-Path $libs "include"),
  (Join-Path $libs "dio_qspi\include")
)

# Firmware sources that are pure C++ (no Arduino.h / ESP-IDF / LVGL).
# WalletSecurity.cpp needs Arduino.h + esp_system.h (esp_fill_random), and
# WalletUi/WalletBoardPort/WalletCli/WalletTransportPolicy need Arduino +
# LVGL configuration; those are exercised by the full arduino-cli build in CI.
# WalletEngine.cpp, EvmTransaction.cpp and BitcoinTransaction.cpp are compiled
# here too - the derive_address() seed-parameter refactor broke
# EvmTransaction.cpp and only the device build caught it, so any source that
# can compile with the curated include set is kept in this list.
$sources = @(
  "CryptoPrimitives.cpp",
  "SolanaTransaction.cpp",
  "Blake2b.cpp", "Blake256.cpp", "CryptoExtended.cpp", "Ed25519.cpp", "BlsG1.cpp",
  "WalletLinkCrypto.cpp", "WalletLink.cpp", "WalletNfcApdu.cpp",
  "base58.cpp", "local_bech32.cpp", "local_segwit.cpp", "keccak256.cpp",
  "local_ripemd160.cpp", "WalletAddresses.cpp", "WalletAltAddresses.cpp",
  "CryptoNoteAddress.cpp", "CryptoNoteRingCt.cpp", "CryptoNoteAmounts.cpp", "CryptoNoteOutputScan.cpp", "CryptoNoteTransaction.cpp", "CryptoNoteSpend.cpp", "CryptoNoteBulletproofPlus.cpp", "CryptoNoteReview.cpp", "CryptoNoteSigning.cpp", "CryptoNoteMasari.cpp", "WalletNetworks.cpp", "QrlXmss.cpp",
  "WalletCustody.cpp", "SecureElementPort.cpp", "RandomSource.cpp", "EinkPanel.cpp", "QrCode.cpp",
  "WalletSecurity.cpp",
  "WalletTokens.cpp", "WalletCatalog.cpp", "WalletMiningCatalog.cpp", "WalletSession.cpp",
  "WalletEngine.cpp", "EvmTransaction.cpp", "BitcoinTransaction.cpp", "KaspaTransaction.cpp", "TokenCalldata.cpp", "ZcashTransaction.cpp", "TronTransaction.cpp", "CosmosTransaction.cpp", "StellarTransaction.cpp", "AlgorandTransaction.cpp", "ChainCommon.cpp", "ChainTransaction.cpp", "VeChainTransaction.cpp", "IconTransaction.cpp", "PolkadotTransaction.cpp", "SuiTransaction.cpp", "FilecoinTransaction.cpp", "TonCell.cpp", "TonTransaction.cpp", "DecredTransaction.cpp", "CkbTransaction.cpp", "HiveTransaction.cpp", "CardanoDerivation.cpp", "CardanoTransaction.cpp", "HederaTransaction.cpp", "SiaTransaction.cpp", "NemTransaction.cpp", "IcpTransaction.cpp", "ErgoTransaction.cpp", "Clvm.cpp", "ChiaTransaction.cpp", "BlsG2.cpp", "WalletSigning.cpp", "NearTransaction.cpp", "TezosTransaction.cpp", "XrpTransaction.cpp", "Totp.cpp", "EinkFrame.cpp"
)

$objDir = Join-Path $PSScriptRoot "obj-device/$Target"
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

# Include flags are passed directly (the curated set is small; the xtensa g++
# response-file handling mishandles backslash -I paths, so avoid @file).
$incArgs = foreach ($i in $includes) { "-I$i" }
$log = Join-Path $objDir "compile.log"
$fail = 0
foreach ($s in $sources) {
  $src = Join-Path $root $s
  if (-not (Test-Path $src)) { throw "Missing required source: $s" }
  $obj = Join-Path $objDir ($s -replace '\.cpp$', '.o')
  # Windows PowerShell wraps stderr warnings as non-terminating errors.
  # Judge native compilation by its exit status, not by the presence of stderr.
  $global:LASTEXITCODE = $null
  $ErrorActionPreference = "Continue"
  & $gcc @architectureFlags -std=c++17 -O2 -Wall -Wno-unused-parameter -DMBEDTLS_ALLOW_PRIVATE_ACCESS $incArgs -c $src -o $obj *> $log
  $rc = $global:LASTEXITCODE
  $ErrorActionPreference = "Stop"
  Write-Output ("  {0} => rc={1}" -f $s, $rc)
  if ($rc -ne 0) {
    $fail++
    Write-Output "----- $s compiler output -----"
    Get-Content $log | Select-Object -First 30 | ForEach-Object { Write-Output $_ }
  }
}
# --- Arduino-parity compile ------------------------------------------------
# The curated include set above is smaller than the one arduino-cli uses, and it
# does not define ARDUINO. That combination let a build break in CI while every
# local check stayed green: TrustAnchor.cpp included <esp_flash_encryption.h>,
# which the Arduino core does not ship, and nothing here compiled that branch.
# These sources are therefore also compiled exactly the way arduino-cli does it:
# every component include directory plus -DARDUINO.
$paritySources = @("TrustAnchor.cpp")
# arduino-cli builds its include path from the SDK's flags/includes file, which
# is a list of "-iprefix + iwithprefixbefore" pairs. Reproducing that exact
# mechanism here turned out to be fragile, so this step spells the same directory
# set out with -I: every component include directory, the per-chip register
# headers, and the flash-mode directory that carries sdkconfig.h. A header that
# IDF has but the bundle lacks must fail here, not only in CI.
$parityArgs = @()
$parityArgs += "-I" + (Join-Path $core "cores\esp32")
$parityArgs += "-I" + $root
$parityArgs += "-I" + $mbedtlsInclude
$parityArgs += "-I" + $mbedtlsPort
foreach ($dir in Get-ChildItem (Join-Path $libs "include") -Directory -Recurse -ErrorAction SilentlyContinue) {
  # Component includes sit at include/<component>/include and, for per-chip
  # headers, at include/<component>/<chip>/include. Register maps are
  # "register" directories whose chips add a hw_ver* level. All of them are on
  # arduino-cli's include path.
  if ($dir.Name -eq "include" -or $dir.Name -eq "register" -or $dir.Name -like "hw_ver*") {
    $parityArgs += "-I" + $dir.FullName
  }
}
foreach ($mode in @("dio_qspi", "qio_qspi")) {
  $modeInclude = Join-Path $libs "$mode\include"
  if (Test-Path $modeInclude) { $parityArgs += "-I" + $modeInclude }
}
foreach ($s in $paritySources) {
  $src = Join-Path $root $s
  $obj = Join-Path $objDir ($s -replace '\.cpp$', '.arduino.o')
  $log = Join-Path $objDir "compile-arduino.log"
  $global:LASTEXITCODE = $null
  $ErrorActionPreference = "Continue"
  # LVGL is not on this include path; the parity step is about the Arduino/IDF
  # branches, so the UI is switched off instead of pointing at a missing header.
  & $gcc @architectureFlags -std=c++17 -O2 -Wall -Wno-unused-parameter `
      -DARDUINO=10819 -DARDUINO_ARCH_ESP32 -DESP_PLATFORM -DHEXWALLET_ENABLE_LVGL=0 `
      -DMBEDTLS_ALLOW_PRIVATE_ACCESS @parityArgs -c $src -o $obj *> $log
  $rc = $global:LASTEXITCODE
  $ErrorActionPreference = "Stop"
  Write-Output ("  [arduino-parity] {0} => rc={1}" -f $s, $rc)
  if ($rc -ne 0) {
    $fail++
    Write-Output "----- $s [arduino-parity] compiler output -----"
    Get-Content $log | Select-Object -First 40 | ForEach-Object { Write-Output $_ }
  }
}

if ($fail -gt 0) {
  Write-Output "DEVICE COMPILE: $fail source(s) FAILED"
  exit 1
}
Write-Output "DEVICE COMPILE ($Target): all sources OK"
exit 0

