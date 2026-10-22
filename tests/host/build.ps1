# Builds and runs the host-side self-tests for the extended crypto stack.
# Uses MSVC (cl.exe from Visual Studio 2022) and the mbedtls headers bundled
# with the ESP32 Arduino core; mbedtls_host.c provides the runtime for the
# subset of mbedtls the firmware uses, so the API surface matches the device.
#
# Usage:  powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot "esp32_paths.ps1")

# Locate the Visual Studio installation and import the MSVC dev environment.
$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstall) { throw "Visual Studio with the C++ toolset was not found." }
$vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found at: $vcvars" }

# Import the environment that vcvars64.bat would set (INCLUDE/LIB/PATH...).
cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
  if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
}

$out = Join-Path $PSScriptRoot "host_test.exe"
$objDir = Join-Path $PSScriptRoot "obj"
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

$common = @(
  "/nologo", "/O2", "/W3",
  "/D_CRT_SECURE_NO_WARNINGS",
  "/DMBEDTLS_ALLOW_PRIVATE_ACCESS",
  "/DHEXWALLET_ENABLE_LVGL=0",
  "/DHEXWALLET_BOARD=0",
  "/I$PSScriptRoot", "/I$root", "/I$mbedtlsInclude", "/I$mbedtlsPort"
)

# Compile the C mbedtls shim (must stay C, mirrors the ESP32 mbedtls build).
& cl @common /std:c11 /c (Join-Path $PSScriptRoot "mbedtls_host.c") "/Fo$objDir\mbedtls_host.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$cppSources = @(
  "CryptoPrimitives.cpp",
  "Blake2b.cpp",
  "CryptoExtended.cpp",
  "Ed25519.cpp",
  "BlsG1.cpp",
  "base58.cpp",
  "local_bech32.cpp",
  "local_segwit.cpp",
  "keccak256.cpp",
  "local_ripemd160.cpp",
  "WalletAddresses.cpp",
  "WalletAltAddresses.cpp",
  "WalletNetworks.cpp",
  "WalletCatalog.cpp",
  "WalletTokens.cpp",
  "CryptoNoteAddress.cpp",
  "QrlXmss.cpp",
  "WalletCustody.cpp",
  "BitcoinTransaction.cpp",
  "KaspaTransaction.cpp",
  "TokenCalldata.cpp",
  "CosmosTransaction.cpp",
  "MoneroScan.cpp",
  "host_security.cpp",
  "host_test_main.cpp"
)

$cppObjs = @()
foreach ($s in $cppSources) {
  $src = Join-Path $root $s
  if (-not (Test-Path $src)) { $src = Join-Path $PSScriptRoot $s }
  $obj = Join-Path $objDir ($s -replace '\.cpp$', '.obj')
  & cl @common /std:c++17 /EHsc /utf-8 /c $src "/Fo$obj"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  $cppObjs += $obj
}

& cl @common "/Fe$out" $cppObjs (Join-Path $objDir "mbedtls_host.obj") /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $out
exit $LASTEXITCODE
