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
  "/D_CRT_SECURE_NO_WARNINGS", "/DHEXWALLET_HOST_TEST=1",
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
  "SolanaTransaction.cpp",
  "StellarTransaction.cpp",
  "WalletEngine.cpp",
  "Blake2b.cpp",
  "Blake256.cpp",
  "CryptoExtended.cpp",
  "WalletLinkCrypto.cpp",
  "WalletLink.cpp",
  "WalletNfcApdu.cpp",
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
  "WalletMiningCatalog.cpp",
  "WalletTokens.cpp",
  "CryptoNoteAddress.cpp",
  "CryptoNoteRingCt.cpp", "CryptoNoteAmounts.cpp", "CryptoNoteOutputScan.cpp", "CryptoNoteSpend.cpp",
  "CryptoNoteTransaction.cpp",
  "CryptoNoteBulletproofPlus.cpp",
  "CryptoNoteReview.cpp",
  "CryptoNoteSigning.cpp",
  "CryptoNoteMasari.cpp",
  "QrlXmss.cpp",
  "WalletCustody.cpp", "SecureElementPort.cpp",
  "BitcoinTransaction.cpp",
  "KaspaTransaction.cpp",
  "TronTransaction.cpp",
  "CosmosTransaction.cpp",
  "AlgorandTransaction.cpp",
  "ChainCommon.cpp", "ChainTransaction.cpp",
  "VeChainTransaction.cpp", "IconTransaction.cpp", "PolkadotTransaction.cpp", "SuiTransaction.cpp", "FilecoinTransaction.cpp",
  "TonCell.cpp", "TonTransaction.cpp", "DecredTransaction.cpp", "CkbTransaction.cpp", "HiveTransaction.cpp", "CardanoDerivation.cpp", "CardanoTransaction.cpp", "HederaTransaction.cpp", "SiaTransaction.cpp", "NemTransaction.cpp", "IcpTransaction.cpp", "ErgoTransaction.cpp", "Clvm.cpp", "ChiaTransaction.cpp", "BlsG2.cpp",
  "NearTransaction.cpp", "TezosTransaction.cpp",
  "Totp.cpp",
  "EinkFrame.cpp",
  "XrpTransaction.cpp",
  "TokenCalldata.cpp",
  "ZcashTransaction.cpp",
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

# Second binary: the phone-link harness used by tests/test_phone_link.py.
# It links the real WalletLink/WalletLinkCrypto/WalletNfcApdu code with a stub
# application handler so the phone-side reference client can be validated
# end to end without hardware.
$pipeSources = @(
  "CryptoPrimitives.cpp",
  "Blake2b.cpp",
  "CryptoExtended.cpp",
  "WalletLinkCrypto.cpp",
  "WalletLink.cpp",
  "WalletNfcApdu.cpp",
  "Ed25519.cpp",
  "BlsG1.cpp",
  "keccak256.cpp",
  "local_ripemd160.cpp",
  "host_security.cpp"
)
$pipeObjs = @()
foreach ($s in $pipeSources) {
  $src = Join-Path $root $s
  if (-not (Test-Path $src)) { $src = Join-Path $PSScriptRoot $s }
  $obj = Join-Path $objDir ("pipe_" + ($s -replace '\.cpp$', '.obj'))
  & cl @common /std:c++17 /EHsc /utf-8 /c $src "/Fo$obj"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  $pipeObjs += $obj
}
& cl @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot "link_pipe.cpp") "/Fo$objDir\pipe_link_pipe.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cl @common "/Fe$(Join-Path $PSScriptRoot 'link_pipe.exe')" $pipeObjs "$objDir\pipe_link_pipe.obj" (Join-Path $objDir "mbedtls_host.obj") /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Exercise the enabled NFC driver, including actual SPI frame construction.
& cl /nologo /O2 /W3 /std:c++17 /EHsc /utf-8 /DHEXWALLET_BOARD=0 /DHEXWALLET_ENABLE_LVGL=0 "/I$PSScriptRoot/mock" "/I$root" (Join-Path $PSScriptRoot "nfc_port_test.cpp") "/Fo$objDir/nfc_port_test.obj" "/Fe$(Join-Path $PSScriptRoot 'nfc_port_test.exe')"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot 'nfc_port_test.exe')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& cl @common /std:c++17 /EHsc /utf-8 (Join-Path $root 'WalletWorkerExecution.cpp') (Join-Path $PSScriptRoot 'worker_execution_test.cpp') "/Fo$objDir/" "/Fe$(Join-Path $PSScriptRoot 'worker_execution_test.exe')"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot 'worker_execution_test.exe')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Resolved-catalog dump used by tools/coin_coverage_report.py. It links the
# real WalletCatalog/WalletNetworks objects, so the report reflects what the
# firmware actually exposes instead of what the source text looks like.
$catalogSources = @(
  "base58.cpp", "local_bech32.cpp", "local_segwit.cpp", "keccak256.cpp",
  "local_ripemd160.cpp", "WalletAddresses.cpp", "WalletAltAddresses.cpp",
  "CryptoPrimitives.cpp", "Blake2b.cpp", "Blake256.cpp", "CryptoExtended.cpp", "Ed25519.cpp",
  "BlsG1.cpp", "WalletNetworks.cpp", "WalletCatalog.cpp", "WalletTokens.cpp",
  "CosmosTransaction.cpp", "StellarTransaction.cpp",
  "ChainCommon.cpp", "ChainTransaction.cpp", "VeChainTransaction.cpp",
  "IconTransaction.cpp", "PolkadotTransaction.cpp", "SuiTransaction.cpp", "FilecoinTransaction.cpp", "TonCell.cpp",
  "TonTransaction.cpp", "DecredTransaction.cpp", "CkbTransaction.cpp", "HiveTransaction.cpp", "CardanoDerivation.cpp", "CardanoTransaction.cpp", "HederaTransaction.cpp", "SiaTransaction.cpp", "NemTransaction.cpp", "IcpTransaction.cpp", "ErgoTransaction.cpp", "Clvm.cpp", "ChiaTransaction.cpp", "BlsG2.cpp", "WalletEngine.cpp", "QrlXmss.cpp",
  "AlgorandTransaction.cpp", "NearTransaction.cpp", "TezosTransaction.cpp",
  "CryptoNoteAddress.cpp", "CryptoNoteRingCt.cpp", "CryptoNoteAmounts.cpp",
  "CryptoNoteTransaction.cpp", "CryptoNoteBulletproofPlus.cpp",
  "CryptoNoteSpend.cpp", "CryptoNoteReview.cpp",
  "WalletCustody.cpp", "SecureElementPort.cpp", "host_security.cpp"
)
$catalogObjs = @()
foreach ($s in $catalogSources) {
  $src = Join-Path $root $s
  if (-not (Test-Path $src)) { $src = Join-Path $PSScriptRoot $s }
  $obj = Join-Path $objDir ("cat_" + ($s -replace '\.cpp$', '.obj'))
  & cl @common /std:c++17 /EHsc /utf-8 /c $src "/Fo$obj"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  $catalogObjs += $obj
}
& cl @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot "catalog_dump.cpp") "/Fo$objDir\catalog_dump.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cl @common "/Fe$(Join-Path $PSScriptRoot 'catalog_dump.exe')" $catalogObjs "$objDir\catalog_dump.obj" (Join-Path $objDir "mbedtls_host.obj") /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Independent BP+ fixture consumer (links only wallet objects).
$probeObjs = @($cppObjs | Where-Object { (Split-Path $_ -Leaf) -ne 'host_test_main.obj' })
& cl @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot 'bp_plus_probe.cpp') "/Fo$objDir/bp_plus_probe.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cl @common "/Fe$(Join-Path $PSScriptRoot 'bp_plus_probe.exe')" $probeObjs "$objDir/bp_plus_probe.obj" "$objDir/mbedtls_host.obj" /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& cl @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot 'solana_probe.cpp') "/Fo$objDir/solana_probe.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cl @common "/Fe$(Join-Path $PSScriptRoot 'solana_probe.exe')" $probeObjs "$objDir/solana_probe.obj" "$objDir/mbedtls_host.obj" /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& cl @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot 'tron_probe.cpp') "/Fo$objDir/tron_probe.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cl @common "/Fe$(Join-Path $PSScriptRoot 'tron_probe.exe')" $probeObjs "$objDir/tron_probe.obj" "$objDir/mbedtls_host.obj" /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& cl @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot 'cosmos_probe.cpp') "/Fo$objDir/cosmos_probe.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cl @common "/Fe$(Join-Path $PSScriptRoot 'cosmos_probe.exe')" $probeObjs "$objDir/cosmos_probe.obj" "$objDir/mbedtls_host.obj" /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

foreach ($probe in @('algorand_probe', 'near_probe', 'tezos_probe', 'totp_probe', 'xrp_probe')) {
  & cl @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot "$probe.cpp") "/Fo$objDir/$probe.obj"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  & cl @common "/Fe$(Join-Path $PSScriptRoot "$probe.exe")" $probeObjs "$objDir/$probe.obj" "$objDir/mbedtls_host.obj" /link
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

& cl @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot 'stellar_probe.cpp') "/Fo$objDir/stellar_probe.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cl @common "/Fe$(Join-Path $PSScriptRoot 'stellar_probe.exe')" $probeObjs "$objDir/stellar_probe.obj" "$objDir/mbedtls_host.obj" /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $out
exit $LASTEXITCODE

