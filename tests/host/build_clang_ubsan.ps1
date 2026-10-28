# Diagnostic build: compiles the host self-test suite with clang-cl + UBSan to
# surface any undefined behavior in the crypto code that MSVC's /O2 tolerates
# but other optimizers expose. NOT part of CI; run manually:
#   powershell -ExecutionPolicy Bypass -File tests/host/build_clang_ubsan.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot "esp32_paths.ps1")
$espLibs = $espLibsRoot
$mbedtlsInclude = Join-Path $espLibs "include\mbedtls\mbedtls\include"
$mbedtlsPort   = Join-Path $espLibs "include\mbedtls\port\include"

$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstall) { throw "Visual Studio with the C++ toolset was not found." }
$vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
  if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
}

$clangCommand = Get-Command clang-cl.exe -ErrorAction SilentlyContinue
$vsClang = Join-Path $vsInstall 'VC/Tools/Llvm/x64/bin/clang-cl.exe'
$clang = if ($env:HEXWALLET_CLANG) { $env:HEXWALLET_CLANG } elseif (Test-Path $vsClang) { $vsClang } elseif ($clangCommand) { $clangCommand.Source } else { '' }
if (-not (Test-Path $clang)) { throw "clang-cl not found (set HEXWALLET_CLANG)" }

$out = Join-Path $PSScriptRoot "host_test_clang.exe"
$objDir = Join-Path $PSScriptRoot "obj-clang"
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

$common = @(
  "/nologo", "/O2", "/W3", "-m64",
  "-fsanitize=undefined", "-fno-sanitize-recover=all",
  "/D_CRT_SECURE_NO_WARNINGS", "/DHEXWALLET_HOST_TEST=1",
  "/DMBEDTLS_ALLOW_PRIVATE_ACCESS",
  "/DHEXWALLET_ENABLE_LVGL=0",
  "/I$PSScriptRoot", "/I$root", "/I$mbedtlsInclude", "/I$mbedtlsPort"
)

& $clang @common /std:c11 /c (Join-Path $PSScriptRoot "mbedtls_host.c") "/Fo$objDir\mbedtls_host.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$cppSources = @(
  "CryptoPrimitives.cpp",
  "SolanaTransaction.cpp",
  "TronTransaction.cpp",
  "CosmosTransaction.cpp", "StellarTransaction.cpp",
  "AlgorandTransaction.cpp", "ChainCommon.cpp", "ChainTransaction.cpp", "VeChainTransaction.cpp", "IconTransaction.cpp", "PolkadotTransaction.cpp", "SuiTransaction.cpp", "FilecoinTransaction.cpp", "TonCell.cpp", "TonTransaction.cpp", "DecredTransaction.cpp", "CkbTransaction.cpp", "HiveTransaction.cpp", "CardanoDerivation.cpp", "CardanoTransaction.cpp", "HederaTransaction.cpp", "SiaTransaction.cpp", "NemTransaction.cpp", "IcpTransaction.cpp", "ErgoTransaction.cpp", "Clvm.cpp", "ChiaTransaction.cpp", "BlsG2.cpp", "NearTransaction.cpp", "TezosTransaction.cpp", "XrpTransaction.cpp", "Totp.cpp", "EinkFrame.cpp", "WalletEngine.cpp",
  "WalletLinkCrypto.cpp", "WalletLink.cpp", "WalletNfcApdu.cpp",
  "Blake2b.cpp", "Blake256.cpp", "CryptoExtended.cpp", "Ed25519.cpp", "BlsG1.cpp",
  "base58.cpp", "local_bech32.cpp", "local_segwit.cpp", "keccak256.cpp",
  "local_ripemd160.cpp", "WalletAddresses.cpp", "WalletAltAddresses.cpp",
  "WalletNetworks.cpp", "WalletCatalog.cpp", "WalletMiningCatalog.cpp", "WalletTokens.cpp",
  "CryptoNoteAddress.cpp", "CryptoNoteRingCt.cpp", "CryptoNoteAmounts.cpp", "CryptoNoteOutputScan.cpp", "CryptoNoteTransaction.cpp", "CryptoNoteSpend.cpp", "CryptoNoteBulletproofPlus.cpp", "CryptoNoteReview.cpp", "CryptoNoteSigning.cpp", "CryptoNoteMasari.cpp", "QrlXmss.cpp", "WalletCustody.cpp", "SecureElementPort.cpp", "RandomSource.cpp",
  "KaspaTransaction.cpp", "TokenCalldata.cpp", "ZcashTransaction.cpp",
  "BitcoinTransaction.cpp",
  "host_security.cpp", "host_test_main.cpp"
)
$cppObjs = @()
foreach ($s in $cppSources) {
  $src = Join-Path $root $s
  if (-not (Test-Path $src)) { $src = Join-Path $PSScriptRoot $s }
  $obj = Join-Path $objDir ($s -replace '\.cpp$', '.obj')
  & $clang @common /std:c++17 /EHsc /utf-8 /c $src "/Fo$obj"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  $cppObjs += $obj
}

& $clang @common "/Fe$out" $cppObjs (Join-Path $objDir "mbedtls_host.obj") /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $clang @common /std:c++17 /EHsc /utf-8 (Join-Path $root 'WalletWorkerExecution.cpp') (Join-Path $PSScriptRoot 'worker_execution_test.cpp') "/Fo$objDir/" "/Fe$(Join-Path $PSScriptRoot 'worker_execution_test.exe')"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot 'worker_execution_test.exe')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $out
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$probeObjs = @($cppObjs | Where-Object { (Split-Path $_ -Leaf) -ne 'host_test_main.obj' })
& $clang @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot 'solana_probe.cpp') "/Fo$objDir/solana_probe.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $clang @common "/Fe$(Join-Path $PSScriptRoot 'solana_probe_clang.exe')" $probeObjs "$objDir/solana_probe.obj" "$objDir/mbedtls_host.obj" /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $clang @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot 'tron_probe.cpp') "/Fo$objDir/tron_probe.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $clang @common "/Fe$(Join-Path $PSScriptRoot 'tron_probe_clang.exe')" $probeObjs "$objDir/tron_probe.obj" "$objDir/mbedtls_host.obj" /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $clang @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot 'cosmos_probe.cpp') "/Fo$objDir/cosmos_probe.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $clang @common "/Fe$(Join-Path $PSScriptRoot 'cosmos_probe_clang.exe')" $probeObjs "$objDir/cosmos_probe.obj" "$objDir/mbedtls_host.obj" /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $clang @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot 'stellar_probe.cpp') "/Fo$objDir/stellar_probe.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $clang @common "/Fe$(Join-Path $PSScriptRoot 'stellar_probe_clang.exe')" $probeObjs "$objDir/stellar_probe.obj" "$objDir/mbedtls_host.obj" /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
foreach ($probe in @('algorand_probe', 'near_probe', 'tezos_probe', 'totp_probe')) {
  & $clang @common /std:c++17 /EHsc /utf-8 /c (Join-Path $PSScriptRoot "$probe.cpp") "/Fo$objDir/$probe.obj"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  & $clang @common "/Fe$(Join-Path $PSScriptRoot "${probe}_clang.exe")" $probeObjs "$objDir/$probe.obj" "$objDir/mbedtls_host.obj" /link
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

exit $LASTEXITCODE

