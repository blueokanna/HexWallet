# Diagnostic build: compiles the host self-test suite with clang-cl + UBSan to
# surface any undefined behavior in the crypto code that MSVC's /O2 tolerates
# but other optimizers expose. NOT part of CI; run manually:
#   powershell -ExecutionPolicy Bypass -File tests/host/build_clang_ubsan.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$espLibs = "C:\Users\blueo\AppData\Local\Arduino15\packages\esp32\tools\esp32-libs\3.3.10\include\mbedtls"
$mbedtlsInclude = Join-Path $espLibs "mbedtls\include"
$mbedtlsPort   = Join-Path $espLibs "port\include"

$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstall) { throw "Visual Studio with the C++ toolset was not found." }
$vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
  if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
}

$clang = Get-ChildItem (Join-Path $vsInstall "VC\Tools\Llvm\bin\clang-cl.exe") -ErrorAction SilentlyContinue
if (-not $clang) { throw "clang-cl not found" }

$out = Join-Path $PSScriptRoot "host_test_clang.exe"
$objDir = Join-Path $PSScriptRoot "obj-clang"
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

$common = @(
  "/nologo", "/O2", "/W3", "/GS-", "-m64",
  "/D_CRT_SECURE_NO_WARNINGS",
  "/DMBEDTLS_ALLOW_PRIVATE_ACCESS",
  "/I$PSScriptRoot", "/I$root", "/I$mbedtlsInclude", "/I$mbedtlsPort"
)

& $clang @common /std:c11 /c (Join-Path $PSScriptRoot "mbedtls_host.c") "/Fo$objDir\mbedtls_host.obj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$cppSources = @(
  "CryptoPrimitives.cpp", "CryptoExtended.cpp", "Ed25519.cpp", "BlsG1.cpp",
  "base58.cpp", "local_bech32.cpp", "local_segwit.cpp", "keccak256.cpp",
  "local_ripemd160.cpp", "WalletAddresses.cpp", "WalletAltAddresses.cpp",
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

& $out
exit $LASTEXITCODE
