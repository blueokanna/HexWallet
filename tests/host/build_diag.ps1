# One-off: build and run tests/host/diag.exe (diagnostic harness).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ps = $PSScriptRoot
# mbedtls headers come from the ESP32 Arduino core's esp32-libs tool.  CI sets
# HEXWALLET_ESP32_LIBS to the esp32-libs tool's "include\mbedtls" directory;
# locally we fall back to the default Arduino15 install location.
$defaultEspLibs = "C:\Users\blueo\AppData\Local\Arduino15\packages\esp32\tools\esp32-libs\3.3.10\include\mbedtls"
$espLibs = if ($env:HEXWALLET_ESP32_LIBS -and (Test-Path $env:HEXWALLET_ESP32_LIBS)) {
  $env:HEXWALLET_ESP32_LIBS
} else {
  $defaultEspLibs
}
$mbedtlsInclude = Join-Path $espLibs "mbedtls\include"
$mbedtlsPort   = Join-Path $espLibs "port\include"

$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstall) { throw "Visual Studio with the C++ toolset was not found." }
$vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
  if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
}

$common = @(
  "/nologo", "/O2", "/W3",
  "/D_CRT_SECURE_NO_WARNINGS",
  "/DMBEDTLS_ALLOW_PRIVATE_ACCESS",
  "/I$ps", "/I$root", "/I$mbedtlsInclude", "/I$mbedtlsPort"
)

$sources = @(
  "diag.cpp", "mbedtls_host.c",
  "CryptoPrimitives.cpp", "CryptoExtended.cpp", "Ed25519.cpp", "BlsG1.cpp",
  "base58.cpp", "local_bech32.cpp", "local_segwit.cpp", "keccak256.cpp",
  "local_ripemd160.cpp", "WalletAddresses.cpp", "WalletAltAddresses.cpp",
  "host_security.cpp"
)
$files = foreach ($s in $sources) {
  $p = Join-Path $ps $s
  if (-not (Test-Path $p)) { $p = Join-Path $root $s }
  $p
}
New-Item -ItemType Directory -Force -Path (Join-Path $ps "obj") | Out-Null
& cl @common /std:c++17 /EHsc /utf-8 "/Fo$ps\obj\" "/Fe$ps\diag.exe" $files /link
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& "$ps\diag.exe"
exit $LASTEXITCODE
