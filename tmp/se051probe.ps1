$ErrorActionPreference = "Stop"
Set-Location "d:\ArduinoProject\HexWallet"
. (Join-Path $PSScriptRoot "..\tests\host\esp32_paths.ps1")
$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object { if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] } }
$common = @("/nologo","/O2","/W3","/std:c++17","/EHsc","/utf-8","/D_CRT_SECURE_NO_WARNINGS","/DHEXWALLET_HOST_TEST=1","/DMBEDTLS_ALLOW_PRIVATE_ACCESS","/Itests/host","/I.","/I$mbedtlsInclude","/I$mbedtlsPort")
& cl @common tmp\se051_full_probe.cpp Se051Apdu.cpp Se051Curves.cpp CryptoPrimitives.cpp Ed25519.cpp keccak256.cpp local_ripemd160.cpp tests\host\host_security.cpp tests\host\mbedtls_host.c /Fe:tmp\se051_full_probe.exe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& tmp\se051_full_probe.exe
exit $LASTEXITCODE
