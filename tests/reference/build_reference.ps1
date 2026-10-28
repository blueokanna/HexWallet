$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'fetch_reference.ps1')
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$work = Join-Path $root 'build/monero-reference'
$adapter = Join-Path $PSScriptRoot 'adapter'
$vswhere = 'C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe'
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'MSVC C++ tools required' }
$vcvars = Join-Path $vs 'VC/Auxiliary/Build/vcvars64.bat'
cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
  if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
}
Push-Location $work
try {
  $flags=@('/nologo','/O2','/W3','/D_CRT_SECURE_NO_WARNINGS',"/I$adapter",'/Isrc','/Isrc/ringct','/Icontrib/epee/include')
  & cl @flags /std:c11 /c src/crypto/crypto-ops.c src/crypto/crypto-ops-data.c src/crypto/keccak.c
  if($LASTEXITCODE -ne 0) { throw 'Reference C compilation failed' }
  & cl @flags /std:c++17 /EHsc (Join-Path $PSScriptRoot 'monero_reference.cpp') src/ringct/multiexp.cc crypto-ops.obj crypto-ops-data.obj keccak.obj /Femonero_reference.exe
  if($LASTEXITCODE -ne 0) { throw 'Reference C++ compilation failed' }
} finally { Pop-Location }
