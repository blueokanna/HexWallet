# Compares the in-tree QR encoder against an independent implementation.
#
# run_qr_code_self_tests() proves the encoder and its own reader agree; it cannot
# prove a scanner would accept the symbol. This check compiles QrCode.cpp and
# nayuki/QR-Code-generator (pinned commit) into one binary and compares every
# module of versions 1-10 x levels L/M/Q/H x masks 0-7 against it.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tests/host/qr_cross_check.ps1
#
# Requires: Visual Studio 2022 (cl.exe) and network access on the first run to
# fetch the reference into build/qr-reference.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$reference = Join-Path $root "build\qr-reference"
$referenceCommit = "3c6d0b3cefb4e049dc337e82237c9644399716a8"

$vsInstall = if ($env:HEXWALLET_VS_INSTALL) { $env:HEXWALLET_VS_INSTALL }
             else { "C:\Program Files\Microsoft Visual Studio\2022\Community" }
$vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
  Write-Output "ERROR: vcvars64.bat not found at $vcvars"
  exit 2
}

$referenceCpp = Join-Path $reference "cpp\qrcodegen.cpp"
if (-not (Test-Path $referenceCpp)) {
  New-Item -ItemType Directory -Force -Path $reference | Out-Null
  if (-not (Test-Path (Join-Path $reference ".git"))) {
    cmd /c "git -C `"$reference`" init --quiet" | Out-Null
  }
  cmd /c "git -C `"$reference`" fetch --depth 1 https://github.com/nayuki/QR-Code-generator.git $referenceCommit" | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Write-Output "ERROR: failed to fetch the reference QR encoder"
    exit 1
  }
  cmd /c "git -C `"$reference`" checkout --detach FETCH_HEAD --quiet" | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Write-Output "ERROR: failed to check out the reference QR encoder"
    exit 1
  }
}

$outDir = Join-Path $PSScriptRoot "obj-qr"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$source = Join-Path $PSScriptRoot "qr_cross_check.cpp"
$exe = Join-Path $outDir "qr_cross_check.exe"
$log = Join-Path $outDir "build.log"
$command = "`"$vcvars`" >nul 2>&1 && cl /nologo /std:c++17 /EHsc /O2 " +
           "/I`"$root`" /I`"$reference\cpp`" `"$source`" `"$referenceCpp`" /Fe:`"$exe`" /Fo:`"$outDir\\`""
cmd /c $command *> $log
if ($LASTEXITCODE -ne 0) {
  Write-Output "QR CROSS CHECK: build failed"
  Get-Content $log | Select-Object -First 40 | ForEach-Object { Write-Output $_ }
  exit 1
}

& $exe
if ($LASTEXITCODE -ne 0) {
  Write-Output "QR CROSS CHECK: FAILED"
  exit 1
}
exit 0
