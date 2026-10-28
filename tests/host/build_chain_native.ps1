param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $root
try {
  $expected = 'e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df'
  if (-not (Test-Path -LiteralPath 'build/chain-mbedtls/CMakeLists.txt')) {
    throw 'Clone Mbed-TLS/mbedtls tag mbedtls-3.6.5 with --recurse-submodules into build/chain-mbedtls first (see docs/sui-filecoin-signing.md).'
  }
  $actual = git -C build/chain-mbedtls rev-parse HEAD
  if ($LASTEXITCODE -ne 0 -or $actual -ne $expected) { throw 'Unexpected Mbed TLS revision' }
  $pythonPath = (Get-Command $Python -ErrorAction Stop).Source
  cmake -S tests/host/chain -B build/chain-native -A x64 "-DPython3_EXECUTABLE=$pythonPath"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  cmake --build build/chain-native --config Release --parallel 4
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  & $pythonPath -m unittest discover -s tests -p test_chain_adapters.py
  exit $LASTEXITCODE
} finally { Pop-Location }
