$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $root
try {
  $expected = '2492c60788b47055994e5d123b02482202f38262'
  $actual = git -C build/qrl-oracle rev-parse HEAD
  if ($LASTEXITCODE -ne 0 -or $actual -ne $expected) { throw 'Wrong qrllib oracle revision' }
  git -C build/qrl-oracle diff --exit-code
  if ($LASTEXITCODE -ne 0) { throw 'Modified qrllib oracle' }
  cmake -S tests/host/qrl -B build/qrl-native -A x64
  if ($LASTEXITCODE -ne 0) { throw 'QRL oracle configure failed' }
  cmake --build build/qrl-native --config Release --parallel 1
  if ($LASTEXITCODE -ne 0) { throw 'QRL oracle build failed' }
  & build/qrl-native/Release/qrl_oracle.exe
  if ($LASTEXITCODE -ne 0) { throw 'QRL oracle comparison failed' }
} finally { Pop-Location }
