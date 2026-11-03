param([switch]$RefreshOracle)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
Push-Location $root
try {
  $fixture = Join-Path $PSScriptRoot 'vectors.txt'
  $fixtureHash = 'c9cc8ded1b77d0124bc10425b1d0e1aa4b6b84874ead3e5bd15b4b85411ae06d'
  if ($RefreshOracle) {
    $oracle = Join-Path $root 'build/pearl-oracle'
    $revision = git -C $oracle rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $revision -ne 'd7c517d267f10f5bcbbdc366f3e603942f9a5ab5') { throw 'Wrong Pearl oracle revision' }
    git -C $oracle diff --exit-code HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Modified Pearl oracle' }
    $go = Join-Path $root 'build/pearl-toolchain/go/bin/go.exe'
    if (!(Test-Path -LiteralPath $go)) { throw 'Install the pinned Go toolchain as described in README.md' }
    $env:GOPATH = Join-Path $root 'build/pearl-gopath'
    $env:GOCACHE = Join-Path $root 'build/pearl-gocache'
    $env:CGO_ENABLED = '0'
    $env:GOTOOLCHAIN = 'local'
    Push-Location $oracle
    try {
      & $go run (Join-Path $PSScriptRoot 'oracle/main.go') $fixture
      if ($LASTEXITCODE -ne 0) { throw 'Pearl oracle failed' }
    } finally { Pop-Location }
  }
  if ((Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash -ne $fixtureHash) { throw 'Pearl fixture hash mismatch' }
  $revision = git -C build/chain-mbedtls rev-parse HEAD
  if ($LASTEXITCODE -ne 0 -or $revision -ne 'e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df') { throw 'Wrong Mbed TLS revision' }
  $out = Join-Path $root 'build/pearl-audit'
  New-Item -ItemType Directory -Force $out | Out-Null
  $sources = @(Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Extension -in '.cpp','.h' })
  $sources += @(Get-ChildItem -LiteralPath (Join-Path $root 'src'),(Join-Path $root 'tests/host') -Recurse -File |
    Where-Object { $_.Extension -in '.cpp','.h','.c','.ps1','.go' -or $_.Name -eq 'CMakeLists.txt' })
  $sources += Get-Item -LiteralPath $fixture
  $before = @($sources | Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash)
  $before | ConvertTo-Json | Set-Content (Join-Path $out 'source-hashes.json')
  cmake -S tests/host/pearl_audit -B $out -A x64
  if ($LASTEXITCODE -ne 0) { throw 'Pearl audit configure failed' }
  cmake --build $out --config Release --target pearl_audit --parallel 4
  if ($LASTEXITCODE -ne 0) { throw 'Pearl audit build failed' }
  & (Join-Path $out 'Release/pearl_audit.exe') $fixture | Tee-Object -FilePath (Join-Path $out 'results.txt')
  $result = $LASTEXITCODE
  $after = @($sources | Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash)
  if (Compare-Object $before $after -Property Path,Hash) { throw 'Source changed during audit; re-run on a stable snapshot' }
  exit $result
} finally { Pop-Location }
