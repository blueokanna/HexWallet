$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
Push-Location $root
try {
  & (Join-Path $PSScriptRoot 'prepare.ps1')
  $out = Join-Path $root 'build/taproot-audit'
  New-Item -ItemType Directory -Force $out | Out-Null
  $revision = git -C build/chain-mbedtls rev-parse HEAD
  if ($LASTEXITCODE -ne 0 -or $revision -ne 'e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df') {
    throw 'Expected Mbed TLS 3.6.5 pinned revision'
  }
  # Concurrent implementation work must invalidate an audit, not silently change it.
  $sources = @(Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Extension -in '.cpp','.h' })
  $sources += @(Get-ChildItem -LiteralPath (Join-Path $root 'src'),(Join-Path $root 'tests/host') -Recurse -File |
    Where-Object { $_.Extension -in '.cpp','.h','.c','.ps1' -or $_.Name -eq 'CMakeLists.txt' })
  $before = @($sources | Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash)
  $before | ConvertTo-Json | Set-Content (Join-Path $out 'source-hashes.json')
  cmake -S tests/host/taproot_audit -B $out -A x64
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  cmake --build $out --config Release --target taproot_audit --parallel 4
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  & (Join-Path $out 'Release/taproot_audit.exe') (Join-Path $PSScriptRoot 'vectors.txt') | Tee-Object -FilePath (Join-Path $out 'results.txt')
  $result = $LASTEXITCODE
  $after = @($sources | Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash)
  if (Compare-Object $before $after -Property Path,Hash) {
    Write-Error 'Source changed during audit. Re-run after the implementation writer has stopped.'
    exit 2
  }
  exit $result
} finally { Pop-Location }
