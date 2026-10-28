$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$check = Join-Path $PSScriptRoot 'policy_check.ps1'
$probe = Join-Path $root ('src/policy_probe_' + [guid]::NewGuid().ToString('N') + '.h')
try {
  # A nested Arduino source and an include after the first line both escaped
  # the previous check. Exercise the actual policy entry point, not a copy.
  [IO.File]::WriteAllText($probe, "// regression probe`n#include <Arduino.h>`n#include <WiFi.h>`n")
  $output = & powershell -ExecutionPolicy Bypass -File $check -RegistryOnly 2>&1
  if ($LASTEXITCODE -ne 1 -or ($output -join "`n") -notmatch 'network stack included in firmware:') {
    throw 'Network policy failed to reject a nested later-line include'
  }
} finally {
  if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe }
}
$output = & powershell -ExecutionPolicy Bypass -File $check -ProductionPolicy 'build/does-not-exist-policy.exe' 2>&1
if ($LASTEXITCODE -ne 1 -or ($output -join "`n") -notmatch 'not built') {
  throw 'Missing production binary was incorrectly accepted'
}
Write-Output 'policy-regressions=pass'
