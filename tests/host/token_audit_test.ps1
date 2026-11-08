# Offline fault injection for the live-audit gate. No RPC requests leave this test.
param([string]$Scenario)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not $Scenario) {
  $cases = @{
    valid = 0; dynamic = 0; wrong_network = 2; unreachable = 2;
    missing_code = 2; bad_envelope = 2; bad_offset = 2;
    malformed_decimals = 2; false_interface = 1; empty_selection = 1
  }
  $shell = (Get-Process -Id $PID).Path
  foreach ($case in $cases.GetEnumerator()) {
    $ErrorActionPreference = 'Continue'
    $output = & $shell -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Scenario $case.Key 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -ne $case.Value) { throw "token audit case $($case.Key): expected $($case.Value), got $code`n$output" }
    Write-Output "token-audit-$($case.Key)=pass"
  }
  exit 0
}

$records = @{}
$source = Get-Content -Raw (Join-Path $root 'WalletTokens.cpp')
$pattern = '\{\s*"([^"]+)",\s*"eth",\s*"([^"]+)",\s*"([^"]+)",\s*TokenStandard::(\w+),\s*"(0x[0-9a-fA-F]{40})",\s*(\d+),'
foreach ($match in [regex]::Matches($source, $pattern)) {
  $records[$match.Groups[5].Value] = @{
    symbol = $match.Groups[2].Value; name = $match.Groups[3].Value;
    decimals = [int]$match.Groups[6].Value
  }
}
if ($records.Count -eq 0) { throw 'No fixture records extracted' }

function Start-Sleep { param($Seconds, $Milliseconds) }
function Encode-Text([string]$text) {
  $raw = -join ([Text.Encoding]::UTF8.GetBytes($text) | ForEach-Object { '{0:x2}' -f $_ })
  if ($Scenario -in @('dynamic', 'bad_offset') -or $raw.Length -gt 64) {
    $offset = if ($Scenario -eq 'bad_offset') { 64 } else { 32 }
    return '0x' + ('{0:x64}' -f $offset) + ('{0:x64}' -f ($raw.Length / 2)) +
      $raw.PadRight([int][Math]::Ceiling($raw.Length / 64.0) * 64, '0')
  }
  return '0x' + $raw.PadRight(64, '0')
}
function Invoke-RestMethod {
  param($Method, $Uri, $ContentType, $Body, $TimeoutSec)
  if ($Scenario -eq 'unreachable') { throw 'Injected transport failure' }
  $request = $Body | ConvertFrom-Json
  $result = switch ($request.method) {
    eth_chainId { if ($Scenario -eq 'wrong_network') { '0x38' } else { '0x1' } }
    eth_getCode { if ($Scenario -eq 'missing_code') { '0x' } else { '0x60006000' } }
    eth_call {
      $call = $request.params[0]
      $row = $records[$call.to]
      if (-not $row) { throw 'Unexpected test contract' }
      switch ($call.data.Substring(0, 10)) {
        '0x95d89b41' { Encode-Text $row.symbol }
        '0x06fdde03' { Encode-Text $row.name }
        '0x313ce567' {
          if ($Scenario -eq 'malformed_decimals') { '0x06' }
          else { '0x' + ('{0:x64}' -f $row.decimals) }
        }
        '0x01ffc9a7' {
          $invalid = $call.data.Substring(10, 8) -eq 'ffffffff'
          $supported = -not $invalid -or $Scenario -eq 'false_interface'
          '0x' + ('0' * 63) + [int]$supported
        }
        default { throw 'Unexpected test method selector' }
      }
    }
    default { throw 'Unexpected JSON-RPC method' }
  }
  return [pscustomobject]@{
    jsonrpc = '2.0'; id = $(if ($Scenario -eq 'bad_envelope') { 7 } else { 1 }); result = $result
  }
}
$network = if ($Scenario -eq 'empty_selection') { 'nonexistent' } else { 'eth' }
& (Join-Path $root 'tools/token_audit.ps1') -Network $network -DelayMs 0 -TimeoutSeconds 1
exit $LASTEXITCODE
