param([string]$Probe = 'build/chain-native/Release/chain_probe.exe')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$probe = Join-Path $root $Probe
if (!(Test-Path -LiteralPath $probe)) { throw 'Build the native chain probe first' }
$vectors = Get-Content -Raw (Join-Path $root 'tests/fixtures/evm-access-list.json') | ConvertFrom-Json
$checks = 0
foreach ($case in $vectors.valid) {
  $output = (& $probe eth $vectors.seed $case.unsigned 0) -join "`n"
  if ($LASTEXITCODE -ne 0) { throw "Valid transaction rejected: $($case.name): $output" }
  foreach ($expected in @("hash=$($case.hash)", "signed=$($case.signed)",
      "access_addresses=$($case.addresses)", "access_keys=$($case.keys)", "sender=$($vectors.sender)")) {
    if (($output -split "`n") -notcontains $expected) { throw "Oracle mismatch: $($case.name): $expected" }
  }
  $reviewStart = $output.IndexOf("access_keys=$($case.keys)`n") + "access_keys=$($case.keys)`n".Length
  $reviewEnd = $output.IndexOf('hash=', $reviewStart)
  if ($reviewEnd -lt $reviewStart -or $output.Substring($reviewStart, $reviewEnd - $reviewStart) -cne $case.review) {
    throw "Incomplete or altered review text: $($case.name)"
  }
  ++$checks
  $detailsStart = $output.IndexOf("BEGIN EVM DETAILS`n") + "BEGIN EVM DETAILS`n".Length
  $detailsEnd = $output.IndexOf("END EVM DETAILS`n", $detailsStart)
  if ($detailsEnd -lt $detailsStart -or $output.Substring($detailsStart, $detailsEnd - $detailsStart) -cne $case.details) {
    throw "Incomplete envelope/contract metadata: $($case.name)"
  }
  ++$checks
  foreach ($mutation in @('access-count', 'access-bytes', 'review', 'hash', 'payload', 'index',
      'type', 'call-owner', 'call-flags', 'nonce', 'unterminated-review', '8')) {
    $output = (& $probe eth $vectors.seed $case.unsigned 0 $mutation) -join "`n"
    if ($LASTEXITCODE -eq 0 -or $output -notmatch 'size=0' -or $output -notmatch 'zero=1' -or $output -notmatch 'guard=1') {
      # Empty-list payload bytes outside the signed length are intentionally ignored.
      if ($mutation -eq 'access-bytes' -and $case.addresses -eq 0) { continue }
      throw "Mutation accepted or output leaked: $($case.name)/${mutation}: $output"
    }
    ++$checks
  }
}
foreach ($case in $vectors.invalid) {
  $output = (& $probe eth $vectors.seed $case.unsigned 0) -join "`n"
  if ($LASTEXITCODE -eq 0) { throw "Malformed transaction accepted: $($case.name)" }
  ++$checks
}
foreach ($sample in ($vectors.valid | Where-Object name -match 'two-slots$')) {
  for ($length = 1; $length -lt $sample.unsigned.Length / 2; ++$length) {
    $output = & $probe eth $vectors.seed $sample.unsigned.Substring(0, $length * 2) 0
    if ($LASTEXITCODE -eq 0) { throw "Truncation accepted: $($sample.name)/$length" }
    ++$checks
  }
}
# Another EVM profile must not inherit type-1 admission by family alone.
$sample = $vectors.valid | Where-Object name -eq 'type1-empty'
foreach ($network in @('etc', 'bsc', 'avaxc', 'cro')) {
  $output = (& $probe $network $vectors.seed $sample.unsigned 0) -join "`n"
  if ($LASTEXITCODE -eq 0 -or ($output -split "`n") -notcontains 'error=4') {
    throw "Type-1 network policy not enforced: ${network}: $output"
  }
  ++$checks
}
Write-Output "evm-access-list=$checks checks passed (ethers $($vectors.version) oracle)"
