# Development PC only. Uses the pinned upstream executable, never wallet code.
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'build_reference.ps1')
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root 'build/monero-reference/monero_reference.exe'
$out = Join-Path $root 'tests/fixtures/monero-bp-plus'
New-Item -ItemType Directory -Force $out | Out-Null
$manifest = [ordered]@{
  source = 'monero-project/monero'
  version = 'v0.18.4.0'
  commit = 'f1311d4237404ab7da76241dbf10e92a65132cc4'
  generator = 'tests/reference/monero_reference.cpp'
  randomness = 'Public deterministic skGen adapter: Keccak(label || decimal counter), reduced mod l. Counter resets per process. TEST ONLY.'
  cases = @()
}
foreach ($count in @(1,2,3,4,5,8,9,16)) {
  $rows = & $exe $count
  if ($LASTEXITCODE -ne 0) { throw "Upstream proof failed: $count" }
  $data = [ordered]@{}
  $generators = [ordered]@{}
  foreach ($line in $rows) {
    $pair = $line -split '=',2
    if ($pair.Count -ne 2) { throw "Malformed output: $line" }
    if($pair[0].StartsWith('generator_')) { $generators[$pair[0]]=$pair[1] }
    else { $data[$pair[0]]=$pair[1] }
  }
  if($data.accepted -ne '1') { throw 'Upstream rejected generated proof' }
  $proof = @("$count $($data.rounds)")
  for($i=0;$i -lt $count;$i++) { $proof += $data["V_$i"] }
  foreach($field in @('A','A1','B','r1','s1','d1')) { $proof += $data[$field] }
  foreach($field in @('L','R')) { for($i=0;$i -lt [int]$data.rounds;$i++) { $proof += $data["${field}_$i"] } }
  $name="outputs-$count"
  [IO.File]::WriteAllText((Join-Path $out "$name.txt"),($proof -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText((Join-Path $out "$name.json"),($data | ConvertTo-Json -Depth 3)+"`n",[Text.UTF8Encoding]::new($false))
  $manifest.cases += @{name=$name;expected='accept';count=$count;proof_sha256=(Get-FileHash (Join-Path $out "$name.txt")).Hash.ToLowerInvariant();trace_sha256=(Get-FileHash (Join-Path $out "$name.json")).Hash.ToLowerInvariant()}
  if($count -eq 16) { [IO.File]::WriteAllText((Join-Path $out 'generators.json'),($generators | ConvertTo-Json)+"`n",[Text.UTF8Encoding]::new($false)) }
}
$manifest.generators_sha256=(Get-FileHash (Join-Path $out 'generators.json')).Hash.ToLowerInvariant()
$manifest.reference_sources_sha256=[ordered]@{}
$sources=@(Get-ChildItem (Join-Path $PSScriptRoot 'adapter') -Recurse -File) +
  @(Get-Item (Join-Path $PSScriptRoot 'monero_reference.cpp'),(Join-Path $PSScriptRoot 'monero-reference.json'))
foreach($source in $sources | Sort-Object FullName) {
  $relative=$source.FullName.Substring($root.Length+1).Replace('\','/')
  $manifest.reference_sources_sha256[$relative]=(Get-FileHash $source.FullName).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText((Join-Path $out 'manifest.json'),($manifest | ConvertTo-Json -Depth 5)+"`n",[Text.UTF8Encoding]::new($false))
Write-Host 'Independent BP+ fixtures generated and accepted by pinned upstream verifier.'
