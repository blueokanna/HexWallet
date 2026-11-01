param(
  [string]$Catalog = 'tests/host/catalog_dump.exe',
  [string]$Output = 'docs/native-chain-capabilities.md'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$binary = Join-Path $root $Catalog
if (!(Test-Path -LiteralPath $binary)) { throw 'Build tests/host/build.ps1 before generating coverage.' }
$raw = & $binary --native
if ($LASTEXITCODE -ne 0) { throw 'Resolved catalog export failed.' }
$rows = @($raw | ForEach-Object {
  $fields = $_ -split '\|', 7
  if ($fields.Count -ne 7) { throw "Invalid catalog record: $_" }
  [pscustomobject]@{ Id=$fields[0]; Symbol=$fields[1]; Name=$fields[2]; Caps=[int]$fields[3];
    Network=$fields[4]; Domain=$fields[5]; Scope=$fields[6] }
})
if ($rows.Count -eq 0 -or @($rows.Id | Select-Object -Unique).Count -ne $rows.Count) {
  throw 'Empty catalog or duplicate network IDs.'
}
$groups = @($rows | Group-Object Domain | Sort-Object Name)
$signing = @($groups | Where-Object { @($_.Group | Where-Object { ($_.Caps -band 4) -ne 0 }).Count -gt 0 }).Count
$lines = @('# Native network capabilities', '',
  'Generated from the compiled, resolved catalog by `tools/native_coverage.ps1`. No token contract registry is read.', '',
  "Profiles: $($rows.Count). Distinct execution/address domains: $($groups.Count). Domains with a signing-code claim: $signing.", '',
  'EVM domains use chain ID; Bitcoin-family address variants merge when coin type and both Base58 versions agree (legacy rows may omit the SegWit HRP). Other adapters keep their explicit network IDs. These are conservative catalog groups, not independently attested chain identities. A domain is not necessarily an independent L1 or a distinct native coin: for example, several rollups use ETH.', '',
  '**SIGN means a registered code path, not complete protocol support, node acceptance or hardware certification.** Production custody, display and boot policies still apply. ADDRESS has no admitted signing path.', '',
  '| Domain | Profiles | Native asset | Code capability | Implemented scope |',
  '| --- | --- | --- | --- | --- |')
foreach ($group in $groups) {
  $entries = $group.Group
  $symbols = @($entries.Symbol | Sort-Object -Unique) -join ', '
  $ids = @($entries.Id | Sort-Object) -join ', '
  $cap = if (@($entries | Where-Object { ($_.Caps -band 4) -ne 0 }).Count) { 'SIGN' } else { 'ADDRESS' }
  $scope = (@($entries.Scope | Sort-Object -Unique) -join '; ').Replace('|', '\|')
  $lines += "| $($group.Name) | $ids | $symbols | $cap | $scope |"
}
[IO.File]::WriteAllLines((Join-Path $root $Output), $lines, (New-Object Text.UTF8Encoding $false))
Write-Output "native coverage: $($rows.Count) profiles, $($groups.Count) domains, $signing signing-code claims"
