# Firmware policy gates. Pure PowerShell so the repository has one toolchain:
# Arduino/xtensa for the device, MSVC or clang for host tests, PowerShell for
# the build and these checks. Wire this into CI and run it before flashing.
#
#   powershell -ExecutionPolicy Bypass -File tests/host/policy_check.ps1
#
# Covered here because they must not depend on a test runtime:
#   1. no GRAVEYARD identity in any registry that can reach a user
#   2. withdrawn chains stay withdrawn
#   3. the mining table only points at catalog entries that actually ship
#   4. the firmware does not include a network stack
#   5. the production policy binary refuses to open a wallet without a
#      secure-element backend
param(
  [string]$ProductionPolicy = "build/chain-native/Release/production_policy.exe",
  [switch]$RegistryOnly
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$failures = New-Object System.Collections.Generic.List[string]

function Fail([string]$message) {
  $failures.Add($message)
}

function Read-Text([string]$relative) {
  $path = Join-Path $root $relative
  if (-not (Test-Path $path)) { throw "missing required file: $relative" }
  return [System.IO.File]::ReadAllText($path)
}

# ---------------------------------------------------------------------------
# 1 + 2. GRAVEYARD identities
# ---------------------------------------------------------------------------
$snapshotPath = Join-Path $root "tools/miningpoolstats_graveyard.json"
if (-not (Test-Path $snapshotPath)) { throw "missing graveyard snapshot" }
$snapshot = Get-Content -Raw -Path $snapshotPath | ConvertFrom-Json
if ($snapshot.exceptions.Count -ne 0) {
  Fail "graveyard policy must not carry per-coin exceptions"
}
$graveyard = @{}
foreach ($coin in $snapshot.coins.PSObject.Properties) {
  $key = ($coin.Value.n.Trim().ToLowerInvariant()) + "|" + ($coin.Value.s.ToUpperInvariant())
  $graveyard[$key] = $true
}
if ($graveyard.Count -lt 100) {
  Fail "graveyard snapshot parsed only $($graveyard.Count) identities; refusing to treat that as clean"
}
if (-not $graveyard.ContainsKey("flux|FLUX")) {
  Fail "graveyard snapshot no longer lists Flux; the snapshot may be stale or truncated"
}

# nameIndex/symbolIndex select the display name and ticker of each row layout.
$registries = @(
  @{ File = "WalletNetworks.cpp";                     Name = 2; Symbol = 1; Catalog = $false },
  @{ File = "WalletCatalog.cpp";                      Name = 2; Symbol = 1; Catalog = $true },
  @{ File = "src/generated/WalletForkCatalog.inc";    Name = 2; Symbol = 1; Catalog = $true },
  @{ File = "src/generated/WalletForkProfiles.inc";   Name = 2; Symbol = 1; Catalog = $false },
  @{ File = "src/generated/WalletMiningCatalog.inc";  Name = 1; Symbol = 0; Catalog = $false }
)

$catalogIds = @{}
foreach ($registry in $registries) {
  $text = Read-Text $registry.File
  foreach ($line in ($text -split "`n")) {
    $trimmed = $line.Trim()
    if (-not $trimmed.StartsWith("{")) { continue }
    $fields = [regex]::Matches($line, '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value }
    if ($fields.Count -le [Math]::Max($registry.Name, $registry.Symbol)) { continue }
    $identity = $fields[$registry.Name].Trim().ToLowerInvariant() + "|" + $fields[$registry.Symbol].ToUpperInvariant()
    if ($graveyard.ContainsKey($identity)) {
      Fail "$($registry.File): graveyard identity listed -> $($line.Trim())"
    }
    if ($registry.Catalog) {
      $catalogIds[$fields[0]] = $true
    }
  }
}

$forkRegistry = Get-Content -Raw -Path (Join-Path $root "tools/fork_registry.json") | ConvertFrom-Json
foreach ($row in $forkRegistry.profiles) {
  $identity = $row.name.Trim().ToLowerInvariant() + "|" + $row.symbol.ToUpperInvariant()
  if ($graveyard.ContainsKey($identity)) {
    Fail "tools/fork_registry.json: graveyard identity '$($row.network)'"
  }
}

foreach ($forbidden in @('"msr", "MSR", "Masari"', '{"flux",', '{"qubic",', '"flux", SighashFamily', '0x76b809bb')) {
  if ((Read-Text "WalletNetworks.cpp").Contains($forbidden)) {
    Fail "WalletNetworks.cpp still contains withdrawn chain marker: $forbidden"
  }
}
if ((Read-Text "WalletCatalog.cpp").Contains('"flux", "FLUX"')) {
  Fail "WalletCatalog.cpp still lists FLUX"
}
if ((Read-Text "src/generated/WalletMiningCatalog.inc").Contains('"FLUX"')) {
  Fail "mining catalog still lists FLUX"
}

# ---------------------------------------------------------------------------
# 3. Mining rows must resolve to a shipped catalog entry
# ---------------------------------------------------------------------------
foreach ($line in ((Read-Text "src/generated/WalletMiningCatalog.inc") -split "`n")) {
  $trimmed = $line.Trim()
  if (-not $trimmed.StartsWith("{")) { continue }
  $fields = [regex]::Matches($line, '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value }
  $catalogId = $fields[$fields.Count - 1]
  if (-not $catalogIds.ContainsKey($catalogId)) {
    Fail "mining row points at a catalog id that is not shipped: $catalogId"
  }
}

# ---------------------------------------------------------------------------
# 4. No network stack in the firmware
# ---------------------------------------------------------------------------
$networkInclude = [regex]'(?m)^\s*#\s*include\s*[<"](WiFi|HTTPClient|Ethernet|WebServer|WiFiClient|WiFiUdp|HTTPUpdate|WebSocket|NetworkClient|NetworkUdp|esp_http_client|esp_http_server|esp_https_ota|esp_wifi|esp_netif|esp_tls|mbedtls/ssl|lwip/)'
$firmware = @(Get-ChildItem -LiteralPath $root -File) +
            @(Get-ChildItem -LiteralPath (Join-Path $root 'src') -File -Recurse)
foreach ($file in $firmware) {
  if ($file.Extension -notin @('.c', '.cpp', '.h', '.hpp', '.ino', '.inc')) { continue }
  if ($networkInclude.IsMatch([System.IO.File]::ReadAllText($file.FullName))) {
    Fail "network stack included in firmware: $($file.FullName)"
  }
}

# ---------------------------------------------------------------------------
# 5. Secret material never reaches an output path
# ---------------------------------------------------------------------------
# The seed phrase is the asset. These checks keep that property structural
# rather than a habit: the export switch must stay off, and no firmware source
# may print a mnemonic, private key, chain code or raw entropy.
$config = Read-Text "WalletConfig.h"
if ($config -notmatch '(?m)^#define HEXWALLET_ENABLE_SECRET_EXPORT 0\s*$') {
  Fail "HEXWALLET_ENABLE_SECRET_EXPORT must default to 0 in WalletConfig.h"
}
$secretPrint = [regex]'(Serial\.print|printf|puts)\s*\([^;]*\b(mnemonic|private_key|chain_code|seed_words|master_seed|entropy)\b'
foreach ($file in $firmware) {
  if ($file.Extension -notin @('.c', '.cpp', '.h', '.hpp', '.ino')) { continue }
  $lines = [System.IO.File]::ReadAllLines($file.FullName)
  for ($index = 0; $index -lt $lines.Length; ++$index) {
    if ($secretPrint.IsMatch($lines[$index])) {
      Fail "secret-bearing value printed: $($file.Name):$($index + 1)"
    }
  }
}
# Host mnemonic import and secret export must stay behind the disabled switch.
$cli = Read-Text "WalletCli.cpp"
foreach ($guard in @('ERR host-mnemonic-import-disabled', 'ERR secret-export-disabled')) {
  if ($cli.IndexOf($guard, [System.StringComparison]::Ordinal) -lt 0) {
    Fail "WalletCli.cpp must keep the '$guard' refusal"
  }
}
# Turning the switch on must stay a compile error, not a runtime flag.
if ($config -notmatch '(?s)#if HEXWALLET_ENABLE_SECRET_EXPORT\s*\r?\n\s*#error "Secret export is not supported by this wallet\."') {
  Fail "WalletConfig.h must keep the compile-time refusal of secret export"
}

# ---------------------------------------------------------------------------
# 6. Production policy binary
# ---------------------------------------------------------------------------
$policyPath = Join-Path $root $ProductionPolicy
if ($RegistryOnly) {
  Write-Output 'registry-only: production custody executable NOT verified'
} elseif (Test-Path $policyPath) {
  $output = & $policyPath 2>&1
  $code = $LASTEXITCODE
  if ($code -ne 0 -or ($output -join "`n") -notmatch 'production_policy=pass') {
    Fail "production_policy.exe failed: $($output -join ' ')"
  }
} else {
  Fail "$ProductionPolicy not built; run tests/host/build_chain_native.ps1 or explicitly use -RegistryOnly for partial validation"
}

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
if ($failures.Count -ne 0) {
  foreach ($failure in $failures) { Write-Output "FAIL $failure" }
  Write-Output "policy: $($failures.Count) failure(s)"
  exit 1
}
$scope = if ($RegistryOnly) { 'registry-policy' } else { 'policy' }
Write-Output "graveyard-identities=$($graveyard.Count) registries=$($registries.Count) $scope=pass"
exit 0
