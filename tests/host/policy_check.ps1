# Firmware policy gates. Pure PowerShell so the repository has one toolchain:
# Arduino/xtensa for the device, MSVC or clang for host tests, PowerShell for
# the build and these checks. Wire this into CI and run it before flashing.
#
#   powershell -ExecutionPolicy Bypass -File tests/host/policy_check.ps1
#
# Covered here because they must not depend on a test runtime:
#   1. no retired identity in any registry that can reach a user
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
# 1 + 2. Check the same pinned source snapshot used by the catalog generator.
$source = Get-Content -Raw -Encoding UTF8 -Path (Join-Path $root "tools/miningpoolstats_coin_list.json") | ConvertFrom-Json
$retired = @{}
$retiredIds = @{}
foreach ($coin in $source.GRAVEYARD.PSObject.Properties) {
  $key = $coin.Value.n.Trim().ToLowerInvariant() + "|" + $coin.Value.s.ToUpperInvariant()
  $retired[$key] = $true
  $retiredIds[$coin.Name] = $true
}
[string[]]$sortedKeys = $retired.Keys
[Array]::Sort($sortedKeys, [StringComparer]::Ordinal)
$hash = [Security.Cryptography.SHA256]::Create()
try {
  $digest = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(($sortedKeys -join "`n")))).Replace("-", "").ToLowerInvariant()
} finally { $hash.Dispose() }
if ($digest -ne "1472528b52f8ccc7fbfdc4976000f7312acaaac6e5d0341616362a191d60625d") { Fail "retired identity set differs from the reviewed snapshot" }

# nameIndex/symbolIndex select the display name and ticker of each row layout.
$registries = @(
  @{ File = "WalletNetworks.cpp";                     Name = 2; Symbol = 1; Catalog = $false },
  @{ File = "WalletCatalog.cpp";                      Name = 2; Symbol = 1; Catalog = $true },
  @{ File = "src/generated/WalletForkCatalog.inc";    Name = 2; Symbol = 1; Catalog = $true },
  @{ File = "src/generated/WalletForkProfiles.inc";   Name = 2; Symbol = 1; Catalog = $false },
  @{ File = "src/generated/WalletMiningCatalog.inc";  Name = 1; Symbol = 0; Catalog = $false }
)

$catalogIds = @{}
function Registry-Identity([string]$name, [string]$symbol) {
  # Address forms do not revive a retired chain under a suffixed display name.
  $base = $name.Trim() -replace '\s+(Native SegWit|Nested SegWit|Legacy)$', ''
  return $base.ToLowerInvariant() + '|' + $symbol.ToUpperInvariant()
}
function Test-RetiredIdentity([string]$name, [string]$symbol) {
  # A suffix such as a chain or address variant must not bypass a name/ticker match.
  while ($name) {
    if ($retired.ContainsKey((Registry-Identity $name $symbol))) { return $true }
    $split = $name.LastIndexOf(' ')
    if ($split -lt 0) { break }
    $name = $name.Substring(0,$split)
  }
  return $false
}
foreach ($registry in $registries) {
  $text = Read-Text $registry.File
  foreach ($line in ($text -split "`n")) {
    $trimmed = $line.Trim()
    if (-not $trimmed.StartsWith("{")) { continue }
    $fields = [regex]::Matches($line, '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value }
    if ($fields.Count -le [Math]::Max($registry.Name, $registry.Symbol)) { continue }
    $identity = Registry-Identity $fields[$registry.Name] $fields[$registry.Symbol]
    if ((Test-RetiredIdentity $fields[$registry.Name] $fields[$registry.Symbol]) -or
        ($registry.Name -eq 2 -and $retiredIds.ContainsKey($fields[0]))) {
      Fail "$($registry.File): retired identity listed -> $($line.Trim())"
    }
    if ($registry.Catalog) {
      $catalogIds[$fields[0]] = $true
    }
  }
}

$forkRegistry = Get-Content -Raw -Path (Join-Path $root "tools/fork_registry.json") | ConvertFrom-Json
foreach ($row in $forkRegistry.profiles) {
  $identity = $row.name.Trim().ToLowerInvariant() + "|" + $row.symbol.ToUpperInvariant()
  if (Test-RetiredIdentity $row.name $row.symbol) {
    Fail "tools/fork_registry.json: retired identity '$($row.network)'"
  }
}

if ((Read-Text "WalletNetworks.cpp").Contains('0x76b809bb')) {
  Fail "obsolete consensus branch id in network registry"
}

# 2b. Identities the project deliberately does not carry. Every one was
# examined against its own upstream; the reasons are in
# WalletCatalog.cpp (kRefusedChains) and wiki/Admission-Policy.md. Pinning the
# absence here keeps a profile, a catalog row or a mining mapping from
# appearing ahead of the implementation.
$refused = @(
  @{ Id = 'aion';      Symbol = 'AION' },
  @{ Id = 'beam';      Symbol = 'BEAM' },
  @{ Id = 'ironfish';  Symbol = 'IRON' },
  @{ Id = 'xelis';     Symbol = 'XEL' },
  @{ Id = 'qubitcoin'; Symbol = 'QTC' },
  @{ Id = 'qubic';     Symbol = 'QUBIC' }
)
foreach ($chain in $refused) {
  $id = $chain.Id
  foreach ($marker in @("{`"$id`"", "`"$id`", SighashFamily")) {
    if ((Read-Text "WalletNetworks.cpp").Contains($marker)) {
      Fail "WalletNetworks.cpp carries refused chain '$id': $marker"
    }
  }
  if ((Read-Text "WalletCatalog.cpp").Contains("`"$id`"")) {
    Fail "WalletCatalog.cpp lists refused chain '$id'"
  }
  # Mining rows carry the source slug and the wallet id. Quantus and
  # Qubitcoin share QTC, so the ticker alone cannot identify a refused row.
  $miningRows = Read-Text "src/generated/WalletMiningCatalog.inc"
  if ($miningRows.Contains("`"$id`"") -or
      ($id -ne 'qubitcoin' -and $miningRows.Contains("`"$($chain.Symbol)`""))) {
    Fail "mining catalog maps refused identity '$id'"
  }
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
Write-Output "retired-identities=$($retired.Count) registries=$($registries.Count) $scope=pass"
# --- 6. Unbounded string copies may not grow -------------------------------
# strcpy/strcat/sprintf carry no length. Every remaining occurrence is either a
# string literal into a larger buffer, or preceded by an explicit strlen check
# in the same function. The counts below are the reviewed baseline; a new
# occurrence - or these calls appearing in a file that had none - fails here so
# the next adapter cannot quietly reintroduce the pattern.
# Review buffers are never truncated: chain_copy_text() refuses instead, because
# a shortened address on the approval screen is a different destination.
$stringCopyBaseline = @{
  'AlgorandTransaction.cpp' = 1   # previous[8] <- key[8], both fixed and equal
  'ChainCommon.cpp' = 1           # "0" into a formatted buffer
  'CkbTransaction.cpp' = 4        # strlen-checked, or literals
  'FilecoinTransaction.cpp' = 1   # "FIL"
  'HederaTransaction.cpp' = 2     # fixed key alias
  'HiveTransaction.cpp' = 4       # strlen-checked, or a literal
  'IcpTransaction.cpp' = 1        # "ICP"
  'KaspaTransaction.cpp' = 1      # self-test corrupting a fixed local copy
  'NearTransaction.cpp' = 1       # "ed25519:" prefix
  'SiaTransaction.cpp' = 1        # "SC"
  'StellarTransaction.cpp' = 2    # "NONE" / "XLM"
  'SuiTransaction.cpp' = 1        # "SUI"
}
$stringCopyFiles = Get-ChildItem -Path $root -File | Where-Object { $_.Extension -eq '.cpp' -or $_.Extension -eq '.h' }
foreach ($file in $stringCopyFiles) {
  $found = @(Select-String -Path $file.FullName -Pattern '\b(strcpy|strcat|sprintf)\(' |
             Where-Object { $_.Line.Trim() -notmatch '^//' }).Count
  $expected = 0
  if ($stringCopyBaseline.ContainsKey($file.Name)) { $expected = $stringCopyBaseline[$file.Name] }
  if ($found -gt $expected) {
    throw "policy: $($file.Name) uses $found unbounded string cop(ies), baseline is $expected. Use chain_copy_text() or a bounded snprintf."
  }
}
Write-Output "unbounded-string-copies=baseline policy=pass"
exit 0
