param([switch]$Fetch)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$manifest = Get-Content (Join-Path $PSScriptRoot 'monero-reference.json') -Raw | ConvertFrom-Json
$work = Join-Path $root 'build/monero-reference'
foreach ($file in $manifest.files) {
  $target = Join-Path $work $file.path
  if ($Fetch) {
    New-Item -ItemType Directory -Force (Split-Path -Parent $target) | Out-Null
    $url = "https://raw.githubusercontent.com/monero-project/monero/$($manifest.commit)/$($file.path)"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $target
  }
  if (!(Test-Path $target)) { throw "Missing $target; run with -Fetch on the development PC." }
  if ((Get-FileHash $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) {
    throw "Reference source checksum mismatch: $($file.path)"
  }
}
