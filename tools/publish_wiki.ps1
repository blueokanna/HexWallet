# Publishes wiki/*.md to the GitHub wiki repository.
#
# GitHub wikis do not support subdirectories: every page is a flat .md file in
# the wiki repository root. Files starting with "_" are special (_Sidebar.md,
# _Footer.md) and are rendered on every page.
#
# Create the first page in the GitHub web UI once, then run this script.
#
#   powershell -ExecutionPolicy Bypass -File tools/publish_wiki.ps1 -DryRun
#   powershell -ExecutionPolicy Bypass -File tools/publish_wiki.ps1
param(
  [string]$Remote = 'https://github.com/blueokanna/HexWallet.wiki.git',
  [string]$Message = 'wiki: sync from repository',
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'wiki'
$checkout = Join-Path $root 'build/wiki-publish'

if (-not (Test-Path $source)) { throw "wiki source not found: $source" }

if (Test-Path (Join-Path $checkout '.git')) {
  & git -C $checkout pull --ff-only
  if ($LASTEXITCODE -ne 0) { throw "git pull failed in $checkout" }
} else {
  & git clone $Remote $checkout
  if ($LASTEXITCODE -ne 0) {
    throw "clone failed. Create one page in the GitHub wiki UI first, then retry. Remote: $Remote"
  }
}

Get-ChildItem -Path $source -Filter '*.md' -File | ForEach-Object {
  Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $checkout $_.Name) -Force
}

& git -C $checkout add --all
if ($LASTEXITCODE -ne 0) { throw 'git add failed' }

$status = & git -C $checkout status --porcelain
if (-not $status) {
  Write-Output 'wiki: already in sync'
  exit 0
}

& git -C $checkout commit -m $Message
if ($LASTEXITCODE -ne 0) { throw 'git commit failed' }

if ($DryRun) {
  Write-Output 'wiki: dry run, commit created locally but not pushed'
  exit 0
}

& git -C $checkout push
if ($LASTEXITCODE -ne 0) { throw 'git push failed' }
Write-Output 'wiki: published'
