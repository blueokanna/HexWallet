$ErrorActionPreference = 'Stop'
& py -3.10 (Join-Path $PSScriptRoot 'restore_coin_icons.py')
if ($LASTEXITCODE) { throw 'Icon provenance check failed' }
& (Join-Path $PSScriptRoot 'pack_coin_icons.ps1')
