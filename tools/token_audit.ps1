# Audits every registered EVM token against the live chain.
#
# The registry in WalletTokens.cpp is the only thing standing between "this
# contract is USDC" and "this contract is a lookalike that happens to share the
# symbol". This script asks each contract itself - symbol(), decimals(), name() -
# through a public RPC and compares the answers with what the firmware believes.
#
# Addresses are never invented here: the registry row is the claim, and the chain
# is the witness. A row that cannot be reached is reported as unreachable, not
# as passed.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools/token_audit.ps1
#   powershell -ExecutionPolicy Bypass -File tools/token_audit.ps1 -Network eth
param(
  [string]$Network,
  [int]$TimeoutSeconds = 20,
  [int]$DelayMs = 400
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$registry = Join-Path $root 'WalletTokens.cpp'

# One public endpoint per network. A network without an entry is skipped loudly:
# an unverified row is exactly the thing this audit exists to find.
$rpc = @{
  eth      = 'https://ethereum-rpc.publicnode.com'
  bsc      = 'https://bsc-rpc.publicnode.com'
  matic    = 'https://polygon-bor-rpc.publicnode.com'
  arb1     = 'https://arbitrum-one-rpc.publicnode.com'
  base     = 'https://base-rpc.publicnode.com'
  opt      = 'https://optimism-rpc.publicnode.com'
  linea    = 'https://linea-rpc.publicnode.com'
  scroll   = 'https://scroll-rpc.publicnode.com'
  xlayer   = 'https://xlayerrpc.okx.com'
  zksync   = 'https://mainnet.era.zksync.io'
  avaxc    = 'https://avalanche-c-chain-rpc.publicnode.com'
  celo     = 'https://celo-rpc.publicnode.com'
  cro      = 'https://cronos-evm-rpc.publicnode.com'
  kava     = 'https://kava-evm-rpc.publicnode.com'
  unichain = 'https://unichain-rpc.publicnode.com'
  kaia     = 'https://public-en.node.kaia.io'
  bera     = 'https://bera-rpc.publicnode.com'
  monad    = 'https://monad-rpc.publicnode.com'
  plasma   = 'https://plasma-rpc.publicnode.com'
  opbnb    = 'https://opbnb-rpc.publicnode.com'
  mantle   = 'https://mantle-rpc.publicnode.com'
  blast    = 'https://blast-rpc.publicnode.com'
  metis    = 'https://metis-rpc.publicnode.com'
  aurora   = 'https://aurora-rpc.publicnode.com'
}

function Invoke-Call([string]$url, [string]$to, [string]$data, [int]$timeout) {
  $body = @{ jsonrpc = '2.0'; id = 1; method = 'eth_call';
             params = @(@{ to = $to; data = $data }, 'latest') } | ConvertTo-Json -Compress -Depth 5
  # Public endpoints throttle aggressively. One retry after a pause separates
  # "rate limited" from "this contract does not answer", which are very
  # different findings for a registry audit.
  for ($attempt = 0; $attempt -lt 2; ++$attempt) {
    try {
      $response = Invoke-RestMethod -Method Post -Uri $url -ContentType 'application/json' `
        -Body $body -TimeoutSec $timeout
      if ($null -eq $response.result) { return $null }
      return $response.result
    } catch {
      if ($attempt -eq 1) { throw }
      Start-Sleep -Seconds 2
    }
  }
}

# ABI responses here are either a dynamic string or, in older tokens, a
# right-padded bytes32. Both appear in this registry, so both are decoded.
function ConvertFrom-Text([string]$hex) {
  if ([string]::IsNullOrWhiteSpace($hex) -or $hex -eq '0x') { return $null }
  $raw = $hex.Substring(2)
  if ($raw.Length -ge 128) {
    $length = [Convert]::ToInt32($raw.Substring(64, 64), 16)
    if ($length -gt 0 -and $raw.Length -ge 128 + $length * 2) {
      $bytes = [byte[]]::new($length)
      for ($i = 0; $i -lt $length; ++$i) {
        $bytes[$i] = [Convert]::ToByte($raw.Substring(128 + $i * 2, 2), 16)
      }
      return [Text.Encoding]::UTF8.GetString($bytes).Trim()
    }
  }
  if ($raw.Length -eq 64) {
    $bytes = [byte[]]::new(32)
    for ($i = 0; $i -lt 32; ++$i) { $bytes[$i] = [Convert]::ToByte($raw.Substring($i * 2, 2), 16) }
    return [Text.Encoding]::UTF8.GetString($bytes).Trim([char]0).Trim()
  }
  return $null
}

# Issuers rebrand tokens in place and bridged deployments carry a suffix the
# chain does not know, so labels are compared after folding the typographic
# "tugrik" sign used by Tether and dropping punctuation.
function Normalize-Symbol([string]$text) {
  if ($null -eq $text) { return '' }
  $folded = $text.Replace([char]0x20AE, 'T')
  return ($folded.ToUpperInvariant() -replace '[^A-Z0-9]', '')
}

$rows = @()
$current = $null
foreach ($line in Get-Content $registry) {
  if ($line -match '^\s*\{\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]*)",\s*TokenStandard::(\w+),') {
    $current = [pscustomobject]@{
      id = $matches[1]; network = $matches[2]; symbol = $matches[3]; name = $matches[4]
      standard = $matches[5]; contract = $null; decimals = $null
    }
    $rows += $current
    continue
  }
  if ($null -ne $current -and $line -match '^\s*"0x([0-9a-fA-F]{40})",\s*(\d+),') {
    $current.contract = '0x' + $matches[1]
    $current.decimals = [int]$matches[2]
    $current = $null
  }
}

$checked = 0; $failed = 0; $skipped = 0; $warned = 0; $unreachable = 0
foreach ($row in $rows) {
  if ($row.standard -notin @('Erc20', 'Bep20', 'Erc721', 'Erc1155')) { continue }
  if ($Network -and $row.network -ne $Network) { continue }
  if (-not $rpc.ContainsKey($row.network)) {
    Write-Output ("  SKIP    {0,-18} {1,-8} no RPC configured for network '{2}'" -f $row.id, $row.symbol, $row.network)
    ++$skipped
    continue
  }
  $url = $rpc[$row.network]
  Start-Sleep -Milliseconds $DelayMs
  try {
    if ($row.standard -in @('Erc721', 'Erc1155')) {
      $id = if ($row.standard -eq 'Erc721') { '80ac58cd' } else { 'd9b67a26' }
      $answer = Invoke-Call $url $row.contract ('0x01ffc9a7' + $id + ('0' * 56)) $TimeoutSeconds
      if ($null -eq $answer) { throw 'Missing ERC-165 response' }
      ++$checked
      if ($answer -eq ('0x' + ('0' * 63) + '1')) {
        Write-Output "  OK      $($row.id) $($row.standard) interface=$id"
      } else {
        ++$failed
        Write-Output "  MISMATCH $($row.id) interface=$id"
      }
      continue
    }
    $symbolHex = Invoke-Call $url $row.contract '0x95d89b41' $TimeoutSeconds
    $decimalsHex = Invoke-Call $url $row.contract '0x313ce567' $TimeoutSeconds
    $nameHex = Invoke-Call $url $row.contract '0x06fdde03' $TimeoutSeconds
    $onSymbol = ConvertFrom-Text $symbolHex
    $onName = ConvertFrom-Text $nameHex
    $onDecimals = if ($decimalsHex) { [Convert]::ToInt32($decimalsHex.Substring(2), 16) } else { $null }
    # Decimals are the value that moves money: a mismatch is fatal. The symbol is
    # a display label - issuers rebrand contracts in place (USDT -> USD-T0) and
    # bridged tokens carry a suffix the chain does not know - so a label drift is
    # reported, not failed.
    $decimalsOk = ($onDecimals -eq $row.decimals)
    $symbolOk = (Normalize-Symbol $onSymbol) -eq (Normalize-Symbol $row.symbol)
    ++$checked
    if (-not $decimalsOk) {
      ++$failed
      Write-Output ("  MISMATCH {0,-18} {1,-8} chain={2,-8} dec={3,-3} (registry {4}) name={5}" -f `
        $row.id, $row.symbol, $onSymbol, $onDecimals, $row.decimals, $onName)
    } elseif (-not $symbolOk) {
      ++$warned
      Write-Output ("  LABEL   {0,-18} {1,-8} chain={2,-8} dec={3,-3} name={4}" -f `
        $row.id, $row.symbol, $onSymbol, $onDecimals, $onName)
    } else {
      Write-Output ("  OK      {0,-18} {1,-8} chain={2,-8} dec={3,-3} name={4}" -f `
        $row.id, $row.symbol, $onSymbol, $onDecimals, $onName)
    }
  } catch {
    ++$unreachable
    Write-Output ("  UNREACH {0,-18} {1,-8} {2}" -f $row.id, $row.symbol, $_.Exception.Message)
  }
}
Write-Output "token-audit: checked=$checked decimals-mismatch=$failed label-drift=$warned unreachable=$unreachable skipped=$skipped"
if ($unreachable -ne 0) {
  Write-Output "note: unreachable rows were not proven either way; rerun with -Network to retry a single chain"
}
if ($failed -ne 0) { exit 1 }
