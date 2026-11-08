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
  [ValidateRange(1, 120)][int]$TimeoutSeconds = 20,
  [ValidateRange(0, 10000)][int]$DelayMs = 400
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
  kavaevm  = 'https://kava-evm-rpc.publicnode.com'
  unichain = 'https://unichain-rpc.publicnode.com'
  kaia     = 'https://public-en.node.kaia.io'
  # Project endpoints; the former PublicNode hostnames returned HTTP 404.
  # https://docs.berachain.com/build/getting-started/common-resources
  # https://docs.monad.xyz/developer-essentials/network-information
  # https://chainid.network/chain/9745/
  bera     = 'https://rpc.berachain.com'
  monad    = 'https://rpc.monad.xyz'
  plasma   = 'https://rpc.plasma.to'
  opbnb    = 'https://opbnb-rpc.publicnode.com'
  mantle   = 'https://mantle-rpc.publicnode.com'
  blast    = 'https://blast-rpc.publicnode.com'
  metis    = 'https://metis-rpc.publicnode.com'
  aurora   = 'https://aurora-rpc.publicnode.com'
}

function Invoke-Rpc([string]$url, [string]$method, [object[]]$parameters, [int]$timeout) {
  $body = @{ jsonrpc = '2.0'; id = 1; method = $method;
             params = @($parameters) } | ConvertTo-Json -Compress -Depth 5
  # Public endpoints throttle aggressively. One retry after a pause separates
  # "rate limited" from "this contract does not answer", which are very
  # different findings for a registry audit.
  for ($attempt = 0; $attempt -lt 2; ++$attempt) {
    try {
      $response = Invoke-RestMethod -Method Post -Uri $url -ContentType 'application/json' `
        -Body $body -TimeoutSec $timeout
      if ($response.jsonrpc -ne '2.0' -or $response.id -ne 1 -or $null -ne $response.error -or
          $response.result -isnot [string] -or $response.result.Length -gt 131072 -or
          $response.result -cnotmatch '^0x[0-9a-fA-F]*$') {
        throw "Invalid JSON-RPC response for $method"
      }
      return $response.result
    } catch {
      if ($attempt -eq 1) { throw }
      Start-Sleep -Seconds 2
    }
  }
}

function Invoke-Call([string]$url, [string]$to, [string]$data, [int]$timeout) {
  return Invoke-Rpc $url 'eth_call' @(@{ to = $to; data = $data }, 'latest') $timeout
}

# ABI responses here are either a dynamic string or, in older tokens, a
# right-padded bytes32. Both appear in this registry, so both are decoded.
function ConvertFrom-Text([string]$hex) {
  if ([string]::IsNullOrWhiteSpace($hex) -or $hex -eq '0x') { return $null }
  $raw = $hex.Substring(2)
  if ($raw.Length -ge 128) {
    if ($raw.Substring(0, 64) -ne (('0' * 62) + '20')) { throw 'Invalid ABI string offset' }
    $length = [Convert]::ToInt32($raw.Substring(64, 64), 16)
    if ($length -gt 0 -and $length -le 4096 -and
        $raw.Length -eq 128 + [int][Math]::Ceiling($length / 32.0) * 64) {
      if ($raw.Substring(128 + $length * 2) -match '[^0]') { throw 'Nonzero ABI string padding' }
      $bytes = [byte[]]::new($length)
      for ($i = 0; $i -lt $length; ++$i) {
        $bytes[$i] = [Convert]::ToByte($raw.Substring(128 + $i * 2, 2), 16)
      }
      return (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes).Trim()
    }
  }
  if ($raw.Length -eq 64) {
    $bytes = [byte[]]::new(32)
    for ($i = 0; $i -lt 32; ++$i) { $bytes[$i] = [Convert]::ToByte($raw.Substring($i * 2, 2), 16) }
    return (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes).TrimEnd([char]0).Trim()
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

# Read chain IDs from the firmware registry instead of maintaining a second
# identity table. Refuse incomplete extraction when a selected row needs it.
$chainIds = @{}
$profiles = Get-Content -Raw -Encoding UTF8 (Join-Path $root 'WalletNetworks.cpp')
$profilePattern = '\{\s*"([^"]+)",\s*"[^"]*",\s*"[^"]*",\s*\d+,\s*\d+,\s*\d+,\s*DerivationStyle::\w+,\s*AddressEncoding::Evm,\s*\{[^}]*\},\s*0,\s*(\d+),'
foreach ($match in [regex]::Matches($profiles, $profilePattern)) {
  $chainIds[$match.Groups[1].Value] = [uint64]$match.Groups[2].Value
}
$networkChecks = @{}
$selected = @($rows | Where-Object {
  $_.standard -in @('Erc20', 'Bep20', 'Erc721', 'Erc1155') -and
  (-not $Network -or $_.network -eq $Network)
})
if ($selected.Count -eq 0) { throw 'No EVM token records selected; nothing was verified.' }

$checked = 0; $failed = 0; $skipped = 0; $warned = 0; $unreachable = 0
foreach ($row in $selected) {
  if (-not $rpc.ContainsKey($row.network)) {
    Write-Output ("  SKIP    {0,-18} {1,-8} no RPC configured for network '{2}'" -f $row.id, $row.symbol, $row.network)
    ++$skipped
    continue
  }
  $url = $rpc[$row.network]
  Start-Sleep -Milliseconds $DelayMs
  try {
    if (-not $row.contract -or $null -eq $row.decimals -or -not $chainIds.ContainsKey($row.network)) {
      throw 'Incomplete token or network registry extraction'
    }
    if (-not $networkChecks.ContainsKey($row.network)) {
      try {
        $chain = Invoke-Rpc $url 'eth_chainId' @() $TimeoutSeconds
        if ($chain -cnotmatch '^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$' -or
            [Convert]::ToUInt64($chain.Substring(2), 16) -ne $chainIds[$row.network]) {
          throw 'RPC chain ID does not match the firmware network'
        }
        $networkChecks[$row.network] = ''
      } catch { $networkChecks[$row.network] = $_.Exception.Message }
    }
    if ($networkChecks[$row.network]) { throw $networkChecks[$row.network] }
    $code = Invoke-Rpc $url 'eth_getCode' @($row.contract, 'latest') $TimeoutSeconds
    if ($code -cnotmatch '^0x(?:[0-9a-fA-F]{2})+$' -or $code -match '^0x0*$') {
      throw 'No contract bytecode at the registered address'
    }
    if ($row.standard -in @('Erc721', 'Erc1155')) {
      $id = if ($row.standard -eq 'Erc721') { '80ac58cd' } else { 'd9b67a26' }
      # ERC-165 requires both its own interface and rejection of 0xffffffff.
      # A fallback that returns true for everything is not interface evidence.
      $erc165 = Invoke-Call $url $row.contract ('0x01ffc9a701ffc9a7' + ('0' * 56)) $TimeoutSeconds
      $invalid = Invoke-Call $url $row.contract ('0x01ffc9a7ffffffff' + ('0' * 56)) $TimeoutSeconds
      $answer = Invoke-Call $url $row.contract ('0x01ffc9a7' + $id + ('0' * 56)) $TimeoutSeconds
      if ($null -eq $answer) { throw 'Missing ERC-165 response' }
      ++$checked
      if ($erc165 -eq ('0x' + ('0' * 63) + '1') -and
          $invalid -eq ('0x' + ('0' * 64)) -and $answer -eq ('0x' + ('0' * 63) + '1')) {
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
    if ([string]::IsNullOrWhiteSpace($onSymbol) -or [string]::IsNullOrWhiteSpace($onName) -or
        $onSymbol -match '[\x00-\x1f\x7f]' -or $onName -match '[\x00-\x1f\x7f]' -or
        $decimalsHex -cnotmatch '^0x[0-9a-fA-F]{64}$') { throw 'Malformed or missing token metadata' }
    $onDecimals = [Convert]::ToInt32($decimalsHex.Substring(2), 16)
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
if ($checked -eq 0 -or $unreachable -ne 0 -or $skipped -ne 0) { exit 2 }
exit 0
