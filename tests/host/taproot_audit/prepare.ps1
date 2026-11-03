$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'bip341-wallet-test-vectors.json'
if((Get-FileHash $source).Hash -ne '403E19FB81DD1F31E745699216308F61FB403774B2AAFA87B631B8F7C042D37F') { throw 'BIP341 fixture changed' }
$vectors=Get-Content $source -Raw | ConvertFrom-Json
$lines=[Collections.Generic.List[string]]::new()
$v=$vectors.keyPathSpending[0]
$lines.Add($v.given.rawUnsignedTx)
foreach($utxo in $v.given.utxosSpent) { $lines.Add("$($utxo.amountSats) $($utxo.scriptPubKey)") }
foreach($inputVector in $v.inputSpending) { $lines.Add("$($inputVector.given.txinIndex) $($inputVector.given.hashType) $($inputVector.intermediary.sigHash) -") }
# Independent annex extensions of the published DEFAULT SigMsg. No wallet code
# computes these expectations: .NET SHA256 hashes the BIP341 serialization.
function Unhex([string]$text) {
  $bytes=New-Object byte[] ($text.Length/2)
  for($i=0;$i -lt $bytes.Length;$i++) { $bytes[$i]=[Convert]::ToByte($text.Substring(2*$i,2),16) }
  return ,$bytes
}
$sha=[Security.Cryptography.SHA256]::Create()
try {
  $tag=$sha.ComputeHash([Text.Encoding]::ASCII.GetBytes('TapSighash'))
  foreach($size in @(1,252,253)) {
    $annex=New-Object byte[] $size; $annex[0]=0x50
    $prefix=if($size -lt 253) { [byte[]]@($size) } else { [byte[]]@(253,253,0) }
    $msg=Unhex $v.inputSpending[3].intermediary.sigMsg
    if($msg.Length -ne 175 -or $msg[170] -ne 0) { throw 'Unexpected reference SigMsg layout' }
    $msg[170]=1
    $annexPreimage=[Collections.Generic.List[byte]]::new()
    $annexPreimage.AddRange([byte[]]$prefix); $annexPreimage.AddRange([byte[]]$annex)
    $annexDigest=$sha.ComputeHash($annexPreimage.ToArray())
    $preimage=[Collections.Generic.List[byte]]::new()
    $preimage.AddRange($tag); $preimage.AddRange($tag); $preimage.AddRange([byte[]]$msg); $preimage.AddRange($annexDigest)
    $digest=$sha.ComputeHash($preimage.ToArray())
    $digestHex=([BitConverter]::ToString($digest)).Replace('-','').ToLowerInvariant()
    $annexHex=([BitConverter]::ToString($annex)).Replace('-','').ToLowerInvariant()
    $lines.Add("4 0 $digestHex $annexHex")
  }
} finally { $sha.Dispose() }
[IO.File]::WriteAllLines((Join-Path $PSScriptRoot 'vectors.txt'),$lines,[Text.UTF8Encoding]::new($false))
