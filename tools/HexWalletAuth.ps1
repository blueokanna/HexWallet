param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$Salt,
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$Nonce,
  [ValidateRange(1, 10000000)][int]$Iterations = 120000
)

function ConvertFrom-Hex([string]$Text) {
  $bytes = [byte[]]::new($Text.Length / 2)
  for ($index = 0; $index -lt $bytes.Length; $index++) {
    $bytes[$index] = [Convert]::ToByte($Text.Substring($index * 2, 2), 16)
  }
  return $bytes
}

function ConvertTo-Hex([byte[]]$Bytes) {
  return -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

$securePin = Read-Host 'HexWallet PIN' -AsSecureString
$pinPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePin)
$pinBytes = $null
$saltBytes = $null
$nonceBytes = $null
$verifier = $null
try {
  $pinText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pinPointer)
  $pinBytes = [Text.Encoding]::UTF8.GetBytes($pinText)
  $saltBytes = ConvertFrom-Hex $Salt
  $nonceBytes = ConvertFrom-Hex $Nonce
  $pbkdf2 = [Security.Cryptography.Rfc2898DeriveBytes]::new(
      $pinBytes, $saltBytes, $Iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
  try { $verifier = $pbkdf2.GetBytes(32) } finally { $pbkdf2.Dispose() }
  $hmac = [Security.Cryptography.HMACSHA256]::new($verifier)
  try { ConvertTo-Hex ($hmac.ComputeHash($nonceBytes)) }
  finally { $hmac.Dispose() }
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pinPointer)
  if ($pinBytes) { [Array]::Clear($pinBytes, 0, $pinBytes.Length) }
  if ($saltBytes) { [Array]::Clear($saltBytes, 0, $saltBytes.Length) }
  if ($nonceBytes) { [Array]::Clear($nonceBytes, 0, $nonceBytes.Length) }
  if ($verifier) { [Array]::Clear($verifier, 0, $verifier.Length) }
}
