# Builds the native chain probe and the production policy binary against a real
# Mbed TLS 3.6.5 tree, then runs both self-checks.
#
# The probe links the actual WalletSecurity.cpp so BIP32/SLIP-0010 and secp256k1
# come from the firmware, not from a host shim. The policy binary is compiled
# without the host-only historical Substrate admission and with
# HEXWALLET_REQUIRE_SECURE_CUSTODY=1, so it must refuse to open a wallet.
#
# Prerequisite (once):
#   git clone --depth 1 --branch mbedtls-3.6.5 --recurse-submodules `
#     --shallow-submodules https://github.com/Mbed-TLS/mbedtls.git build/chain-mbedtls
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $root
try {
  # Pinned so a moving branch cannot silently change the crypto library.
  $expected = 'e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df'
  if (-not (Test-Path -LiteralPath 'build/chain-mbedtls/CMakeLists.txt')) {
    throw 'Clone Mbed-TLS/mbedtls tag mbedtls-3.6.5 with --recurse-submodules into build/chain-mbedtls first.'
  }
  $actual = git -C build/chain-mbedtls rev-parse HEAD
  if ($LASTEXITCODE -ne 0 -or $actual -ne $expected) { throw 'Unexpected Mbed TLS revision' }

  cmake -S tests/host/chain -B build/chain-native -A x64
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  cmake --build build/chain-native --config Release --parallel 4
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  & 'build/chain-native/Release/chain_probe.exe' alph-zeph-selftest
  if ($LASTEXITCODE -ne 0) { throw 'Alephium / Zephyr derivation failed' }
  $alph = Get-Content -Raw tests/fixtures/alephium/p2pkh-transfer.json | ConvertFrom-Json
  $result = & 'build/chain-native/Release/chain_probe.exe' alph $alph.seed $alph.unsignedTx $alph.index
  if ($LASTEXITCODE -ne 0 -or $result -notcontains "signed=$($alph.signature)" -or
      $result -notcontains "sender=$($alph.sender)" -or $result -notcontains "recipient=$($alph.recipient)" -or
      $result -notcontains 'amount=50.0 ALPH' -or $result -notcontains 'fee=0.002 ALPH' -or
      $result -notcontains "hash=$($alph.txId)") { throw 'Alephium SDK transfer mismatch' }
  foreach ($raw in @(('000100' + $alph.unsignedTx.Substring(6)),
                     ('000001' + $alph.unsignedTx.Substring(6)), ($alph.unsignedTx + '00'))) {
    & 'build/chain-native/Release/chain_probe.exe' alph $alph.seed $raw $alph.index | Out-Null
    if ($LASTEXITCODE -eq 0) { throw 'Alephium accepted a different network, script, or trailing data' }
  }
  & 'build/chain-native/Release/chain_probe.exe' zephyr-mainnet 'tests/fixtures/zephyr/7e2f3d9d1b5deaf3db873d5fe5d6c54272d127a84aa04ddc18bd46e66a9a7c12.bin'
  if ($LASTEXITCODE -ne 0) { throw 'Zephyr mainnet wire format, hash or balance mismatch' }
  & 'build/chain-native/Release/chain_probe.exe' beam-output-selftest
  if ($LASTEXITCODE -ne 0) { throw 'Beam output or transaction failed' }
  & 'build/chain-native/Release/chain_probe.exe' beam-regular-address
  if ($LASTEXITCODE -ne 0) { throw 'Beam regular address did not match the independent reference' }
  & 'build/chain-native/Release/chain_probe.exe' quantus-selftest
  if ($LASTEXITCODE -ne 0) { throw 'Quantus HD account vector failed' }
  & 'build/chain-native/Release/chain_probe.exe' quantus-signature-kat
  if ($LASTEXITCODE -ne 0) { throw 'Quantus signature context or upstream KAT mismatch' }
  $quantus = Get-Content -Raw tests/fixtures/quantus/native-transfer.json | ConvertFrom-Json
  & 'build/chain-native/Release/chain_probe.exe' quantus-extrinsic-kat $quantus.seed $quantus.payload tests/fixtures/quantus/native-transfer.bin
  if ($LASTEXITCODE -ne 0) { throw 'Quantus WASM extrinsic layout or signature mismatch' }
  & 'build/chain-native/Release/chain_probe.exe' xelis-native-account
  if ($LASTEXITCODE -ne 0) { throw 'Xelis recovery, address or signature mismatch' }
  # Cyprus-1 0x00060019fdf877647e4a9bab684b0c51732b590cb0ffebc058fb29702fe87f97.
  # Re-sign the same fields with the public zero-seed test wallet. The first
  # eligible child is 165. Expected signature from ethers 6.15 SigningKey.
  $quaiPayload = '08001214004894e7c041bac2a4575241c0ec96ddd37866e018cdda0322091900fc11c0f9a81d0828e0da0132003a010942061e76ec20d2ad4a00'
  $quaiResult = & 'build/chain-native/Release/chain_probe.exe' quai ('00' * 64) $quaiPayload 165
  if ($LASTEXITCODE -ne 0 -or $quaiResult -notcontains 'sender=0x00006d8faf5c7b23aa6d700e5333db4f6443f7f9' -or
      $quaiResult -notcontains 'amount=461.239553057389813 QUAI' -or
      $quaiResult -notcontains 'fee=0.937891263351532 QUAI' -or
      $quaiResult -notcontains 'signed=0581f4e9d77120e744300f62cece7f9c872bc44722ff962c4fb4954170169a1a5f11a40d1bb8c9ef82beb2cd508063513ea3a97b2bec974d870e1d0dcc25406a00') {
    throw 'Quai derivation, transfer review or signature mismatch'
  }
  & 'build/chain-native/Release/chain_probe.exe' wallet-selftest
  if ($LASTEXITCODE -ne 0) { throw 'wallet self-test failed' }
  & 'build/chain-native/Release/chain_probe.exe' primary-assets
  if ($LASTEXITCODE -ne 0) { throw 'Primary asset address derivation or signing capability failed' }
  & 'build/chain-native/Release/chain_probe.exe' chain-selftest
  if ($LASTEXITCODE -ne 0) { throw 'chain_probe self-test failed' }
  # Real BIP32/ECDSA is linked here, so this runs the device-only Zcash signer
  # (t1 P2PKH and t3 P2SH-P2PK) instead of the stubbed host harness.
  & 'build/chain-native/Release/chain_probe.exe' zcash-sign-selftest
  if ($LASTEXITCODE -ne 0) { throw 'zcash sign self-test failed' }
  & 'build/chain-native/Release/chain_probe.exe' cosmos-sign-selftest
  if ($LASTEXITCODE -ne 0) { throw 'cosmos sign self-test failed' }
  & 'build/chain-native/Release/chain_probe.exe' dash-sign-selftest
  if ($LASTEXITCODE -ne 0) { throw 'dash sign self-test failed' }
  # PSBT v0/v2 parsing and the signature both envelopes must agree on: needs real BIP32/ECDSA.
  & 'build/chain-native/Release/chain_probe.exe' bitcoin-tx-selftest
  if ($LASTEXITCODE -ne 0) { throw 'bitcoin transaction self-test failed' }
  & 'build/chain-native/Release/chain_probe.exe' evm-sign-selftest
  if ($LASTEXITCODE -ne 0) { throw 'evm sign self-test failed' }
  foreach ($approval in (Get-Content -Raw tests/fixtures/evm/approval-review.json | ConvertFrom-Json)) {
    $review = & 'build/chain-native/Release/chain_probe.exe' eth ('00' * 64) $approval.wire 0
    if ($LASTEXITCODE -ne 0 -or $review -notcontains $approval.review -or
        $review -notcontains 'SPENDER / OPERATOR' -or $review -notcontains '0x1212121212121212121212121212121212121212') {
      throw "Incorrect approval review: $($approval.review)"
    }
  }

  & 'build/chain-native/Release/chain_probe.exe' stark-selftest
  if ($LASTEXITCODE -ne 0) { throw 'stark derivation self-test failed' }

  & 'build/chain-native/Release/production_policy.exe'
  if ($LASTEXITCODE -ne 0) { throw 'production_policy failed' }
  foreach ($block in 1..3) {
    & 'build/chain-native/Release/production_policy.exe' $block
    if ($LASTEXITCODE -ne 0) { throw "Boot entropy failure in block $block was not latched" }
  }

  Write-Output 'chain-native: probe and policy self-tests passed'
} finally { Pop-Location }
