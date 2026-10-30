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
  & 'build/chain-native/Release/chain_probe.exe' evm-sign-selftest
  if ($LASTEXITCODE -ne 0) { throw 'evm sign self-test failed' }

  & 'build/chain-native/Release/production_policy.exe'
  if ($LASTEXITCODE -ne 0) { throw 'production_policy failed' }

  Write-Output 'chain-native: probe and policy self-tests passed'
} finally { Pop-Location }
