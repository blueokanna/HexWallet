// Host entry point for the extended crypto / address self-tests. Compiles and
// runs the firmware's own self-test functions against official vectors
// (RFC 8032, RFC 7693, FIPS 202, FIPS 180-4, BIP-173/350, CashAddr, Kaspa,
// EIP-2333, Chia standard addresses). See build.ps1.
#include <stdio.h>

#include "../../CryptoExtended.h"
#include "../../WalletAltAddresses.h"

int main() {
  const bool extended = hexwallet::run_crypto_extended_self_tests();
  const bool addresses = hexwallet::run_alt_address_self_tests();
  printf("extended-crypto=%s\n", extended ? "pass" : "FAIL");
  printf("alt-addresses=%s\n", addresses ? "pass" : "FAIL");
  return (extended && addresses) ? 0 : 1;
}
