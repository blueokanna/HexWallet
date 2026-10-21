// Host entry point for the extended crypto / address self-tests. Compiles and
// runs the firmware's own self-test functions against official vectors
// (RFC 8032, RFC 7693, FIPS 202, FIPS 180-4, BIP-173/350, CashAddr, Kaspa,
// EIP-2333, Chia standard addresses). See build.ps1.
#include <stdio.h>

#include "../../CryptoExtended.h"
#include "../../CryptoNoteAddress.h"
#include "../../CryptoPrimitives.h"
#include "../../QrlXmss.h"
#include "../../WalletAltAddresses.h"
#include "../../WalletCatalog.h"
#include "../../WalletCustody.h"

int main() {
  const bool primitives = hexwallet::run_crypto_self_tests();
  const bool extended = hexwallet::run_crypto_extended_self_tests();
  const bool addresses = hexwallet::run_alt_address_self_tests();
  const bool cryptonote = hexwallet::run_cryptonote_self_tests();
  const bool qrl = hexwallet::run_qrl_xmss_self_tests();
  const bool custody = hexwallet::run_custody_self_tests();
  const bool catalog = hexwallet::run_catalog_self_tests();
  printf("crypto-primitives=%s\n", primitives ? "pass" : "FAIL");
  printf("extended-crypto=%s\n", extended ? "pass" : "FAIL");
  printf("alt-addresses=%s\n", addresses ? "pass" : "FAIL");
  printf("cryptonote=%s\n", cryptonote ? "pass" : "FAIL");
  printf("qrl-xmss=%s\n", qrl ? "pass" : "FAIL");
  printf("custody=%s\n", custody ? "pass" : "FAIL");
  printf("catalog=%s\n", catalog ? "pass" : "FAIL");
  return (primitives && extended && addresses && cryptonote && qrl && custody && catalog) ? 0 : 1;
}
