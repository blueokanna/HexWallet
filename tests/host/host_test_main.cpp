#include <stdio.h>

#include "../../CryptoExtended.h"
#include "../../CryptoNoteAddress.h"
#include "../../CryptoPrimitives.h"
#include "../../BitcoinTransaction.h"
#include "../../Blake2b.h"
#include "../../KaspaTransaction.h"
#include "../../MoneroScan.h"
#include "../../CosmosTransaction.h"
#include "../../TokenCalldata.h"
#include "../../QrlXmss.h"
#include "../../WalletAltAddresses.h"
#include "../../WalletCatalog.h"
#include "../../WalletCustody.h"
#include "../../WalletNetworks.h"
#include "../../WalletTokens.h"

int main() {
  const bool primitives = hexwallet::run_crypto_self_tests();
  const bool extended = hexwallet::run_crypto_extended_self_tests();
  const bool addresses = hexwallet::run_alt_address_self_tests();
  const bool cryptonote = hexwallet::run_cryptonote_self_tests();
  const bool qrl = hexwallet::run_qrl_xmss_self_tests();
  const bool custody = hexwallet::run_custody_self_tests();
  const bool networks = hexwallet::run_network_profile_self_tests();
  const bool sighash = hexwallet::run_bitcoin_sighash_self_tests();
  const bool monero = hexwallet::run_monero_scan_self_tests();
  const bool kaspa = hexwallet::run_kaspa_self_tests();
  const bool blake2b = hexwallet::run_blake2b_self_tests();
  const bool calldata = hexwallet::run_token_calldata_self_tests();
  const bool cosmos = hexwallet::run_cosmos_self_tests();
  const bool catalog = hexwallet::run_catalog_self_tests();
  const bool tokens = hexwallet::run_token_profile_self_tests();
  printf("crypto-primitives=%s\n", primitives ? "pass" : "FAIL");
  printf("extended-crypto=%s\n", extended ? "pass" : "FAIL");
  printf("alt-addresses=%s\n", addresses ? "pass" : "FAIL");
  printf("cryptonote=%s\n", cryptonote ? "pass" : "FAIL");
  printf("qrl-xmss=%s\n", qrl ? "pass" : "FAIL");
  printf("custody=%s\n", custody ? "pass" : "FAIL");
  printf("networks=%s\n", networks ? "pass" : "FAIL");
  printf("sighash=%s\n", sighash ? "pass" : "FAIL");
  printf("monero-scan=%s\n", monero ? "pass" : "FAIL");
  printf("kaspa=%s\n", kaspa ? "pass" : "FAIL");
  printf("blake2b=%s\n", blake2b ? "pass" : "FAIL");
  printf("token-calldata=%s\n", calldata ? "pass" : "FAIL");
  printf("cosmos=%s\n", cosmos ? "pass" : "FAIL");
  printf("catalog=%s\n", catalog ? "pass" : "FAIL");
  printf("tokens=%s\n", tokens ? "pass" : "FAIL");
  return (primitives && extended && addresses && cryptonote && qrl && custody && networks && sighash && monero && kaspa && blake2b && calldata && cosmos && catalog && tokens) ? 0 : 1;
}
