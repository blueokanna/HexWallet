#include "CryptoNoteOutputScan.h"
#include <stdio.h>

#include "../../CryptoExtended.h"
#include "../../CryptoNoteAddress.h"
#include "../../CryptoNoteRingCt.h"
#include "../../CryptoNoteAmounts.h"
#include "../../CryptoNoteTransaction.h"
#include "../../CryptoPrimitives.h"
#include "../../BitcoinTransaction.h"
#include "../../Blake2b.h"
#include "../../KaspaTransaction.h"
#include "../../TokenCalldata.h"
#include "../../QrlXmss.h"
#include "../../ZcashTransaction.h"
#include "../../WalletAltAddresses.h"
#include "../../WalletCatalog.h"
#include "../../WalletMiningCatalog.h"
#include "../../WalletCustody.h"
#include "../../WalletLink.h"
#include "../../WalletLinkCrypto.h"
#include "../../WalletNfcApdu.h"
#include "../../WalletNetworks.h"
#include "../../WalletTokens.h"

int main() {
  const bool output_scan = hexwallet::run_cryptonote_output_scan_self_tests();
  printf("cryptonote-output-scan=%s\n", output_scan ? "pass" : "FAIL");
  const bool primitives = hexwallet::run_crypto_self_tests();
  const bool extended = hexwallet::run_crypto_extended_self_tests();
  const bool addresses = hexwallet::run_alt_address_self_tests();
  const bool cryptonote = hexwallet::run_cryptonote_self_tests();
  const bool cryptonote_ringct = hexwallet::run_cryptonote_ringct_self_tests();
  const bool amounts = hexwallet::run_ringct_amount_self_tests();
  const bool cryptonote_tx = hexwallet::run_cryptonote_transaction_self_tests();
  const bool cryptonote_clsag = hexwallet::run_cryptonote_clsag_self_test();
  const bool qrl = hexwallet::run_qrl_xmss_self_tests();
  const bool custody = hexwallet::run_custody_self_tests();
  const bool networks = hexwallet::run_network_profile_self_tests();
  const bool sighash = hexwallet::run_bitcoin_sighash_self_tests();
  const bool kaspa = hexwallet::run_kaspa_self_tests();
  const bool blake2b = hexwallet::run_blake2b_self_tests();
  const bool calldata = hexwallet::run_token_calldata_self_tests();
  const bool zcash = hexwallet::run_zcash_sighash_self_tests();
  const bool catalog = hexwallet::run_catalog_self_tests();
  const bool mining = hexwallet::run_mining_catalog_self_tests();
  const bool tokens = hexwallet::run_token_profile_self_tests();
  const bool link_crypto = hexwallet::run_link_crypto_self_test();
  const bool wallet_link = hexwallet::run_wallet_link_self_test();
  const bool nfc_apdu = hexwallet::run_wallet_nfc_apdu_self_test();
  printf("crypto-primitives=%s\n", primitives ? "pass" : "FAIL");
  printf("extended-crypto=%s\n", extended ? "pass" : "FAIL");
  printf("alt-addresses=%s\n", addresses ? "pass" : "FAIL");
  printf("cryptonote=%s\n", cryptonote ? "pass" : "FAIL");
  printf("cryptonote-ringct=%s\n", cryptonote_ringct ? "pass" : "FAIL");
  printf("ringct-amounts=%s\n", amounts ? "pass" : "FAIL");
  printf("cryptonote-clsag=%s\n", cryptonote_clsag ? "pass" : "FAIL");
  printf("cryptonote-tx=%s\n", cryptonote_tx ? "pass" : "FAIL");
  printf("qrl-xmss=%s\n", qrl ? "pass" : "FAIL");
  printf("custody=%s\n", custody ? "pass" : "FAIL");
  printf("networks=%s\n", networks ? "pass" : "FAIL");
  printf("sighash=%s\n", sighash ? "pass" : "FAIL");
  printf("kaspa=%s\n", kaspa ? "pass" : "FAIL");
  printf("blake2b=%s\n", blake2b ? "pass" : "FAIL");
  printf("token-calldata=%s\n", calldata ? "pass" : "FAIL");
  printf("zcash=%s\n", zcash ? "pass" : "FAIL");
  printf("catalog=%s\n", catalog ? "pass" : "FAIL");
  printf("mining-catalog=%s\n", mining ? "pass" : "FAIL");
  printf("tokens=%s\n", tokens ? "pass" : "FAIL");
  printf("link-crypto=%s\n", link_crypto ? "pass" : "FAIL");
  printf("wallet-link=%s\n", wallet_link ? "pass" : "FAIL");
  printf("nfc-apdu=%s\n", nfc_apdu ? "pass" : "FAIL");
  return (output_scan && amounts && cryptonote_tx && primitives && extended && addresses && cryptonote && cryptonote_ringct && cryptonote_clsag && qrl && custody && networks && sighash && kaspa && blake2b && calldata && zcash && catalog && mining && tokens && link_crypto && wallet_link && nfc_apdu) ? 0 : 1;
}
