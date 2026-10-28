#include "CryptoNoteOutputScan.h"
#include <stdio.h>

#include "../../CryptoExtended.h"
#include "../../CryptoNoteAddress.h"
#include "../../CryptoNoteRingCt.h"
#include "../../CryptoNoteAmounts.h"
#include "../../CryptoNoteSpend.h"
#include "../../CryptoNoteTransaction.h"
#include "../../CryptoNoteBulletproofPlus.h"
#include "../../CryptoNoteReview.h"
#include "../../CryptoNoteSigning.h"
#include "../../CryptoNoteMasari.h"
#include "../../CryptoPrimitives.h"
#include "../../BitcoinTransaction.h"
#include "../../Blake2b.h"
#include "../../Blake256.h"
#include "../../KaspaTransaction.h"
#include "../../TokenCalldata.h"
#include "../../TronTransaction.h"
#include "../../CosmosTransaction.h"
#include "../../StellarTransaction.h"
#include "../../AlgorandTransaction.h"
#include "../../ChainTransaction.h"
#include "../../NearTransaction.h"
#include "../../TezosTransaction.h"
#include "../../Totp.h"
#include "../../EinkFrame.h"
#include "../../XrpTransaction.h"
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
  const bool cryptonote_spend = hexwallet::run_cryptonote_spend_self_tests();
  const bool cryptonote_bp_plus = hexwallet::run_bulletproof_plus_self_tests();
  const bool bulletproof_plus_reference = hexwallet::run_bulletproof_plus_reference_vector_self_test();
  const bool cryptonote_review = hexwallet::run_cryptonote_review_self_tests();
  const bool cryptonote_signing = hexwallet::run_cryptonote_signing_self_tests();
  const bool masari = hexwallet::run_masari_self_tests();
  const bool cryptonote_mainnet = hexwallet::run_cryptonote_mainnet_vector_self_test();
  const bool cryptonote_clsag = hexwallet::run_cryptonote_clsag_self_test();
  const bool qrl = hexwallet::run_qrl_xmss_self_tests();
  const bool custody = hexwallet::run_custody_self_tests();
  const bool networks = hexwallet::run_network_profile_self_tests();
  const bool sighash = hexwallet::run_bitcoin_sighash_self_tests();
  const bool kaspa = hexwallet::run_kaspa_self_tests();
  const bool blake2b = hexwallet::run_blake2b_self_tests();
  const bool blake256 = hexwallet::run_blake256_self_tests();
  const bool calldata = hexwallet::run_token_calldata_self_tests();
  const bool tron = hexwallet::run_tron_self_tests();
  const bool cosmos = hexwallet::run_cosmos_self_tests();
  const bool stellar = hexwallet::run_stellar_self_tests();
  const bool algorand = hexwallet::run_algorand_self_tests();
  const bool chain = hexwallet::run_chain_self_tests();
  const bool tezos = hexwallet::run_tezos_self_tests();
  const bool near = hexwallet::run_near_self_tests();
  const bool totp = hexwallet::run_totp_self_tests();
  const bool eink = hexwallet::run_eink_frame_self_tests();
  const bool xrp = hexwallet::run_xrp_self_tests();
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
  printf("cryptonote-spend=%s\n", cryptonote_spend ? "pass" : "FAIL");
  printf("bulletproof-plus=%s\n", cryptonote_bp_plus ? "pass" : "FAIL");
  printf("bulletproof-plus-reference=%s\n", bulletproof_plus_reference ? "pass" : "FAIL");
  const bool bulletproof_plus_mainnet = hexwallet::run_bulletproof_plus_mainnet_probe();
  printf("cryptonote-review=%s\n", cryptonote_review ? "pass" : "FAIL");
  if (!cryptonote_review) printf("cryptonote-review-stage=%d error=%d\n", hexwallet::cryptonote_review_last_stage(), hexwallet::cryptonote_review_last_error());
  printf("cryptonote-signing=%s\n", cryptonote_signing ? "pass" : "FAIL");
  if (!cryptonote_signing) printf("cryptonote-signing-stage=%d error=%d\n", hexwallet::cryptonote_signing_last_stage(), hexwallet::cryptonote_signing_last_error());
  printf("masari=%s\n", masari ? "pass" : "FAIL");
  if (!masari) printf("masari-stage=%d error=%d\n", hexwallet::masari_last_stage(), hexwallet::masari_last_error());
  printf("cryptonote-mainnet=%s\n", cryptonote_mainnet ? "pass" : "FAIL");
  printf("bulletproof-plus-mainnet=%s\n", bulletproof_plus_mainnet ? "accepted" : "rejected");
  printf("qrl-xmss=%s\n", qrl ? "pass" : "FAIL");
  printf("custody=%s\n", custody ? "pass" : "FAIL");
  printf("networks=%s\n", networks ? "pass" : "FAIL");
  printf("sighash=%s\n", sighash ? "pass" : "FAIL");
  printf("kaspa=%s\n", kaspa ? "pass" : "FAIL");
  printf("blake2b=%s\n", blake2b ? "pass" : "FAIL");
  printf("blake256=%s\n", blake256 ? "pass" : "FAIL");
  printf("token-calldata=%s\n", calldata ? "pass" : "FAIL");
  printf("tron=%s\n", tron ? "pass" : "FAIL");
  printf("cosmos=%s\n", cosmos ? "pass" : "FAIL");
  printf("stellar=%s\n", stellar ? "pass" : "FAIL");
  printf("algorand=%s\n", algorand ? "pass" : "FAIL");
  printf("chain=%s\n", chain ? "pass" : "FAIL");
#if defined(HEXWALLET_HOST_TEST)
  if (!chain) hexwallet::report_chain_self_tests();
#endif
  printf("tezos=%s\n", tezos ? "pass" : "FAIL");
  printf("near=%s\n", near ? "pass" : "FAIL");
  printf("totp=%s\n", totp ? "pass" : "FAIL");
  printf("eink=%s\n", eink ? "pass" : "FAIL");
  printf("xrp=%s\n", xrp ? "pass" : "FAIL");
  printf("zcash=%s\n", zcash ? "pass" : "FAIL");
  printf("catalog=%s\n", catalog ? "pass" : "FAIL");
  printf("mining-catalog=%s\n", mining ? "pass" : "FAIL");
  printf("tokens=%s\n", tokens ? "pass" : "FAIL");
  printf("link-crypto=%s\n", link_crypto ? "pass" : "FAIL");
  printf("wallet-link=%s\n", wallet_link ? "pass" : "FAIL");
  printf("nfc-apdu=%s\n", nfc_apdu ? "pass" : "FAIL");
  return (output_scan && amounts && cryptonote_tx && cryptonote_spend && cryptonote_mainnet && cryptonote_review && cryptonote_signing && masari && cryptonote_bp_plus && bulletproof_plus_mainnet && bulletproof_plus_reference && primitives && extended && addresses && cryptonote && cryptonote_ringct && cryptonote_clsag && qrl && custody && networks && sighash && kaspa && blake2b && blake256 && calldata && tron && cosmos && stellar && algorand && chain && near && tezos && totp && eink && xrp && zcash && catalog && mining && tokens && link_crypto && wallet_link && nfc_apdu) ? 0 : 1;
}
