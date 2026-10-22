#include <Arduino.h>

#ifndef HEXWALLET_LOOP_TASK_STACK_SIZE
#define HEXWALLET_LOOP_TASK_STACK_SIZE (32 * 1024)
#endif
SET_LOOP_TASK_STACK_SIZE(HEXWALLET_LOOP_TASK_STACK_SIZE);

#include "WalletBoardPort.h"
#include "BitcoinTransaction.h"
#include "KaspaTransaction.h"
#include "TokenCalldata.h"
#include "CryptoExtended.h"
#include "WalletCatalog.h"
#include "WalletCli.h"
#include "WalletConfig.h"
#include "CryptoPrimitives.h"
#include "CryptoNoteAddress.h"
#include "CryptoNoteRingCt.h"
#include "CryptoNoteTransaction.h"
#include "EvmTransaction.h"
#include "ZcashTransaction.h"
#include "QrlXmss.h"
#include "WalletCustody.h"
#include "WalletEngine.h"
#include "WalletLinkCrypto.h"
#include "WalletLink.h"
#include "WalletLinkService.h"
#include "WalletNfcApdu.h"
#include "WalletSecurity.h"
#include "WalletSigning.h"
#include "WalletTokens.h"
#include "WalletTransportPolicy.h"
#include "WalletUi.h"

namespace {
bool display_available = false;
bool security_ready = false;
bool last_authenticated = false;
}

void setup() {
  Serial.begin(115200);

#if HEXWALLET_RUN_SELF_TESTS
  const bool crypto = hexwallet::run_crypto_self_tests();
  const bool extended = hexwallet::run_crypto_extended_self_tests();
  const bool cryptonote = hexwallet::run_cryptonote_self_tests();
  const bool cryptonote_ringct = hexwallet::run_cryptonote_ringct_self_tests();
  const bool cryptonote_tx = hexwallet::run_cryptonote_transaction_self_tests();
  const bool qrl = hexwallet::run_qrl_xmss_self_tests();
  const bool custody = hexwallet::run_custody_self_tests();
  const bool catalog = hexwallet::run_catalog_self_tests();
  const bool evm = hexwallet::run_evm_transaction_self_test();
  const bool bip39 = hexwallet::run_bip39_self_test();
  const bool bip32 = hexwallet::run_bip32_self_test();
  const bool bip84 = hexwallet::run_bip84_self_test();
  const bool evm_derive = hexwallet::run_evm_derivation_self_test();
  const bool bip340 = hexwallet::run_bip340_self_test();
  const bool address = hexwallet::run_address_self_tests();
  const bool networks = hexwallet::run_network_profile_self_tests();
  const bool sighash = hexwallet::run_bitcoin_sighash_self_tests();
  const bool kaspa = hexwallet::run_kaspa_self_tests();
  const bool calldata = hexwallet::run_token_calldata_self_tests();
  const bool tokens = hexwallet::run_token_profile_self_tests();
  const bool transport = hexwallet::run_transport_policy_self_test();
  const bool bitcoin = hexwallet::run_bitcoin_transaction_self_test();
  const bool zcash_sighash = hexwallet::run_zcash_sighash_self_tests();
  const bool zcash = hexwallet::run_zcash_transaction_self_test();
  const bool link_crypto = hexwallet::run_link_crypto_self_test();
  const bool wallet_link = hexwallet::run_wallet_link_self_test();
  const bool nfc_apdu = hexwallet::run_wallet_nfc_apdu_self_test();
  const bool signing = hexwallet::run_wallet_signing_self_test();
  Serial.print("SELFTEST crypto=");
  Serial.print(crypto ? "pass" : "FAIL");
  Serial.print(" extended=");
  Serial.print(extended ? "pass" : "FAIL");
  Serial.print(" cryptonote=");
  Serial.print(cryptonote ? "pass" : "FAIL");
  Serial.print(" cryptonote-ringct=");
  Serial.print(cryptonote_ringct ? "pass" : "FAIL");
  Serial.print(" cryptonote-tx=");
  Serial.print(cryptonote_tx ? "pass" : "FAIL");
  Serial.print(" qrl=");
  Serial.print(qrl ? "pass" : "FAIL");
  Serial.print(" custody=");
  Serial.print(custody ? "pass" : "FAIL");
  Serial.print(" catalog=");
  Serial.print(catalog ? "pass" : "FAIL");
  Serial.print(" evm=");
  Serial.print(evm ? "pass" : "FAIL");
  Serial.print(" bip39=");
  Serial.print(bip39 ? "pass" : "FAIL");
  Serial.print(" bip32=");
  Serial.print(bip32 ? "pass" : "FAIL");
  Serial.print(" bip84=");
  Serial.print(bip84 ? "pass" : "FAIL");
  Serial.print(" evm-derive=");
  Serial.print(evm_derive ? "pass" : "FAIL");
  Serial.print(" bip340=");
  Serial.print(bip340 ? "pass" : "FAIL");
  Serial.print(" address=");
  Serial.print(address ? "pass" : "FAIL");
  Serial.print(" networks=");
  Serial.print(networks ? "pass" : "FAIL");
  Serial.print(" sighash=");
  Serial.print(sighash ? "pass" : "FAIL");
  Serial.print(" kaspa=");
  Serial.print(kaspa ? "pass" : "FAIL");
  Serial.print(" calldata=");
  Serial.print(calldata ? "pass" : "FAIL");
  Serial.print(" tokens=");
  Serial.print(tokens ? "pass" : "FAIL");
  Serial.print(" transport=");
  Serial.print(transport ? "pass" : "FAIL");
  Serial.print(" bitcoin=");
  Serial.print(bitcoin ? "pass" : "FAIL");
  Serial.print(" zcash-sighash=");
  Serial.print(zcash_sighash ? "pass" : "FAIL");
  Serial.print(" zcash=");
  Serial.print(zcash ? "pass" : "FAIL");
  Serial.print(" link-crypto=");
  Serial.print(link_crypto ? "pass" : "FAIL");
  Serial.print(" wallet-link=");
  Serial.print(wallet_link ? "pass" : "FAIL");
  Serial.print(" nfc-apdu=");
  Serial.print(nfc_apdu ? "pass" : "FAIL");
  Serial.print(" signing=");
  Serial.println(signing ? "pass" : "FAIL");
  security_ready = crypto && extended && cryptonote && cryptonote_ringct && cryptonote_tx && qrl && custody && catalog && evm && bip39 && bip32 && bip84 && evm_derive && bip340 && address && networks && sighash && kaspa && calldata && tokens && transport && bitcoin && zcash_sighash && zcash && link_crypto && wallet_link && nfc_apdu && signing;
  if (!security_ready) {
    Serial.println("FATAL: cryptographic self-test failed; wallet services disabled");
    return;
  }
#else
  security_ready = true;
#endif
  display_available = hexwallet::board_display_init();
  if (display_available) {
    if (!hexwallet::wallet_ui_init()) {
      Serial.println("FATAL: LVGL UI initialization failed");
      display_available = false;
    }
    hexwallet::board_power(true);
    Serial.print("INFO: display ");
    Serial.print(hexwallet::board_display_width());
    Serial.print("x");
    Serial.print(hexwallet::board_display_height());
    Serial.print(" (");
    Serial.print(hexwallet::board_name());
    Serial.println(")");
  } else {
    Serial.print("WARN: no display on ");
    Serial.println(hexwallet::board_name());
  }
  if (!hexwallet::wallet_cli_init(display_available)) {
    Serial.println("FATAL: authenticated CLI initialization failed");
    security_ready = false;
  }
  if (!hexwallet::wallet_link_service_init()) {
    Serial.println("WARN: phone link identity/pairing store unavailable; NFC/USB requests disabled");
  } else if (!hexwallet::wallet_link_service_nfc_begin()) {
    Serial.print("INFO nfc=");
    Serial.print(hexwallet::wallet_link_service_nfc_state());
    Serial.println("; phone link available over USB only (define HEXWALLET_NFC_PN7161 pins to enable NFC)");
  } else {
    Serial.println("INFO nfc=ready (PN7161 ISO-DEP card emulation)");
  }
}

void loop() {
  if (!security_ready) return;
  hexwallet::wallet_cli_service();
  hexwallet::wallet_link_service_tick(millis());
  hexwallet::wallet_link_service_nfc_service(millis());
  if (display_available) {
    const bool authenticated = hexwallet::wallet_cli_is_authenticated();
    if (authenticated != last_authenticated) {
      hexwallet::wallet_ui_set_authenticated(authenticated);
      last_authenticated = authenticated;
    }
    hexwallet::board_display_service();
    hexwallet::wallet_ui_service();
  }
}
