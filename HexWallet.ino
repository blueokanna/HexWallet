#include <Arduino.h>

#ifndef HEXWALLET_LOOP_TASK_STACK_SIZE
#define HEXWALLET_LOOP_TASK_STACK_SIZE (16 * 1024)
#endif
SET_LOOP_TASK_STACK_SIZE(HEXWALLET_LOOP_TASK_STACK_SIZE);

#include "WalletBoardPort.h"
#include "BitcoinTransaction.h"
#include "WalletCli.h"
#include "WalletConfig.h"
#include "CryptoPrimitives.h"
#include "CryptoNoteAddress.h"
#include "EvmTransaction.h"
#include "WalletEngine.h"
#include "WalletSecurity.h"
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
  const bool cryptonote = hexwallet::run_cryptonote_self_tests();
  const bool evm = hexwallet::run_evm_transaction_self_test();
  const bool bip39 = hexwallet::run_bip39_self_test();
  const bool bip32 = hexwallet::run_bip32_self_test();
  const bool address = hexwallet::run_address_self_tests();
  const bool networks = hexwallet::run_network_profile_self_tests();
  const bool tokens = hexwallet::run_token_profile_self_tests();
  const bool transport = hexwallet::run_transport_policy_self_test();
  const bool bitcoin = hexwallet::run_bitcoin_transaction_self_test();
  Serial.print("SELFTEST crypto="); Serial.print(crypto ? "pass" : "FAIL");
  Serial.print(" cryptonote="); Serial.print(cryptonote ? "pass" : "FAIL");
  Serial.print(" evm="); Serial.print(evm ? "pass" : "FAIL");
  Serial.print(" bip39="); Serial.print(bip39 ? "pass" : "FAIL");
  Serial.print(" bip32="); Serial.print(bip32 ? "pass" : "FAIL");
  Serial.print(" address="); Serial.print(address ? "pass" : "FAIL");
  Serial.print(" networks="); Serial.print(networks ? "pass" : "FAIL");
  Serial.print(" tokens="); Serial.print(tokens ? "pass" : "FAIL");
  Serial.print(" transport="); Serial.print(transport ? "pass" : "FAIL");
  Serial.print(" bitcoin="); Serial.println(bitcoin ? "pass" : "FAIL");
  security_ready = crypto && cryptonote && evm && bip39 && bip32 && address &&
                   networks && tokens && transport && bitcoin;
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
  }
  if (!hexwallet::wallet_cli_init(display_available)) {
    Serial.println("FATAL: authenticated CLI initialization failed");
    security_ready = false;
  }
}

void loop() {
  if (!security_ready) return;
  hexwallet::wallet_cli_service();
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
