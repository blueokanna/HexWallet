#include <Arduino.h>

#include "WalletBoardPort.h"
#include "BitcoinTransaction.h"
#include "WalletCli.h"
#include "WalletConfig.h"
#include "CryptoPrimitives.h"
#include "WalletEngine.h"
#include "WalletSecurity.h"
#include "WalletUi.h"

namespace {
bool display_available = false;
bool security_ready = false;
bool last_authenticated = false;
}

void setup() {
  Serial.begin(115200);

#if HEXWALLET_RUN_SELF_TESTS
  security_ready = hexwallet::run_crypto_self_tests() &&
                   hexwallet::run_bip39_self_test() &&
                   hexwallet::run_bip32_self_test() &&
                   hexwallet::run_address_self_tests() &&
                   hexwallet::run_bitcoin_transaction_self_test();
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
