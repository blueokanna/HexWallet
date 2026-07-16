#include <Arduino.h>

#include "WalletBoardPort.h"
#include "WalletConfig.h"
#include "WalletSecurity.h"
#include "WalletUi.h"

void setup() {
  Serial.begin(115200);

#if HEXWALLET_RUN_SELF_TESTS
  if (!hexwallet::run_bip32_self_test()) {
    Serial.println("FATAL: BIP32 self-test failed");
    return;
  }
#endif

  // Never write secrets to UART. The device starts locked and keyless.
  if (!hexwallet::board_display_init()) {
    Serial.println("Display port is not configured");
    return;
  }
  hexwallet::wallet_ui_init();
}

void loop() {
  hexwallet::board_display_service();
  hexwallet::wallet_ui_service();
}
