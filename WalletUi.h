#ifndef HEXWALLET_UI_H
#define HEXWALLET_UI_H

#include <stddef.h>
#include <stdint.h>

#include "WalletConfig.h"

namespace hexwallet {

constexpr size_t kWalletUiMaxTransactionOutputs = 16;

struct WalletUiTransactionOutput {
  uint64_t value;
  const char *amount_text;
  const char *address;
  const char *ownership;
};

struct WalletUiTransactionReview {
  const char *network;
  WalletUiTransactionOutput outputs[kWalletUiMaxTransactionOutputs];
  size_t output_count;
  uint64_t fee;
  uint64_t fee_rate;
  const char *fee_text;
  const char *approval_code;
  // Link-originated requests use on-device APPROVE/REJECT buttons instead of
  // the six-digit code that the serial host must echo back.
  bool show_decision_buttons;
};

using WalletUiDecisionCallback = void (*)(bool approved);
void wallet_ui_set_decision_callback(WalletUiDecisionCallback callback);

bool wallet_ui_init();
bool wallet_ui_ready();
void wallet_ui_show_port_error();
void wallet_ui_set_authenticated(bool authenticated);
void wallet_ui_set_status(const char *status);
void wallet_ui_show_catalog();
void wallet_ui_show_transaction(const WalletUiTransactionReview &review);
void wallet_ui_show_pairing(uint32_t code, const char *fingerprint);
void wallet_ui_service();

}  // namespace hexwallet

#endif
