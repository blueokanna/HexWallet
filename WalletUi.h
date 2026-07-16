#ifndef HEXWALLET_UI_H
#define HEXWALLET_UI_H

#include "WalletConfig.h"

namespace hexwallet {

// UI holds no mnemonic, seed, private key, address derivation, transaction
// parser, or signing authority. Those belong to separately reviewed services.
bool wallet_ui_init();
void wallet_ui_show_port_error();
void wallet_ui_service();

}  // namespace hexwallet

#endif
