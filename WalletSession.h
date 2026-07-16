#ifndef HEXWALLET_SESSION_H
#define HEXWALLET_SESSION_H

#include <stddef.h>

#include "WalletSecurity.h"

namespace hexwallet {

bool wallet_session_is_loaded();
WalletError wallet_session_generate();
WalletError wallet_session_import(const char *mnemonic);
WalletError wallet_session_load_master(HdPrivateNode *master);
const char *wallet_session_mnemonic_for_export();
void wallet_session_clear();

}

#endif
