#ifndef HEXWALLET_SESSION_H
#define HEXWALLET_SESSION_H

#include <stddef.h>

#include "WalletSecurity.h"

namespace hexwallet {

bool wallet_session_is_loaded();
// False when production custody is required but no real SE-backed wallet
// session backend is integrated. Hardware presence alone is insufficient.
bool wallet_session_custody_available();
// The caller must record an explicit passphrase choice. An empty string means
// the user chose no passphrase; nullptr is never an implicit empty choice.
WalletError wallet_session_generate(const char *passphrase);
WalletError wallet_session_import(const char *mnemonic, const char *passphrase);
WalletError wallet_session_import_language(const char *mnemonic, MnemonicLanguage language, const char *passphrase);
WalletError wallet_session_load_master(HdPrivateNode *master);
WalletError wallet_session_load_seed(uint8_t out_seed[kSeedSize]);
void wallet_session_clear();

}

#endif
