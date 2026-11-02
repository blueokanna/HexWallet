#ifndef HEXWALLET_WALLET_TOTP_H
#define HEXWALLET_WALLET_TOTP_H
#include "TotpAccounts.h"
namespace hexwallet {
// All mutations are staged for a one-time confirmation on the trusted screen.
// The caller must be authenticated. Session accounts are wiped by clear().
bool wallet_totp_import(const char *uri, size_t size);
bool wallet_totp_remove(uint8_t slot);
bool wallet_totp_show(uint8_t slot);
bool wallet_totp_set_time(uint64_t unix_seconds);
bool wallet_totp_info(uint8_t slot, TotpAccountInfo *out);
bool wallet_totp_pending();
void wallet_totp_tick();
void wallet_totp_clear();
}
#endif
