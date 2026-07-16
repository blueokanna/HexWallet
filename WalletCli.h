#ifndef HEXWALLET_CLI_H
#define HEXWALLET_CLI_H

namespace hexwallet {

bool wallet_cli_init(bool display_available);
void wallet_cli_service();
bool wallet_cli_is_authenticated();
void wallet_cli_lock();

}  // namespace hexwallet

#endif
