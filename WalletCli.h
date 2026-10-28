#ifndef HEXWALLET_CLI_H
#define HEXWALLET_CLI_H

namespace hexwallet {

bool wallet_cli_init(bool display_available);
void wallet_cli_service();
bool wallet_cli_is_authenticated();
bool wallet_cli_review_active();
void wallet_cli_lock();

// USB data transport gate. It is closed by default and only the physical
// BOOT/user button (long press) can open it for a bounded window. NFC does not
// depend on this gate.
bool wallet_usb_data_enabled();
void wallet_usb_data_set(bool enabled);
void wallet_usb_data_service();

}  // namespace hexwallet

#endif
