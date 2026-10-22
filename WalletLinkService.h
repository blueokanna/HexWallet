#ifndef HEXWALLET_LINK_SERVICE_H
#define HEXWALLET_LINK_SERVICE_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Protocol adapter between the transport (PN7161 NFC / USB APDU) and the
// wallet. It owns the device identity, the paired-phone store and the
// application request dispatch. Private keys never leave the device.
bool wallet_link_service_init();
void wallet_link_service_tick(uint32_t now_ms);
size_t wallet_link_service_apdu(const uint8_t *apdu, size_t apdu_size,
                                uint32_t now_ms, uint8_t *response,
                                size_t response_capacity);
void wallet_link_service_field_lost();
bool wallet_link_service_ready();
bool wallet_link_service_pairing_pending();
bool wallet_link_service_confirm_pairing();
void wallet_link_service_reject_pairing();

// NFC transport (PN7161). Returns false when the board has no verified NFC
// pin map or the controller failed to initialize; the wallet then keeps the
// link available over USB only.
bool wallet_link_service_nfc_begin();
void wallet_link_service_nfc_service(uint32_t now_ms);
const char *wallet_link_service_nfc_state();

}  // namespace hexwallet

#endif
