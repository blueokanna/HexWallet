// NXP PN7161 (NCI 2.0) NFC controller port.
//
// The wallet presents a card-emulation ISO-DEP target; the phone is the
// reader. APDU payloads are relayed to WalletNfcApdu, which forwards link
// frames to WalletLinkDevice.
//
// The pins are board-specific and MUST come from the schematic: define
// HEXWALLET_NFC_PN7161 and the HEXWALLET_NFC_PIN_* macros in the board
// profile before this port can do anything. Without them the port reports
// NotConfigured and the firmware keeps NFC disabled instead of guessing a
// pin map.
#ifndef HEXWALLET_NFC_PORT_H
#define HEXWALLET_NFC_PORT_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

enum class NfcPortState : uint8_t {
  NotConfigured = 0,
  InitFailed,
  Ready,      // initialized, waiting for a reader
  Activated,  // ISO-DEP target selected by the reader
  Error,
};

// Returns the APDU response size, or 0 when the APDU must be rejected.
using NfcApduHandler = size_t (*)(const uint8_t *apdu, size_t apdu_size,
                                  uint8_t *response, size_t response_capacity);

bool nfc_port_configured();
NfcPortState nfc_port_state();
const char *nfc_port_state_text(NfcPortState state);

// Performs the NCI reset/init/discover sequence. Safe to call repeatedly;
// a failed init leaves the port in InitFailed and NFC stays unusable.
using NfcSessionLostHandler = void (*)();
bool nfc_port_begin(NfcApduHandler handler, NfcSessionLostHandler lost_handler);

// Polls the controller. Must be called from the main loop; it never blocks
// for more than a bounded number of SPI transactions.
void nfc_port_service(uint32_t now_ms);

// Ends the current RF session (field lost, deselect, timeout).
void nfc_port_end_session();

}  // namespace hexwallet

#endif
