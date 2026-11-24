// NXP PN7161 (NCI 2.0) NFC controller port.
//
// The phone link uses ISO-DEP card emulation. A local backup read temporarily
// switches to NFC-A polling for a Type 4 NDEF tag and restores listen mode
// before releasing the result. Tag responses stay in the reader state machine.
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
// Static, non-secret diagnostic for the last failed operation, or nullptr.
const char *nfc_port_error();
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

// Local UI only. Read one NFC-A Type 4 NDEF Text record. The caller owns and
// erases the copied ASCII key. Cancel, field loss and timeout discard it.
enum class NfcBackupStatus : uint8_t { Idle, Pending, Complete, Busy, Controller, Timeout, TagLost, UnsupportedTag, AccessDenied, InvalidRecord, MissingFile, CommandRejected };
NfcBackupStatus nfc_backup_start();
NfcBackupStatus nfc_backup_take(char (&key)[65]);
void nfc_backup_cancel();

}  // namespace hexwallet

#endif
