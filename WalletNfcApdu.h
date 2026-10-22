#ifndef HEXWALLET_NFC_APDU_H
#define HEXWALLET_NFC_APDU_H

#include <stddef.h>
#include <stdint.h>

#include "WalletLink.h"

namespace hexwallet {

// ISO 7816-4 APDU application exposed over NFC. The phone is the reader; the
// PN7161 presents this application as an ISO-DEP tag. Link frames are larger
// than a short APDU, so they are transferred as chained write/read commands:
//
//   SELECT      00 A4 04 00 06 F0 48 57 4C 4B 31
//   WRITE       80 10 00 00 Lc <chunk>          (P1=0x01 on the final chunk)
//   READ        80 11 00 00 00
//   ABORT       80 12 00 00 00
//   STATUS      80 13 00 00 00
//
// The application deliberately has no command that exports a private key.
// Authentication and replay protection live in WalletLink; this layer only
// moves opaque frames and reports transport status words.
class WalletNfcApdu {
 public:
  static constexpr size_t kAidSize = 6;
  static constexpr uint8_t kAid[kAidSize] = {
    0xf0, 0x48, 0x57, 0x4c, 0x4b, 0x31,  // F0 "HWLK1"
  };
  static constexpr size_t kMaxChunk = 240;

  WalletNfcApdu();
  bool init(WalletLinkDevice *link);
  void reset_transfer();
  void field_lost();

  // Processes one complete command APDU. Returns the number of response
  // bytes written, including the two status bytes. The response buffer must
  // have room for data + 2; a truncated response returns 0.
  size_t process(const uint8_t *apdu, size_t apdu_size, uint32_t now_ms,
                 uint8_t *response, size_t response_capacity);

 private:
  size_t status_only(uint16_t status, uint8_t *response,
                     size_t response_capacity) const;
  WalletLinkDevice *link_;
  bool selected_;
  uint8_t request_[kLinkMaxFrameSize];
  size_t request_size_;
  uint8_t reply_[kLinkMaxFrameSize];
  size_t reply_size_;
  size_t reply_offset_;
};

bool run_wallet_nfc_apdu_self_test();

}  // namespace hexwallet

#endif
