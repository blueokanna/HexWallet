#ifndef HEXWALLET_QRCODE_H
#define HEXWALLET_QRCODE_H

#include <stddef.h>
#include <stdint.h>

#include "EinkPanel.h"

namespace hexwallet {

// QR encoder for the strings a wallet actually shows (addresses, xpub
// fingerprints, pairing codes) plus a 1bpp renderer for the e-paper.
//
// Supported set, deliberately narrow and enforced:
//   * byte mode, versions 1-3 (21x21 .. 29x29), ECC level L or M
//   * at most 53 payload bytes (v3-L); longer input is refused, never truncated
// Every version/level combination in that set is a single RS block, so there is
// no interleaving to get wrong.
//
// What is verified by the self-test: the module matrix is read back, the format
// information is re-decoded from both copies, the data modules are unmasked and
// de-zigzagged, Reed-Solomon syndromes are required to be zero and the payload
// must round-trip byte for byte. What is NOT verified here: a physical scanner.
// Scan one code on the bench before shipping a screen that relies on it.

enum class QrEcc : uint8_t { Low = 0, Medium = 1 };

struct QrCode {
  uint8_t size;            // modules per side (21, 25 or 29)
  uint8_t version;         // 1..3
  QrEcc ecc;
  uint8_t mask;            // applied mask pattern 0..7
  uint8_t modules[29 * 29];  // row-major, 1 = dark
};

size_t qr_capacity(uint8_t version, QrEcc ecc);

bool qr_encode(const uint8_t *payload, size_t size, QrEcc ecc, QrCode *out);

bool qr_render(const QrCode &code, uint8_t *bitmap, size_t bitmap_size,
               uint16_t panel_width, uint16_t panel_height, uint16_t x,
               uint16_t y, uint8_t scale);

constexpr uint8_t kQrQuietZone = 4;

bool run_qr_code_self_tests();

}

#endif
