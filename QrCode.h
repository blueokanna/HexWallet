#ifndef HEXWALLET_QRCODE_H
#define HEXWALLET_QRCODE_H

#include <stddef.h>
#include <stdint.h>

#include "EinkPanel.h"

namespace hexwallet {

// QR encoder for the strings a wallet actually shows (addresses, xpub
// fingerprints, pairing codes) plus a 1bpp renderer for the e-paper.
//
// Supported set, deliberately bounded and enforced:
//   * byte mode, versions 1-10 (21x21 .. 57x57), ECC level L or M
//   * up to 271 payload bytes (v10-L); longer input is refused, never truncated
//
// Versions 1-6 are always a single RS block; 7-10 need interleaving and a
// version-information block, and both are implemented here rather than skipped,
// because a 79-character Kaspa address does not fit a single-block symbol.
//
// What the self-test verifies: format information is re-decoded from both
// copies, the data modules are unmasked and de-zigzagged, the codewords are
// de-interleaved again, every RS block's syndromes must be zero, and the
// payload must round-trip byte for byte. What it cannot verify: a physical
// scanner. Scan one code off the panel before shipping a screen that relies on
// it.

enum class QrEcc : uint8_t { Low = 0, Medium = 1 };

constexpr uint8_t kQrMaxVersion = 10;
constexpr uint8_t kQrMaxModules = 57;  // 17 + 4 * kQrMaxVersion

struct QrCode {
  uint8_t size;     // modules per side (21, 25, ... 57)
  uint8_t version;  // 1..kQrMaxVersion
  QrEcc ecc;
  uint8_t mask;     // applied mask pattern 0..7
  // Row-major, 1 = dark. Sized for the largest supported version so a QrCode
  // can live in a static buffer instead of being re-dimensioned per version.
  uint8_t modules[kQrMaxModules * kQrMaxModules];
};

// Largest payload that fits the version/level, in bytes. 0 when the version or
// level is not supported.
size_t qr_capacity(uint8_t version, QrEcc ecc);

// Smallest version that holds the payload. The mask is chosen by the standard
// penalty score.
bool qr_encode(const uint8_t *payload, size_t size, QrEcc ecc, QrCode *out);

// Deterministic variant with an explicit mask. The host cross-check compares
// its matrices against a reference encoder, which only works when both sides
// apply the same mask.
bool qr_encode_masked(const uint8_t *payload, size_t size, QrEcc ecc,
                      uint8_t mask, QrCode *out);

// Draws the symbol into a 1bpp panel bitmap at (x, y) with `scale` pixels per
// module. Returns false when the symbol (including its quiet zone) would leave
// the panel; nothing is written in that case.
bool qr_render(const QrCode &code, uint8_t *bitmap, size_t bitmap_size,
               uint16_t panel_width, uint16_t panel_height, uint16_t x,
               uint16_t y, uint8_t scale);

constexpr uint8_t kQrQuietZone = 4;

bool run_qr_code_self_tests();

}

#endif
