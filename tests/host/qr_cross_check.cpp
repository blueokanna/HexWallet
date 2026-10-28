// Cross-check of QrCode.cpp against nayuki/QR-Code-generator.
//
// The in-tree self-test (run_qr_code_self_tests) can only prove that the encoder
// and its reader agree with each other; a transposed format-information half is
// self-consistent and unreadable by a scanner at the same time. This test
// compares the module matrix of every supported version, level and mask against
// an independent implementation, which is the only way to catch that class of
// bug without a physical scanner.
//
// Driven by tests/host/qr_cross_check.ps1, which fetches the reference at a
// pinned commit and compiles both translation units together.

#include "QrCode.cpp"

#include <stdio.h>

#include <vector>

#include "qrcodegen.hpp"

using namespace hexwallet;

namespace {

qrcodegen::QrCode::Ecc reference_level(QrEcc ecc) {
  switch (ecc) {
    case QrEcc::Low: return qrcodegen::QrCode::Ecc::LOW;
    case QrEcc::Medium: return qrcodegen::QrCode::Ecc::MEDIUM;
    case QrEcc::Quartile: return qrcodegen::QrCode::Ecc::QUARTILE;
    case QrEcc::High: return qrcodegen::QrCode::Ecc::HIGH;
  }
  return qrcodegen::QrCode::Ecc::LOW;
}

}  // namespace

int main() {
  static uint8_t payload[kMaxDataCodewords];
  int checked = 0;
  int mismatches = 0;
  int size_mismatches = 0;

  for (uint8_t version = 1; version <= kQrMaxVersion; ++version) {
    for (QrEcc ecc : {QrEcc::Low, QrEcc::Medium, QrEcc::Quartile, QrEcc::High}) {
      const size_t capacity = qr_capacity(version, ecc);
      for (size_t index = 0; index < capacity; ++index) {
        payload[index] = static_cast<uint8_t>('A' + (index % 26));
      }
      const std::vector<uint8_t> data(payload, payload + capacity);
      const std::vector<qrcodegen::QrSegment> segments{
          qrcodegen::QrSegment::makeBytes(data)};
      for (uint8_t mask = 0; mask < 8; ++mask) {
        QrCode mine = {};
        if (!qr_encode_masked(payload, capacity, ecc, mask, &mine)) {
          printf("FAIL encode v%u lvl%u mask%u\n", version,
                 (int)ecc, mask);
          return 2;
        }
        const qrcodegen::QrCode reference = qrcodegen::QrCode::encodeSegments(
            segments, reference_level(ecc), version, version, mask, false);
        if (reference.getSize() != mine.size) {
          printf("FAIL size v%u lvl%u mask%u\n", version,
                 (int)ecc, mask);
          ++size_mismatches;
          continue;
        }
        int differing = 0;
        for (int y = 0; y < reference.getSize(); ++y) {
          for (int x = 0; x < reference.getSize(); ++x) {
            const bool theirs = reference.getModule(x, y);
            const bool ours = mine.modules[static_cast<size_t>(y) * mine.size + x] != 0;
            if (theirs != ours) {
              if (differing < 4) {
                printf("  module row=%d col=%d reference=%d ours=%d\n", y, x,
                       theirs ? 1 : 0, ours ? 1 : 0);
              }
              ++differing;
            }
          }
        }
        if (differing != 0) {
          printf("FAIL v%u lvl%u mask%u modules=%d\n", version,
                 (int)ecc, mask, differing);
          ++mismatches;
        }
        ++checked;
      }
    }
  }

  printf("qr-cross-check: cases=%d matrix_mismatches=%d size_mismatches=%d\n",
         checked, mismatches, size_mismatches);
  return (mismatches == 0 && size_mismatches == 0) ? 0 : 1;
}
