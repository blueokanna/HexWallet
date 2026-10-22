#ifndef HEXWALLET_MONERO_SCAN_H
#define HEXWALLET_MONERO_SCAN_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoNoteAddress.h"

namespace hexwallet {

// Monero receive-side scanning: given the wallet's view key and the spend
// public key of every tracked account/subaddress, decide which transaction
// outputs belong to the wallet and recover their amounts.  This is the
// view-key-only path, so it works without the spend key being resident.

constexpr size_t kMoneroMaxScanOutputs = 32;
constexpr size_t kMoneroMaxScanSubaddresses = 16;

struct MoneroSubaddressKeys {
  uint32_t account;
  uint32_t minor;
  // D = B + m*G for this subaddress.  Index 0 must be the base address, i.e.
  // spend_public == B with account 0 and minor 0.
  uint8_t spend_public[kCryptoNotePublicKeySize];
};

struct MoneroScannedOutput {
  uint8_t ephemeral_public[kCryptoNotePublicKeySize];  // R, the tx public key
  uint8_t one_time_public[kCryptoNotePublicKeySize];   // P, the output key
  uint8_t encrypted_amount[8];
};

struct MoneroOwnedOutput {
  uint16_t output_index;
  uint8_t subaddress;  // index into the supplied table
  // RingCT outputs carry a Pedersen commitment in the 8-byte amount field, so
  // the amount can only be recovered for pre-RingCT plain outputs. The flag
  // says which case this is instead of inventing a number.
  bool amount_decoded;
  uint64_t amount;
};

// Returns Ok when scanning completed (zero matches is a valid result) and
// fills `owned`.  Outputs whose ephemeral key is not a canonical curve point
// are skipped rather than treated as an error, which mirrors how a node would
// reject them later anyway.
WalletError monero_scan_outputs(const uint8_t view_secret[kCryptoNoteScalarSize],
                                const MoneroSubaddressKeys *subaddresses,
                                size_t subaddress_count,
                                const MoneroScannedOutput *outputs,
                                size_t output_count,
                                MoneroOwnedOutput *owned,
                                size_t *in_out_owned_count);

bool run_monero_scan_self_tests();

}  // namespace hexwallet

#endif
