#ifndef HEXWALLET_ZANO_OUTPUT_H
#define HEXWALLET_ZANO_OUTPUT_H
#include <stdint.h>

namespace hexwallet {
// Ordinary post-HF6 Zarcanum output fields, prior to transaction serialization.
struct ZanoConfidentialOutput {
  uint8_t stealth_address[32];
  uint8_t concealing_point[32];
  uint8_t amount_commitment[32];
  uint8_t blinded_asset[32];
  uint64_t encrypted_amount;
  uint64_t encrypted_payment_id;
};

// Constructs the commitment and encrypted data for one standard recipient.
// For outgoing review compare all returned fields to the parsed transaction.
// tx_secret belongs to the wallet. All buffers are disjoint.
bool zano_build_output(const uint8_t tx_secret[32], uint64_t output_index,
                       const uint8_t recipient_spend[32], const uint8_t recipient_view[32],
                       const uint8_t asset_id[32], uint64_t amount, uint64_t payment_id,
                       bool explicit_native_asset, ZanoConfidentialOutput *out);

struct ZanoReceivedOutput {
  uint64_t amount;
  uint64_t payment_id;
  uint8_t asset_id[32];
  uint8_t amount_mask[32];
  uint8_t asset_mask[32];
};

// Scan a standard recipient output with the wallet's view secret. The caller
// owns (and must erase) the recovered opening. The payment ID is encrypted
// metadata authenticated by the enclosing transaction signature.
bool zano_scan_output(const uint8_t view_secret[32], const uint8_t spend_public[32],
                      const uint8_t tx_public[32], uint64_t index,
                      const ZanoConfidentialOutput &output, ZanoReceivedOutput *out);
}
#endif
