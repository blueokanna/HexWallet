#ifndef HEXWALLET_QRL_TRANSACTION_H
#define HEXWALLET_QRL_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"
#include "CryptoPrimitives.h"
#include "QrlOtsStore.h"
#include "QrlXmss.h"

namespace hexwallet {

// QRL v1 native transfers (XMSS/SHAKE-256 accounts, "Q..." addresses).
//
// The signed object is not the protobuf that goes on the wire. QRL signs
// sha256() of a fixed preimage, and the node recomputes that hash from the
// transaction body it receives:
//
//   data_bytes = master_addr(39) || fee_be8 || message_data ||
//                for each output: address(39) || amount_be8
//   data_hash  = sha256(data_bytes)
//   signature  = XMSS_sign(data_hash)                  (one leaf, once)
//   txhash     = sha256(data_hash || signature || public_key)
//
// qrllib's TransferTransaction.get_data_bytes() builds exactly this, so a
// signature produced here verifies on a QRL node and, more to the point, the
// device displays the same recipient/amount/fee bytes that the hash covers.
// Anything not in the preimage (the nonce, the OTS index) is shown but is not
// signed; the nonce is network state the device cannot verify offline.
//
// Payload "QRL1":
//   0  "QRL1"
//   4  u8  flags                (must be 0 - reserved so the layout can grow)
//   5  u64 fee_be               (Shor, 1 QRL = 1e8 Shor)
//   13 u32 nonce_be             (display only; QRL account nonce)
//   17 u16 message_size_be      (0..kQrlMaxMessageSize)
//   19 u8  message[message_size]
//      u8  output_count         (1..kQrlMaxOutputs)
//      output_count x { u8 address[kQrlAddressBinarySize], u64 amount_be }
//
// The address is the raw 39-byte QRL account address (descriptor || hash ||
// checksum). The device re-checks each checksum and shows "Q" + hex, so the host
// cannot slip a binary destination past the screen.
constexpr size_t kQrlAddressBinarySize = 39;
constexpr size_t kQrlMaxOutputs = 8;
constexpr size_t kQrlMaxMessageSize = 512;
constexpr uint8_t kQrlDecimals = 8;
constexpr size_t kQrlPayloadFixedSize = 19;
constexpr size_t kQrlPreimageSize =
    kQrlAddressBinarySize + 8 + kQrlMaxMessageSize +
    kQrlMaxOutputs * (kQrlAddressBinarySize + 8);
// signature || data hash || public key: the host needs all three to assemble
// the protobuf and to recompute the txhash, and none of them is secret.
constexpr size_t kQrlMaxSignedSize =
    kQrlMaxSignatureSize + kSha256Size + kQrlPublicKeySize;

// Parses the payload, rebuilds the signed preimage from the derived sender
// address and fills the review. No signing happens here.
ChainError qrl_review_payload(const uint8_t *payload, size_t size,
                              const char *sender, ChainReview *review,
                              uint8_t digest[32]);

// Re-derives the account from the BIP39 seed, rebuilds the preimage, reserves
// the next one-time leaf in `port`, signs and self-verifies before returning.
// The journal is bound at index zero on first use; `port` may be null, in which
// case the platform store is used and signing fails closed when there is none.
ChainError qrl_sign_payload(QrlOtsSlotPort *port, const uint8_t *payload,
                            size_t size, const char *sender,
                            const uint8_t seed[kSeedSize],
                            uint32_t address_index, uint8_t *out,
                            size_t *in_out_size);

bool run_qrl_transaction_self_tests();

}  // namespace hexwallet

#endif
