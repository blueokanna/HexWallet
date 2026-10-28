#ifndef HEXWALLET_FILECOIN_TRANSACTION_H
#define HEXWALLET_FILECOIN_TRANSACTION_H
#include "ChainTransaction.h"
namespace hexwallet {
bool run_filecoin_self_tests();
// Canonical CBOR Message, method Send(0), empty params; f1 sender and f0/f1/f3
// recipients. Output is the canonical CBOR SignedMessage [Message, Signature].
ChainError filecoin_review_payload(const uint8_t *data, size_t size,
                                   const char *sender, ChainReview *review,
                                   uint8_t digest[32]);
ChainError filecoin_sign_payload(const uint8_t *data, size_t size,
                                 const uint8_t private_key[32], uint8_t *out,
                                 size_t *in_out_size);
}
#endif
