#ifndef HEXWALLET_RYO_PHONE_PAYMENT_H
#define HEXWALLET_RYO_PHONE_PAYMENT_H

#include "RyoTransaction.h"
#include "WalletLink.h"

namespace hexwallet {
// BEGIN_SIGN includes the opcode, request ID, length-prefixed "ryo", kind,
// child index, and payload length. Each member costs at least 64 wire bytes
// for MLSAG responses plus 72 bytes of supplied chain data.
constexpr size_t kRyoPhonePayloadMax = kLinkMaxPayload - 16;
constexpr size_t kRyoPhoneRingMembersMax = kRyoPhonePayloadMax / (64 + 72);
// Each member uses up to ten offset bytes and 64 response bytes. Each input
// has at most 36 prefix bytes plus a challenge and pseudo-out. The remaining
// 1,100 bytes cover the v3 header, two outputs, 74-byte extra, RingCT base
// and one two-output proof. The frame bound further limits the actual wire.
constexpr size_t kRyoPhoneWireMax = 74 * kRyoPhoneRingMembersMax + 100 * kRyoMaxTxInputs + 1100;

struct RyoPhonePayment {
  uint8_t wire[kRyoPhoneWireMax];
  size_t wire_size;
  uint32_t address_index;
  uint8_t tx_secret[32];
  RyoSpendReview review;
  size_t input_count;
  RyoSpendSource sources[kRyoMaxTxInputs];
  RyoRingMember members[kRyoPhoneRingMembersMax];
  uint64_t offsets[kRyoPhoneRingMembersMax];
};

// On success source pointers refer to arrays inside state. The session owns
// this object at a stable address until rejection, expiry or consumption.
bool ryo_phone_prepare(const uint8_t *payload, size_t size, const uint8_t spend[32],
                       const uint8_t view[32], RyoPhonePayment &state);
} // namespace hexwallet
#endif
