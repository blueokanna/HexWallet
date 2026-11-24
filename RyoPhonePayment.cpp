#include "RyoPhonePayment.h"

#include <string.h>
#include "WalletConfig.h"

namespace hexwallet {
namespace {
uint64_t little_endian(const uint8_t *p, size_t bytes) {
  uint64_t result = 0;
  for (size_t i = 0; i < bytes; ++i) result |= static_cast<uint64_t>(p[i]) << (8 * i);
  return result;
}
}

bool ryo_phone_prepare(const uint8_t *payload, size_t size, const uint8_t spend[32],
                       const uint8_t view[32], RyoPhonePayment &state) {
  // version(1), wire size(2), wire, transaction secret, recipient spend/view,
  // then one funding record per wire input. Counts come from the parsed wire.
  constexpr size_t header = 3;
  constexpr size_t keys = 96;
  constexpr size_t source_header = 2 + 8 + 32 + 64 + 32;
  if (!payload || size < header + keys || size > kRyoPhonePayloadMax || payload[0] != 1) return false;
  state.wire_size = little_endian(payload + 1, 2);
  if (state.wire_size > size - header - keys || state.wire_size > sizeof(state.wire)) return false;
  memcpy(state.wire, payload + header, state.wire_size);
  RyoTransactionView tx{};
  if (ryo_parse_transaction(state.wire, state.wire_size, &tx) != RyoTxError::Ok || tx.version != 3 ||
      tx.fee > HEXWALLET_RYO_MAX_FEE_ATOMIC || tx.ring_size < 25) return false;
  const size_t members = static_cast<size_t>(tx.ring_size) * tx.input_count;
  if (members > kRyoPhoneRingMembersMax ||
      size - header - state.wire_size - keys != tx.input_count * source_header + members * 72) return false;
  const uint8_t *p = payload + header + state.wire_size;
  memcpy(state.tx_secret, p, 32);
  RyoPublicAddress recipient;
  memcpy(recipient.spend, p + 32, 32);
  memcpy(recipient.view, p + 64, 32);
  p += keys;
  state.input_count = tx.input_count;
  for (size_t i = 0; i < state.input_count; ++i) {
    RyoSpendSource &src = state.sources[i];
    src.real_index = little_endian(p, 2);
    src.funding_output_index = little_endian(p + 2, 8);
    memcpy(src.funding_tx_public, p + 10, 32);
    memcpy(src.funding_ecdh, p + 42, 64);
    memcpy(src.pseudo_mask, p + 106, 32);
    p += source_header;
    const size_t first = i * tx.ring_size;
    src.ring = state.members + first;
    src.absolute_offsets = state.offsets + first;
    src.ring_size = tx.ring_size;
    for (size_t j = 0; j < tx.ring_size; ++j, p += 72) {
      state.offsets[first + j] = little_endian(p, 8);
      memcpy(state.members[first + j].destination, p + 8, 32);
      memcpy(state.members[first + j].commitment, p + 40, 32);
    }
  }
  return ryo_review_spend(state.wire, state.wire_size, state.sources, state.input_count,
                          spend, view, state.tx_secret, recipient, &state.review);
}
} // namespace hexwallet
