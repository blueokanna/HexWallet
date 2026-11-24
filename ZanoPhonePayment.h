#pragma once
#if defined(HEXWALLET_HOST_TEST) && defined(HEXWALLET_TEST_ZANO_PHONE_PAYMENTS)
#include <stddef.h>
#include <stdint.h>

namespace hexwallet {
constexpr uint64_t kZanoPhoneFee = 10000000000ULL;
struct ZanoPaymentReview {
  uint8_t recipient_spend[32], recipient_view[32], payer_spend[32], payer_view[32];
  uint64_t amount, change, payment_id;
  uint8_t prefix_hash[32];
};
struct ZanoPhonePayment {
  uint32_t address_index;
  size_t size;
  uint8_t payload[5000]; // Two fixed 16-member inputs and two ordinary outputs.
  ZanoPaymentReview review;
};
bool zano_phone_review(const ZanoPhonePayment &payment, const uint8_t spend[32], const uint8_t view[32],
                       ZanoPaymentReview &review);
bool zano_phone_sign(const ZanoPhonePayment &payment, const uint8_t spend[32], const uint8_t view[32],
                     uint8_t *result, size_t *size);
}
#endif
