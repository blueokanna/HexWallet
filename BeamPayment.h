#pragma once
#include <stddef.h>
#include "BeamOutput.h"

namespace hexwallet {
struct BeamOffer {
  uint64_t amount, fee, min_height, max_height;
  uint8_t sender[32], receiver[32];
  uint8_t sender_excess[33], sender_nonce[33];
};

struct BeamReceiverReply {
  BeamOutput output;
  uint8_t total_excess[33], total_nonce[33];
  uint8_t partial_signature[32], offset[32];
  uint8_t payment_confirmation[65];
};
static_assert(sizeof(BeamReceiverReply) == 902);
constexpr size_t kBeamOfferSize = 162;
bool beam_decode_offer(const uint8_t (&wire)[kBeamOfferSize], BeamOffer &offer);
void beam_encode_offer(const BeamOffer &offer, uint8_t (&wire)[kBeamOfferSize]);

bool beam_endpoint(const uint8_t seed[64], uint64_t index, uint8_t endpoint[32]);
bool beam_receive(const uint8_t seed[64], uint64_t endpoint_index, const BeamOffer &offer,
                  BeamReceiverReply &reply);
bool beam_verify_receiver(const BeamOffer &offer, const BeamReceiverReply &reply);
struct BeamSignedTransfer {
  uint8_t bytes[1632];
  size_t size;
};
class BeamSender {
 public:
  BeamSender() = default;
  ~BeamSender() { cancel(); }
  BeamSender(const BeamSender &) = delete;
  BeamSender &operator=(const BeamSender &) = delete;
  void cancel();
  uint64_t change_amount() const { return change_amount_; }
  bool begin(const uint8_t seed[64], uint64_t endpoint_index, const uint8_t receiver[32],
             const BeamOutput &input, uint64_t amount, uint64_t fee, uint64_t min_height,
             uint64_t max_height, BeamOffer &offer);
  bool finish(const BeamReceiverReply &reply, BeamSignedTransfer &signed_tx);
 private:
  bool active_ = false, has_change_ = false;
  BeamOffer offer_{};
  uint8_t input_[33]{}, kernel_secret_[32]{}, nonce_[32]{}, offset_[32]{};
  BeamOutput change_{};
  uint64_t change_amount_ = 0;
};
}
