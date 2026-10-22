#ifndef HEXWALLET_LINK_H
#define HEXWALLET_LINK_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {
constexpr size_t kLinkProtocolVersion = 1;
constexpr size_t kLinkMaxPayload = 4608;
constexpr size_t kLinkHeaderSize = 18;
constexpr size_t kLinkMaxFrameSize =
    kLinkHeaderSize + kLinkMaxPayload + 32;
constexpr uint32_t kLinkSessionTimeoutMs = 3UL * 60UL * 1000UL;
constexpr uint32_t kLinkMaxFramesPerSession = 4096;

enum class WalletLinkType : uint8_t {
  PairRequest = 0x01,
  PairResponse = 0x02,
  HelloRequest = 0x03,
  HelloResponse = 0x04,
  Request = 0x10,
  Response = 0x11,
  Error = 0x7f,
};

enum class WalletLinkStatus : uint8_t {
  Ok = 0,
  Ignored,
  PendingPairing,
  Rejected,
  InvalidArgument,
  BufferTooSmall,
  NoSession,
  Expired,
  Replay,
  AuthenticationFailed,
  RequestFailed,
};

struct WalletLinkFrameInfo {
  WalletLinkType type;
  uint32_t session_id;
  uint32_t sequence;
  // Points at the 18-byte frame header, which is also the AEAD associated
  // data for Request/Response frames.
  const uint8_t *header;
  const uint8_t *payload;
  size_t payload_size;
  // Non-null only for encrypted Request/Response frames. The tag follows the
  // payload and is not included in payload_size.
  const uint8_t *tag;
};

struct WalletLinkCallbacks {
  bool (*load_phone_key)(void *context, uint8_t out_public_key[32]);
  bool (*store_phone_key)(void *context, const uint8_t phone_public_key[32]);
  void (*show_pairing_code)(void *context, const uint8_t phone_public_key[32],
                            uint32_t code);
  // Clears a pairing prompt that is no longer valid (timeout or rejection).
  void (*clear_pairing_prompt)(void *context);
  // Handles a decrypted application request and writes the plaintext reply.
  WalletLinkStatus (*handle_request)(void *context, const uint8_t *request,
                                     size_t request_size, uint8_t *response,
                                     size_t response_capacity,
                                     size_t *response_size);
};

class WalletLinkDevice {
 public:
  WalletLinkDevice();
  bool init(const uint8_t identity_seed[32],
            const WalletLinkCallbacks &callbacks, void *context);
  void reset_session();
  void reset_pairing();

  WalletLinkStatus receive(const uint8_t *frame, size_t frame_size,
                           uint32_t now_ms, uint8_t *response,
                           size_t response_capacity, size_t *response_size);

  // Called by the trusted UI after the user confirms the displayed code.
  bool confirm_pairing();
  bool pairing_pending() const;
  bool session_active() const;
  uint32_t session_id() const;
  const uint8_t *device_public_key() const;

  // Expires an abandoned pairing prompt and an idle session. Returns true
  // when state was dropped, so the caller can redraw the trusted display.
  bool tick(uint32_t now_ms);

 private:
  WalletLinkStatus handle_pair_request(const WalletLinkFrameInfo &frame,
                                       uint32_t now_ms, uint8_t *response,
                                       size_t response_capacity,
                                       size_t *response_size);
  WalletLinkStatus handle_hello_request(const WalletLinkFrameInfo &frame,
                                        uint32_t now_ms, uint8_t *response,
                                        size_t response_capacity,
                                        size_t *response_size);
  WalletLinkStatus handle_secure_request(const WalletLinkFrameInfo &frame,
                                         uint32_t now_ms, uint8_t *response,
                                         size_t response_capacity,
                                         size_t *response_size);
  WalletLinkStatus build_plain_frame(WalletLinkType type, uint32_t sequence,
                                     const uint8_t *payload,
                                     size_t payload_size, uint8_t *response,
                                     size_t response_capacity,
                                     size_t *response_size) const;

  WalletLinkCallbacks callbacks_;
  void *context_;
  bool initialized_;
  uint8_t identity_seed_[32];
  uint8_t identity_public_[32];
  uint8_t phone_public_[32];
  bool have_phone_;

  bool pairing_pending_;
  bool pairing_confirmed_;
  uint32_t pairing_started_ms_;
  uint8_t pairing_phone_[32];
  uint8_t pairing_nonce_[32];

  bool session_active_;
  uint32_t session_id_;
  uint32_t tx_sequence_;
  uint32_t rx_sequence_;
  uint32_t frame_count_;
  uint32_t last_activity_ms_;
  uint8_t key_c2d_[32];
  uint8_t key_d2c_[32];
};

bool wallet_link_frame_encode(WalletLinkType type, uint32_t session_id,
                              uint32_t sequence, const uint8_t *payload,
                              size_t payload_size, uint8_t *out,
                              size_t out_capacity, size_t *out_size);
bool wallet_link_frame_decode(const uint8_t *frame, size_t frame_size,
                              WalletLinkFrameInfo *out);

bool run_wallet_link_self_test();

}  // namespace hexwallet

#endif
