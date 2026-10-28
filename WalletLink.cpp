#include "WalletLink.h"

#include "RandomSource.h"
#include <esp_system.h>
#include <string.h>

#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "WalletLinkCrypto.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {
constexpr uint8_t kMagic[4] = { 'H', 'W', 'L', 'K' };
constexpr uint8_t kDirectionDeviceToPhone = 1;
constexpr uint8_t kDirectionPhoneToDevice = 2;
constexpr uint32_t kPairingTimeoutMs = 60UL * 1000UL;

// Every link request is handled on the Arduino loop task, which has 8 KiB of
// stack. Two kLinkMaxPayload frames there would overflow it, so the request and
// reply scratch space is static; the link processes one request at a time.
uint8_t *link_request_scratch() {
  static uint8_t buffer[kLinkMaxPayload];
  return buffer;
}

uint8_t *link_reply_scratch() {
  static uint8_t buffer[kLinkMaxPayload];
  return buffer;
}

void write_le32(uint8_t *out, uint32_t value) {
  out[0] = static_cast<uint8_t>(value);
  out[1] = static_cast<uint8_t>(value >> 8);
  out[2] = static_cast<uint8_t>(value >> 16);
  out[3] = static_cast<uint8_t>(value >> 24);
}

uint32_t read_le32(const uint8_t *data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) |
         (static_cast<uint32_t>(data[3]) << 24);
}

bool elapsed_at_least(uint32_t now, uint32_t then, uint32_t interval) {
  return static_cast<uint32_t>(now - then) >= interval;
}

bool is_secure_type(WalletLinkType type) {
  return type == WalletLinkType::Request || type == WalletLinkType::Response;
}

bool sign_domain(const uint8_t seed[32], const char *domain,
                 const uint8_t *fields, size_t fields_size,
                 uint8_t out_signature[64]) {
  const size_t domain_size = strlen(domain);
  constexpr size_t kMaxSignedSize = 256;
  if (domain_size + fields_size > kMaxSignedSize) return false;
  uint8_t buffer[kMaxSignedSize];
  memcpy(buffer, domain, domain_size);
  if (fields_size != 0) memcpy(buffer + domain_size, fields, fields_size);
  const bool ok = ed25519_sign(seed, buffer, domain_size + fields_size,
                               out_signature);
  secure_zero(buffer, sizeof(buffer));
  return ok;
}

bool verify_domain(const uint8_t public_key[32], const char *domain,
                   const uint8_t *fields, size_t fields_size,
                   const uint8_t signature[64]) {
  const size_t domain_size = strlen(domain);
  constexpr size_t kMaxSignedSize = 256;
  if (domain_size + fields_size > kMaxSignedSize) return false;
  uint8_t buffer[kMaxSignedSize];
  memcpy(buffer, domain, domain_size);
  if (fields_size != 0) memcpy(buffer + domain_size, fields, fields_size);
  const bool ok = ed25519_verify(public_key, buffer, domain_size + fields_size,
                                 signature);
  secure_zero(buffer, sizeof(buffer));
  return ok;
}

bool make_session_nonce(uint32_t session_id, uint8_t direction,
                        uint32_t sequence, uint8_t out[12]) {
  memset(out, 0, 12);
  write_le32(out, session_id);
  out[4] = direction;
  write_le32(out + 5, sequence);
  out[9] = 0;
  out[10] = 0;
  out[11] = 0;
  return true;
}

bool derive_session_keys(const uint8_t local_ephemeral_seed[32],
                         const uint8_t peer_ephemeral[32],
                         const uint8_t phone_public[32],
                         const uint8_t phone_ephemeral[32],
                         const uint8_t phone_nonce[32],
                         const uint8_t device_public[32],
                         const uint8_t device_ephemeral[32],
                         const uint8_t device_nonce[32],
                         uint8_t out_c2d[32], uint8_t out_d2c[32],
                         uint32_t *out_session_id) {
  static const uint8_t kSessionLabel[] = "HWLK1-SESSION";
  static const uint8_t kKeyInfo[] = "HWLK1-KEYS";
  uint8_t transcript[sizeof(kSessionLabel) - 1 + 6 * 32];
  size_t offset = 0;
  memcpy(transcript, kSessionLabel, sizeof(kSessionLabel) - 1);
  offset += sizeof(kSessionLabel) - 1;
  memcpy(transcript + offset, phone_public, 32);
  offset += 32;
  memcpy(transcript + offset, phone_ephemeral, 32);
  offset += 32;
  memcpy(transcript + offset, phone_nonce, 32);
  offset += 32;
  memcpy(transcript + offset, device_public, 32);
  offset += 32;
  memcpy(transcript + offset, device_ephemeral, 32);
  offset += 32;
  memcpy(transcript + offset, device_nonce, 32);
  offset += 32;

  uint8_t transcript_hash[32];
  uint8_t shared[32];
  uint8_t keys[64];
  bool ok = crypto_sha256(transcript, offset, transcript_hash) &&
            ed25519_ecdh(local_ephemeral_seed, peer_ephemeral, shared) &&
            link_hkdf_sha256(shared, sizeof(shared), transcript_hash,
                             sizeof(transcript_hash), kKeyInfo,
                             sizeof(kKeyInfo) - 1, keys, sizeof(keys));
  if (ok) {
    memcpy(out_c2d, keys, 32);
    memcpy(out_d2c, keys + 32, 32);
    *out_session_id = read_le32(transcript_hash);
  }
  secure_zero(transcript, sizeof(transcript));
  secure_zero(transcript_hash, sizeof(transcript_hash));
  secure_zero(shared, sizeof(shared));
  secure_zero(keys, sizeof(keys));
  return ok;
}

bool build_header(WalletLinkType type, uint32_t session_id, uint32_t sequence,
                  size_t payload_size, uint8_t out[kLinkHeaderSize]) {
  if (payload_size > kLinkMaxPayload) return false;
  memcpy(out, kMagic, sizeof(kMagic));
  out[4] = static_cast<uint8_t>(kLinkProtocolVersion);
  out[5] = static_cast<uint8_t>(type);
  out[6] = 0;
  out[7] = 0;
  write_le32(out + 8, session_id);
  write_le32(out + 12, sequence);
  out[16] = static_cast<uint8_t>(payload_size);
  out[17] = static_cast<uint8_t>(payload_size >> 8);
  return true;
}

}  // namespace

WalletLinkDevice::WalletLinkDevice()
    : callbacks_{}, context_(nullptr), initialized_(false), identity_seed_{},
      identity_public_{}, phone_public_{}, have_phone_(false),
      pairing_pending_(false), pairing_confirmed_(false),
      pairing_started_ms_(0), pairing_phone_{}, pairing_nonce_{},
      session_active_(false), session_id_(0), tx_sequence_(0), rx_sequence_(0),
      frame_count_(0), last_activity_ms_(0), key_c2d_{}, key_d2c_{} {}

bool WalletLinkDevice::init(const uint8_t identity_seed[32],
                            const WalletLinkCallbacks &callbacks,
                            void *context) {
  if (identity_seed == nullptr) return false;
  memcpy(identity_seed_, identity_seed, sizeof(identity_seed_));
  if (!ed25519_public_key(identity_seed_, identity_public_)) {
    secure_zero(identity_seed_, sizeof(identity_seed_));
    return false;
  }
  callbacks_ = callbacks;
  context_ = context;
  initialized_ = true;
  reset_session();
  reset_pairing();
  have_phone_ = false;
  if (callbacks_.load_phone_key != nullptr) {
    have_phone_ = callbacks_.load_phone_key(context_, phone_public_);
  }
  return true;
}

void WalletLinkDevice::reset_session() {
  session_active_ = false;
  session_id_ = 0;
  tx_sequence_ = 0;
  rx_sequence_ = 0;
  frame_count_ = 0;
  last_activity_ms_ = 0;
  secure_zero(key_c2d_, sizeof(key_c2d_));
  secure_zero(key_d2c_, sizeof(key_d2c_));
}

void WalletLinkDevice::reset_pairing() {
  pairing_pending_ = false;
  pairing_confirmed_ = false;
  pairing_started_ms_ = 0;
  secure_zero(pairing_phone_, sizeof(pairing_phone_));
  secure_zero(pairing_nonce_, sizeof(pairing_nonce_));
}

bool WalletLinkDevice::confirm_pairing() {
  if (!pairing_pending_ || pairing_confirmed_) return false;
  if (callbacks_.store_phone_key == nullptr ||
      !callbacks_.store_phone_key(context_, pairing_phone_)) {
    reset_pairing();
    return false;
  }
  pairing_confirmed_ = true;
  memcpy(phone_public_, pairing_phone_, sizeof(phone_public_));
  have_phone_ = true;
  return true;
}

bool WalletLinkDevice::pairing_pending() const {
  return pairing_pending_ && !pairing_confirmed_;
}

bool WalletLinkDevice::session_active() const {
  return session_active_;
}

uint32_t WalletLinkDevice::session_id() const {
  return session_active_ ? session_id_ : 0;
}

bool WalletLinkDevice::tick(uint32_t now_ms) {
  bool changed = false;
  if (pairing_pending_ && !pairing_confirmed_ &&
      elapsed_at_least(now_ms, pairing_started_ms_, kPairingTimeoutMs)) {
    reset_pairing();
    if (callbacks_.clear_pairing_prompt != nullptr) {
      callbacks_.clear_pairing_prompt(context_);
    }
    changed = true;
  }
  if (session_active_ &&
      elapsed_at_least(now_ms, last_activity_ms_, kLinkSessionTimeoutMs)) {
    reset_session();
    changed = true;
  }
  return changed;
}

const uint8_t *WalletLinkDevice::device_public_key() const {
  return identity_public_;
}

WalletLinkStatus WalletLinkDevice::build_plain_frame(
    WalletLinkType type, uint32_t sequence, const uint8_t *payload,
    size_t payload_size, uint8_t *response, size_t response_capacity,
    size_t *response_size) const {
  return wallet_link_frame_encode(type, 0, sequence, payload, payload_size,
                                  response, response_capacity, response_size)
             ? WalletLinkStatus::Ok
             : WalletLinkStatus::BufferTooSmall;
}

WalletLinkStatus WalletLinkDevice::handle_pair_request(
    const WalletLinkFrameInfo &frame, uint32_t now_ms, uint8_t *response,
    size_t response_capacity, size_t *response_size) {
  constexpr size_t kPairRequestSize = 32 + 32 + 64;
  constexpr size_t kPairResponseSize = 32 + 32 + 32 + 64;
  if (frame.payload_size != kPairRequestSize || frame.tag != nullptr ||
      frame.session_id != 0 || frame.sequence != 0) {
    return WalletLinkStatus::InvalidArgument;
  }
  const uint8_t *phone_public = frame.payload;
  const uint8_t *phone_nonce = frame.payload + 32;
  const uint8_t *signature = frame.payload + 64;
  uint8_t signed_fields[64];
  memcpy(signed_fields, phone_public, 32);
  memcpy(signed_fields + 32, phone_nonce, 32);
  const bool self_signed = verify_domain(phone_public, "HWLK1-PAIR",
                                         signed_fields, sizeof(signed_fields),
                                         signature);
  secure_zero(signed_fields, sizeof(signed_fields));
  if (!self_signed) return WalletLinkStatus::AuthenticationFailed;

  if (have_phone_) {
    if (!crypto_constant_time_equal(phone_public, phone_public_, 32)) {
      return WalletLinkStatus::Rejected;
    }
  } else {
    if (pairing_pending_ &&
        elapsed_at_least(now_ms, pairing_started_ms_, kPairingTimeoutMs)) {
      // An abandoned pairing must not block the next legitimate attempt.
      reset_pairing();
      if (callbacks_.clear_pairing_prompt != nullptr) {
        callbacks_.clear_pairing_prompt(context_);
      }
    }
    if (pairing_pending_) {
      if (!crypto_constant_time_equal(phone_public, pairing_phone_, 32) ||
          !crypto_constant_time_equal(phone_nonce, pairing_nonce_, 32)) {
        // A third party must not be able to cancel the pairing that is
        // already on screen, so the pending state is left untouched.
        return WalletLinkStatus::Rejected;
      }
      if (!pairing_confirmed_) {
        return WalletLinkStatus::PendingPairing;
      }
    } else {
      pairing_pending_ = true;
      pairing_confirmed_ = false;
      pairing_started_ms_ = now_ms;
      memcpy(pairing_phone_, phone_public, 32);
      memcpy(pairing_nonce_, phone_nonce, 32);
      if (callbacks_.show_pairing_code != nullptr) {
        static const uint8_t kCodeLabel[] = "HWLK1-PAIR-CODE";
        uint8_t code_input[sizeof(kCodeLabel) - 1 + 64];
        memcpy(code_input, kCodeLabel, sizeof(kCodeLabel) - 1);
        memcpy(code_input + sizeof(kCodeLabel) - 1, phone_public, 32);
        memcpy(code_input + sizeof(kCodeLabel) - 1 + 32, identity_public_, 32);
        uint8_t digest[32];
        uint32_t code = 0;
        if (crypto_sha256(code_input, sizeof(code_input), digest)) {
          code = (static_cast<uint32_t>(digest[0]) << 16) |
                 (static_cast<uint32_t>(digest[1]) << 8) |
                 static_cast<uint32_t>(digest[2]);
          code %= 1000000UL;
        }
        secure_zero(code_input, sizeof(code_input));
        secure_zero(digest, sizeof(digest));
        callbacks_.show_pairing_code(context_, phone_public_, code);
      }
      return WalletLinkStatus::PendingPairing;
    }
  }

  uint8_t payload[kPairResponseSize];
  size_t offset = 0;
  memcpy(payload + offset, identity_public_, 32);
  offset += 32;
  memcpy(payload + offset, phone_nonce, 32);
  offset += 32;
  uint8_t device_nonce[32];
  random_fill(device_nonce, sizeof(device_nonce));
  memcpy(payload + offset, device_nonce, 32);
  offset += 32;
  uint8_t signed_fields_response[32 + 32 + 32 + 32];
  memcpy(signed_fields_response, phone_public, 32);
  memcpy(signed_fields_response + 32, identity_public_, 32);
  memcpy(signed_fields_response + 64, phone_nonce, 32);
  memcpy(signed_fields_response + 96, device_nonce, 32);
  bool ok = sign_domain(identity_seed_, "HWLK1-PAIR-RESP",
                        signed_fields_response, sizeof(signed_fields_response),
                        payload + offset);
  if (ok) {
    ok = build_plain_frame(WalletLinkType::PairResponse, 1, payload,
                           sizeof(payload), response, response_capacity,
                           response_size) == WalletLinkStatus::Ok;
  }
  secure_zero(device_nonce, sizeof(device_nonce));
  secure_zero(signed_fields_response, sizeof(signed_fields_response));
  secure_zero(payload, sizeof(payload));
  return ok ? WalletLinkStatus::Ok : WalletLinkStatus::BufferTooSmall;
}

WalletLinkStatus WalletLinkDevice::handle_hello_request(
    const WalletLinkFrameInfo &frame, uint32_t now_ms, uint8_t *response,
    size_t response_capacity, size_t *response_size) {
  constexpr size_t kHelloRequestSize = 32 + 32 + 32 + 64;
  constexpr size_t kHelloResponseSize = 32 + 32 + 32 + 64;
  if (frame.payload_size != kHelloRequestSize || frame.tag != nullptr ||
      frame.session_id != 0 || frame.sequence != 0) {
    return WalletLinkStatus::InvalidArgument;
  }
  const uint8_t *phone_public = frame.payload;
  const uint8_t *phone_ephemeral = frame.payload + 32;
  const uint8_t *phone_nonce = frame.payload + 64;
  const uint8_t *signature = frame.payload + 96;
  if (!have_phone_ ||
      !crypto_constant_time_equal(phone_public, phone_public_, 32)) {
    return WalletLinkStatus::Rejected;
  }
  uint8_t signed_fields[96];
  memcpy(signed_fields, phone_public, 32);
  memcpy(signed_fields + 32, phone_ephemeral, 32);
  memcpy(signed_fields + 64, phone_nonce, 32);
  const bool hello_signed = verify_domain(phone_public, "HWLK1-HELLO",
                                          signed_fields, sizeof(signed_fields),
                                          signature);
  secure_zero(signed_fields, sizeof(signed_fields));
  if (!hello_signed) return WalletLinkStatus::AuthenticationFailed;

  uint8_t device_ephemeral_seed[32];
  uint8_t device_ephemeral[32];
  uint8_t device_nonce[32];
  random_fill(device_ephemeral_seed, sizeof(device_ephemeral_seed));
  random_fill(device_nonce, sizeof(device_nonce));
  bool ok = ed25519_public_key(device_ephemeral_seed, device_ephemeral);

  uint8_t response_fields[32 * 6];
  memcpy(response_fields, phone_public, 32);
  memcpy(response_fields + 32, phone_ephemeral, 32);
  memcpy(response_fields + 64, phone_nonce, 32);
  memcpy(response_fields + 96, identity_public_, 32);
  memcpy(response_fields + 128, device_ephemeral, 32);
  memcpy(response_fields + 160, device_nonce, 32);
  uint8_t device_signature[64];
  if (ok) {
    ok = sign_domain(identity_seed_, "HWLK1-RESP", response_fields,
                     sizeof(response_fields), device_signature);
  }

  uint8_t payload[kHelloResponseSize];
  if (ok) {
    size_t offset = 0;
    memcpy(payload + offset, identity_public_, 32);
    offset += 32;
    memcpy(payload + offset, device_ephemeral, 32);
    offset += 32;
    memcpy(payload + offset, device_nonce, 32);
    offset += 32;
    memcpy(payload + offset, device_signature, 64);
    ok = derive_session_keys(
        device_ephemeral_seed, phone_ephemeral, phone_public, phone_ephemeral,
        phone_nonce, identity_public_, device_ephemeral, device_nonce,
        key_c2d_, key_d2c_, &session_id_);
  }
  if (ok) {
    tx_sequence_ = 0;
    rx_sequence_ = 0;
    frame_count_ = 0;
    last_activity_ms_ = now_ms;
    session_active_ = true;
    ok = build_plain_frame(WalletLinkType::HelloResponse, 0, payload,
                           sizeof(payload), response, response_capacity,
                           response_size) == WalletLinkStatus::Ok;
  }
  secure_zero(device_ephemeral_seed, sizeof(device_ephemeral_seed));
  secure_zero(device_ephemeral, sizeof(device_ephemeral));
  secure_zero(device_nonce, sizeof(device_nonce));
  secure_zero(response_fields, sizeof(response_fields));
  secure_zero(device_signature, sizeof(device_signature));
  secure_zero(payload, sizeof(payload));
  if (!ok) reset_session();
  return ok ? WalletLinkStatus::Ok : WalletLinkStatus::AuthenticationFailed;
}

WalletLinkStatus WalletLinkDevice::handle_secure_request(
    const WalletLinkFrameInfo &frame, uint32_t now_ms, uint8_t *response,
    size_t response_capacity, size_t *response_size) {
  if (frame.type != WalletLinkType::Request || frame.tag == nullptr) {
    return WalletLinkStatus::InvalidArgument;
  }
  if (!session_active_) return WalletLinkStatus::NoSession;
  if (frame.session_id != session_id_) return WalletLinkStatus::Rejected;
  if (frame.sequence != rx_sequence_) return WalletLinkStatus::Replay;
  if (frame_count_ >= kLinkMaxFramesPerSession ||
      elapsed_at_least(now_ms, last_activity_ms_, kLinkSessionTimeoutMs)) {
    reset_session();
    return WalletLinkStatus::Expired;
  }
  if (frame.payload_size > kLinkMaxPayload) {
    return WalletLinkStatus::BufferTooSmall;
  }

  uint8_t nonce[12];
  make_session_nonce(session_id_, kDirectionPhoneToDevice, rx_sequence_, nonce);
  uint8_t *plaintext = link_request_scratch();
  const bool opened = link_aead_open(key_c2d_, nonce, frame.header,
                                      kLinkHeaderSize, frame.payload,
                                      frame.payload_size, frame.tag, plaintext);
  if (!opened) {
    secure_zero(plaintext, kLinkMaxPayload);
    reset_session();
    return WalletLinkStatus::AuthenticationFailed;
  }
  ++rx_sequence_;
  ++frame_count_;
  last_activity_ms_ = now_ms;

  if (callbacks_.handle_request == nullptr) {
    secure_zero(plaintext, kLinkMaxPayload);
    return WalletLinkStatus::RequestFailed;
  }
  uint8_t *reply = link_reply_scratch();
  size_t reply_size = 0;
  const WalletLinkStatus request_status = callbacks_.handle_request(
      context_, plaintext, frame.payload_size, reply, kLinkMaxPayload,
      &reply_size);
  secure_zero(plaintext, kLinkMaxPayload);
  if (request_status != WalletLinkStatus::Ok || reply_size > kLinkMaxPayload) {
    secure_zero(reply, kLinkMaxPayload);
    return WalletLinkStatus::RequestFailed;
  }

  uint8_t header[kLinkHeaderSize];
  if (!build_header(WalletLinkType::Response, session_id_, tx_sequence_,
                    reply_size, header) ||
      response_capacity < kLinkHeaderSize + reply_size + kLinkTagSize) {
    secure_zero(reply, kLinkMaxPayload);
    return WalletLinkStatus::BufferTooSmall;
  }
  uint8_t response_nonce[12];
  make_session_nonce(session_id_, kDirectionDeviceToPhone, tx_sequence_,
                     response_nonce);
  const bool sealed =
      link_aead_seal(key_d2c_, response_nonce, header, sizeof(header), reply,
                     reply_size, response + kLinkHeaderSize,
                     response + kLinkHeaderSize + reply_size);
  secure_zero(reply, kLinkMaxPayload);
  if (!sealed) return WalletLinkStatus::AuthenticationFailed;
  memcpy(response, header, sizeof(header));
  *response_size = kLinkHeaderSize + reply_size + kLinkTagSize;
  ++tx_sequence_;
  ++frame_count_;
  return WalletLinkStatus::Ok;
}

WalletLinkStatus WalletLinkDevice::receive(const uint8_t *frame,
                                           size_t frame_size, uint32_t now_ms,
                                           uint8_t *response,
                                           size_t response_capacity,
                                           size_t *response_size) {
  if (response_size == nullptr) return WalletLinkStatus::InvalidArgument;
  *response_size = 0;
  if (!initialized_ || frame == nullptr || response == nullptr) {
    return WalletLinkStatus::InvalidArgument;
  }
  WalletLinkFrameInfo info;
  if (!wallet_link_frame_decode(frame, frame_size, &info)) {
    return WalletLinkStatus::InvalidArgument;
  }
  switch (info.type) {
    case WalletLinkType::PairRequest:
      return handle_pair_request(info, now_ms, response, response_capacity,
                                 response_size);
    case WalletLinkType::HelloRequest:
      return handle_hello_request(info, now_ms, response, response_capacity,
                                  response_size);
    case WalletLinkType::Request:
      return handle_secure_request(info, now_ms, response, response_capacity,
                                   response_size);
    case WalletLinkType::PairResponse:
    case WalletLinkType::HelloResponse:
    case WalletLinkType::Response:
    case WalletLinkType::Error:
      return WalletLinkStatus::Ignored;
  }
  return WalletLinkStatus::Ignored;
}

bool wallet_link_frame_encode(WalletLinkType type, uint32_t session_id,
                              uint32_t sequence, const uint8_t *payload,
                              size_t payload_size, uint8_t *out,
                              size_t out_capacity, size_t *out_size) {
  if (out == nullptr || out_size == nullptr ||
      (payload == nullptr && payload_size != 0) || payload_size > kLinkMaxPayload) {
    return false;
  }
  const size_t total = kLinkHeaderSize + payload_size;
  if (out_capacity < total) return false;
  if (!build_header(type, session_id, sequence, payload_size, out)) return false;
  if (payload_size != 0) memcpy(out + kLinkHeaderSize, payload, payload_size);
  *out_size = total;
  return true;
}

bool wallet_link_frame_decode(const uint8_t *frame, size_t frame_size,
                              WalletLinkFrameInfo *out) {
  if (frame == nullptr || out == nullptr || frame_size < kLinkHeaderSize) {
    return false;
  }
  if (memcmp(frame, kMagic, sizeof(kMagic)) != 0 ||
      frame[4] != kLinkProtocolVersion || frame[6] != 0 || frame[7] != 0) {
    return false;
  }
  const WalletLinkType type = static_cast<WalletLinkType>(frame[5]);
  const uint16_t payload_size =
      static_cast<uint16_t>(frame[16]) |
      static_cast<uint16_t>(static_cast<uint16_t>(frame[17]) << 8);
  if (payload_size > kLinkMaxPayload) return false;
  const size_t tag_size = is_secure_type(type) ? kLinkTagSize : 0;
  if (frame_size != kLinkHeaderSize + payload_size + tag_size) return false;
  out->type = type;
  out->session_id = read_le32(frame + 8);
  out->sequence = read_le32(frame + 12);
  out->header = frame;
  out->payload = frame + kLinkHeaderSize;
  out->payload_size = payload_size;
  out->tag = tag_size == 0 ? nullptr : frame + kLinkHeaderSize + payload_size;
  return true;
}

bool run_wallet_link_self_test() {
  static const uint8_t kDeviceSeed[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x20, 0x30,
  };
  static const uint8_t kPhoneSeed[32] = {
    0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
    0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xa0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
  };
  static const uint8_t kPhoneEphemeralSeed[32] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
  };
  static const uint8_t kPhoneNonce[32] = {
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
  };

  uint8_t device_public[32];
  uint8_t phone_public[32];
  uint8_t phone_ephemeral[32];
  bool ok = ed25519_public_key(kDeviceSeed, device_public) &&
            ed25519_public_key(kPhoneSeed, phone_public) &&
            ed25519_public_key(kPhoneEphemeralSeed, phone_ephemeral);

  // Pairing state is kept in a tiny local emulation of the device NVS.
  struct PairStore {
    uint8_t key[32];
    bool present;
    uint32_t code;
    uint32_t prompts_cleared;
  } store = { {}, false, 0, 0 };

  WalletLinkCallbacks callbacks = {};
  callbacks.load_phone_key = [](void *context, uint8_t out[32]) {
    PairStore *pair = static_cast<PairStore *>(context);
    if (!pair->present) return false;
    memcpy(out, pair->key, 32);
    return true;
  };
  callbacks.store_phone_key = [](void *context, const uint8_t key[32]) {
    PairStore *pair = static_cast<PairStore *>(context);
    memcpy(pair->key, key, 32);
    pair->present = true;
    return true;
  };
  callbacks.show_pairing_code = [](void *context, const uint8_t *,
                                   uint32_t code) {
    static_cast<PairStore *>(context)->code = code;
  };
  callbacks.clear_pairing_prompt = [](void *context) {
    ++static_cast<PairStore *>(context)->prompts_cleared;
  };
  callbacks.handle_request = [](void *, const uint8_t *request,
                                size_t request_size, uint8_t *response,
                                size_t response_capacity, size_t *response_size) {
    if (request_size != 4 || response_capacity < 4) return WalletLinkStatus::RequestFailed;
    for (size_t index = 0; index < 4; ++index) {
      response[index] = static_cast<uint8_t>(request[index] ^ 0x5a);
    }
    *response_size = 4;
    return WalletLinkStatus::Ok;
  };

  WalletLinkDevice device;
  ok = ok && device.init(kDeviceSeed, callbacks, &store);

  uint8_t pair_request[128];
  uint8_t pair_signed[64];
  memcpy(pair_request, phone_public, 32);
  memcpy(pair_request + 32, kPhoneNonce, 32);
  memcpy(pair_signed, phone_public, 32);
  memcpy(pair_signed + 32, kPhoneNonce, 32);
  ok = ok && sign_domain(kPhoneSeed, "HWLK1-PAIR", pair_signed,
                         sizeof(pair_signed), pair_request + 64);
  static uint8_t frame[kLinkMaxFrameSize];
  static uint8_t response[kLinkMaxFrameSize];
  size_t frame_size = 0;
  size_t response_size = 0;
  ok = ok && wallet_link_frame_encode(WalletLinkType::PairRequest, 0, 0,
                                      pair_request, sizeof(pair_request), frame,
                                      sizeof(frame), &frame_size);
  WalletLinkStatus status = device.receive(frame, frame_size, 1000, response,
                                           sizeof(response), &response_size);
  ok = ok && status == WalletLinkStatus::PendingPairing && store.code != 0 &&
       device.pairing_pending();

  // A third phone must not be able to cancel the pairing that is on screen.
  {
    static const uint8_t kOtherSeed[32] = { 0x77 };
    uint8_t other_public[32];
    uint8_t other_request[128];
    uint8_t other_signed[64];
    static uint8_t other_frame[kLinkMaxFrameSize];
    ok = ok && ed25519_public_key(kOtherSeed, other_public);
    memcpy(other_request, other_public, 32);
    memset(other_request + 32, 0x21, 32);
    memcpy(other_signed, other_public, 32);
    memcpy(other_signed + 32, other_request + 32, 32);
    ok = ok && sign_domain(kOtherSeed, "HWLK1-PAIR", other_signed,
                           sizeof(other_signed), other_request + 64);
    size_t other_frame_size = 0;
    ok = ok && wallet_link_frame_encode(WalletLinkType::PairRequest, 0, 0,
                                        other_request, sizeof(other_request),
                                        other_frame, sizeof(other_frame),
                                        &other_frame_size);
    const WalletLinkStatus other_status = device.receive(
        other_frame, other_frame_size, 1100, response, sizeof(response),
        &response_size);
    ok = ok && other_status == WalletLinkStatus::Rejected &&
         device.pairing_pending();
  }

  ok = ok && device.confirm_pairing() && store.present;

  status = device.receive(frame, frame_size, 2000, response, sizeof(response),
                          &response_size);
  WalletLinkFrameInfo info;
  ok = ok && status == WalletLinkStatus::Ok &&
       wallet_link_frame_decode(response, response_size, &info) &&
       info.type == WalletLinkType::PairResponse && info.payload_size == 160;

  uint8_t hello_request[160];
  uint8_t hello_signed[96];
  memcpy(hello_request, phone_public, 32);
  memcpy(hello_request + 32, phone_ephemeral, 32);
  memcpy(hello_request + 64, kPhoneNonce, 32);
  memcpy(hello_signed, phone_public, 32);
  memcpy(hello_signed + 32, phone_ephemeral, 32);
  memcpy(hello_signed + 64, kPhoneNonce, 32);
  ok = ok && sign_domain(kPhoneSeed, "HWLK1-HELLO", hello_signed,
                         sizeof(hello_signed), hello_request + 96);
  ok = ok && wallet_link_frame_encode(WalletLinkType::HelloRequest, 0, 0,
                                      hello_request, sizeof(hello_request),
                                      frame, sizeof(frame), &frame_size);
  status = device.receive(frame, frame_size, 3000, response, sizeof(response),
                          &response_size);
  ok = ok && status == WalletLinkStatus::Ok &&
       wallet_link_frame_decode(response, response_size, &info) &&
       info.type == WalletLinkType::HelloResponse;
  ok = ok && device.session_active();

  // The phone side derives the same session keys independently.
  const uint8_t *device_ephemeral = info.payload + 32;
  const uint8_t *device_nonce = info.payload + 64;
  uint8_t phone_c2d[32];
  uint8_t phone_d2c[32];
  uint32_t phone_session_id = 0;
  ok = ok && derive_session_keys(
                 kPhoneEphemeralSeed, device_ephemeral, phone_public,
                 phone_ephemeral, kPhoneNonce, device_public, device_ephemeral,
                 device_nonce, phone_c2d, phone_d2c, &phone_session_id);

  uint8_t secure_plain[4] = { 1, 2, 3, 4 };
  uint8_t secure_header[kLinkHeaderSize];
  static uint8_t secure_frame[kLinkMaxFrameSize];
  uint8_t secure_nonce[12];
  const uint32_t session_id = device.session_id();
  ok = ok && session_id == phone_session_id && session_id != 0 &&
       build_header(WalletLinkType::Request, session_id, 0,
                    sizeof(secure_plain), secure_header) &&
       make_session_nonce(session_id, kDirectionPhoneToDevice, 0, secure_nonce) &&
       link_aead_seal(phone_c2d, secure_nonce, secure_header,
                      sizeof(secure_header), secure_plain, sizeof(secure_plain),
                      secure_frame + kLinkHeaderSize,
                      secure_frame + kLinkHeaderSize + sizeof(secure_plain));
  const size_t secure_size =
      kLinkHeaderSize + sizeof(secure_plain) + kLinkTagSize;
  memcpy(secure_frame, secure_header, sizeof(secure_header));
  status = device.receive(secure_frame, secure_size, 4000, response,
                          sizeof(response), &response_size);
  WalletLinkFrameInfo secure_response;
  uint8_t secure_reply[4];
  uint8_t response_nonce[12];
  ok = ok && status == WalletLinkStatus::Ok &&
       wallet_link_frame_decode(response, response_size, &secure_response) &&
       secure_response.type == WalletLinkType::Response &&
       secure_response.sequence == 0 &&
       make_session_nonce(session_id, kDirectionDeviceToPhone, 0,
                          response_nonce) &&
       link_aead_open(phone_d2c, response_nonce, secure_response.header,
                      kLinkHeaderSize, secure_response.payload,
                      secure_response.payload_size, secure_response.tag,
                      secure_reply) &&
       secure_reply[0] == static_cast<uint8_t>(secure_plain[0] ^ 0x5a) &&
       secure_reply[3] == static_cast<uint8_t>(secure_plain[3] ^ 0x5a);

  // Replay of an accepted frame must not be processed twice.
  status = device.receive(secure_frame, secure_size, 4100, response,
                          sizeof(response), &response_size);
  ok = ok && status == WalletLinkStatus::Replay;

  // A forged frame with the next sequence must fail authentication and tear
  // the session down.
  secure_frame[kLinkHeaderSize] ^= 1;
  write_le32(secure_frame + 12, 1);
  status = device.receive(secure_frame, secure_size, 4200, response,
                          sizeof(response), &response_size);
  ok = ok && status == WalletLinkStatus::AuthenticationFailed &&
       !device.session_active();

  // A tampered hello signature must not establish a session.
  frame[96] ^= 1;
  status = device.receive(frame, frame_size, 5000, response, sizeof(response),
                          &response_size);
  ok = ok && status == WalletLinkStatus::AuthenticationFailed;

  // An abandoned pairing prompt must expire on its own and clear the screen.
  {
    WalletLinkDevice fresh;
    PairStore fresh_store = { {}, false, 0, 0 };
    ok = ok && fresh.init(kDeviceSeed, callbacks, &fresh_store);
    static uint8_t fresh_frame[kLinkMaxFrameSize];
    size_t fresh_size = 0;
    ok = ok && wallet_link_frame_encode(WalletLinkType::PairRequest, 0, 0,
                                        pair_request, sizeof(pair_request),
                                        fresh_frame, sizeof(fresh_frame),
                                        &fresh_size);
    status = fresh.receive(fresh_frame, fresh_size, 7000, response,
                           sizeof(response), &response_size);
    ok = ok && status == WalletLinkStatus::PendingPairing &&
         fresh.pairing_pending() && fresh_store.prompts_cleared == 0;
    ok = ok && fresh.tick(7000 + 61000) && !fresh.pairing_pending() &&
         fresh_store.prompts_cleared == 1;
    ok = ok && !fresh.tick(7000 + 62000);
  }

  // Wrong link frame lengths and unknown magic are rejected.
  ok = ok && !wallet_link_frame_decode(frame, frame_size - 1, &info);
  frame[0] = 'X';
  ok = ok && !wallet_link_frame_decode(frame, frame_size, &info);

  return ok;
}

}  // namespace hexwallet
