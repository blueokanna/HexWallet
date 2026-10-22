#include "WalletNfcApdu.h"

#include <string.h>

#include "WalletSecurity.h"

namespace hexwallet {
namespace {

constexpr uint8_t kClaSelect = 0x00;
constexpr uint8_t kClaProprietary = 0x80;
constexpr uint8_t kInsSelect = 0xa4;
constexpr uint8_t kInsWrite = 0x10;
constexpr uint8_t kInsRead = 0x11;
constexpr uint8_t kInsAbort = 0x12;
constexpr uint8_t kInsStatus = 0x13;

constexpr uint16_t kSwOk = 0x9000;
constexpr uint16_t kSwMoreData = 0x6100;
constexpr uint16_t kSwWrongLength = 0x6700;
constexpr uint16_t kSwSecurity = 0x6982;
constexpr uint16_t kSwConditions = 0x6985;
constexpr uint16_t kSwWrongData = 0x6a80;
constexpr uint16_t kSwInsNotSupported = 0x6d00;
constexpr uint16_t kSwClaNotSupported = 0x6e00;

void write_u16(uint8_t *out, uint16_t value) {
  out[0] = static_cast<uint8_t>(value >> 8);
  out[1] = static_cast<uint8_t>(value);
}

}  // namespace

WalletNfcApdu::WalletNfcApdu()
    : link_(nullptr), selected_(false), request_{}, request_size_(0),
      reply_{}, reply_size_(0), reply_offset_(0) {}

bool WalletNfcApdu::init(WalletLinkDevice *link) {
  link_ = link;
  selected_ = false;
  reset_transfer();
  return link_ != nullptr;
}

void WalletNfcApdu::reset_transfer() {
  secure_zero(request_, sizeof(request_));
  secure_zero(reply_, sizeof(reply_));
  request_size_ = 0;
  reply_size_ = 0;
  reply_offset_ = 0;
}

void WalletNfcApdu::field_lost() {
  reset_transfer();
  selected_ = false;
  if (link_ != nullptr) link_->reset_session();
}

size_t WalletNfcApdu::status_only(uint16_t status, uint8_t *response,
                                  size_t response_capacity) const {
  if (response == nullptr || response_capacity < 2) return 0;
  write_u16(response, status);
  return 2;
}

size_t WalletNfcApdu::process(const uint8_t *apdu, size_t apdu_size,
                              uint32_t now_ms, uint8_t *response,
                              size_t response_capacity) {
  if (response == nullptr || response_capacity < 2 || link_ == nullptr) return 0;
  if (apdu == nullptr || apdu_size < 4) {
    return status_only(kSwWrongLength, response, response_capacity);
  }
  const uint8_t cla = apdu[0];
  const uint8_t ins = apdu[1];
  const uint8_t p1 = apdu[2];

  if (cla == kClaSelect && ins == kInsSelect) {
    if (p1 != 0x04 || apdu[2] != 0x04 || apdu[3] != 0x00 ||
        apdu_size != 5 + kAidSize || apdu[4] != kAidSize ||
        memcmp(apdu + 5, kAid, kAidSize) != 0) {
      return status_only(kSwWrongData, response, response_capacity);
    }
    reset_transfer();
    selected_ = true;
    response[0] = 0xf0;
    response[1] = kLinkProtocolVersion;
    write_u16(response + 2, kSwOk);
    return 4;
  }

  if (cla != kClaProprietary) {
    return status_only(kSwClaNotSupported, response, response_capacity);
  }
  if (!selected_) {
    return status_only(kSwConditions, response, response_capacity);
  }
  if (apdu_size < 5) {
    return status_only(kSwWrongLength, response, response_capacity);
  }
  const uint8_t lc = apdu[4];
  if (apdu_size != 5 + lc) {
    return status_only(kSwWrongLength, response, response_capacity);
  }

  switch (ins) {
    case kInsWrite: {
      if (reply_size_ != 0 && reply_offset_ < reply_size_) {
        return status_only(kSwConditions, response, response_capacity);
      }
      if (request_size_ + lc > sizeof(request_)) {
        reset_transfer();
        return status_only(kSwWrongLength, response, response_capacity);
      }
      if (lc != 0) memcpy(request_ + request_size_, apdu + 5, lc);
      request_size_ += lc;
      if (p1 != 0x01) {
        return status_only(kSwOk, response, response_capacity);
      }
      reply_size_ = 0;
      reply_offset_ = 0;
      size_t produced = 0;
      const WalletLinkStatus status = link_->receive(
          request_, request_size_, now_ms, reply_, sizeof(reply_), &produced);
      secure_zero(request_, sizeof(request_));
      request_size_ = 0;
      if (status == WalletLinkStatus::Ok && produced != 0) {
        reply_size_ = produced;
        reply_offset_ = 0;
        return status_only(kSwOk, response, response_capacity);
      }
      if (status == WalletLinkStatus::PendingPairing) {
        return status_only(kSwConditions, response, response_capacity);
      }
      if (status == WalletLinkStatus::AuthenticationFailed ||
          status == WalletLinkStatus::Rejected) {
        return status_only(kSwSecurity, response, response_capacity);
      }
      if (status == WalletLinkStatus::Replay ||
          status == WalletLinkStatus::Expired ||
          status == WalletLinkStatus::NoSession) {
        return status_only(kSwConditions, response, response_capacity);
      }
      return status_only(kSwWrongData, response, response_capacity);    }
    case kInsRead: {
      if (p1 != 0x00 || lc != 0 || reply_offset_ >= reply_size_) {
        return status_only(kSwConditions, response, response_capacity);
      }
      const size_t remaining = reply_size_ - reply_offset_;
      const size_t take = remaining < kMaxChunk ? remaining : kMaxChunk;
      if (response_capacity < take + 2) return 0;
      memcpy(response, reply_ + reply_offset_, take);
      reply_offset_ += take;
      write_u16(response + take,
                reply_offset_ < reply_size_ ? kSwMoreData : kSwOk);
      return take + 2;
    }
    case kInsAbort:
      if (lc != 0) return status_only(kSwWrongLength, response, response_capacity);
      reset_transfer();
      return status_only(kSwOk, response, response_capacity);
    case kInsStatus: {
      if (lc != 0 || response_capacity < 10) {
        return status_only(kSwWrongLength, response, response_capacity);
      }
      response[0] = static_cast<uint8_t>(request_size_);
      response[1] = static_cast<uint8_t>(request_size_ >> 8);
      response[2] = static_cast<uint8_t>(reply_size_);
      response[3] = static_cast<uint8_t>(reply_size_ >> 8);
      response[4] = static_cast<uint8_t>(reply_offset_);
      response[5] = static_cast<uint8_t>(reply_offset_ >> 8);
      response[6] = link_->session_active() ? 1 : 0;
      response[7] = link_->pairing_pending() ? 1 : 0;
      write_u16(response + 8, kSwOk);
      return 10;
    }
    default:
      return status_only(kSwInsNotSupported, response, response_capacity);
  }
}

bool run_wallet_nfc_apdu_self_test() {
  static const uint8_t kIdentitySeed[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
  };
  WalletLinkCallbacks callbacks = {};
  WalletLinkDevice link;
  if (!link.init(kIdentitySeed, callbacks, nullptr)) return false;

  WalletNfcApdu app;
  if (!app.init(&link)) return false;

  uint8_t response[512];
  const uint8_t select[] = { 0x00, 0xa4, 0x04, 0x00, 0x06,
                             0xf0, 0x48, 0x57, 0x4c, 0x4b, 0x31 };
  size_t size = app.process(select, sizeof(select), 0, response,
                            sizeof(response));
  bool ok = size == 4 && response[0] == 0xf0 &&
            response[1] == kLinkProtocolVersion && response[2] == 0x90 &&
            response[3] == 0x00;

  // An unauthenticated HelloRequest is assembled from two APDU chunks and
  // must be rejected by the link layer without touching the wallet.
  uint8_t bad_frame[kLinkHeaderSize + 160];
  memset(bad_frame, 0, sizeof(bad_frame));
  memcpy(bad_frame, "HWLK", 4);
  bad_frame[4] = kLinkProtocolVersion;
  bad_frame[5] = static_cast<uint8_t>(WalletLinkType::HelloRequest);
  bad_frame[16] = 160;
  const size_t first = 10;
  uint8_t write1[5 + first] = { 0x80, 0x10, 0x00, 0x00,
                                static_cast<uint8_t>(first) };
  memcpy(write1 + 5, bad_frame, first);
  size = app.process(write1, sizeof(write1), 10, response, sizeof(response));
  ok = ok && size == 2 && response[0] == 0x90 && response[1] == 0x00;
  const size_t second = sizeof(bad_frame) - first;
  uint8_t write2[5 + 200] = { 0x80, 0x10, 0x01, 0x00,
                              static_cast<uint8_t>(second) };
  memcpy(write2 + 5, bad_frame + first, second);
  size = app.process(write2, 5 + second, 20, response, sizeof(response));
  ok = ok && size == 2 && response[0] == 0x69 && response[1] == 0x82;

  // No reply is available.
  const uint8_t read[] = { 0x80, 0x11, 0x00, 0x00, 0x00 };
  size = app.process(read, sizeof(read), 30, response, sizeof(response));
  ok = ok && size == 2 && response[0] == 0x69 && response[1] == 0x85;

  const uint8_t status[] = { 0x80, 0x13, 0x00, 0x00, 0x00 };
  size = app.process(status, sizeof(status), 40, response, sizeof(response));
  ok = ok && size == 10 && response[8] == 0x90 && response[9] == 0x00;

  const uint8_t abort_cmd[] = { 0x80, 0x12, 0x00, 0x00, 0x00 };
  size = app.process(abort_cmd, sizeof(abort_cmd), 50, response,
                     sizeof(response));
  ok = ok && size == 2 && response[0] == 0x90 && response[1] == 0x00;

  // Unknown instructions and an unselected application fail closed.
  const uint8_t unknown[] = { 0x80, 0x7f, 0x00, 0x00, 0x00 };
  size = app.process(unknown, sizeof(unknown), 60, response, sizeof(response));
  ok = ok && size == 2 && response[0] == 0x6d && response[1] == 0x00;
  app.field_lost();
  size = app.process(unknown, sizeof(unknown), 70, response, sizeof(response));
  ok = ok && size == 2 && response[0] == 0x69 && response[1] == 0x85;

  return ok;
}

}  // namespace hexwallet
