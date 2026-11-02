#ifndef HEXWALLET_CTAP_HID_H
#define HEXWALLET_CTAP_HID_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// CTAP 2.2, section 11.2: transport only. This does not implement an
// authenticator, parse CBOR, store credentials or mount a USB interface.
class CtapHid {
 public:
  static constexpr size_t kReportSize = 64;
  static constexpr size_t kMaxPayload = 7609;
  static constexpr uint32_t kBroadcastChannel = 0xffffffffU;
  static constexpr uint32_t kAssemblyTimeoutMs = 3000;
  static constexpr uint32_t kOperationTimeoutMs = 120000;
  static constexpr uint32_t kKeepaliveIntervalMs = 100;

  // Must copy/send the complete report before returning. Returning false
  // latches a transport fault and invalidates the in-flight request. The USB
  // adapter must discard queued reports and detach before reset(). Calls must
  // be serialized by one task; the sink must not re-enter this object.
  using ReportSink = bool (*)(void *context, const uint8_t report[kReportSize]);

  struct Request {
    uint64_t token;
    uint32_t channel;
    const uint8_t *data;
    size_t size;
  };

  // cbor_available is false unless a real, initialized authenticator backend
  // is bound by the owner. Never enable it just to advertise FIDO2 support.
  explicit CtapHid(ReportSink sink, void *context, bool cbor_available = false);
  ~CtapHid();
  CtapHid(const CtapHid &) = delete;
  CtapHid &operator=(const CtapHid &) = delete;

  // Input is exactly one 64-byte HID report, without an OS report-ID prefix.
  // False means malformed report size or a latched transport fault. Valid HID
  // error responses and deliberately ignored packets still return true.
  bool receive(const uint8_t *report, size_t size, uint32_t now_ms);
  bool poll(uint32_t now_ms);

  // Snapshot the pending CBOR command. The borrowed bytes are valid only until
  // the next mutation; copy them before dispatching to a worker. Request tokens
  // never repeat during this object's lifetime, including across reset().
  bool request(Request *out) const;
  bool active(uint64_t token) const;

  // Response includes the CTAP status byte. Only the current request may
  // complete. The backend must also check active(token) before committing a
  // credential or releasing a signature after any asynchronous operation.
  bool complete(uint64_t token, const uint8_t *response, size_t size);
  bool set_waiting_for_presence(uint64_t token, bool waiting, uint32_t now_ms);

  // USB disconnect/data-gate close: invalidate every CID and request and wipe
  // request bytes. Also flush the USB driver's queues; that is adapter-owned.
  void reset();
  bool faulted() const { return faulted_; }

 private:
  enum class State : uint8_t { Idle, Receiving, Processing };
  bool send(uint32_t channel, uint8_t command, const uint8_t *data, size_t size);
  bool error(uint32_t channel, uint8_t code);
  bool finish_receive(uint32_t now_ms);
  bool valid_channel(uint32_t channel) const;
  void clear_transaction();
  void fail();

  ReportSink sink_;
  void *context_;
  bool cbor_available_;
  bool faulted_;
  State state_;
  uint32_t first_channel_;
  uint32_t last_channel_;
  uint32_t channel_;
  uint64_t generation_;
  uint8_t command_;
  uint8_t next_sequence_;
  uint8_t keepalive_status_;
  uint32_t started_ms_;
  uint32_t keepalive_ms_;
  size_t expected_;
  size_t received_;
  uint8_t payload_[kMaxPayload];
};

}  // namespace hexwallet

#endif
