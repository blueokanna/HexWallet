#include "CtapHid.h"

#include <string.h>

namespace hexwallet
{
  namespace
  {
    constexpr uint8_t kPing = 0x01;
    constexpr uint8_t kInit = 0x06;
    constexpr uint8_t kCbor = 0x10;
    constexpr uint8_t kCancel = 0x11;
    constexpr uint8_t kKeepalive = 0x3b;
    constexpr uint8_t kError = 0x3f;
    constexpr uint8_t kInvalidCommand = 0x01;
    constexpr uint8_t kInvalidLength = 0x03;
    constexpr uint8_t kInvalidSequence = 0x04;
    constexpr uint8_t kMessageTimeout = 0x05;
    constexpr uint8_t kChannelBusy = 0x06;
    constexpr uint8_t kInvalidChannel = 0x0b;
    constexpr uint8_t kOther = 0x7f;
    constexpr uint8_t kCtapKeepaliveCancel = 0x2d;
    constexpr uint8_t kCtapActionTimeout = 0x3a;
    constexpr uint8_t kCtapUserActionTimeout = 0x2f;

    void wipe(void *data, size_t size)
    {
      volatile uint8_t *p = static_cast<volatile uint8_t *>(data);
      while (size-- != 0)
        *p++ = 0;
    }

    uint32_t read_channel(const uint8_t *p)
    {
      return (static_cast<uint32_t>(p[0]) << 24) |
             (static_cast<uint32_t>(p[1]) << 16) |
             (static_cast<uint32_t>(p[2]) << 8) | p[3];
    }

    void write_channel(uint8_t *p, uint32_t channel)
    {
      p[0] = static_cast<uint8_t>(channel >> 24);
      p[1] = static_cast<uint8_t>(channel >> 16);
      p[2] = static_cast<uint8_t>(channel >> 8);
      p[3] = static_cast<uint8_t>(channel);
    }
  }

  CtapHid::CtapHid(ReportSink sink, void *context, bool cbor_available)
      : sink_(sink), context_(context), cbor_available_(cbor_available),
        faulted_(sink == nullptr), state_(State::Idle), first_channel_(1),
        last_channel_(0), channel_(0), generation_(0), command_(0),
        next_sequence_(0), keepalive_status_(1), started_ms_(0),
        keepalive_ms_(0), expected_(0), received_(0), payload_{} {}

  CtapHid::~CtapHid() { clear_transaction(); }

  void CtapHid::clear_transaction()
  {
    wipe(payload_, sizeof(payload_));
    state_ = State::Idle;
    channel_ = 0;
    command_ = 0;
    next_sequence_ = 0;
    keepalive_status_ = 1;
    started_ms_ = 0;
    keepalive_ms_ = 0;
    expected_ = received_ = 0;
  }

  void CtapHid::fail()
  {
    clear_transaction();
    faulted_ = true;
  }

  void CtapHid::reset()
  {
    clear_transaction();
    first_channel_ = last_channel_ + 1;
    faulted_ = sink_ == nullptr || generation_ == UINT64_MAX;
  }

  bool CtapHid::valid_channel(uint32_t channel) const
  {
    return channel != 0 && channel != kBroadcastChannel &&
           channel >= first_channel_ && channel <= last_channel_;
  }

  bool CtapHid::send(uint32_t channel, uint8_t command, const uint8_t *data,
                     size_t size)
  {
    if (faulted_ || size > kMaxPayload || (size != 0 && data == nullptr))
    {
      fail();
      return false;
    }
    uint8_t report[kReportSize] = {};
    write_channel(report, channel);
    report[4] = static_cast<uint8_t>(command | 0x80);
    report[5] = static_cast<uint8_t>(size >> 8);
    report[6] = static_cast<uint8_t>(size);
    size_t used = size < 57 ? size : 57;
    if (used != 0)
      memcpy(report + 7, data, used);
    bool ok = sink_(context_, report);
    uint8_t sequence = 0;
    while (ok && used < size)
    {
      wipe(report, sizeof(report));
      write_channel(report, channel);
      report[4] = sequence++;
      const size_t chunk = size - used < 59 ? size - used : 59;
      memcpy(report + 5, data + used, chunk);
      used += chunk;
      ok = sink_(context_, report);
    }
    wipe(report, sizeof(report));
    if (!ok)
      fail();
    return ok;
  }

  bool CtapHid::error(uint32_t channel, uint8_t code)
  {
    return send(channel, kError, &code, 1);
  }

  bool CtapHid::finish_receive(uint32_t now_ms)
  {
    if (command_ == kPing)
    {
      const bool ok = send(channel_, kPing, payload_, received_);
      clear_transaction();
      return ok;
    }
    if (generation_ == UINT64_MAX)
    {
      const bool ok = error(channel_, kOther);
      fail();
      (void)ok;
      return false;
    }
    ++generation_;
    state_ = State::Processing;
    started_ms_ = keepalive_ms_ = now_ms;
    return true;
  }

  bool CtapHid::receive(const uint8_t *report, size_t size, uint32_t now_ms)
  {
    if (report == nullptr || size != kReportSize || faulted_)
      return false;
    if (!poll(now_ms))
      return false;
    const uint32_t cid = read_channel(report);
    const bool initial = (report[4] & 0x80) != 0;
    const uint8_t cmd = report[4] & 0x7f;

    if (initial && cmd == kCancel)
    {
      if (report[5] == 0 && report[6] == 0 &&
          state_ == State::Processing && cid == channel_)
      {
        const uint8_t cancelled = kCtapKeepaliveCancel;
        const bool ok = send(cid, kCbor, &cancelled, 1);
        clear_transaction();
        return ok;
      }
      return true;
    }

    if (!initial)
    {
      if (state_ != State::Receiving || cid != channel_)
        return true;
      if (report[4] != next_sequence_)
      {
        clear_transaction();
        return error(cid, kInvalidSequence);
      }
      const size_t remaining = expected_ - received_;
      const size_t chunk = remaining < 59 ? remaining : 59;
      memcpy(payload_ + received_, report + 5, chunk);
      received_ += chunk;
      ++next_sequence_;
      if (received_ == expected_)
        return finish_receive(now_ms);
      return true;
    }

    if (!valid_channel(cid) &&
        !(cid == kBroadcastChannel && cmd == kInit))
    {
      return error(cid, kInvalidChannel);
    }
    if (state_ != State::Idle && cid != channel_)
    {
      return error(cid, kChannelBusy);
    }
    const size_t length = (static_cast<size_t>(report[5]) << 8) | report[6];
    if (cmd == kInit)
    {
      if (length != 8)
        return error(cid, kInvalidLength);
      clear_transaction();
      uint32_t assigned = cid;
      if (cid == kBroadcastChannel)
      {
        if (last_channel_ == kBroadcastChannel - 1)
          return error(cid, kOther);
        assigned = ++last_channel_;
      }
      uint8_t response[17] = {};
      memcpy(response, report + 7, 8);
      write_channel(response + 8, assigned);
      response[12] = 2;
      response[16] = static_cast<uint8_t>(0x08 | (cbor_available_ ? 0x04 : 0));
      return send(cid, kInit, response, sizeof(response));
    }
    if (state_ == State::Processing)
      return error(cid, kChannelBusy);
    if (state_ == State::Receiving)
    {
      clear_transaction();
      return error(cid, kInvalidSequence);
    }
    if (cmd != kPing && !(cmd == kCbor && cbor_available_))
    {
      return error(cid, kInvalidCommand);
    }
    if (length > kMaxPayload || (cmd == kCbor && length == 0))
    {
      return error(cid, kInvalidLength);
    }
    channel_ = cid;
    command_ = cmd;
    expected_ = length;
    received_ = length < 57 ? length : 57;
    if (received_ != 0)
      memcpy(payload_, report + 7, received_);
    started_ms_ = now_ms;
    next_sequence_ = 0;
    state_ = State::Receiving;
    if (received_ == expected_)
      return finish_receive(now_ms);
    return true;
  }

  bool CtapHid::poll(uint32_t now_ms)
  {
    if (faulted_)
      return false;
    if (state_ == State::Receiving &&
        static_cast<uint32_t>(now_ms - started_ms_) >= kAssemblyTimeoutMs)
    {
      const uint32_t cid = channel_;
      clear_transaction();
      return error(cid, kMessageTimeout);
    }
    if (state_ != State::Processing)
      return true;
    if (static_cast<uint32_t>(now_ms - started_ms_) >= kOperationTimeoutMs)
    {
      const uint8_t timeout = keepalive_status_ == 2 ? kCtapUserActionTimeout : kCtapActionTimeout;
      const bool ok = send(channel_, kCbor, &timeout, 1);
      clear_transaction();
      return ok;
    }
    if (static_cast<uint32_t>(now_ms - keepalive_ms_) >= kKeepaliveIntervalMs)
    {
      keepalive_ms_ = now_ms;
      return send(channel_, kKeepalive, &keepalive_status_, 1);
    }
    return true;
  }

  bool CtapHid::request(Request *out) const
  {
    if (out == nullptr)
      return false;
    *out = {};
    if (faulted_ || state_ != State::Processing)
      return false;
    out->token = generation_;
    out->channel = channel_;
    out->data = payload_;
    out->size = received_;
    return true;
  }

  bool CtapHid::active(uint64_t token) const
  {
    return !faulted_ && state_ == State::Processing && token != 0 &&
           token == generation_;
  }

  bool CtapHid::complete(uint64_t token, const uint8_t *response, size_t size)
  {
    if (!active(token))
      return false;
    if (response == nullptr || size == 0 || size > kMaxPayload)
    {
      const uint32_t cid = channel_;
      clear_transaction();
      error(cid, kOther);
      return false;
    }
    const bool ok = send(channel_, kCbor, response, size);
    clear_transaction();
    return ok;
  }

  bool CtapHid::set_waiting_for_presence(uint64_t token, bool waiting,
                                         uint32_t now_ms)
  {
    if (!poll(now_ms) || !active(token))
      return false;
    const uint8_t status = waiting ? 2 : 1;
    if (keepalive_status_ == status)
      return true;
    keepalive_status_ = status;
    keepalive_ms_ = now_ms;
    return send(channel_, kKeepalive, &keepalive_status_, 1);
  }
}
