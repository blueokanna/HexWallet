#ifndef HEXWALLET_USB_APDU_FRAME_H
#define HEXWALLET_USB_APDU_FRAME_H

#include "WalletSecurity.h"

namespace hexwallet
{

  class UsbApduFrame final
  {
  public:
    static constexpr uint8_t kMagic0 = 0xa5;
    static constexpr uint8_t kMagic1 = 0x5a;
    static constexpr size_t kCapacity = 5000;
    static constexpr uint32_t kTimeoutMs = 10000;
    enum class Result : uint8_t
    {
      Pending,
      Ready,
      Rejected
    };

    UsbApduFrame() = default;
    ~UsbApduFrame() { clear(); }
    UsbApduFrame(const UsbApduFrame &) = delete;
    UsbApduFrame &operator=(const UsbApduFrame &) = delete;

    void clear()
    {
      secure_zero(bytes_, sizeof(bytes_));
      used_ = expected_ = 0;
      started_ = 0;
      rejected_ = false;
    }
    bool active() const { return used_ != 0 || rejected_; }
    bool expired(uint32_t now) const
    {
      return active() && static_cast<uint32_t>(now - started_) >= kTimeoutMs;
    }
    const uint8_t *data() const { return bytes_ + 4; }
    size_t size() const { return expected_ >= 4 ? expected_ - 4 : 0; }

    Result feed(uint8_t value, uint32_t now)
    {
      if (rejected_ || expired(now) ||
          (expected_ != 0 && used_ == expected_) || used_ == sizeof(bytes_))
        return reject();
      if (used_ == 0)
        started_ = now;
      bytes_[used_++] = value;
      if ((used_ == 1 && value != kMagic0) || (used_ == 2 && value != kMagic1))
        return reject();
      if (used_ == 4)
      {
        const size_t payload = static_cast<size_t>(bytes_[2]) |
                               (static_cast<size_t>(bytes_[3]) << 8);
        if (payload < 4 || payload > kCapacity)
          return reject();
        expected_ = payload + 4;
      }
      return expected_ != 0 && used_ == expected_ ? Result::Ready : Result::Pending;
    }

  private:
    Result reject()
    {
      clear();
      rejected_ = true;
      return Result::Rejected;
    }
    uint8_t bytes_[kCapacity + 4] = {};
    size_t used_ = 0;
    size_t expected_ = 0;
    uint32_t started_ = 0;
    bool rejected_ = false;
  };
}
#endif
