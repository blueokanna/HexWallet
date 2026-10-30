#ifndef HEXWALLET_SENSITIVE_LINE_BUFFER_H
#define HEXWALLET_SENSITIVE_LINE_BUFFER_H
#include "WalletSecurity.h"
namespace hexwallet {
enum class LineReadResult : uint8_t { Pending, Ready, Rejected };
// Oversized/malformed input is drained through newline; never execute a suffix.
template <size_t Capacity>
class SensitiveLineBuffer final {
 public:
  static_assert(Capacity >= 2, "Line needs a terminator");
  SensitiveLineBuffer() : bytes_{}, used_(0), discarding_(false) {}
  ~SensitiveLineBuffer() { clear(); }
  SensitiveLineBuffer(const SensitiveLineBuffer &) = delete;
  SensitiveLineBuffer &operator=(const SensitiveLineBuffer &) = delete;
  void clear() { secure_zero(bytes_, sizeof(bytes_)); used_ = 0; discarding_ = false; }
  void discard() { clear(); discarding_ = true; }
  char *data() { return bytes_; }
  bool has_content() const { return used_ != 0; }
  LineReadResult feed(uint8_t byte) {
    if (byte == '\n') {
      if (discarding_) { clear(); return LineReadResult::Pending; }
      bytes_[used_] = '\0'; return LineReadResult::Ready;
    }
    if (discarding_ || byte == '\r') return LineReadResult::Pending;
    if (byte == '\b' || byte == 0x7f) {
      if (used_ != 0) bytes_[--used_] = '\0';
      return LineReadResult::Pending;
    }
    if (byte < 0x20 || byte > 0x7e || used_ + 1 >= Capacity) {
      discard(); return LineReadResult::Rejected;
    }
    bytes_[used_++] = static_cast<char>(byte);
    return LineReadResult::Pending;
  }
 private:
  char bytes_[Capacity];
  size_t used_;
  bool discarding_;
};
}
#endif