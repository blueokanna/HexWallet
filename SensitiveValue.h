#ifndef HEXWALLET_SENSITIVE_VALUE_H
#define HEXWALLET_SENSITIVE_VALUE_H

#include <type_traits>
#include "WalletSecurity.h"

namespace hexwallet {

// Owns one stack-resident secret. Never copy or move it; every ordinary scope
// exit erases its storage, including early returns. Does not protect RAM from
// a compromised MCU, nor clear copies inside a cryptographic implementation.
template <typename T>
class SensitiveValue final {
 public:
  static_assert(std::is_trivially_copyable<T>::value, "Secret must be plain data");
  SensitiveValue() : value_{} {}
  ~SensitiveValue() { secure_zero(&value_, sizeof(value_)); }
  SensitiveValue(const SensitiveValue &) = delete;
  SensitiveValue &operator=(const SensitiveValue &) = delete;
  SensitiveValue(SensitiveValue &&) = delete;
  SensitiveValue &operator=(SensitiveValue &&) = delete;
  T &get() { return value_; }
  const T &get() const { return value_; }
 private:
  T value_;
};

// An output is published only after its producer explicitly commits success.
// The caller owns the buffer and must supply its actual writable capacity.
class SigningOutputGuard final {
 public:
  SigningOutputGuard(uint8_t *output, size_t *size)
      : output_(output), size_(size), capacity_(size ? *size : 0), committed_(false) {}
  ~SigningOutputGuard() {
    if (!committed_) {
      if (output_ != nullptr) secure_zero(output_, capacity_);
      if (size_ != nullptr) *size_ = 0;
    }
  }
  SigningOutputGuard(const SigningOutputGuard &) = delete;
  SigningOutputGuard &operator=(const SigningOutputGuard &) = delete;
  bool valid() const { return output_ != nullptr && size_ != nullptr && capacity_ != 0; }
  bool commit() {
    committed_ = valid() && *size_ != 0 && *size_ <= capacity_;
    return committed_;
  }
 private:
  uint8_t *output_;
  size_t *size_;
  const size_t capacity_;
  bool committed_;
};

}  // namespace hexwallet
#endif
