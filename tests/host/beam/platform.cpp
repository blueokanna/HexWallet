// Host utilities referenced by stock Beam ECC. Randomness comes directly
// from the upstream BCrypt implementation. No HexWallet objects are linked.
#include "utility/common.h"
bool memis0(const void *ptr, size_t size) {
  const auto *bytes = static_cast<const uint8_t *>(ptr);
  for (size_t i = 0; i < size; ++i) if (bytes[i]) return false;
  return true;
}
void memxor(uint8_t *dst, const uint8_t *src, size_t size) {
  for (size_t i = 0; i < size; ++i) dst[i] ^= src[i];
}
void beam::Exc::Fail(const char *message) { throw std::runtime_error(message); }
void std::ThrowSystemError(int) { throw std::runtime_error("System RNG failure"); }
