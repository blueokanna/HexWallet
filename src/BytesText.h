#ifndef HEXWALLET_BYTES_TEXT_H
#define HEXWALLET_BYTES_TEXT_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"

namespace hexwallet {

// Shared byte/hex helpers. Chain adapters used to carry their own copies of
// these three; keeping one implementation avoids the case where one module
// tightens a check and the others keep the old behaviour.
//
// `bytes_equal` is constant-time and must be used for anything that compares
// key material, tags or MACs. Do not replace it with memcmp.
inline bool bytes_equal(const uint8_t *left, const uint8_t *right, size_t size) {
  if (left == nullptr || right == nullptr) return false;
  return crypto_constant_time_equal(left, right, size);
}

// Strict hex decoding: `text` must be exactly `size * 2` characters. Anything
// else (shorter, longer, odd length, non-hex) fails, so a caller can never sign
// a value that was silently truncated.
inline bool hex_decode_exact(const char *text, uint8_t *out, size_t size) {
  if (text == nullptr || out == nullptr) return false;
  size_t length = 0;
  while (text[length] != '\0') {
    if (++length > size * 2) return false;
  }
  if (length != size * 2) return false;
  const auto digit = [](char value) -> int {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
  };
  for (size_t index = 0; index < size; ++index) {
    const int high = digit(text[index * 2]);
    const int low = digit(text[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

// Decode `text` into a fixed-size scratch buffer and compare it in constant
// time with `data`. Used by fixture self-tests, never by a signing path.
inline bool hex_equal_exact(const uint8_t *data, size_t size, const char *text,
                            uint8_t *scratch, size_t scratch_size) {
  if (scratch == nullptr || size > scratch_size) return false;
  if (!hex_decode_exact(text, scratch, size)) return false;
  return bytes_equal(data, scratch, size);
}

}  // namespace hexwallet

#endif
