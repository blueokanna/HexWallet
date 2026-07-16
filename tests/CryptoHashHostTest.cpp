#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../keccak256.h"
#include "../local_ripemd160.h"

namespace {

bool equal_hex(const uint8_t *actual, size_t size, const char *expected) {
  static constexpr char kHex[] = "0123456789abcdef";
  for (size_t index = 0; index < size; ++index) {
    if (kHex[actual[index] >> 4] != expected[index * 2] ||
        kHex[actual[index] & 0x0f] != expected[index * 2 + 1]) return false;
  }
  return expected[size * 2] == '\0';
}

}  // namespace

int main() {
  static const uint8_t kAbc[] = {'a', 'b', 'c'};
  uint8_t digest[32];
  SHA3_CTX context;
  keccak_init(&context);
  bool passed = keccak_update(&context, nullptr, 0) && keccak_final(&context, digest) &&
      equal_hex(digest, 32, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  keccak_init(&context);
  passed = passed && keccak_update(&context, kAbc, 1) &&
      keccak_update(&context, kAbc + 1, 2) && keccak_final(&context, digest) &&
      equal_hex(digest, 32, "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  uint8_t long_input[300];
  uint8_t one_shot[32];
  for (size_t index = 0; index < sizeof(long_input); ++index) long_input[index] = static_cast<uint8_t>(index);
  keccak_init(&context);
  passed = passed && keccak_update(&context, long_input, sizeof(long_input)) &&
      keccak_final(&context, one_shot);
  keccak_init(&context);
  passed = passed && keccak_update(&context, long_input, 17) &&
      keccak_update(&context, long_input + 17, 119) &&
      keccak_update(&context, long_input + 136, sizeof(long_input) - 136) &&
      keccak_final(&context, digest) && memcmp(one_shot, digest, sizeof(digest)) == 0;
  local_ripemd160(nullptr, 0, digest);
  passed = passed && equal_hex(digest, 20, "9c1185a5c5e9fc54612808977ee8f548b2258d31");
  static const uint8_t kQuickBrown[] = "The quick brown fox jumps over the lazy dog";
  local_ripemd160(kQuickBrown, sizeof(kQuickBrown) - 1, digest);
  passed = passed && equal_hex(digest, 20, "37f332f68db77bd9d7edd4969571ad671cf9dd3b");
  return passed ? 0 : 1;
}
