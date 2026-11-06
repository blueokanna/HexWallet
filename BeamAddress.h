#pragma once
#include <stddef.h>
#include <stdint.h>

namespace hexwallet {
constexpr size_t kBeamRegularAddressSize = 128;
bool beam_regular_address(const uint8_t seed[64], uint64_t index, char (&out)[kBeamRegularAddressSize]);
// Only the simple, native-asset token without a requested amount is accepted.
bool beam_regular_recipient(const char *token, uint8_t endpoint[32]);
} // namespace hexwallet
