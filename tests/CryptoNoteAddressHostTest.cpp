#include <stdint.h>
#include <string.h>

#include "../keccak256.h"

namespace {

constexpr char kAlphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr uint8_t kEncodedSizes[] = {0, 2, 3, 5, 6, 7, 9, 10, 11};

bool encode_block(const uint8_t *input, size_t size, char *out) {
  uint64_t value = 0;
  for (size_t index = 0; index < size; ++index) value = (value << 8) | input[index];
  memset(out, '1', kEncodedSizes[size]);
  for (size_t position = kEncodedSizes[size]; value != 0 && position != 0;) {
    const uint64_t quotient = value / 58;
    out[--position] = kAlphabet[value - quotient * 58];
    value = quotient;
  }
  return value == 0;
}

bool encode(const uint8_t *input, size_t size, char *out, size_t out_size) {
  const size_t full_blocks = size / 8;
  const size_t remainder = size % 8;
  const size_t encoded_size = full_blocks * 11 + kEncodedSizes[remainder];
  if (encoded_size + 1 > out_size) return false;
  for (size_t block = 0; block < full_blocks; ++block) {
    if (!encode_block(input + block * 8, 8, out + block * 11)) return false;
  }
  if (remainder != 0 && !encode_block(input + full_blocks * 8, remainder,
                                       out + full_blocks * 11)) return false;
  out[encoded_size] = '\0';
  return true;
}

}  // namespace

int main() {
  static const uint8_t kEd25519BasePoint[32] = {
      0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
      0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
  };
  uint8_t payload[69];
  payload[0] = 18;
  memcpy(payload + 1, kEd25519BasePoint, sizeof(kEd25519BasePoint));
  memcpy(payload + 33, kEd25519BasePoint, sizeof(kEd25519BasePoint));
  SHA3_CTX context;
  uint8_t digest[32];
  keccak_init(&context);
  if (!keccak_update(&context, payload, 65) || !keccak_final(&context, digest)) return 1;
  memcpy(payload + 65, digest, 4);
  char address[96];
  if (!encode(payload, sizeof(payload), address, sizeof(address))) return 1;
  static const char kExpectedAddress[] =
      "44yQXfkWZNmJ8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmJ7suhUXwdrD"
      "J8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmCYrSgjJ";
  if (strcmp(address, kExpectedAddress) != 0) return 1;
  payload[0] = 28;
  keccak_init(&context);
  if (!keccak_update(&context, payload, 65) || !keccak_final(&context, digest)) return 1;
  memcpy(payload + 65, digest, 4);
  if (!encode(payload, sizeof(payload), address, sizeof(address))) return 1;
  static const char kExpectedMasariAddress[] =
      "5jz8fjwSe3wJ8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmJ7suhUXwdrD"
      "J8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmCWb1XQW";
  return strcmp(address, kExpectedMasariAddress) == 0 ? 0 : 1;
}
