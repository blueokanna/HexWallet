#include <Arduino.h>
#include <mbedtls/sha256.h>
#include <string.h>

#include "base58.h"

namespace {

constexpr char kBitcoinAlphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr char kRippleAlphabet[] = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

bool encode_base58(const char *alphabet, char *out, size_t *in_out_size,
                   const void *input, size_t input_size) {
  if (alphabet == nullptr || out == nullptr || in_out_size == nullptr ||
      (input == nullptr && input_size != 0)) {
    return false;
  }
  const uint8_t *bytes = static_cast<const uint8_t *>(input);
  size_t zeroes = 0;
  while (zeroes < input_size && bytes[zeroes] == 0) {
    ++zeroes;
  }
  const size_t work_size = (input_size - zeroes) * 138 / 100 + 1;
  uint8_t *work = static_cast<uint8_t *>(calloc(work_size, sizeof(uint8_t)));
  if (work == nullptr) {
    return false;
  }
  size_t high = work_size - 1;
  for (size_t i = zeroes; i < input_size; ++i) {
    int carry = bytes[i];
    size_t j = work_size - 1;
    for (; j > high || carry != 0; --j) {
      carry += 256 * work[j];
      work[j] = carry % 58;
      carry /= 58;
      if (j == 0) {
        break;
      }
    }
    high = j;
  }
  size_t first = 0;
  while (first < work_size && work[first] == 0) {
    ++first;
  }
  const size_t required = zeroes + work_size - first + 1;
  if (*in_out_size < required) {
    *in_out_size = required;
    free(work);
    return false;
  }
  memset(out, alphabet[0], zeroes);
  size_t output_index = zeroes;
  while (first < work_size) {
    out[output_index++] = alphabet[work[first++]];
  }
  out[output_index] = '\0';
  *in_out_size = required;
  free(work);
  return true;
}

int bitcoin_digit(unsigned char value) {
  if (value >= '1' && value <= '9') return value - '1';
  if (value >= 'A' && value <= 'H') return value - 'A' + 9;
  if (value >= 'J' && value <= 'N') return value - 'J' + 17;
  if (value == 'P') return 22;
  if (value >= 'Q' && value <= 'Z') return value - 'Q' + 23;
  if (value >= 'a' && value <= 'k') return value - 'a' + 33;
  if (value >= 'm' && value <= 'z') return value - 'm' + 44;
  return -1;
}

}  // namespace

bool b58enc(char *b58, size_t *b58sz, const void *bin, size_t binsz) {
  return encode_base58(kBitcoinAlphabet, b58, b58sz, bin, binsz);
}

bool ripple_b58enc(char *b58, size_t *b58sz, const void *bin, size_t binsz) {
  return encode_base58(kRippleAlphabet, b58, b58sz, bin, binsz);
}

bool b58check_dec(uint8_t *bin, size_t *binsz, const char *b58) {
  if (bin == nullptr || binsz == nullptr || b58 == nullptr) {
    return false;
  }
  const size_t encoded_size = strlen(b58);
  if (encoded_size == 0 || encoded_size > 120) {
    return false;
  }
  uint8_t little_endian[128] = {0};
  size_t decoded_size = 0;
  size_t zeroes = 0;
  while (zeroes < encoded_size && b58[zeroes] == '1') {
    ++zeroes;
  }
  for (size_t i = 0; i < encoded_size; ++i) {
    const int digit = bitcoin_digit(static_cast<unsigned char>(b58[i]));
    if (digit < 0) {
      return false;
    }
    int carry = digit;
    for (size_t j = 0; j < decoded_size; ++j) {
      carry += 58 * little_endian[j];
      little_endian[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry != 0) {
      if (decoded_size == sizeof(little_endian)) {
        return false;
      }
      little_endian[decoded_size++] = carry & 0xff;
      carry >>= 8;
    }
  }
  const size_t total_size = zeroes + decoded_size;
  if (total_size < 4) {
    return false;
  }
  const size_t payload_size = total_size - 4;
  if (*binsz < payload_size) {
    *binsz = payload_size;
    return false;
  }
  uint8_t decoded[128] = {0};
  for (size_t i = 0; i < decoded_size; ++i) {
    decoded[zeroes + i] = little_endian[decoded_size - i - 1];
  }
  uint8_t checksum[32];
  mbedtls_sha256(decoded, payload_size, checksum, 0);
  mbedtls_sha256(checksum, sizeof(checksum), checksum, 0);
  const bool valid = memcmp(checksum, decoded + payload_size, 4) == 0;
  if (valid) {
    memcpy(bin, decoded, payload_size);
    *binsz = payload_size;
  }
  memset(little_endian, 0, sizeof(little_endian));
  memset(decoded, 0, sizeof(decoded));
  memset(checksum, 0, sizeof(checksum));
  return valid;
}
