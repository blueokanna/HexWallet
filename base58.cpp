#include <Arduino.h>
#include <mbedtls/platform_util.h>
#include <string.h>

#include "base58.h"
#include "CryptoPrimitives.h"

namespace {

constexpr char kBitcoinAlphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr char kRippleAlphabet[] = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
constexpr size_t kChecksumSize = 4;
constexpr size_t kMaximumEncodedSize = 120;
constexpr size_t kDecodeBufferSize = 128;

struct ScopedZero {
  ScopedZero(void *data_value, size_t size_value) : data(data_value), size(size_value) {}
  ~ScopedZero() { mbedtls_platform_zeroize(data, size); }
  void *data;
  size_t size;
};

void clear_and_free(uint8_t *buffer, size_t size) {
  if (buffer != nullptr) {
    mbedtls_platform_zeroize(buffer, size);
    free(buffer);
  }
}

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
    clear_and_free(work, work_size);
    return false;
  }
  memset(out, alphabet[0], zeroes);
  size_t output_index = zeroes;
  while (first < work_size) {
    out[output_index++] = alphabet[work[first++]];
  }
  out[output_index] = '\0';
  *in_out_size = required;
  clear_and_free(work, work_size);
  return true;
}

int bitcoin_digit(unsigned char value) {
  const char *position = strchr(kBitcoinAlphabet, value);
  return position == nullptr ? -1 : static_cast<int>(position - kBitcoinAlphabet);
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
  if (encoded_size == 0 || encoded_size > kMaximumEncodedSize) {
    return false;
  }
  uint8_t little_endian[kDecodeBufferSize] = {0};
  ScopedZero little_endian_guard(little_endian, sizeof(little_endian));
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
  if (total_size < kChecksumSize) {
    return false;
  }
  const size_t payload_size = total_size - kChecksumSize;
  if (*binsz < payload_size) {
    *binsz = payload_size;
    return false;
  }
  uint8_t decoded[kDecodeBufferSize] = {0};
  ScopedZero decoded_guard(decoded, sizeof(decoded));
  for (size_t i = 0; i < decoded_size; ++i) {
    decoded[zeroes + i] = little_endian[decoded_size - i - 1];
  }
  uint8_t checksum[hexwallet::kSha256Size];
  ScopedZero checksum_guard(checksum, sizeof(checksum));
  const bool valid = hexwallet::crypto_double_sha256(decoded, payload_size, checksum) &&
                     hexwallet::crypto_constant_time_equal(
                         checksum, decoded + payload_size, kChecksumSize);
  if (valid) {
    memcpy(bin, decoded, payload_size);
    *binsz = payload_size;
  }
  return valid;
}
