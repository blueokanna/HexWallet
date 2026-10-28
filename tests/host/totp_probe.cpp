// Host probe for the firmware TOTP implementation. It only prints RFC 4226/6238
// outputs; the Python test derives the same values with hashlib/hmac.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Totp.h"

namespace {

bool hex_decode(const char *text, uint8_t *out, size_t capacity, size_t *size) {
  *size = 0;
  if (text == nullptr || out == nullptr) return false;
  const size_t length = strlen(text);
  if ((length & 1U) != 0 || length / 2 > capacity) return false;
  for (size_t i = 0; i < length; i += 2) {
    unsigned value = 0;
    if (sscanf(text + i, "%2x", &value) != 1) return false;
    out[(*size)++] = static_cast<uint8_t>(value);
  }
  return true;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc >= 5 && strcmp(argv[1], "clock") == 0) {
    if (!hexwallet::totp_clock_set_unix(strtoull(argv[2], nullptr, 10),
                                       strtoull(argv[3], nullptr, 10))) return 2;
    for (int i = 4; i < argc; ++i) {
      uint64_t now = UINT64_MAX;
      const bool valid = hexwallet::totp_clock_unix(strtoull(argv[i], nullptr, 10), &now);
      printf("%u:%llu\n", valid ? 1U : 0U, static_cast<unsigned long long>(now));
    }
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "b32") == 0) {
    uint8_t secret[hexwallet::kTotpSecretMaxBytes] = {};
    size_t size = 0;
    const hexwallet::TotpError error =
        hexwallet::totp_base32_decode(argv[2], secret, sizeof(secret), &size);
    if (error != hexwallet::TotpError::Ok) {
      printf("error=%u\n", static_cast<unsigned>(error));
      return 1;
    }
    for (size_t i = 0; i < size; ++i) printf("%02x", secret[i]);
    printf("\n");
    return 0;
  }
  if (argc != 7 || strcmp(argv[1], "code") != 0) {
    printf("usage: code <sha1|sha256|sha512> <secret-hex> <unix> <period> <digits>\n");
    return 2;
  }
  hexwallet::TotpAlgorithm algorithm;
  if (strcmp(argv[2], "sha1") == 0) algorithm = hexwallet::TotpAlgorithm::Sha1;
  else if (strcmp(argv[2], "sha256") == 0) algorithm = hexwallet::TotpAlgorithm::Sha256;
  else if (strcmp(argv[2], "sha512") == 0) algorithm = hexwallet::TotpAlgorithm::Sha512;
  else return 2;
  uint8_t secret[hexwallet::kTotpSecretMaxBytes] = {};
  size_t secret_size = 0;
  if (!hex_decode(argv[3], secret, sizeof(secret), &secret_size)) return 2;
  const unsigned long long unix_seconds = strtoull(argv[4], nullptr, 10);
  const unsigned long period = strtoul(argv[5], nullptr, 10);
  const unsigned long digits = strtoul(argv[6], nullptr, 10);
  uint32_t code = 0;
  const hexwallet::TotpError error = hexwallet::totp_generate_unix(
      secret, secret_size, unix_seconds, static_cast<uint32_t>(period),
      static_cast<uint32_t>(digits), algorithm, &code);
  if (error != hexwallet::TotpError::Ok) {
    printf("error=%u\n", static_cast<unsigned>(error));
    return 1;
  }
  printf("code=%0*u\n", static_cast<int>(digits), code);
  return 0;
}
