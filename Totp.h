#ifndef HEXWALLET_TOTP_H
#define HEXWALLET_TOTP_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// RFC 4226 / RFC 6238, implemented locally. No network, no time server and no
// dynamic allocation: the caller owns the secret and the display lifetime.
constexpr size_t kTotpSecretMaxBytes = 64;
constexpr uint32_t kTotpDefaultPeriod = 30;
constexpr uint32_t kTotpDefaultDigits = 6;

enum class TotpAlgorithm : uint8_t { Sha1 = 0, Sha256 = 1, Sha512 = 2 };
enum class TotpError : uint8_t {
  Ok,
  InvalidArgument,
  InvalidBase32,
  SecretTooLong,
  Unsupported,
  BufferTooSmall,
};

// Strict RFC 4648 base32: A-Z/2-7, optional spaces and a trailing '=' pad are
// accepted; every other character is rejected. Output is not NUL terminated.
TotpError totp_base32_decode(const char *text, uint8_t *out, size_t capacity,
                             size_t *out_size);

// HOTP/TOTP generation. digits must be 6..8; the RFC 6238 dynamic truncation
// and 31-bit mask are applied before the decimal modulo.
bool totp_generate(const uint8_t *secret, size_t secret_size, uint64_t counter,
                   uint32_t digits, TotpAlgorithm algorithm, uint32_t *out_code);
TotpError totp_generate_unix(const uint8_t *secret, size_t secret_size,
                             uint64_t unix_seconds, uint32_t period,
                             uint32_t digits, TotpAlgorithm algorithm,
                             uint32_t *out_code);

// Monotonic clock anchored by a trusted wall-clock value. The caller supplies
// a 64-bit monotonic millisecond count (ESP-IDF esp_timer_get_time()/1000).
// Do not pass Arduino millis(): after 49.7 days its wrap is indistinguishable
// from a shorter elapsed interval. Clock rollback and overflow invalidate it.
bool totp_clock_set_unix(uint64_t unix_seconds, uint64_t now_ms);
bool totp_clock_unix(uint64_t now_ms, uint64_t *out_unix);
bool totp_clock_valid();
void totp_clock_clear();

bool run_totp_self_tests();

}  // namespace hexwallet

#endif
