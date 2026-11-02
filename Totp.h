#ifndef HEXWALLET_TOTP_H
#define HEXWALLET_TOTP_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{

  constexpr size_t kTotpSecretMaxBytes = 64;
  constexpr uint32_t kTotpDefaultPeriod = 30;
  constexpr uint32_t kTotpDefaultDigits = 6;

  enum class TotpAlgorithm : uint8_t
  {
    Sha1 = 0,
    Sha256 = 1,
    Sha512 = 2
  };
  enum class TotpError : uint8_t
  {
    Ok,
    InvalidArgument,
    InvalidBase32,
    SecretTooLong,
    Unsupported,
    BufferTooSmall,
    InvalidUri,
    DuplicateParameter,
    IssuerMismatch,
    AccountExists,
    StorageFull,
    ClockNotSet,
    InvalidAccount,
  };

  constexpr size_t kTotpBase32MaxChars = 256;
  TotpError totp_base32_decode_sized(const char *text, size_t text_size,
                                     uint8_t *out, size_t capacity,
                                     size_t *out_size);
  TotpError totp_base32_decode(const char *text, uint8_t *out, size_t capacity,
                               size_t *out_size);

  bool totp_generate(const uint8_t *secret, size_t secret_size, uint64_t counter,
                     uint32_t digits, TotpAlgorithm algorithm, uint32_t *out_code);
  TotpError totp_generate_unix(const uint8_t *secret, size_t secret_size,
                               uint64_t unix_seconds, uint32_t period,
                               uint32_t digits, TotpAlgorithm algorithm,
                               uint32_t *out_code);

  bool totp_clock_set_unix(uint64_t unix_seconds, uint64_t now_ms);
  bool totp_clock_unix(uint64_t now_ms, uint64_t *out_unix);
  bool totp_clock_valid();
  void totp_clock_clear();

  bool run_totp_self_tests();

}

#endif
