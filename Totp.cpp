#include "Totp.h"

#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

constexpr uint32_t kSha1Block = 64;
constexpr uint32_t kSha1Digest = 20;

uint32_t rotl32(uint32_t value, uint8_t count) {
  return (value << count) | (value >> (32U - count));
}

void sha1_compress(uint32_t state[5], const uint8_t block[64]) {
  uint32_t w[80];
  for (uint8_t i = 0; i < 16; ++i) {
    w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
           (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
           static_cast<uint32_t>(block[i * 4 + 3]);
  }
  for (uint8_t i = 16; i < 80; ++i) {
    w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  }
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
  for (uint8_t i = 0; i < 80; ++i) {
    uint32_t f = 0, k = 0;
    if (i < 20) {
      f = (b & c) | ((~b) & d);
      k = 0x5A827999U;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1U;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDCU;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6U;
    }
    const uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rotl32(b, 30);
    b = a;
    a = temp;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  secure_zero(w, sizeof(w));
}

void sha1(const uint8_t *data, size_t size, uint8_t out[kSha1Digest]) {
  uint32_t state[5] = {0x67452301U, 0xEFCDAB89U, 0x98BADCFEU, 0x10325476U,
                       0xC3D2E1F0U};
  uint8_t block[64] = {0};
  const uint64_t total_bits = static_cast<uint64_t>(size) * 8U;
  while (size >= 64) {
    sha1_compress(state, data);
    data += 64;
    size -= 64;
  }
  if (size != 0) memcpy(block, data, size);
  block[size] = 0x80;
  if (size >= 56) {
    sha1_compress(state, block);
    memset(block, 0, sizeof(block));
  }
  for (uint8_t i = 0; i < 8; ++i) {
    block[63 - i] = static_cast<uint8_t>(total_bits >> (i * 8U));
  }
  sha1_compress(state, block);
  for (uint8_t i = 0; i < 5; ++i) {
    out[i * 4] = static_cast<uint8_t>(state[i] >> 24);
    out[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
    out[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
    out[i * 4 + 3] = static_cast<uint8_t>(state[i]);
  }
  secure_zero(state, sizeof(state));
  secure_zero(block, sizeof(block));
}

void hmac_sha1(const uint8_t *key, size_t key_size, const uint8_t *data,
               size_t data_size, uint8_t out[kSha1Digest]) {
  uint8_t normalized[64] = {0};
  uint8_t inner[64], outer[64], digest[kSha1Digest];
  if (key_size > sizeof(normalized)) {
    sha1(key, key_size, normalized);
  } else if (key_size != 0) {
    memcpy(normalized, key, key_size);
  }
  for (uint8_t i = 0; i < 64; ++i) {
    inner[i] = normalized[i] ^ 0x36;
    outer[i] = normalized[i] ^ 0x5c;
  }
  uint32_t state[5] = {0x67452301U, 0xEFCDAB89U, 0x98BADCFEU, 0x10325476U,
                       0xC3D2E1F0U};
  uint8_t block[64] = {0};
  // Hash (inner_pad || data) without concatenating into a variable buffer.
  uint64_t total_bits = static_cast<uint64_t>(64 + data_size) * 8U;
  sha1_compress(state, inner);
  while (data_size >= 64) {
    sha1_compress(state, data);
    data += 64;
    data_size -= 64;
  }
  if (data_size != 0) memcpy(block, data, data_size);
  block[data_size] = 0x80;
  if (data_size >= 56) {
    sha1_compress(state, block);
    memset(block, 0, sizeof(block));
  }
  for (uint8_t i = 0; i < 8; ++i) {
    block[63 - i] = static_cast<uint8_t>(total_bits >> (i * 8U));
  }
  sha1_compress(state, block);
  for (uint8_t i = 0; i < 5; ++i) {
    digest[i * 4] = static_cast<uint8_t>(state[i] >> 24);
    digest[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
    digest[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
    digest[i * 4 + 3] = static_cast<uint8_t>(state[i]);
  }
  // Outer hash starts with a fresh state and only the 64-byte pad, so the
  // total length is exactly 84 bytes (one full pad block + 20-byte digest).
  uint32_t outer_state[5] = {0x67452301U, 0xEFCDAB89U, 0x98BADCFEU,
                             0x10325476U, 0xC3D2E1F0U};
  uint8_t outer_block[64] = {0};
  sha1_compress(outer_state, outer);
  memcpy(outer_block, digest, sizeof(digest));
  outer_block[20] = 0x80;
  for (uint8_t i = 0; i < 8; ++i) {
    outer_block[63 - i] = static_cast<uint8_t>((84ULL * 8ULL) >> (i * 8U));
  }
  sha1_compress(outer_state, outer_block);
  for (uint8_t i = 0; i < 5; ++i) {
    out[i * 4] = static_cast<uint8_t>(outer_state[i] >> 24);
    out[i * 4 + 1] = static_cast<uint8_t>(outer_state[i] >> 16);
    out[i * 4 + 2] = static_cast<uint8_t>(outer_state[i] >> 8);
    out[i * 4 + 3] = static_cast<uint8_t>(outer_state[i]);
  }
  secure_zero(normalized, sizeof(normalized));
  secure_zero(inner, sizeof(inner));
  secure_zero(outer, sizeof(outer));
  secure_zero(block, sizeof(block));
  secure_zero(outer_block, sizeof(outer_block));
  secure_zero(digest, sizeof(digest));
  secure_zero(state, sizeof(state));
  secure_zero(outer_state, sizeof(outer_state));
}

bool hmac_for(TotpAlgorithm algorithm, const uint8_t *key, size_t key_size,
              const uint8_t *data, size_t data_size, uint8_t *out,
              size_t *out_size) {
  switch (algorithm) {
    case TotpAlgorithm::Sha1:
      hmac_sha1(key, key_size, data, data_size, out);
      *out_size = kSha1Digest;
      return true;
    case TotpAlgorithm::Sha256:
      if (!crypto_hmac_sha256(key, key_size, data, data_size, out)) return false;
      *out_size = kSha256Size;
      return true;
    case TotpAlgorithm::Sha512:
      if (!crypto_hmac_sha512(key, key_size, data, data_size, out)) return false;
      *out_size = kSha512Size;
      return true;
    default:
      return false;
  }
}

uint32_t decimal_modulus(uint32_t digits) {
  uint32_t value = 1;
  while (digits--) value *= 10U;
  return value;
}

uint64_t clock_unix = 0;
uint64_t clock_millis = 0;
uint64_t clock_last_millis = 0;
bool clock_valid = false;

}  // namespace

TotpError totp_base32_decode(const char *text, uint8_t *out, size_t capacity,
                             size_t *out_size) {
  if (out_size != nullptr) *out_size = 0;
  if (text == nullptr || out == nullptr || out_size == nullptr) {
    return TotpError::InvalidArgument;
  }
  uint32_t buffer = 0;
  uint8_t bits = 0;
  size_t written = 0;
  size_t data_chars = 0;
  size_t pad_chars = 0;
  bool padding = false;
  for (const char *cursor = text; *cursor != '\0'; ++cursor) {
    const char c = *cursor;
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
    if (c == '=') {
      padding = true;
      ++pad_chars;
      continue;
    }
    if (padding) return TotpError::InvalidBase32;
    uint8_t value = 0;
    if (c >= 'A' && c <= 'Z') value = static_cast<uint8_t>(c - 'A');
    else if (c >= 'a' && c <= 'z') value = static_cast<uint8_t>(c - 'a');
    else if (c >= '2' && c <= '7') value = static_cast<uint8_t>(c - '2' + 26);
    else return TotpError::InvalidBase32;
    ++data_chars;
    buffer = (buffer << 5) | value;
    bits = static_cast<uint8_t>(bits + 5);
    if (bits >= 8) {
      bits = static_cast<uint8_t>(bits - 8);
      if (written == capacity) return TotpError::BufferTooSmall;
      out[written++] = static_cast<uint8_t>(buffer >> bits);
      buffer &= (1U << bits) - 1U;
    }
  }
  if (padding) {
    const size_t remainder = data_chars % 8;
    if (remainder == 0 || remainder == 1 || remainder == 3 || remainder == 6 ||
        pad_chars != 8 - remainder) {
      return TotpError::InvalidBase32;
    }
  }
  if (bits >= 5 || (bits != 0 && buffer != 0)) return TotpError::InvalidBase32;
  if (written == 0) return TotpError::InvalidBase32;
  if (written > kTotpSecretMaxBytes) return TotpError::SecretTooLong;
  *out_size = written;
  secure_zero(&buffer, sizeof(buffer));
  return TotpError::Ok;
}

bool totp_generate(const uint8_t *secret, size_t secret_size, uint64_t counter,
                   uint32_t digits, TotpAlgorithm algorithm,
                   uint32_t *out_code) {
  if (out_code != nullptr) *out_code = 0;
  if (secret == nullptr || secret_size == 0 ||
      secret_size > kTotpSecretMaxBytes || out_code == nullptr ||
      digits < 6 || digits > 8) {
    return false;
  }
  uint8_t message[8];
  for (uint8_t i = 0; i < 8; ++i) {
    message[7 - i] = static_cast<uint8_t>(counter >> (i * 8U));
  }
  uint8_t digest[kSha512Size] = {0};
  size_t digest_size = 0;
  const bool hashed = hmac_for(algorithm, secret, secret_size, message,
                               sizeof(message), digest, &digest_size);
  if (!hashed || digest_size < kSha1Digest) {
    secure_zero(digest, sizeof(digest));
    return false;
  }
  const uint8_t offset = digest[digest_size - 1] & 0x0f;
  const uint32_t binary =
      ((static_cast<uint32_t>(digest[offset]) & 0x7fU) << 24) |
      (static_cast<uint32_t>(digest[offset + 1]) << 16) |
      (static_cast<uint32_t>(digest[offset + 2]) << 8) |
      static_cast<uint32_t>(digest[offset + 3]);
  *out_code = binary % decimal_modulus(digits);
  secure_zero(digest, sizeof(digest));
  secure_zero(message, sizeof(message));
  return true;
}

TotpError totp_generate_unix(const uint8_t *secret, size_t secret_size,
                             uint64_t unix_seconds, uint32_t period,
                             uint32_t digits, TotpAlgorithm algorithm,
                             uint32_t *out_code) {
  if (out_code != nullptr) *out_code = 0;
  if (secret == nullptr || secret_size == 0 || out_code == nullptr ||
      period == 0 || period > 3600 || digits < 6 || digits > 8) {
    return TotpError::InvalidArgument;
  }
  if (secret_size > kTotpSecretMaxBytes) return TotpError::SecretTooLong;
  if (!totp_generate(secret, secret_size, unix_seconds / period, digits,
                     algorithm, out_code)) {
    return TotpError::Unsupported;
  }
  return TotpError::Ok;
}

bool totp_clock_set_unix(uint64_t unix_seconds, uint64_t now_ms) {
  if (unix_seconds == 0) return false;
  clock_unix = unix_seconds;
  clock_millis = now_ms;
  clock_last_millis = now_ms;
  clock_valid = true;
  return true;
}

bool totp_clock_unix(uint64_t now_ms, uint64_t *out_unix) {
  if (out_unix == nullptr) return false;
  *out_unix = 0;
  if (!clock_valid) return false;
  if (now_ms < clock_last_millis) {
    totp_clock_clear();
    return false;
  }
  const uint64_t elapsed = (now_ms - clock_millis) / 1000U;
  if (elapsed > UINT64_MAX - clock_unix) {
    totp_clock_clear();
    return false;
  }
  clock_last_millis = now_ms;
  *out_unix = clock_unix + elapsed;
  return true;
}

bool totp_clock_valid() { return clock_valid; }

void totp_clock_clear() {
  clock_unix = 0;
  clock_millis = 0;
  clock_last_millis = 0;
  clock_valid = false;
}

bool run_totp_self_tests() {
  static const uint8_t kAbc[] = {'a', 'b', 'c'};
  static const uint8_t kSha1Abc[20] = {
      0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
      0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
  uint8_t digest[kSha512Size] = {0};
  sha1(kAbc, sizeof(kAbc), digest);
  bool ok = crypto_constant_time_equal(digest, kSha1Abc, sizeof(kSha1Abc));

  // RFC 2202 HMAC-SHA1 case 1.
  uint8_t key[20];
  memset(key, 0x0b, sizeof(key));
  static const uint8_t kHmacData[] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
  static const uint8_t kHmacExpected[20] = {
      0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
      0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00};
  hmac_sha1(key, sizeof(key), kHmacData, sizeof(kHmacData), digest);
  ok = ok && crypto_constant_time_equal(digest, kHmacExpected, sizeof(kHmacExpected));
  secure_zero(key, sizeof(key));

  // RFC 4648 base32 and the canonical TOTP example secret.
  uint8_t secret[kTotpSecretMaxBytes] = {0};
  size_t secret_size = 0;
  ok = ok && totp_base32_decode("MZXW6===", secret, sizeof(secret), &secret_size) ==
                 TotpError::Ok && secret_size == 3 &&
             secret[0] == 'f' && secret[1] == 'o' && secret[2] == 'o';
  secure_zero(secret, sizeof(secret));
  secret_size = 0;
  ok = ok && totp_base32_decode("JBSWY3DPEHPK3PXP", secret, sizeof(secret),
                                &secret_size) == TotpError::Ok &&
             secret_size == 10 &&
             memcmp(secret, "Hello!\xde\xad\xbe\xef", 10) == 0;
  ok = ok && totp_base32_decode("JBSWY3DPEHPK3PX!", secret, sizeof(secret),
                                &secret_size) == TotpError::InvalidBase32;
  secure_zero(secret, sizeof(secret));

  // RFC 6238 Appendix B, SHA-1.
  static const uint8_t kRfcSecret[] = "12345678901234567890";
  struct Vector { uint64_t time; uint32_t code; };
  static const Vector kSha1Vectors[] = {
      {59ULL, 94287082U}, {1111111109ULL, 7081804U},
      {1111111111ULL, 14050471U}, {1234567890ULL, 89005924U},
      {2000000000ULL, 69279037U}, {20000000000ULL, 65353130U}};
  for (const Vector &vector : kSha1Vectors) {
    uint32_t code = 0;
    ok = ok && totp_generate_unix(kRfcSecret, sizeof(kRfcSecret) - 1, vector.time,
                                  30, 8, TotpAlgorithm::Sha1, &code) ==
                   TotpError::Ok && code == vector.code;
  }
  static const uint8_t kRfc256Secret[] = "12345678901234567890123456789012";
  static const uint32_t kSha256Codes[] = {46119246U, 68084774U, 67062674U,
                                          91819424U, 90698825U, 77737706U};
  for (size_t i = 0; i < sizeof(kSha1Vectors) / sizeof(kSha1Vectors[0]); ++i) {
    uint32_t code = 0;
    ok = ok && totp_generate_unix(kRfc256Secret, sizeof(kRfc256Secret) - 1,
                                  kSha1Vectors[i].time, 30, 8,
                                  TotpAlgorithm::Sha256, &code) == TotpError::Ok &&
               code == kSha256Codes[i];
  }
  static const uint8_t kRfc512Secret[] =
      "1234567890123456789012345678901234567890123456789012345678901234";
  static const uint32_t kSha512Codes[] = {90693936U, 25091201U, 99943326U,
                                          93441116U, 38618901U, 47863826U};
  for (size_t i = 0; i < sizeof(kSha1Vectors) / sizeof(kSha1Vectors[0]); ++i) {
    uint32_t code = 0;
    ok = ok && totp_generate_unix(kRfc512Secret, sizeof(kRfc512Secret) - 1,
                                  kSha1Vectors[i].time, 30, 8,
                                  TotpAlgorithm::Sha512, &code) == TotpError::Ok &&
               code == kSha512Codes[i];
  }

  totp_clock_clear();
  ok = ok && !totp_clock_valid() && totp_clock_set_unix(1234567890ULL, 1000U);
  uint64_t now = 0;
  ok = ok && totp_clock_unix(31000U, &now) && now == 1234567920ULL;
  ok = ok && totp_clock_set_unix(1234567890ULL, 0xfffff000U);
  ok = ok && totp_clock_unix(0x100000100ULL, &now) && now == 1234567894ULL;
  ok = ok && !totp_clock_unix(0x100000000ULL, &now);  // rollback even above anchor
  totp_clock_clear();
  return ok;
}

}  // namespace hexwallet
