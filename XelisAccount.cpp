#include "XelisAccount.h"
#include "CryptoPrimitives.h"
#include "RandomSource.h"
#include "SensitiveValue.h"
#include "local_bech32.h"
#include <cstring>
#include <memory>
#define SODIUM_STATIC 1
#define CONFIGURED 1
extern "C" {
#include "src/xelis/ref10/private/ed25519_ref10.h"
}

namespace hexwallet {
namespace {
#include "src/xelis/MnemonicWords.inc"
constexpr uint32_t kWords = 1626;
constexpr uint8_t kH[32] = {0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc, 0x65, 0xc3, 0x77,
                            0xa1, 0x04, 0x8d, 0x74, 0x5f, 0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44,
                            0xcb, 0xcd, 0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34};
bool nonzero(const uint8_t *p) { return p && !sodium_is_zero(p, 32); }
bool scalar(const uint8_t *p) { return nonzero(p) && sc25519_is_canonical(p); }
bool multiply(const uint8_t point[32], const uint8_t s[32], ge25519_p3 &result) {
  ge25519_p3 p;
  if (ristretto255_frombytes(&p, point))
    return false;
  ge25519_scalarmult(&result, s, &p);
  return true;
}
struct Word {
  const char *start;
  size_t length;
};
bool indices(const Word *words, size_t count, const char *dict, uint16_t *output, uint32_t &crc) {
  crc = UINT32_MAX;
  for (size_t i = 0; i < count; ++i) {
    const char *word = dict;
    uint16_t n = 0;
    for (; n < kWords; ++n) {
      const size_t len = strlen(word);
      if (len == words[i].length) {
        size_t j = 0;
        while (j < len) {
          unsigned char c = words[i].start[j];
          if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
          if (c != static_cast<unsigned char>(word[j]))
            break;
          ++j;
        }
        if (j == len)
          break;
      }
      word += len + 1;
    }
    if (n == kWords)
      return false;
    output[i] = n;
    if (i == 24)
      break;
    unsigned characters = 0;
    for (const unsigned char *p = reinterpret_cast<const unsigned char *>(word); *p; ++p) {
      if ((*p & 0xc0) != 0x80 && ++characters > 3)
        break;
      crc ^= *p;
      for (unsigned bit = 0; bit < 8; ++bit)
        crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1)));
    }
  }
  crc = ~crc;
  return true;
}
bool challenge(const uint8_t pk[32], const uint8_t *msg, size_t size, const uint8_t r[32], uint8_t e[32]) {
  if (size > 65536 || (size && !msg))
    return false;
  std::unique_ptr<uint8_t[]> data(new (std::nothrow) uint8_t[64 + size]);
  if (!data)
    return false;
  memcpy(data.get(), pk, 32);
  if (size)
    memcpy(data.get() + 32, msg, size);
  memcpy(data.get() + 32 + size, r, 32);
  uint8_t hash[64];
  const bool hashed = crypto_sha3_512(data.get(), 64 + size, hash);
  secure_zero(data.get(), 64 + size);
  if (!hashed)
    return false;
  sc25519_reduce(hash);
  memcpy(e, hash, 32);
  return true;
}
bool public_from_secret(const uint8_t secret[32], uint8_t pk[32], uint8_t inverse[32]) {
  if (!scalar(secret))
    return false;
  sc25519_invert(inverse, secret);
  ge25519_p3 p;
  if (!multiply(kH, inverse, p))
    return false;
  ristretto255_p3_tobytes(pk, &p);
  return nonzero(pk);
}
} // namespace

bool xelis_recover_private_key(const char *text, uint8_t secret[32]) {
  if (!secret)
    return false;
  memset(secret, 0, 32);
  if (!text)
    return false;
  Word words[25];
  size_t count = 0;
  while (*text) {
    if (*text == ' ') {
      ++text;
      continue;
    }
    if (count == 25)
      return false;
    const char *begin = text;
    while (*text && *text != ' ') {
      if (text - begin >= 32)
        return false;
      ++text;
    }
    words[count++] = {begin, size_t(text - begin)};
  }
  if (count != 24 && count != 25)
    return false;
  SensitiveValue<uint16_t[25]> sequence;
  auto &ids = sequence.get();
  const char *dict = static_cast<unsigned char>(*words[0].start) < 128 ? english : chinese_simplified;
  uint32_t crc;
  if (!indices(words, count, dict, ids, crc) || (count == 25 && ids[crc % 24] != ids[24]))
    return false;
  SensitiveValue<uint8_t[32]> key;
  for (size_t i = 0; i < 8; ++i) {
    const uint32_t a = ids[3 * i], b = ids[3 * i + 1], c = ids[3 * i + 2];
    const uint64_t v =
        a + kWords * ((kWords + b - a) % kWords) + uint64_t(kWords) * kWords * ((kWords + c - b) % kWords);
    if (v > UINT32_MAX)
      return false;
    for (unsigned j = 0; j < 4; ++j)
      key.get()[4 * i + j] = uint8_t(v >> (8 * j));
  }
  if (!scalar(key.get()))
    return false;
  memcpy(secret, key.get(), 32);
  return true;
}

bool xelis_account(const uint8_t secret[32], uint8_t pk[32], char *address, size_t capacity) {
  if (!pk || !address || !capacity)
    return false;
  address[0] = 0;
  memset(pk, 0, 32);
  SensitiveValue<uint8_t[32]> inverse;
  uint8_t bytes[33]{};
  if (!public_from_secret(secret, bytes, inverse.get()))
    return false;
  try {
    std::vector<uint8_t> digits;
    digits.reserve(53);
    unsigned bits = 0;
    uint32_t acc = 0;
    for (uint8_t b : bytes) {
      acc = (acc << 8) | b;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        digits.push_back((acc >> bits) & 31);
      }
    }
    if (bits)
      digits.push_back((acc << (5 - bits)) & 31);
    auto result = bech32::encode("xel", digits, bech32::Encoding::BECH32);
    if (result.size() != 63 || capacity <= result.size())
      return false;
    result[3] = ':';
    memcpy(address, result.c_str(), result.size() + 1);
    memcpy(pk, bytes, 32);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool xelis_public_key_from_address(const char *address, uint8_t pk[32]) {
  if (!pk)
    return false;
  memset(pk, 0, 32);
  if (!address || strlen(address) != 63 || strncmp(address, "xel:", 4))
    return false;
  try {
    std::string text(address);
    text[3] = '1';
    const auto decoded = bech32::decode(text);
    if (decoded.encoding != bech32::Encoding::BECH32 || decoded.hrp != "xel" || decoded.data.size() != 53)
      return false;
    uint8_t raw[33]{};
    uint32_t acc = 0;
    unsigned bits = 0, used = 0;
    for (uint8_t digit : decoded.data) {
      acc = (acc << 5) | digit;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        raw[used++] = uint8_t(acc >> bits);
      }
    }
    ge25519_p3 point;
    if (used != 33 || bits != 1 || (acc & 1) || raw[32] || !nonzero(raw) ||
        ristretto255_frombytes(&point, raw))
      return false;
    memcpy(pk, raw, 32);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool xelis_verify_message(const uint8_t pk[32], const uint8_t *msg, size_t n, const uint8_t sig[64]) {
  if (!nonzero(pk) || !sig || !sc25519_is_canonical(sig) || !sc25519_is_canonical(sig + 32))
    return false;
  ge25519_p3 a, b, r;
  if (!multiply(kH, sig, a) || !multiply(pk, sig + 32, b))
    return false;
  ge25519_cached rhs;
  ge25519_p1p1 diff;
  ge25519_p3_to_cached(&rhs, &b);
  ge25519_sub(&diff, &a, &rhs);
  ge25519_p1p1_to_p3(&r, &diff);
  uint8_t point[32], e[32];
  ristretto255_p3_tobytes(point, &r);
  return nonzero(point) && challenge(pk, msg, n, point, e) && !memcmp(e, sig + 32, 32);
}

bool xelis_sign_message(const uint8_t secret[32], const uint8_t *msg, size_t n, uint8_t sig[64]) {
  if (!sig)
    return false;
  memset(sig, 0, 64);
  SensitiveValue<uint8_t[32]> inv;
  SensitiveValue<uint8_t[64]> nonce;
  uint8_t pk[32], r[32], candidate[64];
  struct NonceInput {
    uint8_t domain[16], digest[64], entropy[32];
  };
  SensitiveValue<NonceInput> material;
  auto &input = material.get();
  memcpy(input.domain, "HexWallet-XEL-v1", 16);
  if ((n && !msg) || n > 65536 || !public_from_secret(secret, pk, inv.get()) ||
      !crypto_sha3_512(msg, n, input.digest) || !random_fill_checked(input.entropy, sizeof(input.entropy)) ||
      !crypto_hmac_sha512(secret, 32, reinterpret_cast<const uint8_t *>(&input), sizeof(input), nonce.get()))
    return false;
  sc25519_reduce(nonce.get());
  ge25519_p3 rp;
  if (!nonzero(nonce.get()) || !multiply(kH, nonce.get(), rp))
    return false;
  ristretto255_p3_tobytes(r, &rp);
  if (!challenge(pk, msg, n, r, candidate + 32))
    return false;
  sc25519_muladd(candidate, inv.get(), candidate + 32, nonce.get());
  if (!xelis_verify_message(pk, msg, n, candidate))
    return false;
  memcpy(sig, candidate, 64);
  return true;
}
} // namespace hexwallet
