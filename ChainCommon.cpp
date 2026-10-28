#include "ChainCommon.h"

#include <stdio.h>
#include <string.h>

#include "RandomSource.h"
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

size_t encoded_length(size_t payload_size) {
  if (payload_size <= 55) return 1 + payload_size;
  size_t length_bytes = 0;
  for (size_t value = payload_size; value != 0; value >>= 8) ++length_bytes;
  return 1 + length_bytes + payload_size;
}

bool append_prefix(uint8_t *out, size_t capacity, size_t *offset,
                   uint8_t short_base, uint8_t long_base,
                   size_t payload_size) {
  if (payload_size <= 55) {
    if (*offset + 1 > capacity) return false;
    out[(*offset)++] = static_cast<uint8_t>(short_base + payload_size);
    return true;
  }
  size_t length_bytes = 0;
  uint8_t encoded[sizeof(size_t)] = {};
  for (size_t value = payload_size; value != 0; value >>= 8) {
    encoded[length_bytes++] = static_cast<uint8_t>(value);
  }
  if (*offset + 1 + length_bytes > capacity) return false;
  out[(*offset)++] = static_cast<uint8_t>(long_base + length_bytes);
  for (size_t index = length_bytes; index != 0; --index) {
    out[(*offset)++] = encoded[index - 1];
  }
  return true;
}

}  // namespace

bool RlpWriter::bytes(const uint8_t *data, size_t size) {
  if (!ok_ || (size != 0 && data == nullptr)) {
    ok_ = false;
    return false;
  }
  if (size == 1 && data[0] < 0x80) {
    if (size_ + 1 > capacity_) {
      ok_ = false;
      return false;
    }
    out_[size_++] = data[0];
    return true;
  }
  if (!append_prefix(out_, capacity_, &size_, 0x80, 0xb7, size)) {
    ok_ = false;
    return false;
  }
  if (size_ + size > capacity_) {
    ok_ = false;
    return false;
  }
  if (size != 0) memcpy(out_ + size_, data, size);
  size_ += size;
  return true;
}

bool RlpWriter::integer(const uint8_t *big_endian, size_t size) {
  if (!ok_ || (size != 0 && big_endian == nullptr)) {
    ok_ = false;
    return false;
  }
  size_t offset = 0;
  while (offset < size && big_endian[offset] == 0) ++offset;
  return bytes(big_endian + offset, size - offset);
}

bool RlpWriter::raw(const uint8_t *data, size_t size) {
  if (!ok_ || (size != 0 && data == nullptr)) {
    ok_ = false;
    return false;
  }
  if (size_ + size > capacity_) {
    ok_ = false;
    return false;
  }
  if (size != 0) memcpy(out_ + size_, data, size);
  size_ += size;
  return true;
}

bool rlp_wrap_list(const uint8_t *payload, size_t payload_size, uint8_t *out,
                   size_t capacity, size_t *out_size) {
  if (out_size == nullptr || out == nullptr ||
      (payload_size != 0 && payload == nullptr)) {
    return false;
  }
  const size_t total = encoded_length(payload_size);
  if (total > capacity) return false;
  size_t offset = 0;
  if (!append_prefix(out, capacity, &offset, 0xc0, 0xf7, payload_size)) return false;
  if (payload_size != 0) memcpy(out + offset, payload, payload_size);
  *out_size = offset + payload_size;
  return true;
}

size_t chain_hex_length(size_t bytes) {
  return bytes * 2 + 1;
}

void chain_hex(const uint8_t *data, size_t size, char *out, size_t out_size) {
  static const char kAlphabet[] = "0123456789abcdef";
  if (out == nullptr || out_size == 0) return;
  const size_t needed = chain_hex_length(size);
  if (data == nullptr || out_size < needed) {
    out[0] = '\0';
    return;
  }
  for (size_t index = 0; index < size; ++index) {
    out[2 * index] = kAlphabet[data[index] >> 4];
    out[2 * index + 1] = kAlphabet[data[index] & 0x0f];
  }
  out[2 * size] = '\0';
}

bool chain_parse_hex(const char *text, uint8_t *out, size_t capacity,
                     size_t *out_size) {
  if (text == nullptr || out == nullptr || out_size == nullptr) return false;
  if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;
  const size_t length = strlen(text);
  if ((length & 1) != 0 || length / 2 > capacity) return false;
  for (size_t index = 0; index < length / 2; ++index) {
    uint8_t value = 0;
    for (size_t nibble = 0; nibble < 2; ++nibble) {
      const char c = text[2 * index + nibble];
      uint8_t digit = 0;
      if (c >= '0' && c <= '9') digit = static_cast<uint8_t>(c - '0');
      else if (c >= 'a' && c <= 'f') digit = static_cast<uint8_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') digit = static_cast<uint8_t>(c - 'A' + 10);
      else return false;
      value = static_cast<uint8_t>((value << 4) | digit);
    }
    out[index] = value;
  }
  *out_size = length / 2;
  return true;
}

bool chain_constant_time_equal(const uint8_t *left, const uint8_t *right,
                               size_t size) {
  if (left == nullptr || right == nullptr) return false;
  uint8_t difference = 0;
  for (size_t index = 0; index < size; ++index) {
    difference |= static_cast<uint8_t>(left[index] ^ right[index]);
  }
  return difference == 0;
}

namespace {

int chain_random_callback(void *, unsigned char *output, size_t length) {
  random_fill(output, length);
  return 0;
}

size_t chain_der_integer(const mbedtls_mpi &value, uint8_t *out) {
  uint8_t raw[32];
  mbedtls_mpi_write_binary(&value, raw, sizeof(raw));
  size_t first = 0;
  while (first < sizeof(raw) - 1 && raw[first] == 0) ++first;
  const bool prefix_zero = (raw[first] & 0x80) != 0;
  const size_t length = sizeof(raw) - first + (prefix_zero ? 1 : 0);
  out[0] = 0x02;
  out[1] = static_cast<uint8_t>(length);
  size_t position = 2;
  if (prefix_zero) out[position++] = 0;
  memcpy(out + position, raw + first, sizeof(raw) - first);
  secure_zero(raw, sizeof(raw));
  return 2 + length;
}

}  // namespace

bool chain_secp256k1_sign_der(const uint8_t private_key[32],
                              const uint8_t digest[32], uint8_t *der,
                              size_t *in_out_size) {
  if (private_key == nullptr || digest == nullptr || der == nullptr ||
      in_out_size == nullptr || *in_out_size < 72) {
    return false;
  }
  mbedtls_ecp_group group;
  mbedtls_mpi d, r, s, half_order;
  mbedtls_ecp_point public_key;
  mbedtls_ecp_group_init(&group);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&half_order);
  mbedtls_ecp_point_init(&public_key);
  int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
  if (result == 0) result = mbedtls_mpi_read_binary(&d, private_key, 32);
  if (result == 0) {
    result = mbedtls_ecdsa_sign_det_ext(&group, &r, &s, &d, digest, 32,
                                        MBEDTLS_MD_SHA256,
                                        chain_random_callback, nullptr);
  }
  if (result == 0) result = mbedtls_mpi_copy(&half_order, &group.N);
  if (result == 0) result = mbedtls_mpi_shift_r(&half_order, 1);
  if (result == 0 && mbedtls_mpi_cmp_mpi(&s, &half_order) > 0) {
    result = mbedtls_mpi_sub_mpi(&s, &group.N, &s);
  }
  if (result == 0) {
    result = mbedtls_ecp_mul(&group, &public_key, &d, &group.G,
                             chain_random_callback, nullptr);
  }
  if (result == 0) {
    result = mbedtls_ecdsa_verify(&group, digest, 32, &public_key, &r, &s);
  }
  uint8_t integers[70] = {};
  size_t integer_size = 0;
  if (result == 0) {
    integer_size = chain_der_integer(r, integers);
    integer_size += chain_der_integer(s, integers + integer_size);
    if (*in_out_size < integer_size + 2) result = -1;
  }
  if (result == 0) {
    der[0] = 0x30;
    der[1] = static_cast<uint8_t>(integer_size);
    memcpy(der + 2, integers, integer_size);
    *in_out_size = integer_size + 2;
  }
  secure_zero(integers, sizeof(integers));
  mbedtls_mpi_free(&half_order);
  mbedtls_ecp_point_free(&public_key);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&group);
  return result == 0;
}

namespace {

// Local HMAC-SHA256 so RFC 6979 does not depend on the streaming mbedtls HMAC
// API (the host test shim only implements the one-shot variant).
bool hmac_sha256_local(const uint8_t *key, size_t key_size, const uint8_t *msg,
                       size_t msg_size, uint8_t out[32]) {
  if (key == nullptr || out == nullptr || (msg == nullptr && msg_size != 0) ||
      msg_size > 256) {
    return false;
  }
  uint8_t block[64] = {};
  if (key_size > sizeof(block)) {
    if (!crypto_sha256(key, key_size, block)) return false;
  } else {
    memcpy(block, key, key_size);
  }
  uint8_t buffer[64 + 256] = {};
  for (size_t i = 0; i < 64; ++i) buffer[i] = static_cast<uint8_t>(block[i] ^ 0x36);
  if (msg_size != 0) memcpy(buffer + 64, msg, msg_size);
  uint8_t inner[32] = {};
  bool ok = crypto_sha256(buffer, 64 + msg_size, inner);
  if (ok) {
    memset(buffer, 0, sizeof(buffer));
    for (size_t i = 0; i < 64; ++i) buffer[i] = static_cast<uint8_t>(block[i] ^ 0x5c);
    memcpy(buffer + 64, inner, 32);
    ok = crypto_sha256(buffer, 96, out);
  }
  secure_zero(block, sizeof(block));
  secure_zero(buffer, sizeof(buffer));
  secure_zero(inner, sizeof(inner));
  return ok;
}

// RFC 6979 section 3.2 with optional extra entropy (libsecp256k1's
// nonce_function_rfc6979 also appends extra data before the first HMAC).
bool rfc6979_nonce(const uint8_t private_key[32], const uint8_t digest[32],
                   const uint8_t *extra, size_t extra_size, uint8_t out[32]) {
  if (extra_size > 8) return false;
  uint8_t v[32];
  uint8_t k[32];
  memset(v, 0x01, sizeof(v));
  memset(k, 0x00, sizeof(k));
  uint8_t message[32 + 1 + 32 + 32 + 8];
  size_t size = 0;
  memcpy(message, v, 32);
  size = 32;
  message[size++] = 0x00;
  memcpy(message + size, private_key, 32);
  size += 32;
  memcpy(message + size, digest, 32);
  size += 32;
  if (extra_size != 0) {
    memcpy(message + size, extra, extra_size);
    size += extra_size;
  }
  bool ok = hmac_sha256_local(k, sizeof(k), message, size, k);
  if (ok) ok = hmac_sha256_local(k, sizeof(k), v, sizeof(v), v);
  if (ok) {
    memcpy(message, v, 32);
    message[32] = 0x01;
    ok = hmac_sha256_local(k, sizeof(k), message, size, k) &&
         hmac_sha256_local(k, sizeof(k), v, sizeof(v), v) &&
         hmac_sha256_local(k, sizeof(k), v, sizeof(v), v);
  }
  if (ok) memcpy(out, v, 32);
  secure_zero(v, sizeof(v));
  secure_zero(k, sizeof(k));
  secure_zero(message, sizeof(message));
  return ok;
}

}  // namespace

bool chain_secp256k1_sign_der_canonical(const uint8_t private_key[32],
                                        const uint8_t digest[32], uint8_t *der,
                                        size_t *in_out_size,
                                        uint8_t *out_recovery) {
  if (private_key == nullptr || digest == nullptr || der == nullptr ||
      in_out_size == nullptr || out_recovery == nullptr ||
      *in_out_size < 72) {
    return false;
  }
  mbedtls_ecp_group group;
  mbedtls_mpi d, e, k, r, s, inverse, half_order, x;
  mbedtls_ecp_point point;
  mbedtls_ecp_group_init(&group);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&e);
  mbedtls_mpi_init(&k);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&inverse);
  mbedtls_mpi_init(&half_order);
  mbedtls_mpi_init(&x);
  mbedtls_ecp_point_init(&point);

  int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
  if (result == 0) result = mbedtls_mpi_read_binary(&d, private_key, 32);
  if (result == 0) result = mbedtls_mpi_read_binary(&e, digest, 32);
  if (result == 0) result = mbedtls_mpi_mod_mpi(&e, &e, &group.N);
  if (result == 0) result = mbedtls_mpi_copy(&half_order, &group.N);
  if (result == 0) result = mbedtls_mpi_shift_r(&half_order, 1);

  bool canonical = false;
  uint8_t recovery = 0;
  uint8_t r_bytes[32] = {};
  uint8_t s_bytes[32] = {};
  // Roughly 1 in 4 nonces yields a canonical pair, so the loop terminates
  // almost immediately; the cap only bounds pathological cases.
  for (uint32_t attempt = 0; result == 0 && !canonical && attempt < 256;
       ++attempt) {
    uint8_t extra[4] = {static_cast<uint8_t>(attempt),
                        static_cast<uint8_t>(attempt >> 8),
                        static_cast<uint8_t>(attempt >> 16),
                        static_cast<uint8_t>(attempt >> 24)};
    uint8_t nonce[32] = {};
    if (!rfc6979_nonce(private_key, digest, extra, sizeof(extra), nonce)) {
      result = -1;
      break;
    }
    bool usable = false;
    for (uint32_t bump = 0; result == 0 && bump < 64 && !usable; ++bump) {
      if (bump != 0) {
        nonce[31] = static_cast<uint8_t>(nonce[31] + 1);
      }
      if (mbedtls_mpi_read_binary(&k, nonce, 32) != 0) {
        result = -1;
        break;
      }
      if (mbedtls_mpi_cmp_int(&k, 1) < 0 ||
          mbedtls_mpi_cmp_mpi(&k, &group.N) >= 0) {
        continue;
      }
      if (mbedtls_ecp_mul(&group, &point, &k, &group.G, chain_random_callback,
                          nullptr) != 0) {
        result = -1;
        break;
      }
      if (mbedtls_mpi_copy(&x, &point.MBEDTLS_PRIVATE(X)) != 0 ||
          mbedtls_mpi_mod_mpi(&r, &x, &group.N) != 0) {
        result = -1;
        break;
      }
      if (mbedtls_mpi_cmp_int(&r, 0) == 0) continue;
      if (mbedtls_mpi_inv_mod(&inverse, &k, &group.N) != 0) {
        result = -1;
        break;
      }
      // s = k^-1 (e + r*d) mod n
      if (mbedtls_mpi_mul_mpi(&s, &r, &d) != 0 ||
          mbedtls_mpi_mod_mpi(&s, &s, &group.N) != 0 ||
          mbedtls_mpi_add_mpi(&s, &s, &e) != 0 ||
          mbedtls_mpi_mod_mpi(&s, &s, &group.N) != 0 ||
          mbedtls_mpi_mul_mpi(&s, &s, &inverse) != 0 ||
          mbedtls_mpi_mod_mpi(&s, &s, &group.N) != 0) {
        result = -1;
        break;
      }
      if (mbedtls_mpi_cmp_int(&s, 0) == 0) continue;
      bool flipped = false;
      if (mbedtls_mpi_cmp_mpi(&s, &half_order) > 0) {
        if (mbedtls_mpi_sub_mpi(&s, &group.N, &s) != 0) {
          result = -1;
          break;
        }
        flipped = true;
      }
      if (mbedtls_mpi_write_binary(&r, r_bytes, 32) != 0 ||
          mbedtls_mpi_write_binary(&s, s_bytes, 32) != 0) {
        result = -1;
        break;
      }
      if ((r_bytes[0] & 0x80) != 0 || (s_bytes[0] & 0x80) != 0 ||
          (r_bytes[0] == 0 && !(r_bytes[1] & 0x80)) ||
          (s_bytes[0] == 0 && !(s_bytes[1] & 0x80))) {
        continue;  // not canonical, try the next nonce
      }
      const uint8_t parity = static_cast<uint8_t>(
          mbedtls_mpi_get_bit(&point.MBEDTLS_PRIVATE(Y), 0));
      recovery = static_cast<uint8_t>((flipped ? (parity ^ 1U) : parity) |
          (mbedtls_mpi_cmp_mpi(&x, &group.N) >= 0 ? 2U : 0U));
      usable = true;
      canonical = true;
    }
    secure_zero(nonce, sizeof(nonce));
  }
  if (result == 0 && canonical) {
    uint8_t integers[70] = {};
    size_t integer_size = chain_der_integer(r, integers);
    integer_size += chain_der_integer(s, integers + integer_size);
    if (*in_out_size < integer_size + 2) {
      result = -1;
    } else {
      der[0] = 0x30;
      der[1] = static_cast<uint8_t>(integer_size);
      memcpy(der + 2, integers, integer_size);
      *in_out_size = integer_size + 2;
      *out_recovery = recovery;
    }
    secure_zero(integers, sizeof(integers));
  }
  secure_zero(r_bytes, sizeof(r_bytes));
  secure_zero(s_bytes, sizeof(s_bytes));
  mbedtls_mpi_free(&x);
  mbedtls_mpi_free(&half_order);
  mbedtls_mpi_free(&inverse);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&k);
  mbedtls_mpi_free(&e);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&point);
  mbedtls_ecp_group_free(&group);
  return result == 0 && canonical;
}

bool chain_format_units(uint64_t value, uint8_t decimals, const char *symbol,
                        char *out, size_t out_size) {
  if (out == nullptr || out_size == 0 || symbol == nullptr || decimals > 18) {
    return false;
  }
  if (decimals == 0) {
    const int written = snprintf(out, out_size, "%llu %s",
                                 static_cast<unsigned long long>(value), symbol);
    return written > 0 && static_cast<size_t>(written) < out_size;
  }
  uint64_t scale = 1;
  for (uint8_t index = 0; index < decimals; ++index) scale *= 10;
  const uint64_t whole = value / scale;
  uint64_t fraction = value % scale;
  char digits[19] = {};
  for (size_t index = decimals; index != 0; --index) {
    digits[index - 1] = static_cast<char>('0' + (fraction % 10));
    fraction /= 10;
  }
  size_t length = decimals;
  while (length > 1 && digits[length - 1] == '0') --length;
  digits[length] = '\0';
  const int written = snprintf(out, out_size, "%llu.%s %s",
                               static_cast<unsigned long long>(whole), digits,
                               symbol);
  return written > 0 && static_cast<size_t>(written) < out_size;
}

bool chain_u128_is_zero(const uint8_t value[kChainUint128Size]) {
  uint8_t aggregate = 0;
  for (size_t index = 0; index < kChainUint128Size; ++index) {
    aggregate |= value[index];
  }
  return aggregate == 0;
}

void chain_u128_minimal(const uint8_t value[kChainUint128Size],
                        const uint8_t **out, size_t *out_size) {
  size_t offset = 0;
  while (offset < kChainUint128Size && value[offset] == 0) ++offset;
  *out = value + offset;
  *out_size = kChainUint128Size - offset;
}

bool chain_u128_hex(const uint8_t value[kChainUint128Size], char *out,
                    size_t out_size) {
  if (value == nullptr || out == nullptr) return false;
  const uint8_t *minimal = nullptr;
  size_t minimal_size = 0;
  chain_u128_minimal(value, &minimal, &minimal_size);
  if (minimal_size == 0) {
    if (out_size < 2) return false;
    out[0] = '0';
    out[1] = '\0';
    return true;
  }
  if (out_size < 2 * minimal_size + 1) return false;
  chain_hex(minimal, minimal_size, out, out_size);
  return true;
}

bool chain_format_units128(const uint8_t value[kChainUint128Size],
                           uint8_t decimals, const char *symbol, char *out,
                           size_t out_size) {
  if (value == nullptr || out == nullptr || out_size == 0 || symbol == nullptr ||
      decimals > 38) {
    return false;
  }
  // Repeated division by ten keeps the implementation free of compiler-specific
  // 128-bit integer extensions.
  uint8_t work[kChainUint128Size] = {};
  memcpy(work, value, sizeof(work));
  char reversed[48] = {};
  size_t digits = 0;
  bool nonzero = !chain_u128_is_zero(work);
  while (nonzero && digits < sizeof(reversed) - 1) {
    uint32_t remainder = 0;
    for (size_t index = 0; index < kChainUint128Size; ++index) {
      const uint32_t current = (remainder << 8) | work[index];
      work[index] = static_cast<uint8_t>(current / 10);
      remainder = current % 10;
    }
    reversed[digits++] = static_cast<char>('0' + remainder);
    nonzero = !chain_u128_is_zero(work);
  }
  if (digits == 0) reversed[digits++] = '0';
  char decimal[56] = {};
  for (size_t index = 0; index < digits; ++index) {
    decimal[index] = reversed[digits - 1 - index];
  }
  decimal[digits] = '\0';

  char whole[56] = {};
  char fraction[40] = {};
  if (digits <= decimals) {
    strcpy(whole, "0");
    const size_t zeros = decimals - digits;
    memset(fraction, '0', zeros);
    memcpy(fraction + zeros, decimal, digits);
    fraction[decimals] = '\0';
  } else {
    const size_t whole_digits = digits - decimals;
    memcpy(whole, decimal, whole_digits);
    whole[whole_digits] = '\0';
    memcpy(fraction, decimal + whole_digits, decimals);
    fraction[decimals] = '\0';
  }
  if (decimals == 0) {
    const int written = snprintf(out, out_size, "%s %s", whole, symbol);
    return written > 0 && static_cast<size_t>(written) < out_size;
  }
  size_t fraction_length = decimals;
  while (fraction_length > 1 && fraction[fraction_length - 1] == '0') {
    --fraction_length;
  }
  fraction[fraction_length] = '\0';
  const int written = snprintf(out, out_size, "%s.%s %s", whole, fraction,
                               symbol);
  secure_zero(work, sizeof(work));
  return written > 0 && static_cast<size_t>(written) < out_size;
}

uint64_t chain_read_u32_le(const uint8_t *data) {
  return static_cast<uint64_t>(data[0]) |
         (static_cast<uint64_t>(data[1]) << 8) |
         (static_cast<uint64_t>(data[2]) << 16) |
         (static_cast<uint64_t>(data[3]) << 24);
}

uint64_t chain_read_u64_le(const uint8_t *data) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; ++index) {
    value |= static_cast<uint64_t>(data[index]) << (8 * index);
  }
  return value;
}

void chain_write_u32_le(uint32_t value, uint8_t *out) {
  for (size_t index = 0; index < 4; ++index) {
    out[index] = static_cast<uint8_t>(value >> (8 * index));
  }
}

void chain_write_u64_le(uint64_t value, uint8_t *out) {
  for (size_t index = 0; index < 8; ++index) {
    out[index] = static_cast<uint8_t>(value >> (8 * index));
  }
}

}  // namespace hexwallet
