// RingCT encoding follows Monero/Masari rctOps; see tools/ringct_source_review.json.
// Upstream license notice: third_party/monero-ringct-LICENSE.txt.
#include "CryptoNoteAmounts.h"

#include <string.h>

#include "CryptoExtended.h"
#include "CryptoNoteRingCt.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {
constexpr uint8_t kG[32] = {
    0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66};
// RingCT's fixed amount generator, shared by the inspected Monero/Masari code.
constexpr uint8_t kH[32] = {
    0x8b,0x65,0x59,0x70,0x15,0x37,0x99,0xaf,0x2a,0xea,0xdc,0x9f,0xf1,0xad,0xd0,0xea,
    0x6c,0x72,0x51,0xd5,0x41,0x54,0xcf,0xa9,0x2c,0x17,0x3a,0x0d,0xd3,0x9c,0x1f,0x94};
constexpr uint8_t kOne[32] = {1};

bool reduced(const uint8_t value[32]) {
  if (value == nullptr) return false;
  uint8_t copy[32];
  memcpy(copy, value, sizeof(copy));
  ed25519_scalar_reduce_mod_l(copy);
  const bool ok = crypto_constant_time_equal(copy, value, sizeof(copy));
  secure_zero(copy, sizeof(copy));
  return ok;
}

size_t encoding_size(RingCtAmountEncoding encoding) {
  switch (encoding) {
    case RingCtAmountEncoding::Legacy: return 64;
    case RingCtAmountEncoding::Compact: return 8;
    default: return 0;
  }
}

void amount_scalar(uint64_t amount, uint8_t out[32]) {
  memset(out, 0, 32);
  for (size_t i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>(amount >> (8 * i));
}

bool amount_factor(const uint8_t key[32], uint8_t out[32]) {
  uint8_t data[38];
  memcpy(data, "amount", 6);
  memcpy(data + 6, key, 32);
  const bool ok = crypto_keccak256(data, sizeof(data), out);
  secure_zero(data, sizeof(data));
  return ok;
}
}  // namespace

bool ringct_commitment(const uint8_t mask[32], uint64_t amount, uint8_t out[32]) {
  if (out == nullptr) return false;
  uint8_t scalar[32], masked[32] = {}, valued[32] = {}, result[32] = {};
  amount_scalar(amount, scalar);
  const bool ok = reduced(mask) && ed25519_point_mul_compressed(kG, mask, masked) &&
      ed25519_point_mul_compressed(kH, scalar, valued) &&
      ed25519_point_add_compressed(masked, valued, result);
  memset(out, 0, 32);
  if (ok) memcpy(out, result, 32);
  secure_zero(scalar, sizeof(scalar)); secure_zero(masked, sizeof(masked));
  secure_zero(valued, sizeof(valued)); secure_zero(result, sizeof(result));
  return ok;
}

bool ringct_commitment_mask(const uint8_t amount_key[32], uint8_t out[32]) {
  if (out == nullptr) return false;
  uint8_t data[47] = {}, result[32] = {};
  bool ok = reduced(amount_key);
  if (ok) {
    memcpy(data, "commitment_mask", 15);
    memcpy(data + 15, amount_key, 32);
    ok = cryptonote_hash_to_scalar(data, sizeof(data), result);
  }
  memset(out, 0, 32);
  if (ok) memcpy(out, result, 32);
  secure_zero(data, sizeof(data)); secure_zero(result, sizeof(result));
  return ok;
}

bool ringct_encode_amount(RingCtAmountEncoding encoding,
                          const uint8_t amount_key[32], uint64_t amount,
                          const uint8_t legacy_mask[32], uint8_t *wire,
                          size_t wire_size, uint8_t out_commitment[32]) {
  uint8_t mask[32] = {}, scalar[32], first[32] = {}, second[32] = {};
  uint8_t encoded[64] = {}, commitment[32] = {};
  amount_scalar(amount, scalar);
  bool ok = wire != nullptr && out_commitment != nullptr &&
      encoding_size(encoding) != 0 && wire_size == encoding_size(encoding) &&
      reduced(amount_key);
  if (ok && encoding == RingCtAmountEncoding::Compact) {
    ok = ringct_commitment_mask(amount_key, mask) && amount_factor(amount_key, first);
    for (size_t i = 0; i < 8; ++i) encoded[i] = scalar[i] ^ first[i];
  } else if (ok) {
    ok = reduced(legacy_mask) && cryptonote_hash_to_scalar(amount_key, 32, first) &&
         cryptonote_hash_to_scalar(first, 32, second);
    if (ok) {
      memcpy(mask, legacy_mask, 32);
      ed25519_scalar_muladd(encoded, kOne, mask, first);
      ed25519_scalar_muladd(encoded + 32, kOne, scalar, second);
    }
  }
  if (ok) ok = ringct_commitment(mask, amount, commitment);
  if (wire != nullptr) memset(wire, 0, wire_size);
  if (out_commitment != nullptr) memset(out_commitment, 0, 32);
  if (ok) { memcpy(wire, encoded, wire_size); memcpy(out_commitment, commitment, 32); }
  secure_zero(mask, sizeof(mask)); secure_zero(scalar, sizeof(scalar));
  secure_zero(first, sizeof(first)); secure_zero(second, sizeof(second));
  secure_zero(encoded, sizeof(encoded)); secure_zero(commitment, sizeof(commitment));
  return ok;
}

bool ringct_decode_amount(RingCtAmountEncoding encoding,
                          const uint8_t amount_key[32], const uint8_t *wire,
                          size_t wire_size, const uint8_t commitment[32],
                          uint64_t *out_amount, uint8_t out_mask[32]) {
  uint8_t mask[32] = {}, scalar[32] = {}, first[32] = {}, second[32] = {};
  uint8_t expected[32] = {};
  uint64_t amount = 0;
  bool ok = wire != nullptr && commitment != nullptr && out_amount != nullptr &&
      out_mask != nullptr && encoding_size(encoding) != 0 &&
      wire_size == encoding_size(encoding) && reduced(amount_key);
  if (ok && encoding == RingCtAmountEncoding::Compact) {
    ok = ringct_commitment_mask(amount_key, mask) && amount_factor(amount_key, first);
    for (size_t i = 0; i < 8; ++i) scalar[i] = wire[i] ^ first[i];
  } else if (ok) {
    ok = reduced(wire) && reduced(wire + 32) &&
         cryptonote_hash_to_scalar(amount_key, 32, first) &&
         cryptonote_hash_to_scalar(first, 32, second);
    if (ok) {
      ed25519_scalar_mulsub(mask, kOne, first, wire);
      ed25519_scalar_mulsub(scalar, kOne, second, wire + 32);
      for (size_t i = 8; i < 32; ++i) ok = (scalar[i] == 0) && ok;
    }
  }
  if (ok) {
    for (size_t i = 0; i < 8; ++i) amount |= static_cast<uint64_t>(scalar[i]) << (8 * i);
    ok = ringct_commitment(mask, amount, expected) &&
         crypto_constant_time_equal(expected, commitment, 32);
  }
  if (out_amount != nullptr) *out_amount = ok ? amount : 0;
  if (out_mask != nullptr) { memset(out_mask, 0, 32); if (ok) memcpy(out_mask, mask, 32); }
  secure_zero(mask, sizeof(mask)); secure_zero(scalar, sizeof(scalar));
  secure_zero(first, sizeof(first)); secure_zero(second, sizeof(second));
  secure_zero(expected, sizeof(expected)); secure_zero(&amount, sizeof(amount));
  return ok;
}

namespace {
struct AmountVector {
  RingCtAmountEncoding encoding;
  uint64_t amount;
  const char *key;
  const char *mask;
  const char *wire;
  const char *commitment;
};
const AmountVector kVectors[] = {
#include "src/generated/RingCtAmountVectors.inc"
};

bool decode_hex(const char *text, uint8_t *out, size_t size) {
  if (strlen(text) != size * 2) return false;
  for (size_t i = 0; i < size; ++i) {
    unsigned value = 0;
    for (size_t j = 0; j < 2; ++j) {
      const char ch = text[2*i+j];
      if (ch >= '0' && ch <= '9') value = value * 16 + ch - '0';
      else if (ch >= 'a' && ch <= 'f') value = value * 16 + ch - 'a' + 10;
      else return false;
    }
    out[i] = static_cast<uint8_t>(value);
  }
  return true;
}
bool all_zero(const uint8_t *bytes, size_t size) {
  uint8_t value = 0;
  for (size_t i = 0; i < size; ++i) value |= bytes[i];
  return value == 0;
}
}  // namespace

bool run_ringct_amount_self_tests() {
  bool passed = true;
  uint8_t key[32], mask[32], expected[32], expected_wire[64], wire[64];
  uint8_t commitment[32], recovered_mask[32];
  uint64_t recovered = 0;
  for (const AmountVector &vector : kVectors) {
    const size_t size = encoding_size(vector.encoding);
    if (!decode_hex(vector.key, key, 32) || !decode_hex(vector.mask, mask, 32) ||
        !decode_hex(vector.commitment, expected, 32) ||
        !decode_hex(vector.wire, expected_wire, size)) return false;
    const bool encoded = ringct_encode_amount(vector.encoding, key, vector.amount,
                                              mask, wire, size, commitment);
    passed = encoded && crypto_constant_time_equal(wire, expected_wire, size) &&
             crypto_constant_time_equal(commitment, expected, 32) && passed;
    // Decode the independent fixture, not the bytes produced by the encoder.
    passed = ringct_decode_amount(vector.encoding, key, expected_wire, size,
                                  expected, &recovered, recovered_mask) &&
             recovered == vector.amount &&
             crypto_constant_time_equal(recovered_mask, mask, 32) && passed;
    expected_wire[0] ^= 1;
    passed = !ringct_decode_amount(vector.encoding, key, expected_wire, size,
                                   expected, &recovered, recovered_mask) &&
             recovered == 0 && all_zero(recovered_mask, 32) && passed;
    expected_wire[0] ^= 1;
    expected[0] ^= 1;
    passed = !ringct_decode_amount(vector.encoding, key, expected_wire, size,
                                   expected, &recovered, recovered_mask) && passed;
    expected[0] ^= 1;
    key[0] ^= 1;
    passed = !ringct_decode_amount(vector.encoding, key, expected_wire, size,
                                   expected, &recovered, recovered_mask) && passed;
    key[0] ^= 1;
    for (size_t length = 0; length < size; ++length) {
      passed = !ringct_decode_amount(vector.encoding, key, expected_wire, length,
                                     expected, &recovered, recovered_mask) && passed;
    }
    passed = !ringct_decode_amount(vector.encoding, key, expected_wire, size + 1,
                                   expected, &recovered, recovered_mask) && passed;
  }
  // Noncanonical scalar encodings must not be silently reduced on input.
  memset(mask, 0xff, sizeof(mask));
  passed = !ringct_commitment(mask, 1, commitment) && all_zero(commitment, 32) && passed;
  passed = !ringct_encode_amount(RingCtAmountEncoding::Legacy, key, 1, mask,
                                 wire, 64, commitment) && all_zero(wire, 64) && passed;
  passed = !ringct_encode_amount(static_cast<RingCtAmountEncoding>(255), key, 1,
                                 mask, wire, 8, commitment) && passed;
  passed = !ringct_commitment_mask(nullptr, mask) && all_zero(mask, 32) && passed;
  passed = !ringct_decode_amount(RingCtAmountEncoding::Compact, nullptr,
                                 expected_wire, 8, expected, &recovered, recovered_mask) &&
           recovered == 0 && all_zero(recovered_mask, 32) && passed;
  // Legacy decoded amounts above uint64 must fail before commitment checking.
  uint8_t high_amount[32] = {}, first[32], second[32];
  high_amount[8] = 1;
  passed = cryptonote_hash_to_scalar(key, 32, first) &&
           cryptonote_hash_to_scalar(first, 32, second) && passed;
  memcpy(wire, first, 32); // zero mask encoded with shared scalar
  ed25519_scalar_muladd(wire + 32, kOne, high_amount, second);
  passed = !ringct_decode_amount(RingCtAmountEncoding::Legacy, key, wire, 64,
                                 expected, &recovered, recovered_mask) && passed;
  secure_zero(key, sizeof(key)); secure_zero(mask, sizeof(mask));
  secure_zero(wire, sizeof(wire)); secure_zero(recovered_mask, sizeof(recovered_mask));
  secure_zero(high_amount, sizeof(high_amount)); secure_zero(first, sizeof(first));
  secure_zero(second, sizeof(second)); secure_zero(&recovered, sizeof(recovered));
  return passed;
}

}  // namespace hexwallet
