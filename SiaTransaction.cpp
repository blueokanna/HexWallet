#include "SiaTransaction.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoExtended.h"

namespace hexwallet {
namespace {

struct Request {
  const uint8_t *parent_id;
  const uint8_t *input_value;
  const uint8_t *parent_address;
  uint8_t count;
  const uint8_t *outputs;
  const uint8_t *fee;
};

bool zero(const uint8_t *p, size_t size) {
  uint8_t all = 0;
  for (size_t i = 0; i < size; ++i) all |= p[i];
  return all == 0;
}

bool add128(uint8_t out[16], const uint8_t in[16]) {
  unsigned carry = 0;
  for (size_t i = 0; i < 16; ++i) {
    const unsigned sum = unsigned(out[i]) + in[i] + carry;
    out[i] = static_cast<uint8_t>(sum);
    carry = sum >> 8;
  }
  return carry == 0;
}

bool format_currency(const uint8_t le[16], char *out, size_t size) {
  uint8_t be[16];
  for (size_t i = 0; i < 16; ++i) be[i] = le[15 - i];
  return chain_format_units128(be, 24, "SC", out, size);
}

bool format_address(const uint8_t address[32], char *out, size_t size) {
  if (size < 77) return false;
  uint8_t encoded[38], checksum[32];
  if (!crypto_blake2b(address, 32, checksum, 32)) return false;
  memcpy(encoded, address, 32);
  memcpy(encoded + 32, checksum, 6);
  chain_hex(encoded, sizeof(encoded), out, size);
  return true;
}

bool parse_address(const char *text, uint8_t out[32]) {
  if (!text || strlen(text) != 76) return false;
  uint8_t encoded[38], checksum[32];
  size_t size = 0;
  if (!chain_parse_hex(text, encoded, sizeof(encoded), &size) || size != 38 ||
      !crypto_blake2b(encoded, 32, checksum, 32) ||
      !chain_constant_time_equal(checksum, encoded + 32, 6)) return false;
  memcpy(out, encoded, 32);
  return true;
}

ChainError parse(const uint8_t *payload, size_t size, const uint8_t owner[32],
                 Request *r) {
  if (!payload || !r) return ChainError::InvalidArgument;
  if (size < 85 || memcmp(payload, "SCV2", 4)) return ChainError::Malformed;
  r->parent_id = payload + 4;
  r->input_value = payload + 36;
  r->parent_address = payload + 52;
  r->count = payload[84];
  if (r->count < 1 || r->count > 2 || size != 101 + size_t(r->count) * 48)
    return ChainError::Malformed;
  r->outputs = payload + 85;
  r->fee = r->outputs + size_t(r->count) * 48;
  if (zero(r->parent_id, 32) || zero(r->input_value, 16))
    return ChainError::Malformed;
  if (!chain_constant_time_equal(owner, r->parent_address, 32))
    return ChainError::WrongWallet;
  if (r->count == 2 &&
      !chain_constant_time_equal(owner, r->outputs + 48 + 16, 32))
    return ChainError::WrongWallet;
  uint8_t total[16];
  memcpy(total, r->fee, 16);
  if (zero(total, 16)) return ChainError::FeePolicy;
  // Cap fee at 10 SC = 10^25 hastings.
  static const uint8_t kFeeCap[16] = {
      0x00,0x00,0x00,0x4a,0x48,0x01,0x14,0x16,0x95,0x45,0x08,0,0,0,0,0};
  for (size_t i = 16; i-- > 0;) {
    if (r->fee[i] > kFeeCap[i]) return ChainError::FeePolicy;
    if (r->fee[i] < kFeeCap[i]) break;
  }
  for (size_t i = 0; i < r->count; ++i) {
    const uint8_t *output = r->outputs + 48 * i;
    if (zero(output, 16) || zero(output + 16, 32)) return ChainError::InvalidAmount;
    if (!add128(total, output)) return ChainError::InvalidAmount;
  }
  if (!chain_constant_time_equal(total, r->input_value, 16))
    return ChainError::InvalidAmount;
  return ChainError::Ok;
}

bool hash_request(const Request &r, uint8_t digest[32]) {
  uint8_t bytes[256] = {};
  size_t n = 0;
  static const char kDomain[] = "sia/sig/input|";
  memcpy(bytes, kDomain, sizeof(kDomain) - 1); n += sizeof(kDomain) - 1;
  bytes[n++] = 2;
  chain_write_u64_le(1, bytes + n); n += 8;
  memcpy(bytes + n, r.parent_id, 32); n += 32;
  chain_write_u64_le(r.count, bytes + n); n += 8;
  memcpy(bytes + n, r.outputs, 48 * r.count); n += 48 * r.count;
  n += 7 * 8;
  bytes[n++] = 0;
  memcpy(bytes + n, r.fee, 16); n += 16;
  return crypto_blake2b(bytes, n, digest, 32);
}

}  // namespace

WalletError sia_address(const uint8_t public_key[32], char *out, size_t out_size) {
  if (!public_key || !out) return WalletError::InvalidArgument;
  if (out_size < 77) return WalletError::BufferTooSmall;
  uint8_t preimage[46] = {}, address[32];
  memcpy(preimage, "sia/address|", 12);
  preimage[12] = 1; preimage[13] = 3;
  memcpy(preimage + 14, public_key, 32);
  return crypto_blake2b(preimage, sizeof(preimage), address, 32) &&
                 format_address(address, out, out_size)
             ? WalletError::Ok : WalletError::CryptoFailure;
}

ChainError sia_review_payload(const uint8_t *payload, size_t size,
                              const char *sender, ChainReview *review,
                              uint8_t digest[32]) {
  if (!review || !digest) return ChainError::InvalidArgument;
  memset(review, 0, sizeof(*review));
  uint8_t owner[32];
  if (!parse_address(sender, owner)) return ChainError::WrongWallet;
  Request r = {};
  ChainError error = parse(payload, size, owner, &r);
  if (error != ChainError::Ok) return error;
  if (!hash_request(r, digest)) return ChainError::CryptoFailure;
  strcpy(review->symbol, "SC");
  snprintf(review->sender, sizeof(review->sender), "%s", sender);
  if (!format_address(r.outputs + 16, review->recipient, sizeof(review->recipient)) ||
      !format_currency(r.outputs, review->amount, sizeof(review->amount)) ||
      !format_currency(r.fee, review->fee, sizeof(review->fee)))
    return ChainError::BufferTooSmall;
  char change[64] = "0.0 SC";
  if (r.count == 2 && !format_currency(r.outputs + 48, change, sizeof(change)))
    return ChainError::BufferTooSmall;
  snprintf(review->extra, sizeof(review->extra),
           "V2 native transfer\nCHANGE %s\nNode must verify input value, policy, "
           "proof and maturity. No network ID in signature.", change);
  return ChainError::Ok;
}

ChainError sia_sign_payload(const uint8_t *payload, size_t size,
                            const uint8_t private_key[32], uint8_t *out,
                            size_t *in_out_size) {
  if (!in_out_size) return ChainError::InvalidArgument;
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  if (out) secure_zero(out, capacity);
  if (!private_key || !out) return ChainError::InvalidArgument;
  if (capacity < 64) return ChainError::BufferTooSmall;
  uint8_t public_key[32], digest[32];
  char sender[77];
  ChainReview review = {};
  if (!ed25519_public_key(private_key, public_key) ||
      sia_address(public_key, sender, sizeof(sender)) != WalletError::Ok)
    return ChainError::CryptoFailure;
  ChainError error = sia_review_payload(payload, size, sender, &review, digest);
  if (error == ChainError::Ok && !ed25519_sign(private_key, digest, 32, out))
    error = ChainError::CryptoFailure;
  if (error == ChainError::Ok) *in_out_size = 64;
  else secure_zero(out, capacity);
  secure_zero(digest, sizeof(digest));
  return error;
}

bool run_sia_self_tests() {
  // @siafoundation/sdk 0.5.0, addressFromSpendPolicy({type:'pk', policy:...}).
  uint8_t public_key[32]; memset(public_key, 0x11, sizeof(public_key));
  char address[77];
  return sia_address(public_key, address, sizeof(address)) == WalletError::Ok &&
      !strcmp(address, "f9584b512ef330ce1a227c77685c2dd2177c4710e8cb976501daef308b3b2c4143863cb2902f");
}

}  // namespace hexwallet
