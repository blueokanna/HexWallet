#include "TezosTransaction.h"
#include "Blake2b.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "base58.h"
#include <stdio.h>
#include <string.h>
#include "src/generated/TezosVectorsTest.inc"

namespace hexwallet {
namespace {
class Reader {
 public:
  Reader(const uint8_t *data, size_t size) : data_(data), size_(size) {}
  bool bytes(uint8_t *out, size_t count) {
    if (count > size_ - offset_) return false;
    memcpy(out, data_ + offset_, count); offset_ += count; return true;
  }
  bool byte(uint8_t *out) { return bytes(out, 1); }
  bool natural(uint64_t *out) {
    *out = 0;
    // Zarith unsigned N, minimally encoded, bounded to int64 for mutez/counters.
    for (unsigned i = 0; i < 9; ++i) {
      uint8_t b = 0;
      if (!byte(&b)) return false;
      *out |= uint64_t(b & 127U) << (7U * i);
      if (!(b & 128U)) return i == 0 || b != 0;
    }
    return false;
  }
  bool done() const { return offset_ == size_; }
 private:
  const uint8_t *data_; size_t size_, offset_ = 0;
};
bool nonzero(const uint8_t *bytes, size_t size) {
  uint8_t result = 0;
  for (size_t i = 0; i < size; ++i) result |= bytes[i];
  return result != 0;
}
bool encode(const uint8_t *prefix, size_t prefix_size, const uint8_t *bytes,
            size_t size, char *out, size_t capacity) {
  uint8_t payload[40] = {}, checksum[32] = {};
  if (prefix_size + size + 4 > sizeof(payload)) return false;
  memcpy(payload, prefix, prefix_size); memcpy(payload + prefix_size, bytes, size);
  if (!crypto_double_sha256(payload, prefix_size + size, checksum)) return false;
  memcpy(payload + prefix_size + size, checksum, 4);
  return b58enc(out, &capacity, payload, prefix_size + size + 4);
}
bool account(const uint8_t encoded[21], char out[37]) {
  static const uint8_t prefixes[4][3] = {{6,161,159}, {6,161,161}, {6,161,164}, {6,161,166}};
  return encoded[0] < 4 && encode(prefixes[encoded[0]], 3, encoded + 1, 20, out, 37);
}
bool add(uint64_t *total, uint64_t value) {
  if (value > static_cast<uint64_t>(INT64_MAX) - *total) return false;
  *total += value; return true;
}
bool same_review(const TezosReview &a, const TezosReview &b) {
  if (a.operation_count != b.operation_count || a.total != b.total ||
      a.total_fee != b.total_fee || a.total_storage_limit != b.total_storage_limit ||
      memcmp(a.source, b.source, sizeof(a.source)) ||
      memcmp(a.public_key, b.public_key, sizeof(a.public_key)) ||
      memcmp(a.branch, b.branch, sizeof(a.branch))) return false;
  for (size_t i = 0; i < kTezosMaxOperations; ++i) {
    const auto &x = a.operations[i]; const auto &y = b.operations[i];
    if (x.reveal != y.reveal || x.fee != y.fee || x.counter != y.counter ||
        x.gas_limit != y.gas_limit || x.storage_limit != y.storage_limit ||
        x.amount != y.amount || memcmp(x.recipient, y.recipient, sizeof(x.recipient))) return false;
  }
  return true;
}
TezosError parse(const uint8_t *raw, size_t size, const uint8_t owner[32], TezosTransaction *out) {
  Reader r(raw, size);
  uint8_t branch[32] = {}, source[21] = {}, expected[21] = {};
  auto &v = out->review;
  const uint8_t branch_prefix[2] = {1,52}, key_prefix[4] = {13,15,37,217};
  if (!r.bytes(branch, 32) || !nonzero(branch, 32)) return TezosError::Malformed;
  if (!crypto_blake2b(owner, 32, expected + 1, 20) || !account(expected, v.source) ||
      !encode(key_prefix, 4, owner, 32, v.public_key, sizeof(v.public_key)) ||
      !encode(branch_prefix, 2, branch, 32, v.branch, sizeof(v.branch))) return TezosError::CryptoFailure;
  uint64_t previous_counter = 0;
  while (!r.done()) {
    if (v.operation_count == kTezosMaxOperations) return TezosError::Unsupported;
    auto &op = v.operations[v.operation_count];
    uint8_t tag = 0;
    if (!r.byte(&tag)) return TezosError::Malformed;
    if (tag != 107 && tag != 108) return TezosError::Unsupported;
    if (tag == 107 && v.operation_count != 0) return TezosError::Unsupported;
    op.reveal = tag == 107;
    if (!r.bytes(source, 21)) return TezosError::Malformed;
    if (memcmp(source, expected, 21)) return TezosError::WrongWallet;
    if (!r.natural(&op.fee) || !r.natural(&op.counter) || !r.natural(&op.gas_limit) ||
        !r.natural(&op.storage_limit) || !op.counter ||
        (v.operation_count && op.counter != previous_counter + 1)) return TezosError::Malformed;
    previous_counter = op.counter;
    // Device policy caps; they do not assert the current baker fee or constants.
    if (op.fee > 1000000 || !op.gas_limit || op.gas_limit > 1040000 ||
        op.storage_limit > 60000 || !add(&v.total_fee, op.fee) || v.total_fee > 1000000 ||
        !add(&v.total_storage_limit, op.storage_limit)) return TezosError::FeePolicy;
    if (op.reveal) {
      uint8_t curve = 0, key[32] = {}, proof = 0;
      if (!r.byte(&curve) || curve != 0) return TezosError::Unsupported;
      if (!r.bytes(key, 32)) return TezosError::Malformed;
      if (memcmp(key, owner, 32)) return TezosError::WrongWallet;
      // Modern reveal contains an optional BLS proof field, absent for Ed25519.
      if (!r.byte(&proof) || proof != 0) return TezosError::Unsupported;
      memcpy(op.recipient, v.source, sizeof(op.recipient));
    } else {
      uint8_t destination_kind = 0, destination[21] = {}, parameters = 0;
      if (!r.natural(&op.amount) || !op.amount || !add(&v.total, op.amount)) return TezosError::InvalidAmount;
      if (!r.byte(&destination_kind) || destination_kind != 0) return TezosError::Unsupported;
      if (!r.bytes(destination, 21) || !nonzero(destination + 1, 20)) return TezosError::Malformed;
      if (!account(destination, op.recipient)) return TezosError::Unsupported;
      if (!r.byte(&parameters) || parameters != 0) return TezosError::Unsupported;
    }
    ++v.operation_count;
  }
  if (!v.operation_count) return TezosError::Malformed;
  Blake2bState hash;
  const uint8_t watermark = 3;
  if (!blake2b_init(&hash, 32, nullptr, 0)) return TezosError::CryptoFailure;
  blake2b_update(&hash, &watermark, 1); blake2b_update(&hash, raw, size);
  if (!blake2b_final(&hash, out->signing_hash)) return TezosError::CryptoFailure;
  memcpy(out->transaction, raw, size); out->transaction_size = static_cast<uint16_t>(size);
  return TezosError::Ok;
}
}
bool tezos_derivation_path(uint32_t account_index, uint32_t change, uint32_t index, uint32_t out[5]) {
  if (!out || account_index >= kHardenedOffset || change >= kHardenedOffset || index >= kHardenedOffset) return false;
  out[0] = 44 | kHardenedOffset; out[1] = 1729 | kHardenedOffset;
  out[2] = account_index | kHardenedOffset; out[3] = change | kHardenedOffset; out[4] = index | kHardenedOffset;
  return true;
}
bool tezos_derive_key(const uint8_t seed[kSeedSize], uint32_t index, uint8_t out[32]) {
  uint32_t path[5];
  if (!out) return false;
  if (seed && tezos_derivation_path(0, 0, index, path) && slip10_ed25519_derive(seed, kSeedSize, path, 5, out)) return true;
  secure_zero(out, 32); return false;
}
bool tezos_format_amount(uint64_t mutez, char *out, size_t capacity) {
  if (!out || !capacity) return false;
  const int n = snprintf(out, capacity, "%llu.%06llu XTZ",
      static_cast<unsigned long long>(mutez / 1000000), static_cast<unsigned long long>(mutez % 1000000));
  return n > 0 && static_cast<size_t>(n) < capacity;
}
TezosError tezos_review_transaction(const uint8_t *raw, size_t size, const uint8_t owner[32], TezosTransaction *out) {
  if (!out) return TezosError::InvalidArgument;
  memset(out, 0, sizeof(*out));
  if (!raw || !owner || !size || size > kTezosMaxTransaction) return TezosError::InvalidArgument;
  const auto error = parse(raw, size, owner, out);
  if (error != TezosError::Ok) secure_zero(out, sizeof(*out));
  return error;
}
TezosError tezos_sign_transaction(const TezosTransaction &tx, const uint8_t seed[kSeedSize],
                                 uint8_t *out, size_t *in_out_size) {
  if (!in_out_size) return TezosError::InvalidArgument;
  const size_t capacity = *in_out_size; *in_out_size = 0;
  if (!seed || !out) return TezosError::InvalidArgument;
  uint8_t child[32] = {}, owner[32] = {}, signature[64] = {};
  TezosTransaction verified = {};
  auto error = TezosError::CryptoFailure;
  if (tezos_derive_key(seed, tx.address_index, child) && ed25519_public_key(child, owner)) {
    error = tezos_review_transaction(tx.transaction, tx.transaction_size, owner, &verified);
    if (error == TezosError::Ok && (!same_review(tx.review, verified.review) ||
        memcmp(tx.signing_hash, verified.signing_hash, 32))) error = TezosError::Malformed;
    if (error == TezosError::Ok) {
      if (capacity < verified.transaction_size + 64U) error = TezosError::BufferTooSmall;
      else if (!ed25519_sign(child, verified.signing_hash, 32, signature) ||
               !ed25519_verify(owner, verified.signing_hash, 32, signature)) error = TezosError::CryptoFailure;
      else {
        memcpy(out, verified.transaction, verified.transaction_size);
        memcpy(out + verified.transaction_size, signature, 64);
        *in_out_size = verified.transaction_size + 64;
      }
    }
  }
  secure_zero(child, sizeof(child)); secure_zero(signature, sizeof(signature)); secure_zero(&verified, sizeof(verified));
  return error;
}
bool run_tezos_self_tests() {
  uint8_t child[32] = {}, owner[32] = {};
  TezosTransaction tx = {};
  uint8_t signed_tx[kTezosMaxSigned] = {}; size_t size = sizeof(signed_tx);
  const bool ok = tezos_derive_key(kTezosTestSeed, 0, child) && ed25519_public_key(child, owner) &&
      tezos_review_transaction(kTezosTestRequest, sizeof(kTezosTestRequest), owner, &tx) == TezosError::Ok &&
      memcmp(tx.signing_hash, kTezosTestHash, 32) == 0 && strcmp(tx.review.source, kTezosTestSigner) == 0 &&
      tezos_sign_transaction(tx, kTezosTestSeed, signed_tx, &size) == TezosError::Ok &&
      size == sizeof(kTezosTestSigned) && memcmp(signed_tx, kTezosTestSigned, size) == 0;
  secure_zero(child, sizeof(child)); secure_zero(&tx, sizeof(tx)); secure_zero(signed_tx, sizeof(signed_tx));
  return ok;
}
}
