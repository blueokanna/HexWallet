#include "SuiTransaction.h"
#include <stdio.h>
#include <string.h>
#include "ChainCommon.h"
#include "CryptoExtended.h"

namespace hexwallet {
namespace {
class Reader {
 public:
  Reader(const uint8_t *data, size_t size) : data_(data), size_(size) {}
  const uint8_t *take(size_t n) {
    if (n > size_ - pos_) { ok_ = false; return nullptr; }
    const uint8_t *p = data_ + pos_; pos_ += n; return p;
  }
  bool literal(uint8_t b) { const uint8_t *p = take(1); return p && *p == b; }
  uint64_t u64() { const uint8_t *p = take(8); return p ? chain_read_u64_le(p) : 0; }
  bool index(uint8_t kind, uint16_t index) {
    const uint8_t *p = take(3);
    return p && p[0] == kind && p[1] == (index & 255) && p[2] == (index >> 8);
  }
  bool done() const { return ok_ && pos_ == size_; }
 private:
  const uint8_t *data_; size_t size_, pos_ = 0; bool ok_ = true;
};
bool nonzero(const uint8_t *p, size_t n) {
  uint8_t v = 0; for (size_t i = 0; i < n; ++i) v |= p[i]; return v != 0;
}
bool hex_address(const uint8_t *p, char *out, size_t capacity) {
  if (capacity < 67) return false;
  out[0] = '0'; out[1] = 'x'; chain_hex(p, 32, out + 2, capacity - 2); return true;
}
}

bool sui_address(const uint8_t public_key[32], char *out, size_t capacity) {
  if (!public_key || !out || capacity < 67) return false;
  uint8_t tagged[33] = {}, hash[32] = {};
  memcpy(tagged + 1, public_key, 32);
  return crypto_blake2b(tagged, sizeof(tagged), hash, sizeof(hash)) &&
         hex_address(hash, out, capacity);
}

ChainError sui_review_payload(const uint8_t *data, size_t size,
                              const char *sender, ChainReview *review,
                              uint8_t digest[32]) {
  if (!data || !sender || !review || !digest || !size || size > kChainMaxPayload)
    return ChainError::InvalidArgument;
  memset(review, 0, sizeof(*review));
  Reader r(data, size);
  // TransactionData::V1, TransactionKind::ProgrammableTransaction, two pure
  // inputs. All enum/length values in this admitted subset are <128: exact
  // byte comparisons also reject non-minimal ULEB128 encodings.
  if (!r.literal(0) || !r.literal(0) || !r.literal(2) ||
      !r.literal(0) || !r.literal(8)) return ChainError::Unsupported;
  const uint64_t amount = r.u64();
  if (!r.literal(0) || !r.literal(32)) return ChainError::Malformed;
  const uint8_t *recipient = r.take(32);
  if (!recipient) return ChainError::Malformed;
  // SplitCoins { GasCoin, [Input(0)] }.
  if (!r.literal(2) || !r.literal(2) || !r.literal(0) || !r.literal(1) ||
      !r.index(1, 0)) return ChainError::Unsupported;
  // TransferObjects { [NestedResult(0,0)], Input(1) }.
  if (!r.literal(1) || !r.literal(1) || !r.index(3, 0) ||
      !r.literal(0) || !r.literal(0) || !r.index(1, 1))
    return ChainError::Unsupported;
  const uint8_t *owner = r.take(32);
  const uint8_t *count = r.take(1);
  if (!owner || !count || *count == 0 || *count > 8) return ChainError::Unsupported;
  const uint8_t *ids[8] = {};
  for (size_t i = 0; i < *count; ++i) {
    ids[i] = r.take(32);
    const uint64_t version = r.u64();
    if (!ids[i] || !nonzero(ids[i], 32) || version == 0 || !r.literal(32))
      return ChainError::Malformed;
    const uint8_t *hash = r.take(32);
    if (!hash || !nonzero(hash, 32)) return ChainError::Malformed;
    for (size_t j = 0; j < i; ++j)
      if (!memcmp(ids[j], ids[i], 32)) return ChainError::Malformed;
  }
  const uint8_t *gas_owner = r.take(32);
  if (!gas_owner || memcmp(owner, gas_owner, 32)) return ChainError::WrongWallet;
  const uint64_t price = r.u64(), budget = r.u64();
  const uint8_t *expiration = r.take(1);
  if (!expiration || *expiration > 1) return ChainError::Unsupported;
  const uint64_t epoch = *expiration ? r.u64() : 0;
  if (!r.done()) return ChainError::Malformed;
  if (!amount || !nonzero(recipient, 32)) return ChainError::InvalidAmount;
  if (!price || !budget || budget > 100000000000ULL || amount > UINT64_MAX - budget)
    return ChainError::FeePolicy;
  hex_address(owner, review->sender, sizeof(review->sender));
  if (strcmp(review->sender, sender)) return ChainError::WrongWallet;
  hex_address(recipient, review->recipient, sizeof(review->recipient));
  strcpy(review->symbol, "SUI");
  if (!chain_format_units(amount, 9, "SUI", review->amount, sizeof(review->amount)) ||
      !chain_format_units(budget, 9, "SUI MAX", review->fee, sizeof(review->fee)))
    return ChainError::BufferTooSmall;
  snprintf(review->extra, sizeof(review->extra),
           "GAS PRICE %llu MIST\nGAS OBJECTS %u\nEXPIRY %s%llu\nNO CHAIN ID IN BCS",
           static_cast<unsigned long long>(price), static_cast<unsigned>(*count),
           *expiration ? "EPOCH " : "NONE / ", static_cast<unsigned long long>(epoch));
  uint8_t intent[kChainMaxPayload + 3] = {}; // Intent(TransactionData,V0,Sui)
  memcpy(intent + 3, data, size);
  const bool ok = crypto_blake2b(intent, size + 3, digest, 32);
  secure_zero(intent, sizeof(intent));
  return ok ? ChainError::Ok : ChainError::CryptoFailure;
}

ChainError sui_sign_payload(const uint8_t *data, size_t size,
                            const uint8_t private_key[32], uint8_t *out,
                            size_t *in_out_size) {
  if (!in_out_size) return ChainError::InvalidArgument;
  const size_t capacity = *in_out_size; *in_out_size = 0;
  if (!private_key || !out) return ChainError::InvalidArgument;
  if (capacity < 97) return ChainError::BufferTooSmall;
  uint8_t pub[32] = {}, digest[32] = {}, signature[64] = {};
  char sender[67] = {}; ChainReview review = {};
  if (!ed25519_public_key(private_key, pub) || !sui_address(pub, sender, sizeof(sender)))
    return ChainError::CryptoFailure;
  const ChainError error = sui_review_payload(data, size, sender, &review, digest);
  if (error != ChainError::Ok) return error;
  if (!ed25519_sign(private_key, digest, 32, signature)) return ChainError::CryptoFailure;
  out[0] = 0; memcpy(out + 1, signature, 64); memcpy(out + 65, pub, 32);
  *in_out_size = 97; secure_zero(signature, sizeof(signature));
  return ChainError::Ok;
}
bool run_sui_self_tests() {
#include "src/generated/SuiVectorsTest.inc"
  uint8_t seed[64], child[32] = {}, pub[32] = {}, digest[32] = {}, signed_tx[97] = {};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(i);
  const uint32_t path[] = {0x8000002c, 0x80000310, 0x80000000, 0x80000000, 0x80000000};
  ChainReview review = {}; char address[67] = {}; size_t size = sizeof(signed_tx);
  const bool ok = slip10_ed25519_derive(seed, sizeof(seed), path, 5, child) &&
      ed25519_public_key(child, pub) && sui_address(pub, address, sizeof(address)) &&
      !strcmp(address, kAddress) &&
      sui_review_payload(kPayload, sizeof(kPayload), address, &review, digest) == ChainError::Ok &&
      !memcmp(digest, kExpectedDigest, 32) && !strcmp(review.recipient, kRecipient) &&
      !strcmp(review.amount, kAmount) && !strcmp(review.fee, kFee) &&
      sui_sign_payload(kPayload, sizeof(kPayload), child, signed_tx, &size) == ChainError::Ok &&
      size == sizeof(kExpectedSigned) && !memcmp(signed_tx, kExpectedSigned, size);
  secure_zero(child, sizeof(child)); secure_zero(seed, sizeof(seed)); return ok;
}
} // namespace hexwallet
