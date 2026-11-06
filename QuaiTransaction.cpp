#include "QuaiTransaction.h"

#include <stdio.h>
#include <string.h>
#include "ChainCommon.h"
#include "CryptoPrimitives.h"
#include "WalletAddresses.h"
#include "src/EcdsaCurve.h"

namespace hexwallet {
namespace {
// The admitted message is small enough that every length has a one-byte
// canonical encoding. Tags must occur exactly once and in signing order.
struct Reader {
  const uint8_t *data;
  size_t left;

  bool take(uint8_t byte) {
    if (!left || *data != byte) return false;
    ++data;
    --left;
    return true;
  }
  bool bytes(uint8_t tag, size_t min, size_t max, const uint8_t **out, size_t *len) {
    if (!take(tag) || left == 0) return false;
    *len = *data++;
    --left;
    if (*len < min || *len > max || *len > left) return false;
    *out = data;
    data += *len;
    left -= *len;
    return true;
  }
  bool number(uint8_t tag, uint64_t *out) {
    if (!take(tag)) return false;
    *out = 0;
    for (unsigned shift = 0; left && shift <= 63; shift += 7) {
      const uint8_t byte = *data++;
      --left;
      if (shift == 63 && byte > 1) return false;
      *out |= static_cast<uint64_t>(byte & 127) << shift;
      if (byte < 128) return shift == 0 || byte != 0;
    }
    return false;
  }
};
}

bool quai_cyprus1_address(const char *address) {
  return address && strlen(address) == 42 && strncmp(address, "0x00", 4) == 0 &&
         address[4] >= '0' && address[4] <= '7';
}

ChainError quai_review_payload(const uint8_t *payload, size_t size, const char *sender,
                               ChainReview *review, uint8_t digest[32]) {
  if (!payload || !review || !digest || !sender) return ChainError::InvalidArgument;
  Reader reader{payload, size};
  const uint8_t *to, *value, *price;
  size_t to_size, value_size, price_size;
  uint64_t nonce, gas;
  if (!reader.take(0x08) || !reader.take(0) ||
      !reader.bytes(0x12, 20, 20, &to, &to_size) || !reader.number(0x18, &nonce) ||
      !reader.bytes(0x22, 1, 32, &value, &value_size) || value[0] == 0 ||
      !reader.number(0x28, &gas) || gas < 21000 ||
      !reader.take(0x32) || !reader.take(0) ||
      !reader.take(0x3a) || !reader.take(1) || !reader.take(9) ||
      !reader.bytes(0x42, 1, 8, &price, &price_size) || price[0] == 0 ||
      !reader.take(0x4a) || !reader.take(0) || reader.left) return ChainError::Malformed;
  if (to[0] != 0 || to[1] >= 128 || !quai_cyprus1_address(sender))
    return ChainError::WrongNetwork;
  static constexpr uint8_t kZeroAddress[20]{};
  if (!memcmp(to, kZeroAddress, sizeof(kZeroAddress))) return ChainError::Unsupported;
  uint64_t gas_price = 0;
  for (size_t i = 0; i < price_size; ++i) gas_price = (gas_price << 8) | price[i];
  if (gas > UINT64_MAX / gas_price) return ChainError::FeePolicy;
  if (!chain_format_units_bytes(value, value_size, 18, "QUAI", review->amount, sizeof(review->amount)) ||
      !chain_format_units(gas * gas_price, 18, "QUAI", review->fee, sizeof(review->fee)))
    return ChainError::InvalidAmount;
  chain_copy_text(review->symbol, sizeof(review->symbol), "QUAI");
  chain_copy_text(review->sender, sizeof(review->sender), sender);
  memcpy(review->recipient, "0x", 2);
  chain_hex(to, to_size, review->recipient + 2, sizeof(review->recipient) - 2);
  snprintf(review->extra, sizeof(review->extra),
           "CYPRUS-1 MAINNET\nNONCE %llu\nGAS LIMIT %llu\nGAS PRICE %llu WEI",
           (unsigned long long)nonce, (unsigned long long)gas, (unsigned long long)gas_price);
  return crypto_keccak256(payload, size, digest) ? ChainError::Ok : ChainError::CryptoFailure;
}

bool run_quai_self_tests() {
  // Cyprus-1 block 0xa7a0c1, transaction 0. Recovered from the on-chain r/s/v.
  uint8_t public_key[65], signature[64];
  size_t bytes;
  char sender[43];
  // SEC1 key recovered with the chain's v=1, r and s. Check its address
  // against the RPC sender and verify the signature over the device digest.
  if (!chain_parse_hex("04f3989dc9531ec5c54145ab29f70931c1d7acb45df0e51c7e83cafb6910c812e2639a00ef3c9ae5afca533b633486ff132bba27d746b52ed7601eab8bb53dbd96",
                       public_key, sizeof(public_key), &bytes) || bytes != sizeof(public_key) ||
      address_evm(public_key, sender, sizeof(sender)) != WalletError::Ok ||
      strcmp(sender, "0x0022646d0cbf8456e6f9f5a5dd6bbb9754ed30f1") ||
      !chain_parse_hex("6c626769932b5a1d6c0db939bac4a3bdef2a7da5854a4592766cbe3273245efa42566f73842f3a099a097c3409d5c63affe04484b5b0ad89c34183fcec26adda",
                       signature, sizeof(signature), &bytes) || bytes != sizeof(signature)) return false;
  uint8_t raw[80], digest[32], expected[32];
  size_t len, hash_size;
  ChainReview review{};
  if (!chain_parse_hex("08001214004894e7c041bac2a4575241c0ec96ddd37866e018cdda0322091900fc11c0f9a81d0828e0da0132003a010942061e76ec20d2ad4a00",
                       raw, sizeof(raw), &len) ||
      !chain_parse_hex("2bdd787191ccbcd525e05ce9e91244461f4086344e4a9fae4952f81d841cefc3", expected, 32, &hash_size) ||
      quai_review_payload(raw, len, sender, &review, digest) != ChainError::Ok ||
      memcmp(expected, digest, 32) || !ecdsa_verify_digest(EcdsaCurve::Secp256k1, public_key + 1, digest, signature) ||
      strcmp(review.recipient, "0x004894e7c041bac2a4575241c0ec96ddd37866e0") ||
      quai_review_payload(raw, len - 1, sender, &review, digest) == ChainError::Ok) return false;
  raw[len] = 0;
  if (quai_review_payload(raw, len + 1, sender, &review, digest) == ChainError::Ok) return false;
  raw[1] = 1; // External transaction.
  if (quai_review_payload(raw, len, sender, &review, digest) == ChainError::Ok) return false;
  raw[1] = 0;
  raw[5] |= 0x80; // Qi ledger.
  if (quai_review_payload(raw, len, sender, &review, digest) == ChainError::Ok) return false;
  memset(raw + 4, 0, 20);
  return quai_review_payload(raw, len, sender, &review, digest) != ChainError::Ok;
}
}
