#include "QuantusTransaction.h"
#include "QuantusAccount.h"
#include "WalletAltAddresses.h"
#include "Blake2b.h"
#include "ChainCommon.h"
#include "MlDsa87.h"
#include "RandomSource.h"
#include "SensitiveValue.h"
#include <cstdio>
#include <cstring>
#include <memory>

namespace hexwallet {
namespace {
const uint8_t genesis[32] = {0xfb, 0x54, 0x87, 0xc0, 0xbe, 0x6a, 0xe4, 0xad, 0xe2, 0xd4, 0x1d,
                             0x16, 0xe5, 0x04, 0x65, 0x12, 0x98, 0x61, 0x63, 0x6c, 0x2b, 0x8d,
                             0x61, 0xfa, 0x94, 0xd7, 0xa1, 0x96, 0x31, 0x62, 0x6f, 0xba};
constexpr uint8_t signing_context[] = "QUANTUS_EXTRINSIC";
struct Transfer {
  size_t call_size, extra_size;
  uint8_t amount[16], tip[16];
  uint64_t nonce;
  unsigned period, phase;
  const uint8_t *checkpoint;
};

// Canonical SCALE Compact<u128>, expanded to big endian for the amount formatter.
bool compact(const uint8_t *&p, const uint8_t *end, uint8_t (&out)[16]) {
  if (p == end)
    return false;
  const uint8_t first = *p, mode = first & 3;
  memset(out, 0, 16);
  if (mode == 3) {
    const size_t n = 4 + (first >> 2);
    if (n > 16 || size_t(end - p) < n + 1 || !p[n] || (n == 4 && p[4] < 64))
      return false;
    ++p;
    for (size_t i = 0; i < n; ++i)
      out[15 - i] = *p++;
    return true;
  }
  const size_t n = size_t(1) << mode;
  if (size_t(end - p) < n)
    return false;
  uint32_t v = 0;
  for (size_t i = 0; i < n; ++i)
    v |= uint32_t(*p++) << (8 * i);
  v >>= 2;
  if ((mode == 1 && v < 64) || (mode == 2 && v < 16384))
    return false;
  for (size_t i = 0; i < n; ++i)
    out[15 - i] = uint8_t(v >> (8 * i));
  return true;
}

ChainError parse(const uint8_t *data, size_t size, Transfer &tx) {
  if (!data || size < 35 + 1 + 4 + 73 || size > 180)
    return ChainError::Malformed;
  if (data[0] != 2 || (data[1] != 0 && data[1] != 3) || data[2])
    return ChainError::Unsupported;
  const uint8_t *p = data + 35, *end = data + size;
  if (!compact(p, end, tx.amount) || chain_u128_is_zero(tx.amount) || p == end)
    return ChainError::InvalidAmount;
  tx.call_size = size_t(p - data);
  tx.period = tx.phase = 0;
  uint16_t era = *p++;
  if (era) {
    if (p == end)
      return ChainError::Malformed;
    era |= uint16_t(*p++) << 8;
    tx.period = 2u << (era & 15);
    const unsigned factor = tx.period > 4096 ? tx.period / 4096 : 1;
    tx.phase = (era >> 4) * factor;
    if (tx.period < 4 || tx.phase >= tx.period)
      return ChainError::Malformed;
  }
  uint8_t nonce[16], zero[8]{};
  if (!compact(p, end, nonce) || memcmp(nonce, zero, 8) || !compact(p, end, tx.tip) || p == end || *p++)
    return ChainError::Malformed;
  tx.nonce = 0;
  for (size_t i = 8; i < 16; ++i)
    tx.nonce = (tx.nonce << 8) | nonce[i];
  tx.extra_size = size_t(p - data) - tx.call_size;
  if (end - p != 73 || p[72])
    return ChainError::Malformed;
  if (chain_read_u32_le(p) != 153 || chain_read_u32_le(p + 4) != 6)
    return ChainError::RuntimeMismatch;
  if (memcmp(p + 8, genesis, 32))
    return ChainError::WrongNetwork;
  tx.checkpoint = p + 40;
  if (!tx.period && memcmp(tx.checkpoint, genesis, 32))
    return ChainError::WrongNetwork;
  return ChainError::Ok;
}
} // namespace

ChainError quantus_review(const uint8_t *payload, size_t size, const char *sender, ChainReview &r,
                          uint8_t digest[32]) {
  Transfer tx{};
  const auto error = parse(payload, size, tx);
  if (error != ChainError::Ok)
    return error;
  char tip[58], checkpoint[65];
  if (!chain_copy_text(r.symbol, sizeof(r.symbol), "QTC") ||
      !chain_copy_text(r.sender, sizeof(r.sender), sender) ||
      address_ss58(189, payload + 3, r.recipient, sizeof(r.recipient)) != WalletError::Ok ||
      !chain_format_units128(tx.amount, 12, "QTC", r.amount, sizeof(r.amount)) ||
      !chain_format_units128(tx.tip, 12, "QTC", tip, sizeof(tip)) ||
      !blake2b_keyed_hash(nullptr, 0, payload, size, digest, 32))
    return ChainError::InvalidArgument;
  if (snprintf(r.fee, sizeof(r.fee), "Tip %s", tip) >= int(sizeof(r.fee)))
    return ChainError::InvalidAmount;
  chain_hex(tx.checkpoint, 32, checkpoint, sizeof(checkpoint));
  const char *kind = payload[1] == 3 ? "Keep account alive" : "Allow account removal";
  char era[64] = "Immortal";
  if (tx.period)
    snprintf(era, sizeof(era), "Period %u blocks, phase %u", tx.period, tx.phase);
  snprintf(r.extra, sizeof(r.extra), "%s | %s | Nonce %llu\nCheckpoint %s\nBase fee is set by the network.",
           kind, era, (unsigned long long)tx.nonce, checkpoint);
  return ChainError::Ok;
}

ChainError quantus_sign(const uint8_t *payload, size_t size, const uint8_t seed[32], uint8_t *out,
                        size_t *capacity) {
  if (!seed || !out || !capacity)
    return ChainError::InvalidArgument;
  const size_t available = *capacity;
  *capacity = 0;
  Transfer tx{};
  auto error = parse(payload, size, tx);
  if (error != ChainError::Ok)
    return error;
  const size_t body = 35 + kMlDsa87SignatureSize + kMlDsa87PublicKeySize + tx.extra_size + tx.call_size;
  if (available < body + 2 || body >= 16384)
    return ChainError::BufferTooSmall;
  using Key = SensitiveValue<uint8_t[kMlDsa87SecretKeySize]>;
  std::unique_ptr<Key> secret(new (std::nothrow) Key);
  if (!secret)
    return ChainError::CryptoFailure;
  uint8_t *signature = out + 37, *pk = signature + kMlDsa87SignatureSize;
  SensitiveValue<uint8_t[32]> random;
  uint8_t formatted[2 + sizeof(signing_context) - 1 + 180] = {0, sizeof(signing_context) - 1};
  memcpy(formatted + 2, signing_context, sizeof(signing_context) - 1);
  memcpy(formatted + 1 + sizeof(signing_context), payload, size);
  const size_t signed_size = 1 + sizeof(signing_context) + size;
  if (!ml_dsa_87_keypair_from_seed(seed, pk, secret->get()) || !random_fill_checked(random.get(), 32) ||
      !ml_dsa_87_sign(secret->get(), formatted, signed_size, random.get(), signature) ||
      !ml_dsa_87_verify(pk, formatted, signed_size, signature)) {
    secure_zero(out, body + 2);
    return ChainError::CryptoFailure;
  }
  uint16_t len = uint16_t((body << 2) | 1);
  out[0] = uint8_t(len);
  out[1] = uint8_t(len >> 8);
  out[2] = 0x84;
  out[3] = 0;
  quantus_account_id(pk, out + 4);
  out[36] = 0; // DilithiumSignatureScheme::MlDsa87
  uint8_t *extra = pk + kMlDsa87PublicKeySize;
  memcpy(extra, payload + tx.call_size, tx.extra_size);
  memcpy(extra + tx.extra_size, payload, tx.call_size);
  *capacity = body + 2;
  return ChainError::Ok;
}
} // namespace hexwallet
