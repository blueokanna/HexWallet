#include "PolkadotTransaction.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "WalletAltAddresses.h"

namespace hexwallet {
namespace {

constexpr uint8_t kPolkadotNetwork = 0;
constexpr uint8_t kKusamaNetwork = 2;
constexpr uint8_t kCallTransfer = 0;
constexpr uint8_t kCallTransferKeepAlive = 3;

const uint8_t kPolkadotGenesis[32] = {
    0x91, 0xb1, 0x71, 0xbb, 0x15, 0x8e, 0x2d, 0x38, 0x48, 0xfa, 0x23, 0xa9,
    0xf1, 0xc2, 0x51, 0x82, 0xfb, 0x8e, 0x20, 0x31, 0x3b, 0x2c, 0x1e, 0xb4,
    0x92, 0x19, 0xda, 0x7a, 0x70, 0xce, 0x90, 0xc3};
const uint8_t kKusamaGenesis[32] = {
    0xb0, 0xa8, 0xd4, 0x93, 0x28, 0x5c, 0x2d, 0xf7, 0x32, 0x90, 0xdf, 0xb7,
    0xe6, 0x1f, 0x87, 0x0f, 0x17, 0xb4, 0x18, 0x01, 0x19, 0x7a, 0x14, 0x9c,
    0xa9, 0x36, 0x54, 0x49, 0x9e, 0xa3, 0xda, 0xfe};

struct PolkadotRequest {
  uint8_t network;
  uint8_t call;
  uint8_t recipient[32];
  uint8_t amount_be[kChainUint128Size];
  uint32_t nonce;
  uint32_t spec_version;
  uint32_t transaction_version;
  uint8_t tip_be[kChainUint128Size];
  uint32_t era_period;
  uint64_t era_block;
  uint8_t genesis[32];
  uint8_t block_hash[32];
  // Polkadot/Kusama signed extensions end with `CheckMetadataHash`, whose
  // `AdditionalSigned` is `Option<[u8;32]>`. Disabled mode adds one 0x00 byte.
  bool metadata_hash_implicit;
};

// SCALE Era encoding. Immortal is the single byte 0x00. Mortal packs
// (period.trailing_zeros() - 1) | (phase / quantize_factor) << 4 into a
// little-endian u16, matching substrate's `impl Encode for Era`.
size_t encode_era(uint32_t period, uint64_t block, uint8_t out[2]) {
  if (period == 0) {
    out[0] = 0x00;
    return 1;
  }
  uint8_t log = 0;
  while ((static_cast<uint32_t>(1) << log) < period) ++log;
  const uint32_t quantize = (period >> 12) == 0 ? 1 : (period >> 12);
  const uint32_t phase = static_cast<uint32_t>(block % period) / quantize;
  const uint16_t encoded = static_cast<uint16_t>((log - 1) | (phase << 4));
  out[0] = static_cast<uint8_t>(encoded);
  out[1] = static_cast<uint8_t>(encoded >> 8);
  return 2;
}

bool valid_era(uint32_t period) {
  if (period == 0) return true;
  if (period < 4 || period > 65536) return false;
  return (period & (period - 1)) == 0;
}

const uint8_t *expected_genesis(uint8_t network) {
  if (network == kPolkadotNetwork) return kPolkadotGenesis;
  if (network == kKusamaNetwork) return kKusamaGenesis;
  return nullptr;
}

const char *network_symbol(uint8_t network) {
  return network == kKusamaNetwork ? "KSM" : "DOT";
}

uint8_t network_decimals(uint8_t network) {
  return network == kKusamaNetwork ? 12 : 10;
}

uint8_t family_network(ChainFamily family) {
  return family == ChainFamily::Kusama ? kKusamaNetwork : kPolkadotNetwork;
}

void write_u32_le(uint32_t value, uint8_t out[4]) {
  chain_write_u32_le(value, out);
}

bool compact_u64(uint64_t value, uint8_t *out, size_t capacity,
                 size_t *out_size) {
  size_t size = 0;
  if (value < 64) {
    size = 1;
    if (capacity < size) return false;
    out[0] = static_cast<uint8_t>(value << 2);
  } else if (value < (1ULL << 14)) {
    size = 2;
    if (capacity < size) return false;
    const uint16_t encoded = static_cast<uint16_t>((value << 2) | 1);
    out[0] = static_cast<uint8_t>(encoded);
    out[1] = static_cast<uint8_t>(encoded >> 8);
  } else if (value < (1ULL << 30)) {
    size = 4;
    if (capacity < size) return false;
    const uint32_t encoded = static_cast<uint32_t>((value << 2) | 2);
    out[0] = static_cast<uint8_t>(encoded);
    out[1] = static_cast<uint8_t>(encoded >> 8);
    out[2] = static_cast<uint8_t>(encoded >> 16);
    out[3] = static_cast<uint8_t>(encoded >> 24);
  } else {
    uint8_t little[8] = {};
    size_t bytes = 0;
    for (size_t index = 0; index < 8; ++index) {
      const uint8_t byte = static_cast<uint8_t>(value >> (8 * index));
      little[index] = byte;
      if (byte != 0) bytes = index + 1;
    }
    if (bytes > 8) return false;
    size = 1 + bytes;
    if (capacity < size) return false;
    // SCALE mode 3 stores (byte_length - 4) in the upper six bits; the
    // minimum payload length for this mode is four bytes.
    out[0] = static_cast<uint8_t>(((bytes - 4) << 2) | 3);
    memcpy(out + 1, little, bytes);
  }
  *out_size = size;
  return true;
}

bool compact_u128(const uint8_t be[kChainUint128Size], uint8_t *out,
                  size_t capacity, size_t *out_size) {
  const uint8_t *minimal = nullptr;
  size_t minimal_size = 0;
  chain_u128_minimal(be, &minimal, &minimal_size);
  if (minimal_size == 0) return compact_u64(0, out, capacity, out_size);
  if (minimal_size <= 8) {
    uint64_t value = 0;
    for (size_t index = 0; index < minimal_size; ++index) {
      value = (value << 8) | minimal[index];
    }
    return compact_u64(value, out, capacity, out_size);
  }
  if (minimal_size > 16) return false;
  size_t size = 1 + minimal_size;
  if (capacity < size) return false;
  out[0] = static_cast<uint8_t>(((minimal_size - 4) << 2) | 3);
  for (size_t index = 0; index < minimal_size; ++index) {
    out[1 + index] = minimal[minimal_size - 1 - index];
  }
  *out_size = size;
  return true;
}

ChainError parse_payload(ChainFamily family, const uint8_t *payload,
                         size_t size, PolkadotRequest *request) {
  if (payload == nullptr || request == nullptr) {
    return ChainError::InvalidArgument;
  }
  const bool v2 = size == kPolkadotPayloadSizeV2 &&
                  memcmp(payload, "DOT2", 4) == 0;
  const bool v1 = size == kPolkadotPayloadSize &&
                  memcmp(payload, "DOT1", 4) == 0;
  if (!v1 && !v2) {
    return size == kPolkadotPayloadSize || size == kPolkadotPayloadSizeV2
               ? ChainError::Malformed
               : ChainError::InvalidArgument;
  }
  size_t offset = 4;
  request->network = payload[offset++];
  request->call = payload[offset++];
  request->metadata_hash_implicit = v2;
  memcpy(request->recipient, payload + offset, 32);
  offset += 32;
  memcpy(request->amount_be, payload + offset, kChainUint128Size);
  offset += kChainUint128Size;
  request->nonce = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  request->spec_version = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  request->transaction_version = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  memset(request->tip_be, 0, sizeof(request->tip_be));
  request->era_period = 0;
  request->era_block = 0;
  if (v2) {
    memcpy(request->tip_be, payload + offset, kChainUint128Size);
    offset += kChainUint128Size;
    // era_period_log: 0 = immortal, 2..16 = log2(period); the next byte is
    // reserved and must be zero so the layout cannot be reinterpreted.
    const uint8_t era_log = payload[offset];
    const uint8_t reserved = payload[offset + 1];
    offset += 2;
    if (reserved != 0) return ChainError::Malformed;
    if (era_log == 0) {
      request->era_period = 0;
    } else if (era_log >= 2 && era_log <= 16) {
      request->era_period = static_cast<uint32_t>(1) << era_log;
    } else {
      return ChainError::Malformed;
    }
    request->era_block = chain_read_u64_le(payload + offset);
    offset += 8;
  }
  memcpy(request->genesis, payload + offset, 32);
  offset += 32;
  memcpy(request->block_hash, payload + offset, 32);
  offset += 32;
  if (offset != size) return ChainError::Malformed;

  if (request->network != family_network(family)) {
    return ChainError::WrongNetwork;
  }
  const uint8_t *genesis = expected_genesis(request->network);
  if (genesis == nullptr ||
      !chain_constant_time_equal(request->genesis, genesis, 32)) {
    return ChainError::WrongNetwork;
  }
  if (!valid_era(request->era_period)) return ChainError::Malformed;
  if (request->era_period == 0) {
    // Immortal: the era hash must be the genesis hash.
    if (!chain_constant_time_equal(request->block_hash, request->genesis, 32)) {
      return ChainError::Malformed;
    }
  } else {
    uint8_t zero[32] = {};
    if (chain_constant_time_equal(request->block_hash, zero, 32) ||
        chain_constant_time_equal(request->block_hash, request->genesis, 32)) {
      return ChainError::Malformed;
    }
  }
  if (request->call != kCallTransfer &&
      request->call != kCallTransferKeepAlive) {
    return ChainError::Unsupported;
  }
  if (chain_u128_is_zero(request->amount_be)) {
    return ChainError::InvalidAmount;
  }
  if (request->spec_version == 0 || request->transaction_version == 0) {
    return ChainError::Malformed;
  }
  uint8_t zero[32] = {};
  if (chain_constant_time_equal(request->recipient, zero, 32)) {
    return ChainError::InvalidAmount;
  }
  return ChainError::Ok;
}

bool build_call(const PolkadotRequest &request, uint8_t *out,
                size_t capacity, size_t *out_size) {
  uint8_t amount[32] = {};
  size_t amount_size = 0;
  if (!compact_u128(request.amount_be, amount, sizeof(amount), &amount_size)) {
    return false;
  }
  const size_t total = 2 + 1 + 32 + amount_size;
  if (total > capacity) return false;
  out[0] = 0x05;  // pallet 5: balances
  out[1] = request.call;
  out[2] = 0x00;  // MultiAddress::Id
  memcpy(out + 3, request.recipient, 32);
  memcpy(out + 35, amount, amount_size);
  *out_size = total;
  return true;
}

bool build_signing_payload(const PolkadotRequest &request,
                           uint8_t *out, size_t capacity, size_t *out_size) {
  uint8_t call[96] = {};
  size_t call_size = 0;
  if (!build_call(request, call, sizeof(call), &call_size)) return false;
  uint8_t nonce[16] = {};
  size_t nonce_size = 0;
  if (!compact_u64(request.nonce, nonce, sizeof(nonce), &nonce_size)) {
    return false;
  }
  uint8_t tip[16] = {};
  size_t tip_size = 0;
  if (!compact_u128(request.tip_be, tip, sizeof(tip), &tip_size)) {
    return false;
  }
  uint8_t era[2] = {};
  const size_t era_size = encode_era(request.era_period, request.era_block, era);
  const size_t extra = request.metadata_hash_implicit ? 1 : 0;
  const size_t total = call_size + era_size + nonce_size + tip_size + 4 + 4 +
                       32 + 32 + extra;
  if (total > capacity) return false;
  size_t offset = 0;
  memcpy(out + offset, call, call_size);
  offset += call_size;
  memcpy(out + offset, era, era_size);
  offset += era_size;
  memcpy(out + offset, nonce, nonce_size);
  offset += nonce_size;
  memcpy(out + offset, tip, tip_size);
  offset += tip_size;
  uint8_t le4[4] = {};
  write_u32_le(request.spec_version, le4);
  memcpy(out + offset, le4, 4);
  offset += 4;
  write_u32_le(request.transaction_version, le4);
  memcpy(out + offset, le4, 4);
  offset += 4;
  memcpy(out + offset, request.genesis, 32);
  offset += 32;
  memcpy(out + offset, request.block_hash, 32);
  offset += 32;
  if (request.metadata_hash_implicit) out[offset++] = 0x00;
  *out_size = offset;
  return true;
}

ChainError sign_with_seed(ChainFamily family, const uint8_t *payload,
                          size_t size, const uint8_t seed[32], uint8_t *out,
                          size_t *in_out_size) {
  if (seed == nullptr || out == nullptr || in_out_size == nullptr) {
    return ChainError::InvalidArgument;
  }
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  PolkadotRequest request;
  ChainError error = parse_payload(family, payload, size, &request);
  if (error != ChainError::Ok) return error;

  uint8_t call[96] = {};
  size_t call_size = 0;
  uint8_t signing[256] = {};
  size_t signing_size = 0;
  if (!build_call(request, call, sizeof(call), &call_size) ||
      !build_signing_payload(request, signing, sizeof(signing), &signing_size)) {
    return ChainError::BufferTooSmall;
  }
  uint8_t digest[32] = {};
  if (!crypto_blake2b(signing, signing_size, digest, sizeof(digest))) {
    secure_zero(signing, sizeof(signing));
    return ChainError::CryptoFailure;
  }
  uint8_t public_key[32] = {};
  uint8_t signature[64] = {};
  bool ok = ed25519_public_key(seed, public_key) &&
            // Substrate hashes only signing payloads longer than 256 bytes.
            ed25519_sign(seed, signing_size > 256 ? digest : signing,
                         signing_size > 256 ? sizeof(digest) : signing_size,
                         signature);
  if (!ok) {
    secure_zero(signing, sizeof(signing));
    secure_zero(signature, sizeof(signature));
    return ChainError::CryptoFailure;
  }

  uint8_t body[256] = {};
  size_t offset = 0;
  body[offset++] = 0x84;  // signed, extrinsic version 4
  body[offset++] = 0x00;  // MultiAddress::Id
  memcpy(body + offset, public_key, 32);
  offset += 32;
  body[offset++] = 0x00;  // MultiSignature::Ed25519
  memcpy(body + offset, signature, 64);
  offset += 64;
  uint8_t era[2] = {};
  const size_t era_size = encode_era(request.era_period, request.era_block, era);
  memcpy(body + offset, era, era_size);
  offset += era_size;
  uint8_t nonce[16] = {};
  size_t nonce_size = 0;
  if (!compact_u64(request.nonce, nonce, sizeof(nonce), &nonce_size)) {
    error = ChainError::BufferTooSmall;
  } else {
    memcpy(body + offset, nonce, nonce_size);
    offset += nonce_size;
    uint8_t tip[16] = {};
    size_t tip_size = 0;
    if (!compact_u128(request.tip_be, tip, sizeof(tip), &tip_size)) {
      error = ChainError::BufferTooSmall;
    } else {
      memcpy(body + offset, tip, tip_size);
      offset += tip_size;
      memcpy(body + offset, call, call_size);
      offset += call_size;
    }
  }

  uint8_t length[8] = {};
  size_t length_size = 0;
  if (error == ChainError::Ok &&
      !compact_u64(offset, length, sizeof(length), &length_size)) {
    error = ChainError::BufferTooSmall;
  }
  if (error == ChainError::Ok) {
    if (capacity < length_size + offset) {
      error = ChainError::BufferTooSmall;
    } else {
      memcpy(out, length, length_size);
      memcpy(out + length_size, body, offset);
      *in_out_size = length_size + offset;
    }
  }
  secure_zero(signing, sizeof(signing));
  secure_zero(signature, sizeof(signature));
  secure_zero(body, sizeof(body));
  return error;
}

}  // namespace

ChainError polkadot_review_payload(ChainFamily family, const uint8_t *payload,
                                   size_t size, const char *sender,
                                   ChainReview *review, uint8_t digest[32]) {
  if (sender == nullptr || review == nullptr || digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  memset(review, 0, sizeof(*review));
  PolkadotRequest request;
  ChainError error = parse_payload(family, payload, size, &request);
  if (error != ChainError::Ok) return error;
  uint8_t signing[256] = {};
  size_t signing_size = 0;
  if (!build_signing_payload(request, signing, sizeof(signing), &signing_size)) {
    return ChainError::BufferTooSmall;
  }
  if (!crypto_blake2b(signing, signing_size, digest, 32)) {
    secure_zero(signing, sizeof(signing));
    return ChainError::CryptoFailure;
  }
  secure_zero(signing, sizeof(signing));

  char recipient[64] = {};
  if (address_ss58(request.network, request.recipient, recipient,
                   sizeof(recipient)) != WalletError::Ok) {
    return ChainError::CryptoFailure;
  }
  strncpy(review->symbol, network_symbol(request.network),
          sizeof(review->symbol) - 1);
  strncpy(review->sender, sender, sizeof(review->sender) - 1);
  strncpy(review->recipient, recipient, sizeof(review->recipient) - 1);
  if (!chain_format_units128(request.amount_be, network_decimals(request.network),
                             network_symbol(request.network), review->amount,
                             sizeof(review->amount))) {
    return ChainError::BufferTooSmall;
  }
  char tip[64] = {};
  if (!chain_format_units128(request.tip_be, network_decimals(request.network),
                             network_symbol(request.network), tip,
                             sizeof(tip))) {
    return ChainError::BufferTooSmall;
  }
  if (chain_u128_is_zero(request.tip_be)) {
    strncpy(review->fee, "TIP 0", sizeof(review->fee) - 1);
  } else {
    snprintf(review->fee, sizeof(review->fee), "TIP %s", tip);
  }
  const char *ext = request.metadata_hash_implicit
                        ? "\nEXT CHECKMETADATAHASH DISABLED"
                        : "";
  if (request.era_period == 0) {
    snprintf(review->extra, sizeof(review->extra),
             "CALL %s\nNONCE %lu\nSPEC VERSION %lu\nTX VERSION %lu\nERA IMMORTAL%s",
             request.call == kCallTransferKeepAlive ? "transferKeepAlive"
                                                    : "transfer",
             static_cast<unsigned long>(request.nonce),
             static_cast<unsigned long>(request.spec_version),
             static_cast<unsigned long>(request.transaction_version), ext);
  } else {
    snprintf(review->extra, sizeof(review->extra),
             "CALL %s\nNONCE %lu\nSPEC VERSION %lu\nTX VERSION %lu\n"
             "ERA MORTAL %u\nBLOCK %llu%s",
             request.call == kCallTransferKeepAlive ? "transferKeepAlive"
                                                    : "transfer",
             static_cast<unsigned long>(request.nonce),
             static_cast<unsigned long>(request.spec_version),
             static_cast<unsigned long>(request.transaction_version),
             static_cast<unsigned>(request.era_period),
             static_cast<unsigned long long>(request.era_block), ext);
  }
  return ChainError::Ok;
}

ChainError polkadot_sign_payload(ChainFamily family, const uint8_t *payload,
                                 size_t size, const uint8_t seed[32],
                                 uint8_t *out, size_t *in_out_size) {
  return sign_with_seed(family, payload, size, seed, out, in_out_size);
}

bool run_polkadot_self_tests() {
  // SCALE Era vectors cross-checked against scalecodec's Era.process_encode.
  {
    struct EraVector {
      uint32_t period;
      uint64_t block;
      uint8_t encoded[2];
      size_t size;
    };
    static const EraVector kEras[] = {
        {0, 0, {0x00, 0x00}, 1},
        {64, 12345678, {0xe5, 0x00}, 2},
        {4, 100, {0x01, 0x00}, 2},
        {4096, 999999, {0xfb, 0x23}, 2},
        {65536, 123456789, {0x1f, 0xcd}, 2},
    };
    for (size_t i = 0; i < sizeof(kEras) / sizeof(kEras[0]); ++i) {
      uint8_t encoded[2] = {};
      const size_t size = encode_era(kEras[i].period, kEras[i].block, encoded);
      if (size != kEras[i].size ||
          memcmp(encoded, kEras[i].encoded, kEras[i].size) != 0) {
        ::printf("polkadot era %u/%llu mismatch\n",
                 static_cast<unsigned>(kEras[i].period),
                 static_cast<unsigned long long>(kEras[i].block));
        return false;
      }
    }
  }
  static const uint8_t kSeed[32] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  static const uint8_t kPayload[kPolkadotPayloadSize] = {
      'D', 'O', 'T', '1', 0x00, 0x03,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x01, 0x1f, 0x71, 0xfb, 0x04, 0xcb,
      0x07, 0x00, 0x00, 0x00,
      0xc8, 0x55, 0x0f, 0x00,
      0x1a, 0x00, 0x00, 0x00,
      0x91, 0xb1, 0x71, 0xbb, 0x15, 0x8e, 0x2d, 0x38,
      0x48, 0xfa, 0x23, 0xa9, 0xf1, 0xc2, 0x51, 0x82,
      0xfb, 0x8e, 0x20, 0x31, 0x3b, 0x2c, 0x1e, 0xb4,
      0x92, 0x19, 0xda, 0x7a, 0x70, 0xce, 0x90, 0xc3,
      0x91, 0xb1, 0x71, 0xbb, 0x15, 0x8e, 0x2d, 0x38,
      0x48, 0xfa, 0x23, 0xa9, 0xf1, 0xc2, 0x51, 0x82,
      0xfb, 0x8e, 0x20, 0x31, 0x3b, 0x2c, 0x1e, 0xb4,
      0x92, 0x19, 0xda, 0x7a, 0x70, 0xce, 0x90, 0xc3};
#include "src/generated/PolkadotVectorsTest.inc"
  ChainReview review;
  uint8_t digest[32] = {};
  const ChainError review_error = polkadot_review_payload(
      ChainFamily::Polkadot, kPayload, sizeof(kPayload),
      "15kypVvwBLVS1eFtT9tb2ZS2HLXLbsy5iZaddcFzRrm5izi", &review, digest);
  bool ok = review_error == ChainError::Ok &&
            chain_constant_time_equal(digest, kExpectedDigest, 32) &&
            !strcmp(review.recipient,
                    "1PNtGSJ2VC7gGhEPqTbtj9mBEUcwM3SDL71WSqtRzSVxDkG") &&
            !strcmp(review.amount, "123.4567890123 DOT") &&
            !strcmp(review.extra,
                    "CALL transferKeepAlive\nNONCE 7\nSPEC VERSION 1005000\n"
                    "TX VERSION 26\nERA IMMORTAL");
  uint8_t signed_extrinsic[kPolkadotMaxSigned] = {};
  size_t signed_size = sizeof(signed_extrinsic);
  const ChainError sign_error = polkadot_sign_payload(
      ChainFamily::Polkadot, kPayload, sizeof(kPayload), kSeed,
      signed_extrinsic, &signed_size);
  ok = ok && sign_error == ChainError::Ok &&
       signed_size == sizeof(kExpectedSigned) &&
       chain_constant_time_equal(signed_extrinsic, kExpectedSigned,
                                 sizeof(kExpectedSigned));
  uint8_t wrong_network[sizeof(kPayload)] = {};
  memcpy(wrong_network, kPayload, sizeof(kPayload));
  wrong_network[4] = 0x02;
  const ChainError wrong_error = polkadot_review_payload(
      ChainFamily::Polkadot, wrong_network, sizeof(wrong_network),
      "15kypVvwBLVS1eFtT9tb2ZS2HLXLbsy5iZaddcFzRrm5izi", &review, digest);
  ok = ok && wrong_error == ChainError::WrongNetwork;

  // DOT2: mortal era (period 64 at block 12345678) plus the trailing
  // CheckMetadataHash implicit byte. Digest reproduced independently with
  // BLAKE2b-256 over call||era||nonce||tip||spec||txver||genesis||block||00.
  static const uint8_t kPayloadV2[kPolkadotPayloadSizeV2] = {
      'D', 'O', 'T', '2', 0x00, 0x03,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x01, 0x1f, 0x71, 0xfb, 0x04, 0xcb,
      0x07, 0x00, 0x00, 0x00,
      0xc8, 0x55, 0x0f, 0x00,
      0x1a, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x06, 0x00,
      0x4e, 0x61, 0xbc, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x91, 0xb1, 0x71, 0xbb, 0x15, 0x8e, 0x2d, 0x38,
      0x48, 0xfa, 0x23, 0xa9, 0xf1, 0xc2, 0x51, 0x82,
      0xfb, 0x8e, 0x20, 0x31, 0x3b, 0x2c, 0x1e, 0xb4,
      0x92, 0x19, 0xda, 0x7a, 0x70, 0xce, 0x90, 0xc3,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
  static const uint8_t kExpectedDigestV2[32] = {
      0x0b, 0xa4, 0x99, 0x8c, 0x53, 0x80, 0xac, 0x1b, 0x14, 0xe6, 0xf5,
      0x27, 0x71, 0x72, 0x97, 0xc4, 0x58, 0x2d, 0x97, 0x65, 0xab, 0x19,
      0xc6, 0x3e, 0x9f, 0x53, 0xcd, 0x9f, 0x3a, 0x9b, 0xc7, 0x4f};
  ChainReview review_v2;
  uint8_t digest_v2[32] = {};
  const ChainError review_v2_error = polkadot_review_payload(
      ChainFamily::Polkadot, kPayloadV2, sizeof(kPayloadV2),
      "15kypVvwBLVS1eFtT9tb2ZS2HLXLbsy5iZaddcFzRrm5izi", &review_v2, digest_v2);
  ok = ok && review_v2_error == ChainError::Ok &&
       chain_constant_time_equal(digest_v2, kExpectedDigestV2, 32) &&
       !strcmp(review_v2.extra,
               "CALL transferKeepAlive\nNONCE 7\nSPEC VERSION 1005000\n"
               "TX VERSION 26\nERA MORTAL 64\nBLOCK 12345678\n"
               "EXT CHECKMETADATAHASH DISABLED");
#if defined(HEXWALLET_HOST_TEST)
  if (!ok) {
    ::printf("polkadot v2 review err=%d\n", static_cast<int>(review_v2_error));
    ::printf("polkadot v2 digest=%02x%02x%02x%02x%02x%02x\n", digest_v2[0],
             digest_v2[1], digest_v2[2], digest_v2[3], digest_v2[4],
             digest_v2[5]);
    ::printf("polkadot v2 extra=[%s]\n", review_v2.extra);
  }
#endif
  uint8_t signed_v2[kPolkadotMaxSigned] = {};
  size_t signed_v2_size = sizeof(signed_v2);
  const ChainError sign_v2_error = polkadot_sign_payload(
      ChainFamily::Polkadot, kPayloadV2, sizeof(kPayloadV2), kSeed, signed_v2,
      &signed_v2_size);
  ok = ok && sign_v2_error == ChainError::Ok &&
       signed_v2_size == 147 &&
       signed_v2[2] == 0x84 && signed_v2[3] == 0x00;
  (void)signed_v2;

  // Era period must be a power of two in [4, 65536].
  uint8_t bad_era[sizeof(kPayloadV2)] = {};
  memcpy(bad_era, kPayloadV2, sizeof(kPayloadV2));
  bad_era[4 + 1 + 1 + 32 + 16 + 4 + 4 + 4 + 16] = 0x01;
  const ChainError bad_era_error = polkadot_review_payload(
      ChainFamily::Polkadot, bad_era, sizeof(bad_era),
      "15kypVvwBLVS1eFtT9tb2ZS2HLXLbsy5iZaddcFzRrm5izi", &review, digest);
  ok = ok && bad_era_error == ChainError::Malformed;

  return ok;
}

}  // namespace hexwallet
