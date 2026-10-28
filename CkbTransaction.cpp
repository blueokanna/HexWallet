#include "CkbTransaction.h"

#include <stdio.h>
#include <string.h>

#include "Blake2b.h"
#include "ChainCommon.h"
#include "WalletAltAddresses.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

constexpr uint8_t kCkbCodeHash[32] = {
    0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2,
    0x18, 0x8b, 0x23, 0xf1, 0xb9, 0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65,
    0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8};
// Mainnet SECP256K1/blake160 dep group out point.
constexpr uint8_t kCkbDepTxHash[32] = {
    0x71, 0xa7, 0xba, 0x8f, 0xc9, 0x63, 0x49, 0xfe, 0xa0, 0xed, 0x3a,
    0x5c, 0x47, 0x99, 0x2e, 0x3b, 0x40, 0x84, 0xb0, 0x31, 0xa4, 0x22,
    0x64, 0xa0, 0x18, 0xe0, 0x07, 0x2e, 0x81, 0x72, 0xe4, 0x6c};
constexpr uint8_t kCkbPersonal[16] = {
    'c', 'k', 'b', '-', 'd', 'e', 'f', 'a', 'u', 'l', 't', '-', 'h', 'a', 's', 'h'};
constexpr uint64_t kCkbShannonPerUnit = 100000000ULL;
constexpr uint64_t kCkbMinimumCell = 61ULL * kCkbShannonPerUnit;
constexpr uint64_t kCkbMaximumFee = 10ULL * kCkbShannonPerUnit;
constexpr size_t kCkbMaxRawSize = 512;

struct CkbInput {
  uint8_t tx_hash[32];
  uint32_t index;
  uint64_t since;
  uint64_t capacity;
};

struct CkbOutput {
  uint64_t capacity;
  uint8_t lock_args[20];
};

struct CkbParsed {
  CkbInput input;
  CkbOutput outputs[2];
  uint8_t output_count;
};

bool ckb_hash(const uint8_t *data, size_t size, uint8_t digest[32]) {
  Blake2bState state;
  if (!blake2b_init_personal(&state, 32, kCkbPersonal)) return false;
  blake2b_update(&state, data, size);
  return blake2b_final(&state, digest);
}

bool ckb_lock_args(const uint8_t public_key[33], uint8_t args[20]) {
  uint8_t hash[32];
  if (!ckb_hash(public_key, 33, hash)) return false;
  memcpy(args, hash, 20);
  secure_zero(hash, sizeof(hash));
  return true;
}

void put_u32(uint8_t *out, uint32_t value) {
  out[0] = static_cast<uint8_t>(value);
  out[1] = static_cast<uint8_t>(value >> 8);
  out[2] = static_cast<uint8_t>(value >> 16);
  out[3] = static_cast<uint8_t>(value >> 24);
}

void put_u64(uint8_t *out, uint64_t value) {
  for (uint8_t i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>(value >> (8 * i));
}

bool parse_payload(const uint8_t *payload, size_t size, CkbParsed *out) {
  if (payload == nullptr || out == nullptr || size < 86 ||
      size > kCkbPayloadSize || memcmp(payload, "CKB1", 4) != 0) {
    return false;
  }
  size_t offset = 4;
  if (payload[offset++] != 1) return false;
  CkbParsed parsed = {};
  memcpy(parsed.input.tx_hash, payload + offset, 32);
  offset += 32;
  parsed.input.index = static_cast<uint32_t>(
      payload[offset] | (payload[offset + 1] << 8) |
      (payload[offset + 2] << 16) | (payload[offset + 3] << 24));
  offset += 4;
  parsed.input.since = chain_read_u64_le(payload + offset);
  offset += 8;
  parsed.input.capacity = chain_read_u64_le(payload + offset);
  offset += 8;
  const uint8_t output_count = payload[offset++];
  if (output_count == 0 || output_count > 2) return false;
  if (size != 86 + (output_count - 1) * 28) return false;
  parsed.output_count = output_count;
  for (uint8_t i = 0; i < output_count; ++i) {
    parsed.outputs[i].capacity = chain_read_u64_le(payload + offset);
    offset += 8;
    memcpy(parsed.outputs[i].lock_args, payload + offset, 20);
    offset += 20;
  }
  *out = parsed;
  return true;
}

size_t write_script(const uint8_t args[20], uint8_t *out) {
  // table { code_hash, hash_type, args }
  put_u32(out, 73);
  put_u32(out + 4, 16);
  put_u32(out + 8, 48);
  put_u32(out + 12, 49);
  memcpy(out + 16, kCkbCodeHash, 32);
  out[48] = 1;  // hash_type = type
  put_u32(out + 49, 20);
  memcpy(out + 53, args, 20);
  return 73;
}

size_t write_output(uint64_t capacity, const uint8_t args[20], uint8_t *out) {
  // table { capacity, lock, type: None }
  put_u32(out, 97);
  put_u32(out + 4, 16);
  put_u32(out + 8, 24);
  put_u32(out + 12, 97);
  put_u64(out + 16, capacity);
  write_script(args, out + 24);
  return 97;
}

size_t write_input(const CkbInput &input, uint8_t *out) {
  put_u64(out, input.since);
  memcpy(out + 8, input.tx_hash, 32);
  put_u32(out + 40, input.index);
  return 44;
}

size_t write_cell_dep(uint8_t *out) {
  memcpy(out, kCkbDepTxHash, 32);
  put_u32(out + 32, 0);
  out[36] = 1;  // dep_group
  return 37;
}

size_t write_raw_transaction(const CkbParsed &tx, uint8_t *out,
                             size_t capacity) {
  const size_t outputs_size = 4 + 4 * tx.output_count + 97 * tx.output_count;
  const size_t data_size = 4 + 8 * tx.output_count;
  const size_t full_size = 125 + outputs_size + data_size;
  if (full_size > capacity) return 0;

  put_u32(out, static_cast<uint32_t>(full_size));
  put_u32(out + 4, 28);
  put_u32(out + 8, 32);
  put_u32(out + 12, 73);
  put_u32(out + 16, 77);
  put_u32(out + 20, 125);
  put_u32(out + 24, static_cast<uint32_t>(125 + outputs_size));
  size_t offset = 28;
  put_u32(out + offset, 0);  // version
  offset += 4;
  put_u32(out + offset, 1);  // cell_deps: one dep group
  offset += 4;
  offset += write_cell_dep(out + offset);
  put_u32(out + offset, 0);  // header_deps
  offset += 4;
  put_u32(out + offset, 1);  // inputs
  offset += 4;
  offset += write_input(tx.input, out + offset);

  put_u32(out + offset, static_cast<uint32_t>(outputs_size));
  offset += 4;
  size_t item_offset = 4 + 4 * tx.output_count;
  for (uint8_t i = 0; i < tx.output_count; ++i) {
    put_u32(out + offset, static_cast<uint32_t>(item_offset));
    offset += 4;
    item_offset += 97;
  }
  for (uint8_t i = 0; i < tx.output_count; ++i) {
    offset += write_output(tx.outputs[i].capacity, tx.outputs[i].lock_args,
                           out + offset);
  }

  put_u32(out + offset, static_cast<uint32_t>(data_size));
  offset += 4;
  item_offset = 4 + 4 * tx.output_count;
  for (uint8_t i = 0; i < tx.output_count; ++i) {
    put_u32(out + offset, static_cast<uint32_t>(item_offset));
    offset += 4;
    item_offset += 4;
  }
  for (uint8_t i = 0; i < tx.output_count; ++i) {
    put_u32(out + offset, 0);  // empty output data
    offset += 4;
  }
  return offset;
}

size_t write_witness_args(uint8_t *out) {
  // table { lock: Some(Bytes(65 x 0)), input_type: None, output_type: None }
  put_u32(out, 85);
  put_u32(out + 4, 16);
  put_u32(out + 8, 85);
  put_u32(out + 12, 85);
  put_u32(out + 16, 65);
  memset(out + 20, 0, 65);
  return 85;
}

bool build_digest(const CkbParsed &tx, uint8_t digest[32]) {
  uint8_t raw[kCkbMaxRawSize] = {};
  const size_t raw_size = write_raw_transaction(tx, raw, sizeof(raw));
  if (raw_size == 0) return false;
  uint8_t tx_hash[32] = {};
  if (!ckb_hash(raw, raw_size, tx_hash)) {
    secure_zero(raw, sizeof(raw));
    return false;
  }
  uint8_t witness[85] = {};
  write_witness_args(witness);
  uint8_t preimage[32 + 8 + 85] = {};
  memcpy(preimage, tx_hash, 32);
  put_u64(preimage + 32, sizeof(witness));
  memcpy(preimage + 40, witness, sizeof(witness));
  const bool ok = ckb_hash(preimage, sizeof(preimage), digest);
  secure_zero(raw, sizeof(raw));
  secure_zero(tx_hash, sizeof(tx_hash));
  secure_zero(witness, sizeof(witness));
  secure_zero(preimage, sizeof(preimage));
  return ok;
}

ChainError review_parsed(const CkbParsed &tx, const uint8_t own_args[20],
                         const char *sender, ChainReview *review,
                         uint8_t digest[32]) {
  if (sender == nullptr || review == nullptr || digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  const CkbOutput *recipient = nullptr;
  const CkbOutput *change = nullptr;
  for (uint8_t i = 0; i < tx.output_count; ++i) {
    const bool own = memcmp(tx.outputs[i].lock_args, own_args, 20) == 0;
    if (own) {
      if (change != nullptr || i + 1 != tx.output_count) {
        return ChainError::WrongWallet;
      }
      change = &tx.outputs[i];
    } else {
      if (recipient != nullptr || i != 0) return ChainError::Unsupported;
      recipient = &tx.outputs[i];
    }
  }
  if (recipient == nullptr) return ChainError::WrongWallet;

  uint64_t total_out = 0;
  for (uint8_t i = 0; i < tx.output_count; ++i) {
    if (tx.outputs[i].capacity < kCkbMinimumCell) return ChainError::InvalidAmount;
    if (total_out > UINT64_MAX - tx.outputs[i].capacity) {
      return ChainError::InvalidAmount;
    }
    total_out += tx.outputs[i].capacity;
  }
  if (tx.input.capacity < total_out) return ChainError::InvalidAmount;
  const uint64_t fee = tx.input.capacity - total_out;
  if (fee > kCkbMaximumFee) return ChainError::FeePolicy;

  char recipient_address[kChainMaxAddress] = {};
  if (address_ckb_from_args(recipient->lock_args, recipient_address,
                            sizeof(recipient_address)) != WalletError::Ok) {
    return ChainError::CryptoFailure;
  }
  ChainReview built = {};
  memcpy(built.symbol, "CKB", 4);
  if (strlen(sender) >= sizeof(built.sender) ||
      strlen(recipient_address) >= sizeof(built.recipient)) {
    return ChainError::InvalidArgument;
  }
  strcpy(built.sender, sender);
  strcpy(built.recipient, recipient_address);
  if (!chain_format_units(recipient->capacity, 8, "CKB", built.amount,
                          sizeof(built.amount)) ||
      !chain_format_units(fee, 8, "CKB", built.fee, sizeof(built.fee))) {
    return ChainError::InvalidAmount;
  }
  if (change == nullptr) {
    strcpy(built.extra, "no change cell");
  } else {
    strcpy(built.extra, "change returned to wallet");
  }
  if (!build_digest(tx, digest)) return ChainError::CryptoFailure;
  *review = built;
  return ChainError::Ok;
}

}  // namespace

ChainError ckb_review_payload(const uint8_t *payload, size_t size,
                              const uint8_t public_key[33], const char *sender,
                              ChainReview *review, uint8_t digest[32]) {
  if (public_key == nullptr || sender == nullptr || review == nullptr ||
      digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  CkbParsed tx = {};
  if (!parse_payload(payload, size, &tx)) return ChainError::Malformed;
  uint8_t own_args[20] = {};
  if (!ckb_lock_args(public_key, own_args)) return ChainError::CryptoFailure;
  const ChainError error =
      review_parsed(tx, own_args, sender, review, digest);
  secure_zero(own_args, sizeof(own_args));
  return error;
}

ChainError ckb_sign_payload(const uint8_t *payload, size_t size,
                            const uint8_t private_key[32], uint8_t *out,
                            size_t *in_out_size) {
  if (private_key == nullptr || out == nullptr || in_out_size == nullptr) {
    return ChainError::InvalidArgument;
  }
  if (*in_out_size < 65) return ChainError::BufferTooSmall;
  *in_out_size = 0;
  CkbParsed tx = {};
  if (!parse_payload(payload, size, &tx)) return ChainError::Malformed;
  uint8_t digest[32] = {};
  if (!build_digest(tx, digest)) return ChainError::CryptoFailure;
  RecoverableSignature signature = {};
  const WalletError error =
      secp256k1_sign_digest_recoverable(private_key, digest, &signature);
  secure_zero(digest, sizeof(digest));
  if (error != WalletError::Ok || signature.y_parity > 1) {
    secure_zero(&signature, sizeof(signature));
    return ChainError::CryptoFailure;
  }
  memcpy(out, signature.r, 32);
  memcpy(out + 32, signature.s, 32);
  out[64] = signature.y_parity;
  *in_out_size = 65;
  secure_zero(&signature, sizeof(signature));
  return ChainError::Ok;
}

bool run_ckb_self_tests() {
  // Mainnet transaction f2851617...: one input, two P2PKH outputs. Its
  // signing message is the CKB secp256k1 blake160 sighash-all message
  // (transaction hash || u64 witness length || WitnessArgs with a zero lock).
  static const uint8_t kTxHash[32] = {
      0xb8, 0x00, 0x94, 0x83, 0xde, 0x54, 0x57, 0x25, 0x24, 0x4b, 0xab,
      0x58, 0xf5, 0xc4, 0x8f, 0xee, 0xfb, 0x50, 0xfe, 0xbb, 0x1b, 0x0e,
      0xa7, 0xd7, 0x01, 0x36, 0x6a, 0xde, 0x84, 0x9f, 0x66, 0x42};
  static const uint8_t kRecipient[20] = {
      0x3d, 0x4f, 0xe6, 0xb7, 0xb4, 0x3d, 0x2d, 0x8e, 0x7e, 0x62,
      0xbc, 0xa4, 0x12, 0xf1, 0x81, 0x9f, 0xad, 0xb1, 0x95, 0x07};
  static const uint8_t kChange[20] = {
      0x87, 0xc7, 0x13, 0xe6, 0x0a, 0xfa, 0x56, 0xca, 0x87, 0x11,
      0x94, 0x2f, 0xc5, 0x7e, 0x96, 0x66, 0xd7, 0x47, 0x46, 0x94};
  static const uint8_t kExpectedDigest[32] = {
      0x0d, 0x7c, 0x50, 0xbc, 0x1e, 0x4f, 0x99, 0xe4, 0x9b, 0xa1, 0x3e,
      0x05, 0x19, 0xd8, 0xda, 0x2f, 0x60, 0x82, 0x89, 0x34, 0x7b, 0xdd,
      0xf8, 0x46, 0x3b, 0x5c, 0xaf, 0x69, 0xd6, 0x3b, 0xb6, 0x8f};

  uint8_t payload[kCkbPayloadSize] = {};
  size_t offset = 0;
  memcpy(payload, "CKB1", 4);
  offset = 4;
  payload[offset++] = 1;
  memcpy(payload + offset, kTxHash, 32);
  offset += 32;
  put_u32(payload + offset, 0);
  offset += 4;
  put_u64(payload + offset, 0);
  offset += 8;
  put_u64(payload + offset, 68500000000ULL);
  offset += 8;
  payload[offset++] = 2;
  put_u64(payload + offset, 55115351354ULL);
  offset += 8;
  memcpy(payload + offset, kRecipient, 20);
  offset += 20;
  put_u64(payload + offset, 13308720092ULL);
  offset += 8;
  memcpy(payload + offset, kChange, 20);
  offset += 20;

  CkbParsed tx = {};
  uint8_t digest[32] = {};
  bool ok = parse_payload(payload, offset, &tx) &&
            build_digest(tx, digest);
  if (!ok) {
    ::printf("FAIL: ckb parse/digest\n");
  } else if (!chain_constant_time_equal(digest, kExpectedDigest,
                                        sizeof(kExpectedDigest))) {
    ::printf("FAIL: ckb digest ");
    for (uint8_t i = 0; i < 32; ++i) ::printf("%02x", digest[i]);
    ::printf("\n");
    ok = false;
  }

  // Review vector for private key 1.
  static const uint8_t kPublicKey[33] = {
      0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
      0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
      0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
  static const uint8_t kOwnArgs[20] = {
      0x75, 0x17, 0x8f, 0x34, 0x54, 0x9c, 0x5f, 0xe9, 0xcd, 0x1a,
      0x0c, 0x57, 0xae, 0xbd, 0x01, 0xe7, 0xdd, 0xf9, 0x24, 0x9e};
  uint8_t review_payload[kCkbPayloadSize] = {};
  offset = 0;
  memcpy(review_payload, "CKB1", 4);
  offset = 4;
  review_payload[offset++] = 1;
  memset(review_payload + offset, 0x11, 32);
  offset += 32;
  put_u32(review_payload + offset, 0);
  offset += 4;
  put_u64(review_payload + offset, 0);
  offset += 8;
  put_u64(review_payload + offset, 30000000000ULL);
  offset += 8;
  review_payload[offset++] = 2;
  put_u64(review_payload + offset, 15000000000ULL);
  offset += 8;
  memset(review_payload + offset, 0x22, 20);
  offset += 20;
  put_u64(review_payload + offset, 14990000000ULL);
  offset += 8;
  memcpy(review_payload + offset, kOwnArgs, 20);
  offset += 20;
  ChainReview review = {};
  uint8_t review_digest[32] = {};
  const ChainError review_error =
      ckb_review_payload(review_payload, offset, kPublicKey,
                         "ckb1qyq829u0x32fchlfe5dqc4awh5q70h0eyj0q2zdh7f",
                         &review, review_digest);
  if (review_error != ChainError::Ok) {
    ::printf("FAIL: ckb review error %u\n",
             static_cast<unsigned>(review_error));
    ok = false;
  } else if (strcmp(review.recipient,
                    "ckb1qyqzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qeenzg7") ||
             strcmp(review.amount, "150.0 CKB") ||
             strcmp(review.fee, "0.1 CKB") || strcmp(review.symbol, "CKB")) {
    ::printf("FAIL: ckb review %s %s %s %s\n", review.symbol,
             review.recipient, review.amount, review.fee);
    ok = false;
  }
  return ok;
}

}  // namespace hexwallet
