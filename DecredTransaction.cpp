#include "DecredTransaction.h"

#include <stdio.h>
#include <string.h>

#include "Blake256.h"
#include "ChainCommon.h"
#include "CryptoPrimitives.h"
#include "local_ripemd160.h"
#include "WalletAltAddresses.h"

namespace hexwallet {
namespace {

constexpr uint32_t kDcrVersion = 1;
constexpr uint32_t kDcrHashAll = 1;
constexpr size_t kDcrMaxSighashInputs = 8;
constexpr size_t kDcrMaxSighashOutputs = 8;

struct DcrInput {
  uint8_t previous_hash[32];
  uint32_t previous_index;
  uint8_t tree;
  uint32_t sequence;
};

struct DcrOutput {
  uint64_t value;
  uint16_t version;
  uint8_t script[kDcrMaxScript];
  uint8_t script_size;
};

struct DcrSighashTx {
  uint32_t version;
  uint8_t input_count;
  DcrInput inputs[kDcrMaxSighashInputs];
  uint8_t output_count;
  DcrOutput outputs[kDcrMaxSighashOutputs];
  uint32_t lock_time;
  uint32_t expiry;
};

struct Writer {
  uint8_t *data;
  size_t capacity;
  size_t size = 0;
  bool ok = true;

  bool bytes(const uint8_t *value, size_t length) {
    if (!ok || size + length > capacity) {
      ok = false;
      return false;
    }
    if (length != 0) memcpy(data + size, value, length);
    size += length;
    return true;
  }
  bool u16(uint16_t value) {
    uint8_t raw[2] = {static_cast<uint8_t>(value),
                      static_cast<uint8_t>(value >> 8)};
    return bytes(raw, sizeof(raw));
  }
  bool u32(uint32_t value) {
    uint8_t raw[4] = {};
    chain_write_u32_le(value, raw);
    return bytes(raw, sizeof(raw));
  }
  bool u64(uint64_t value) {
    uint8_t raw[8] = {};
    chain_write_u64_le(value, raw);
    return bytes(raw, sizeof(raw));
  }
  bool varint(uint64_t value) {
    if (value < 0xfd) {
      const uint8_t raw = static_cast<uint8_t>(value);
      return bytes(&raw, 1);
    }
    if (value <= 0xffff) {
      uint8_t raw[3] = {0xfd, static_cast<uint8_t>(value),
                        static_cast<uint8_t>(value >> 8)};
      return bytes(raw, sizeof(raw));
    }
    if (value <= 0xffffffffULL) {
      uint8_t raw[5] = {0xfe};
      chain_write_u32_le(static_cast<uint32_t>(value), raw + 1);
      return bytes(raw, sizeof(raw));
    }
    uint8_t raw[9] = {0xff};
    chain_write_u64_le(value, raw + 1);
    return bytes(raw, sizeof(raw));
  }
};

bool dcr_sighash(const uint8_t *script, size_t script_size, uint32_t hash_type,
                 const DcrSighashTx &tx, uint8_t input_index,
                 uint8_t digest[32]) {
  if (script == nullptr || digest == nullptr ||
      input_index >= tx.input_count) {
    return false;
  }
  uint8_t prefix[1024] = {};
  Writer prefix_writer = {prefix, sizeof(prefix)};
  prefix_writer.u32(tx.version | (1UL << 16));
  prefix_writer.varint(tx.input_count);
  for (uint8_t index = 0; index < tx.input_count; ++index) {
    const DcrInput &input = tx.inputs[index];
    prefix_writer.bytes(input.previous_hash, 32);
    prefix_writer.u32(input.previous_index);
    prefix_writer.bytes(&input.tree, 1);
    prefix_writer.u32(input.sequence);
  }
  prefix_writer.varint(tx.output_count);
  for (uint8_t index = 0; index < tx.output_count; ++index) {
    const DcrOutput &output = tx.outputs[index];
    prefix_writer.u64(output.value);
    prefix_writer.u16(output.version);
    prefix_writer.varint(output.script_size);
    prefix_writer.bytes(output.script, output.script_size);
  }
  prefix_writer.u32(tx.lock_time);
  prefix_writer.u32(tx.expiry);
  if (!prefix_writer.ok) return false;
  uint8_t prefix_hash[32] = {};
  if (!blake256_hash(prefix, prefix_writer.size, prefix_hash)) return false;

  uint8_t witness[256] = {};
  Writer witness_writer = {witness, sizeof(witness)};
  witness_writer.u32(tx.version | (3UL << 16));
  witness_writer.varint(tx.input_count);
  for (uint8_t index = 0; index < tx.input_count; ++index) {
    const bool signed_input = index == input_index;
    witness_writer.varint(signed_input ? script_size : 0);
    if (signed_input) witness_writer.bytes(script, script_size);
  }
  if (!witness_writer.ok) return false;
  uint8_t witness_hash[32] = {};
  if (!blake256_hash(witness, witness_writer.size, witness_hash)) return false;

  uint8_t final_buffer[68] = {};
  Writer final_writer = {final_buffer, sizeof(final_buffer)};
  final_writer.u32(hash_type);
  final_writer.bytes(prefix_hash, 32);
  final_writer.bytes(witness_hash, 32);
  if (!final_writer.ok) return false;
  return blake256_hash(final_buffer, final_writer.size, digest);
}

bool build_p2pkh_script(const uint8_t public_key[33], uint8_t *script,
                        size_t *script_size) {
  if (public_key == nullptr || script == nullptr || script_size == nullptr) {
    return false;
  }
  uint8_t blake[32] = {};
  uint8_t hash[20] = {};
  if (!blake256_hash(public_key, 33, blake)) return false;
  local_ripemd160(blake, sizeof(blake), hash);
  script[0] = 0x76;
  script[1] = 0xa9;
  script[2] = 0x14;
  memcpy(script + 3, hash, 20);
  script[23] = 0x88;
  script[24] = 0xac;
  *script_size = 25;
  secure_zero(blake, sizeof(blake));
  secure_zero(hash, sizeof(hash));
  return true;
}

ChainError parse_payload(const uint8_t *payload, size_t size, DcrSighashTx *tx,
                         uint64_t *input_value) {
  if (payload == nullptr || tx == nullptr || input_value == nullptr ||
      size < 94 || size > kDcrPayloadSize) {
    return ChainError::InvalidArgument;
  }
  if (memcmp(payload, "DCR1", 4) != 0) return ChainError::Malformed;
  memset(tx, 0, sizeof(*tx));
  tx->version = kDcrVersion;
  tx->input_count = 1;
  size_t offset = 4;
  memcpy(tx->inputs[0].previous_hash, payload + offset, 32);
  offset += 32;
  tx->inputs[0].previous_index =
      static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  tx->inputs[0].tree = payload[offset++];
  tx->inputs[0].sequence =
      static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  tx->lock_time = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  tx->expiry = static_cast<uint32_t>(chain_read_u32_le(payload + offset));
  offset += 4;
  *input_value = chain_read_u64_le(payload + offset);
  offset += 8;
  const uint8_t output_count = payload[offset++];
  if (output_count == 0 || output_count > kDcrMaxOutputs) {
    return ChainError::Unsupported;
  }
  tx->output_count = output_count;
  for (uint8_t index = 0; index < output_count; ++index) {
    if (offset + 9 > size) return ChainError::Malformed;
    tx->outputs[index].value = chain_read_u64_le(payload + offset);
    offset += 8;
    const uint8_t script_size = payload[offset++];
    if (script_size == 0 || script_size > kDcrMaxScript ||
        offset + script_size > size) {
      return ChainError::Malformed;
    }
    memcpy(tx->outputs[index].script, payload + offset, script_size);
    tx->outputs[index].script_size = script_size;
    tx->outputs[index].version = 0;
    offset += script_size;
  }
  if (offset != size) return ChainError::Malformed;
  if (tx->inputs[0].tree > 1) return ChainError::Unsupported;
  if (tx->outputs[0].value == 0) return ChainError::InvalidAmount;
  return ChainError::Ok;
}

}  // namespace

ChainError dcr_review_payload(const uint8_t *payload, size_t size,
                              const uint8_t public_key[33],
                              const char *sender, ChainReview *review,
                              uint8_t digest[32]) {
  if (public_key == nullptr || sender == nullptr || review == nullptr ||
      digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  memset(review, 0, sizeof(*review));
  DcrSighashTx tx;
  uint64_t input_value = 0;
  ChainError error = parse_payload(payload, size, &tx, &input_value);
  if (error != ChainError::Ok) return error;
  uint8_t own_script[kDcrMaxScript] = {};
  size_t own_script_size = 0;
  if (!build_p2pkh_script(public_key, own_script, &own_script_size)) {
    return ChainError::CryptoFailure;
  }

  uint64_t output_total = 0;
  int external_index = -1;
  bool change_seen = false;
  char addresses[kDcrMaxOutputs][64] = {};
  for (uint8_t index = 0; index < tx.output_count; ++index) {
    const DcrOutput &output = tx.outputs[index];
    if (output.value > input_value ||
        output_total > input_value - output.value) {
      return ChainError::InvalidAmount;
    }
    output_total += output.value;
    if (address_decred_from_script(0x073f, 0x071a, output.script,
                                   output.script_size, addresses[index],
                                   sizeof(addresses[index])) != WalletError::Ok) {
      return ChainError::Unsupported;
    }
    if (output.script_size == own_script_size &&
        chain_constant_time_equal(output.script, own_script, own_script_size)) {
      change_seen = true;
    } else if (external_index < 0) {
      external_index = index;
    }
  }
  if (external_index < 0) return ChainError::InvalidAmount;
  const uint64_t fee = input_value - output_total;
  if (fee > 100000000ULL) return ChainError::FeePolicy;
  if (!dcr_sighash(own_script, own_script_size, kDcrHashAll, tx, 0, digest)) {
    return ChainError::CryptoFailure;
  }

  strncpy(review->symbol, "DCR", sizeof(review->symbol) - 1);
  strncpy(review->sender, sender, sizeof(review->sender) - 1);
  strncpy(review->recipient, addresses[external_index],
          sizeof(review->recipient) - 1);
  if (!chain_format_units(tx.outputs[external_index].value, 8, "DCR",
                          review->amount, sizeof(review->amount))) {
    return ChainError::BufferTooSmall;
  }
  if (!chain_format_units(fee, 8, "DCR", review->fee, sizeof(review->fee))) {
    return ChainError::BufferTooSmall;
  }
  snprintf(review->extra, sizeof(review->extra),
           "%s\nOUTPUTS %u\nINPUT VALUE %llu ATOMS\nLOCK TIME %lu\nEXPIRY %lu",
           change_seen ? "CHANGE INCLUDED" : "NO CHANGE OUTPUT",
           static_cast<unsigned>(tx.output_count),
           static_cast<unsigned long long>(input_value),
           static_cast<unsigned long>(tx.lock_time),
           static_cast<unsigned long>(tx.expiry));
  secure_zero(own_script, sizeof(own_script));
  return ChainError::Ok;
}

ChainError dcr_sign_payload(const uint8_t *payload, size_t size,
                            const uint8_t private_key[32], uint8_t *out,
                            size_t *in_out_size) {
  if (private_key == nullptr || out == nullptr || in_out_size == nullptr) {
    return ChainError::InvalidArgument;
  }
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  DcrSighashTx tx;
  uint64_t input_value = 0;
  ChainError error = parse_payload(payload, size, &tx, &input_value);
  if (error != ChainError::Ok) return error;
  uint8_t public_key[33] = {};
  uint8_t own_script[kDcrMaxScript] = {};
  size_t own_script_size = 0;
  if (public_key_from_private(private_key, public_key) != WalletError::Ok ||
      !build_p2pkh_script(public_key, own_script, &own_script_size)) {
    return ChainError::CryptoFailure;
  }
  uint8_t digest[32] = {};
  if (!dcr_sighash(own_script, own_script_size, kDcrHashAll, tx, 0, digest)) {
    secure_zero(own_script, sizeof(own_script));
    return ChainError::CryptoFailure;
  }
  uint8_t der[72] = {};
  size_t der_size = sizeof(der);
  if (!chain_secp256k1_sign_der(private_key, digest, der, &der_size)) {
    secure_zero(own_script, sizeof(own_script));
    secure_zero(der, sizeof(der));
    return ChainError::CryptoFailure;
  }
  uint8_t signature_with_type[73] = {};
  memcpy(signature_with_type, der, der_size);
  signature_with_type[der_size] = kDcrHashAll;
  const size_t signature_size = der_size + 1;
  uint8_t script_sig[128] = {};
  size_t script_sig_size = 0;
  script_sig[script_sig_size++] = static_cast<uint8_t>(signature_size);
  memcpy(script_sig + script_sig_size, signature_with_type, signature_size);
  script_sig_size += signature_size;
  script_sig[script_sig_size++] = 33;
  memcpy(script_sig + script_sig_size, public_key, 33);
  script_sig_size += 33;

  Writer writer = {out, capacity};
  writer.u32(tx.version);
  writer.varint(tx.input_count);
  writer.bytes(tx.inputs[0].previous_hash, 32);
  writer.u32(tx.inputs[0].previous_index);
  writer.bytes(&tx.inputs[0].tree, 1);
  writer.u32(tx.inputs[0].sequence);
  writer.varint(script_sig_size);
  writer.bytes(script_sig, script_sig_size);
  writer.varint(tx.output_count);
  for (uint8_t index = 0; index < tx.output_count; ++index) {
    writer.u64(tx.outputs[index].value);
    writer.u16(tx.outputs[index].version);
    writer.varint(tx.outputs[index].script_size);
    writer.bytes(tx.outputs[index].script, tx.outputs[index].script_size);
  }
  writer.u32(tx.lock_time);
  writer.u32(tx.expiry);
  if (!writer.ok) error = ChainError::BufferTooSmall;
  else *in_out_size = writer.size;
  secure_zero(own_script, sizeof(own_script));
  secure_zero(der, sizeof(der));
  secure_zero(signature_with_type, sizeof(signature_with_type));
  secure_zero(script_sig, sizeof(script_sig));
  return error;
}

bool run_decred_self_tests() {
  // dcrd txscript/sighash_test.go TestCalcSignatureHash.
  static const uint8_t kExpected[32] = {
      0x4c, 0xe2, 0xcd, 0x04, 0x2d, 0x64, 0xe3, 0x5b, 0x36, 0xfd, 0xbd,
      0x16, 0xaf, 0xf0, 0xd3, 0x8a, 0x5a, 0xbe, 0xbf, 0xf0, 0xe5, 0xe8,
      0xf6, 0xb6, 0xb3, 0x1f, 0xcd, 0x4a, 0xc6, 0x95, 0x79, 0x05};
  DcrSighashTx tx = {};
  tx.version = 1;
  tx.input_count = 3;
  for (uint8_t index = 0; index < 3; ++index) {
    const uint8_t seed = index;
    blake256_hash(&seed, 1, tx.inputs[index].previous_hash);
    tx.inputs[index].previous_index = index;
    tx.inputs[index].tree = 0;
    tx.inputs[index].sequence = 0xffffffffUL;
  }
  tx.output_count = 2;
  for (uint8_t index = 0; index < 2; ++index) {
    tx.outputs[index].value = 0x0000ff00ff00ff00ULL;
    tx.outputs[index].version = 0;
    tx.outputs[index].script[0] = 0x51;
    tx.outputs[index].script_size = 1;
  }
  static const uint8_t kScript[1] = {0x51};
  uint8_t digest[32] = {};
  bool ok = dcr_sighash(kScript, sizeof(kScript), kDcrHashAll, tx, 0, digest) &&
            chain_constant_time_equal(digest, kExpected, sizeof(kExpected));

  // Review vector: one 2 DCR input, 1.5 DCR to 0x22.. and 0.49 DCR change.
  static const uint8_t kPublicKey[33] = {
      0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
      0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
      0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
  uint8_t payload[160] = {};
  size_t offset = 0;
  memcpy(payload, "DCR1", 4);
  offset = 4;
  memset(payload + offset, 0x11, 32);
  offset += 32;
  chain_write_u32_le(0, payload + offset);
  offset += 4;
  payload[offset++] = 0;
  chain_write_u32_le(0xffffffffUL, payload + offset);
  offset += 4;
  chain_write_u32_le(0, payload + offset);
  offset += 4;
  chain_write_u32_le(0, payload + offset);
  offset += 4;
  chain_write_u64_le(200000000ULL, payload + offset);
  offset += 8;
  payload[offset++] = 2;
  chain_write_u64_le(150000000ULL, payload + offset);
  offset += 8;
  payload[offset++] = 25;
  payload[offset++] = 0x76;
  payload[offset++] = 0xa9;
  payload[offset++] = 0x14;
  memset(payload + offset, 0x22, 20);
  offset += 20;
  payload[offset++] = 0x88;
  payload[offset++] = 0xac;
  chain_write_u64_le(49000000ULL, payload + offset);
  offset += 8;
  payload[offset++] = 25;
  payload[offset++] = 0x76;
  payload[offset++] = 0xa9;
  payload[offset++] = 0x14;
  // Change script for the generator public key used by kPublicKey.
  static const uint8_t kOwnHash[20] = {
      0xe2, 0x80, 0xcb, 0x6e, 0x66, 0xb9, 0x66, 0x79, 0xae, 0xc2,
      0x88, 0xb1, 0xfb, 0xdb, 0xd4, 0xdb, 0x08, 0x07, 0x7a, 0x1b};
  memcpy(payload + offset, kOwnHash, 20);
  offset += 20;
  payload[offset++] = 0x88;
  payload[offset++] = 0xac;
  ChainReview review;
  uint8_t review_digest[32] = {};
  ok = ok && dcr_review_payload(payload, offset, kPublicKey,
                                "DsmcYVbP1Nmag2H4AS17UTvmWXmGeA7nLDx",
                                &review, review_digest) == ChainError::Ok &&
       !strcmp(review.recipient, "DsU5PMaVftfyDEDieCq3WTbsbL9AQBoTu8J") &&
       !strcmp(review.amount, "1.5 DCR") && !strcmp(review.fee, "0.01 DCR");
  return ok;
}

}  // namespace hexwallet
