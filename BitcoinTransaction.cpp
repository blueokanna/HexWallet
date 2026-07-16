#include "BitcoinTransaction.h"

#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <esp_random.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletAddresses.h"

namespace hexwallet {
namespace {

constexpr uint64_t kMaximumBitcoinSupply = 21000000ULL * 100000000ULL;
constexpr uint32_t kSighashAll = 1;
constexpr uint8_t kPsbtMagic[] = {'p', 's', 'b', 't', 0xff};

struct Cursor {
  const uint8_t *data;
  size_t size;
  size_t position;
};

struct Writer {
  uint8_t *data;
  size_t size;
  size_t position;
};

bool add_u64(uint64_t left, uint64_t right, uint64_t *out) {
  if (UINT64_MAX - left < right) return false;
  *out = left + right;
  return true;
}

bool read_bytes(Cursor *cursor, size_t count, const uint8_t **out) {
  if (cursor == nullptr || count > cursor->size - cursor->position) return false;
  if (out != nullptr) *out = cursor->data + cursor->position;
  cursor->position += count;
  return true;
}

bool read_u32(Cursor *cursor, uint32_t *out) {
  const uint8_t *bytes;
  if (!read_bytes(cursor, 4, &bytes)) return false;
  *out = static_cast<uint32_t>(bytes[0]) |
         (static_cast<uint32_t>(bytes[1]) << 8) |
         (static_cast<uint32_t>(bytes[2]) << 16) |
         (static_cast<uint32_t>(bytes[3]) << 24);
  return true;
}

bool read_u64(Cursor *cursor, uint64_t *out) {
  const uint8_t *bytes;
  if (!read_bytes(cursor, 8, &bytes)) return false;
  uint64_t value = 0;
  for (size_t index = 0; index < 8; ++index) value |= static_cast<uint64_t>(bytes[index]) << (index * 8);
  *out = value;
  return true;
}

TransactionError read_compact_size(Cursor *cursor, uint64_t *out) {
  const uint8_t *first;
  if (!read_bytes(cursor, 1, &first)) return TransactionError::Truncated;
  if (*first < 0xfd) {
    *out = *first;
    return TransactionError::Ok;
  }
  const size_t length = *first == 0xfd ? 2 : (*first == 0xfe ? 4 : 8);
  const uint8_t *bytes;
  if (!read_bytes(cursor, length, &bytes)) return TransactionError::Truncated;
  uint64_t value = 0;
  for (size_t index = 0; index < length; ++index) value |= static_cast<uint64_t>(bytes[index]) << (index * 8);
  if ((length == 2 && value < 0xfd) || (length == 4 && value <= 0xffff) ||
      (length == 8 && value <= 0xffffffffULL)) return TransactionError::NonCanonical;
  *out = value;
  return TransactionError::Ok;
}

bool write_bytes(Writer *writer, const void *data, size_t count) {
  if (writer == nullptr || count > writer->size - writer->position) return false;
  if (count != 0) memcpy(writer->data + writer->position, data, count);
  writer->position += count;
  return true;
}

bool write_u32(Writer *writer, uint32_t value) {
  uint8_t bytes[4] = {static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8),
                      static_cast<uint8_t>(value >> 16), static_cast<uint8_t>(value >> 24)};
  return write_bytes(writer, bytes, sizeof(bytes));
}

bool write_u64(Writer *writer, uint64_t value) {
  uint8_t bytes[8];
  for (size_t index = 0; index < sizeof(bytes); ++index) bytes[index] = static_cast<uint8_t>(value >> (index * 8));
  return write_bytes(writer, bytes, sizeof(bytes));
}

bool write_compact_size(Writer *writer, uint64_t value) {
  if (value < 0xfd) {
    const uint8_t byte = static_cast<uint8_t>(value);
    return write_bytes(writer, &byte, 1);
  }
  if (value <= 0xffff) {
    const uint8_t bytes[3] = {0xfd, static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8)};
    return write_bytes(writer, bytes, sizeof(bytes));
  }
  if (value <= 0xffffffffULL) {
    const uint8_t prefix = 0xfe;
    return write_bytes(writer, &prefix, 1) && write_u32(writer, static_cast<uint32_t>(value));
  }
  const uint8_t prefix = 0xff;
  return write_bytes(writer, &prefix, 1) && write_u64(writer, value);
}

TransactionError read_map_item(Cursor *cursor, const uint8_t **key, size_t *key_size,
                               const uint8_t **value, size_t *value_size, bool *end) {
  uint64_t compact_key_size;
  TransactionError result = read_compact_size(cursor, &compact_key_size);
  if (result != TransactionError::Ok) return result;
  if (compact_key_size == 0) {
    *end = true;
    return TransactionError::Ok;
  }
  if (compact_key_size > HEXWALLET_MAX_PSBT_BYTES || compact_key_size > SIZE_MAX) return TransactionError::TooLarge;
  if (!read_bytes(cursor, static_cast<size_t>(compact_key_size), key)) return TransactionError::Truncated;
  uint64_t compact_value_size;
  result = read_compact_size(cursor, &compact_value_size);
  if (result != TransactionError::Ok) return result;
  if (compact_value_size > HEXWALLET_MAX_PSBT_BYTES || compact_value_size > SIZE_MAX) return TransactionError::TooLarge;
  if (!read_bytes(cursor, static_cast<size_t>(compact_value_size), value)) return TransactionError::Truncated;
  *key_size = static_cast<size_t>(compact_key_size);
  *value_size = static_cast<size_t>(compact_value_size);
  *end = false;
  return TransactionError::Ok;
}

TransactionError parse_unsigned_transaction(const uint8_t *data, size_t size,
                                            BitcoinSigningRequest *request) {
  Cursor cursor = {data, size, 0};
  if (!read_u32(&cursor, &request->version) || (request->version != 1 && request->version != 2)) {
    return TransactionError::Unsupported;
  }
  uint64_t input_count;
  TransactionError result = read_compact_size(&cursor, &input_count);
  if (result != TransactionError::Ok) return result;
  if (input_count == 0 || input_count > kBitcoinMaxInputs) return TransactionError::TooLarge;
  request->input_count = static_cast<uint8_t>(input_count);
  for (size_t index = 0; index < input_count; ++index) {
    const uint8_t *txid;
    if (!read_bytes(&cursor, 32, &txid) || !read_u32(&cursor, &request->inputs[index].previous_index)) {
      return TransactionError::Truncated;
    }
    memcpy(request->inputs[index].previous_txid, txid, 32);
    uint64_t script_size;
    result = read_compact_size(&cursor, &script_size);
    if (result != TransactionError::Ok) return result;
    if (script_size != 0) return TransactionError::Unsupported;
    if (!read_u32(&cursor, &request->inputs[index].sequence)) return TransactionError::Truncated;
  }
  uint64_t output_count;
  result = read_compact_size(&cursor, &output_count);
  if (result != TransactionError::Ok) return result;
  if (output_count == 0 || output_count > kBitcoinMaxOutputs) return TransactionError::TooLarge;
  request->output_count = static_cast<uint8_t>(output_count);
  for (size_t index = 0; index < output_count; ++index) {
    BitcoinOutput &output = request->outputs[index];
    if (!read_u64(&cursor, &output.value) || output.value > kMaximumBitcoinSupply) {
      return TransactionError::InvalidAmount;
    }
    uint64_t script_size;
    result = read_compact_size(&cursor, &script_size);
    if (result != TransactionError::Ok) return result;
    if (script_size > kBitcoinMaxScriptSize) return TransactionError::Unsupported;
    const uint8_t *script;
    if (!read_bytes(&cursor, static_cast<size_t>(script_size), &script)) return TransactionError::Truncated;
    output.script_size = static_cast<uint8_t>(script_size);
    memcpy(output.script, script, output.script_size);
    if (address_from_script(kBitcoinMainnet, output.script, output.script_size,
                            output.address, sizeof(output.address)) != WalletError::Ok) {
      return TransactionError::Unsupported;
    }
    if (!add_u64(request->output_total, output.value, &request->output_total)) return TransactionError::InvalidAmount;
  }
  if (!read_u32(&cursor, &request->lock_time)) return TransactionError::Truncated;
  return cursor.position == cursor.size ? TransactionError::Ok : TransactionError::NonCanonical;
}

bool master_fingerprint(const HdPrivateNode &master, uint8_t out[4]) {
  uint8_t public_key[kCompressedPublicKeySize];
  uint8_t hash[kRipemd160Size];
  const bool ok = public_key_from_private(master.private_key, public_key) == WalletError::Ok &&
                  crypto_hash160(public_key, sizeof(public_key), hash);
  if (ok) memcpy(out, hash, 4);
  secure_zero(public_key, sizeof(public_key));
  secure_zero(hash, sizeof(hash));
  return ok;
}

WalletError derive_array_path(const HdPrivateNode &master, const uint32_t *path,
                              size_t depth, HdPrivateNode *out) {
  if (path == nullptr || out == nullptr || depth == 0 || depth > kBitcoinMaxPathDepth) {
    return WalletError::InvalidPath;
  }
  HdPrivateNode current = master;
  for (size_t index = 0; index < depth; ++index) {
    HdPrivateNode next;
    const WalletError result = hd_private_derive(&current, path[index], &next);
    secure_zero(&current, sizeof(current));
    if (result != WalletError::Ok) return result;
    current = next;
  }
  *out = current;
  return WalletError::Ok;
}

bool valid_bitcoin_single_sig_path(const uint32_t *path, size_t depth) {
  return depth == 5 && (path[0] == (49U | kHardenedOffset) ||
                        path[0] == (84U | kHardenedOffset)) &&
         path[1] == kHardenedOffset && path[2] >= kHardenedOffset &&
         path[3] <= 1 && path[4] < kHardenedOffset;
}

bool path_matches_spend_type(const BitcoinInput &input) {
  return valid_bitcoin_single_sig_path(input.path, input.path_depth) &&
         ((input.spend_type == BitcoinSpendType::NativeP2wpkh &&
           input.path[0] == (84U | kHardenedOffset)) ||
          (input.spend_type == BitcoinSpendType::NestedP2shP2wpkh &&
           input.path[0] == (49U | kHardenedOffset)));
}

TransactionError parse_derivation(const uint8_t *key, size_t key_size,
                                  const uint8_t *value, size_t value_size,
                                  const HdPrivateNode &master, BitcoinInput *input,
                                  BitcoinOutput *output) {
  if (key_size != 34 || value_size < 8 || (value_size - 4) % 4 != 0) return TransactionError::NonCanonical;
  const size_t depth = (value_size - 4) / 4;
  if (depth > kBitcoinMaxPathDepth) return TransactionError::TooLarge;
  uint8_t expected_fingerprint[4];
  if (!master_fingerprint(master, expected_fingerprint)) return TransactionError::CryptoFailure;
  const bool fingerprint_ok = crypto_constant_time_equal(value, expected_fingerprint, 4);
  secure_zero(expected_fingerprint, sizeof(expected_fingerprint));
  if (!fingerprint_ok) return TransactionError::WrongWallet;
  uint32_t path[kBitcoinMaxPathDepth] = {};
  for (size_t index = 0; index < depth; ++index) {
    const uint8_t *part = value + 4 + index * 4;
    path[index] = static_cast<uint32_t>(part[0]) | (static_cast<uint32_t>(part[1]) << 8) |
                  (static_cast<uint32_t>(part[2]) << 16) | (static_cast<uint32_t>(part[3]) << 24);
  }
  if (!valid_bitcoin_single_sig_path(path, depth)) return TransactionError::Unsupported;
  HdPrivateNode derived;
  uint8_t public_key[kCompressedPublicKeySize];
  const WalletError derive_result = derive_array_path(master, path, depth, &derived);
  const bool public_ok = derive_result == WalletError::Ok &&
                         public_key_from_private(derived.private_key, public_key) == WalletError::Ok;
  secure_zero(&derived, sizeof(derived));
  if (!public_ok) {
    secure_zero(public_key, sizeof(public_key));
    return TransactionError::CryptoFailure;
  }
  const bool key_ok = crypto_constant_time_equal(key + 1, public_key, sizeof(public_key));
  if (input != nullptr) {
    memcpy(input->path, path, depth * sizeof(uint32_t));
    input->path_depth = static_cast<uint8_t>(depth);
    memcpy(input->public_key, public_key, sizeof(public_key));
  }
  if (output != nullptr && key_ok) {
    uint8_t hash[kRipemd160Size] = {};
    uint8_t redeem_script[22] = {0, 20};
    uint8_t redeem_hash[kRipemd160Size] = {};
    const bool hashed = crypto_hash160(public_key, sizeof(public_key), hash);
    memcpy(redeem_script + 2, hash, sizeof(hash));
    const bool native = hashed && path[0] == (84U | kHardenedOffset) && output->script_size == 22 &&
                        output->script[0] == 0 && output->script[1] == 20 &&
                        crypto_constant_time_equal(output->script + 2, hash, sizeof(hash));
    const bool nested = hashed && path[0] == (49U | kHardenedOffset) && output->script_size == 23 &&
                        output->script[0] == 0xa9 && output->script[1] == 0x14 && output->script[22] == 0x87 &&
                        crypto_hash160(redeem_script, sizeof(redeem_script), redeem_hash) &&
                        crypto_constant_time_equal(output->script + 2, redeem_hash, sizeof(redeem_hash));
    const bool script_ok = native || nested;
    secure_zero(hash, sizeof(hash));
    secure_zero(redeem_script, sizeof(redeem_script));
    secure_zero(redeem_hash, sizeof(redeem_hash));
    if (!script_ok) {
      secure_zero(public_key, sizeof(public_key));
      secure_zero(path, sizeof(path));
      return TransactionError::WrongWallet;
    }
    output->wallet_owned = true;
    output->change = path[3] == 1;
  }
  secure_zero(public_key, sizeof(public_key));
  secure_zero(path, sizeof(path));
  return key_ok ? TransactionError::Ok : TransactionError::WrongWallet;
}

TransactionError parse_input_map(Cursor *cursor, const HdPrivateNode &master, BitcoinInput *input) {
  bool has_utxo = false;
  bool has_derivation = false;
  bool has_sighash = false;
  bool has_redeem_script = false;
  uint8_t redeem_script[22] = {};
  while (true) {
    const uint8_t *key;
    const uint8_t *value;
    size_t key_size;
    size_t value_size;
    bool end;
    TransactionError result = read_map_item(cursor, &key, &key_size, &value, &value_size, &end);
    if (result != TransactionError::Ok || end) {
      if (result != TransactionError::Ok) return result;
      if (!has_utxo || !has_derivation) return TransactionError::MissingField;
      if (input->spend_type == BitcoinSpendType::NativeP2wpkh) {
        if (has_redeem_script) return TransactionError::Unsupported;
      } else if (input->spend_type == BitcoinSpendType::NestedP2shP2wpkh) {
        if (!has_redeem_script) return TransactionError::MissingField;
        uint8_t redeem_hash[kRipemd160Size];
        const bool valid_redeem = crypto_hash160(redeem_script, sizeof(redeem_script), redeem_hash) &&
                                  crypto_constant_time_equal(redeem_hash, input->p2sh_hash, sizeof(redeem_hash));
        secure_zero(redeem_hash, sizeof(redeem_hash));
        if (!valid_redeem) return TransactionError::WrongWallet;
        memcpy(input->witness_key_hash, redeem_script + 2, sizeof(input->witness_key_hash));
      } else {
        return TransactionError::Unsupported;
      }
      secure_zero(redeem_script, sizeof(redeem_script));
      return path_matches_spend_type(*input) ? TransactionError::Ok : TransactionError::WrongWallet;
    }
    if (key_size == 1 && key[0] == 0x01) {
      if (has_utxo) return TransactionError::DuplicateField;
      Cursor utxo = {value, value_size, 0};
      uint64_t script_size;
      if (!read_u64(&utxo, &input->value)) return TransactionError::Truncated;
      result = read_compact_size(&utxo, &script_size);
      if (result != TransactionError::Ok) return result;
      const uint8_t *script;
      if ((script_size != 22 && script_size != 23) || !read_bytes(&utxo, static_cast<size_t>(script_size), &script) ||
          utxo.position != utxo.size || input->value > kMaximumBitcoinSupply) {
        return TransactionError::Unsupported;
      }
      if (script_size == 22 && script[0] == 0 && script[1] == 20) {
        input->spend_type = BitcoinSpendType::NativeP2wpkh;
        memcpy(input->witness_key_hash, script + 2, sizeof(input->witness_key_hash));
      } else if (script_size == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87) {
        input->spend_type = BitcoinSpendType::NestedP2shP2wpkh;
        memcpy(input->p2sh_hash, script + 2, sizeof(input->p2sh_hash));
      } else {
        return TransactionError::Unsupported;
      }
      has_utxo = true;
    } else if (key_size == 34 && key[0] == 0x06) {
      if (has_derivation) return TransactionError::DuplicateField;
      result = parse_derivation(key, key_size, value, value_size, master, input, nullptr);
      if (result != TransactionError::Ok) return result;
      has_derivation = true;
    } else if (key_size == 1 && key[0] == 0x03) {
      if (has_sighash || value_size != 4 || value[0] != 1 || value[1] != 0 || value[2] != 0 || value[3] != 0) {
        return has_sighash ? TransactionError::DuplicateField : TransactionError::Unsupported;
      }
      has_sighash = true;
    } else if (key_size == 1 && key[0] == 0x04) {
      if (has_redeem_script || value_size != sizeof(redeem_script) || value[0] != 0 || value[1] != 20) {
        return has_redeem_script ? TransactionError::DuplicateField : TransactionError::Unsupported;
      }
      memcpy(redeem_script, value, sizeof(redeem_script));
      has_redeem_script = true;
    } else {
      return TransactionError::Unsupported;
    }
  }
}

TransactionError verify_input_script(BitcoinInput *input) {
  uint8_t hash[kRipemd160Size] = {};
  const bool hashed = crypto_hash160(input->public_key, sizeof(input->public_key), hash);
  const bool native = input->spend_type == BitcoinSpendType::NativeP2wpkh &&
                      crypto_constant_time_equal(hash, input->witness_key_hash, sizeof(hash));
  const bool nested = input->spend_type == BitcoinSpendType::NestedP2shP2wpkh &&
                      crypto_constant_time_equal(hash, input->witness_key_hash, sizeof(hash));
  const bool matches = hashed && (native || nested) && path_matches_spend_type(*input);
  secure_zero(hash, sizeof(hash));
  return matches ? TransactionError::Ok : TransactionError::WrongWallet;
}

TransactionError parse_output_map(Cursor *cursor, const HdPrivateNode &master, BitcoinOutput *output) {
  bool has_derivation = false;
  while (true) {
    const uint8_t *key;
    const uint8_t *value;
    size_t key_size;
    size_t value_size;
    bool end;
    TransactionError result = read_map_item(cursor, &key, &key_size, &value, &value_size, &end);
    if (result != TransactionError::Ok || end) return result;
    if (key_size == 34 && key[0] == 0x02) {
      if (has_derivation) return TransactionError::DuplicateField;
      result = parse_derivation(key, key_size, value, value_size, master, nullptr, output);
      if (result != TransactionError::Ok) return result;
      has_derivation = true;
    } else {
      return TransactionError::Unsupported;
    }
  }
}

bool serialize_outputs(const BitcoinSigningRequest &request, uint8_t *out, size_t out_size, size_t *written) {
  Writer writer = {out, out_size, 0};
  for (size_t index = 0; index < request.output_count; ++index) {
    const BitcoinOutput &output = request.outputs[index];
    if (!write_u64(&writer, output.value) || !write_compact_size(&writer, output.script_size) ||
        !write_bytes(&writer, output.script, output.script_size)) return false;
  }
  *written = writer.position;
  return true;
}

TransactionError bip143_digest(const BitcoinSigningRequest &request, size_t input_index,
                               uint8_t out[kSha256Size]) {
  uint8_t prevouts[kBitcoinMaxInputs * 36];
  uint8_t sequences[kBitcoinMaxInputs * 4];
  uint8_t outputs[kBitcoinMaxOutputs * (8 + 1 + kBitcoinMaxScriptSize)];
  Writer prevout_writer = {prevouts, sizeof(prevouts), 0};
  Writer sequence_writer = {sequences, sizeof(sequences), 0};
  for (size_t index = 0; index < request.input_count; ++index) {
    if (!write_bytes(&prevout_writer, request.inputs[index].previous_txid, 32) ||
        !write_u32(&prevout_writer, request.inputs[index].previous_index) ||
        !write_u32(&sequence_writer, request.inputs[index].sequence)) return TransactionError::BufferTooSmall;
  }
  size_t outputs_size;
  if (!serialize_outputs(request, outputs, sizeof(outputs), &outputs_size)) return TransactionError::BufferTooSmall;
  uint8_t hash_prevouts[kSha256Size];
  uint8_t hash_sequences[kSha256Size];
  uint8_t hash_outputs[kSha256Size];
  if (!crypto_double_sha256(prevouts, prevout_writer.position, hash_prevouts) ||
      !crypto_double_sha256(sequences, sequence_writer.position, hash_sequences) ||
      !crypto_double_sha256(outputs, outputs_size, hash_outputs)) return TransactionError::CryptoFailure;
  const BitcoinInput &input = request.inputs[input_index];
  uint8_t key_hash[kRipemd160Size];
  if (!crypto_hash160(input.public_key, sizeof(input.public_key), key_hash)) return TransactionError::CryptoFailure;
  uint8_t preimage[182];
  Writer writer = {preimage, sizeof(preimage), 0};
  const uint8_t script_prefix[] = {0x19, 0x76, 0xa9, 0x14};
  const uint8_t script_suffix[] = {0x88, 0xac};
  const bool serialized = write_u32(&writer, request.version) &&
      write_bytes(&writer, hash_prevouts, sizeof(hash_prevouts)) &&
      write_bytes(&writer, hash_sequences, sizeof(hash_sequences)) &&
      write_bytes(&writer, input.previous_txid, sizeof(input.previous_txid)) &&
      write_u32(&writer, input.previous_index) && write_bytes(&writer, script_prefix, sizeof(script_prefix)) &&
      write_bytes(&writer, key_hash, sizeof(key_hash)) && write_bytes(&writer, script_suffix, sizeof(script_suffix)) &&
      write_u64(&writer, input.value) && write_u32(&writer, input.sequence) &&
      write_bytes(&writer, hash_outputs, sizeof(hash_outputs)) && write_u32(&writer, request.lock_time) &&
      write_u32(&writer, kSighashAll);
  const bool hashed = serialized && crypto_double_sha256(preimage, writer.position, out);
  secure_zero(prevouts, sizeof(prevouts));
  secure_zero(sequences, sizeof(sequences));
  secure_zero(outputs, sizeof(outputs));
  secure_zero(hash_prevouts, sizeof(hash_prevouts));
  secure_zero(hash_sequences, sizeof(hash_sequences));
  secure_zero(hash_outputs, sizeof(hash_outputs));
  secure_zero(key_hash, sizeof(key_hash));
  secure_zero(preimage, sizeof(preimage));
  return hashed ? TransactionError::Ok : TransactionError::CryptoFailure;
}

int random_callback(void *, unsigned char *output, size_t length) {
  esp_fill_random(output, length);
  return 0;
}

size_t der_integer(const mbedtls_mpi &value, uint8_t *out) {
  uint8_t raw[32];
  mbedtls_mpi_write_binary(&value, raw, sizeof(raw));
  size_t first = 0;
  while (first + 1 < sizeof(raw) && raw[first] == 0) ++first;
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

TransactionError sign_digest(const uint8_t private_key[kPrivateKeySize],
                             const uint8_t digest[kSha256Size], uint8_t *der, size_t *der_size) {
  mbedtls_ecp_group group;
  mbedtls_mpi d;
  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_mpi half_order;
  mbedtls_ecp_point public_key;
  mbedtls_ecp_group_init(&group);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&half_order);
  mbedtls_ecp_point_init(&public_key);
  int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
  if (result == 0) result = mbedtls_mpi_read_binary(&d, private_key, kPrivateKeySize);
  if (result == 0) result = mbedtls_ecdsa_sign_det_ext(&group, &r, &s, &d, digest, kSha256Size,
                                                       MBEDTLS_MD_SHA256, random_callback, nullptr);
  if (result == 0) result = mbedtls_mpi_copy(&half_order, &group.N);
  if (result == 0) result = mbedtls_mpi_shift_r(&half_order, 1);
  if (result == 0 && mbedtls_mpi_cmp_mpi(&s, &half_order) > 0) result = mbedtls_mpi_sub_mpi(&s, &group.N, &s);
  if (result == 0) result = mbedtls_ecp_mul(&group, &public_key, &d, &group.G, random_callback, nullptr);
  if (result == 0) result = mbedtls_ecdsa_verify(&group, digest, kSha256Size, &public_key, &r, &s);
  uint8_t integers[70];
  size_t integer_size = 0;
  if (result == 0) {
    integer_size = der_integer(r, integers);
    integer_size += der_integer(s, integers + integer_size);
    if (*der_size < integer_size + 2) result = -1;
  }
  if (result == 0) {
    der[0] = 0x30;
    der[1] = static_cast<uint8_t>(integer_size);
    memcpy(der + 2, integers, integer_size);
    *der_size = integer_size + 2;
  }
  secure_zero(integers, sizeof(integers));
  mbedtls_mpi_free(&half_order);
  mbedtls_ecp_point_free(&public_key);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&group);
  return result == 0 ? TransactionError::Ok : TransactionError::CryptoFailure;
}

uint32_t stripped_size(const BitcoinSigningRequest &request) {
  uint32_t size = 4 + 1 + 1 + 4;
  for (size_t index = 0; index < request.input_count; ++index) {
    const size_t script_size = request.inputs[index].spend_type == BitcoinSpendType::NestedP2shP2wpkh ? 23 : 0;
    size += 32 + 4 + 1 + script_size + 4;
  }
  for (size_t index = 0; index < request.output_count; ++index) {
    size += 8 + 1 + request.outputs[index].script_size;
  }
  return size;
}

}

TransactionError bitcoin_parse_psbt(const uint8_t *psbt, size_t psbt_size,
                                    const HdPrivateNode &master, BitcoinSigningRequest *out) {
  if (psbt == nullptr || out == nullptr || psbt_size < sizeof(kPsbtMagic) ||
      psbt_size > HEXWALLET_MAX_PSBT_BYTES) return TransactionError::InvalidArgument;
  BitcoinSigningRequest parsed;
  clear_bitcoin_request(&parsed);
  Cursor cursor = {psbt, psbt_size, 0};
  const uint8_t *magic;
  if (!read_bytes(&cursor, sizeof(kPsbtMagic), &magic) || memcmp(magic, kPsbtMagic, sizeof(kPsbtMagic)) != 0) {
    return TransactionError::NonCanonical;
  }
  bool has_unsigned_tx = false;
  while (true) {
    const uint8_t *key;
    const uint8_t *value;
    size_t key_size;
    size_t value_size;
    bool end;
    TransactionError result = read_map_item(&cursor, &key, &key_size, &value, &value_size, &end);
    if (result != TransactionError::Ok) return result;
    if (end) break;
    if (key_size != 1 || key[0] != 0x00) return TransactionError::Unsupported;
    if (has_unsigned_tx) return TransactionError::DuplicateField;
    result = parse_unsigned_transaction(value, value_size, &parsed);
    if (result != TransactionError::Ok) return result;
    has_unsigned_tx = true;
  }
  if (!has_unsigned_tx) return TransactionError::MissingField;
  for (size_t index = 0; index < parsed.input_count; ++index) {
    TransactionError result = parse_input_map(&cursor, master, &parsed.inputs[index]);
    if (result != TransactionError::Ok) return result;
    result = verify_input_script(&parsed.inputs[index]);
    if (result != TransactionError::Ok) return result;
    if (!add_u64(parsed.input_total, parsed.inputs[index].value, &parsed.input_total)) return TransactionError::InvalidAmount;
  }
  for (size_t index = 0; index < parsed.output_count; ++index) {
    const TransactionError result = parse_output_map(&cursor, master, &parsed.outputs[index]);
    if (result != TransactionError::Ok) return result;
  }
  if (cursor.position != cursor.size) return TransactionError::NonCanonical;
  if (parsed.input_total < parsed.output_total) return TransactionError::InvalidAmount;
  parsed.fee = parsed.input_total - parsed.output_total;
  const uint32_t stripped = stripped_size(parsed);
  const uint32_t witness_minimum = 2 + parsed.input_count * 109;
  parsed.estimated_vbytes = (stripped * 4 + witness_minimum + 3) / 4;
  if (parsed.fee > HEXWALLET_MAX_BITCOIN_FEE_SATS || parsed.estimated_vbytes == 0 ||
      parsed.fee > HEXWALLET_MAX_BITCOIN_FEE_RATE * static_cast<uint64_t>(parsed.estimated_vbytes)) {
    return TransactionError::FeePolicy;
  }
  if (!crypto_sha256(psbt, psbt_size, parsed.psbt_hash)) return TransactionError::CryptoFailure;
  *out = parsed;
  return TransactionError::Ok;
}

TransactionError bitcoin_sign_request(const BitcoinSigningRequest &request,
                                      const HdPrivateNode &master,
                                      uint8_t *out_transaction, size_t *in_out_size) {
  if (out_transaction == nullptr || in_out_size == nullptr || request.input_count == 0 ||
      request.input_count > kBitcoinMaxInputs || request.output_count == 0 ||
      request.output_count > kBitcoinMaxOutputs || (request.version != 1 && request.version != 2)) {
    return TransactionError::InvalidArgument;
  }
  uint64_t input_total = 0;
  uint64_t output_total = 0;
  for (size_t index = 0; index < request.input_count; ++index) {
    const BitcoinInput &input = request.inputs[index];
    uint8_t key_hash[kRipemd160Size] = {};
    uint8_t redeem_script[22] = {0, 20};
    uint8_t redeem_hash[kRipemd160Size] = {};
    memcpy(redeem_script + 2, input.witness_key_hash, sizeof(input.witness_key_hash));
    const bool native = input.spend_type == BitcoinSpendType::NativeP2wpkh;
    const bool nested = input.spend_type == BitcoinSpendType::NestedP2shP2wpkh &&
                        crypto_hash160(redeem_script, sizeof(redeem_script), redeem_hash) &&
                        crypto_constant_time_equal(redeem_hash, input.p2sh_hash, sizeof(redeem_hash));
    const bool valid = input.value <= kMaximumBitcoinSupply &&
                       path_matches_spend_type(input) &&
                       crypto_hash160(input.public_key, sizeof(input.public_key), key_hash) &&
                       crypto_constant_time_equal(key_hash, input.witness_key_hash, sizeof(key_hash)) &&
                       (native || nested) &&
                       add_u64(input_total, input.value, &input_total);
    secure_zero(key_hash, sizeof(key_hash));
    secure_zero(redeem_script, sizeof(redeem_script));
    secure_zero(redeem_hash, sizeof(redeem_hash));
    if (!valid) return TransactionError::WrongWallet;
  }
  for (size_t index = 0; index < request.output_count; ++index) {
    const BitcoinOutput &output = request.outputs[index];
    char address[kAddressTextSize];
    const bool valid = output.value <= kMaximumBitcoinSupply && output.script_size <= kBitcoinMaxScriptSize &&
                       address_from_script(kBitcoinMainnet, output.script, output.script_size,
                                           address, sizeof(address)) == WalletError::Ok &&
                       add_u64(output_total, output.value, &output_total);
    secure_zero(address, sizeof(address));
    if (!valid) return TransactionError::Unsupported;
  }
  const uint32_t expected_vbytes = (stripped_size(request) * 4 + 2 + request.input_count * 109 + 3) / 4;
  if (input_total < output_total || input_total != request.input_total || output_total != request.output_total ||
      input_total - output_total != request.fee || request.fee > HEXWALLET_MAX_BITCOIN_FEE_SATS ||
      request.estimated_vbytes == 0 || request.estimated_vbytes != expected_vbytes ||
      request.fee > HEXWALLET_MAX_BITCOIN_FEE_RATE * static_cast<uint64_t>(request.estimated_vbytes)) {
    return TransactionError::FeePolicy;
  }
  uint8_t signatures[kBitcoinMaxInputs][kBitcoinMaxDerSignatureSize];
  uint8_t signature_sizes[kBitcoinMaxInputs] = {};
  for (size_t index = 0; index < request.input_count; ++index) {
    HdPrivateNode derived;
    if (derive_array_path(master, request.inputs[index].path, request.inputs[index].path_depth, &derived) != WalletError::Ok) {
      secure_zero(signatures, sizeof(signatures));
      return TransactionError::WrongWallet;
    }
    uint8_t public_key[kCompressedPublicKeySize];
    const bool key_matches = public_key_from_private(derived.private_key, public_key) == WalletError::Ok &&
        crypto_constant_time_equal(public_key, request.inputs[index].public_key, sizeof(public_key));
    secure_zero(public_key, sizeof(public_key));
    if (!key_matches) {
      secure_zero(&derived, sizeof(derived));
      secure_zero(signatures, sizeof(signatures));
      return TransactionError::WrongWallet;
    }
    uint8_t digest[kSha256Size];
    TransactionError result = bip143_digest(request, index, digest);
    size_t der_size = sizeof(signatures[index]) - 1;
    if (result == TransactionError::Ok) result = sign_digest(derived.private_key, digest, signatures[index], &der_size);
    secure_zero(&derived, sizeof(derived));
    secure_zero(digest, sizeof(digest));
    if (result != TransactionError::Ok || der_size + 1 > sizeof(signatures[index])) {
      secure_zero(signatures, sizeof(signatures));
      return result == TransactionError::Ok ? TransactionError::BufferTooSmall : result;
    }
    signatures[index][der_size] = static_cast<uint8_t>(kSighashAll);
    signature_sizes[index] = static_cast<uint8_t>(der_size + 1);
  }
  Writer writer = {out_transaction, *in_out_size, 0};
  const uint8_t marker_flag[] = {0, 1};
  bool ok = write_u32(&writer, request.version) && write_bytes(&writer, marker_flag, sizeof(marker_flag)) &&
            write_compact_size(&writer, request.input_count);
  for (size_t index = 0; ok && index < request.input_count; ++index) {
    const BitcoinInput &input = request.inputs[index];
    uint8_t redeem_script[22] = {0, 20};
    const uint8_t push_redeem = sizeof(redeem_script);
    memcpy(redeem_script + 2, input.witness_key_hash, sizeof(input.witness_key_hash));
    const bool nested = input.spend_type == BitcoinSpendType::NestedP2shP2wpkh;
    ok = write_bytes(&writer, input.previous_txid, sizeof(input.previous_txid)) &&
         write_u32(&writer, input.previous_index) &&
         write_compact_size(&writer, nested ? sizeof(redeem_script) + 1 : 0) &&
         (!nested || (write_bytes(&writer, &push_redeem, sizeof(push_redeem)) &&
                      write_bytes(&writer, redeem_script, sizeof(redeem_script)))) &&
         write_u32(&writer, input.sequence);
    secure_zero(redeem_script, sizeof(redeem_script));
  }
  ok = ok && write_compact_size(&writer, request.output_count);
  for (size_t index = 0; ok && index < request.output_count; ++index) {
    const BitcoinOutput &output = request.outputs[index];
    ok = write_u64(&writer, output.value) && write_compact_size(&writer, output.script_size) &&
         write_bytes(&writer, output.script, output.script_size);
  }
  for (size_t index = 0; ok && index < request.input_count; ++index) {
    ok = write_compact_size(&writer, 2) && write_compact_size(&writer, signature_sizes[index]) &&
         write_bytes(&writer, signatures[index], signature_sizes[index]) &&
         write_compact_size(&writer, sizeof(request.inputs[index].public_key)) &&
         write_bytes(&writer, request.inputs[index].public_key, sizeof(request.inputs[index].public_key));
  }
  ok = ok && write_u32(&writer, request.lock_time);
  secure_zero(signatures, sizeof(signatures));
  if (!ok) return TransactionError::BufferTooSmall;
  *in_out_size = writer.position;
  return TransactionError::Ok;
}

const char *transaction_error_text(TransactionError error) {
  switch (error) {
    case TransactionError::Ok: return "ok";
    case TransactionError::InvalidArgument: return "invalid-argument";
    case TransactionError::Truncated: return "truncated";
    case TransactionError::NonCanonical: return "non-canonical";
    case TransactionError::Unsupported: return "unsupported-field-or-script";
    case TransactionError::TooLarge: return "limit-exceeded";
    case TransactionError::MissingField: return "missing-field";
    case TransactionError::DuplicateField: return "duplicate-field";
    case TransactionError::WrongWallet: return "wrong-wallet-or-path";
    case TransactionError::InvalidAmount: return "invalid-amount";
    case TransactionError::FeePolicy: return "fee-policy";
    case TransactionError::CryptoFailure: return "crypto-failure";
    case TransactionError::BufferTooSmall: return "buffer-too-small";
  }
  return "unknown";
}

void clear_bitcoin_request(BitcoinSigningRequest *request) {
  if (request != nullptr) secure_zero(request, sizeof(*request));
}

bool run_bitcoin_transaction_self_test() {
  BitcoinSigningRequest request = {};
  request.version = 1;
  request.lock_time = 0x11;
  request.input_count = 2;
  request.output_count = 2;
  const uint8_t prev0[32] = {0xff,0xf7,0xf7,0x88,0x1a,0x80,0x99,0xaf,0xa6,0x94,0x0d,0x42,0xd1,0xe7,0xf6,0x36,0x2b,0xec,0x38,0x17,0x1e,0xa3,0xed,0xf4,0x33,0x54,0x1d,0xb4,0xe4,0xad,0x96,0x9f};
  const uint8_t prev1[32] = {0xef,0x51,0xe1,0xb8,0x04,0xcc,0x89,0xd1,0x82,0xd2,0x79,0x65,0x5c,0x3a,0xa8,0x9e,0x81,0x5b,0x1b,0x30,0x9f,0xe2,0x87,0xd9,0xb2,0xb5,0x5d,0x57,0xb9,0x0e,0xc6,0x8a};
  memcpy(request.inputs[0].previous_txid, prev0, 32);
  memcpy(request.inputs[1].previous_txid, prev1, 32);
  request.inputs[0].sequence = 0xffffffee;
  request.inputs[1].previous_index = 1;
  request.inputs[1].sequence = 0xffffffff;
  request.inputs[1].value = 600000000;
  const uint8_t public_key[33] = {0x02,0x54,0x76,0xc2,0xe8,0x31,0x88,0x36,0x8d,0xa1,0xff,0x3e,0x29,0x2e,0x7a,0xca,0xfc,0xdb,0x35,0x66,0xbb,0x0a,0xd2,0x53,0xf6,0x2f,0xc7,0x0f,0x07,0xae,0xee,0x63,0x57};
  memcpy(request.inputs[1].public_key, public_key, sizeof(public_key));
  const uint8_t output0[25] = {0x76,0xa9,0x14,0x82,0x80,0xb3,0x7d,0xf3,0x78,0xdb,0x99,0xf6,0x6f,0x85,0xc9,0x5a,0x78,0x3a,0x76,0xac,0x7a,0x6d,0x59,0x88,0xac};
  const uint8_t output1[25] = {0x76,0xa9,0x14,0x3b,0xde,0x42,0xdb,0xee,0x7e,0x4d,0xbe,0x6a,0x21,0xb2,0xd5,0x0c,0xe2,0xf0,0x16,0x7f,0xaa,0x81,0x59,0x88,0xac};
  request.outputs[0].value = 112340000;
  request.outputs[1].value = 223450000;
  request.outputs[0].script_size = sizeof(output0);
  request.outputs[1].script_size = sizeof(output1);
  memcpy(request.outputs[0].script, output0, sizeof(output0));
  memcpy(request.outputs[1].script, output1, sizeof(output1));
  const uint8_t expected[32] = {0xc3,0x7a,0xf3,0x11,0x16,0xd1,0xb2,0x7c,0xaf,0x68,0xaa,0xe9,0xe3,0xac,0x82,0xf1,0x47,0x79,0x29,0x01,0x4d,0x5b,0x91,0x76,0x57,0xd0,0xeb,0x49,0x47,0x8c,0xb6,0x70};
  const uint8_t private_key[32] = {0x61,0x9c,0x33,0x50,0x25,0xc7,0xf4,0x01,0x2e,0x55,0x6c,0x2a,0x58,0xb2,0x50,0x6e,0x30,0xb8,0x51,0x1b,0x53,0xad,0xe9,0x5e,0xa3,0x16,0xfd,0x8c,0x32,0x86,0xfe,0xb9};
  const uint8_t expected_signature[70] = {0x30,0x44,0x02,0x20,0x36,0x09,0xe1,0x7b,0x84,0xf6,0xa7,0xd3,0x0c,0x80,0xbf,0xa6,0x10,0xb5,0xb4,0x54,0x2f,0x32,0xa8,0xa0,0xd5,0x44,0x7a,0x12,0xfb,0x13,0x66,0xd7,0xf0,0x1c,0xc4,0x4a,0x02,0x20,0x57,0x3a,0x95,0x4c,0x45,0x18,0x33,0x15,0x61,0x40,0x6f,0x90,0x30,0x0e,0x8f,0x33,0x58,0xf5,0x19,0x28,0xd4,0x3c,0x21,0x2a,0x8c,0xae,0xd0,0x2d,0xe6,0x7e,0xeb,0xee};
  uint8_t digest[kSha256Size];
  uint8_t signature[kBitcoinMaxDerSignatureSize];
  size_t signature_size = sizeof(signature);
  bool passed = bip143_digest(request, 1, digest) == TransactionError::Ok &&
                crypto_constant_time_equal(digest, expected, sizeof(expected)) &&
                sign_digest(private_key, digest, signature, &signature_size) == TransactionError::Ok &&
                signature_size == sizeof(expected_signature) &&
                crypto_constant_time_equal(signature, expected_signature, sizeof(expected_signature));
  secure_zero(digest, sizeof(digest));
  secure_zero(signature, sizeof(signature));
  clear_bitcoin_request(&request);

  const uint8_t seed[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  const uint32_t input_path[5] = {49U | kHardenedOffset, kHardenedOffset,
                                  kHardenedOffset, 0, 0};
  const uint32_t output_path[5] = {49U | kHardenedOffset, kHardenedOffset,
                                   kHardenedOffset, 1, 0};
  HdPrivateNode master;
  HdPrivateNode input_node;
  HdPrivateNode output_node;
  uint8_t input_public[kCompressedPublicKeySize];
  uint8_t output_public[kCompressedPublicKeySize];
  uint8_t input_redeem[22] = {0, 20};
  uint8_t output_redeem[22] = {0, 20};
  uint8_t input_script[23] = {0xa9, 0x14};
  uint8_t output_script[23] = {0xa9, 0x14};
  uint8_t fingerprint[4];
  passed = passed && hd_private_from_seed(seed, sizeof(seed), &master) == WalletError::Ok &&
           derive_array_path(master, input_path, 5, &input_node) == WalletError::Ok &&
           derive_array_path(master, output_path, 5, &output_node) == WalletError::Ok &&
           public_key_from_private(input_node.private_key, input_public) == WalletError::Ok &&
           public_key_from_private(output_node.private_key, output_public) == WalletError::Ok &&
           crypto_hash160(input_public, sizeof(input_public), input_redeem + 2) &&
           crypto_hash160(output_public, sizeof(output_public), output_redeem + 2) &&
           crypto_hash160(input_redeem, sizeof(input_redeem), input_script + 2) &&
           crypto_hash160(output_redeem, sizeof(output_redeem), output_script + 2) &&
           master_fingerprint(master, fingerprint);
  input_script[22] = 0x87;
  output_script[22] = 0x87;

  uint8_t unsigned_transaction[128];
  Writer unsigned_writer = {unsigned_transaction, sizeof(unsigned_transaction), 0};
  uint8_t zero_txid[32] = {};
  bool serialized = write_u32(&unsigned_writer, 2) && write_compact_size(&unsigned_writer, 1) &&
      write_bytes(&unsigned_writer, zero_txid, sizeof(zero_txid)) && write_u32(&unsigned_writer, 0) &&
      write_compact_size(&unsigned_writer, 0) && write_u32(&unsigned_writer, 0xfffffffd) &&
      write_compact_size(&unsigned_writer, 1) && write_u64(&unsigned_writer, 90000) &&
      write_compact_size(&unsigned_writer, sizeof(output_script)) &&
      write_bytes(&unsigned_writer, output_script, sizeof(output_script)) && write_u32(&unsigned_writer, 0);

  uint8_t psbt[384];
  Writer psbt_writer = {psbt, sizeof(psbt), 0};
  const uint8_t global_key = 0x00;
  const uint8_t witness_utxo_key = 0x01;
  const uint8_t redeem_script_key = 0x04;
  const uint8_t input_derivation_type = 0x06;
  const uint8_t output_derivation_type = 0x02;
  serialized = passed && serialized && write_bytes(&psbt_writer, kPsbtMagic, sizeof(kPsbtMagic)) &&
      write_compact_size(&psbt_writer, 1) && write_bytes(&psbt_writer, &global_key, 1) &&
      write_compact_size(&psbt_writer, unsigned_writer.position) &&
      write_bytes(&psbt_writer, unsigned_transaction, unsigned_writer.position) &&
      write_compact_size(&psbt_writer, 0) && write_compact_size(&psbt_writer, 1) &&
      write_bytes(&psbt_writer, &witness_utxo_key, 1) && write_compact_size(&psbt_writer, 32) &&
      write_u64(&psbt_writer, 100000) && write_compact_size(&psbt_writer, sizeof(input_script)) &&
      write_bytes(&psbt_writer, input_script, sizeof(input_script)) &&
      write_compact_size(&psbt_writer, 1) && write_bytes(&psbt_writer, &redeem_script_key, 1) &&
      write_compact_size(&psbt_writer, sizeof(input_redeem)) && write_bytes(&psbt_writer, input_redeem, sizeof(input_redeem)) &&
      write_compact_size(&psbt_writer, 34) &&
      write_bytes(&psbt_writer, &input_derivation_type, 1) &&
      write_bytes(&psbt_writer, input_public, sizeof(input_public)) && write_compact_size(&psbt_writer, 24) &&
      write_bytes(&psbt_writer, fingerprint, sizeof(fingerprint));
  for (size_t index = 0; serialized && index < 5; ++index) serialized = write_u32(&psbt_writer, input_path[index]);
  serialized = serialized && write_compact_size(&psbt_writer, 0) && write_compact_size(&psbt_writer, 34) &&
      write_bytes(&psbt_writer, &output_derivation_type, 1) &&
      write_bytes(&psbt_writer, output_public, sizeof(output_public)) && write_compact_size(&psbt_writer, 24) &&
      write_bytes(&psbt_writer, fingerprint, sizeof(fingerprint));
  for (size_t index = 0; serialized && index < 5; ++index) serialized = write_u32(&psbt_writer, output_path[index]);
  serialized = serialized && write_compact_size(&psbt_writer, 0);

  BitcoinSigningRequest parsed;
  uint8_t signed_transaction[384];
  size_t signed_size = sizeof(signed_transaction);
  passed = serialized && bitcoin_parse_psbt(psbt, psbt_writer.position, master, &parsed) == TransactionError::Ok &&
           parsed.input_count == 1 && parsed.output_count == 1 && parsed.fee == 10000 &&
           parsed.outputs[0].wallet_owned && parsed.outputs[0].change &&
           bitcoin_sign_request(parsed, master, signed_transaction, &signed_size) == TransactionError::Ok &&
           signed_size > 44 && signed_transaction[4] == 0 && signed_transaction[5] == 1 &&
           signed_transaction[43] == 23 && signed_transaction[44] == 22;
  clear_bitcoin_request(&parsed);
  secure_zero(&master, sizeof(master));
  secure_zero(&input_node, sizeof(input_node));
  secure_zero(&output_node, sizeof(output_node));
  secure_zero(input_public, sizeof(input_public));
  secure_zero(output_public, sizeof(output_public));
  secure_zero(input_redeem, sizeof(input_redeem));
  secure_zero(output_redeem, sizeof(output_redeem));
  secure_zero(input_script, sizeof(input_script));
  secure_zero(output_script, sizeof(output_script));
  secure_zero(fingerprint, sizeof(fingerprint));
  secure_zero(unsigned_transaction, sizeof(unsigned_transaction));
  secure_zero(psbt, sizeof(psbt));
  secure_zero(signed_transaction, sizeof(signed_transaction));
  return passed;
}

}
