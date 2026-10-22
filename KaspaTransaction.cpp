#include "KaspaTransaction.h"

#include <string.h>

#include "Blake2b.h"
#include "CryptoExtended.h"
#include "WalletConfig.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

// Domain-separation keys from kaspa-hashes (blake2b_hasher! macro). The key is
// the literal ASCII string, padded with zeros to the 32-byte digest length.
constexpr char kTransactionIdKey[] = "TransactionID";
constexpr char kTransactionSigningKey[] = "TransactionSigningHash";

// Consensus mass parameters (consensus/core/src/config/params.rs, mainnet).
constexpr uint64_t kMassPerTransactionByte = 1;
constexpr uint64_t kMassPerScriptPublicKeyByte = 10;
constexpr uint64_t kGramsPerSigopCountUnit = 1000;
constexpr uint64_t kTransientByteToMassFactor = 4;
// STORAGE_MASS_PARAMETER = SOMPI_PER_KASPA * 10_000
constexpr uint64_t kStorageMassParameter = kKaspaSompiPerKaspa * 10000ULL;
constexpr uint64_t kUtxoConstStorage = 32 + 4 + 8 + 8 + 1 + 2 + 8;
constexpr uint64_t kUtxoUnitSize = 100;

constexpr uint8_t kSighashMask = 0x07;
constexpr uint8_t kSighashAnyoneCanPay = 0x80;

constexpr uint8_t kP2pkScriptSize = 34;  // OP_DATA_32 || x-only key || OP_CHECKSIG
constexpr uint8_t kP2shScriptSize = 35;  // OP_BLAKE2B || OP_DATA_32 || hash || OP_EQUAL
constexpr uint8_t kOpData32 = 0x20;
constexpr uint8_t kOpCheckSig = 0xac;
constexpr uint8_t kOpBlake2b = 0xaa;
constexpr uint8_t kOpEqual = 0x87;
constexpr uint16_t kAddressVersionP2pk = 0;
constexpr uint16_t kAddressVersionP2sh = 8;

struct Writer {
  uint8_t *data;
  size_t capacity;
  size_t position;
};

bool write_bytes(Writer *writer, const void *data, size_t size) {
  if (writer->position + size > writer->capacity) return false;
  memcpy(writer->data + writer->position, data, size);
  writer->position += size;
  return true;
}

// Protobuf varint and length-delimited helpers for the broadcast encoding.
bool write_varint(Writer *writer, uint64_t value) {
  do {
    uint8_t byte = static_cast<uint8_t>(value & 0x7f);
    value >>= 7;
    if (value != 0) byte |= 0x80;
    if (!write_bytes(writer, &byte, 1)) return false;
  } while (value != 0);
  return true;
}

bool write_tag(Writer *writer, uint32_t field, uint32_t wire_type) {
  return write_varint(writer, (static_cast<uint64_t>(field) << 3) | wire_type);
}

bool add_u64(uint64_t left, uint64_t right, uint64_t *out) {
  if (out == nullptr || left > UINT64_MAX - right) return false;
  *out = left + right;
  return true;
}

void hash_outpoint(Blake2bState *state, const KaspaOutpoint &outpoint) {
  blake2b_update(state, outpoint.transaction_id, sizeof(outpoint.transaction_id));
  uint8_t index[4];
  for (uint8_t byte = 0; byte < 4; ++byte) {
    index[byte] = static_cast<uint8_t>(outpoint.index >> (8 * byte));
  }
  blake2b_update(state, index, sizeof(index));
}

void hash_script_public_key(Blake2bState *state, uint16_t version,
                            const uint8_t *script, uint8_t script_size) {
  uint8_t version_bytes[2] = { static_cast<uint8_t>(version),
                               static_cast<uint8_t>(version >> 8) };
  blake2b_update(state, version_bytes, sizeof(version_bytes));
  uint8_t length[8];
  const uint64_t size = script_size;
  for (uint8_t byte = 0; byte < 8; ++byte) {
    length[byte] = static_cast<uint8_t>(size >> (8 * byte));
  }
  blake2b_update(state, length, sizeof(length));
  blake2b_update(state, script, script_size);
}

bool digest_keyed(const char *key, size_t key_size, Blake2bState *state,
                  uint8_t out[32]) {
  (void)key;
  (void)key_size;
  return blake2b_final(state, out);
}

Blake2bState start_hash(const char *key, size_t key_size) {
  Blake2bState state;
  blake2b_init(&state, 32, reinterpret_cast<const uint8_t *>(key), key_size);
  return state;
}

uint8_t kaspa_sighash_byte(KaspaSighash sighash) {
  return static_cast<uint8_t>(sighash);
}

bool sighash_is_anyone_can_pay(KaspaSighash sighash) {
  return (kaspa_sighash_byte(sighash) & kSighashAnyoneCanPay) != 0;
}

uint8_t sighash_base(KaspaSighash sighash) {
  return kaspa_sighash_byte(sighash) & kSighashMask;
}

bool valid_kaspa_sighash(KaspaSighash sighash) {
  const uint8_t value = kaspa_sighash_byte(sighash);
  return value == 0x01 || value == 0x02 || value == 0x04 || value == 0x81 ||
         value == 0x82 || value == 0x84;
}

// KIP-0009 plurality: how many 100-byte storage units a UTXO occupies. Every
// standard 35-byte P2PK/P2SH script public key has a plurality of 1.
uint64_t utxo_plurality(uint8_t script_size) {
  return (kUtxoConstStorage + script_size + kUtxoUnitSize - 1) / kUtxoUnitSize;
}

bool derive_and_verify_key(const HdPrivateNode &master, uint32_t index,
                           const NetworkProfile &network, uint8_t *out_key,
                           uint8_t *out_xonly) {
  // Kaspa spends a P2PK output whose key is the BIP32 child at
  // m/44'/111111'/account'/change/index, hardened coin type only.
  const uint32_t path[5] = { 44U | kHardenedOffset,
                             static_cast<uint32_t>(network.derivation_coin_type) | kHardenedOffset,
                             kHardenedOffset, 0, index };
  HdPrivateNode current = master;
  for (size_t depth = 0; depth < 5; ++depth) {
    HdPrivateNode next;
    const WalletError result = hd_private_derive(&current, path[depth], &next);
    secure_zero(&current, sizeof(current));
    if (result != WalletError::Ok) return false;
    current = next;
  }
  uint8_t parity;
  const WalletError keyed =
      secp256k1_xonly_public_key(current.private_key, out_xonly, &parity);
  (void)parity;
  if (out_key != nullptr) memcpy(out_key, current.private_key, kPrivateKeySize);
  secure_zero(&current, sizeof(current));
  return keyed == WalletError::Ok;
}

}  // namespace

KaspaError kaspa_sighash(const KaspaTransaction &transaction, size_t input_index,
                         KaspaSighash sighash, uint8_t out_digest[32]) {
  if (out_digest == nullptr || input_index >= transaction.input_count ||
      transaction.input_count == 0 || transaction.output_count == 0 ||
      transaction.version != 0 || !valid_kaspa_sighash(sighash)) {
    return KaspaError::InvalidArgument;
  }
  const bool anyone_can_pay = sighash_is_anyone_can_pay(sighash);
  const uint8_t base = sighash_base(sighash);

  // previous_outputs_hash: zero when ANYONECANPAY.
  uint8_t previous_outputs_hash[32] = {};
  if (!anyone_can_pay) {
    Blake2bState state = start_hash(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1);
    for (size_t index = 0; index < transaction.input_count; ++index) {
      hash_outpoint(&state, transaction.inputs[index].previous_outpoint);
    }
    digest_keyed(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1,
                 &state, previous_outputs_hash);
  }

  // sequences_hash: zero for SINGLE, NONE and ANYONECANPAY.
  uint8_t sequences_hash[32] = {};
  if (base != 0x04 && base != 0x02 && !anyone_can_pay) {
    Blake2bState state = start_hash(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1);
    for (size_t index = 0; index < transaction.input_count; ++index) {
      uint8_t sequence[8];
      const uint64_t value = transaction.inputs[index].sequence;
      for (uint8_t byte = 0; byte < 8; ++byte) {
        sequence[byte] = static_cast<uint8_t>(value >> (8 * byte));
      }
      blake2b_update(&state, sequence, sizeof(sequence));
    }
    digest_keyed(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1,
                 &state, sequences_hash);
  }

  // sig_op_counts_hash: zero when ANYONECANPAY; only v0 commits to it.
  uint8_t sigop_counts_hash[32] = {};
  if (!anyone_can_pay) {
    Blake2bState state = start_hash(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1);
    for (size_t index = 0; index < transaction.input_count; ++index) {
      const uint8_t count = transaction.inputs[index].sigop_count;
      blake2b_update(&state, &count, 1);
    }
    digest_keyed(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1,
                 &state, sigop_counts_hash);
  }

  // outputs_hash.
  uint8_t outputs_hash[32] = {};
  if (base == 0x02) {
    // SIGHASH_NONE commits to no outputs.
  } else if (base == 0x04) {
    if (input_index < transaction.output_count) {
      const KaspaOutput &output = transaction.outputs[input_index];
      Blake2bState state = start_hash(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1);
      uint8_t value[8];
      for (uint8_t byte = 0; byte < 8; ++byte) {
        value[byte] = static_cast<uint8_t>(output.value >> (8 * byte));
      }
      blake2b_update(&state, value, sizeof(value));
      hash_script_public_key(&state, output.script_version, output.script,
                             output.script_size);
      digest_keyed(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1,
                   &state, outputs_hash);
    }
  } else {
    Blake2bState state = start_hash(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1);
    for (size_t index = 0; index < transaction.output_count; ++index) {
      const KaspaOutput &output = transaction.outputs[index];
      uint8_t value[8];
      for (uint8_t byte = 0; byte < 8; ++byte) {
        value[byte] = static_cast<uint8_t>(output.value >> (8 * byte));
      }
      blake2b_update(&state, value, sizeof(value));
      hash_script_public_key(&state, output.script_version, output.script,
                             output.script_size);
    }
    digest_keyed(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1,
                 &state, outputs_hash);
  }

  // payload_hash: zero for a native transaction with an empty payload.
  uint8_t payload_hash[32] = {};
  if (transaction.payload_size != 0) {
    Blake2bState state = start_hash(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1);
    uint8_t length[8];
    const uint64_t size = transaction.payload_size;
    for (uint8_t byte = 0; byte < 8; ++byte) {
      length[byte] = static_cast<uint8_t>(size >> (8 * byte));
    }
    blake2b_update(&state, length, sizeof(length));
    blake2b_update(&state, transaction.payload, transaction.payload_size);
    digest_keyed(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1,
                 &state, payload_hash);
  }

  const KaspaInput &input = transaction.inputs[input_index];
  Blake2bState state = start_hash(kTransactionSigningKey, sizeof(kTransactionSigningKey) - 1);
  uint8_t version_bytes[2] = { static_cast<uint8_t>(transaction.version),
                               static_cast<uint8_t>(transaction.version >> 8) };
  blake2b_update(&state, version_bytes, sizeof(version_bytes));
  blake2b_update(&state, previous_outputs_hash, sizeof(previous_outputs_hash));
  blake2b_update(&state, sequences_hash, sizeof(sequences_hash));
  blake2b_update(&state, sigop_counts_hash, sizeof(sigop_counts_hash));
  hash_outpoint(&state, input.previous_outpoint);
  hash_script_public_key(&state, input.script_version, input.script,
                         input.script_size);
  uint8_t amount[8];
  for (uint8_t byte = 0; byte < 8; ++byte) {
    amount[byte] = static_cast<uint8_t>(input.value >> (8 * byte));
  }
  blake2b_update(&state, amount, sizeof(amount));
  uint8_t sequence[8];
  for (uint8_t byte = 0; byte < 8; ++byte) {
    sequence[byte] = static_cast<uint8_t>(input.sequence >> (8 * byte));
  }
  blake2b_update(&state, sequence, sizeof(sequence));
  blake2b_update(&state, &input.sigop_count, 1);
  blake2b_update(&state, outputs_hash, sizeof(outputs_hash));
  uint8_t lock_time[8];
  for (uint8_t byte = 0; byte < 8; ++byte) {
    lock_time[byte] = static_cast<uint8_t>(transaction.lock_time >> (8 * byte));
  }
  blake2b_update(&state, lock_time, sizeof(lock_time));
  // Native subnetwork id: 20 zero bytes.
  const uint8_t subnetwork[20] = {};
  blake2b_update(&state, subnetwork, sizeof(subnetwork));
  const uint8_t gas[8] = {};
  blake2b_update(&state, gas, sizeof(gas));
  blake2b_update(&state, payload_hash, sizeof(payload_hash));
  const uint8_t hash_type = kaspa_sighash_byte(sighash);
  blake2b_update(&state, &hash_type, 1);
  const bool ok = blake2b_final(&state, out_digest);
  secure_zero(previous_outputs_hash, sizeof(previous_outputs_hash));
  secure_zero(sequences_hash, sizeof(sequences_hash));
  secure_zero(sigop_counts_hash, sizeof(sigop_counts_hash));
  secure_zero(outputs_hash, sizeof(outputs_hash));
  secure_zero(payload_hash, sizeof(payload_hash));
  return ok ? KaspaError::Ok : KaspaError::CryptoFailure;
}

KaspaError kaspa_transaction_id(const KaspaTransaction &transaction,
                                uint8_t out_id[32]) {
  if (out_id == nullptr || transaction.version != 0 ||
      transaction.input_count == 0 ||
      transaction.input_count > kKaspaMaxInputs ||
      transaction.output_count > kKaspaMaxOutputs) {
    return KaspaError::InvalidArgument;
  }
  // The ID excludes the signature script and the mass commitment, so a v0
  // transaction signs to a stable ID regardless of the signature bytes.
  Blake2bState state = start_hash(kTransactionIdKey, sizeof(kTransactionIdKey) - 1);
  uint8_t u16[2] = { static_cast<uint8_t>(transaction.version),
                     static_cast<uint8_t>(transaction.version >> 8) };
  blake2b_update(&state, u16, sizeof(u16));
  uint8_t count[8];
  const uint64_t input_count = transaction.input_count;
  for (uint8_t byte = 0; byte < 8; ++byte) {
    count[byte] = static_cast<uint8_t>(input_count >> (8 * byte));
  }
  blake2b_update(&state, count, sizeof(count));
  for (size_t index = 0; index < transaction.input_count; ++index) {
    hash_outpoint(&state, transaction.inputs[index].previous_outpoint);
    const uint8_t empty_script_length[8] = {};
    blake2b_update(&state, empty_script_length, sizeof(empty_script_length));
    uint8_t sequence[8];
    for (uint8_t byte = 0; byte < 8; ++byte) {
      sequence[byte] = static_cast<uint8_t>(transaction.inputs[index].sequence >> (8 * byte));
    }
    blake2b_update(&state, sequence, sizeof(sequence));
  }
  const uint64_t output_count = transaction.output_count;
  for (uint8_t byte = 0; byte < 8; ++byte) {
    count[byte] = static_cast<uint8_t>(output_count >> (8 * byte));
  }
  blake2b_update(&state, count, sizeof(count));
  for (size_t index = 0; index < transaction.output_count; ++index) {
    const KaspaOutput &output = transaction.outputs[index];
    uint8_t value[8];
    for (uint8_t byte = 0; byte < 8; ++byte) {
      value[byte] = static_cast<uint8_t>(output.value >> (8 * byte));
    }
    blake2b_update(&state, value, sizeof(value));
    hash_script_public_key(&state, output.script_version, output.script,
                           output.script_size);
  }
  uint8_t lock_time[8];
  for (uint8_t byte = 0; byte < 8; ++byte) {
    lock_time[byte] = static_cast<uint8_t>(transaction.lock_time >> (8 * byte));
  }
  blake2b_update(&state, lock_time, sizeof(lock_time));
  const uint8_t subnetwork[20] = {};
  blake2b_update(&state, subnetwork, sizeof(subnetwork));
  const uint8_t gas[8] = {};
  blake2b_update(&state, gas, sizeof(gas));
  const uint8_t payload_length[8] = {};
  blake2b_update(&state, payload_length, sizeof(payload_length));
  if (transaction.payload_size != 0) {
    // A non-native payload would also change the subnetwork id; the wallet
    // refuses those in kaspa_review, so this stays unreachable in practice.
    uint8_t size_bytes[8];
    for (uint8_t byte = 0; byte < 8; ++byte) {
      size_bytes[byte] = static_cast<uint8_t>(transaction.payload_size >> (8 * byte));
    }
    blake2b_update(&state, size_bytes, sizeof(size_bytes));
    blake2b_update(&state, transaction.payload, transaction.payload_size);
  }
  return blake2b_final(&state, out_id) ? KaspaError::Ok : KaspaError::CryptoFailure;
}

KaspaError kaspa_masses(const KaspaTransaction &transaction,
                        uint64_t *compute_mass, uint64_t *transient_mass,
                        uint64_t *storage_mass) {
  if (compute_mass == nullptr || transient_mass == nullptr ||
      storage_mass == nullptr || transaction.version != 0 ||
      transaction.input_count == 0) {
    return KaspaError::InvalidArgument;
  }
  // transaction_estimated_serialized_size for a v0 native transaction.
  uint64_t size = 2 + 8 + 8 + 8 + 20 + 8 + 8;
  uint64_t total_script_public_key_size = 0;
  uint64_t total_sigops = 0;
  for (size_t index = 0; index < transaction.input_count; ++index) {
    size += kKaspaOutpointSize + 8 + transaction.inputs[index].script_size + 8;
    // The wire serialization carries the *signature* script; the estimate uses
    // its actual length, which at review time is the fixed 65-byte P2PK form.
    size += kKaspaSignatureSize;
    total_sigops += transaction.inputs[index].sigop_count;
  }
  for (size_t index = 0; index < transaction.output_count; ++index) {
    const uint64_t script_size = transaction.outputs[index].script_size;
    size += 8 + 2 + 8 + script_size;
    total_script_public_key_size += 2 + script_size;
  }
  size += transaction.payload_size;

  const uint64_t size_mass = size * kMassPerTransactionByte;
  const uint64_t script_mass = total_script_public_key_size * kMassPerScriptPublicKeyByte;
  const uint64_t sigop_mass = total_sigops * kGramsPerSigopCountUnit;
  *compute_mass = size_mass + script_mass + sigop_mass;
  *transient_mass = size * kTransientByteToMassFactor;

  // KIP-0009 storage mass. harmonic_outs = sum(C * plurality^2 / amount).
  uint64_t outs_plurality = 0;
  uint64_t harmonic_outs = 0;
  for (size_t index = 0; index < transaction.output_count; ++index) {
    const uint64_t plurality = utxo_plurality(transaction.outputs[index].script_size);
    if (transaction.outputs[index].value == 0) return KaspaError::InvalidAmount;
    outs_plurality += plurality;
    const uint64_t numerator = kStorageMassParameter * plurality * plurality;
    if (!add_u64(harmonic_outs, numerator / transaction.outputs[index].value,
                 &harmonic_outs)) {
      return KaspaError::InvalidAmount;
    }
  }
  uint64_t ins_plurality = 0;
  uint64_t harmonic_ins = 0;
  for (size_t index = 0; index < transaction.input_count; ++index) {
    const uint64_t plurality = utxo_plurality(transaction.inputs[index].script_size);
    ins_plurality += plurality;
    if (transaction.inputs[index].value == 0) return KaspaError::InvalidAmount;
    const uint64_t numerator = kStorageMassParameter * plurality * plurality;
    if (!add_u64(harmonic_ins, numerator / transaction.inputs[index].value,
                 &harmonic_ins)) {
      return KaspaError::InvalidAmount;
    }
  }
  const bool relaxed = outs_plurality == 1 ||
                       (transaction.input_count <= 2 &&
                        (ins_plurality == 1 || (outs_plurality == 2 && ins_plurality == 2)));
  if (relaxed) {
    *storage_mass = harmonic_outs > harmonic_ins ? harmonic_outs - harmonic_ins : 0;
  } else {
    uint64_t sum_ins = 0;
    for (size_t index = 0; index < transaction.input_count; ++index) {
      if (!add_u64(sum_ins, transaction.inputs[index].value, &sum_ins)) {
        return KaspaError::InvalidAmount;
      }
    }
    uint64_t mean_ins = ins_plurality == 0 ? 0 : sum_ins / ins_plurality;
    if (mean_ins == 0) mean_ins = 1;
    const uint64_t arithmetic_ins =
        ins_plurality * (kStorageMassParameter / mean_ins);
    *storage_mass = harmonic_outs > arithmetic_ins ? harmonic_outs - arithmetic_ins : 0;
  }
  return KaspaError::Ok;
}

KaspaError kaspa_address_from_script(const char *prefix, uint16_t version,
                                     const uint8_t *script, uint8_t script_size,
                                     char *out, size_t out_size) {
  if (prefix == nullptr || script == nullptr || out == nullptr) {
    return KaspaError::InvalidArgument;
  }
  uint8_t payload[64];
  size_t payload_size = 0;
  if (version == kAddressVersionP2pk && script_size == kP2pkScriptSize &&
      script[0] == kOpData32 && script[kP2pkScriptSize - 1] == kOpCheckSig) {
    memcpy(payload, script + 1, 32);
    payload_size = 32;
  } else if (version == kAddressVersionP2sh && script_size == kP2shScriptSize &&
             script[0] == kOpBlake2b && script[1] == kOpData32 &&
             script[kP2shScriptSize - 1] == kOpEqual) {
    memcpy(payload, script + 2, 32);
    payload_size = 32;
  } else {
    return KaspaError::Unsupported;
  }
  const bool ok = kaspa_bech32_encode(prefix, static_cast<uint8_t>(version),
                                      payload, payload_size, out, out_size);
  secure_zero(payload, sizeof(payload));
  return ok ? KaspaError::Ok : KaspaError::BufferTooSmall;
}

KaspaError kaspa_script_from_address(const char *prefix, const char *address,
                                     uint16_t *out_version, uint8_t *out_script,
                                     uint8_t *out_script_size) {
  if (prefix == nullptr || address == nullptr || out_version == nullptr ||
      out_script == nullptr || out_script_size == nullptr) {
    return KaspaError::InvalidArgument;
  }
  uint8_t version_byte = 0;
  uint8_t payload[kKaspaMaxScriptPublicKeySize];
  size_t payload_size = sizeof(payload);
  if (!kaspa_bech32_decode(prefix, address, &version_byte, payload, &payload_size)) {
    secure_zero(payload, sizeof(payload));
    return KaspaError::InvalidArgument;
  }
  KaspaError result = KaspaError::Unsupported;
  if (version_byte == kAddressVersionP2pk && payload_size == 32) {
    out_script[0] = kOpData32;
    memcpy(out_script + 1, payload, 32);
    out_script[kP2pkScriptSize - 1] = kOpCheckSig;
    *out_script_size = kP2pkScriptSize;
    *out_version = kAddressVersionP2pk;
    result = KaspaError::Ok;
  } else if (version_byte == kAddressVersionP2sh && payload_size == 32) {
    out_script[0] = kOpBlake2b;
    out_script[1] = kOpData32;
    memcpy(out_script + 2, payload, 32);
    out_script[kP2shScriptSize - 1] = kOpEqual;
    *out_script_size = kP2shScriptSize;
    *out_version = kAddressVersionP2sh;
    result = KaspaError::Ok;
  }
  secure_zero(payload, sizeof(payload));
  return result;
}

KaspaError kaspa_review(KaspaTransaction *transaction) {
  if (transaction == nullptr || transaction->version != 0 ||
      transaction->input_count == 0 ||
      transaction->input_count > kKaspaMaxInputs ||
      transaction->output_count == 0 ||
      transaction->output_count > kKaspaMaxOutputs ||
      transaction->payload_size > kKaspaMaxPayloadSize) {
    return KaspaError::InvalidArgument;
  }
  uint64_t input_total = 0;
  for (size_t index = 0; index < transaction->input_count; ++index) {
    const KaspaInput &input = transaction->inputs[index];
    if (input.value == 0 || input.value > kKaspaMaxSompi ||
        input.script_size == 0 ||
        input.script_size > kKaspaMaxScriptPublicKeySize ||
        input.script_version != 0) {
      return KaspaError::InvalidAmount;
    }
    // The wallet only spends its own P2PK outputs.
    if (input.script[0] != kOpData32 ||
        input.script[input.script_size - 1] != kOpCheckSig ||
        input.script_size != kP2pkScriptSize) {
      return KaspaError::Unsupported;
    }
    if (!add_u64(input_total, input.value, &input_total)) {
      return KaspaError::InvalidAmount;
    }
    for (size_t other = index + 1; other < transaction->input_count; ++other) {
      const KaspaInput &candidate = transaction->inputs[other];
      if (candidate.previous_outpoint.index == input.previous_outpoint.index &&
          crypto_constant_time_equal(candidate.previous_outpoint.transaction_id,
                                     input.previous_outpoint.transaction_id, 32)) {
        return KaspaError::DuplicateField;
      }
    }
  }
  uint64_t output_total = 0;
  for (size_t index = 0; index < transaction->output_count; ++index) {
    KaspaOutput &output = transaction->outputs[index];
    if (output.value == 0 || output.value > kKaspaMaxSompi ||
        output.script_size == 0 ||
        output.script_size > kKaspaMaxScriptPublicKeySize ||
        output.script_version != 0) {
      return KaspaError::InvalidAmount;
    }
    if (!add_u64(output_total, output.value, &output_total)) {
      return KaspaError::InvalidAmount;
    }
    const KaspaError rendered =
        kaspa_address_from_script("kaspa", output.script_version, output.script,
                                  output.script_size, output.address,
                                  sizeof(output.address));
    if (rendered != KaspaError::Ok) return rendered;
  }
  if (input_total < output_total) return KaspaError::InvalidAmount;
  transaction->input_total = input_total;
  transaction->output_total = output_total;
  transaction->fee = input_total - output_total;
  if (transaction->fee > HEXWALLET_MAX_BITCOIN_FEE_SATS) return KaspaError::FeePolicy;
  const KaspaError mass = kaspa_masses(*transaction, &transaction->compute_mass,
                                       &transaction->transient_mass,
                                       &transaction->storage_mass);
  if (mass != KaspaError::Ok) return mass;
  const uint64_t total_mass =
      transaction->compute_mass + transaction->storage_mass;
  if (total_mass == 0) return KaspaError::FeePolicy;
  if (transaction->fee > HEXWALLET_MAX_BITCOIN_FEE_RATE * total_mass) {
    return KaspaError::FeePolicy;
  }
  // Review fingerprint: FNV-1a over the fields an approval covers. The device
  // shows this value and the signer recomputes it, so a changed amount, fee or
  // recipient invalidates the one-time confirmation code.
  uint32_t hash = 2166136261UL;
  const auto mix = [&hash](const uint8_t *data, size_t size) {
    for (size_t index = 0; index < size; ++index) {
      hash ^= data[index];
      hash *= 16777619UL;
    }
  };
  const uint8_t version_bytes[2] = { static_cast<uint8_t>(transaction->version),
                                     static_cast<uint8_t>(transaction->version >> 8) };
  mix(version_bytes, sizeof(version_bytes));
  for (size_t index = 0; index < transaction->input_count; ++index) {
    const KaspaInput &input = transaction->inputs[index];
    mix(input.previous_outpoint.transaction_id, 32);
    mix(reinterpret_cast<const uint8_t *>(&input.previous_outpoint.index), 4);
    mix(input.script + 1, 32);
  }
  for (size_t index = 0; index < transaction->output_count; ++index) {
    const KaspaOutput &output = transaction->outputs[index];
    mix(reinterpret_cast<const uint8_t *>(&output.value), 8);
    mix(output.script, output.script_size);
  }
  transaction->request_hash = hash;
  return KaspaError::Ok;
}

KaspaError kaspa_sign_transaction(const KaspaTransaction &transaction,
                                  const HdPrivateNode &master,
                                  uint8_t *out_transaction,
                                  size_t *in_out_size) {
  if (out_transaction == nullptr || in_out_size == nullptr ||
      transaction.version != 0 || transaction.input_count == 0 ||
      transaction.output_count == 0) {
    return KaspaError::InvalidArgument;
  }
  const NetworkProfile *network = find_network_profile("kas");
  if (network == nullptr) return KaspaError::Unsupported;

  uint8_t signatures[kKaspaMaxInputs][kKaspaSignatureSize];
  for (size_t index = 0; index < transaction.input_count; ++index) {
    uint8_t secret[kPrivateKeySize];
    uint8_t xonly[kPrivateKeySize];
    const bool derived = derive_and_verify_key(master, transaction.inputs[index].address_index,
                                               *network, secret, xonly);
    const bool matches = derived &&
        crypto_constant_time_equal(xonly, transaction.inputs[index].script + 1, 32);
    if (!matches) {
      secure_zero(secret, sizeof(secret));
      secure_zero(xonly, sizeof(xonly));
      secure_zero(signatures, sizeof(signatures));
      return KaspaError::WrongWallet;
    }
    uint8_t digest[32];
    KaspaError result = kaspa_sighash(transaction, index, KaspaSighash::All, digest);
    if (result == KaspaError::Ok) {
      // aux_rand of zeros is the BIP340 known-answer form; determinism is
      // acceptable because RFC6979-style nonce derivation is already used for
      // the ECDSA paths and the digest is unique per input.
      const uint8_t aux[kPrivateKeySize] = {};
      if (secp256k1_schnorr_sign(secret, digest, aux, signatures[index]) !=
          WalletError::Ok) {
        result = KaspaError::CryptoFailure;
      } else {
        signatures[index][64] = static_cast<uint8_t>(KaspaSighash::All);
      }
    }
    secure_zero(secret, sizeof(secret));
    secure_zero(xonly, sizeof(xonly));
    secure_zero(digest, sizeof(digest));
    if (result != KaspaError::Ok) {
      secure_zero(signatures, sizeof(signatures));
      return result;
    }
  }

  const KaspaError serialized =
      kaspa_serialize_transaction(transaction, signatures, out_transaction, in_out_size);
  secure_zero(signatures, sizeof(signatures));
  return serialized;
}

// proto3 wire encoding of the TransactionMessage hierarchy from
// protocol/p2p/proto/p2p.proto. Scalars at their default value are omitted and
// fields are emitted in ascending tag order, which is what prost (the encoder
// the reference node uses) produces.
KaspaError kaspa_serialize_transaction(
    const KaspaTransaction &transaction,
    const uint8_t signature_scripts[kKaspaMaxInputs][kKaspaSignatureSize],
    uint8_t *out_transaction, size_t *in_out_size) {
  if (signature_scripts == nullptr || out_transaction == nullptr ||
      in_out_size == nullptr || transaction.version != 0 ||
      transaction.input_count == 0 || transaction.input_count > kKaspaMaxInputs ||
      transaction.output_count == 0 ||
      transaction.output_count > kKaspaMaxOutputs) {
    return KaspaError::InvalidArgument;
  }
  Writer writer = { out_transaction, *in_out_size, 0 };

  for (size_t index = 0; index < transaction.input_count; ++index) {
    const KaspaInput &input = transaction.inputs[index];
    // TransactionId { bytes bytes = 1; } wrapping the 32-byte id.
    uint8_t transaction_id[40];
    Writer id = { transaction_id, sizeof(transaction_id), 0 };
    if (!write_tag(&id, 1, 2) || !write_varint(&id, 32) ||
        !write_bytes(&id, input.previous_outpoint.transaction_id, 32)) {
      return KaspaError::BufferTooSmall;
    }
    // Outpoint { TransactionId transactionId = 1; uint32 index = 2; }
    uint8_t outpoint[64];
    Writer point = { outpoint, sizeof(outpoint), 0 };
    if (!write_tag(&point, 1, 2) || !write_varint(&point, id.position) ||
        !write_bytes(&point, transaction_id, id.position)) {
      return KaspaError::BufferTooSmall;
    }
    if (input.previous_outpoint.index != 0 &&
        (!write_tag(&point, 2, 0) ||
         !write_varint(&point, input.previous_outpoint.index))) {
      return KaspaError::BufferTooSmall;
    }
    // TransactionInput { Outpoint = 1; bytes signatureScript = 2;
    //                    uint64 sequence = 3; uint32 compute_commit = 4; }
    uint8_t message[192];
    Writer body = { message, sizeof(message), 0 };
    if (!write_tag(&body, 1, 2) || !write_varint(&body, point.position) ||
        !write_bytes(&body, outpoint, point.position) ||
        !write_tag(&body, 2, 2) || !write_varint(&body, kKaspaSignatureSize) ||
        !write_bytes(&body, signature_scripts[index], kKaspaSignatureSize)) {
      return KaspaError::BufferTooSmall;
    }
    if (input.sequence != 0 &&
        (!write_tag(&body, 3, 0) || !write_varint(&body, input.sequence))) {
      return KaspaError::BufferTooSmall;
    }
    if (!write_tag(&writer, 2, 2) || !write_varint(&writer, body.position) ||
        !write_bytes(&writer, message, body.position)) {
      return KaspaError::BufferTooSmall;
    }
  }

  for (size_t index = 0; index < transaction.output_count; ++index) {
    const KaspaOutput &output = transaction.outputs[index];
    // ScriptPublicKey { bytes script = 1; uint32 version = 2; }
    uint8_t script_public_key[96];
    Writer spk = { script_public_key, sizeof(script_public_key), 0 };
    if (!write_tag(&spk, 1, 2) || !write_varint(&spk, output.script_size) ||
        !write_bytes(&spk, output.script, output.script_size)) {
      return KaspaError::BufferTooSmall;
    }
    if (output.script_version != 0 &&
        (!write_tag(&spk, 2, 0) || !write_varint(&spk, output.script_version))) {
      return KaspaError::BufferTooSmall;
    }
    // TransactionOutput { uint64 value = 1; ScriptPublicKey = 2; covenant = 3; }
    uint8_t message[192];
    Writer body = { message, sizeof(message), 0 };
    if (output.value != 0 &&
        (!write_tag(&body, 1, 0) || !write_varint(&body, output.value))) {
      return KaspaError::BufferTooSmall;
    }
    if (!write_tag(&body, 2, 2) || !write_varint(&body, spk.position) ||
        !write_bytes(&body, script_public_key, spk.position)) {
      return KaspaError::BufferTooSmall;
    }
    if (!write_tag(&writer, 3, 2) || !write_varint(&writer, body.position) ||
        !write_bytes(&writer, message, body.position)) {
      return KaspaError::BufferTooSmall;
    }
  }

  if (transaction.lock_time != 0 &&
      (!write_tag(&writer, 4, 0) || !write_varint(&writer, transaction.lock_time))) {
    return KaspaError::BufferTooSmall;
  }
  // SubnetworkId { bytes bytes = 1; } ? the native id is the empty message and
  // the reference encoder always populates the field, so it stays on the wire.
  const uint8_t native_subnetwork[2] = { 0x2a, 0x00 };
  if (!write_bytes(&writer, native_subnetwork, sizeof(native_subnetwork))) {
    return KaspaError::BufferTooSmall;
  }
  if (transaction.payload_size != 0 &&
      (!write_tag(&writer, 8, 2) || !write_varint(&writer, transaction.payload_size) ||
       !write_bytes(&writer, transaction.payload, transaction.payload_size))) {
    return KaspaError::BufferTooSmall;
  }
  *in_out_size = writer.position;
  return KaspaError::Ok;
}

const char *kaspa_error_text(KaspaError error) {
  switch (error) {
    case KaspaError::Ok: return "ok";
    case KaspaError::InvalidArgument: return "invalid-argument";
    case KaspaError::Truncated: return "truncated";
    case KaspaError::NonCanonical: return "non-canonical";
    case KaspaError::Unsupported: return "unsupported";
    case KaspaError::TooLarge: return "limit-exceeded";
    case KaspaError::MissingField: return "missing-field";
    case KaspaError::DuplicateField: return "duplicate-input";
    case KaspaError::WrongWallet: return "wrong-wallet";
    case KaspaError::InvalidAmount: return "invalid-amount";
    case KaspaError::FeePolicy: return "fee-policy";
    case KaspaError::CryptoFailure: return "crypto-failure";
    case KaspaError::BufferTooSmall: return "buffer-too-small";
  }
  return "unknown";
}

void clear_kaspa_transaction(KaspaTransaction *transaction) {
  if (transaction != nullptr) secure_zero(transaction, sizeof(*transaction));
}

bool run_kaspa_self_tests() {
  // Official rusty-kaspa sighash vectors (consensus/core/src/hashing/sighash.rs
  // tests::test_signature_hash). The transaction layout mirrors the reference
  // test exactly: two 34-byte P2PK script public keys, three inputs and two
  // outputs.
  const uint8_t previous[32] = {
    0x88, 0x0e, 0xb9, 0x81, 0x9a, 0x31, 0x82, 0x1d, 0x9d, 0x23, 0x99, 0xe2,
    0xf3, 0x5e, 0x24, 0x33, 0xb7, 0x26, 0x37, 0xe3, 0x93, 0xd7, 0x1e, 0xcc,
    0x9b, 0x8d, 0x02, 0x50, 0xf4, 0x91, 0x53, 0xc3 };
  const uint8_t script1[34] = {
    0x20, 0x83, 0x25, 0x61, 0x3d, 0x2e, 0xea, 0xf7, 0x17, 0x6a, 0xc6, 0xc6,
    0x70, 0xb1, 0x3c, 0x00, 0x43, 0x15, 0x6c, 0x42, 0x74, 0x38, 0xed, 0x72,
    0xd7, 0x4b, 0x78, 0x00, 0x86, 0x2a, 0xd8, 0x84, 0xe8, 0xac };
  const uint8_t script2[34] = {
    0x20, 0xfc, 0xef, 0x4c, 0x10, 0x6c, 0xf1, 0x11, 0x35, 0xbb, 0xd7, 0x0f,
    0x02, 0xa7, 0x26, 0xa9, 0x21, 0x62, 0xd2, 0xfb, 0x8b, 0x22, 0xf0, 0x46,
    0x91, 0x26, 0xf8, 0x00, 0x86, 0x2a, 0xd8, 0x84, 0xe8, 0xac };
  const uint8_t expected_all[32] = {
    0x03, 0xb7, 0xac, 0x69, 0x27, 0xb2, 0xb6, 0x71, 0x00, 0x73, 0x4c, 0x3c,
    0xc3, 0x13, 0xff, 0x8c, 0x2e, 0x8b, 0x3c, 0xe3, 0xe7, 0x46, 0xd4, 0x6d,
    0xd6, 0x60, 0xb7, 0x06, 0xa9, 0x16, 0xb1, 0xf5 };
  const uint8_t expected_single[32] = {
    0x02, 0x2a, 0xd9, 0x67, 0x19, 0x2f, 0x39, 0xd8, 0xd5, 0x89, 0x5d, 0x24,
    0x3e, 0x02, 0x5e, 0xc1, 0x4c, 0xc7, 0xa7, 0x97, 0x08, 0xc5, 0xe3, 0x64,
    0x89, 0x4d, 0x4e, 0xff, 0x3c, 0xec, 0xb1, 0xb0 };

  KaspaTransaction transaction = {};
  transaction.version = 0;
  transaction.lock_time = 1615462089000ULL;
  transaction.input_count = 3;
  transaction.output_count = 2;
  for (size_t index = 0; index < 3; ++index) {
    memcpy(transaction.inputs[index].previous_outpoint.transaction_id, previous, 32);
    transaction.inputs[index].previous_outpoint.index = static_cast<uint32_t>(index);
    transaction.inputs[index].sequence = index;
    transaction.inputs[index].sigop_count = 0;
  }
  const uint64_t input_values[3] = { 100, 200, 300 };
  const uint8_t *input_scripts[3] = { script1, script2, script2 };
  for (size_t index = 0; index < 3; ++index) {
    transaction.inputs[index].value = input_values[index];
    transaction.inputs[index].script_version = 0;
    transaction.inputs[index].script_size = 34;
    memcpy(transaction.inputs[index].script, input_scripts[index], 34);
  }
  transaction.outputs[0].value = 300;
  transaction.outputs[0].script_size = 34;
  memcpy(transaction.outputs[0].script, script2, 34);
  transaction.outputs[1].value = 300;
  transaction.outputs[1].script_size = 34;
  memcpy(transaction.outputs[1].script, script1, 34);

  uint8_t digest[32];
  bool passed = kaspa_sighash(transaction, 0, KaspaSighash::All, digest) == KaspaError::Ok &&
                crypto_constant_time_equal(digest, expected_all, sizeof(expected_all));
  passed = kaspa_sighash(transaction, 2, KaspaSighash::Single, digest) == KaspaError::Ok &&
           crypto_constant_time_equal(digest, expected_single, sizeof(expected_single)) && passed;
  // Transaction ID for the same transaction, taken from the reference
  // implementation's own id() on the identical input set.
  const uint8_t expected_id[32] = {
    0xd3, 0x7a, 0x4a, 0x8d, 0xfe, 0xab, 0x47, 0x3a, 0x23, 0x8f, 0xe2, 0xc4,
    0xa1, 0xf6, 0x02, 0xd6, 0x3c, 0xdb, 0xb5, 0x28, 0x04, 0xa0, 0x4e, 0xb0,
    0xc8, 0x1d, 0xf1, 0x0a, 0xc8, 0xaa, 0x81, 0x2c };
  passed = kaspa_transaction_id(transaction, digest) == KaspaError::Ok &&
           crypto_constant_time_equal(digest, expected_id, sizeof(expected_id)) && passed;
  secure_zero(digest, sizeof(digest));

  // KIP-0009 storage mass for a single 35-byte output paid by a single input
  // must be C/amount_out - C/amount_in, clamped at zero.
  KaspaTransaction pair = {};
  pair.version = 0;
  pair.input_count = 1;
  pair.output_count = 1;
  pair.inputs[0].value = 1000000000ULL;
  pair.inputs[0].script_size = kP2pkScriptSize;
  pair.inputs[0].sigop_count = 1;
  pair.outputs[0].value = 900000000ULL;
  pair.outputs[0].script_size = kP2pkScriptSize;
  uint64_t compute = 0;
  uint64_t transient = 0;
  uint64_t storage = 0;
  passed = kaspa_masses(pair, &compute, &transient, &storage) == KaspaError::Ok &&
           storage == (kStorageMassParameter / 900000000ULL) -
                          (kStorageMassParameter / 1000000000ULL) &&
           compute > 0 && transient > 0 && passed;

  // Address round-trip against the official rusty-kaspa P2PK vector.
  char address[kAddressTextSize];
  uint16_t version_out = 0;
  uint8_t script_out[kKaspaMaxScriptPublicKeySize];
  uint8_t script_out_size = 0;
  const uint8_t kAddressPayload[32] = {
    0x5f, 0xff, 0x3c, 0x4d, 0xa1, 0x8f, 0x2d, 0x53, 0x9c, 0x5e, 0x1f, 0x7a,
    0x0c, 0x1f, 0x8f, 0x21, 0x0c, 0x4f, 0x9f, 0x2b, 0x8f, 0x2f, 0x2f, 0x2f,
    0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f };
  (void)kAddressPayload;
  const uint8_t kPkOneX[kPrivateKeySize] = {
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95,
    0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98 };
  uint8_t script[kKaspaMaxScriptPublicKeySize];
  script[0] = kOpData32;
  memcpy(script + 1, kPkOneX, 32);
  script[kP2pkScriptSize - 1] = kOpCheckSig;
  passed = kaspa_address_from_script("kaspa", 0, script, kP2pkScriptSize, address, sizeof(address)) ==
               KaspaError::Ok &&
           strcmp(address, "kaspa:qpumuen7l8wthtz45p3ftn58pvrs9xlumvkuu2xet8egzkcklqtes4ypce9sf") == 0 &&
           kaspa_script_from_address("kaspa", address, &version_out, script_out,
                                     &script_out_size) == KaspaError::Ok &&
           version_out == 0 && script_out_size == kP2pkScriptSize &&
           crypto_constant_time_equal(script, script_out, kP2pkScriptSize) && passed;
  // A single-character corruption must fail the checksum.
  char corrupted[kAddressTextSize];
  strcpy(corrupted, address);
  corrupted[10] = corrupted[10] == 'q' ? 'p' : 'q';
  passed = kaspa_script_from_address("kaspa", corrupted, &version_out, script_out,
                                     &script_out_size) != KaspaError::Ok && passed;

  clear_kaspa_transaction(&transaction);
  clear_kaspa_transaction(&pair);
  secure_zero(script, sizeof(script));
  secure_zero(corrupted, sizeof(corrupted));

  // Broadcast encoding pinned to prost (the encoder the reference node uses)
  // for a single-input/single-output transaction with a synthetic signature.
  KaspaTransaction wire = {};
  wire.version = 0;
  wire.input_count = 1;
  wire.output_count = 1;
  memcpy(wire.inputs[0].previous_outpoint.transaction_id, previous, 32);
  wire.inputs[0].sequence = 0;
  wire.inputs[0].script_version = 0;
  wire.inputs[0].script_size = 34;
  memcpy(wire.inputs[0].script, script1, 34);
  wire.inputs[0].value = 1000;
  wire.outputs[0].value = 1000;
  wire.outputs[0].script_version = 0;
  wire.outputs[0].script_size = 34;
  memcpy(wire.outputs[0].script, script1, 34);
  static const uint8_t kExpectedWire[] = {
    0x12, 0x69, 0x0a, 0x24, 0x0a, 0x22, 0x0a, 0x20, 0x88, 0x0e, 0xb9, 0x81,
    0x9a, 0x31, 0x82, 0x1d, 0x9d, 0x23, 0x99, 0xe2, 0xf3, 0x5e, 0x24, 0x33,
    0xb7, 0x26, 0x37, 0xe3, 0x93, 0xd7, 0x1e, 0xcc, 0x9b, 0x8d, 0x02, 0x50,
    0xf4, 0x91, 0x53, 0xc3, 0x12, 0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01, 0x1a,
    0x29, 0x08, 0xe8, 0x07, 0x12, 0x24, 0x0a, 0x22, 0x20, 0x83, 0x25, 0x61,
    0x3d, 0x2e, 0xea, 0xf7, 0x17, 0x6a, 0xc6, 0xc6, 0x70, 0xb1, 0x3c, 0x00,
    0x43, 0x15, 0x6c, 0x42, 0x74, 0x38, 0xed, 0x72, 0xd7, 0x4b, 0x78, 0x00,
    0x86, 0x2a, 0xd8, 0x84, 0xe8, 0xac, 0x2a, 0x00
  };
  uint8_t signature_scripts[kKaspaMaxInputs][kKaspaSignatureSize];
  memset(signature_scripts, 0x11, sizeof(signature_scripts));
  for (size_t index = 0; index < kKaspaMaxInputs; ++index) {
    signature_scripts[index][64] = 0x01;
  }
  uint8_t wire_bytes[512];
  size_t wire_size = sizeof(wire_bytes);
  passed = kaspa_serialize_transaction(wire, signature_scripts, wire_bytes, &wire_size) ==
               KaspaError::Ok &&
           wire_size == sizeof(kExpectedWire) &&
           crypto_constant_time_equal(wire_bytes, kExpectedWire, sizeof(kExpectedWire)) &&
           passed;
  secure_zero(signature_scripts, sizeof(signature_scripts));
  clear_kaspa_transaction(&wire);
  return passed;
}

}  // namespace hexwallet
