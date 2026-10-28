#include "ErgoTransaction.h"

#include <mbedtls/bignum.h>
#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoExtended.h"
#include "WalletAltAddresses.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

constexpr uint8_t kErgoNetworkMainnet = 0;
constexpr size_t kErgoMaxInputs = 16;
constexpr size_t kErgoMaxDataInputs = 16;
constexpr size_t kErgoMaxTokenIds = 32;
constexpr size_t kErgoMaxOutputs = 32;
constexpr size_t kErgoMaxBoxTokens = 16;
constexpr size_t kErgoMaxRegisters = 6;
constexpr size_t kErgoMaxTreeSize = 512;
constexpr size_t kErgoMaxRegisterSize = 320;
constexpr size_t kErgoMaxMessage = 2048;
constexpr size_t kErgoProofSize = 56;
// Segregated ErgoTree wrapper the prover builds around the proposition before
// hashing it into the Fiat-Shamir transcript:
//   header v0 | 1 constant | (SSigmaProp, ProveDlog, point) | ConstPlaceholder(0)
constexpr uint8_t kErgoFiatShamirPrefix[4] = {0x10, 0x01, 0x08, 0xcd};
constexpr uint8_t kErgoFiatShamirSuffix[2] = {0x73, 0x00};
constexpr uint8_t kErgoP2pkTreePrefix[3] = {0x00, 0x08, 0xcd};
constexpr char kErgoNonceTag[] = "ergprovedlog/nonce";
constexpr char kErgoAuxTag[] = "erg/aux";

struct ErgoToken {
  uint16_t index;
  uint64_t amount;
};

struct ErgoInput {
  const uint8_t *box_id;
  const uint8_t *tree;
  uint16_t tree_size;
};

struct ErgoOutput {
  uint64_t value;
  uint32_t creation_height;
  const uint8_t *tree;
  uint16_t tree_size;
  uint8_t token_count;
  ErgoToken tokens[kErgoMaxBoxTokens];
  uint8_t register_count;
  const uint8_t *registers[kErgoMaxRegisters];
  uint16_t register_sizes[kErgoMaxRegisters];
};

struct ErgoRequest {
  uint8_t network;
  uint64_t host_input_total;
  uint8_t input_count;
  ErgoInput inputs[kErgoMaxInputs];
  uint8_t data_input_count;
  const uint8_t *data_inputs[kErgoMaxDataInputs];
  uint8_t token_id_count;
  const uint8_t *token_ids[kErgoMaxTokenIds];
  uint8_t output_count;
  ErgoOutput outputs[kErgoMaxOutputs];
};

struct Reader {
  const uint8_t *data;
  size_t size;
  size_t offset;

  bool take(const uint8_t **out, size_t count) {
    if (count > size - offset) return false;
    *out = data + offset;
    offset += count;
    return true;
  }
  bool u8(uint8_t *out) {
    const uint8_t *p = nullptr;
    if (!take(&p, 1)) return false;
    *out = *p;
    return true;
  }
  bool u16_le(uint16_t *out) {
    const uint8_t *p = nullptr;
    if (!take(&p, 2)) return false;
    *out = static_cast<uint16_t>(p[0] | (p[1] << 8));
    return true;
  }
  bool u32_le(uint32_t *out) {
    const uint8_t *p = nullptr;
    if (!take(&p, 4)) return false;
    *out = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
    return true;
  }
  bool u64_be(uint64_t *out) {
    const uint8_t *p = nullptr;
    if (!take(&p, 8)) return false;
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | p[i];
    *out = value;
    return true;
  }
};

ChainError parse_payload(const uint8_t *payload, size_t size,
                         ErgoRequest *request) {
  if (payload == nullptr || request == nullptr) return ChainError::InvalidArgument;
  if (size < 5 || memcmp(payload, "ERG1", 4) != 0) return ChainError::Malformed;
  memset(request, 0, sizeof(*request));
  Reader reader = {payload, size, 4};
  if (!reader.u8(&request->network)) return ChainError::Malformed;
  if (request->network != kErgoNetworkMainnet) return ChainError::WrongNetwork;
  if (!reader.u64_be(&request->host_input_total)) return ChainError::Malformed;
  if (!reader.u8(&request->input_count)) return ChainError::Malformed;
  if (request->input_count == 0 || request->input_count > kErgoMaxInputs) {
    return ChainError::Malformed;
  }
  for (uint8_t i = 0; i < request->input_count; ++i) {
    ErgoInput *input = &request->inputs[i];
    if (!reader.take(&input->box_id, 32) || !reader.u16_le(&input->tree_size)) {
      return ChainError::Malformed;
    }
    if (input->tree_size < sizeof(kErgoP2pkTreePrefix) ||
        input->tree_size > kErgoMaxTreeSize) {
      return ChainError::Malformed;
    }
    if (!reader.take(&input->tree, input->tree_size)) return ChainError::Malformed;
  }
  if (!reader.u8(&request->data_input_count) ||
      request->data_input_count > kErgoMaxDataInputs) {
    return ChainError::Malformed;
  }
  for (uint8_t i = 0; i < request->data_input_count; ++i) {
    if (!reader.take(&request->data_inputs[i], 32)) return ChainError::Malformed;
  }
  if (!reader.u8(&request->token_id_count) ||
      request->token_id_count > kErgoMaxTokenIds) {
    return ChainError::Malformed;
  }
  for (uint8_t i = 0; i < request->token_id_count; ++i) {
    if (!reader.take(&request->token_ids[i], 32)) return ChainError::Malformed;
  }
  if (!reader.u8(&request->output_count) || request->output_count == 0 ||
      request->output_count > kErgoMaxOutputs) {
    return ChainError::Malformed;
  }
  for (uint8_t i = 0; i < request->output_count; ++i) {
    ErgoOutput *output = &request->outputs[i];
    if (!reader.u64_be(&output->value) ||
        !reader.u32_le(&output->creation_height) ||
        !reader.u16_le(&output->tree_size)) {
      return ChainError::Malformed;
    }
    if (output->tree_size == 0 || output->tree_size > kErgoMaxTreeSize) {
      return ChainError::Malformed;
    }
    if (!reader.take(&output->tree, output->tree_size)) return ChainError::Malformed;
    if (!reader.u8(&output->token_count) ||
        output->token_count > kErgoMaxBoxTokens) {
      return ChainError::Malformed;
    }
    for (uint8_t t = 0; t < output->token_count; ++t) {
      uint16_t index = 0;
      if (!reader.u16_le(&index) || !reader.u64_be(&output->tokens[t].amount)) {
        return ChainError::Malformed;
      }
      if (index >= request->token_id_count) return ChainError::Malformed;
      if (output->tokens[t].amount == 0) return ChainError::InvalidAmount;
      output->tokens[t].index = index;
    }
    if (!reader.u8(&output->register_count) ||
        output->register_count > kErgoMaxRegisters) {
      return ChainError::Malformed;
    }
    for (uint8_t r = 0; r < output->register_count; ++r) {
      if (!reader.u16_le(&output->register_sizes[r])) return ChainError::Malformed;
      if (output->register_sizes[r] == 0 ||
          output->register_sizes[r] > kErgoMaxRegisterSize) {
        return ChainError::Malformed;
      }
      if (!reader.take(&output->registers[r], output->register_sizes[r])) {
        return ChainError::Malformed;
      }
    }
  }
  if (reader.offset != reader.size) return ChainError::Malformed;
  return ChainError::Ok;
}

struct Writer {
  uint8_t *data;
  size_t capacity;
  size_t offset;
  bool ok = true;

  void raw(const uint8_t *bytes, size_t count) {
    if (!ok) return;
    if (count > capacity - offset) {
      ok = false;
      return;
    }
    memcpy(data + offset, bytes, count);
    offset += count;
  }
  // Ergo's SCALE-like variable length unsigned integer (unsigned LEB128).
  void vlq(uint64_t value) {
    if (!ok) return;
    uint8_t encoded[10];
    size_t count = 0;
    do {
      uint8_t byte = static_cast<uint8_t>(value & 0x7f);
      value >>= 7;
      if (value != 0) byte |= 0x80;
      encoded[count++] = byte;
    } while (value != 0);
    raw(encoded, count);
  }
};

const uint8_t *tokens_digest_at(const ErgoRequest &request, uint16_t index) {
  return request.token_ids[index];
}

// Transaction id preimage: the transaction serialized with empty spending
// proofs. Layout confirmed byte-for-byte against mainnet transaction ids.
bool build_message(const ErgoRequest &request, uint8_t *out, size_t capacity,
                   size_t *out_size) {
  Writer writer = {out, capacity, 0};
  writer.vlq(request.input_count);
  for (uint8_t i = 0; i < request.input_count; ++i) {
    writer.raw(request.inputs[i].box_id, 32);
    // Empty proof bytes and empty context extension.
    writer.vlq(0);
    writer.vlq(0);
  }
  writer.vlq(request.data_input_count);
  for (uint8_t i = 0; i < request.data_input_count; ++i) {
    writer.raw(request.data_inputs[i], 32);
  }
  writer.vlq(request.token_id_count);
  for (uint8_t i = 0; i < request.token_id_count; ++i) {
    writer.raw(tokens_digest_at(request, i), 32);
  }
  writer.vlq(request.output_count);
  for (uint8_t i = 0; i < request.output_count; ++i) {
    const ErgoOutput &output = request.outputs[i];
    writer.vlq(output.value);
    writer.raw(output.tree, output.tree_size);
    writer.vlq(output.creation_height);
    writer.vlq(output.token_count);
    for (uint8_t t = 0; t < output.token_count; ++t) {
      writer.vlq(output.tokens[t].index);
      writer.vlq(output.tokens[t].amount);
    }
    writer.vlq(output.register_count);
    for (uint8_t r = 0; r < output.register_count; ++r) {
      writer.raw(output.registers[r], output.register_sizes[r]);
    }
  }
  if (!writer.ok) return false;
  *out_size = writer.offset;
  return true;
}

bool is_p2pk(const uint8_t *tree, size_t size) {
  return size == sizeof(kErgoP2pkTreePrefix) + kCompressedPublicKeySize &&
         memcmp(tree, kErgoP2pkTreePrefix, sizeof(kErgoP2pkTreePrefix)) == 0;
}

void hex_prefix(const uint8_t *data, size_t size, size_t chars, char *out,
                size_t out_size) {
  static const char kDigits[] = "0123456789abcdef";
  const size_t limit = chars < size * 2 ? chars : size * 2;
  size_t i = 0;
  for (; i < limit && i + 1 < out_size; ++i) {
    const uint8_t byte = data[i / 2];
    out[i] = kDigits[(i % 2 == 0) ? (byte >> 4) : (byte & 0x0f)];
  }
  out[i] = '\0';
}

// secp256k1 generator multiplication goes through the same audited helper the
// rest of the wallet uses, so there is a single ECP implementation on device.
bool multiply_generator(const uint8_t scalar_be[32], uint8_t out[33]) {
  return public_key_from_private(scalar_be, out) == WalletError::Ok;
}
bool derive_public_key(const uint8_t private_key[32], uint8_t out[33]) {
  return multiply_generator(private_key, out);
}

// Ergo's EIP-2333-free Schnorr nonce: BIP340-style with a separate domain tag
// per sigma protocol, so a ProveDlog nonce can never collide with another
// proposition's nonce.
bool derive_nonce(const uint8_t private_key[32], const uint8_t *public_key,
                  const uint8_t *message, size_t message_size,
                  const uint8_t aux_rand[32], uint8_t out[32]) {
  uint8_t aux_input[sizeof(kErgoAuxTag) - 1 + 32];
  memcpy(aux_input, kErgoAuxTag, sizeof(kErgoAuxTag) - 1);
  memcpy(aux_input + sizeof(kErgoAuxTag) - 1, aux_rand, 32);
  uint8_t aux_hash[32];
  if (!crypto_blake2b(aux_input, sizeof(aux_input), aux_hash, sizeof(aux_hash))) {
    return false;
  }
  uint8_t masked[32];
  for (size_t i = 0; i < 32; ++i) masked[i] = private_key[i] ^ aux_hash[i];

  uint8_t input[sizeof(kErgoNonceTag) - 1 + 32 + 33 + kErgoMaxMessage];
  size_t offset = 0;
  memcpy(input, kErgoNonceTag, sizeof(kErgoNonceTag) - 1);
  offset += sizeof(kErgoNonceTag) - 1;
  memcpy(input + offset, masked, 32);
  offset += 32;
  memcpy(input + offset, public_key, 33);
  offset += 33;
  if (message_size > kErgoMaxMessage) return false;
  memcpy(input + offset, message, message_size);
  offset += message_size;
  const bool ok = crypto_blake2b(input, offset, out, 32);
  secure_zero(aux_hash, sizeof(aux_hash));
  secure_zero(masked, sizeof(masked));
  return ok;
}

// e = BLAKE2b-256(LEAF(0x01) || i16_len(tree) || tree || i16_len(a) || a || msg)
// truncated to the 24-byte soundness parameter.
bool fiat_shamir_challenge(const uint8_t *public_key, const uint8_t *nonce_point,
                           const uint8_t *message, size_t message_size,
                           uint8_t out[24]) {
  uint8_t tree[sizeof(kErgoFiatShamirPrefix) + 33 + sizeof(kErgoFiatShamirSuffix)];
  memcpy(tree, kErgoFiatShamirPrefix, sizeof(kErgoFiatShamirPrefix));
  memcpy(tree + sizeof(kErgoFiatShamirPrefix), public_key, 33);
  memcpy(tree + sizeof(kErgoFiatShamirPrefix) + 33, kErgoFiatShamirSuffix,
         sizeof(kErgoFiatShamirSuffix));
  const size_t tree_size = sizeof(tree);

  const size_t total = 1 + 2 + tree_size + 2 + 33 + message_size;
  if (total > 1 + 2 + tree_size + 2 + 33 + kErgoMaxMessage) return false;
  uint8_t transcript[1 + 2 + sizeof(tree) + 2 + 33 + kErgoMaxMessage];
  size_t offset = 0;
  transcript[offset++] = 0x01;
  transcript[offset++] = static_cast<uint8_t>(tree_size >> 8);
  transcript[offset++] = static_cast<uint8_t>(tree_size & 0xff);
  memcpy(transcript + offset, tree, tree_size);
  offset += tree_size;
  transcript[offset++] = 0;
  transcript[offset++] = 33;
  memcpy(transcript + offset, nonce_point, 33);
  offset += 33;
  memcpy(transcript + offset, message, message_size);
  offset += message_size;
  uint8_t hash[32];
  const bool ok = crypto_blake2b(transcript, offset, hash, sizeof(hash));
  if (ok) memcpy(out, hash, 24);
  secure_zero(hash, sizeof(hash));
  return ok;
}

// z = r + e * d (mod n)
bool compute_response(const uint8_t private_key[32], const uint8_t nonce[32],
                      const uint8_t challenge[24], uint8_t out[32]) {
  static const char kOrderHex[] =
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
  mbedtls_mpi order, z, r, e, d;
  mbedtls_mpi_init(&order);
  mbedtls_mpi_init(&z);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&e);
  mbedtls_mpi_init(&d);
  int result = mbedtls_mpi_read_string(&order, 16, kOrderHex);
  if (result == 0) result = mbedtls_mpi_read_binary(&r, nonce, 32);
  if (result == 0) result = mbedtls_mpi_read_binary(&e, challenge, 24);
  if (result == 0) result = mbedtls_mpi_read_binary(&d, private_key, 32);
  if (result == 0) result = mbedtls_mpi_mul_mpi(&z, &e, &d);
  if (result == 0) result = mbedtls_mpi_mod_mpi(&z, &z, &order);
  if (result == 0) result = mbedtls_mpi_add_mpi(&z, &z, &r);
  if (result == 0) result = mbedtls_mpi_mod_mpi(&z, &z, &order);
  if (result == 0) result = mbedtls_mpi_write_binary(&z, out, 32);
  mbedtls_mpi_free(&order);
  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&e);
  mbedtls_mpi_free(&d);
  return result == 0;
}

ChainError render_tree(const uint8_t *tree, size_t tree_size, char *out,
                       size_t out_size) {
  if (is_p2pk(tree, tree_size)) {
    size_t size = out_size;
    const WalletError error =
        address_ergo(tree + sizeof(kErgoP2pkTreePrefix), out, &size);
    if (error != WalletError::Ok) return ChainError::BufferTooSmall;
    return ChainError::Ok;
  }
  uint8_t hash[32];
  if (!crypto_blake2b(tree, tree_size, hash, sizeof(hash))) {
    return ChainError::CryptoFailure;
  }
  char hex[17];
  hex_prefix(hash, sizeof(hash), 16, hex, sizeof(hex));
  snprintf(out, out_size, "SCRIPT %s", hex);
  secure_zero(hash, sizeof(hash));
  return ChainError::Ok;
}

}  // namespace

ChainError ergo_review_payload(const uint8_t *payload, size_t size,
                               const char *sender, ChainReview *review,
                               uint8_t digest[32]) {
  if (payload == nullptr || sender == nullptr || review == nullptr ||
      digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  ErgoRequest request;
  ChainError error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;

  uint8_t message[kErgoMaxMessage];
  size_t message_size = 0;
  if (!build_message(request, message, sizeof(message), &message_size)) {
    return ChainError::BufferTooSmall;
  }
  if (!crypto_blake2b(message, message_size, digest, 32)) {
    secure_zero(message, sizeof(message));
    return ChainError::CryptoFailure;
  }
  secure_zero(message, sizeof(message));

  memset(review, 0, sizeof(*review));
  strncpy(review->symbol, "ERG", sizeof(review->symbol) - 1);
  strncpy(review->sender, sender, sizeof(review->sender) - 1);

  uint64_t total_out = 0;
  int payment = -1;
  uint32_t change_count = 0;
  uint64_t change_value = 0;
  for (uint8_t i = 0; i < request.output_count; ++i) {
    total_out += request.outputs[i].value;
    char candidate[kChainMaxAddress];
    error = render_tree(request.outputs[i].tree, request.outputs[i].tree_size,
                        candidate, sizeof(candidate));
    if (error != ChainError::Ok) return error;
    if (strcmp(candidate, sender) != 0) {
      // The screen has room for one recipient. A second external output would
      // be signed without ever being shown, so the review refuses instead.
      if (payment >= 0) return ChainError::Unsupported;
      payment = i;
    } else {
      ++change_count;
      change_value += request.outputs[i].value;
    }
  }

  // Everything that leaves the wallet is exactly one output plus its tokens;
  // every other output is change back to the sending address.
  const uint8_t payment_tokens =
      payment >= 0 ? request.outputs[payment].token_count : 0;
  if (payment >= 0) {
    error = render_tree(request.outputs[payment].tree,
                        request.outputs[payment].tree_size, review->recipient,
                        sizeof(review->recipient));
    if (error != ChainError::Ok) return error;
    if (!chain_format_units(request.outputs[payment].value, 9, "ERG",
                            review->amount, sizeof(review->amount))) {
      return ChainError::BufferTooSmall;
    }
  } else {
    // Every output returns to this wallet, so only the fee can be lost.
    strncpy(review->recipient, sender, sizeof(review->recipient) - 1);
    if (!chain_format_units(change_value, 9, "ERG", review->amount,
                            sizeof(review->amount))) {
      return ChainError::BufferTooSmall;
    }
  }

  if (request.host_input_total >= total_out) {
    const uint64_t fee = request.host_input_total - total_out;
    char amount[kChainMaxAmount];
    if (!chain_format_units(fee, 9, "ERG", amount, sizeof(amount))) {
      return ChainError::BufferTooSmall;
    }
    snprintf(review->fee, sizeof(review->fee), "%s HOST", amount);
  } else {
    strncpy(review->fee, "INPUTS UNDERFLOW", sizeof(review->fee) - 1);
  }

  char txid[17];
  hex_prefix(digest, 32, 16, txid, sizeof(txid));
  const int header = snprintf(review->extra, sizeof(review->extra),
                              "TX %s\nIN %u OUT %u CHG %u\n", txid,
                              static_cast<unsigned>(request.input_count),
                              static_cast<unsigned>(request.output_count),
                              static_cast<unsigned>(change_count));
  if (header < 0 || static_cast<size_t>(header) >= sizeof(review->extra)) {
    return ChainError::BufferTooSmall;
  }
  // Every token on the payment output is part of what leaves; listing them all
  // is mandatory, so no room means no signature.
  size_t used = static_cast<size_t>(header);
  for (uint8_t t = 0; t < payment_tokens; ++t) {
    const ErgoToken &token = request.outputs[payment].tokens[t];
    const uint8_t *id = request.token_ids[token.index];
    const int line = snprintf(review->extra + used, sizeof(review->extra) - used,
                              "T %02x%02x%02x%02x %llu\n", id[0], id[1], id[2],
                              id[3],
                              static_cast<unsigned long long>(token.amount));
    if (line < 0 || static_cast<size_t>(line) >= sizeof(review->extra) - used) {
      return ChainError::BufferTooSmall;
    }
    used += static_cast<size_t>(line);
  }
  return ChainError::Ok;
}

ChainError ergo_sign_payload(const uint8_t *payload, size_t size,
                             const uint8_t private_key[32], uint8_t *out,
                             size_t *in_out_size) {
  if (payload == nullptr || private_key == nullptr || out == nullptr ||
      in_out_size == nullptr) {
    return ChainError::InvalidArgument;
  }
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  ErgoRequest request;
  ChainError error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;

  uint8_t public_key[33];
  if (!derive_public_key(private_key, public_key)) {
    return ChainError::CryptoFailure;
  }
  // Only sign when every input is P2PK for this key: a proof for any other
  // proposition would be rejected by the chain and would hide what is signed.
  for (uint8_t i = 0; i < request.input_count; ++i) {
    const ErgoInput &input = request.inputs[i];
    if (!is_p2pk(input.tree, input.tree_size) ||
        memcmp(input.tree + sizeof(kErgoP2pkTreePrefix), public_key, 33) != 0) {
      secure_zero(public_key, sizeof(public_key));
      return ChainError::Unsupported;
    }
  }

  uint8_t message[kErgoMaxMessage];
  size_t message_size = 0;
  if (!build_message(request, message, sizeof(message), &message_size)) {
    secure_zero(public_key, sizeof(public_key));
    return ChainError::BufferTooSmall;
  }

  static const uint8_t kAuxRand[32] = {};
  uint8_t nonce[32];
  uint8_t nonce_point[33];
  uint8_t challenge[24];
  uint8_t response[32];
  bool ok = derive_nonce(private_key, public_key, message, message_size,
                         kAuxRand, nonce) &&
            multiply_generator(nonce, nonce_point) &&
            fiat_shamir_challenge(public_key, nonce_point, message,
                                  message_size, challenge) &&
            compute_response(private_key, nonce, challenge, response);
  secure_zero(nonce, sizeof(nonce));
  secure_zero(message, sizeof(message));
  if (!ok) {
    secure_zero(public_key, sizeof(public_key));
    secure_zero(response, sizeof(response));
    return ChainError::CryptoFailure;
  }

  uint8_t proof[kErgoProofSize];
  memcpy(proof, challenge, sizeof(challenge));
  memcpy(proof + sizeof(challenge), response, sizeof(response));

  // Emit the full signed transaction: the same preimage with `proof || empty
  // extension` in place of the two empty bytes for each input.
  Writer writer = {out, capacity, 0};
  writer.vlq(request.input_count);
  for (uint8_t i = 0; i < request.input_count; ++i) {
    writer.raw(request.inputs[i].box_id, 32);
    writer.vlq(kErgoProofSize);
    writer.raw(proof, sizeof(proof));
    writer.vlq(0);
  }
  writer.vlq(request.data_input_count);
  for (uint8_t i = 0; i < request.data_input_count; ++i) {
    writer.raw(request.data_inputs[i], 32);
  }
  writer.vlq(request.token_id_count);
  for (uint8_t i = 0; i < request.token_id_count; ++i) {
    writer.raw(request.token_ids[i], 32);
  }
  writer.vlq(request.output_count);
  for (uint8_t i = 0; i < request.output_count; ++i) {
    const ErgoOutput &output = request.outputs[i];
    writer.vlq(output.value);
    writer.raw(output.tree, output.tree_size);
    writer.vlq(output.creation_height);
    writer.vlq(output.token_count);
    for (uint8_t t = 0; t < output.token_count; ++t) {
      writer.vlq(output.tokens[t].index);
      writer.vlq(output.tokens[t].amount);
    }
    writer.vlq(output.register_count);
    for (uint8_t r = 0; r < output.register_count; ++r) {
      writer.raw(output.registers[r], output.register_sizes[r]);
    }
  }
  secure_zero(proof, sizeof(proof));
  secure_zero(public_key, sizeof(public_key));
  secure_zero(response, sizeof(response));
  if (!writer.ok) return ChainError::BufferTooSmall;
  *in_out_size = writer.offset;
  return ChainError::Ok;
}

bool parse_hex(const char *hex, uint8_t *out, size_t capacity, size_t *out_size) {
  size_t length = 0;
  while (hex[length * 2] != '\0' && hex[length * 2 + 1] != '\0') ++length;
  if (length > capacity) return false;
  for (size_t i = 0; i < length; ++i) {
    uint8_t value = 0;
    for (size_t half = 0; half < 2; ++half) {
      const char c = hex[i * 2 + half];
      uint8_t digit = 0;
      if (c >= '0' && c <= '9') digit = static_cast<uint8_t>(c - '0');
      else if (c >= 'a' && c <= 'f') digit = static_cast<uint8_t>(c - 'a' + 10);
      else return false;
      value = static_cast<uint8_t>((value << 4) | digit);
    }
    out[i] = value;
  }
  *out_size = length;
  return true;
}

bool run_ergo_self_tests() {
  // Vector produced independently in Python: key 00..1f, recipient 0x11 * 32,
  // 1 ERG output at height 1000000, deterministic nonce with a zero aux rand.
  // The transaction id below is BLAKE2b-256 of the preimage documented above.
  static const char kPayloadHex[] =
      "4552473100000000003b9aca0001"
      "1111111111111111111111111111111111111111111111111111111111111111"
      "24000008cd036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
      "000001"
      "000000003b9aca0040420f0024000008cd036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
      "0000";
  static const char kExpectedSignedHex[] =
      "01"
      "1111111111111111111111111111111111111111111111111111111111111111"
      "38"
      "421a8b7fbb3601eedd8d4f9ba9471d0a43e7ca7a1b57bef4a6b6f6b9535ab35cd7bdd2580372ea8d20c515d595c1a98747c86e008edb5a31"
      "00000001"
      "8094ebdc030008cd036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2c0843d0000";
  static const uint8_t kExpectedDigest[32] = {
      0x13, 0x16, 0xbb, 0xe3, 0x94, 0xf5, 0xf7, 0xe5, 0x95, 0xab, 0x93,
      0xd8, 0x65, 0x6c, 0xbe, 0xfe, 0x19, 0x4d, 0x0d, 0x1b, 0x28, 0xda,
      0xfb, 0x8e, 0xb8, 0x6e, 0xb5, 0xef, 0x93, 0x9d, 0xd8, 0x76};
  static const char kExpectedSender[] =
      "9hHznwfnpLDkjuf4BmtWfYXFA3B2rrsaC9Xf2XX9Gyo1Cdayxqe";
  static const uint8_t kPrivateKey[32] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

  uint8_t payload[kChainMaxPayload] = {};
  size_t payload_size = 0;
  if (!parse_hex(kPayloadHex, payload, sizeof(payload), &payload_size)) return false;
  uint8_t expected_signed[256] = {};
  size_t expected_signed_size = 0;
  if (!parse_hex(kExpectedSignedHex, expected_signed, sizeof(expected_signed),
                 &expected_signed_size)) {
    return false;
  }

  ChainReview review;
  uint8_t digest[32] = {};
  const ChainError review_error = ergo_review_payload(
      payload, payload_size, kExpectedSender, &review, digest);
  bool ok = review_error == ChainError::Ok &&
            chain_constant_time_equal(digest, kExpectedDigest, 32) &&
            !strcmp(review.symbol, "ERG") &&
            !strcmp(review.recipient, kExpectedSender) &&
            !strcmp(review.amount, "1.0 ERG") &&
            !strcmp(review.fee, "0.0 ERG HOST") &&
            !strncmp(review.extra, "TX 1316bbe394f5f7e5\nIN 1 OUT 1 CHG 1\n",
                     sizeof("TX 1316bbe394f5f7e5\nIN 1 OUT 1 CHG 1\n") - 1);
  if (!ok) {
#if defined(HEXWALLET_HOST_TEST)
    ::printf("ergo review err=%d digest=%02x%02x amount=%s fee=%s rec=%s extra=%s\n",
             static_cast<int>(review_error), digest[0], digest[1], review.amount,
             review.fee, review.recipient, review.extra);
#endif
    return false;
  }

  // Any trailing byte, unknown network or truncated transaction must be refused.
  uint8_t tampered[kChainMaxPayload + 1] = {};
  memcpy(tampered, payload, payload_size);
  tampered[payload_size] = 0x00;
  ok = ok && ergo_review_payload(tampered, payload_size + 1, kExpectedSender,
                                 &review, digest) == ChainError::Malformed;
  memcpy(tampered, payload, payload_size);
  tampered[4] = 0x01;
  ok = ok && ergo_review_payload(tampered, payload_size, kExpectedSender,
                                 &review, digest) == ChainError::WrongNetwork;
  memcpy(tampered, payload, payload_size);
  tampered[46] = 0x00;  // input tree length 0
  ok = ok && ergo_review_payload(tampered, payload_size, kExpectedSender,
                                 &review, digest) == ChainError::Malformed;

  // Regression: a second external output would be signed without ever being
  // displayed, so the review must refuse the whole transaction.
  static const char kTwoExternalHex[] =
      "4552473100000000003b9aca0001"
      "1111111111111111111111111111111111111111111111111111111111111111"
      "24000008cd036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
      "0000"
      "02"
      "000000003b9aca0040420f0024000008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980000"
      "000000000bebc20040420f0024000008cd02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50000";
  uint8_t two_external[kChainMaxPayload] = {};
  size_t two_size = 0;
  ok = ok && parse_hex(kTwoExternalHex, two_external, sizeof(two_external),
                       &two_size) &&
       ergo_review_payload(two_external, two_size, kExpectedSender, &review,
                           digest) == ChainError::Unsupported;
#if defined(HEXWALLET_HOST_TEST)
  if (!ok) {
    ::printf("ergo two-external size=%u err=%d\n", static_cast<unsigned>(two_size),
             static_cast<int>(ergo_review_payload(two_external, two_size,
                                                  kExpectedSender, &review,
                                                  digest)));
  }
#endif

  // Regression: tokens travelling with the payment must be listed on screen.
  static const char kTokenPaymentHex[] =
      "4552473100000000003b9aca0001"
      "1111111111111111111111111111111111111111111111111111111111111111"
      "24000008cd036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
      "00"
      "01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "01000000003b9aca0040420f0024000008cd0279be667ef9dcbbac55a06295ce870b"
      "07029bfcdb2dce28d959f2815b16f81798010000000000000000138800";
  uint8_t token_payment[kChainMaxPayload] = {};
  size_t token_size = 0;
  ok = ok && parse_hex(kTokenPaymentHex, token_payment, sizeof(token_payment),
                       &token_size);
  if (ok) {
    ChainReview token_review;
    uint8_t token_digest[32] = {};
    const ChainError token_error = ergo_review_payload(
        token_payment, token_size, kExpectedSender, &token_review, token_digest);
    ok = token_error == ChainError::Ok &&
         strcmp(token_review.amount, "1.0 ERG") == 0 &&
         strcmp(token_review.recipient, kExpectedSender) != 0 &&
         strstr(token_review.extra, "T aaaaaaaa 5000\n") != nullptr &&
         strstr(token_review.extra, "OUT 1 CHG 0") != nullptr;
#if defined(HEXWALLET_HOST_TEST)
    if (!ok) {
      ::printf("ergo token err=%d rec=%s amount=%s extra=%s\n",
               static_cast<int>(token_error), token_review.recipient,
               token_review.amount, token_review.extra);
    }
#endif
  }

  // Six tokens do not fit the review area, so the review refuses rather than
  // dropping some of them.
  static const char kSixTokenHex[] =
      "4552473100000000003b9aca000111111111111111111111111111111111111111111111"
      "1111111111111111111124000008cd036d6caac248af96f6afa7f904f550253a0f3ef3f5"
      "aa2fe6838a95b216691468e20001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaa01000000003b9aca0040420f0024000008cd0279be667ef9dcbb"
      "ac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798100000ffffffffffffffff"
      "0000ffffffffffffffff0000ffffffffffffffff0000ffffffffffffffff0000ffffffff"
      "ffffffff0000ffffffffffffffff0000ffffffffffffffff0000ffffffffffffffff0000"
      "ffffffffffffffff0000ffffffffffffffff0000ffffffffffffffff0000ffffffffffff"
      "ffff0000ffffffffffffffff0000ffffffffffffffff0000ffffffffffffffff0000ffff"
      "ffffffffffff00";
  uint8_t six_tokens[kChainMaxPayload] = {};
  size_t six_size = 0;
  ok = ok && parse_hex(kSixTokenHex, six_tokens, sizeof(six_tokens), &six_size) &&
       ergo_review_payload(six_tokens, six_size, kExpectedSender, &review,
                           digest) == ChainError::BufferTooSmall;
#if defined(HEXWALLET_HOST_TEST)
  if (!ok) {
    const ChainError many = ergo_review_payload(six_tokens, six_size,
                                                kExpectedSender, &review, digest);
    ::printf("ergo many-token size=%u err=%d\n",
             static_cast<unsigned>(six_size), static_cast<int>(many));
  }
#endif

#if !defined(HEXWALLET_HOST_TEST) || defined(HEXWALLET_REAL_MBEDTLS)
  uint8_t signed_out[512] = {};
  size_t signed_size = sizeof(signed_out);
  const ChainError sign_error =
      ergo_sign_payload(payload, payload_size, kPrivateKey, signed_out,
                        &signed_size);
  ok = ok && sign_error == ChainError::Ok &&
       signed_size == expected_signed_size &&
       chain_constant_time_equal(signed_out, expected_signed, expected_signed_size);
  if (!ok) {
#if defined(HEXWALLET_HOST_TEST)
    ::printf("ergo sign err=%d size=%u expected=%u\n",
             static_cast<int>(sign_error), static_cast<unsigned>(signed_size),
             static_cast<unsigned>(expected_signed_size));
#endif
  }

  // A non-P2PK input script must never be signed.
  uint8_t script_input[kChainMaxPayload] = {};
  memcpy(script_input, payload, payload_size);
  script_input[50] = 0xcc;
  size_t rejected_size = sizeof(signed_out);
  ok = ok && ergo_sign_payload(script_input, payload_size, kPrivateKey,
                               signed_out, &rejected_size) ==
                 ChainError::Unsupported;
  // A transaction paying someone else with our key is fine; the same payload
  // signed with a different key must be refused because the input script no
  // longer matches.
  uint8_t other_key[32] = {};
  memcpy(other_key, kPrivateKey, sizeof(other_key));
  other_key[31] ^= 0x01;
  rejected_size = sizeof(signed_out);
  ok = ok && ergo_sign_payload(payload, payload_size, other_key, signed_out,
                               &rejected_size) == ChainError::Unsupported;
  secure_zero(other_key, sizeof(other_key));
#endif
  (void)kPrivateKey;
  return ok;
}

}  // namespace hexwallet
