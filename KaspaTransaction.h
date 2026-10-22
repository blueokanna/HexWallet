#ifndef HEXWALLET_KASPA_TRANSACTION_H
#define HEXWALLET_KASPA_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "WalletEngine.h"
#include "WalletNetworks.h"

namespace hexwallet {

// Kaspa transaction support: BLAKE2b-keyed transaction IDs, the Sompi-based
// sighash with its hash-type masks, KIP-0009 storage mass, BIP340 Schnorr
// signing over secp256k1, and the broadcast serialization.
//
// Version 0 transactions only. Version 1 introduced compute budgets, covenants
// and a BLAKE3-based transaction ID; emitting a v0 transaction while claiming
// v1 support would produce bytes the network silently rejects, so v1 is
// refused with an explicit error instead.

constexpr size_t kKaspaMaxInputs = 8;
constexpr size_t kKaspaMaxOutputs = 16;
constexpr size_t kKaspaMaxPayloadSize = 64;
constexpr size_t kKaspaMaxScriptPublicKeySize = 64;
constexpr size_t kKaspaMaxSignatureScriptSize = 96;
constexpr size_t kKaspaOutpointSize = 36;
constexpr size_t kKaspaSignatureSize = 65;  // 64-byte Schnorr + hash type
constexpr uint64_t kKaspaSompiPerKaspa = 100000000ULL;
constexpr uint64_t kKaspaMaxSompi = 29000000000ULL * kKaspaSompiPerKaspa;

enum class KaspaError : uint8_t {
  Ok = 0,
  InvalidArgument,
  Truncated,
  NonCanonical,
  Unsupported,
  TooLarge,
  MissingField,
  DuplicateField,
  WrongWallet,
  InvalidAmount,
  FeePolicy,
  CryptoFailure,
  BufferTooSmall,
};

enum class KaspaSighash : uint8_t {
  All = 0x01,
  None = 0x02,
  Single = 0x04,
  AllAnyoneCanPay = 0x81,
  NoneAnyoneCanPay = 0x82,
  SingleAnyoneCanPay = 0x84,
};

struct KaspaOutpoint {
  uint8_t transaction_id[32];
  uint32_t index;
};

struct KaspaInput {
  KaspaOutpoint previous_outpoint;
  uint64_t sequence;
  // Sigop count carried in the v0 sighash. Standard P2PK spends use 1.
  uint8_t sigop_count;
  // BIP44 address index this UTXO was received at; the signer re-derives the
  // key from it and refuses the transaction unless the x-only key matches.
  uint32_t address_index;
  // Previous output being spent (from the wallet's UTXO set or the caller).
  uint64_t value;
  uint16_t script_version;
  uint8_t script[kKaspaMaxScriptPublicKeySize];
  uint8_t script_size;
};

struct KaspaOutput {
  uint64_t value;
  uint16_t script_version;
  uint8_t script[kKaspaMaxScriptPublicKeySize];
  uint8_t script_size;
  char address[kAddressTextSize];
  bool wallet_owned;
  bool change;
};

struct KaspaTransaction {
  uint16_t version;
  uint64_t lock_time;
  KaspaInput inputs[kKaspaMaxInputs];
  KaspaOutput outputs[kKaspaMaxOutputs];
  uint8_t input_count;
  uint8_t output_count;
  uint8_t payload[kKaspaMaxPayloadSize];
  uint8_t payload_size;
  uint64_t input_total;
  uint64_t output_total;
  uint64_t fee;
  uint64_t compute_mass;
  uint64_t transient_mass;
  uint64_t storage_mass;
  uint32_t request_hash;  // FNV-1a over the reviewed encoding
};

// BLAKE2b-256 keyed transaction id over the signed transaction (the signature
// script is excluded from the ID, per the reference implementation).
KaspaError kaspa_transaction_id(const KaspaTransaction &transaction,
                                uint8_t out_id[32]);

// Sompi sighash. `sighash` selects which outputs/inputs are committed.
KaspaError kaspa_sighash(const KaspaTransaction &transaction, size_t input_index,
                         KaspaSighash sighash, uint8_t out_digest[32]);

// KIP-0009 masses. `compute_mass` covers size, script public keys and sigops;
// `storage_mass` is the persistent UTXO-set cost.
KaspaError kaspa_masses(const KaspaTransaction &transaction,
                        uint64_t *compute_mass, uint64_t *transient_mass,
                        uint64_t *storage_mass);

// Recompute every derived field (totals, fee, masses, address rendering) and
// apply the fee policy. Call after populating inputs/outputs.
KaspaError kaspa_review(KaspaTransaction *transaction);

// Sign every input and serialize the transaction as the protobuf
// TransactionMessage that gRPC SubmitTransaction expects.
KaspaError kaspa_sign_transaction(const KaspaTransaction &transaction,
                                  const HdPrivateNode &master,
                                  uint8_t *out_transaction,
                                  size_t *in_out_size);

// Serialize with caller-supplied signature scripts (64-byte Schnorr || hash
// type per input). Exposed so the wire format can be pinned to the reference
// encoder independent of key derivation.
KaspaError kaspa_serialize_transaction(
    const KaspaTransaction &transaction,
    const uint8_t signature_scripts[kKaspaMaxInputs][kKaspaSignatureSize],
    uint8_t *out_transaction, size_t *in_out_size);

// Parse a Kaspa address (bech32 with the Kaspa 5-byte checksum) into a
// script public key. cashaddr_prefix selects the network prefix, e.g. "kaspa".
KaspaError kaspa_script_from_address(const char *prefix, const char *address,
                                     uint16_t *out_version, uint8_t *out_script,
                                     uint8_t *out_script_size);
// Render a script public key back as a Kaspa address.
KaspaError kaspa_address_from_script(const char *prefix, uint16_t version,
                                     const uint8_t *script, uint8_t script_size,
                                     char *out, size_t out_size);

const char *kaspa_error_text(KaspaError error);
void clear_kaspa_transaction(KaspaTransaction *transaction);
bool run_kaspa_self_tests();

}  // namespace hexwallet

#endif
