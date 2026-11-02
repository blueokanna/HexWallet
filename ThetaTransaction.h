#ifndef HEXWALLET_THETA_TRANSACTION_H
#define HEXWALLET_THETA_TRANSACTION_H
#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"
namespace hexwallet {
// Native Theta SendTx (TFUEL/THETA transfer). This is not an Ethereum
// transaction: Theta signs an RLP list whose payload is
//   RLP(chain_id) || RLP(type = 2) || RLP({fee, inputs, outputs})
// wrapped in the six-field Ethereum envelope with every field but `input`
// zeroed, and the digest is keccak-256 of that envelope.
//
// The layout below is pinned by a mainnet transfer: block 1000000, tx
// 0x1ccc4b6efb1f9cdcf1a6ff29bd4eb28e65b7e9e7877a4f46687bcf5063e17bca. Its
// 65-byte signature recovers to the input address only with chain id
// "mainnet" and this exact encoding, so the self-test compares both the
// envelope bytes and the digest.
constexpr size_t kThetaAddressSize = 20;
constexpr size_t kThetaMaxInputs = 4;
constexpr size_t kThetaMaxOutputs = 4;
constexpr size_t kThetaMaxSignBytes = 512;

struct ThetaCoin {
  uint64_t theta_wei;
  uint64_t tfuel_wei;
};

struct ThetaInput {
  uint8_t address[kThetaAddressSize];
  ThetaCoin coins;  // amount spent plus the fee
  uint64_t sequence;
};

struct ThetaOutput {
  uint8_t address[kThetaAddressSize];
  ThetaCoin coins;
};

struct ThetaSendTx {
  const char *chain_id;  // "mainnet"
  ThetaCoin fee;
  ThetaInput inputs[kThetaMaxInputs];
  size_t input_count;
  ThetaOutput outputs[kThetaMaxOutputs];
  size_t output_count;
};

// Device-facing request, 46 bytes, big endian:
//   [0]    version = 1
//   [1]    chain selector: 0 mainnet, 1 testnet, 2 privatenet
//   [2..21] recipient
//   [22..29] amount in TFuelWei
//   [30..37] fee in TFuelWei
//   [38..45] sender sequence
// The sender is never taken from the host: it is the derived address, so a
// request can only ever move this wallet's own coins.
constexpr size_t kThetaRequestSize = 46;
constexpr uint8_t kThetaRequestVersion = 1;

// RLP envelope the device hashes and signs.
bool theta_sendtx_sign_bytes(const ThetaSendTx &tx, uint8_t *out,
                             size_t capacity, size_t *out_size);
// keccak-256 of the envelope; this is the 32-byte digest an ECDSA signature
// over secp256k1 covers.
bool theta_sendtx_digest(const ThetaSendTx &tx, uint8_t out[32]);
bool run_theta_self_tests();

// Chain adapter entry points. `review` gets the fields the panel prints and
// `digest` the exact bytes that will be signed; signing re-derives everything
// from the same payload so the two cannot drift.
ChainError theta_review_payload(const uint8_t *payload, size_t size,
                                const char *derived_address,
                                ChainReview *review, uint8_t digest[32]);
// Output is the 65-byte r || s || recovery-id Theta expects in TxInput.Signature.
ChainError theta_sign_payload(const uint8_t *payload, size_t size,
                              const uint8_t private_key[32],
                              const char *sender_address, uint8_t *out,
                              size_t *in_out_size);
}  // namespace hexwallet
#endif
