#ifndef HEXWALLET_BITCOIN_TRANSACTION_H
#define HEXWALLET_BITCOIN_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "WalletConfig.h"
#include "WalletEngine.h"
#include "WalletNetworks.h"

namespace hexwallet {

// 16 inputs, not 8: BIP341's own wallet vectors spend nine, and the cap was
// the only reason this wallet could not check them verbatim.
constexpr size_t kBitcoinMaxInputs = 16;
constexpr size_t kBitcoinMaxOutputs = 16;
constexpr size_t kBitcoinMaxScriptSize = 34;
// Largest witnessScript this firmware will hash for BIP143: a 15-of-15
// CHECKMULTISIG is 1 + 15 * 34 + 2 = 513 bytes, so 520 leaves room and still
// keeps the digest preimage inside a fixed stack buffer.
constexpr size_t kBitcoinMaxWitnessScriptSize = 520;
constexpr size_t kBitcoinMaxMultisigKeys = 15;
constexpr size_t kBitcoinMaxPathDepth = 10;
constexpr size_t kBitcoinMaxDerSignatureSize = 72;

enum class BitcoinSpendType : uint8_t {
  NativeP2wpkh,
  NestedP2shP2wpkh,
  LegacyP2pkh,
  TaprootBip86,
};

// Address family plus the consensus sighash rules the chain inherited.  The
// caller supplies this from the network signing policy so the review that the
// user approves and the digest that gets signed can never drift apart.
struct BitcoinChainParams {
  const char *network_id;
  const char *cashaddr_prefix;  // non-null when the chain renders CashAddr
  UtxoAddressProfile address;
  SighashFamily sighash;
  uint32_t fork_id;
};

enum class TransactionError : uint8_t {
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

struct BitcoinInput {
  uint8_t previous_txid[32];
  uint32_t previous_index;
  uint32_t sequence;
  uint64_t value;
  BitcoinSpendType spend_type;
  uint8_t public_key[kCompressedPublicKeySize];
  uint8_t witness_key_hash[kRipemd160Size];
  uint8_t p2sh_hash[kRipemd160Size];
  uint32_t path[kBitcoinMaxPathDepth];
  uint8_t path_depth;
  uint8_t taproot_output_key[32];
  uint8_t taproot_sighash; // BIP86 policy: DEFAULT (0) or ALL (1).
};

struct BitcoinOutput {
  uint64_t value;
  uint8_t script[kBitcoinMaxScriptSize];
  uint8_t script_size;
  char address[kAddressTextSize];
  bool wallet_owned;
  bool change;
};

struct BitcoinSigningRequest {
  uint32_t version;
  uint32_t lock_time;
  BitcoinChainParams chain;
  BitcoinInput inputs[kBitcoinMaxInputs];
  BitcoinOutput outputs[kBitcoinMaxOutputs];
  uint8_t input_count;
  uint8_t output_count;
  uint64_t input_total;
  uint64_t output_total;
  uint64_t fee;
  uint32_t estimated_vbytes;
  uint8_t psbt_hash[kSha256Size];
};

TransactionError bitcoin_parse_psbt(const uint8_t *psbt, size_t psbt_size,
                                    const HdPrivateNode &master,
                                    const BitcoinChainParams &chain,
                                    BitcoinSigningRequest *out);
TransactionError bitcoin_sign_request(const BitcoinSigningRequest &request,
                                      const HdPrivateNode &master,
                                      uint8_t *out_transaction,
                                      size_t *in_out_size);
// Signs a PSBT in place and returns a PSBT, which is the format every host
// actually consumes: one 0x02 partial signature per input this device owns, all
// other map entries - including signatures other parties already contributed and
// fields this firmware merely tolerates - copied through byte for byte. A
// signature that is already present and identical is left alone (the call is
// idempotent); the same key with a different value is refused rather than
// overwritten.
//
// This is deliberately separate from bitcoin_sign_request(): the latter
// assembles a complete transaction and therefore cannot represent a spend that
// still needs another signer.
struct BitcoinPsbtSignSummary {
  uint8_t total_inputs;
  uint8_t signed_inputs;    // entries this call added
  uint8_t unchanged_inputs; // entries that already matched byte for byte
};
TransactionError bitcoin_sign_psbt(const uint8_t *psbt, size_t psbt_size,
                                   const HdPrivateNode &master,
                                   const BitcoinChainParams &chain,
                                   uint8_t *out_psbt, size_t out_capacity,
                                   size_t *out_size,
                                   BitcoinPsbtSignSummary *summary);
const char *transaction_error_text(TransactionError error);
void clear_bitcoin_request(BitcoinSigningRequest *request);
bool run_bitcoin_transaction_self_test();
// Index of the last checkpoint reached by run_bitcoin_transaction_self_test().
// A failing self-test on a device has no console worth reading; this turns "the
// Bitcoin tests failed" into "they stopped at step 112".
int bitcoin_self_test_stage();
// Digest-only vectors (legacy, BIP143 and SIGHASH_FORKID). Safe to run on the
// host: no ECDSA, no key derivation.
bool run_bitcoin_sighash_self_tests();
// Groestlcoin: Bitcoin's legacy preimage with a single-SHA256 digest, pinned to
// a real mainnet spend whose DER signature verifies against it and not against
// the double-SHA256 digest.
bool run_groestlcoin_sighash_self_tests();
// Exposed so external tooling can audit the exact bytes an approval covers.
TransactionError bitcoin_sighash_legacy(const BitcoinSigningRequest &request,
                                        size_t input_index, uint32_t sighash_type,
                                        uint8_t out[kSha256Size]);
TransactionError bitcoin_sighash_bip143(const BitcoinSigningRequest &request,
                                       size_t input_index, uint32_t sighash_type,
                                       uint8_t out[kSha256Size]);
// BIP143 digest with an explicit scriptCode, which is what a witness-v0
// multisig (P2WSH) spend commits to: the full witnessScript rather than the
// fixed 25-byte P2PKH script the P2WPKH path uses. All four defined hash types
// (ALL/NONE/SINGLE) with and without ANYONECANPAY are computed, because that is
// what BIP143's own P2SH-P2WSH 6-of-6 vector exercises; the signing path still
// only ever asks for SIGHASH_ALL. `script_code` is serialized with its
// CompactSize length prefix, as the spec requires.
TransactionError bitcoin_sighash_witness_v0(const BitcoinSigningRequest &request,
                                            size_t input_index,
                                            uint32_t sighash_type,
                                            const uint8_t *script_code,
                                            size_t script_code_size,
                                            uint8_t out[kSha256Size]);

// Canonical m-of-n CHECKMULTISIG witnessScript:
//   OP_m <33-byte key>... OP_n OP_CHECKMULTISIG, with OP_1..OP_16 as small
// integers (so 1 <= m <= n <= 15). No other opcodes, no extra pushes: a script
// this firmware cannot parse byte for byte is one it cannot honestly display.
bool bitcoin_multisig_script(const uint8_t *public_keys, size_t key_count,
                             uint8_t threshold, uint8_t *out, size_t capacity,
                             size_t *out_size);
// Parses the inverse. `keys` receives key_count * 33 bytes. Rejects non-minimal
// integer encodings, out-of-range thresholds and any trailing byte.
bool bitcoin_parse_multisig_script(const uint8_t *script, size_t script_size,
                                   uint8_t *threshold, uint8_t *key_count,
                                   uint8_t *keys, size_t key_capacity);
// sha256(witnessScript): the witness program of a P2WSH output.
bool bitcoin_p2wsh_program(const uint8_t *witness_script,
                           size_t witness_script_size, uint8_t out[32]);
// 0x00 0x20 || sha256(witnessScript): the redeemScript of a P2SH-P2WSH output,
// whose hash160 is the P2SH address payload.
bool bitcoin_p2sh_p2wsh_redeem(const uint8_t *witness_script,
                               size_t witness_script_size, uint8_t out[34]);
// BIP341 taproot signature hash over the same request structure. Full hash-type
// set (DEFAULT/ALL/NONE/SINGLE, with or without ANYONECANPAY) plus an optional
// annex, because that is what BIP341's wallet vectors exercise; the BIP86
// signer below restricts itself to DEFAULT and ALL. `annex` must start with the
// 0x50 tag when supplied.
TransactionError bitcoin_sighash_taproot(const BitcoinSigningRequest &request,
                                         size_t input_index, uint8_t hash_type,
                                         const uint8_t *annex, size_t annex_size,
                                         uint8_t out[kSha256Size]);
uint32_t bitcoin_estimated_vbytes(const BitcoinSigningRequest &request);

}

#endif
