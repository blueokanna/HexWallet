#ifndef HEXWALLET_BITCOIN_TRANSACTION_H
#define HEXWALLET_BITCOIN_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "WalletConfig.h"
#include "WalletEngine.h"
#include "WalletNetworks.h"

namespace hexwallet {

constexpr size_t kBitcoinMaxInputs = 8;
constexpr size_t kBitcoinMaxOutputs = 16;
constexpr size_t kBitcoinMaxScriptSize = 34;
constexpr size_t kBitcoinMaxPathDepth = 10;
constexpr size_t kBitcoinMaxDerSignatureSize = 72;

enum class BitcoinSpendType : uint8_t {
  NativeP2wpkh,
  NestedP2shP2wpkh,
  LegacyP2pkh,
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
const char *transaction_error_text(TransactionError error);
void clear_bitcoin_request(BitcoinSigningRequest *request);
bool run_bitcoin_transaction_self_test();
// Digest-only vectors (legacy, BIP143 and SIGHASH_FORKID). Safe to run on the
// host: no ECDSA, no key derivation.
bool run_bitcoin_sighash_self_tests();
// Exposed so external tooling can audit the exact bytes an approval covers.
TransactionError bitcoin_sighash_legacy(const BitcoinSigningRequest &request,
                                        size_t input_index, uint32_t sighash_type,
                                        uint8_t out[kSha256Size]);
TransactionError bitcoin_sighash_bip143(const BitcoinSigningRequest &request,
                                       size_t input_index, uint32_t sighash_type,
                                       uint8_t out[kSha256Size]);
uint32_t bitcoin_estimated_vbytes(const BitcoinSigningRequest &request);

}

#endif
