#ifndef HEXWALLET_ZCASH_TRANSACTION_H
#define HEXWALLET_ZCASH_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "WalletEngine.h"
#include "WalletNetworks.h"

namespace hexwallet {

// Zcash Overwinter/Sapling v4 transparent transactions. Signed inputs are
// t1 P2PKH and t3 P2SH whose redeem script is the canonical
// `<compressed pubkey> OP_CHECKSIG` form holding this wallet's key; shielded
// components are parsed to reject them explicitly. The host supplies prevout
// values/scripts (and the redeem script for P2SH) in the review payload, and
// the device re-derives every key and re-hashes the redeem script before
// signing. P2SH multisig and every other redeem form are refused: a single
// device cannot produce the other signatures, and it cannot verify them.

constexpr size_t kZcashMaxInputs = 8;
constexpr size_t kZcashMaxOutputs = 16;
constexpr size_t kZcashMaxScriptSize = 34;
constexpr size_t kZcashMaxPathDepth = 10;
constexpr size_t kZcashMaxDerSignatureSize = 72;
constexpr size_t kZcashMaxSignatureSize = kZcashMaxDerSignatureSize + 1;
// `<0x21> <33-byte compressed pubkey> OP_CHECKSIG`
constexpr size_t kZcashMaxRedeemScriptSize = 1 + 33 + 1;
// push(signature) + push(redeem script or pubkey)
constexpr size_t kZcashMaxScriptSigSize =
    1 + kZcashMaxSignatureSize + 1 + kZcashMaxRedeemScriptSize;
constexpr size_t kZcashMaxTransactionSize = 4096;
constexpr uint64_t kZcashZatsPerZec = 100000000ULL;
constexpr uint64_t kZcashMaxZats = 21000000ULL * kZcashZatsPerZec;
constexpr uint64_t kFluxMaxZats = 440000000ULL * kZcashZatsPerZec;
// Parser upper bound across every admitted ZIP-243 transparent network.
constexpr uint64_t kZcashTransparentParseMaxZats = kFluxMaxZats;
constexpr uint32_t kZcashV4Version = 0x80000004UL;
constexpr uint32_t kZcashSaplingVersionGroupId = 0x892F2085UL;

enum class ZcashError : uint8_t {
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

struct ZcashChainParams {
  const char *network_id;
  uint16_t p2pkh_version;
  uint16_t p2sh_version;
  uint32_t branch_id;
  uint32_t derivation_coin_type;
};

struct ZcashInput {
  uint8_t previous_txid[32];
  uint32_t previous_index;
  uint32_t sequence;
  uint64_t value;
  // Previous output scriptPubKey: P2PKH (t1) or P2SH (t3).
  uint8_t script[kZcashMaxScriptSize];
  uint8_t script_size;
  // P2SH only: the redeem script, which must be exactly
  // `<0x21> <33-byte compressed pubkey> OP_CHECKSIG` and must HASH160 to
  // script[2..21]. Zcash commits the redeem script as the ZIP-243 scriptCode.
  // Empty for P2PKH prevouts.
  uint8_t redeem[kZcashMaxRedeemScriptSize];
  uint8_t redeem_size;
  // m/44'/coin'/account'/change/index. The signer re-derives the key and
  // refuses the transaction unless HASH160(pubkey) equals script[3..22] (P2PKH)
  // or the redeem script carries that same pubkey (P2SH).
  uint32_t account;
  uint8_t change;
  uint32_t address_index;
};

struct ZcashOutput {
  uint64_t value;
  uint8_t script[kZcashMaxScriptSize];
  uint8_t script_size;
  char address[kAddressTextSize];
};

struct ZcashSigningRequest {
  ZcashChainParams chain;
  uint32_t version;
  uint32_t version_group_id;
  uint32_t lock_time;
  uint32_t expiry_height;
  int64_t value_balance;
  ZcashInput inputs[kZcashMaxInputs];
  ZcashOutput outputs[kZcashMaxOutputs];
  uint8_t input_count;
  uint8_t output_count;
  uint64_t input_total;
  uint64_t output_total;
  uint64_t fee;
  uint32_t estimated_vbytes;
  uint8_t request_hash[kSha256Size];
};

// Review payload layout (all integers little-endian):
//   magic "ZEC4" or "ZEC5" (4 bytes)
//   u32 branch_id
//   u32 unsigned_transaction_size
//   unsigned v4 transaction bytes (every scriptSig must be empty)
//   u8 input_count (must equal the transaction's vin count)
//   input_count * { u64 value, u8 script_size + scriptPubKey,
//                   u32 account, u8 change, u32 address_index
//                   [, u8 redeem_size + redeem script] }
// The bracketed redeem field exists only under "ZEC5" and must be zero for
// P2PKH inputs; "ZEC4" cannot carry a P2SH prevout. The payload must end
// exactly after the last input record.
ZcashError zcash_parse_review_payload(const uint8_t *data, size_t size,
                                      const ZcashChainParams &chain,
                                      ZcashSigningRequest *out);

// Sign every input and emit the network serialization. The caller must have
// already shown the review and verified the approval code.
ZcashError zcash_sign_request(const ZcashSigningRequest &request,
                              const HdPrivateNode &master,
                              uint8_t *out_transaction, size_t *in_out_size);

// ZIP-243 digest for any v4 transaction. `input_index` is -1 (NOT_AN_INPUT)
// for the digest used by shielded signatures; this module only signs with a
// concrete input. `hash_type` accepts SIGHASH_ALL/NONE/SINGLE, optionally
// ORed with SIGHASH_ANYONECANPAY. Exposed so host tests can pin the official
// Zcash vector independently of key derivation.
ZcashError zcash_zip243_sighash_v4(const uint8_t *transaction,
                                   size_t transaction_size,
                                   const uint8_t *script_code,
                                   size_t script_code_size,
                                   int32_t input_index, uint32_t hash_type,
                                   uint64_t amount, uint32_t branch_id,
                                   uint8_t out_digest[kSha256Size]);

// True when `redeem` is exactly `<0x21> <33-byte compressed pubkey>
// OP_CHECKSIG` and HASH160(redeem) equals the hash committed by the P2SH
// prevout script. Pure function over public data: no key material and no curve
// work, so the rule is pinned by host tests as well as by the device signer.
bool zcash_p2sh_redeem_commits(const uint8_t *script, size_t script_size,
                               const uint8_t *redeem, size_t redeem_size);

const char *zcash_error_text(ZcashError error);
void clear_zcash_request(ZcashSigningRequest *request);
// Host-safe: official ZIP-243 transparent vector plus parser failure paths.
bool run_zcash_sighash_self_tests();
// Device-only: full BIP32 derivation, ECDSA signing and round-trip parse.
bool run_zcash_transaction_self_test();

}  // namespace hexwallet

#endif
