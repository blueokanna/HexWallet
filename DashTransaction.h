#ifndef HEXWALLET_DASH_TRANSACTION_H
#define HEXWALLET_DASH_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "WalletEngine.h"
#include "WalletNetworks.h"

namespace hexwallet {

// Dash plain payments. Dash encodes the transaction type in the high 16 bits
// of nVersion; only nType == 0 (an ordinary payment) is modelled here. The
// special types - ProRegTx/ProUpServTx/ProUpRegTx/ProUpRevTx, CbTx, quorum
// commitments, asset locks and asset unlocks - all carry an opaque
// `extraPayload` that this adapter cannot decode, so a device that showed a
// recipient and amount for them would be inventing the review. They are
// refused instead.
//
// Wire format, taken from live mainnet bytes rather than from documentation:
//   int32  nVersion | (nType << 16)   (plain: 2 or 3, nType always 0)
//   vin, vout
//   uint32 nLockTime
//   -- and nothing else: a plain transaction has no extraPayload field --
// The digest is Bitcoin's legacy algorithm over that exact serialization.
// `dash_legacy_sighash` is pinned against two mainnet signature digests
// (one v3, one v2) in `run_dash_self_tests`.
//
// InstantSend adds no bytes to a transaction. A masternode quorum locks the
// inputs out of band; the wallet's only obligation is to emit byte-correct
// transactions and to never claim a lock it cannot see. Lock state is
// reported by the phone or the node, never asserted by the firmware.

constexpr size_t kDashMaxInputs = 4;
constexpr size_t kDashMaxOutputs = 8;
constexpr size_t kDashMaxScriptSize = 34;
// 10 + 4 * 149 + 8 * 43 = 950, so every admitted request fits with room to
// spare even with worst-case DER signatures.
constexpr size_t kDashMaxTransactionSize = 1024;
constexpr size_t kDashMaxPreviousTransactionSize = 1024;
constexpr size_t kDashMaxDerSignatureSize = 72;
constexpr size_t kDashMaxSignatureSize = kDashMaxDerSignatureSize + 1;
constexpr size_t kDashP2pkhScriptSize = 25;
constexpr size_t kDashP2shScriptSize = 23;
// 4 (version) + 1 (vin count) + 1 (vout count) + 4 (nLockTime)
constexpr uint32_t kDashBaseVbytes = 10;
// 32 (outpoint hash) + 4 (outpoint index) + 1 (scriptSig length) +
// 74 (1-byte push of a 73-byte DER signature plus SIGHASH_ALL) +
// 34 (1-byte push of a 33-byte compressed pubkey) + 4 (sequence)
constexpr uint32_t kDashP2pkhInputVbytes = 149;
constexpr uint64_t kDashDuffsPerDash = 100000000ULL;
// Dash kept Bitcoin's MAX_MONEY constant; the real supply is below it.
constexpr uint64_t kDashMaxDuffs = 21000000ULL * kDashDuffsPerDash;
constexpr uint32_t kDashVersion = 3;
constexpr uint32_t kDashCoinType = 5;
constexpr uint32_t kDashMaxLockTime = 0x7fffffffUL;

enum class DashError : uint8_t {
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

struct DashChainParams {
  const char *network_id;
  uint8_t p2pkh_version;
  uint8_t p2sh_version;
};

struct DashInput {
  uint8_t previous_txid[32];
  uint32_t previous_index;
  uint32_t sequence;
  uint64_t value;
  // Previous output scriptPubKey, exactly the canonical 25-byte P2PKH form.
  // The signer re-derives the key and refuses unless HASH160(pubkey) is the
  // hash this script pays, so the host cannot aim a signature at a script the
  // device does not own.
  uint8_t script[kDashP2pkhScriptSize];
  uint8_t script_size;
  // m/44'/5'/account'/change/index.
  uint32_t account;
  uint8_t change;
  uint32_t address_index;
  char address[kAddressTextSize];
  // Full non-witness transaction: the signer verifies its txid, output index,
  // amount and script. Legacy sighash alone does not commit the input amount.
  uint8_t previous_transaction[kDashMaxPreviousTransactionSize];
  uint16_t previous_transaction_size;
};

struct DashOutput {
  uint64_t value;
  uint8_t script[kDashMaxScriptSize];
  uint8_t script_size;
  // Rendered from `script`, never from host text, so the trusted display and
  // the signed bytes cannot disagree.
  char address[kAddressTextSize];
};

struct DashTransaction {
  DashChainParams chain;
  uint32_t version;
  uint32_t lock_time;
  DashInput inputs[kDashMaxInputs];
  DashOutput outputs[kDashMaxOutputs];
  uint8_t input_count;
  uint8_t output_count;
  uint64_t input_total;
  uint64_t output_total;
  uint64_t fee;
  uint32_t estimated_vbytes;
  uint8_t payload_hash[kSha256Size];
};

// Review payload layout (little-endian throughout):
//   magic "DAS2" (4 bytes)
//   u32 lock_time                       (<= kDashMaxLockTime)
//   u8  input_count                     (1..kDashMaxInputs)
//   input_count * { u8[32] previous_txid, u32 previous_index, u32 sequence,
//                   u64 value, u8 script_size + script,
//                   u32 account, u8 change, u32 address_index }
//   u8  output_count                    (1..kDashMaxOutputs)
//   output_count * { u64 value, u8 script_size + script }
//   input_count * { u16 previous_transaction_size, previous_transaction }
// The payload must end exactly after the last previous transaction; trailing bytes are a
// parse error, not ignored padding.
// Legacy "DASH" payloads have no previous transactions. They remain parseable
// for diagnostics, but dash_sign_transaction rejects them with MissingField.
DashError dash_parse_review_payload(const uint8_t *data, size_t size,
                                    const DashChainParams &chain,
                                    DashTransaction *out);

// Sign every input and emit the network serialization. Each input is signed
// with SIGHASH_ALL over the legacy digest of its own P2PKH scriptCode, which
// is the only form Dash consensus accepts for these inputs.
DashError dash_sign_transaction(const DashTransaction &request,
                                const HdPrivateNode &master,
                                uint8_t *out_transaction, size_t *in_out_size);
// Checks all funding proofs and derivation paths before showing approval.
// No signature is generated.
DashError dash_validate_inputs(const DashTransaction &request,
                               const HdPrivateNode &master);

// Legacy signature hash of `transaction` for `input_index`, committing
// `script_code` in that input's scriptSig slot and appending the 4-byte hash
// type. Only canonical P2PKH scriptCode and SIGHASH_ALL are admitted. Pure
// function over public data: no key material, no curve work, so
// live mainnet digests are pinned on the host.
DashError dash_legacy_sighash(const uint8_t *transaction,
                              size_t transaction_size, size_t input_index,
                              const uint8_t *script_code,
                              size_t script_code_size, uint8_t hash_type,
                              uint8_t out_digest[kSha256Size]);

const char *dash_error_text(DashError error);
void clear_dash_transaction(DashTransaction *request);
// Host-safe: mainnet digest vectors, parser limits and rejection paths.
bool run_dash_self_tests();
// Device-only: full BIP32 derivation, ECDSA signing and round-trip parse.
bool run_dash_signature_self_test();

}  // namespace hexwallet

#endif
