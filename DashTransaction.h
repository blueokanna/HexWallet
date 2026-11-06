#ifndef HEXWALLET_DASH_TRANSACTION_H
#define HEXWALLET_DASH_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "CryptoPrimitives.h"
#include "WalletEngine.h"
#include "WalletNetworks.h"

namespace hexwallet
{
  constexpr size_t kDashMaxInputs = 4;
  constexpr size_t kDashMaxOutputs = 8;
  constexpr size_t kDashMaxScriptSize = 34;
  constexpr size_t kDashMaxTransactionSize = 1024;
  constexpr size_t kDashMaxPreviousTransactionSize = 1024;
  constexpr size_t kDashMaxDerSignatureSize = 72;
  constexpr size_t kDashMaxSignatureSize = kDashMaxDerSignatureSize + 1;
  constexpr size_t kDashP2pkhScriptSize = 25;
  constexpr size_t kDashP2shScriptSize = 23;
  constexpr uint32_t kDashBaseVbytes = 10;
  constexpr uint32_t kDashP2pkhInputVbytes = 149;
  constexpr uint64_t kDashDuffsPerDash = 100000000ULL;
  constexpr uint64_t kDashMaxDuffs = 21000000ULL * kDashDuffsPerDash;
  constexpr uint32_t kDashVersion = 3;
  constexpr uint32_t kDashCoinType = 5;
  constexpr uint32_t kDashMaxLockTime = 0x7fffffffUL;
  constexpr uint8_t kDashFlagInstantSend = 0x01;
  constexpr uint8_t kDashKnownFlags = kDashFlagInstantSend;

  enum class DashError : uint8_t
  {
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

  struct DashChainParams
  {
    const char *network_id;
    uint8_t p2pkh_version;
    uint8_t p2sh_version;
  };

  struct DashInput
  {
    uint8_t previous_txid[32];
    uint32_t previous_index;
    uint32_t sequence;
    uint64_t value;
    uint8_t script[kDashP2pkhScriptSize];
    uint8_t script_size;
    uint32_t account;
    uint8_t change;
    uint32_t address_index;
    char address[kAddressTextSize];
    uint8_t previous_transaction[kDashMaxPreviousTransactionSize];
    uint16_t previous_transaction_size;
  };

  struct DashOutput
  {
    uint64_t value;
    uint8_t script[kDashMaxScriptSize];
    uint8_t script_size;
    char address[kAddressTextSize];
  };

  struct DashTransaction
  {
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
    uint8_t flags;
    // True only when every input carried its funding transaction and that
    // transaction provably pays this input's txid, index, value and script.
    // A request without it is refused before any key is derived, because a
    // host-supplied amount is exactly how a fee gets hidden.
    bool funding_verified;
  };

  // Review payload layout (little-endian throughout):
  //   magic "DAS2" or "DAS3" (4 bytes)
  //   u32 lock_time                       (<= kDashMaxLockTime)
  //   u8  input_count                     (1..kDashMaxInputs)
  //   input_count * { u8[32] previous_txid, u32 previous_index, u32 sequence,
  //                   u64 value, u8 script_size + script,
  //                   u32 account, u8 change, u32 address_index }
  //   u8  output_count                    (1..kDashMaxOutputs)
  //   output_count * { u64 value, u8 script_size + script }
  //   input_count * { u16 previous_transaction_size, previous_transaction }
  //   [u8 flags]                          (DAS3 only; DAS2 implies flags = 0)
  // The payload must end exactly after the last record; trailing bytes are a
  // parse error, not ignored padding.
  //
  // Each funding transaction must be a type-0 Dash transaction whose
  // double-SHA256 equals `previous_txid` and whose `previous_index` output pays
  // exactly `value` and `script`. Otherwise the parser fails with WrongWallet:
  // the device would otherwise be signing a fee it was told rather than one it
  // computed.
  //
  // Legacy "DASH" payloads carry no funding transactions. They stay parseable
  // so an old host gets a precise diagnostic, and every signing entry point
  // refuses them with MissingField.
  DashError dash_parse_review_payload(const uint8_t *data, size_t size,
                                      const DashChainParams &chain,
                                      DashTransaction *out);

  // True when the payload magic is a shape this firmware can sign. One source
  // of truth for the signing layer, so the magic cannot be accepted by one
  // layer and rejected by the parser.
  bool dash_payload_is_signable(const uint8_t *data, size_t size);

  // InstantSend intent declared by the host. Advisory: it changes what the
  // screen says, never what is signed.
  bool dash_instant_send_requested(const DashTransaction &request);

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

}

#endif
