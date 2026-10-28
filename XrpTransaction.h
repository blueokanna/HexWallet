#ifndef HEXWALLET_XRP_TRANSACTION_H
#define HEXWALLET_XRP_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet {

constexpr size_t kXrpAccountSize = 20;
constexpr size_t kXrpPublicKeySize = 33;
constexpr size_t kXrpAddressTextSize = 40;
constexpr size_t kXrpHashSize = 32;
constexpr size_t kXrpMaxUnsigned = 192;
constexpr size_t kXrpMaxSignature = 72;
constexpr size_t kXrpMaxSigned = kXrpMaxUnsigned + kXrpMaxSignature + 4;
constexpr uint64_t kXrpMaxFeeDrops = 2000000;
constexpr uint64_t kXrpMaxAmountDrops = 100000000000000000ULL;

enum class XrpError : uint8_t {
  Ok,
  InvalidArgument,
  Malformed,
  Unsupported,
  WrongWallet,
  InvalidAmount,
  FeePolicy,
  CryptoFailure,
  BufferTooSmall,
};

struct XrpReview {
  uint8_t source[kXrpAccountSize];
  uint8_t destination[kXrpAccountSize];
  uint8_t public_key[kXrpPublicKeySize];
  uint64_t amount_drops;
  uint64_t fee_drops;
  uint32_t sequence;
  uint32_t last_ledger_sequence;
  uint32_t destination_tag;
  bool has_destination_tag;
  uint8_t unsigned_tx[kXrpMaxUnsigned];
  uint16_t unsigned_size;
  uint16_t signature_offset;
  uint8_t signing_hash[kXrpHashSize];
  char source_text[kXrpAddressTextSize];
  char destination_text[kXrpAddressTextSize];
  char amount_text[64];
  char fee_text[64];
  char hash_text[65];
};

struct XrpTransaction {
  XrpReview review;
  uint32_t address_index;
};

// Compact payload (big endian):
//   version=1, has_tag (0/1), amount drops (u64), fee drops (u64),
//   sequence (u32), last ledger (u32), destination tag (u32),
//   destination account id (20 bytes).
XrpError xrp_review_payload(const uint8_t *payload, size_t size,
                            const uint8_t public_key[kXrpPublicKeySize],
                            XrpTransaction *out);

XrpError xrp_sign_transaction(const XrpTransaction &transaction,
                              const uint8_t private_key[kPrivateKeySize],
                              uint8_t *out, size_t *in_out_size);

bool xrp_address_from_account(const uint8_t account[kXrpAccountSize], char *out,
                              size_t capacity);
bool xrp_format_amount(uint64_t drops, char *out, size_t capacity);
void clear_xrp_transaction(XrpTransaction *transaction);
const char *xrp_error_text(XrpError error);
bool run_xrp_self_tests();

}  // namespace hexwallet

#endif
