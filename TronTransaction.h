#ifndef HEXWALLET_TRON_TRANSACTION_H
#define HEXWALLET_TRON_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet {

// TRON review/sign surface. The host sends the raw `raw_data` protobuf bytes,
// never a decoded struct: every field that reaches the trusted display and the
// signature is re-parsed here from those exact bytes.
//
// Supported contract types are deliberately narrow:
//   * TransferContract      - native TRX to a 21-byte account address
//   * TransferAssetContract - TRC-10 transfer: chain asset id + 21-byte to
//   * TriggerSmartContract  - TRC-20 transfer(address,uint256) or
//                             transferFrom(address,address,uint256) with
//                             from == owner, against a registered contract,
//                             call_value == 0
// NFT calldata can be structurally decoded, but there are no verified NFT
// contract registrations. All TRC-721/1155 signing requests are refused.
//
// TRC-10 has no contract address: the chain keys the asset by the identifier in
// `asset_name` (mainnet uses the numeric id, for example "1002000"). A
// registered id renders with its verified abbr and precision. Any other
// identifier is displayed byte-for-byte and the amount stays in exact base
// units, because an issuer-defined precision cannot be verified offline.
//
// The memo field (`raw_data.data`) is displayed, bounded to printable ASCII.
// Multi-contract transactions, non-owner permissions, call_token fields, zero
// amounts, batch transfers and contract calls with attached TRX are refused
// instead of guessed at.

constexpr size_t kTronAddressSize = 21;
constexpr size_t kTronTxIdSize = 32;
constexpr size_t kTronSignatureSize = 65;
constexpr size_t kTronWordSize = 32;
constexpr size_t kTronMaxRawData = 1024;
constexpr size_t kTronAddressTextSize = 40;
constexpr size_t kTronAmountTextSize = 96;
constexpr size_t kTronSymbolSize = 16;
// TRC-10 asset identifiers are capped at 32 bytes by the chain. Non-ASCII
// identifiers are rendered as 0x-hex so the display never substitutes glyphs.
constexpr size_t kTronAssetIdSize = 32;
constexpr size_t kTronAssetIdTextSize = 2 * kTronAssetIdSize + 4;
constexpr size_t kTronMethodSize = 24;
// Memo text is shown in full or the request is refused; this is the bound the
// trusted display can render without truncation.
constexpr size_t kTronMemoSize = 64;
constexpr size_t kTronMemoTextSize = kTronMemoSize + 1;
constexpr uint8_t kTronTrxDecimals = 6;
constexpr uint64_t kTronSunPerTrx = 1000000;
// A TRC-20 transfer burns energy; fee_limit is the maximum TRX the chain may
// consume for it. 100 TRX covers a plain USDT transfer with a wide margin.
constexpr uint64_t kTronMaxFeeLimitSun = 100 * kTronSunPerTrx;
// Host transactions normally expire 60 s after timestamp. 24 h is the largest
// window this review treats as sane without a trusted wall clock.
constexpr int64_t kTronMaxLifetimeMs = 24LL * 60LL * 60LL * 1000LL;

enum class TronKind : uint8_t {
  Native = 0,
  Trc20 = 1,
  Trc721 = 2,
  Trc1155 = 3,
  Trc10 = 4,
};

enum class TronError : uint8_t {
  Ok = 0,
  InvalidArgument,
  Malformed,
  Unsupported,
  WrongWallet,
  InvalidAmount,
  FeePolicy,
  UnknownToken,
  CryptoFailure,
  BufferTooSmall,
};

struct TronTransferReview {
  TronKind kind;
  uint8_t owner[kTronAddressSize];
  uint8_t recipient[kTronAddressSize];
  uint8_t token_contract[kTronAddressSize];
  uint8_t token_decimals;
  uint8_t amount[kTronWordSize];  // big-endian 256-bit word
  uint8_t token_id[kTronWordSize];  // ERC-721/1155 id; zero when unused
  bool has_token_id;
  // TRC-10 identifier exactly as it appears in `asset_name`, plus its display
  // form (ASCII verbatim, 0x-hex otherwise). `asset_registered` selects between
  // verified precision and exact base-unit rendering.
  uint8_t asset_id[kTronAssetIdSize];
  uint8_t asset_id_size;
  char asset_id_text[kTronAssetIdTextSize];
  bool asset_registered;
  // TRC-20 entry point, so transfer and transferFrom cannot be confused.
  char method_text[kTronMethodSize];
  // raw_data memo (field 10); present only when the reviewed bytes carry one.
  char memo_text[kTronMemoTextSize];
  bool has_memo;
  uint64_t fee_limit_sun;
  int64_t expiration_ms;
  int64_t timestamp_ms;
  uint8_t ref_block_hash[8];
  uint8_t tx_id[kTronTxIdSize];
  char owner_text[kTronAddressTextSize];
  char recipient_text[kTronAddressTextSize];
  char token_contract_text[kTronAddressTextSize];
  char token_symbol[kTronSymbolSize];
  char amount_text[kTronAmountTextSize];
  char token_id_text[80];
};

struct TronTransaction {
  TronTransferReview review;
  uint8_t raw_data[kTronMaxRawData];
  uint16_t raw_data_size;
  uint32_t address_index;
};

// Parses the raw_data bytes, verifies that the contract owner equals the
// supplied wallet address, resolves the TRC-20 contract through the registered
// token table and fills the trusted-display strings. Never signs.
TronError tron_review_raw_data(const uint8_t *data, size_t size,
                               const uint8_t owner[kTronAddressSize],
                               TronTransaction *out);

// Re-parses the bytes, compares every review field and binds the owner to the
// actual signing key. Returns canonical r||s||v (v = 27 + recovery id, low-S).
// On failure the output is untouched and *in_out_size is zero.
TronError tron_sign_transaction(const TronTransaction &reviewed,
                                const uint8_t private_key[kPrivateKeySize],
                                uint8_t *out_signature, size_t *in_out_size);

// Canonical wire form of a recoverable signature. Split out so the envelope can
// be checked against reference bytes without a curve implementation.
TronError tron_encode_signature(const RecoverableSignature &signature,
                                uint8_t *out_signature, size_t *in_out_size);

// Decimal formatting used by the review. Returns false rather than truncating.
bool tron_format_amount(const TronTransferReview &review, char *out, size_t size);

// 21-byte owner address for a private key (0x41 || keccak256(pubkey)[12..32]).
TronError tron_owner_from_private(const uint8_t private_key[kPrivateKeySize],
                                  uint8_t out_owner[kTronAddressSize]);

void clear_tron_transaction(TronTransaction *transaction);
const char *tron_error_text(TronError error);
bool run_tron_self_tests();

}  // namespace hexwallet

#endif
