#include "StarknetTransaction.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoPrimitives.h"
#include "StarknetCrypto.h"
#include "WalletCustomTokens.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

// Offsets of the "SNV3" payload, kept next to the parser so the layout in the
// header and the code cannot drift apart.
constexpr size_t kOffsetKind = 4;
constexpr size_t kOffsetNonceDa = 5;
constexpr size_t kOffsetFeeDa = 6;
constexpr size_t kOffsetConstructorCount = 7;
constexpr size_t kOffsetClassHash = 8;
constexpr size_t kOffsetSalt = 40;
constexpr size_t kOffsetConstructor = 72;
constexpr size_t kOffsetNonce = 104;
constexpr size_t kOffsetTip = 112;
constexpr size_t kOffsetL1Amount = 120;
constexpr size_t kOffsetL1Price = 128;
constexpr size_t kOffsetL2Amount = 144;
constexpr size_t kOffsetL2Price = 152;
constexpr size_t kOffsetL1DataAmount = 168;
constexpr size_t kOffsetL1DataPrice = 176;
constexpr size_t kOffsetEntryPoint = 192;
constexpr size_t kOffsetCalldataCount = 224;
constexpr size_t kOffsetCalldata = 226;

constexpr size_t kPriceSize = 16;

// Every admitted call is `transfer(recipient, u256 amount)`:
//   to, selector, 3, recipient, amount_low, amount_high
// The account then repeats the concatenated call data as the trailing span, so a
// call costs 6 felts in the call array plus 3 in the span.
constexpr size_t kCallFelts = 6;
constexpr uint64_t kTransferSpanLength = 3;
constexpr size_t kTrailingFelts = 1 + kTransferSpanLength;  // length + data
constexpr size_t kCalldataPerCall = kCallFelts + kTransferSpanLength;
constexpr size_t kCalldataHeaderFelts = 2;  // call-array length + span length

// execute(...) calldata for `calls` transfers.
constexpr size_t calldata_felts(size_t calls) {
  return kCalldataHeaderFelts + calls * kCalldataPerCall;
}
constexpr size_t kMaxCalldataFelts = calldata_felts(kStarknetMaxCalls);

struct StarknetFeltSpan {
  const uint8_t (*felts)[kStarknetFeltSize];
  size_t count;
};

struct StarknetCall {
  uint8_t target[kStarknetFeltSize];
  uint8_t recipient[kStarknetFeltSize];
  uint8_t amount[kStarknetFeltSize];
  bool declared;  // matched a token the user registered on this device
  char symbol[kCustomTokenSymbolSize];
  uint8_t decimals;
};

struct StarknetRequest {
  uint8_t kind;
  uint8_t nonce_da_mode;
  uint8_t fee_da_mode;
  uint8_t class_hash[kStarknetFeltSize];
  uint8_t salt[kStarknetFeltSize];
  uint8_t constructor_key[kStarknetFeltSize];
  uint64_t nonce;
  StarkV3Fees fees;
  StarknetFeltSpan calldata;
};

uint64_t read_be64(const uint8_t *data) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; ++index) value = (value << 8) | data[index];
  return value;
}

bool bytes_are_zero(const uint8_t *data, size_t size) {
  uint8_t aggregate = 0;
  for (size_t index = 0; index < size; ++index) aggregate |= data[index];
  return aggregate == 0;
}

// True when the felt fits in its low `size` bytes, i.e. it is a small integer or
// a u128 operand rather than a full field element.
bool felt_fits(const uint8_t felt[kStarknetFeltSize], size_t size) {
  return bytes_are_zero(felt, kStarknetFeltSize - size);
}

bool felt_to_u64(const uint8_t felt[kStarknetFeltSize], uint64_t *out) {
  if (out == nullptr || !felt_fits(felt, 8)) return false;
  *out = read_be64(felt + kStarknetFeltSize - 8);
  return true;
}

// 64x64 -> 128 without compiler-specific types: MSVC has no __int128 and the
// RISC-V target has no 128-bit multiply.
void mul_u64_u64(uint64_t left, uint64_t right, uint64_t *low, uint64_t *high) {
  const uint64_t left_low = left & 0xffffffffull;
  const uint64_t left_high = left >> 32;
  const uint64_t right_low = right & 0xffffffffull;
  const uint64_t right_high = right >> 32;
  const uint64_t low_low = left_low * right_low;
  const uint64_t low_high = left_low * right_high;
  const uint64_t high_low = left_high * right_low;
  const uint64_t high_high = left_high * right_high;
  const uint64_t middle =
      (low_low >> 32) + (low_high & 0xffffffffull) + (high_low & 0xffffffffull);
  *low = (middle << 32) | (low_low & 0xffffffffull);
  *high = high_high + (low_high >> 32) + (high_low >> 32) + (middle >> 32);
}

struct Wide256 {
  uint64_t limb[4];
};

// wide += factor * multiplier, with a u64 factor and a u128 multiplier.
void wide_add_product(Wide256 *wide, uint64_t factor,
                      const uint8_t multiplier[kPriceSize]) {
  const uint64_t multiplier_high = read_be64(multiplier);
  const uint64_t multiplier_low = read_be64(multiplier + 8);
  uint64_t product[4] = {};
  mul_u64_u64(factor, multiplier_low, &product[0], &product[1]);
  mul_u64_u64(factor, multiplier_high, &product[2], &product[3]);
  uint64_t carry = 0;
  for (size_t index = 0; index < 4; ++index) {
    const uint64_t sum = wide->limb[index] + product[index];
    const uint64_t with_carry = sum + carry;
    carry = (sum < wide->limb[index] ? 1u : 0u) + (with_carry < sum ? 1u : 0u);
    wide->limb[index] = with_carry;
  }
}

void wide_add_u64(Wide256 *wide, uint64_t value) {
  uint64_t carry = value;
  for (size_t index = 0; index < 4 && carry != 0; ++index) {
    const uint64_t sum = wide->limb[index] + carry;
    carry = sum < wide->limb[index] ? 1 : 0;
    wide->limb[index] = sum;
  }
}

void wide_to_bytes(const Wide256 &wide, uint8_t out[kStarknetFeltSize]) {
  for (size_t index = 0; index < 4; ++index) {
    const uint64_t value = wide.limb[3 - index];
    for (size_t byte = 0; byte < 8; ++byte) {
      out[index * 8 + byte] = static_cast<uint8_t>(value >> (8 * (7 - byte)));
    }
  }
}

// tip + L1_GAS + L2_GAS + L1_DATA. Each product is below 2^192, so the sum is
// exact in 256 bits and the fee line never rounds.
void maximum_fee(const StarkV3Fees &fees, uint8_t out[kStarknetFeltSize]) {
  Wide256 wide = {};
  wide_add_u64(&wide, fees.tip);
  wide_add_product(&wide, fees.l1_gas.max_amount, fees.l1_gas.max_price);
  wide_add_product(&wide, fees.l2_gas.max_amount, fees.l2_gas.max_price);
  wide_add_product(&wide, fees.l1_data_gas.max_amount,
                   fees.l1_data_gas.max_price);
  wide_to_bytes(wide, out);
}

bool entry_point_is_execute(const uint8_t entry_point[kStarknetFeltSize]) {
  uint8_t selector[kStarknetFeltSize];
  if (!starknet_selector("execute", selector)) return false;
  return chain_constant_time_equal(entry_point, selector, kStarknetFeltSize);
}

ChainError parse_payload(const uint8_t *payload, size_t size,
                         StarknetRequest *request) {
  if (payload == nullptr || request == nullptr) {
    return ChainError::InvalidArgument;
  }
  if (size < kStarknetCommonHeaderSize || memcmp(payload, "SNV3", 4) != 0) {
    return ChainError::Malformed;
  }
  memset(request, 0, sizeof(*request));
  request->kind = payload[kOffsetKind];
  if (request->kind != kStarknetKindInvoke &&
      request->kind != kStarknetKindDeploy) {
    return ChainError::Unsupported;
  }
  request->nonce_da_mode = payload[kOffsetNonceDa];
  request->fee_da_mode = payload[kOffsetFeeDa];
  if (request->nonce_da_mode > 1 || request->fee_da_mode > 1) {
    return ChainError::Unsupported;
  }
  // Multi-key and session-key accounts put more than one felt in the
  // constructor. This adapter cannot prove ownership of those, so it refuses
  // them instead of trusting a host-supplied account address.
  if (payload[kOffsetConstructorCount] != 1) return ChainError::Unsupported;
  memcpy(request->class_hash, payload + kOffsetClassHash, kStarknetFeltSize);
  memcpy(request->salt, payload + kOffsetSalt, kStarknetFeltSize);
  memcpy(request->constructor_key, payload + kOffsetConstructor,
         kStarknetFeltSize);
  request->nonce = read_be64(payload + kOffsetNonce);
  request->fees.tip = read_be64(payload + kOffsetTip);
  request->fees.l1_gas.max_amount = read_be64(payload + kOffsetL1Amount);
  memcpy(request->fees.l1_gas.max_price, payload + kOffsetL1Price, kPriceSize);
  request->fees.l2_gas.max_amount = read_be64(payload + kOffsetL2Amount);
  memcpy(request->fees.l2_gas.max_price, payload + kOffsetL2Price, kPriceSize);
  request->fees.l1_data_gas.max_amount = read_be64(payload + kOffsetL1DataAmount);
  memcpy(request->fees.l1_data_gas.max_price, payload + kOffsetL1DataPrice,
         kPriceSize);

  if (request->kind == kStarknetKindDeploy) {
    return size == kStarknetDeployPayloadSize ? ChainError::Ok
                                              : ChainError::Malformed;
  }
  if (!entry_point_is_execute(payload + kOffsetEntryPoint)) {
    return ChainError::Unsupported;
  }
  const uint16_t calldata_count = static_cast<uint16_t>(
      (static_cast<uint16_t>(payload[kOffsetCalldataCount]) << 8) |
      payload[kOffsetCalldataCount + 1]);
  // The calldata has to be exactly what one write of 1..kStarknetMaxCalls
  // transfers serializes to; anything else is a layout the device cannot print.
  if (calldata_count < calldata_felts(1) || calldata_count > kMaxCalldataFelts ||
      (calldata_count - kCalldataHeaderFelts) % kCalldataPerCall != 0) {
    return ChainError::Malformed;
  }
  if (size != kStarknetInvokeHeaderSize +
                  static_cast<size_t>(calldata_count) * kStarknetFeltSize) {
    return ChainError::Malformed;
  }
  request->calldata.felts =
      reinterpret_cast<const uint8_t(*)[kStarknetFeltSize]>(payload +
                                                            kOffsetCalldata);
  request->calldata.count = calldata_count;
  return ChainError::Ok;
}

// Reads one u256 ERC-20 amount. The two operands are stored as felts, i.e.
// right-aligned, so the significant bytes are the low half of each.
ChainError read_amount(const uint8_t low[kStarknetFeltSize],
                       const uint8_t high[kStarknetFeltSize],
                       uint8_t amount[kStarknetFeltSize]) {
  if (!felt_fits(low, 16) || !felt_fits(high, 16)) return ChainError::Malformed;
  const bool empty = bytes_are_zero(low, kStarknetFeltSize) &&
                     bytes_are_zero(high, kStarknetFeltSize);
  if (empty) return ChainError::InvalidAmount;
  memset(amount, 0, kStarknetFeltSize);
  memcpy(amount, high + 16, 16);
  memcpy(amount + 16, low + 16, 16);
  return ChainError::Ok;
}

// Parses the compiled `execute` calldata and proves it is a batch of N
// `transfer(recipient, u256)` calls, in the order the account will run them.
// The trailing span is the concatenation the account slices with the offsets
// from the call array, so it is compared felt by felt: a review that showed the
// call-array copy while the account executed the span would be a lie.
ChainError decode_calls(const StarknetRequest &request, StarknetCall *calls,
                        size_t *out_count) {
  const size_t count = request.calldata.count;
  uint64_t call_count = 0;
  if (!felt_to_u64(request.calldata.felts[0], &call_count)) {
    return ChainError::Malformed;
  }
  if (call_count == 0 || call_count > kStarknetMaxCalls) {
    return ChainError::Unsupported;
  }
  const size_t expected = calldata_felts(static_cast<size_t>(call_count));
  if (expected != count) return ChainError::Malformed;

  const size_t trailing_index = 1 + static_cast<size_t>(call_count) * kCallFelts;
  uint64_t trailing = 0;
  if (!felt_to_u64(request.calldata.felts[trailing_index], &trailing) ||
      trailing != kTransferSpanLength * call_count) {
    return ChainError::Malformed;
  }
  const uint8_t *span = request.calldata.felts[trailing_index + 1];
  uint8_t transfer_selector[kStarknetFeltSize];
  if (!starknet_selector("transfer", transfer_selector)) {
    return ChainError::CryptoFailure;
  }
  for (size_t index = 0; index < call_count; ++index) {
    const uint8_t (*call)[kStarknetFeltSize] =
        request.calldata.felts + 1 + index * kCallFelts;
    uint64_t span_length = 0;
    if (!felt_to_u64(call[2], &span_length)) return ChainError::Malformed;
    if (span_length != kTransferSpanLength) return ChainError::Unsupported;
    if (!chain_constant_time_equal(call[1], transfer_selector,
                                   kStarknetFeltSize)) {
      return ChainError::Unsupported;
    }
    const uint8_t *inline_span = call[3];
    if (!chain_constant_time_equal(
            inline_span, span + index * kTransferSpanLength * kStarknetFeltSize,
            kTransferSpanLength * kStarknetFeltSize)) {
      return ChainError::Malformed;
    }
    StarknetCall &decoded = calls[index];
    memset(&decoded, 0, sizeof(decoded));
    if (bytes_are_zero(call[0], kStarknetFeltSize)) {
      return ChainError::InvalidAmount;
    }
    if (bytes_are_zero(inline_span, kStarknetFeltSize)) {
      return ChainError::InvalidAmount;
    }
    memcpy(decoded.target, call[0], kStarknetFeltSize);
    memcpy(decoded.recipient, inline_span, kStarknetFeltSize);
    const ChainError amount_error =
        read_amount(inline_span + kStarknetFeltSize,
                    inline_span + 2 * kStarknetFeltSize, decoded.amount);
    if (amount_error != ChainError::Ok) return amount_error;
  }
  *out_count = static_cast<size_t>(call_count);
  return ChainError::Ok;
}

// Attaches the labels of any token the user registered on this device. The
// amounts stay base units unless a record exists, and a record is a local
// label, never an issuer attestation - the review says so.
void annotate_tokens(StarknetCall *calls, size_t count, const char *network_id) {
  for (size_t index = 0; index < count; ++index) {
    StarknetCall &call = calls[index];
    const CustomTokenRecord *record =
        custom_token_find(network_id, call.target, kStarknetFeltSize);
    if (record == nullptr) continue;
    call.declared = true;
    call.decimals = record->decimals;
    memcpy(call.symbol, record->symbol, sizeof(call.symbol));
    call.symbol[sizeof(call.symbol) - 1] = '\0';
  }
}

bool format_amount(const StarknetCall &call, char *out, size_t out_size) {
  char text[kChainMaxAmount];
  if (call.declared) {
    if (!chain_format_units256(call.amount, call.decimals, call.symbol, text,
                               sizeof(text))) {
      return false;
    }
    return chain_copy_text(out, out_size, text);
  }
  if (!chain_format_units256(call.amount, 0, "raw", text, sizeof(text))) {
    return false;
  }
  return chain_copy_text(out, out_size, text);
}

ChainError check_fee_policy(const StarkV3Fees &fees) {
  // A v3 transaction has to offer gas for execution at a non-zero price. An empty
  // L1_DATA bound is accepted because pre-0.13.4 clients still send it.
  if (fees.l1_gas.max_amount == 0 || fees.l2_gas.max_amount == 0) {
    return ChainError::FeePolicy;
  }
  if (bytes_are_zero(fees.l1_gas.max_price, kPriceSize) ||
      bytes_are_zero(fees.l2_gas.max_price, kPriceSize)) {
    return ChainError::FeePolicy;
  }
  return ChainError::Ok;
}

bool fill_deploy_review(const StarknetRequest &request, ChainReview *review) {
  if (!chain_copy_text(review->recipient, sizeof(review->recipient),
                       "ACCOUNT DEPLOY") ||
      !chain_copy_text(review->amount, sizeof(review->amount), "0 STRK")) {
    return false;
  }
  char class_text[kStarknetAddressTextSize];
  char salt_text[kStarknetAddressTextSize];
  if (!starknet_felt_text(request.class_hash, class_text, sizeof(class_text)) ||
      !starknet_felt_text(request.salt, salt_text, sizeof(salt_text))) {
    return false;
  }
  const int written = snprintf(
      review->extra, sizeof(review->extra),
      "CLASS\n%s\nSALT\n%s\nNONCE %llu\nDA %u/%u", class_text, salt_text,
      static_cast<unsigned long long>(request.nonce),
      static_cast<unsigned>(request.nonce_da_mode),
      static_cast<unsigned>(request.fee_da_mode));
  return written > 0 && static_cast<size_t>(written) < sizeof(review->extra);
}

// One review row per call. The summary fields mirror the first call so a
// consumer that only reads them still shows a real destination.
bool fill_invoke_review(const StarknetRequest &request, const StarknetCall *calls,
                        size_t call_count, ChainReview *review) {
  char class_text[kStarknetAddressTextSize];
  if (!starknet_felt_text(request.class_hash, class_text, sizeof(class_text))) {
    return false;
  }
  if (call_count > kChainMaxCalls) return false;
  for (size_t index = 0; index < call_count; ++index) {
    ChainCallSummary &summary = review->calls[index];
    if (!starknet_felt_text(calls[index].target, summary.target,
                            sizeof(summary.target)) ||
        !starknet_felt_text(calls[index].recipient, summary.recipient,
                            sizeof(summary.recipient)) ||
        !format_amount(calls[index], summary.amount, sizeof(summary.amount))) {
      return false;
    }
    summary.declared = calls[index].declared;
  }
  review->call_count = static_cast<uint8_t>(call_count);
  if (!chain_copy_text(review->recipient, sizeof(review->recipient),
                       review->calls[0].recipient) ||
      !chain_copy_text(review->amount, sizeof(review->amount),
                       review->calls[0].amount)) {
    return false;
  }
  // The account address is a function of the class hash, so the class hash is
  // shown too: the companion app can only compare it if the device displays it.
  // A batch keeps the call rows; the count makes a mis-rendered list obvious.
  const int written = snprintf(
      review->extra, sizeof(review->extra), "CALLS %u\nCLASS\n%s\nNONCE %llu\nDA %u/%u",
      static_cast<unsigned>(call_count), class_text,
      static_cast<unsigned long long>(request.nonce),
      static_cast<unsigned>(request.nonce_da_mode),
      static_cast<unsigned>(request.fee_da_mode));
  return written > 0 && static_cast<size_t>(written) < sizeof(review->extra);
}

}  // namespace

bool starknet_felt_text(const uint8_t felt[kStarknetFeltSize], char *out,
                        size_t capacity) {
  static const char kDigits[] = "0123456789abcdef";
  if (felt == nullptr || out == nullptr || capacity < kStarknetAddressTextSize) {
    return false;
  }
  out[0] = '0';
  out[1] = 'x';
  for (size_t index = 0; index < kStarknetFeltSize; ++index) {
    out[2 + index * 2] = kDigits[felt[index] >> 4];
    out[3 + index * 2] = kDigits[felt[index] & 0x0f];
  }
  out[kStarknetAddressTextSize - 1] = '\0';
  return true;
}

bool starknet_selector(const char *name, uint8_t out[kStarknetFeltSize]) {
  if (name == nullptr || out == nullptr) return false;
  uint8_t digest[kKeccak256Size];
  if (!crypto_keccak256(reinterpret_cast<const uint8_t *>(name), strlen(name),
                        digest)) {
    return false;
  }
  memcpy(out, digest, kStarknetFeltSize);
  out[0] &= 0x03;  // Starknet selectors are the low 250 bits of keccak-256
  secure_zero(digest, sizeof(digest));
  return true;
}

bool starknet_key_pair(const uint8_t bip32_key[kPrivateKeySize],
                       uint8_t out_private[kStarknetFeltSize],
                       uint8_t out_public[kStarknetFeltSize]) {
  if (bip32_key == nullptr || out_private == nullptr || out_public == nullptr) {
    return false;
  }
  uint8_t private_key[kStarknetFeltSize];
  const bool ok = stark_grind_key(bip32_key, private_key) &&
                  stark_public_key(private_key, out_public);
  if (!ok) {
    secure_zero(private_key, sizeof(private_key));
    return false;
  }
  memcpy(out_private, private_key, kStarknetFeltSize);
  secure_zero(private_key, sizeof(private_key));
  return true;
}

bool starknet_account_address(const uint8_t class_hash[kStarknetFeltSize],
                              const uint8_t salt[kStarknetFeltSize],
                              const uint8_t public_key[kStarknetFeltSize],
                              uint8_t out[kStarknetFeltSize]) {
  if (class_hash == nullptr || salt == nullptr || public_key == nullptr ||
      out == nullptr) {
    return false;
  }
  uint8_t constructor[1][kStarknetFeltSize];
  memcpy(constructor[0], public_key, kStarknetFeltSize);
  uint8_t deployer[kStarknetFeltSize] = {};
  return stark_contract_address(class_hash, salt, constructor, 1, deployer, out);
}

ChainError starknet_review_payload(const uint8_t *payload, size_t size,
                                   const uint8_t bip32_key[kPrivateKeySize],
                                   ChainReview *review, uint8_t digest[32]) {
  if (bip32_key == nullptr || review == nullptr || digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  StarknetRequest request;
  ChainError error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;
  error = check_fee_policy(request.fees);
  if (error != ChainError::Ok) return error;

  uint8_t own_private[kStarknetFeltSize];
  uint8_t own_public[kStarknetFeltSize];
  if (!starknet_key_pair(bip32_key, own_private, own_public)) {
    return ChainError::CryptoFailure;
  }
  // The constructor argument is the account key. If it is not this wallet's Stark
  // key the account is not ours, whatever address the host claims.
  const bool owned = chain_constant_time_equal(own_public,
                                               request.constructor_key,
                                               kStarknetFeltSize);
  secure_zero(own_private, sizeof(own_private));
  secure_zero(own_public, sizeof(own_public));
  if (!owned) return ChainError::WrongWallet;

  uint8_t account[kStarknetFeltSize];
  if (!starknet_account_address(request.class_hash, request.salt,
                                request.constructor_key, account)) {
    return ChainError::CryptoFailure;
  }

  StarknetCall calls[kStarknetMaxCalls];
  size_t call_count = 0;
  bool hashed = false;
  if (request.kind == kStarknetKindDeploy) {
    uint8_t constructor[1][kStarknetFeltSize];
    memcpy(constructor[0], request.constructor_key, kStarknetFeltSize);
    hashed = stark_deploy_account_v3_hash(
        account, request.class_hash, request.salt, constructor, 1,
        request.nonce, request.fees, request.nonce_da_mode, request.fee_da_mode,
        digest);
  } else {
    error = decode_calls(request, calls, &call_count);
    if (error != ChainError::Ok) {
      secure_zero(calls, sizeof(calls));
      return error;
    }
    annotate_tokens(calls, call_count, "stark");
    hashed = stark_invoke_v3_hash(account, request.nonce, request.fees,
                                  request.nonce_da_mode, request.fee_da_mode,
                                  request.calldata.felts, request.calldata.count,
                                  digest);
  }
  if (!hashed) {
    secure_zero(calls, sizeof(calls));
    return ChainError::CryptoFailure;
  }

  uint8_t fee[kStarknetFeltSize];
  maximum_fee(request.fees, fee);
  char fee_text[64];
  const bool fee_ok = chain_format_units256(fee, kStarknetDecimals, "STRK",
                                            fee_text, sizeof(fee_text));
  secure_zero(fee, sizeof(fee));
  if (!fee_ok) return ChainError::BufferTooSmall;

  memset(review, 0, sizeof(*review));
  char account_text[kStarknetAddressTextSize];
  if (!starknet_felt_text(account, account_text, sizeof(account_text)) ||
      !chain_copy_text(review->symbol, sizeof(review->symbol), "STRK") ||
      !chain_copy_text(review->sender, sizeof(review->sender), account_text) ||
      !chain_copy_text(review->fee, sizeof(review->fee), fee_text)) {
    return ChainError::BufferTooSmall;
  }
  const bool filled =
      request.kind == kStarknetKindDeploy
          ? fill_deploy_review(request, review)
          : fill_invoke_review(request, calls, call_count, review);
  secure_zero(calls, sizeof(calls));
  if (!filled) {
    memset(review, 0, sizeof(*review));
    return ChainError::BufferTooSmall;
  }
  return ChainError::Ok;
}

ChainError starknet_sign_payload(const uint8_t *payload, size_t size,
                                 const uint8_t bip32_key[kPrivateKeySize],
                                 uint8_t *out, size_t *in_out_size) {
  if (in_out_size == nullptr) return ChainError::InvalidArgument;
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  if (out != nullptr) secure_zero(out, capacity);
  if (payload == nullptr || bip32_key == nullptr || out == nullptr) {
    return ChainError::InvalidArgument;
  }
  ChainReview review;
  uint8_t digest[kStarknetFeltSize];
  ChainError error =
      starknet_review_payload(payload, size, bip32_key, &review, digest);
  if (error != ChainError::Ok) return error;
  if (capacity < kStarknetSignatureSize) {
    secure_zero(digest, sizeof(digest));
    return ChainError::BufferTooSmall;
  }
  uint8_t private_key[kStarknetFeltSize];
  uint8_t public_key[kStarknetFeltSize];
  uint8_t r[kStarknetFeltSize];
  uint8_t s[kStarknetFeltSize];
  const bool signed_ok =
      starknet_key_pair(bip32_key, private_key, public_key) &&
      stark_sign(private_key, digest, r, s);
  secure_zero(private_key, sizeof(private_key));
  secure_zero(public_key, sizeof(public_key));
  secure_zero(digest, sizeof(digest));
  if (!signed_ok) {
    secure_zero(r, sizeof(r));
    secure_zero(s, sizeof(s));
    secure_zero(out, capacity);
    return ChainError::CryptoFailure;
  }
  memcpy(out, r, kStarknetFeltSize);
  memcpy(out + kStarknetFeltSize, s, kStarknetFeltSize);
  *in_out_size = kStarknetSignatureSize;
  secure_zero(r, sizeof(r));
  secure_zero(s, sizeof(s));
  return ChainError::Ok;
}

namespace {

void write_be64(uint64_t value, uint8_t *out) {
  for (size_t index = 0; index < 8; ++index) {
    out[index] = static_cast<uint8_t>(value >> (8 * (7 - index)));
  }
}

// Left-pads short hex strings so vectors can be written without leading zeros.
bool decode_felt(const char *text, uint8_t out[kStarknetFeltSize]) {
  if (text == nullptr || out == nullptr) return false;
  const char *digits = text;
  if (digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) digits += 2;
  const size_t length = strlen(digits);
  if (length == 0 || length > 2 * kStarknetFeltSize) return false;
  char padded[2 * kStarknetFeltSize + 1];
  memset(padded, '0', 2 * kStarknetFeltSize);
  memcpy(padded + (2 * kStarknetFeltSize - length), digits, length);
  padded[2 * kStarknetFeltSize] = '\0';
  size_t decoded = 0;
  if (!chain_parse_hex(padded, out, kStarknetFeltSize, &decoded) ||
      decoded != kStarknetFeltSize) {
    secure_zero(out, kStarknetFeltSize);
    return false;
  }
  return true;
}

// One `transfer` call exactly as the account ABI serializes it.
struct CallSpec {
  const char *token;
  const char *recipient;
  uint64_t amount_low;
  uint64_t amount_high;
};

// Builds [N, (token, selector, 3, recipient, low, high)*, 3N, span...] and
// returns the felt count, or 0 on error.
size_t build_calldata(uint8_t *out, size_t felt_capacity, const CallSpec *calls,
                      size_t count) {
  if (out == nullptr || calls == nullptr || count == 0 ||
      count > kStarknetMaxCalls || calldata_felts(count) > felt_capacity) {
    return 0;
  }
  uint8_t transfer_selector[kStarknetFeltSize];
  if (!starknet_selector("transfer", transfer_selector)) return 0;
  const size_t felt = kStarknetFeltSize;
  uint8_t (*felts)[kStarknetFeltSize] =
      reinterpret_cast<uint8_t(*)[kStarknetFeltSize]>(out);
  size_t cursor = 0;
  felts[cursor][felt - 1] = static_cast<uint8_t>(count);
  ++cursor;
  for (size_t index = 0; index < count; ++index) {
    if (!decode_felt(calls[index].token, felts[cursor]) ||
        !decode_felt(calls[index].recipient, felts[cursor + 3])) {
      return 0;
    }
    memcpy(felts[cursor + 1], transfer_selector, felt);
    felts[cursor + 2][felt - 1] = 3;
    write_be64(calls[index].amount_low, felts[cursor + 4] + felt - 8);
    write_be64(calls[index].amount_high, felts[cursor + 5] + felt - 8);
    cursor += kCallFelts;
  }
  felts[cursor][felt - 1] = static_cast<uint8_t>(3 * count);
  ++cursor;
  for (size_t index = 0; index < count; ++index) {
    if (!decode_felt(calls[index].recipient, felts[cursor])) return 0;
    write_be64(calls[index].amount_low, felts[cursor + 1] + felt - 8);
    write_be64(calls[index].amount_high, felts[cursor + 2] + felt - 8);
    cursor += kTransferSpanLength;
  }
  return cursor == calldata_felts(count) ? cursor : 0;
}

// Common "SNV3" header shared by both kinds.
void fill_header(uint8_t *payload, uint8_t kind,
                 const uint8_t class_hash[kStarknetFeltSize],
                 const uint8_t salt[kStarknetFeltSize],
                 const uint8_t key[kStarknetFeltSize], uint64_t nonce) {
  memcpy(payload, "SNV3", 4);
  payload[kOffsetKind] = kind;
  payload[kOffsetConstructorCount] = 1;
  memcpy(payload + kOffsetClassHash, class_hash, kStarknetFeltSize);
  memcpy(payload + kOffsetSalt, salt, kStarknetFeltSize);
  memcpy(payload + kOffsetConstructor, key, kStarknetFeltSize);
  write_be64(nonce, payload + kOffsetNonce);
  write_be64(9, payload + kOffsetTip);
  write_be64(1000, payload + kOffsetL1Amount);
  write_be64(2000, payload + kOffsetL1Price + 8);
  write_be64(3000, payload + kOffsetL2Amount);
  write_be64(4000, payload + kOffsetL2Price + 8);
  write_be64(500, payload + kOffsetL1DataAmount);
  write_be64(600, payload + kOffsetL1DataPrice + 8);
}

}  // namespace

bool run_starknet_self_tests() {
  // Vectors come from an independent reference implementation (this
  // repository's Python reference, itself pinned to the published StarkWare /
  // @scure Pedersen, Poseidon, Stark-key and ECDSA vectors) plus the two
  // selector constants the Starknet ecosystem ships for execute/transfer.
  static const char *kBip32Key =
      "1f2e3d4c5b6a79880f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a6978";
  static const char *kStarkPublic =
      "0xfd951253df631cdedad78b3aa27a417f73c9c7da45e3673007a068bb122663";
  static const char *kClassHash =
      "0x34445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162";
  static const char *kSalt =
      "0x5464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6061626364";
  static const char *kAccount =
      "0x2d2035baa0f96a8f55eccb4edc6042a200dcc994b014260bc0959edcf5446c7";
  static const char *kExecuteSelector =
      "0x240060cdb34fcc260f41eac7474ee1d7c80b7e3607daff9ac67c7ea2ebb1c44";
  static const char *kTransferSelector =
      "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e";
  static const char *kRecipient =
      "0x2434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6061";
  static const char *kSingleToken = "0xabcdef01";
  static const char *kBatchTokenA =
      "0x142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60";
  static const char *kBatchRecipientB =
      "0x64748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465";
  static const char *kInvokeHash =
      "0x7d9e30284fbe346a0d4571c0e1aa590db22d978f9817442af5619cf3e2891cc";
  static const char *kInvokeR =
      "0x6e1de98e86f5ee9653c55aa5feef1914f886160cdbeb6ca26f9ffb02b6337c3";
  static const char *kInvokeS =
      "0xf9e31e93d31e8213d07695498776f9e8ed70299bdb9d2917d114164f215b40";
  static const char *kBatchHash =
      "0x6cf464fb2a4bcbc8ea754dd71f756685851029e2936ca7bf7587689395b673b";
  static const char *kBatchR =
      "0x74c2bcca8adf8ea060fc89ea181fc0991c093600deebac45dae4444929f0a2";
  static const char *kBatchS =
      "0x13b9624969f217bb372e2f91264ff82487e49adb3d351c639277bfd1eddc059";
  static const char *kDeployHash =
      "0x1583ab150bd9dd05eb82d57b2554817ec93cadf877218fa07162163010d1cb";
  static const char *kDeployR =
      "0x4b8c69d73ab6f4ea67b08aea5cc8a4a65e5663d532c8481e52b47090274318f";
  static const char *kDeployS =
      "0x7d73b6b5aa083d091f096c914bae6e4dfcb9c5dd40041f782e592a9148d9690";
  static const uint64_t kAmountLow = 1000000000000000005ull;

  uint8_t bip32_key[kPrivateKeySize];
  size_t bip32_size = 0;
  if (!chain_parse_hex(kBip32Key, bip32_key, sizeof(bip32_key), &bip32_size) ||
      bip32_size != kPrivateKeySize) {
    return false;
  }
  uint8_t class_hash[kStarknetFeltSize];
  uint8_t salt[kStarknetFeltSize];
  uint8_t public_key[kStarknetFeltSize];
  uint8_t expected_account[kStarknetFeltSize];
  uint8_t expected_execute[kStarknetFeltSize];
  uint8_t expected_transfer[kStarknetFeltSize];
  uint8_t expected_recipient[kStarknetFeltSize];
  uint8_t expected_invoke[kStarknetFeltSize];
  uint8_t expected_batch[kStarknetFeltSize];
  uint8_t expected_deploy[kStarknetFeltSize];
  uint8_t expected_r[kStarknetFeltSize];
  uint8_t expected_s[kStarknetFeltSize];
  uint8_t digest[kStarknetFeltSize];
  bool passed = decode_felt(kClassHash, class_hash) &&
                decode_felt(kSalt, salt) &&
                decode_felt(kStarkPublic, public_key) &&
                decode_felt(kAccount, expected_account) &&
                decode_felt(kExecuteSelector, expected_execute) &&
                decode_felt(kTransferSelector, expected_transfer) &&
                decode_felt(kRecipient, expected_recipient) &&
                decode_felt(kInvokeHash, expected_invoke) &&
                decode_felt(kBatchHash, expected_batch) &&
                decode_felt(kDeployHash, expected_deploy);

  uint8_t private_key[kStarknetFeltSize];
  uint8_t derived_public[kStarknetFeltSize];
  passed = passed && starknet_key_pair(bip32_key, private_key, derived_public);
  passed = passed && chain_constant_time_equal(derived_public, public_key,
                                               kStarknetFeltSize);
  secure_zero(private_key, sizeof(private_key));
  secure_zero(derived_public, sizeof(derived_public));

  uint8_t account[kStarknetFeltSize];
  passed = passed && starknet_account_address(class_hash, salt, public_key,
                                              account);
  passed = passed && chain_constant_time_equal(account, expected_account,
                                               kStarknetFeltSize);

  uint8_t selector[kStarknetFeltSize];
  passed = passed && starknet_selector("execute", selector) &&
           chain_constant_time_equal(selector, expected_execute,
                                     kStarknetFeltSize) &&
           starknet_selector("transfer", selector) &&
           chain_constant_time_equal(selector, expected_transfer,
                                     kStarknetFeltSize);

  // --- invoke: one ERC-20 transfer ---------------------------------------
  uint8_t single[kStarknetInvokeHeaderSize +
                 calldata_felts(1) * kStarknetFeltSize] = {};
  fill_header(single, kStarknetKindInvoke, class_hash, salt, public_key, 7);
  memcpy(single + kOffsetEntryPoint, expected_execute, kStarknetFeltSize);
  const CallSpec single_call = {kSingleToken, kRecipient, kAmountLow, 0};
  const size_t single_felts =
      build_calldata(single + kOffsetCalldata,
                     (sizeof(single) - kOffsetCalldata) / kStarknetFeltSize,
                     &single_call, 1);
  passed = passed && single_felts == calldata_felts(1);
  single[kOffsetCalldataCount + 1] = static_cast<uint8_t>(single_felts);

  ChainReview review;
  passed = passed && starknet_review_payload(single, sizeof(single), bip32_key,
                                             &review, digest) == ChainError::Ok;
  passed = passed && chain_constant_time_equal(digest, expected_invoke,
                                               kStarknetFeltSize);
  passed = passed && strcmp(review.symbol, "STRK") == 0;
  passed = passed && strcmp(review.fee, "0.000000000014300009 STRK") == 0;
  passed = passed && review.call_count == 1;
  passed = passed && strcmp(review.amount, "1000000000000000005 raw") == 0;
  char expected_text[kStarknetAddressTextSize];
  passed = passed && starknet_felt_text(expected_account, expected_text,
                                        sizeof(expected_text)) &&
           strcmp(review.sender, expected_text) == 0;
  passed = passed && starknet_felt_text(expected_recipient, expected_text,
                                        sizeof(expected_text)) &&
           strcmp(review.calls[0].recipient, expected_text) == 0 &&
           strcmp(review.recipient, expected_text) == 0;
  passed = passed && strstr(review.extra, "CALLS 1") != nullptr;
  passed = passed && starknet_felt_text(class_hash, expected_text,
                                        sizeof(expected_text)) &&
           strstr(review.extra, expected_text) != nullptr;

  uint8_t signature[kStarknetSignatureSize];
  size_t signature_size = sizeof(signature);
  passed = passed && starknet_sign_payload(single, sizeof(single), bip32_key,
                                           signature, &signature_size) ==
                         ChainError::Ok;
  passed = passed && signature_size == kStarknetSignatureSize;
  passed = passed && decode_felt(kInvokeR, expected_r) &&
           decode_felt(kInvokeS, expected_s) &&
           chain_constant_time_equal(signature, expected_r, kStarknetFeltSize) &&
           chain_constant_time_equal(signature + kStarknetFeltSize, expected_s,
                                     kStarknetFeltSize) &&
           stark_verify(public_key, expected_invoke, expected_r, expected_s);

  // --- invoke: a batch of two transfers ----------------------------------
  const CallSpec batch_calls[2] = {
      {kBatchTokenA, kRecipient, 1500000, 0},
      {kSingleToken, kBatchRecipientB, kAmountLow, 0},
  };
  uint8_t batch[kStarknetInvokeHeaderSize +
                calldata_felts(2) * kStarknetFeltSize] = {};
  fill_header(batch, kStarknetKindInvoke, class_hash, salt, public_key, 7);
  memcpy(batch + kOffsetEntryPoint, expected_execute, kStarknetFeltSize);
  const size_t batch_felts =
      build_calldata(batch + kOffsetCalldata,
                     (sizeof(batch) - kOffsetCalldata) / kStarknetFeltSize,
                     batch_calls, 2);
  passed = passed && batch_felts == calldata_felts(2);
  batch[kOffsetCalldataCount + 1] = static_cast<uint8_t>(batch_felts);

  passed = passed && starknet_review_payload(batch, sizeof(batch), bip32_key,
                                             &review, digest) == ChainError::Ok &&
           chain_constant_time_equal(digest, expected_batch, kStarknetFeltSize);
  passed = passed && review.call_count == 2;
  passed = passed && strcmp(review.calls[0].amount, "1500000 raw") == 0 &&
           strcmp(review.calls[1].amount, "1000000000000000005 raw") == 0;
  passed = passed && strstr(review.extra, "CALLS 2") != nullptr;
  uint8_t token_a[kStarknetFeltSize];
  passed = passed && decode_felt(kBatchTokenA, token_a) &&
           starknet_felt_text(token_a, expected_text, sizeof(expected_text)) &&
           strcmp(review.calls[0].target, expected_text) == 0;

  size_t batch_signature_size = sizeof(signature);
  passed = passed && starknet_sign_payload(batch, sizeof(batch), bip32_key,
                                           signature, &batch_signature_size) ==
                         ChainError::Ok &&
           batch_signature_size == kStarknetSignatureSize &&
           decode_felt(kBatchR, expected_r) && decode_felt(kBatchS, expected_s) &&
           chain_constant_time_equal(signature, expected_r, kStarknetFeltSize) &&
           chain_constant_time_equal(signature + kStarknetFeltSize, expected_s,
                                     kStarknetFeltSize);

  // A token the user registered on the device gets its symbol and decimals; the
  // signed digest must not move, because the metadata is a local label.
  passed = passed && custom_token_add("stark", token_a, kStarknetFeltSize, "USDC",
                                     "USD Coin", 6) == CustomTokenError::Ok &&
           starknet_review_payload(batch, sizeof(batch), bip32_key, &review,
                                   digest) == ChainError::Ok &&
           chain_constant_time_equal(digest, expected_batch, kStarknetFeltSize) &&
           strcmp(review.calls[0].amount, "1.5 USDC") == 0 &&
           strcmp(review.calls[1].amount, "1000000000000000005 raw") == 0;
  passed = passed && custom_token_remove("stark", token_a, kStarknetFeltSize) ==
                         CustomTokenError::Ok &&
           starknet_review_payload(batch, sizeof(batch), bip32_key, &review,
                                   digest) == ChainError::Ok &&
           strcmp(review.calls[0].amount, "1500000 raw") == 0;

  // --- deploy_account ----------------------------------------------------
  uint8_t deploy[kStarknetDeployPayloadSize];
  memcpy(deploy, single, sizeof(deploy));
  deploy[kOffsetKind] = kStarknetKindDeploy;
  ChainReview deploy_review;
  passed = passed && starknet_review_payload(deploy, sizeof(deploy), bip32_key,
                                             &deploy_review, digest) ==
                         ChainError::Ok &&
           chain_constant_time_equal(digest, expected_deploy,
                                     kStarknetFeltSize);
  passed = passed && strcmp(deploy_review.recipient, "ACCOUNT DEPLOY") == 0;
  passed = passed && strcmp(deploy_review.amount, "0 STRK") == 0;
  passed = passed && deploy_review.call_count == 0;
  passed = passed && starknet_felt_text(salt, expected_text,
                                        sizeof(expected_text)) &&
           strstr(deploy_review.extra, expected_text) != nullptr;
  size_t deploy_size = sizeof(signature);
  passed = passed && starknet_sign_payload(deploy, sizeof(deploy), bip32_key,
                                           signature, &deploy_size) ==
                         ChainError::Ok &&
           deploy_size == kStarknetSignatureSize &&
           decode_felt(kDeployR, expected_r) && decode_felt(kDeployS, expected_s) &&
           chain_constant_time_equal(signature, expected_r, kStarknetFeltSize) &&
           chain_constant_time_equal(signature + kStarknetFeltSize, expected_s,
                                     kStarknetFeltSize);

  // --- refusals ----------------------------------------------------------
  const size_t felt = kStarknetFeltSize;
  const size_t single_size = sizeof(single);
  uint8_t copy[sizeof(batch)];
  ChainReview ignored;
  uint8_t ignored_digest[kStarknetFeltSize];
  memcpy(copy, single, single_size);
  copy[kOffsetConstructor + felt - 1] ^= 1;
  const ChainError foreign_key = starknet_review_payload(copy, single_size,
                                                         bip32_key, &ignored,
                                                         ignored_digest);
  memcpy(copy, single, single_size);
  copy[kOffsetKind] = 2;
  const ChainError wrong_kind = starknet_review_payload(copy, single_size,
                                                        bip32_key, &ignored,
                                                        ignored_digest);
  memcpy(copy, single, single_size);
  copy[kOffsetConstructorCount] = 2;
  const ChainError multi_key = starknet_review_payload(copy, single_size,
                                                       bip32_key, &ignored,
                                                       ignored_digest);
  memcpy(copy, single, single_size);
  copy[kOffsetFeeDa] = 2;
  const ChainError wrong_da = starknet_review_payload(copy, single_size,
                                                      bip32_key, &ignored,
                                                      ignored_digest);
  memcpy(copy, single, single_size);
  copy[kOffsetEntryPoint + felt - 1] ^= 1;
  const ChainError wrong_entry = starknet_review_payload(copy, single_size,
                                                         bip32_key, &ignored,
                                                         ignored_digest);
  memcpy(copy, single, single_size);
  memcpy(copy + kOffsetCalldata + 2 * felt, expected_execute, felt);
  const ChainError wrong_selector = starknet_review_payload(copy, single_size,
                                                            bip32_key, &ignored,
                                                            ignored_digest);
  memcpy(copy, batch, sizeof(batch));
  copy[kOffsetCalldata + 14 * felt + felt - 1] ^= 1;
  const ChainError span_mismatch = starknet_review_payload(copy, sizeof(batch),
                                                           bip32_key, &ignored,
                                                           ignored_digest);
  memcpy(copy, single, single_size);
  memset(copy + kOffsetCalldata + 5 * felt, 0, 2 * felt);
  memset(copy + kOffsetCalldata + 9 * felt, 0, 2 * felt);
  const ChainError zero_amount = starknet_review_payload(copy, single_size,
                                                         bip32_key, &ignored,
                                                         ignored_digest);
  memcpy(copy, single, single_size);
  memset(copy + kOffsetCalldata + felt, 0, felt);
  const ChainError zero_target = starknet_review_payload(copy, single_size,
                                                         bip32_key, &ignored,
                                                         ignored_digest);
  memcpy(copy, single, single_size);
  memset(copy + kOffsetCalldata + 4 * felt, 0, felt);
  memset(copy + kOffsetCalldata + 8 * felt, 0, felt);
  const ChainError zero_recipient = starknet_review_payload(copy, single_size,
                                                            bip32_key, &ignored,
                                                            ignored_digest);
  memcpy(copy, single, single_size);
  write_be64(0, copy + kOffsetL1Amount);
  const ChainError zero_gas = starknet_review_payload(copy, single_size,
                                                      bip32_key, &ignored,
                                                      ignored_digest);
  memcpy(copy, single, single_size);
  memset(copy + kOffsetCalldata, 0, felt);
  const ChainError zero_calls = starknet_review_payload(copy, single_size,
                                                        bip32_key, &ignored,
                                                        ignored_digest);
  // A fifth call would not fit the review; the count is refused up front.
  memcpy(copy, batch, sizeof(batch));
  copy[kOffsetCalldata + felt - 1] = 5;
  const ChainError too_many = starknet_review_payload(copy, sizeof(batch),
                                                      bip32_key, &ignored,
                                                      ignored_digest);
  const ChainError truncated = starknet_review_payload(single, single_size - 1,
                                                       bip32_key, &ignored,
                                                       ignored_digest);
  memcpy(copy, single, single_size);
  copy[0] = 'X';
  const ChainError wrong_magic = starknet_review_payload(copy, single_size,
                                                         bip32_key, &ignored,
                                                         ignored_digest);

  uint8_t other_key[kPrivateKeySize];
  memcpy(other_key, bip32_key, sizeof(other_key));
  other_key[0] ^= 0xff;
  size_t refused_size = sizeof(signature);
  const ChainError wrong_wallet = starknet_sign_payload(single, single_size,
                                                        other_key, signature,
                                                        &refused_size);
  size_t tight_size = kStarknetSignatureSize - 1;
  const ChainError tight = starknet_sign_payload(single, single_size, bip32_key,
                                                 signature, &tight_size);

  passed = passed && foreign_key == ChainError::WrongWallet;
  passed = passed && wrong_kind == ChainError::Unsupported;
  passed = passed && multi_key == ChainError::Unsupported;
  passed = passed && wrong_da == ChainError::Unsupported;
  passed = passed && wrong_entry == ChainError::Unsupported;
  passed = passed && wrong_selector == ChainError::Unsupported;
  passed = passed && span_mismatch == ChainError::Malformed;
  passed = passed && zero_amount == ChainError::InvalidAmount;
  passed = passed && zero_target == ChainError::InvalidAmount;
  passed = passed && zero_recipient == ChainError::InvalidAmount;
  passed = passed && zero_gas == ChainError::FeePolicy;
  passed = passed && zero_calls == ChainError::Unsupported;
  passed = passed && too_many == ChainError::Unsupported;
  passed = passed && truncated == ChainError::Malformed;
  passed = passed && wrong_magic == ChainError::Malformed;
  passed = passed && wrong_wallet == ChainError::WrongWallet &&
           refused_size == 0;
  passed = passed && tight == ChainError::BufferTooSmall;

  secure_zero(bip32_key, sizeof(bip32_key));
  secure_zero(signature, sizeof(signature));
  secure_zero(expected_r, sizeof(expected_r));
  secure_zero(expected_s, sizeof(expected_s));
  secure_zero(copy, sizeof(copy));
  secure_zero(&review, sizeof(review));
  return passed;
}

}  // namespace hexwallet
