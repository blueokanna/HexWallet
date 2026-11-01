#include "AptosTransaction.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

constexpr char kSigningDomain[] = "APTOS::RawTransaction";
constexpr uint8_t kPayloadEntryFunction = 2;
constexpr uint8_t kTransferKind = 0;
constexpr uint64_t kMaxGas = 100000000ull;
constexpr uint64_t kMaxGasPrice = 1000000000ull;

struct AptosRequest {
  uint8_t chain_id;
  uint64_t max_gas;
  uint64_t gas_unit_price;
  uint64_t expiration;
  uint32_t sequence;
  uint8_t recipient[kAptosAddressSize];
  uint64_t amount;
};

uint64_t read_be64(const uint8_t *data) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; ++index) value = (value << 8) | data[index];
  return value;
}

uint32_t read_be32(const uint8_t *data) {
  uint32_t value = 0;
  for (size_t index = 0; index < 4; ++index) value = (value << 8) | data[index];
  return value;
}

bool all_zero(const uint8_t *data, size_t size) {
  uint8_t accumulator = 0;
  for (size_t index = 0; index < size; ++index) accumulator |= data[index];
  return accumulator == 0;
}

// Minimal BCS writer covering the four encodings this transaction needs. Every
// length is checked and a short buffer is a refusal, never a truncation.
class Bcs {
 public:
  explicit Bcs(uint8_t *out, size_t capacity) : out_(out), capacity_(capacity) {}

  bool uleb(uint64_t value) {
    do {
      const uint8_t low = static_cast<uint8_t>(value & 0x7f);
      value >>= 7;
      if (!put(static_cast<uint8_t>(low | (value != 0 ? 0x80 : 0x00)))) {
        return false;
      }
    } while (value != 0);
    return true;
  }
  bool u8(uint8_t value) { return put(value); }
  bool u64(uint64_t value) {
    for (size_t index = 0; index < 8; ++index) {
      if (!put(static_cast<uint8_t>(value))) return false;
      value >>= 8;
    }
    return true;
  }
  bool fixed(const uint8_t *data, size_t size) {
    if (data == nullptr || size > capacity_ - size_) return false;
    memcpy(out_ + size_, data, size);
    size_ += size;
    return true;
  }
  bool bytes(const uint8_t *data, size_t size) {
    return uleb(size) && fixed(data, size);
  }
  bool identifier(const char *text) {
    if (text == nullptr) return false;
    return bytes(reinterpret_cast<const uint8_t *>(text), strlen(text));
  }
  size_t size() const { return size_; }

 private:
  bool put(uint8_t value) {
    if (size_ >= capacity_) return false;
    out_[size_++] = value;
    return true;
  }
  uint8_t *out_;
  size_t capacity_;
  size_t size_ = 0;
};

ChainError parse_payload(const uint8_t *payload, size_t size, AptosRequest *request) {
  if (payload == nullptr || request == nullptr) return ChainError::InvalidArgument;
  if (size != kAptosPayloadSize || memcmp(payload, "APT1", 4) != 0) {
    return ChainError::Malformed;
  }
  memset(request, 0, sizeof(*request));
  request->chain_id = payload[4];
  if (payload[5] != kTransferKind) return ChainError::Unsupported;
  request->max_gas = read_be64(payload + 6);
  request->gas_unit_price = read_be64(payload + 14);
  request->expiration = read_be64(payload + 22);
  request->sequence = read_be32(payload + 30);
  memcpy(request->recipient, payload + 34, kAptosAddressSize);
  request->amount = read_be64(payload + 66);
  if (request->chain_id != kAptosMainnetChainId &&
      request->chain_id != kAptosTestnetChainId) {
    return ChainError::WrongNetwork;
  }
  if (request->amount == 0) return ChainError::InvalidAmount;
  if (all_zero(request->recipient, kAptosAddressSize)) {
    return ChainError::InvalidAmount;
  }
  if (request->max_gas == 0 || request->max_gas > kMaxGas ||
      request->gas_unit_price > kMaxGasPrice) {
    return ChainError::FeePolicy;
  }
  // The maximum fee is shown to the user, so it has to be representable.
  if (request->max_gas > UINT64_MAX / request->gas_unit_price) {
    return ChainError::FeePolicy;
  }
  return ChainError::Ok;
}

// BCS(RawTransaction) for 0x1::aptos_account::transfer. The two EntryFunction
// arguments are themselves BCS values, length-prefixed like any Vec<u8>.
bool build_raw_transaction(const AptosRequest &request,
                           const uint8_t sender[kAptosAddressSize], uint8_t *out,
                           size_t capacity, size_t *out_size) {
  // 0x1 as a 32-byte account address: big-endian, so the 1 is the last byte.
  static const uint8_t kAptosFramework[kAptosAddressSize] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  uint8_t amount[8] = {};
  for (size_t index = 0; index < sizeof(amount); ++index) {
    amount[index] = static_cast<uint8_t>(request.amount >> (8 * index));
  }
  Bcs bcs(out, capacity);
  const bool ok =
      bcs.fixed(sender, kAptosAddressSize) && bcs.u64(request.sequence) &&
      bcs.uleb(kPayloadEntryFunction) &&
      bcs.fixed(kAptosFramework, kAptosAddressSize) &&
      bcs.identifier("aptos_account") && bcs.identifier("transfer") &&
      bcs.uleb(0) /* ty_args: Vec<TypeTag> */ &&
      bcs.uleb(2) /* args: Vec<Vec<u8>> */ &&
      bcs.bytes(request.recipient, kAptosAddressSize) &&
      bcs.bytes(amount, sizeof(amount)) && bcs.u64(request.max_gas) &&
      bcs.u64(request.gas_unit_price) && bcs.u64(request.expiration) &&
      bcs.u8(request.chain_id);
  secure_zero(amount, sizeof(amount));
  if (!ok) {
    secure_zero(out, capacity);
    return false;
  }
  *out_size = bcs.size();
  return true;
}

ChainError signing_digest(const AptosRequest &request,
                          const uint8_t sender[kAptosAddressSize],
                          uint8_t digest[kSha256Size]) {
  uint8_t message[sizeof(kSigningDomain) - 1 + 256];
  const size_t domain = sizeof(kSigningDomain) - 1;
  memcpy(message, kSigningDomain, domain);
  size_t payload_size = 0;
  ChainError error = ChainError::Ok;
  if (!build_raw_transaction(request, sender, message + domain,
                             sizeof(message) - domain, &payload_size)) {
    error = ChainError::BufferTooSmall;
  } else if (!crypto_sha3_256(message, domain + payload_size, digest)) {
    error = ChainError::CryptoFailure;
  }
  secure_zero(message, sizeof(message));
  return error;
}

bool decode_address(const char *text, uint8_t out[kAptosAddressSize]) {
  if (text == nullptr || out == nullptr ||
      strlen(text) != kAptosAddressTextSize - 1 || text[0] != '0' ||
      (text[1] != 'x' && text[1] != 'X')) {
    return false;
  }
  size_t decoded = 0;
  if (!chain_parse_hex(text + 2, out, kAptosAddressSize, &decoded) ||
      decoded != kAptosAddressSize) {
    secure_zero(out, kAptosAddressSize);
    return false;
  }
  return true;
}

}  // namespace

bool aptos_address(const uint8_t public_key[kAptosAddressSize], char *out,
                   size_t capacity) {
  if (public_key == nullptr || out == nullptr || capacity < kAptosAddressTextSize) {
    return false;
  }
  uint8_t tagged[kAptosAddressSize + 1] = {};
  uint8_t hash[kSha256Size];
  memcpy(tagged, public_key, kAptosAddressSize);
  // The trailing 0x00 is the single-signer scheme marker; dropping it produces a
  // well-formed address that no key controls.
  const bool ok = crypto_sha3_256(tagged, sizeof(tagged), hash);
  if (ok) {
    out[0] = '0';
    out[1] = 'x';
    chain_hex(hash, sizeof(hash), out + 2, capacity - 2);
  } else {
    out[0] = '\0';
  }
  secure_zero(tagged, sizeof(tagged));
  secure_zero(hash, sizeof(hash));
  return ok;
}

ChainError aptos_review_payload(const uint8_t *payload, size_t size,
                                const char *sender, ChainReview *review,
                                uint8_t digest[32]) {
  if (sender == nullptr || review == nullptr || digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  AptosRequest request;
  ChainError error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;
  uint8_t sender_bytes[kAptosAddressSize];
  if (!decode_address(sender, sender_bytes)) return ChainError::WrongWallet;
  error = signing_digest(request, sender_bytes, digest);
  secure_zero(sender_bytes, sizeof(sender_bytes));
  if (error != ChainError::Ok) return error;

  memset(review, 0, sizeof(*review));
  if (!chain_copy_text(review->symbol, sizeof(review->symbol), "APT") ||
      !chain_copy_text(review->sender, sizeof(review->sender), sender)) {
    return ChainError::BufferTooSmall;
  }
  char address[kAptosAddressTextSize];
  address[0] = '0';
  address[1] = 'x';
  chain_hex(request.recipient, sizeof(request.recipient), address + 2,
            sizeof(address) - 2);
  if (!chain_copy_text(review->recipient, sizeof(review->recipient), address)) {
    return ChainError::BufferTooSmall;
  }
  char amount[32];
  if (!chain_format_units(request.amount, kAptosDecimals, "APT", amount,
                          sizeof(amount)) ||
      !chain_copy_text(review->amount, sizeof(review->amount), amount)) {
    return ChainError::BufferTooSmall;
  }
  char fee[32];
  if (!chain_format_units(request.max_gas * request.gas_unit_price, kAptosDecimals,
                          "APT", fee, sizeof(fee)) ||
      !chain_copy_text(review->fee, sizeof(review->fee), fee)) {
    return ChainError::BufferTooSmall;
  }
  const int written = snprintf(
      review->extra, sizeof(review->extra),
      "SEQUENCE %lu\nGAS %llu x %llu\nEXPIRY %llu\nCHAIN %u",
      static_cast<unsigned long>(request.sequence),
      static_cast<unsigned long long>(request.max_gas),
      static_cast<unsigned long long>(request.gas_unit_price),
      static_cast<unsigned long long>(request.expiration),
      static_cast<unsigned>(request.chain_id));
  if (written < 0 || static_cast<size_t>(written) >= sizeof(review->extra)) {
    return ChainError::BufferTooSmall;
  }
  return ChainError::Ok;
}

ChainError aptos_sign_payload(const uint8_t *payload, size_t size,
                              const char *sender,
                              const uint8_t private_key[kPrivateKeySize],
                              uint8_t *out, size_t *in_out_size) {
  if (in_out_size == nullptr) return ChainError::InvalidArgument;
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  if (out != nullptr) secure_zero(out, capacity);
  if (payload == nullptr || sender == nullptr || private_key == nullptr ||
      out == nullptr) {
    return ChainError::InvalidArgument;
  }
  AptosRequest request;
  ChainError error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;

  uint8_t public_key[kAptosAddressSize];
  uint8_t own_address[kAptosAddressSize];
  uint8_t sender_bytes[kAptosAddressSize];
  char own_text[kAptosAddressTextSize];
  bool key_ok = ed25519_public_key(private_key, public_key);
  if (key_ok) {
    key_ok = aptos_address(public_key, own_text, sizeof(own_text)) &&
             decode_address(own_text, own_address);
  }
  const bool same_account = key_ok && decode_address(sender, sender_bytes) &&
                            crypto_constant_time_equal(sender_bytes, own_address,
                                                       kAptosAddressSize);
  secure_zero(sender_bytes, sizeof(sender_bytes));
  if (!same_account) {
    secure_zero(public_key, sizeof(public_key));
    secure_zero(own_address, sizeof(own_address));
    return key_ok ? ChainError::WrongWallet : ChainError::CryptoFailure;
  }

  uint8_t digest[kSha256Size];
  error = signing_digest(request, own_address, digest);
  secure_zero(own_address, sizeof(own_address));
  if (error != ChainError::Ok) {
    secure_zero(public_key, sizeof(public_key));
    return error;
  }
  if (capacity < kAptosAuthenticatorSize) {
    secure_zero(public_key, sizeof(public_key));
    secure_zero(digest, sizeof(digest));
    return ChainError::BufferTooSmall;
  }
  uint8_t signature[64];
  const bool signed_ok =
      ed25519_sign(private_key, digest, sizeof(digest), signature);
  secure_zero(digest, sizeof(digest));
  if (!signed_ok) {
    secure_zero(public_key, sizeof(public_key));
    secure_zero(signature, sizeof(signature));
    secure_zero(out, capacity);
    return ChainError::CryptoFailure;
  }
  out[0] = 0x00;  // AccountAuthenticator::Ed25519
  memcpy(out + 1, signature, sizeof(signature));
  memcpy(out + 1 + sizeof(signature), public_key, kAptosAddressSize);
  secure_zero(signature, sizeof(signature));
  secure_zero(public_key, sizeof(public_key));
  *in_out_size = kAptosAuthenticatorSize;
  return ChainError::Ok;
}

bool run_aptos_self_tests() {
  // Key, address, RawTransaction digest and signature were generated with an
  // independent implementation (Python hashlib.sha3_256 + libsodium Ed25519)
  // following the BCS layout in aptos-core's generate-format fixture, so this
  // pins exact bytes rather than only proving that signing round-trips.
  static const uint8_t kSeed[kPrivateKeySize] = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
      0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
  static const char kExpectedAddress[] =
      "0xb6bbeddd149a70b603089e5a1e4e259c39d6cbfb0139265b1d4bd79eaf790b03";
  static const uint8_t kExpectedDigest[kSha256Size] = {
      0x64, 0xac, 0xdd, 0x1c, 0x2b, 0x63, 0x24, 0x29, 0x71, 0x69, 0xc9,
      0x93, 0x3e, 0x52, 0x03, 0xf6, 0x8a, 0x6d, 0xa9, 0x79, 0x85, 0x5c,
      0x50, 0x20, 0x20, 0x1d, 0x29, 0xc1, 0x26, 0x2c, 0xb3, 0xa9};
  static const uint8_t kExpectedAuthenticator[kAptosAuthenticatorSize] = {
      0x00, 0x40, 0x78, 0x9a, 0x84, 0x25, 0x48, 0x3d, 0x48, 0x3f, 0xa3,
      0x5f, 0x6e, 0xe1, 0x99, 0x30, 0x92, 0x59, 0x18, 0xd3, 0x8b, 0xd7,
      0xfb, 0x2a, 0x8e, 0x4b, 0x68, 0x21, 0xa9, 0x0b, 0xdc, 0xde, 0x4f,
      0xb2, 0x18, 0xe3, 0xc9, 0xec, 0xe5, 0xe5, 0xc5, 0xc4, 0x1c, 0x18,
      0xeb, 0x7b, 0x1c, 0xd2, 0x5e, 0xd8, 0x21, 0x76, 0x2a, 0xd8, 0x4c,
      0x9f, 0x33, 0xf7, 0x50, 0x9d, 0x07, 0x95, 0x29, 0x76, 0x00, 0x79,
      0xb5, 0x56, 0x2e, 0x8f, 0xe6, 0x54, 0xf9, 0x40, 0x78, 0xb1, 0x12,
      0xe8, 0xa9, 0x8b, 0xa7, 0x90, 0x1f, 0x85, 0x3a, 0xe6, 0x95, 0xbe,
      0xd7, 0xe0, 0xe3, 0x91, 0x0b, 0xad, 0x04, 0x96, 0x64};

  uint8_t public_key[kAptosAddressSize];
  char address[kAptosAddressTextSize];
  bool passed = ed25519_public_key(kSeed, public_key) &&
                aptos_address(public_key, address, sizeof(address)) &&
                strcmp(address, kExpectedAddress) == 0;

  uint8_t payload[kAptosPayloadSize] = {};
  memcpy(payload, "APT1", 4);
  payload[4] = kAptosMainnetChainId;
  payload[5] = 0x00;
  const uint64_t header_fields[3] = {2000, 100, 1799999999};
  for (size_t index = 0; index < 3; ++index) {
    for (size_t byte = 0; byte < 8; ++byte) {
      payload[6 + index * 8 + byte] =
          static_cast<uint8_t>(header_fields[index] >> (8 * (7 - byte)));
    }
  }
  payload[33] = 0x07;
  memset(payload + 34, 0x44, kAptosAddressSize);
  const uint64_t amount = 12345678;
  for (size_t byte = 0; byte < 8; ++byte) {
    payload[66 + byte] = static_cast<uint8_t>(amount >> (8 * (7 - byte)));
  }

  ChainReview review;
  uint8_t digest[kSha256Size];
  passed = passed &&
           aptos_review_payload(payload, sizeof(payload), address, &review,
                                digest) == ChainError::Ok;
  passed = passed && chain_constant_time_equal(digest, kExpectedDigest, kSha256Size);
  passed = passed && strcmp(review.symbol, "APT") == 0;
  passed = passed && strcmp(review.amount, "0.12345678 APT") == 0;
  passed = passed && strcmp(review.fee, "0.002 APT") == 0;
  passed = passed && strcmp(review.sender, address) == 0;
  passed = passed && strstr(review.extra, "SEQUENCE 7") != nullptr;
  passed = passed && strncmp(review.recipient,
                   "0x4444444444444444444444444444444444444444444444444444444444444444",
                   kAptosAddressTextSize - 1) == 0;

  uint8_t authenticator[kAptosAuthenticatorSize];
  size_t authenticator_size = sizeof(authenticator);
  passed = passed &&
           aptos_sign_payload(payload, sizeof(payload), address, kSeed,
                              authenticator, &authenticator_size) == ChainError::Ok;
  passed = passed && authenticator_size == kAptosAuthenticatorSize;
  passed = passed && chain_constant_time_equal(authenticator,
                                               kExpectedAuthenticator,
                                               kAptosAuthenticatorSize);

  // Refusals. A zero amount, an unknown chain, an unadmitted payload kind, a
  // truncated buffer and a sender this key does not control must never reach a
  // signature.
  uint8_t copy[kAptosPayloadSize];
  ChainReview ignored;
  uint8_t ignored_digest[kSha256Size];
  memcpy(copy, payload, sizeof(copy));
  memset(copy + 66, 0, 8);
  const ChainError zero_amount = aptos_review_payload(copy, sizeof(copy), address,
                                                      &ignored, ignored_digest);
  memcpy(copy, payload, sizeof(copy));
  copy[4] = 9;
  const ChainError wrong_chain = aptos_review_payload(copy, sizeof(copy), address,
                                                      &ignored, ignored_digest);
  memcpy(copy, payload, sizeof(copy));
  copy[5] = 3;
  const ChainError wrong_kind = aptos_review_payload(copy, sizeof(copy), address,
                                                     &ignored, ignored_digest);
  memcpy(copy, payload, sizeof(copy));
  memset(copy + 34, 0, kAptosAddressSize);
  const ChainError zero_recipient = aptos_review_payload(copy, sizeof(copy), address,
                                                         &ignored, ignored_digest);
  const ChainError truncated = aptos_review_payload(payload, sizeof(payload) - 1,
                                                    address, &ignored,
                                                    ignored_digest);
  char other[kAptosAddressTextSize];
  memcpy(other, kExpectedAddress, sizeof(other));
  other[10] = other[10] == 'a' ? 'b' : 'a';
  size_t refused_size = sizeof(authenticator);
  const ChainError wrong_sender =
      aptos_sign_payload(payload, sizeof(payload), other, kSeed, authenticator,
                         &refused_size);
  passed = passed && zero_amount == ChainError::InvalidAmount;
  passed = passed && wrong_chain == ChainError::WrongNetwork;
  passed = passed && wrong_kind == ChainError::Unsupported;
  passed = passed && zero_recipient == ChainError::InvalidAmount;
  passed = passed && truncated == ChainError::Malformed;
  passed = passed && wrong_sender == ChainError::WrongWallet && refused_size == 0;
  secure_zero(public_key, sizeof(public_key));
  secure_zero(authenticator, sizeof(authenticator));
  secure_zero(digest, sizeof(digest));
  return passed;
}

}  // namespace hexwallet
