#include "WalletAddresses.h"

#include <string.h>
#include <string>
#include <vector>

#include "base58.h"
#include "CryptoPrimitives.h"
#include "local_segwit.h"

namespace hexwallet {
namespace {

constexpr size_t kVersionSize = 1;
constexpr size_t kBase58ChecksumSize = 4;
constexpr size_t kMaximumBase58PayloadSize = 78;
constexpr size_t kMaximumBase58CheckedSize = kMaximumBase58PayloadSize + kBase58ChecksumSize;
constexpr size_t kVersionedHash160Size = kVersionSize + kRipemd160Size;
constexpr uint8_t kWitnessVersionZeroOpcode = 0x00;

WalletError base58check(const uint8_t *payload, size_t payload_size, bool ripple_alphabet,
                        char *out, size_t *in_out_size) {
  if (payload == nullptr || out == nullptr || in_out_size == nullptr ||
      payload_size > kMaximumBase58PayloadSize) {
    return WalletError::InvalidArgument;
  }
  uint8_t encoded[kMaximumBase58CheckedSize];
  uint8_t checksum[kSha256Size];
  if (!crypto_double_sha256(payload, payload_size, checksum)) {
    secure_zero(encoded, sizeof(encoded));
    secure_zero(checksum, sizeof(checksum));
    return WalletError::CryptoFailure;
  }
  memcpy(encoded, payload, payload_size);
  memcpy(encoded + payload_size, checksum, kBase58ChecksumSize);
  const size_t checked_size = payload_size + kBase58ChecksumSize;
  const bool ok = ripple_alphabet ? ripple_b58enc(out, in_out_size, encoded, checked_size)
                                  : b58enc(out, in_out_size, encoded, checked_size);
  secure_zero(encoded, sizeof(encoded));
  secure_zero(checksum, sizeof(checksum));
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

}  // namespace

WalletError address_p2pkh(const UtxoAddressProfile &profile,
                          const uint8_t public_key[kCompressedPublicKeySize],
                          char *out, size_t *in_out_size) {
  if (public_key == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t payload[kVersionedHash160Size];
  payload[0] = profile.p2pkh_version;
  if (!crypto_hash160(public_key, kCompressedPublicKeySize, payload + 1)) {
    secure_zero(payload, sizeof(payload));
    return WalletError::CryptoFailure;
  }
  const WalletError result = base58check(payload, sizeof(payload), profile.ripple_alphabet,
                                         out, in_out_size);
  secure_zero(payload, sizeof(payload));
  return result;
}

WalletError address_p2sh_p2wpkh(const UtxoAddressProfile &profile,
                                const uint8_t public_key[kCompressedPublicKeySize],
                                char *out, size_t *in_out_size) {
  if (public_key == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t witness_key_hash[kRipemd160Size];
  uint8_t redeem_script[2 + kRipemd160Size];
  uint8_t payload[kVersionedHash160Size];
  if (!crypto_hash160(public_key, kCompressedPublicKeySize, witness_key_hash)) {
    return WalletError::CryptoFailure;
  }
  redeem_script[0] = kWitnessVersionZeroOpcode;
  redeem_script[1] = static_cast<uint8_t>(kRipemd160Size);
  memcpy(redeem_script + 2, witness_key_hash, sizeof(witness_key_hash));
  payload[0] = profile.p2sh_version;
  const bool hashed = crypto_hash160(redeem_script, sizeof(redeem_script), payload + 1);
  secure_zero(witness_key_hash, sizeof(witness_key_hash));
  secure_zero(redeem_script, sizeof(redeem_script));
  if (!hashed) {
    secure_zero(payload, sizeof(payload));
    return WalletError::CryptoFailure;
  }
  const WalletError result = base58check(payload, sizeof(payload), profile.ripple_alphabet,
                                         out, in_out_size);
  secure_zero(payload, sizeof(payload));
  return result;
}

WalletError address_p2wpkh(const UtxoAddressProfile &profile,
                           const uint8_t public_key[kCompressedPublicKeySize],
                           char *out, size_t out_size) {
  if (public_key == nullptr || out == nullptr || profile.bech32_hrp == nullptr || out_size == 0) {
    return WalletError::InvalidArgument;
  }
  uint8_t witness_key_hash[kRipemd160Size];
  if (!crypto_hash160(public_key, kCompressedPublicKeySize, witness_key_hash)) {
    return WalletError::CryptoFailure;
  }
  const std::vector<uint8_t> program(witness_key_hash, witness_key_hash + sizeof(witness_key_hash));
  const std::string address = segwit_address::encode(profile.bech32_hrp, 0, program);
  secure_zero(witness_key_hash, sizeof(witness_key_hash));
  if (address.empty() || address.size() + 1 > out_size) {
    return address.empty() ? WalletError::CryptoFailure : WalletError::BufferTooSmall;
  }
  memcpy(out, address.c_str(), address.size() + 1);
  return WalletError::Ok;
}

WalletError address_evm(const uint8_t public_key[kUncompressedPublicKeySize],
                        char *out, size_t out_size) {
  constexpr size_t kAddressBytes = 20;
  constexpr size_t kTextSize = 2 + kAddressBytes * 2 + 1;
  if (public_key == nullptr || out == nullptr || out_size < kTextSize || public_key[0] != 0x04) {
    return out_size < kTextSize ? WalletError::BufferTooSmall : WalletError::InvalidArgument;
  }
  uint8_t digest[kKeccak256Size];
  if (!crypto_keccak256(public_key + 1, kUncompressedPublicKeySize - 1, digest)) {
    return WalletError::CryptoFailure;
  }
  static constexpr char kHex[] = "0123456789abcdef";
  out[0] = '0';
  out[1] = 'x';
  const uint8_t *address = digest + kKeccak256Size - kAddressBytes;
  for (size_t index = 0; index < kAddressBytes; ++index) {
    out[2 + index * 2] = kHex[address[index] >> 4];
    out[3 + index * 2] = kHex[address[index] & 0x0f];
  }
  out[kTextSize - 1] = '\0';
  secure_zero(digest, sizeof(digest));
  return WalletError::Ok;
}

WalletError address_keccak_base58(uint8_t version,
                                  const uint8_t public_key[kUncompressedPublicKeySize],
                                  char *out, size_t *in_out_size) {
  if (public_key == nullptr || out == nullptr || in_out_size == nullptr || public_key[0] != 0x04) {
    return WalletError::InvalidArgument;
  }
  uint8_t digest[kKeccak256Size];
  uint8_t payload[1 + kRipemd160Size];
  if (!crypto_keccak256(public_key + 1, kUncompressedPublicKeySize - 1, digest)) {
    return WalletError::CryptoFailure;
  }
  payload[0] = version;
  memcpy(payload + 1, digest + kKeccak256Size - kRipemd160Size, kRipemd160Size);
  const WalletError result = base58check(payload, sizeof(payload), false, out, in_out_size);
  secure_zero(digest, sizeof(digest));
  secure_zero(payload, sizeof(payload));
  return result;
}

WalletError address_from_script(const UtxoAddressProfile &profile,
                                const uint8_t *script, size_t script_size,
                                char *out, size_t out_size) {
  if (script == nullptr || out == nullptr || out_size == 0) return WalletError::InvalidArgument;
  if (script_size == 22 && script[0] == 0x00 && script[1] == 0x14 && profile.bech32_hrp != nullptr) {
    const std::vector<uint8_t> program(script + 2, script + 22);
    const std::string address = segwit_address::encode(profile.bech32_hrp, 0, program);
    if (address.empty()) return WalletError::CryptoFailure;
    if (address.size() + 1 > out_size) return WalletError::BufferTooSmall;
    memcpy(out, address.c_str(), address.size() + 1);
    return WalletError::Ok;
  }
  uint8_t payload[kVersionedHash160Size];
  if (script_size == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
      script[23] == 0x88 && script[24] == 0xac) {
    payload[0] = profile.p2pkh_version;
    memcpy(payload + 1, script + 3, kRipemd160Size);
  } else if (script_size == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87) {
    payload[0] = profile.p2sh_version;
    memcpy(payload + 1, script + 2, kRipemd160Size);
  } else {
    return WalletError::InvalidArgument;
  }
  size_t encoded_size = out_size;
  const WalletError result = base58check(payload, sizeof(payload), profile.ripple_alphabet,
                                         out, &encoded_size);
  secure_zero(payload, sizeof(payload));
  return result;
}

}  // namespace hexwallet
