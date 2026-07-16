#include "WalletAddresses.h"

#include <mbedtls/md.h>
#include <string.h>
#include <string>
#include <vector>

#include "base58.h"
#include "local_ripemd160.h"
#include "local_segwit.h"

namespace hexwallet {
namespace {

bool sha256(const uint8_t *data, size_t length, uint8_t out[32]) {
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  const int result = info == nullptr ? -1 :
      (mbedtls_md_setup(&context, info, 0) || mbedtls_md_starts(&context) ||
       mbedtls_md_update(&context, data, length) || mbedtls_md_finish(&context, out));
  mbedtls_md_free(&context);
  return result == 0;
}

bool hash160(const uint8_t *data, size_t length, uint8_t out[20]) {
  uint8_t digest[32];
  const bool ok = sha256(data, length, digest);
  if (ok) {
    local_ripemd160(digest, sizeof(digest), out);
  }
  secure_zero(digest, sizeof(digest));
  return ok;
}

WalletError base58check(const uint8_t *payload, size_t payload_size, char *out, size_t *in_out_size) {
  if (payload == nullptr || out == nullptr || in_out_size == nullptr || payload_size > 78) {
    return WalletError::InvalidArgument;
  }
  uint8_t encoded[82];
  uint8_t first[32];
  uint8_t checksum[32];
  if (!sha256(payload, payload_size, first) || !sha256(first, sizeof(first), checksum)) {
    secure_zero(encoded, sizeof(encoded));
    secure_zero(first, sizeof(first));
    secure_zero(checksum, sizeof(checksum));
    return WalletError::CryptoFailure;
  }
  memcpy(encoded, payload, payload_size);
  memcpy(encoded + payload_size, checksum, 4);
  const bool ok = b58enc(out, in_out_size, encoded, payload_size + 4);
  secure_zero(encoded, sizeof(encoded));
  secure_zero(first, sizeof(first));
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
  uint8_t payload[21];
  payload[0] = profile.p2pkh_version;
  if (!hash160(public_key, kCompressedPublicKeySize, payload + 1)) {
    secure_zero(payload, sizeof(payload));
    return WalletError::CryptoFailure;
  }
  const WalletError result = base58check(payload, sizeof(payload), out, in_out_size);
  secure_zero(payload, sizeof(payload));
  return result;
}

WalletError address_p2sh_p2wpkh(const UtxoAddressProfile &profile,
                                const uint8_t public_key[kCompressedPublicKeySize],
                                char *out, size_t *in_out_size) {
  if (public_key == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t witness_key_hash[20];
  uint8_t redeem_script[22];
  uint8_t payload[21];
  if (!hash160(public_key, kCompressedPublicKeySize, witness_key_hash)) {
    return WalletError::CryptoFailure;
  }
  redeem_script[0] = 0x00;
  redeem_script[1] = 0x14;
  memcpy(redeem_script + 2, witness_key_hash, sizeof(witness_key_hash));
  payload[0] = profile.p2sh_version;
  const bool hashed = hash160(redeem_script, sizeof(redeem_script), payload + 1);
  secure_zero(witness_key_hash, sizeof(witness_key_hash));
  secure_zero(redeem_script, sizeof(redeem_script));
  if (!hashed) {
    secure_zero(payload, sizeof(payload));
    return WalletError::CryptoFailure;
  }
  const WalletError result = base58check(payload, sizeof(payload), out, in_out_size);
  secure_zero(payload, sizeof(payload));
  return result;
}

WalletError address_p2wpkh(const UtxoAddressProfile &profile,
                           const uint8_t public_key[kCompressedPublicKeySize],
                           char *out, size_t out_size) {
  if (public_key == nullptr || out == nullptr || profile.bech32_hrp == nullptr || out_size == 0) {
    return WalletError::InvalidArgument;
  }
  uint8_t witness_key_hash[20];
  if (!hash160(public_key, kCompressedPublicKeySize, witness_key_hash)) {
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

}  // namespace hexwallet
