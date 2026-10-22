#include "WalletSecurity.h"

#include <Arduino.h>
#include <esp_system.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/pkcs5.h>
#include <string.h>

#include "base58.h"
#include "CryptoPrimitives.h"
#include "WalletAddresses.h"
#include "word_list.h"

namespace hexwallet {
namespace {

constexpr size_t kMnemonicTextSize = 256;
constexpr size_t kMaxPassphraseSize = 128;
constexpr size_t kExtendedKeyPayloadSize = 78;
constexpr size_t kExtendedKeyCheckedSize = 82;

int random_callback(void *, unsigned char *output, size_t length) {
  esp_fill_random(output, length);
  return 0;
}

bool valid_private_key(const uint8_t key[kPrivateKeySize]) {
  mbedtls_ecp_group group;
  mbedtls_mpi scalar;
  mbedtls_ecp_group_init(&group);
  mbedtls_mpi_init(&scalar);
  const int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) || mbedtls_mpi_read_binary(&scalar, key, kPrivateKeySize);
  const bool valid = result == 0 && mbedtls_mpi_cmp_int(&scalar, 0) > 0 && mbedtls_mpi_cmp_mpi(&scalar, &group.N) < 0;
  mbedtls_mpi_free(&scalar);
  mbedtls_ecp_group_free(&group);
  return valid;
}

bool hash160(const uint8_t *data, size_t length, uint8_t out[20]) {
  return crypto_hash160(data, length, out);
}

int hex_nibble(char character) {
  if (character >= '0' && character <= '9') return character - '0';
  if (character >= 'a' && character <= 'f') return character - 'a' + 10;
  if (character >= 'A' && character <= 'F') return character - 'A' + 10;
  return -1;
}

bool parse_hex_fixed(const char *text, uint8_t *out, size_t size) {
  if (text == nullptr || out == nullptr || strlen(text) != size * 2) return false;
  for (size_t index = 0; index < size; ++index) {
    const int high = hex_nibble(text[index * 2]);
    const int low = hex_nibble(text[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

bool bip340_tagged_hash(const char *tag, const uint8_t *data, size_t size,
                        uint8_t out[kSha256Size]) {  if (tag == nullptr || out == nullptr || (data == nullptr && size != 0) || size > 96) {
    return false;
  }
  uint8_t tag_hash[kSha256Size];
  uint8_t buffer[2 * kSha256Size + 96];
  if (!crypto_sha256(reinterpret_cast<const uint8_t *>(tag), strlen(tag), tag_hash)) {
    return false;
  }
  memcpy(buffer, tag_hash, kSha256Size);
  memcpy(buffer + kSha256Size, tag_hash, kSha256Size);
  if (size != 0) memcpy(buffer + 2 * kSha256Size, data, size);
  const bool ok = crypto_sha256(buffer, 2 * kSha256Size + size, out);
  secure_zero(tag_hash, sizeof(tag_hash));
  secure_zero(buffer, sizeof(buffer));
  return ok;
}

bool fingerprint(const uint8_t public_key[kCompressedPublicKeySize], uint32_t *out) {
  if (public_key == nullptr || out == nullptr) return false;
  uint8_t digest[20];
  const bool ok = hash160(public_key, kCompressedPublicKeySize, digest);
  if (ok) {
    *out = (static_cast<uint32_t>(digest[0]) << 24) | (static_cast<uint32_t>(digest[1]) << 16) | (static_cast<uint32_t>(digest[2]) << 8) | digest[3];
  }
  secure_zero(digest, sizeof(digest));
  return ok;
}

void write_u32_be(uint8_t *out, uint32_t value) {
  out[0] = static_cast<uint8_t>(value >> 24);
  out[1] = static_cast<uint8_t>(value >> 16);
  out[2] = static_cast<uint8_t>(value >> 8);
  out[3] = static_cast<uint8_t>(value);
}

bool version_bytes(ExtendedKeyFormat format, bool private_key, uint8_t out[4]) {
  if ((private_key && (format == ExtendedKeyFormat::Xpub || format == ExtendedKeyFormat::Zpub || format == ExtendedKeyFormat::Tpub || format == ExtendedKeyFormat::Vpub)) || (!private_key && (format == ExtendedKeyFormat::Xprv || format == ExtendedKeyFormat::Zprv || format == ExtendedKeyFormat::Tprv || format == ExtendedKeyFormat::Vprv))) {
    return false;
  }
  static const uint32_t kVersions[] = {
    0x0488ADE4UL,
    0x0488B21EUL,
    0x04B2430CUL,
    0x04B24746UL,
    0x04358394UL,
    0x043587CFUL,
    0x045F18BCUL,
    0x045F1CF6UL,
  };
  const uint8_t index = static_cast<uint8_t>(format);
  if (index >= sizeof(kVersions) / sizeof(kVersions[0])) return false;
  write_u32_be(out, kVersions[index]);
  return true;
}

WalletError serialize_payload(const uint8_t *key, const uint8_t chain_code[kChainCodeSize],
                              uint8_t depth, uint32_t parent_fingerprint, uint32_t child_number,
                              ExtendedKeyFormat format, bool private_key,
                              char *out, size_t *in_out_size) {
  if (key == nullptr || chain_code == nullptr || out == nullptr || in_out_size == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t version[4];
  if (*in_out_size < kExtendedKeyTextSize || !version_bytes(format, private_key, version)) {
    return *in_out_size < kExtendedKeyTextSize ? WalletError::BufferTooSmall : WalletError::InvalidArgument;
  }
  uint8_t payload[kExtendedKeyPayloadSize];
  uint8_t checked[kExtendedKeyCheckedSize];
  memcpy(payload, version, sizeof(version));
  payload[4] = depth;
  write_u32_be(payload + 5, parent_fingerprint);
  write_u32_be(payload + 9, child_number);
  memcpy(payload + 13, chain_code, kChainCodeSize);
  if (private_key) {
    payload[45] = 0;
    memcpy(payload + 46, key, kPrivateKeySize);
  } else {
    memcpy(payload + 45, key, kCompressedPublicKeySize);
  }
  uint8_t checksum[32];
  if (!crypto_double_sha256(payload, sizeof(payload), checksum)) {
    secure_zero(payload, sizeof(payload));
    secure_zero(checksum, sizeof(checksum));
    return WalletError::CryptoFailure;
  }
  memcpy(checked, payload, sizeof(payload));
  memcpy(checked + sizeof(payload), checksum, 4);
  size_t encoded_size = *in_out_size;
  const bool encoded = b58enc(out, &encoded_size, checked, sizeof(checked));
  secure_zero(payload, sizeof(payload));
  secure_zero(checked, sizeof(checked));
  secure_zero(checksum, sizeof(checksum));
  if (!encoded) {
    *in_out_size = encoded_size;
    return WalletError::BufferTooSmall;
  }
  *in_out_size = encoded_size;
  return WalletError::Ok;
}

bool word_index(const char *word, size_t length, uint16_t *out_index) {
  for (uint16_t index = 0; index < 2048; ++index) {
    const char *candidate = english_word_list[index];
    if (strlen(candidate) == length && memcmp(candidate, word, length) == 0) {
      *out_index = index;
      return true;
    }
  }
  return false;
}

bool english_word_list_is_valid() {
  return strcmp(english_word_list[0], "abandon") == 0 && strcmp(english_word_list[2047], "zoo") == 0;
}

}  // namespace

void secure_zero(void *data, size_t length) {
  if (data != nullptr && length != 0) {
    mbedtls_platform_zeroize(data, length);
  }
}

bool is_ascii(const char *text) {
  if (text == nullptr) {
    return false;
  }
  for (; *text != '\0'; ++text) {
    if (static_cast<unsigned char>(*text) > 0x7f) {
      return false;
    }
  }
  return true;
}

WalletError bip39_generate_english_24(char *out, size_t out_size) {
  if (out == nullptr || out_size < kMnemonicTextSize) {
    return WalletError::BufferTooSmall;
  }
  if (!english_word_list_is_valid()) {
    return WalletError::CryptoFailure;
  }
  uint8_t entropy[32];
  uint8_t digest[32];
  uint8_t bits[33];
  esp_fill_random(entropy, sizeof(entropy));
  if (!crypto_sha256(entropy, sizeof(entropy), digest)) {
    secure_zero(entropy, sizeof(entropy));
    return WalletError::CryptoFailure;
  }
  memcpy(bits, entropy, sizeof(entropy));
  bits[32] = digest[0];
  size_t used = 0;
  for (uint8_t word = 0; word < 24; ++word) {
    uint16_t index = 0;
    for (uint8_t bit = 0; bit < 11; ++bit) {
      const uint16_t position = static_cast<uint16_t>(word) * 11 + bit;
      index = static_cast<uint16_t>((index << 1) | ((bits[position / 8] >> (7 - position % 8)) & 1));
    }
    const char *candidate = english_word_list[index];
    const size_t candidate_length = strlen(candidate);
    if (used + candidate_length + (word == 0 ? 1 : 2) > out_size) {
      secure_zero(entropy, sizeof(entropy));
      secure_zero(digest, sizeof(digest));
      secure_zero(bits, sizeof(bits));
      return WalletError::BufferTooSmall;
    }
    if (word != 0) {
      out[used++] = ' ';
    }
    memcpy(out + used, candidate, candidate_length);
    used += candidate_length;
  }
  out[used] = '\0';
  secure_zero(entropy, sizeof(entropy));
  secure_zero(digest, sizeof(digest));
  secure_zero(bits, sizeof(bits));
  return WalletError::Ok;
}

WalletError bip39_validate_english(const char *mnemonic) {
  if (mnemonic == nullptr || !is_ascii(mnemonic) || !english_word_list_is_valid()) {
    return mnemonic != nullptr && !is_ascii(mnemonic) ? WalletError::UnsupportedUnicode : WalletError::InvalidMnemonic;
  }
  const size_t length = strlen(mnemonic);
  if (length == 0 || length >= kMnemonicTextSize) {
    return WalletError::InvalidMnemonic;
  }
  uint8_t bits[33] = { 0 };
  uint16_t bit_position = 0;
  uint8_t word_count = 0;
  const char *cursor = mnemonic;
  while (*cursor != '\0') {
    const char *end = strchr(cursor, ' ');
    const size_t word_length = end == nullptr ? strlen(cursor) : static_cast<size_t>(end - cursor);
    uint16_t index;
    if (word_length == 0 || word_count == 24 || !word_index(cursor, word_length, &index)) {
      return WalletError::InvalidMnemonic;
    }
    for (int bit = 10; bit >= 0; --bit) {
      if ((index >> bit) & 1) {
        bits[bit_position / 8] |= static_cast<uint8_t>(1U << (7 - bit_position % 8));
      }
      ++bit_position;
    }
    ++word_count;
    if (end == nullptr) {
      break;
    }
    cursor = end + 1;
  }
  if (word_count != 12 && word_count != 15 && word_count != 18 && word_count != 21 && word_count != 24) {
    return WalletError::InvalidMnemonic;
  }
  const uint16_t entropy_bits = static_cast<uint16_t>(word_count) * 11 * 32 / 33;
  const uint8_t checksum_bits = entropy_bits / 32;
  uint8_t digest[32];
  if (!crypto_sha256(bits, entropy_bits / 8, digest)) {
    secure_zero(bits, sizeof(bits));
    return WalletError::CryptoFailure;
  }
  for (uint8_t bit = 0; bit < checksum_bits; ++bit) {
    const uint8_t supplied = (bits[(entropy_bits + bit) / 8] >> (7 - ((entropy_bits + bit) % 8))) & 1;
    const uint8_t expected = (digest[0] >> (7 - bit)) & 1;
    if (supplied != expected) {
      secure_zero(bits, sizeof(bits));
      secure_zero(digest, sizeof(digest));
      return WalletError::InvalidMnemonic;
    }
  }
  secure_zero(bits, sizeof(bits));
  secure_zero(digest, sizeof(digest));
  return WalletError::Ok;
}

WalletError bip39_seed_from_english(const char *mnemonic, const char *passphrase,
                                    uint8_t out_seed[kSeedSize]) {
  if (out_seed == nullptr || passphrase == nullptr) {
    return WalletError::InvalidArgument;
  }
  const WalletError validation = bip39_validate_english(mnemonic);
  if (validation != WalletError::Ok) {
    return validation;
  }
  if (!is_ascii(passphrase)) {
    return WalletError::UnsupportedUnicode;
  }
  const size_t passphrase_length = strlen(passphrase);
  if (passphrase_length > kMaxPassphraseSize) {
    return WalletError::InvalidArgument;
  }
  char salt[sizeof("mnemonic") + kMaxPassphraseSize];
  memcpy(salt, "mnemonic", 8);
  memcpy(salt + 8, passphrase, passphrase_length);
  const int result = mbedtls_pkcs5_pbkdf2_hmac_ext(
    MBEDTLS_MD_SHA512, reinterpret_cast<const unsigned char *>(mnemonic), strlen(mnemonic),
    reinterpret_cast<const unsigned char *>(salt), 8 + passphrase_length,
    2048, kSeedSize, out_seed);
  secure_zero(salt, sizeof(salt));
  return result == 0 ? WalletError::Ok : WalletError::CryptoFailure;
}

bool run_bip39_self_test() {
  static const char kMnemonic[] =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  static const uint8_t kExpectedSeed[kSeedSize] = {
    0xc5,
    0x52,
    0x57,
    0xc3,
    0x60,
    0xc0,
    0x7c,
    0x72,
    0x02,
    0x9a,
    0xeb,
    0xc1,
    0xb5,
    0x3c,
    0x05,
    0xed,
    0x03,
    0x62,
    0xad,
    0xa3,
    0x8e,
    0xad,
    0x3e,
    0x3e,
    0x9e,
    0xfa,
    0x37,
    0x08,
    0xe5,
    0x34,
    0x95,
    0x53,
    0x1f,
    0x09,
    0xa6,
    0x98,
    0x75,
    0x99,
    0xd1,
    0x82,
    0x64,
    0xc1,
    0xe1,
    0xc9,
    0x2f,
    0x2c,
    0xf1,
    0x41,
    0x63,
    0x0c,
    0x7a,
    0x3c,
    0x4a,
    0xb7,
    0xc8,
    0x1b,
    0x2f,
    0x00,
    0x16,
    0x98,
    0xe7,
    0x46,
    0x3b,
    0x04,
  };
  uint8_t seed[kSeedSize];
  const bool passed = bip39_validate_english(kMnemonic) == WalletError::Ok && bip39_seed_from_english(kMnemonic, "TREZOR", seed) == WalletError::Ok && crypto_constant_time_equal(seed, kExpectedSeed, sizeof(seed));
  secure_zero(seed, sizeof(seed));
  return passed;
}

WalletError public_key_from_private(const uint8_t private_key[kPrivateKeySize],
                                    uint8_t out_public_key[kCompressedPublicKeySize]) {
  if (private_key == nullptr || out_public_key == nullptr || !valid_private_key(private_key)) {
    return WalletError::InvalidKey;
  }
  mbedtls_ecp_group group;
  mbedtls_ecp_point point;
  mbedtls_mpi scalar;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&point);
  mbedtls_mpi_init(&scalar);
  size_t length = kCompressedPublicKeySize;
  const int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) || mbedtls_mpi_read_binary(&scalar, private_key, kPrivateKeySize) || mbedtls_ecp_mul(&group, &point, &scalar, &group.G, random_callback, nullptr) || mbedtls_ecp_point_write_binary(&group, &point, MBEDTLS_ECP_PF_COMPRESSED, &length, out_public_key, kCompressedPublicKeySize);
  mbedtls_mpi_free(&scalar);
  mbedtls_ecp_point_free(&point);
  mbedtls_ecp_group_free(&group);
  return result == 0 && length == kCompressedPublicKeySize ? WalletError::Ok : WalletError::CryptoFailure;
}

WalletError uncompressed_public_key_from_private(
  const uint8_t private_key[kPrivateKeySize],
  uint8_t out_public_key[kUncompressedPublicKeySize]) {
  if (private_key == nullptr || out_public_key == nullptr || !valid_private_key(private_key)) {
    return WalletError::InvalidKey;
  }
  mbedtls_ecp_group group;
  mbedtls_ecp_point point;
  mbedtls_mpi scalar;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&point);
  mbedtls_mpi_init(&scalar);
  size_t length = kUncompressedPublicKeySize;
  const int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) || mbedtls_mpi_read_binary(&scalar, private_key, kPrivateKeySize) || mbedtls_ecp_mul(&group, &point, &scalar, &group.G, random_callback, nullptr) || mbedtls_ecp_point_write_binary(&group, &point, MBEDTLS_ECP_PF_UNCOMPRESSED, &length, out_public_key, kUncompressedPublicKeySize);
  mbedtls_mpi_free(&scalar);
  mbedtls_ecp_point_free(&point);
  mbedtls_ecp_group_free(&group);
  return result == 0 && length == kUncompressedPublicKeySize ? WalletError::Ok
                                                             : WalletError::CryptoFailure;
}

WalletError secp256k1_sign_digest_recoverable(
  const uint8_t private_key[kPrivateKeySize],
  const uint8_t digest[kPrivateKeySize], RecoverableSignature *out_signature) {
  if (private_key == nullptr || digest == nullptr || out_signature == nullptr || !valid_private_key(private_key)) {
    return WalletError::InvalidArgument;
  }
  memset(out_signature, 0, sizeof(*out_signature));
  mbedtls_ecp_group group;
  mbedtls_ecp_point public_key;
  mbedtls_ecp_point recovery_point;
  mbedtls_mpi private_scalar, r, s, half_order, z, inverse_s, u1, u2, reduced_x;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&public_key);
  mbedtls_ecp_point_init(&recovery_point);
  mbedtls_mpi_init(&private_scalar);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&half_order);
  mbedtls_mpi_init(&z);
  mbedtls_mpi_init(&inverse_s);
  mbedtls_mpi_init(&u1);
  mbedtls_mpi_init(&u2);
  mbedtls_mpi_init(&reduced_x);
  int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
  if (result == 0) result = mbedtls_mpi_read_binary(&private_scalar, private_key, kPrivateKeySize);
  if (result == 0) {
    result = mbedtls_ecdsa_sign_det_ext(&group, &r, &s, &private_scalar,
                                        digest, kSha256Size, MBEDTLS_MD_SHA256,
                                        random_callback, nullptr);
  }
  if (result == 0) result = mbedtls_mpi_copy(&half_order, &group.N);
  if (result == 0) result = mbedtls_mpi_shift_r(&half_order, 1);
  if (result == 0 && mbedtls_mpi_cmp_mpi(&s, &half_order) > 0) {
    result = mbedtls_mpi_sub_mpi(&s, &group.N, &s);
  }
  if (result == 0) {
    result = mbedtls_ecp_mul(&group, &public_key, &private_scalar, &group.G,
                             random_callback, nullptr);
  }
  if (result == 0) {
    result = mbedtls_ecdsa_verify(&group, digest, kSha256Size, &public_key, &r, &s);
  }

  // The verification point equals the ECDSA nonce point for the normalized
  // low-S signature. Its Y parity is the recovery bit used by Ethereum.
  if (result == 0) result = mbedtls_mpi_read_binary(&z, digest, kSha256Size);
  if (result == 0) result = mbedtls_mpi_mod_mpi(&z, &z, &group.N);
  if (result == 0) result = mbedtls_mpi_inv_mod(&inverse_s, &s, &group.N);
  if (result == 0) result = mbedtls_mpi_mul_mpi(&u1, &z, &inverse_s);
  if (result == 0) result = mbedtls_mpi_mod_mpi(&u1, &u1, &group.N);
  if (result == 0) result = mbedtls_mpi_mul_mpi(&u2, &r, &inverse_s);
  if (result == 0) result = mbedtls_mpi_mod_mpi(&u2, &u2, &group.N);
  if (result == 0) {
    result = mbedtls_ecp_muladd(&group, &recovery_point, &u1, &group.G, &u2, &public_key);
  }
  if (result == 0) {
    result = mbedtls_mpi_copy(&reduced_x, &recovery_point.MBEDTLS_PRIVATE(X));
  }
  if (result == 0) result = mbedtls_mpi_mod_mpi(&reduced_x, &reduced_x, &group.N);
  if (result == 0 && (mbedtls_mpi_cmp_mpi(&reduced_x, &r) != 0 || mbedtls_mpi_cmp_mpi(&recovery_point.MBEDTLS_PRIVATE(X), &group.N) >= 0)) {
    result = MBEDTLS_ERR_ECP_VERIFY_FAILED;
  }
  if (result == 0) result = mbedtls_mpi_write_binary(&r, out_signature->r, kPrivateKeySize);
  if (result == 0) result = mbedtls_mpi_write_binary(&s, out_signature->s, kPrivateKeySize);
  if (result == 0) {
    out_signature->y_parity = static_cast<uint8_t>(
      mbedtls_mpi_get_bit(&recovery_point.MBEDTLS_PRIVATE(Y), 0));
  }

  mbedtls_mpi_free(&reduced_x);
  mbedtls_mpi_free(&u2);
  mbedtls_mpi_free(&u1);
  mbedtls_mpi_free(&inverse_s);
  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&half_order);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&private_scalar);
  mbedtls_ecp_point_free(&recovery_point);
  mbedtls_ecp_point_free(&public_key);
  mbedtls_ecp_group_free(&group);
  if (result != 0) secure_zero(out_signature, sizeof(*out_signature));
  return result == 0 ? WalletError::Ok : WalletError::CryptoFailure;
}

WalletError secp256k1_xonly_public_key(const uint8_t private_key[kPrivateKeySize],
                                       uint8_t out_xonly[kPrivateKeySize],
                                       uint8_t *out_parity) {
  if (private_key == nullptr || out_xonly == nullptr || !valid_private_key(private_key)) {
    return WalletError::InvalidArgument;
  }
  mbedtls_ecp_group group;
  mbedtls_ecp_point point;
  mbedtls_mpi scalar;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&point);
  mbedtls_mpi_init(&scalar);
  int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
  if (result == 0) result = mbedtls_mpi_read_binary(&scalar, private_key, kPrivateKeySize);
  if (result == 0) {
    result = mbedtls_ecp_mul(&group, &point, &scalar, &group.G, random_callback, nullptr);
  }
  if (result == 0) {
    result = mbedtls_mpi_write_binary(&point.MBEDTLS_PRIVATE(X), out_xonly, kPrivateKeySize);
  }
  if (result == 0 && out_parity != nullptr) {
    *out_parity = static_cast<uint8_t>(mbedtls_mpi_get_bit(&point.MBEDTLS_PRIVATE(Y), 0));
  }
  mbedtls_mpi_free(&scalar);
  mbedtls_ecp_point_free(&point);
  mbedtls_ecp_group_free(&group);
  if (result != 0) secure_zero(out_xonly, kPrivateKeySize);
  return result == 0 ? WalletError::Ok : WalletError::CryptoFailure;
}

WalletError secp256k1_schnorr_sign(const uint8_t private_key[kPrivateKeySize],
                                   const uint8_t message[kPrivateKeySize],
                                   const uint8_t aux_rand[kPrivateKeySize],
                                   uint8_t out_signature[64]) {
  if (private_key == nullptr || message == nullptr || aux_rand == nullptr ||
      out_signature == nullptr || !valid_private_key(private_key)) {
    return WalletError::InvalidArgument;
  }
  memset(out_signature, 0, 64);
  mbedtls_ecp_group group;
  mbedtls_ecp_point public_point;
  mbedtls_ecp_point nonce_point;
  mbedtls_mpi scalar, adjusted, nonce, k, challenge, product, sum;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&public_point);
  mbedtls_ecp_point_init(&nonce_point);
  mbedtls_mpi_init(&scalar);
  mbedtls_mpi_init(&adjusted);
  mbedtls_mpi_init(&nonce);
  mbedtls_mpi_init(&k);
  mbedtls_mpi_init(&challenge);
  mbedtls_mpi_init(&product);
  mbedtls_mpi_init(&sum);

  uint8_t public_x[kPrivateKeySize];
  uint8_t nonce_hash[kSha256Size];
  uint8_t aux_hash[kSha256Size];
  uint8_t adjusted_bytes[kPrivateKeySize];
  uint8_t nonce_input[3 * kPrivateKeySize];
  uint8_t challenge_input[3 * kPrivateKeySize];
  uint8_t nonce_x[kPrivateKeySize];
  uint8_t signature_s[kPrivateKeySize];

  int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
  if (result == 0) result = mbedtls_mpi_read_binary(&scalar, private_key, kPrivateKeySize);
  if (result == 0) {
    result = mbedtls_ecp_mul(&group, &public_point, &scalar, &group.G,
                             random_callback, nullptr);
  }
  if (result == 0) {
    result = mbedtls_mpi_write_binary(&public_point.MBEDTLS_PRIVATE(X), public_x,
                                      kPrivateKeySize);
  }
  if (result == 0) {
    if (mbedtls_mpi_get_bit(&public_point.MBEDTLS_PRIVATE(Y), 0) != 0) {
      result = mbedtls_mpi_sub_mpi(&adjusted, &group.N, &scalar);
    } else {
      result = mbedtls_mpi_copy(&adjusted, &scalar);
    }
  }
  if (result == 0) {
    result = mbedtls_mpi_write_binary(&adjusted, adjusted_bytes, kPrivateKeySize);
  }
  if (result == 0) {
    result = bip340_tagged_hash("BIP0340/aux", aux_rand, kPrivateKeySize, aux_hash)
               ? 0 : -1;
  }
  for (size_t index = 0; index < kPrivateKeySize && result == 0; ++index) {
    nonce_input[index] = adjusted_bytes[index] ^ aux_hash[index];
  }
  if (result == 0) {
    memcpy(nonce_input + kPrivateKeySize, public_x, kPrivateKeySize);
    memcpy(nonce_input + 2 * kPrivateKeySize, message, kPrivateKeySize);
    result = bip340_tagged_hash("BIP0340/nonce", nonce_input, sizeof(nonce_input),
                                nonce_hash) ? 0 : -1;
  }
  if (result == 0) result = mbedtls_mpi_read_binary(&nonce, nonce_hash, kSha256Size);
  if (result == 0) result = mbedtls_mpi_mod_mpi(&nonce, &nonce, &group.N);
  if (result == 0 && mbedtls_mpi_cmp_int(&nonce, 0) == 0) result = -1;
  if (result == 0) {
    result = mbedtls_ecp_mul(&group, &nonce_point, &nonce, &group.G,
                             random_callback, nullptr);
  }
  if (result == 0) {
    result = mbedtls_mpi_write_binary(&nonce_point.MBEDTLS_PRIVATE(X), nonce_x,
                                      kPrivateKeySize);
  }
  if (result == 0) {
    if (mbedtls_mpi_get_bit(&nonce_point.MBEDTLS_PRIVATE(Y), 0) != 0) {
      result = mbedtls_mpi_sub_mpi(&k, &group.N, &nonce);
    } else {
      result = mbedtls_mpi_copy(&k, &nonce);
    }
  }
  if (result == 0) {
    memcpy(challenge_input, nonce_x, kPrivateKeySize);
    memcpy(challenge_input + kPrivateKeySize, public_x, kPrivateKeySize);
    memcpy(challenge_input + 2 * kPrivateKeySize, message, kPrivateKeySize);
    uint8_t challenge_hash[kSha256Size];
    result = bip340_tagged_hash("BIP0340/challenge", challenge_input,
                                sizeof(challenge_input), challenge_hash)
               ? 0 : -1;
    if (result == 0) {
      result = mbedtls_mpi_read_binary(&challenge, challenge_hash, kSha256Size);
    }
    secure_zero(challenge_hash, sizeof(challenge_hash));
  }
  if (result == 0) result = mbedtls_mpi_mod_mpi(&challenge, &challenge, &group.N);
  if (result == 0) result = mbedtls_mpi_mul_mpi(&product, &challenge, &adjusted);
  if (result == 0) result = mbedtls_mpi_add_mpi(&sum, &product, &k);
  if (result == 0) result = mbedtls_mpi_mod_mpi(&sum, &sum, &group.N);
  if (result == 0) result = mbedtls_mpi_write_binary(&sum, signature_s, kPrivateKeySize);
  if (result == 0) {
    memcpy(out_signature, nonce_x, kPrivateKeySize);
    memcpy(out_signature + kPrivateKeySize, signature_s, kPrivateKeySize);
  }

  secure_zero(public_x, sizeof(public_x));
  secure_zero(nonce_hash, sizeof(nonce_hash));
  secure_zero(aux_hash, sizeof(aux_hash));
  secure_zero(adjusted_bytes, sizeof(adjusted_bytes));
  secure_zero(nonce_input, sizeof(nonce_input));
  secure_zero(challenge_input, sizeof(challenge_input));
  secure_zero(nonce_x, sizeof(nonce_x));
  secure_zero(signature_s, sizeof(signature_s));
  mbedtls_mpi_free(&sum);
  mbedtls_mpi_free(&product);
  mbedtls_mpi_free(&challenge);
  mbedtls_mpi_free(&k);
  mbedtls_mpi_free(&nonce);
  mbedtls_mpi_free(&adjusted);
  mbedtls_mpi_free(&scalar);
  mbedtls_ecp_point_free(&nonce_point);
  mbedtls_ecp_point_free(&public_point);
  mbedtls_ecp_group_free(&group);
  if (result != 0) {
    secure_zero(out_signature, 64);
    return WalletError::CryptoFailure;
  }
  return WalletError::Ok;
}

bool secp256k1_schnorr_verify(const uint8_t xonly_public_key[kPrivateKeySize],
                              const uint8_t message[kPrivateKeySize],
                              const uint8_t signature[64]) {
  if (xonly_public_key == nullptr || message == nullptr || signature == nullptr) {
    return false;
  }
  mbedtls_ecp_group group;
  mbedtls_ecp_point public_point, nonce_point, check_point;
  mbedtls_mpi s, e, neg_e;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&public_point);
  mbedtls_ecp_point_init(&nonce_point);
  mbedtls_ecp_point_init(&check_point);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&e);
  mbedtls_mpi_init(&neg_e);
  uint8_t compressed[33];
  uint8_t challenge_input[3 * kPrivateKeySize];
  uint8_t challenge_hash[kSha256Size];
  uint8_t expected[33];
  uint8_t actual[33];
  size_t actual_size = 0;
  bool ok = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) == 0;
  if (ok) ok = mbedtls_mpi_read_binary(&s, signature + kPrivateKeySize,
                                       kPrivateKeySize) == 0 &&
               mbedtls_mpi_cmp_mpi(&s, &group.N) < 0;
  if (ok) {
    compressed[0] = 0x02;
    memcpy(compressed + 1, xonly_public_key, kPrivateKeySize);
    ok = mbedtls_ecp_point_read_binary(&group, &public_point, compressed,
                                       sizeof(compressed)) == 0 &&
         mbedtls_ecp_check_pubkey(&group, &public_point) == 0;
  }
  if (ok) {
    compressed[0] = 0x02;
    memcpy(compressed + 1, signature, kPrivateKeySize);
    ok = mbedtls_ecp_point_read_binary(&group, &nonce_point, compressed,
                                       sizeof(compressed)) == 0 &&
         mbedtls_ecp_check_pubkey(&group, &nonce_point) == 0;
  }
  if (ok) {
    memcpy(challenge_input, signature, kPrivateKeySize);
    memcpy(challenge_input + kPrivateKeySize, xonly_public_key, kPrivateKeySize);
    memcpy(challenge_input + 2 * kPrivateKeySize, message, kPrivateKeySize);
    ok = bip340_tagged_hash("BIP0340/challenge", challenge_input,
                            sizeof(challenge_input), challenge_hash);
  }
  if (ok) {
    ok = mbedtls_mpi_read_binary(&e, challenge_hash, kSha256Size) == 0 &&
         mbedtls_mpi_mod_mpi(&e, &e, &group.N) == 0;
  }
  if (ok) {
    if (mbedtls_mpi_cmp_int(&e, 0) == 0) {
      ok = mbedtls_ecp_mul(&group, &check_point, &s, &group.G,
                           random_callback, nullptr) == 0;
    } else {
      ok = mbedtls_mpi_sub_mpi(&neg_e, &group.N, &e) == 0 &&
           mbedtls_ecp_muladd(&group, &check_point, &s, &group.G, &neg_e,
                              &public_point) == 0;
    }
  }
  if (ok) {
    ok = mbedtls_ecp_point_write_binary(&group, &check_point,
                                        MBEDTLS_ECP_PF_COMPRESSED, &actual_size,
                                        actual, sizeof(actual)) == 0 &&
         actual_size == sizeof(actual);
  }
  if (ok) {
    expected[0] = 0x02;
    memcpy(expected + 1, signature, kPrivateKeySize);
    ok = crypto_constant_time_equal(actual, expected, sizeof(expected));
  }
  secure_zero(compressed, sizeof(compressed));
  secure_zero(challenge_input, sizeof(challenge_input));
  secure_zero(challenge_hash, sizeof(challenge_hash));
  secure_zero(expected, sizeof(expected));
  secure_zero(actual, sizeof(actual));
  mbedtls_mpi_free(&neg_e);
  mbedtls_mpi_free(&e);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_point_free(&check_point);
  mbedtls_ecp_point_free(&nonce_point);
  mbedtls_ecp_point_free(&public_point);
  mbedtls_ecp_group_free(&group);
  return ok;
}

WalletError hd_private_from_seed(const uint8_t *seed, size_t seed_size, HdPrivateNode *out_node) {
  if (seed == nullptr || out_node == nullptr || seed_size < 16 || seed_size > 64) {
    return WalletError::InvalidArgument;
  }
  static const uint8_t kBip32Key[] = "Bitcoin seed";
  uint8_t material[64];
  if (!crypto_hmac_sha512(kBip32Key, sizeof(kBip32Key) - 1, seed, seed_size, material)) {
    return WalletError::CryptoFailure;
  }
  if (!valid_private_key(material)) {
    secure_zero(material, sizeof(material));
    return WalletError::InvalidChild;
  }
  memcpy(out_node->private_key, material, kPrivateKeySize);
  memcpy(out_node->chain_code, material + kPrivateKeySize, kChainCodeSize);
  out_node->depth = 0;
  out_node->parent_fingerprint = 0;
  out_node->child_number = 0;
  secure_zero(material, sizeof(material));
  return WalletError::Ok;
}

WalletError hd_private_derive(const HdPrivateNode *parent, uint32_t index, HdPrivateNode *out_node) {
  if (parent == nullptr || out_node == nullptr || !valid_private_key(parent->private_key) || parent->depth == 255) {
    return WalletError::InvalidArgument;
  }
  uint8_t data[37];
  uint8_t material[64];
  uint8_t parent_public[kCompressedPublicKeySize];
  const WalletError public_error = public_key_from_private(parent->private_key, parent_public);
  if (public_error != WalletError::Ok) {
    return public_error;
  }
  uint32_t parent_fingerprint;
  if (!fingerprint(parent_public, &parent_fingerprint)) {
    secure_zero(parent_public, sizeof(parent_public));
    return WalletError::CryptoFailure;
  }
  if (index >= kHardenedOffset) {
    data[0] = 0;
    memcpy(data + 1, parent->private_key, kPrivateKeySize);
  } else {
    memcpy(data, parent_public, sizeof(parent_public));
  }
  write_u32_be(data + 33, index);
  if (!crypto_hmac_sha512(parent->chain_code, kChainCodeSize, data, sizeof(data), material)) {
    secure_zero(data, sizeof(data));
    secure_zero(parent_public, sizeof(parent_public));
    return WalletError::CryptoFailure;
  }
  mbedtls_ecp_group group;
  mbedtls_mpi left;
  mbedtls_mpi parent_key;
  mbedtls_mpi child_key;
  mbedtls_ecp_group_init(&group);
  mbedtls_mpi_init(&left);
  mbedtls_mpi_init(&parent_key);
  mbedtls_mpi_init(&child_key);
  const int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) || mbedtls_mpi_read_binary(&left, material, kPrivateKeySize) || mbedtls_mpi_read_binary(&parent_key, parent->private_key, kPrivateKeySize) || mbedtls_mpi_add_mpi(&child_key, &left, &parent_key) || mbedtls_mpi_mod_mpi(&child_key, &child_key, &group.N);
  const bool valid = result == 0 && mbedtls_mpi_cmp_int(&left, 0) > 0 && mbedtls_mpi_cmp_mpi(&left, &group.N) < 0 && mbedtls_mpi_cmp_int(&child_key, 0) != 0;
  if (valid) {
    mbedtls_mpi_write_binary(&child_key, out_node->private_key, kPrivateKeySize);
    memcpy(out_node->chain_code, material + kPrivateKeySize, kChainCodeSize);
    out_node->depth = parent->depth + 1;
    out_node->parent_fingerprint = parent_fingerprint;
    out_node->child_number = index;
  }
  mbedtls_mpi_free(&child_key);
  mbedtls_mpi_free(&parent_key);
  mbedtls_mpi_free(&left);
  mbedtls_ecp_group_free(&group);
  secure_zero(data, sizeof(data));
  secure_zero(material, sizeof(material));
  secure_zero(parent_public, sizeof(parent_public));
  return valid ? WalletError::Ok : WalletError::InvalidChild;
}

WalletError hd_public_neuter(const HdPrivateNode *private_node, HdPublicNode *out_node) {
  if (private_node == nullptr || out_node == nullptr) {
    return WalletError::InvalidArgument;
  }
  const WalletError result = public_key_from_private(private_node->private_key, out_node->public_key);
  if (result != WalletError::Ok) {
    return result;
  }
  memcpy(out_node->chain_code, private_node->chain_code, kChainCodeSize);
  out_node->depth = private_node->depth;
  out_node->parent_fingerprint = private_node->parent_fingerprint;
  out_node->child_number = private_node->child_number;
  return WalletError::Ok;
}

WalletError hd_public_derive(const HdPublicNode *parent, uint32_t index, HdPublicNode *out_node) {
  if (parent == nullptr || out_node == nullptr || index >= kHardenedOffset || parent->depth == 255) {
    return index >= kHardenedOffset ? WalletError::HardenedPublicDerivation : WalletError::InvalidArgument;
  }
  uint8_t data[37];
  uint8_t material[64];
  memcpy(data, parent->public_key, kCompressedPublicKeySize);
  uint32_t parent_fingerprint;
  if (!fingerprint(parent->public_key, &parent_fingerprint)) {
    return WalletError::CryptoFailure;
  }
  write_u32_be(data + 33, index);
  if (!crypto_hmac_sha512(parent->chain_code, kChainCodeSize, data, sizeof(data), material)) {
    return WalletError::CryptoFailure;
  }
  mbedtls_ecp_group group;
  mbedtls_ecp_point parent_point;
  mbedtls_ecp_point child_point;
  mbedtls_mpi left;
  mbedtls_mpi one;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&parent_point);
  mbedtls_ecp_point_init(&child_point);
  mbedtls_mpi_init(&left);
  mbedtls_mpi_init(&one);
  size_t public_size = kCompressedPublicKeySize;
  int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) || mbedtls_ecp_point_read_binary(&group, &parent_point, parent->public_key, kCompressedPublicKeySize);
  if (result == 0) result = mbedtls_ecp_check_pubkey(&group, &parent_point);
  if (result == 0) result = mbedtls_mpi_read_binary(&left, material, kPrivateKeySize);
  const bool valid_offset = result == 0 && mbedtls_mpi_cmp_int(&left, 0) > 0 && mbedtls_mpi_cmp_mpi(&left, &group.N) < 0;
  if (result == 0 && !valid_offset) result = MBEDTLS_ERR_ECP_INVALID_KEY;
  if (result == 0) result = mbedtls_mpi_lset(&one, 1);
  if (result == 0) {
    // mbedTLS exposes point addition through muladd: R = left * G + 1 * parent.
    result = mbedtls_ecp_muladd(&group, &child_point, &left, &group.G,
                                &one, &parent_point);
  }
  if (result == 0) {
    result = mbedtls_ecp_check_pubkey(&group, &child_point);
  }
  if (result == 0) {
    result = mbedtls_ecp_point_write_binary(&group, &child_point, MBEDTLS_ECP_PF_COMPRESSED,
                                            &public_size, out_node->public_key,
                                            kCompressedPublicKeySize);
  }
  const bool valid = result == 0 && valid_offset && !mbedtls_ecp_is_zero(&child_point) && public_size == kCompressedPublicKeySize;
  if (valid) {
    memcpy(out_node->chain_code, material + kPrivateKeySize, kChainCodeSize);
    out_node->depth = parent->depth + 1;
    out_node->parent_fingerprint = parent_fingerprint;
    out_node->child_number = index;
  }
  mbedtls_mpi_free(&left);
  mbedtls_mpi_free(&one);
  mbedtls_ecp_point_free(&child_point);
  mbedtls_ecp_point_free(&parent_point);
  mbedtls_ecp_group_free(&group);
  secure_zero(data, sizeof(data));
  secure_zero(material, sizeof(material));
  return valid ? WalletError::Ok : WalletError::InvalidChild;
}

WalletError hd_private_derive_path(const HdPrivateNode *master, const char *path,
                                   HdPrivateNode *out_node) {
  if (master == nullptr || path == nullptr || out_node == nullptr || path[0] != 'm' || (path[1] != '\0' && path[1] != '/')) {
    return WalletError::InvalidPath;
  }
  HdPrivateNode current = *master;
  const char *cursor = path + 1;
  while (*cursor != '\0') {
    ++cursor;
    if (*cursor < '0' || *cursor > '9') {
      secure_zero(&current, sizeof(current));
      return WalletError::InvalidPath;
    }
    uint32_t index = 0;
    while (*cursor >= '0' && *cursor <= '9') {
      if (index > 214748364U || (index == 214748364U && *cursor > '7')) {
        secure_zero(&current, sizeof(current));
        return WalletError::InvalidPath;
      }
      index = index * 10 + static_cast<uint32_t>(*cursor - '0');
      ++cursor;
    }
    if (*cursor == '\'' || *cursor == 'h' || *cursor == 'H') {
      index |= kHardenedOffset;
      ++cursor;
    }
    if (*cursor != '\0' && *cursor != '/') {
      secure_zero(&current, sizeof(current));
      return WalletError::InvalidPath;
    }
    HdPrivateNode next;
    const WalletError result = hd_private_derive(&current, index, &next);
    secure_zero(&current, sizeof(current));
    if (result != WalletError::Ok) {
      return result;
    }
    current = next;
  }
  *out_node = current;
  return WalletError::Ok;
}

WalletError hd_serialize_private(const HdPrivateNode *node, ExtendedKeyFormat format,
                                 char *out, size_t *in_out_size) {
  if (node == nullptr || !valid_private_key(node->private_key)) {
    return WalletError::InvalidKey;
  }
  return serialize_payload(node->private_key, node->chain_code, node->depth,
                           node->parent_fingerprint, node->child_number, format, true, out, in_out_size);
}

WalletError hd_serialize_public(const HdPublicNode *node, ExtendedKeyFormat format,
                                char *out, size_t *in_out_size) {
  if (node == nullptr) {
    return WalletError::InvalidArgument;
  }
  return serialize_payload(node->public_key, node->chain_code, node->depth,
                           node->parent_fingerprint, node->child_number, format, false, out, in_out_size);
}

bool run_bip32_self_test() {
  const uint8_t seed[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
  HdPrivateNode master{};
  HdPrivateNode derived{};
  HdPublicNode master_public{};
  HdPublicNode derived_public{};
  HdPrivateNode private_child{};
  HdPublicNode private_child_public{};
  static const uint8_t kExpectedMasterPrivate[kPrivateKeySize] = {
    0xe8,
    0xf3,
    0x2e,
    0x72,
    0x3d,
    0xec,
    0xf4,
    0x05,
    0x1a,
    0xef,
    0xac,
    0x8e,
    0x2c,
    0x93,
    0xc9,
    0xc5,
    0xb2,
    0x14,
    0x31,
    0x38,
    0x17,
    0xcd,
    0xb0,
    0x1a,
    0x14,
    0x94,
    0xb9,
    0x17,
    0xc8,
    0x43,
    0x6b,
    0x35,
  };
  static const uint8_t kExpectedMasterChain[kChainCodeSize] = {
    0x87,
    0x3d,
    0xff,
    0x81,
    0xc0,
    0x2f,
    0x52,
    0x56,
    0x23,
    0xfd,
    0x1f,
    0xe5,
    0x16,
    0x7e,
    0xac,
    0x3a,
    0x55,
    0xa0,
    0x49,
    0xde,
    0x3d,
    0x31,
    0x4b,
    0xb4,
    0x2e,
    0xe2,
    0x27,
    0xff,
    0xed,
    0x37,
    0xd5,
    0x08,
  };
  const WalletError master_error = hd_private_from_seed(seed, sizeof(seed), &master);
  const bool master_vector = master_error == WalletError::Ok && memcmp(master.private_key, kExpectedMasterPrivate, kPrivateKeySize) == 0 && memcmp(master.chain_code, kExpectedMasterChain, kChainCodeSize) == 0;
  const WalletError path_error = master_error == WalletError::Ok
                                   ? hd_private_derive_path(&master, "m/0'/1/2'", &derived)
                                   : WalletError::InvalidChild;
  const bool path_metadata = path_error == WalletError::Ok && derived.depth == 3 && derived.child_number == (2 | kHardenedOffset);
  const WalletError master_public_error = master_error == WalletError::Ok
                                            ? hd_public_neuter(&master, &master_public)
                                            : WalletError::InvalidKey;
  const WalletError private_child_error = master_error == WalletError::Ok
                                            ? hd_private_derive(&master, 0, &private_child)
                                            : WalletError::InvalidChild;
  const WalletError private_child_public_error = private_child_error == WalletError::Ok
                                                   ? hd_public_neuter(&private_child, &private_child_public)
                                                   : WalletError::InvalidKey;
  const WalletError public_child_error = master_public_error == WalletError::Ok
                                           ? hd_public_derive(&master_public, 0, &derived_public)
                                           : WalletError::InvalidChild;
  const bool public_metadata = master_public_error == WalletError::Ok && master_public.depth == 0 && public_child_error == WalletError::Ok && derived_public.depth == 1;
  const bool public_private_match = private_child_public_error == WalletError::Ok && public_child_error == WalletError::Ok && memcmp(private_child_public.public_key, derived_public.public_key, kCompressedPublicKeySize) == 0 && memcmp(private_child_public.chain_code, derived_public.chain_code, kChainCodeSize) == 0;
  const bool passed = master_vector && path_metadata && public_metadata && public_private_match;
  if (!passed) {
    // Report only stage status and error codes; never print key material.
    Serial.print("BIP32_DETAIL master=");
    Serial.print(master_vector ? "pass" : "FAIL");
    Serial.print(" path=");
    Serial.print(path_metadata ? "pass" : "FAIL");
    Serial.print(" neuter=");
    Serial.print(master_public_error == WalletError::Ok ? "pass" : "FAIL");
    Serial.print(" private-child=");
    Serial.print(private_child_error == WalletError::Ok ? "pass" : "FAIL");
    Serial.print(" public-child=");
    Serial.print(public_child_error == WalletError::Ok ? "pass" : "FAIL");
    Serial.print(" public-match=");
    Serial.println(public_private_match ? "pass" : "FAIL");
  }
  secure_zero(&master, sizeof(master));
  secure_zero(&derived, sizeof(derived));
  secure_zero(&master_public, sizeof(master_public));
  secure_zero(&derived_public, sizeof(derived_public));
  secure_zero(&private_child, sizeof(private_child));
  secure_zero(&private_child_public, sizeof(private_child_public));
  return passed;
}

bool run_bip84_self_test() {
  // Published BIP84 vectors, including account serialization and change.
  const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const char *paths[] = {"m/84'/0'/0'/0/0", "m/84'/0'/0'/0/1", "m/84'/0'/0'/1/0"};
  const char *addresses[] = {
    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
  };
  uint8_t seed[kSeedSize] = {};
  HdPrivateNode master = {}, child = {};
  HdPublicNode pub = {};
  char text[kExtendedKeyTextSize] = {};
  size_t size = sizeof(text);
  bool passed = bip39_seed_from_english(mnemonic, "", seed) == WalletError::Ok &&
      hd_private_from_seed(seed, sizeof(seed), &master) == WalletError::Ok &&
      hd_serialize_private(&master, ExtendedKeyFormat::Zprv, text, &size) == WalletError::Ok &&
      strcmp(text, "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5") == 0;
  size = sizeof(text);
  passed = passed && hd_public_neuter(&master, &pub) == WalletError::Ok &&
      hd_serialize_public(&pub, ExtendedKeyFormat::Zpub, text, &size) == WalletError::Ok &&
      strcmp(text, "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF") == 0;
  size = sizeof(text);
  passed = passed && hd_private_derive_path(&master, "m/84'/0'/0'", &child) == WalletError::Ok &&
      hd_serialize_private(&child, ExtendedKeyFormat::Zprv, text, &size) == WalletError::Ok &&
      strcmp(text, "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE") == 0;
  size = sizeof(text);
  passed = passed && hd_public_neuter(&child, &pub) == WalletError::Ok &&
      hd_serialize_public(&pub, ExtendedKeyFormat::Zpub, text, &size) == WalletError::Ok &&
      strcmp(text, "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs") == 0;
  for (size_t i = 0; i < 3; ++i) {
    const bool valid = hd_private_derive_path(&master, paths[i], &child) == WalletError::Ok &&
        hd_public_neuter(&child, &pub) == WalletError::Ok &&
        address_p2wpkh(kBitcoinMainnet, pub.public_key, text, sizeof(text)) == WalletError::Ok &&
        strcmp(text, addresses[i]) == 0;
    passed = valid && passed;
  }
  secure_zero(seed, sizeof(seed));
  secure_zero(&master, sizeof(master));
  secure_zero(&child, sizeof(child));
  secure_zero(&pub, sizeof(pub));
  secure_zero(text, sizeof(text));
  return passed;
}

bool run_bip340_self_test() {
  struct Vector {
    const char *secret;
    const char *aux;
    const char *message;
    const char *public_key;
    const char *signature;
  };
  static const Vector kVector[] = {
    { "0000000000000000000000000000000000000000000000000000000000000003",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
      "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
      "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0" },
    { "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
      "0000000000000000000000000000000000000000000000000000000000000001",
      "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
      "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
      "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
      "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A" },
    { "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
      "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
      "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
      "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
      "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
      "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7" },
    { "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
      "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
      "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3" },
  };
  bool passed = true;
  for (size_t index = 0; index < sizeof(kVector) / sizeof(kVector[0]); ++index) {
    const Vector &vector = kVector[index];
    uint8_t secret[kPrivateKeySize];
    uint8_t aux[kPrivateKeySize];
    uint8_t message[kPrivateKeySize];
    uint8_t public_key[kPrivateKeySize];
    uint8_t expected[64];
    uint8_t signature[64];
    uint8_t xonly[kPrivateKeySize];
    uint8_t parity = 0;
    bool ok = parse_hex_fixed(vector.secret, secret, sizeof(secret)) &&
              parse_hex_fixed(vector.aux, aux, sizeof(aux)) &&
              parse_hex_fixed(vector.message, message, sizeof(message)) &&
              parse_hex_fixed(vector.public_key, public_key, sizeof(public_key)) &&
              parse_hex_fixed(vector.signature, expected, sizeof(expected));
    ok = ok && secp256k1_xonly_public_key(secret, xonly, &parity) == WalletError::Ok &&
         crypto_constant_time_equal(xonly, public_key, sizeof(xonly));
    ok = ok && secp256k1_schnorr_sign(secret, message, aux, signature) == WalletError::Ok &&
         crypto_constant_time_equal(signature, expected, sizeof(signature));
    ok = ok && secp256k1_schnorr_verify(public_key, message, expected);
    if (ok) {
      uint8_t tampered[64];
      memcpy(tampered, expected, sizeof(tampered));
      tampered[0] ^= 0x01;
      ok = !secp256k1_schnorr_verify(public_key, message, tampered);
      secure_zero(tampered, sizeof(tampered));
    }
    if (ok) {
      uint8_t changed_message[kPrivateKeySize];
      memcpy(changed_message, message, sizeof(changed_message));
      changed_message[0] ^= 0x01;
      ok = !secp256k1_schnorr_verify(public_key, changed_message, expected);
      secure_zero(changed_message, sizeof(changed_message));
    }
    passed = passed && ok;
    secure_zero(secret, sizeof(secret));
    secure_zero(aux, sizeof(aux));
    secure_zero(message, sizeof(message));
    secure_zero(public_key, sizeof(public_key));
    secure_zero(expected, sizeof(expected));
    secure_zero(signature, sizeof(signature));
    secure_zero(xonly, sizeof(xonly));
    (void)parity;
  }
  return passed;
}

bool run_secp256k1_self_test() {
  static const uint8_t kPrivateKey[kPrivateKeySize] = {
    0x61,
    0x9c,
    0x33,
    0x50,
    0x25,
    0xc7,
    0xf4,
    0x01,
    0x2e,
    0x55,
    0x6c,
    0x2a,
    0x58,
    0xb2,
    0x50,
    0x6e,
    0x30,
    0xb8,
    0x51,
    0x1b,
    0x53,
    0xad,
    0xe9,
    0x5e,
    0xa3,
    0x16,
    0xfd,
    0x8c,
    0x32,
    0x86,
    0xfe,
    0xb9,
  };
  static const uint8_t kDigest[kSha256Size] = {
    0xc3,
    0x7a,
    0xf3,
    0x11,
    0x16,
    0xd1,
    0xb2,
    0x7c,
    0xaf,
    0x68,
    0xaa,
    0xe9,
    0xe3,
    0xac,
    0x82,
    0xf1,
    0x47,
    0x79,
    0x29,
    0x01,
    0x4d,
    0x5b,
    0x91,
    0x76,
    0x57,
    0xd0,
    0xeb,
    0x49,
    0x47,
    0x8c,
    0xb6,
    0x70,
  };
  static const uint8_t kExpectedR[kPrivateKeySize] = {
    0x36,
    0x09,
    0xe1,
    0x7b,
    0x84,
    0xf6,
    0xa7,
    0xd3,
    0x0c,
    0x80,
    0xbf,
    0xa6,
    0x10,
    0xb5,
    0xb4,
    0x54,
    0x2f,
    0x32,
    0xa8,
    0xa0,
    0xd5,
    0x44,
    0x7a,
    0x12,
    0xfb,
    0x13,
    0x66,
    0xd7,
    0xf0,
    0x1c,
    0xc4,
    0x4a,
  };
  static const uint8_t kExpectedS[kPrivateKeySize] = {
    0x57,
    0x3a,
    0x95,
    0x4c,
    0x45,
    0x18,
    0x33,
    0x15,
    0x61,
    0x40,
    0x6f,
    0x90,
    0x30,
    0x0e,
    0x8f,
    0x33,
    0x58,
    0xf5,
    0x19,
    0x28,
    0xd4,
    0x3c,
    0x21,
    0x2a,
    0x8c,
    0xae,
    0xd0,
    0x2d,
    0xe6,
    0x7e,
    0xeb,
    0xee,
  };
  RecoverableSignature signature;
  const bool passed = secp256k1_sign_digest_recoverable(kPrivateKey, kDigest, &signature) == WalletError::Ok && crypto_constant_time_equal(signature.r, kExpectedR, sizeof(signature.r)) && crypto_constant_time_equal(signature.s, kExpectedS, sizeof(signature.s)) && signature.y_parity <= 1;
  secure_zero(&signature, sizeof(signature));
  return passed;
}

}  // namespace hexwallet
