#include "WalletSecurity.h"

#include <Arduino.h>
#include <esp_system.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <string.h>

#include "base58.h"
#include "local_ripemd160.h"
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

bool hmac_sha512(const uint8_t *key, size_t key_length, const uint8_t *data,
                 size_t data_length, uint8_t out[64]) {
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  const int result = info == nullptr ? -1 :
      (mbedtls_md_setup(&context, info, 1) ||
       mbedtls_md_hmac_starts(&context, key, key_length) ||
       mbedtls_md_hmac_update(&context, data, data_length) ||
       mbedtls_md_hmac_finish(&context, out));
  mbedtls_md_free(&context);
  return result == 0;
}

bool valid_private_key(const uint8_t key[kPrivateKeySize]) {
  mbedtls_ecp_group group;
  mbedtls_mpi scalar;
  mbedtls_ecp_group_init(&group);
  mbedtls_mpi_init(&scalar);
  const int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) ||
                     mbedtls_mpi_read_binary(&scalar, key, kPrivateKeySize);
  const bool valid = result == 0 && mbedtls_mpi_cmp_int(&scalar, 0) > 0 &&
                     mbedtls_mpi_cmp_mpi(&scalar, &group.N) < 0;
  mbedtls_mpi_free(&scalar);
  mbedtls_ecp_group_free(&group);
  return valid;
}

bool hash160(const uint8_t *data, size_t length, uint8_t out[20]) {
  uint8_t digest[32];
  if (!sha256(data, length, digest)) {
    return false;
  }
  local_ripemd160(digest, sizeof(digest), out);
  secure_zero(digest, sizeof(digest));
  return true;
}

uint32_t fingerprint(const uint8_t public_key[kCompressedPublicKeySize]) {
  uint8_t digest[20];
  const bool ok = hash160(public_key, kCompressedPublicKeySize, digest);
  const uint32_t result = ok ? (static_cast<uint32_t>(digest[0]) << 24) |
                                  (static_cast<uint32_t>(digest[1]) << 16) |
                                  (static_cast<uint32_t>(digest[2]) << 8) |
                                  digest[3] : 0;
  secure_zero(digest, sizeof(digest));
  return result;
}

void write_u32_be(uint8_t *out, uint32_t value) {
  out[0] = static_cast<uint8_t>(value >> 24);
  out[1] = static_cast<uint8_t>(value >> 16);
  out[2] = static_cast<uint8_t>(value >> 8);
  out[3] = static_cast<uint8_t>(value);
}

bool version_bytes(ExtendedKeyFormat format, bool private_key, uint8_t out[4]) {
  if ((private_key && (format == ExtendedKeyFormat::Xpub || format == ExtendedKeyFormat::Zpub ||
                       format == ExtendedKeyFormat::Tpub || format == ExtendedKeyFormat::Vpub)) ||
      (!private_key && (format == ExtendedKeyFormat::Xprv || format == ExtendedKeyFormat::Zprv ||
                        format == ExtendedKeyFormat::Tprv || format == ExtendedKeyFormat::Vprv))) {
    return false;
  }
  static const uint32_t kVersions[] = {
    0x0488ADE4UL, 0x0488B21EUL, 0x04B2430CUL, 0x04B24746UL,
    0x04358394UL, 0x043587CFUL, 0x045F18BCUL, 0x045F1CF6UL,
  };
  write_u32_be(out, kVersions[static_cast<uint8_t>(format)]);
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
  if (!sha256(payload, sizeof(payload), checksum) || !sha256(checksum, sizeof(checksum), checksum)) {
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
  return strcmp(english_word_list[0], "abandon") == 0 &&
         strcmp(english_word_list[2047], "zoo") == 0;
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
  if (!sha256(entropy, sizeof(entropy), digest)) {
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
  uint8_t bits[33] = {0};
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
  if (!sha256(bits, entropy_bits / 8, digest)) {
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
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  const int result = info == nullptr ? -1 :
      (mbedtls_md_setup(&context, info, 1) ||
       mbedtls_pkcs5_pbkdf2_hmac(&context, reinterpret_cast<const unsigned char *>(mnemonic), strlen(mnemonic),
                                  reinterpret_cast<const unsigned char *>(salt), 8 + passphrase_length,
                                  2048, kSeedSize, out_seed));
  mbedtls_md_free(&context);
  secure_zero(salt, sizeof(salt));
  return result == 0 ? WalletError::Ok : WalletError::CryptoFailure;
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
  const int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) ||
                     mbedtls_mpi_read_binary(&scalar, private_key, kPrivateKeySize) ||
                     mbedtls_ecp_mul(&group, &point, &scalar, &group.G, random_callback, nullptr) ||
                     mbedtls_ecp_point_write_binary(&group, &point, MBEDTLS_ECP_PF_COMPRESSED,
                                                    &length, out_public_key, kCompressedPublicKeySize);
  mbedtls_mpi_free(&scalar);
  mbedtls_ecp_point_free(&point);
  mbedtls_ecp_group_free(&group);
  return result == 0 && length == kCompressedPublicKeySize ? WalletError::Ok : WalletError::CryptoFailure;
}

WalletError hd_private_from_seed(const uint8_t *seed, size_t seed_size, HdPrivateNode *out_node) {
  if (seed == nullptr || out_node == nullptr || seed_size < 16 || seed_size > 64) {
    return WalletError::InvalidArgument;
  }
  static const uint8_t kBip32Key[] = "Bitcoin seed";
  uint8_t material[64];
  if (!hmac_sha512(kBip32Key, sizeof(kBip32Key) - 1, seed, seed_size, material)) {
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
  const uint32_t parent_fingerprint = fingerprint(parent_public);
  if (index >= kHardenedOffset) {
    data[0] = 0;
    memcpy(data + 1, parent->private_key, kPrivateKeySize);
  } else {
    memcpy(data, parent_public, sizeof(parent_public));
  }
  write_u32_be(data + 33, index);
  if (!hmac_sha512(parent->chain_code, kChainCodeSize, data, sizeof(data), material)) {
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
  const int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) ||
                     mbedtls_mpi_read_binary(&left, material, kPrivateKeySize) ||
                     mbedtls_mpi_read_binary(&parent_key, parent->private_key, kPrivateKeySize) ||
                     mbedtls_mpi_add_mpi(&child_key, &left, &parent_key) ||
                     mbedtls_mpi_mod_mpi(&child_key, &child_key, &group.N);
  const bool valid = result == 0 && mbedtls_mpi_cmp_int(&left, 0) > 0 &&
                     mbedtls_mpi_cmp_mpi(&left, &group.N) < 0 && mbedtls_mpi_cmp_int(&child_key, 0) != 0;
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
  const uint32_t parent_fingerprint = fingerprint(parent->public_key);
  write_u32_be(data + 33, index);
  if (!hmac_sha512(parent->chain_code, kChainCodeSize, data, sizeof(data), material)) {
    return WalletError::CryptoFailure;
  }
  mbedtls_ecp_group group;
  mbedtls_ecp_point parent_point;
  mbedtls_ecp_point offset_point;
  mbedtls_ecp_point child_point;
  mbedtls_mpi left;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&parent_point);
  mbedtls_ecp_point_init(&offset_point);
  mbedtls_ecp_point_init(&child_point);
  mbedtls_mpi_init(&left);
  size_t public_size = kCompressedPublicKeySize;
  const int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1) ||
                     mbedtls_ecp_point_read_binary(&group, &parent_point, parent->public_key, kCompressedPublicKeySize) ||
                     mbedtls_mpi_read_binary(&left, material, kPrivateKeySize) ||
                     mbedtls_ecp_mul(&group, &offset_point, &left, &group.G, random_callback, nullptr) ||
                     mbedtls_ecp_add(&group, &child_point, &parent_point, &offset_point) ||
                     mbedtls_ecp_point_write_binary(&group, &child_point, MBEDTLS_ECP_PF_COMPRESSED,
                                                    &public_size, out_node->public_key, kCompressedPublicKeySize);
  const bool valid = result == 0 && mbedtls_mpi_cmp_int(&left, 0) > 0 &&
                     mbedtls_mpi_cmp_mpi(&left, &group.N) < 0 && !mbedtls_ecp_is_zero(&child_point) &&
                     public_size == kCompressedPublicKeySize;
  if (valid) {
    memcpy(out_node->chain_code, material + kPrivateKeySize, kChainCodeSize);
    out_node->depth = parent->depth + 1;
    out_node->parent_fingerprint = parent_fingerprint;
    out_node->child_number = index;
  }
  mbedtls_mpi_free(&left);
  mbedtls_ecp_point_free(&child_point);
  mbedtls_ecp_point_free(&offset_point);
  mbedtls_ecp_point_free(&parent_point);
  mbedtls_ecp_group_free(&group);
  secure_zero(data, sizeof(data));
  secure_zero(material, sizeof(material));
  return valid ? WalletError::Ok : WalletError::InvalidChild;
}

WalletError hd_private_derive_path(const HdPrivateNode *master, const char *path,
                                   HdPrivateNode *out_node) {
  if (master == nullptr || path == nullptr || out_node == nullptr || path[0] != 'm' ||
      (path[1] != '\0' && path[1] != '/')) {
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
  const uint8_t seed[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  HdPrivateNode master;
  HdPrivateNode derived;
  HdPublicNode master_public;
  HdPublicNode derived_public;
  HdPrivateNode private_child;
  HdPublicNode private_child_public;
  const bool passed = hd_private_from_seed(seed, sizeof(seed), &master) == WalletError::Ok &&
                      hd_private_derive_path(&master, "m/0'/1/2'", &derived) == WalletError::Ok &&
                      hd_public_neuter(&master, &master_public) == WalletError::Ok &&
                      hd_private_derive(&master, 0, &private_child) == WalletError::Ok &&
                      hd_public_neuter(&private_child, &private_child_public) == WalletError::Ok &&
                      hd_public_derive(&master_public, 0, &derived_public) == WalletError::Ok &&
                      derived.depth == 3 && derived.child_number == (2 | kHardenedOffset) &&
                      master_public.depth == 0 && derived_public.depth == 1 &&
                      memcmp(private_child_public.public_key, derived_public.public_key,
                             kCompressedPublicKeySize) == 0 &&
                      memcmp(private_child_public.chain_code, derived_public.chain_code,
                             kChainCodeSize) == 0;
  secure_zero(&master, sizeof(master));
  secure_zero(&derived, sizeof(derived));
  secure_zero(&master_public, sizeof(master_public));
  secure_zero(&derived_public, sizeof(derived_public));
  secure_zero(&private_child, sizeof(private_child));
  secure_zero(&private_child_public, sizeof(private_child_public));
  return passed;
}

}  // namespace hexwallet
