#include "CardanoDerivation.h"

#include <string.h>

#include <mbedtls/md.h>

#include "CryptoExtended.h"
#include "WalletAltAddresses.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

constexpr uint32_t kHardened = 0x80000000UL;
constexpr uint8_t kEd25519Seed[] = {
    'e', 'd', '2', '5', '5', '1', '9', ' ', 's', 'e', 'e', 'd'};

bool hmac(mbedtls_md_type_t type, const uint8_t *key, size_t key_size,
          const uint8_t *data, size_t data_size, uint8_t *out,
          size_t out_size) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(type);
  const size_t expected = type == MBEDTLS_MD_SHA512 ? 64 : 32;
  if (info == nullptr || out_size != expected) return false;
  return mbedtls_md_hmac(info, key, key_size, data, data_size, out) == 0;
}

bool hmac_sha512(const uint8_t *key, size_t key_size, const uint8_t *data,
                 size_t data_size, uint8_t out[64]) {
  return hmac(MBEDTLS_MD_SHA512, key, key_size, data, data_size, out, 64);
}

bool hmac_sha256(const uint8_t *key, size_t key_size, const uint8_t *data,
                 size_t data_size, uint8_t out[32]) {
  return hmac(MBEDTLS_MD_SHA256, key, key_size, data, data_size, out, 32);
}

void write_index(uint32_t index, uint8_t out[4]) {
  out[0] = static_cast<uint8_t>(index);
  out[1] = static_cast<uint8_t>(index >> 8);
  out[2] = static_cast<uint8_t>(index >> 16);
  out[3] = static_cast<uint8_t>(index >> 24);
}

bool add_256(uint8_t value[32], const uint8_t addend[32], bool reject_carry) {
  uint16_t carry = 0;
  for (size_t i = 0; i < 32; ++i) {
    const uint16_t sum =
        static_cast<uint16_t>(value[i]) + addend[i] + carry;
    value[i] = static_cast<uint8_t>(sum);
    carry = sum >> 8;
  }
  return !reject_carry || carry == 0;
}

bool derive_child(const CardanoKey &parent, uint32_t index, CardanoKey *out) {
  const bool hardened = (index & kHardened) != 0;
  uint8_t data[1 + 64 + 4] = {};
  const size_t data_size = hardened ? sizeof(data) : 1 + 32 + 4;
  data[0] = hardened ? 0x00 : 0x02;
  if (hardened) {
    memcpy(data + 1, parent.kL, 32);
    memcpy(data + 33, parent.kR, 32);
    write_index(index, data + 65);
  } else {
    memcpy(data + 1, parent.public_key, 32);
    write_index(index, data + 33);
  }

  uint8_t z[64] = {};
  if (!hmac_sha512(parent.chain_code, sizeof(parent.chain_code), data,
                   data_size, z)) {
    return false;
  }
  data[0] = hardened ? 0x01 : 0x03;
  uint8_t digest[64] = {};
  if (!hmac_sha512(parent.chain_code, sizeof(parent.chain_code), data,
                   data_size, digest)) {
    return false;
  }

  CardanoKey child = {};
  memcpy(child.chain_code, digest + 32, 32);
  memcpy(child.kR, parent.kR, 32);
  uint8_t zr[32] = {};
  memcpy(zr, z + 32, 32);
  add_256(child.kR, zr, false);
  memcpy(child.kL, parent.kL, 32);
  uint8_t zl8[32] = {};
  memcpy(zl8, z, 28);
  uint16_t carry = 0;
  for (size_t i = 0; i < 32; ++i) {
    const uint16_t shifted =
        static_cast<uint16_t>(static_cast<uint16_t>(zl8[i]) << 3) | carry;
    zl8[i] = static_cast<uint8_t>(shifted);
    carry = shifted >> 8;
  }
  if (!add_256(child.kL, zl8, true) ||
      !ed25519_public_key_expanded(child.kL, child.public_key)) {
    secure_zero(&child, sizeof(child));
    return false;
  }
  secure_zero(data, sizeof(data));
  secure_zero(z, sizeof(z));
  secure_zero(digest, sizeof(digest));
  secure_zero(zl8, sizeof(zl8));
  secure_zero(zr, sizeof(zr));
  *out = child;
  return true;
}

}  // namespace

bool cardano_derive_path(const uint8_t seed[64], const uint32_t *path,
                         size_t path_size, CardanoKey *out) {
  if (seed == nullptr || path == nullptr || path_size == 0 ||
      path_size > 10 || out == nullptr) {
    return false;
  }
  uint8_t prefixed[65] = {};
  prefixed[0] = 0x01;
  memcpy(prefixed + 1, seed, 64);
  CardanoKey current = {};
  if (!hmac_sha256(kEd25519Seed, sizeof(kEd25519Seed), prefixed,
                   sizeof(prefixed), current.chain_code)) {
    return false;
  }
  uint8_t data[64] = {};
  memcpy(data, seed, 64);
  uint8_t digest[64] = {};
  for (;;) {
    if (!hmac_sha512(kEd25519Seed, sizeof(kEd25519Seed), data, sizeof(data),
                     digest)) {
      return false;
    }
    memcpy(current.kL, digest, 32);
    memcpy(current.kR, digest + 32, 32);
    if ((current.kL[31] & 0x20) == 0) break;
    memcpy(data, digest, 64);
  }
  current.kL[0] &= 0xf8;
  current.kL[31] &= 0x7f;
  current.kL[31] |= 0x40;
  if (!ed25519_public_key_expanded(current.kL, current.public_key)) {
    return false;
  }

  for (size_t i = 0; i < path_size; ++i) {
    CardanoKey child = {};
    if (!derive_child(current, path[i], &child)) {
      secure_zero(&current, sizeof(current));
      return false;
    }
    secure_zero(&current, sizeof(current));
    current = child;
  }
  secure_zero(prefixed, sizeof(prefixed));
  secure_zero(data, sizeof(data));
  secure_zero(digest, sizeof(digest));
  *out = current;
  return true;
}

bool run_cardano_derivation_self_tests() {
  // BIP39 seed for "abandon" x 11 + "about"; vectors from Ledger app-cardano
  // mock data (m/1852'/1815'/0'/0/0 and m/1852'/1815'/0'/2/0).
  static const uint8_t kSeed[64] = {
      0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8,
      0xab, 0x91, 0x55, 0x56, 0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8,
      0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1, 0x9a,
      0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d,
      0xec, 0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad,
      0x3d, 0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4};
  static const uint8_t kPaymentPublic[32] = {
      0xcd, 0x2b, 0x04, 0x7d, 0x1a, 0x80, 0x3e, 0xee, 0x05, 0x97, 0x69,
      0xcf, 0xfb, 0x3d, 0xfd, 0x0a, 0x4b, 0x93, 0x27, 0xe5, 0x5b, 0xc7,
      0x8a, 0xa9, 0x62, 0xd9, 0xbd, 0x4f, 0x72, 0x0d, 0xb0, 0xb2};
  static const uint8_t kStakePublic[32] = {
      0x66, 0x61, 0x0e, 0xfd, 0x33, 0x6e, 0x11, 0x37, 0xc5, 0x25, 0x93,
      0x7b, 0x76, 0x51, 0x1f, 0xbc, 0xf2, 0xa0, 0xe6, 0xbc, 0xf0, 0xd3,
      0x40, 0xa6, 0x7b, 0xcb, 0x39, 0xbc, 0x87, 0x0d, 0x85, 0xe8};
  static const uint8_t kPaymentChain[32] = {
      0x91, 0x4b, 0xa0, 0x7f, 0xb3, 0x81, 0xf2, 0x3c, 0x5c, 0x09, 0xbc,
      0xe2, 0x65, 0x87, 0xbd, 0xf3, 0x59, 0xaa, 0xb7, 0xea, 0x8f, 0x41,
      0x92, 0xad, 0xbf, 0x93, 0xa3, 0x8f, 0xd8, 0x93, 0xcc, 0xea};
  static const uint32_t kPaymentPath[5] = {
      1852 | kHardened, 1815 | kHardened, 0 | kHardened, 0, 0};
  static const uint32_t kStakePath[5] = {
      1852 | kHardened, 1815 | kHardened, 0 | kHardened, 2, 0};
  CardanoKey payment = {};
  CardanoKey stake = {};
  char address[128] = {};
  const bool ok =
      cardano_derive_path(kSeed, kPaymentPath, 5, &payment) &&
      cardano_derive_path(kSeed, kStakePath, 5, &stake) &&
      memcmp(payment.public_key, kPaymentPublic, 32) == 0 &&
      memcmp(stake.public_key, kStakePublic, 32) == 0 &&
      memcmp(payment.chain_code, kPaymentChain, 32) == 0 &&
      address_cardano_base(payment.public_key, stake.public_key, address,
                           sizeof(address)) == WalletError::Ok &&
      strcmp(address,
             "addr1qy2vzmtlgvjrhkq50rngh8d482zj3l20kyrc6kx4ffl3zfqayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwqf7zhh2") == 0;
  secure_zero(&payment, sizeof(payment));
  secure_zero(&stake, sizeof(stake));
  return ok;
}

}  // namespace hexwallet
