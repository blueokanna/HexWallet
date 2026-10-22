#include "MoneroScan.h"

#include <string.h>

#include "CryptoExtended.h"
#include "CryptoPrimitives.h"

namespace hexwallet {
namespace {

constexpr size_t kAmountBytes = 8;
constexpr uint64_t kMaxAmount = (1ULL << 56) - 1;

const uint8_t kEd25519BasePoint[kCryptoNotePublicKeySize] = {
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};

// CryptoNote varint (unsigned, little-endian base-128), also used as the "8"
// multiplier scalar.
size_t write_varint(uint64_t value, uint8_t *out, size_t out_size) {
  size_t used = 0;
  do {
    if (used >= out_size) return 0;
    uint8_t byte = static_cast<uint8_t>(value & 0x7fU);
    value >>= 7;
    if (value != 0) byte |= 0x80;
    out[used++] = byte;
  } while (value != 0);
  return used;
}

// derivation_to_scalar: Hs = sc_reduce32(keccak256(derivation || varint(index))).
bool derivation_scalar(const uint8_t derivation[kCryptoNotePublicKeySize],
                       uint64_t output_index,
                       uint8_t out[kCryptoNoteScalarSize]) {
  uint8_t buffer[kCryptoNotePublicKeySize + 10];
  uint8_t varint[10];
  const size_t varint_size = write_varint(output_index, varint, sizeof(varint));
  if (varint_size == 0) return false;
  memcpy(buffer, derivation, kCryptoNotePublicKeySize);
  memcpy(buffer + kCryptoNotePublicKeySize, varint, varint_size);
  uint8_t digest[kKeccak256Size];
  const bool hashed =
      crypto_keccak256(buffer, kCryptoNotePublicKeySize + varint_size, digest);
  if (hashed) {
    memcpy(out, digest, kCryptoNoteScalarSize);
    ed25519_scalar_reduce_mod_l(out);
  }
  secure_zero(buffer, sizeof(buffer));
  secure_zero(digest, sizeof(digest));
  return hashed;
}

}  // namespace

WalletError monero_scan_outputs(const uint8_t view_secret[kCryptoNoteScalarSize],
                                const MoneroSubaddressKeys *subaddresses,
                                size_t subaddress_count,
                                const MoneroScannedOutput *outputs,
                                size_t output_count,
                                MoneroOwnedOutput *owned,
                                size_t *in_out_owned_count) {
  if (view_secret == nullptr || subaddresses == nullptr || outputs == nullptr ||
      owned == nullptr || in_out_owned_count == nullptr) {
    return WalletError::InvalidArgument;
  }
  if (subaddress_count == 0 || subaddress_count > kMoneroMaxScanSubaddresses ||
      output_count > kMoneroMaxScanOutputs) {
    return WalletError::InvalidArgument;
  }
  const size_t capacity = *in_out_owned_count;
  size_t matches = 0;
  WalletError result = WalletError::Ok;
  for (size_t index = 0; index < output_count; ++index) {
    const MoneroScannedOutput &output = outputs[index];
    if (!ed25519_point_is_valid_compressed(output.ephemeral_public) ||
        !ed25519_point_is_valid_compressed(output.one_time_public)) {
      continue;
    }
    // shared = 8*(a*R); a invalid R is silently skipped above.
    uint8_t shared[kCryptoNotePublicKeySize];
    uint8_t shared8[kCryptoNotePublicKeySize];
    const uint8_t scalar_eight[kCryptoNoteScalarSize] = { 8 };
    if (!ed25519_point_mul_compressed(output.ephemeral_public, view_secret, shared) ||
        !ed25519_point_mul_compressed(shared, scalar_eight, shared8)) {
      secure_zero(shared, sizeof(shared));
      secure_zero(shared8, sizeof(shared8));
      result = WalletError::CryptoFailure;
      break;
    }
    uint8_t hs[kCryptoNoteScalarSize];
    if (!derivation_scalar(shared8, index, hs)) {
      secure_zero(shared, sizeof(shared));
      secure_zero(shared8, sizeof(shared8));
      result = WalletError::CryptoFailure;
      break;
    }
    uint8_t hs_point[kCryptoNotePublicKeySize];
    uint8_t candidate[kCryptoNotePublicKeySize];
    if (!ed25519_point_mul_compressed(kEd25519BasePoint, hs, hs_point)) {
      secure_zero(shared, sizeof(shared));
      secure_zero(shared8, sizeof(shared8));
      secure_zero(hs, sizeof(hs));
      result = WalletError::CryptoFailure;
      break;
    }
    for (size_t table = 0; table < subaddress_count; ++table) {
      if (!ed25519_point_add_compressed(hs_point, subaddresses[table].spend_public,
                                        candidate)) {
        continue;
      }
      if (!crypto_constant_time_equal(candidate, output.one_time_public,
                                      kCryptoNotePublicKeySize)) {
        continue;
      }
      uint64_t amount = 0;
      for (size_t byte = 0; byte < kAmountBytes; ++byte) {
        const uint8_t mask = hs[byte];
        amount |= static_cast<uint64_t>(output.encrypted_amount[byte] ^ mask)
                  << (8 * byte);
      }
      secure_zero(candidate, sizeof(candidate));
      if (matches >= capacity) {
        result = WalletError::BufferTooSmall;
        break;
      }

      const bool decoded = amount <= kMaxAmount;
      owned[matches].output_index = static_cast<uint16_t>(index);
      owned[matches].subaddress = static_cast<uint8_t>(table);
      owned[matches].amount_decoded = decoded;
      owned[matches].amount = decoded ? amount : 0;
      ++matches;
      break;
    }
    secure_zero(shared, sizeof(shared));
    secure_zero(shared8, sizeof(shared8));
    secure_zero(hs, sizeof(hs));
    secure_zero(hs_point, sizeof(hs_point));
    secure_zero(candidate, sizeof(candidate));
    if (result != WalletError::Ok) break;
  }
  *in_out_owned_count = matches;
  return result;
}

bool run_monero_scan_self_tests() {
  // Vector produced by an independent Python Keccak-256 / twisted-Edwards
  // implementation: view key a = 0x11*32, spend key b = 0x22*32, tx secret
  // r = 0x33*32, subaddress (0,1) and amount 1234567890123.
  const uint8_t view_secret[kCryptoNoteScalarSize] = {
    0x24, 0x3d, 0x1b, 0xb4, 0xf6, 0xad, 0xfe, 0xb8, 0x3a, 0x74, 0x19, 0x6e,
    0x32, 0x17, 0x32, 0xfc, 0x10, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01 };
  const uint8_t spend_public[kCryptoNotePublicKeySize] = {
    0x51, 0x2e, 0x1a, 0x20, 0x60, 0xd9, 0x78, 0xa1, 0x1a, 0x9c, 0xe6, 0x5b,
    0xbb, 0x6b, 0x98, 0xdc, 0xf3, 0x30, 0x0b, 0x76, 0x2c, 0x52, 0x0b, 0x13,
    0xfe, 0x2e, 0x65, 0x8b, 0x58, 0x35, 0x93, 0xbf };
  const uint8_t subaddress_public[kCryptoNotePublicKeySize] = {
    0x31, 0x33, 0x75, 0x0b, 0x5c, 0x8f, 0x12, 0x33, 0xf4, 0xce, 0x64, 0x94,
    0x88, 0x82, 0xcd, 0xe8, 0xc0, 0xf9, 0x96, 0x80, 0x0d, 0x8a, 0x44, 0x98,
    0xb4, 0x22, 0xd9, 0x39, 0x39, 0x6d, 0x27, 0x62 };
  const uint8_t ephemeral_public[kCryptoNotePublicKeySize] = {
    0x65, 0x89, 0x28, 0x14, 0xb0, 0xa9, 0xbe, 0xe7, 0xad, 0xe5, 0xad, 0x67,
    0x5c, 0x62, 0x28, 0x4e, 0xa7, 0xe2, 0x49, 0xfb, 0xa0, 0xfc, 0xd6, 0x5f,
    0xaf, 0xa0, 0x07, 0xd3, 0x38, 0x17, 0xd6, 0x6a };
  const uint8_t one_time_public[kCryptoNotePublicKeySize] = {
    0xff, 0x8a, 0x24, 0xa6, 0xd8, 0xff, 0xc3, 0x0b, 0xd3, 0x1c, 0xb6, 0x19,
    0x2b, 0xcd, 0x7c, 0x7c, 0xd1, 0xe4, 0xeb, 0x06, 0x47, 0x93, 0x2b, 0x98,
    0xe5, 0x62, 0x40, 0x2d, 0x4c, 0xb1, 0x45, 0x40 };
  const uint8_t encrypted_amount[8] = { 0xeb, 0x99, 0x6e, 0xb3, 0x4b, 0x9b, 0x65, 0x10 };
  const uint64_t expected_amount = 1234567890123ULL;

  MoneroSubaddressKeys table[2] = {};
  table[0].account = 0;
  table[0].minor = 0;
  memcpy(table[0].spend_public, spend_public, kCryptoNotePublicKeySize);
  table[1].account = 0;
  table[1].minor = 1;
  memcpy(table[1].spend_public, subaddress_public, kCryptoNotePublicKeySize);

  MoneroScannedOutput outputs[2] = {};
  memcpy(outputs[0].ephemeral_public, ephemeral_public, kCryptoNotePublicKeySize);
  memcpy(outputs[0].one_time_public, one_time_public, kCryptoNotePublicKeySize);
  memcpy(outputs[0].encrypted_amount, encrypted_amount, sizeof(encrypted_amount));
  // Second output belongs to the base address, so it must not match either.
  memcpy(outputs[1].ephemeral_public, ephemeral_public, kCryptoNotePublicKeySize);
  memcpy(outputs[1].one_time_public, subaddress_public, kCryptoNotePublicKeySize);
  memcpy(outputs[1].encrypted_amount, encrypted_amount, sizeof(encrypted_amount));

  MoneroOwnedOutput owned[4] = {};
  size_t owned_count = 4;
  const WalletError result =
      monero_scan_outputs(view_secret, table, 2, outputs, 2, owned, &owned_count);
  const bool passed = result == WalletError::Ok && owned_count == 1 &&
                      owned[0].output_index == 0 && owned[0].subaddress == 1 &&
                      owned[0].amount_decoded && owned[0].amount == expected_amount;
  secure_zero(table, sizeof(table));
  secure_zero(outputs, sizeof(outputs));
  secure_zero(owned, sizeof(owned));
  return passed;
}

}  // namespace hexwallet
