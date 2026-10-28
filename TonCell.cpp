#include "TonCell.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {

const uint8_t kTonWalletV4R2CodeHash[32] = {
    0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d, 0x94, 0x83, 0xe7, 0xe0,
    0xd6, 0x2c, 0x81, 0x7d, 0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8,
    0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0};

void ton_cell_init(TonCell *cell) {
  if (cell == nullptr) return;
  memset(cell, 0, sizeof(*cell));
}

bool ton_write_bits(TonBitWriter *writer, uint64_t value, uint8_t count) {
  if (writer == nullptr || writer->cell == nullptr || count > 64 ||
      writer->cell->bits + count > kTonMaxCellBits) {
    if (writer != nullptr) writer->ok = false;
    return false;
  }
  TonCell *cell = writer->cell;
  for (uint8_t index = 0; index < count; ++index) {
    const uint8_t bit = static_cast<uint8_t>(
        (value >> (count - 1 - index)) & 1U);
    const uint16_t position = cell->bits++;
    if (bit != 0) {
      cell->data[position / 8] |= static_cast<uint8_t>(0x80 >> (position % 8));
    }
  }
  return true;
}

bool ton_write_bytes(TonBitWriter *writer, const uint8_t *data, size_t size) {
  if (writer == nullptr || (size != 0 && data == nullptr)) return false;
  if (writer->cell == nullptr ||
      writer->cell->bits + size * 8 > kTonMaxCellBits) {
    writer->ok = false;
    return false;
  }
  for (size_t index = 0; index < size; ++index) {
    if (!ton_write_bits(writer, data[index], 8)) return false;
  }
  return true;
}

bool ton_write_var_uint(TonBitWriter *writer, const uint8_t *big_endian,
                        size_t size) {
  if (writer == nullptr || (big_endian == nullptr && size != 0) || size > 16) {
    return false;
  }
  size_t offset = 0;
  while (offset < size && big_endian[offset] == 0) ++offset;
  const size_t bytes = size - offset;
  if (!ton_write_bits(writer, bytes, 4)) return false;
  return bytes == 0 || ton_write_bytes(writer, big_endian + offset, bytes);
}

bool ton_add_ref(TonBitWriter *writer, const uint8_t hash[32], uint16_t depth) {
  if (writer == nullptr || writer->cell == nullptr || hash == nullptr ||
      writer->cell->ref_count >= kTonMaxRefs) {
    if (writer != nullptr) writer->ok = false;
    return false;
  }
  TonRef &ref = writer->cell->refs[writer->cell->ref_count++];
  memcpy(ref.hash, hash, 32);
  ref.depth = depth;
  return true;
}

bool ton_cell_hash(const TonCell *cell, uint8_t out_hash[32],
                   uint16_t *out_depth) {
  if (cell == nullptr || out_hash == nullptr) return false;
  uint8_t representation[2 + kTonMaxCellData + kTonMaxRefs * 34] = {};
  size_t size = 0;
  uint16_t depth = 0;
  for (uint8_t index = 0; index < cell->ref_count; ++index) {
    if (cell->refs[index].depth > depth) depth = cell->refs[index].depth;
  }
  if (cell->ref_count != 0) ++depth;
  representation[size++] = cell->ref_count;
  representation[size++] = static_cast<uint8_t>(
      (cell->bits + 7) / 8 + cell->bits / 8);
  size_t data_bytes = cell->bits / 8;
  memcpy(representation + size, cell->data, data_bytes);
  size += data_bytes;
  if ((cell->bits % 8) != 0) {
    // Completion tag: a one bit immediately after the last data bit.
    representation[size] = static_cast<uint8_t>(
        cell->data[data_bytes] | (0x80 >> (cell->bits % 8)));
    ++size;
  }
  for (uint8_t index = 0; index < cell->ref_count; ++index) {
    representation[size++] = static_cast<uint8_t>(cell->refs[index].depth >> 8);
    representation[size++] = static_cast<uint8_t>(cell->refs[index].depth);
  }
  for (uint8_t index = 0; index < cell->ref_count; ++index) {
    memcpy(representation + size, cell->refs[index].hash, 32);
    size += 32;
  }
  const bool ok = crypto_sha256(representation, size, out_hash) != false;
  secure_zero(representation, sizeof(representation));
  if (ok && out_depth != nullptr) *out_depth = depth;
  return ok;
}

namespace {

bool build_wallet_state_init(const uint8_t public_key[32], uint32_t wallet_id,
                             TonCell *state_init) {
  if (public_key == nullptr || state_init == nullptr) return false;
  TonCell data;
  ton_cell_init(&data);
  TonBitWriter data_writer = {&data, true};
  if (!ton_write_bits(&data_writer, 0, 32) ||
      !ton_write_bits(&data_writer, wallet_id, 32) ||
      !ton_write_bytes(&data_writer, public_key, 32) ||
      !ton_write_bits(&data_writer, 0, 1)) {
    return false;
  }
  uint8_t data_hash[32] = {};
  if (!ton_cell_hash(&data, data_hash, nullptr)) return false;

  ton_cell_init(state_init);
  TonBitWriter writer = {state_init, true};
  if (!ton_write_bits(&writer, 0x06, 5) ||
      !ton_add_ref(&writer, kTonWalletV4R2CodeHash,
                   kTonWalletV4R2CodeDepth) ||
      !ton_add_ref(&writer, data_hash, 0)) {
    return false;
  }
  return writer.ok;
}

uint16_t crc16_xmodem(const uint8_t *data, size_t size) {
  uint16_t crc = 0;
  for (size_t index = 0; index < size; ++index) {
    crc ^= static_cast<uint16_t>(data[index]) << 8;
    for (uint8_t bit = 0; bit < 8; ++bit) {
      crc = (crc & 0x8000) != 0 ? static_cast<uint16_t>((crc << 1) ^ 0x1021)
                                : static_cast<uint16_t>(crc << 1);
    }
  }
  return crc;
}

bool base64url_encode(const uint8_t *data, size_t size, char *out,
                      size_t out_size) {
  // TON user-friendly addresses use standard base64 (tonsdk/tonweb output).
  static const char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  if (data == nullptr || out == nullptr || size > 64) return false;
  const size_t required = (size + 2) / 3 * 4 + 1;
  if (out_size < required) return false;
  size_t offset = 0;
  size_t input = 0;
  while (input + 3 <= size) {
    const uint32_t value = (static_cast<uint32_t>(data[input]) << 16) |
                           (static_cast<uint32_t>(data[input + 1]) << 8) |
                           data[input + 2];
    out[offset++] = kAlphabet[(value >> 18) & 63];
    out[offset++] = kAlphabet[(value >> 12) & 63];
    out[offset++] = kAlphabet[(value >> 6) & 63];
    out[offset++] = kAlphabet[value & 63];
    input += 3;
  }
  if (input < size) {
    uint32_t value = static_cast<uint32_t>(data[input]) << 16;
    if (input + 1 < size) value |= static_cast<uint32_t>(data[input + 1]) << 8;
    out[offset++] = kAlphabet[(value >> 18) & 63];
    out[offset++] = kAlphabet[(value >> 12) & 63];
    if (input + 1 < size) out[offset++] = kAlphabet[(value >> 6) & 63];
  }
  out[offset] = '\0';
  return true;
}

}  // namespace

bool ton_wallet_data_cell(const uint8_t public_key[32], uint32_t wallet_id,
                          TonCell *out) {
  if (public_key == nullptr || out == nullptr) return false;
  ton_cell_init(out);
  TonBitWriter writer = {out, true};
  return ton_write_bits(&writer, 0, 32) &&
         ton_write_bits(&writer, wallet_id, 32) &&
         ton_write_bytes(&writer, public_key, 32) &&
         ton_write_bits(&writer, 0, 1) && writer.ok;
}

bool ton_wallet_address_hash(const uint8_t public_key[32], uint32_t wallet_id,
                             uint8_t out_hash[32]) {
  if (public_key == nullptr || out_hash == nullptr) return false;
  TonCell state_init;
  if (!build_wallet_state_init(public_key, wallet_id, &state_init)) return false;
  return ton_cell_hash(&state_init, out_hash, nullptr);
}

bool ton_user_friendly_address(uint8_t flags, uint8_t workchain,
                               const uint8_t hash[32], char *out,
                               size_t out_size) {
  if (hash == nullptr || out == nullptr || out_size < 49) return false;
  uint8_t raw[36] = {};
  raw[0] = flags;
  raw[1] = workchain;
  memcpy(raw + 2, hash, 32);
  const uint16_t crc = crc16_xmodem(raw, 34);
  raw[34] = static_cast<uint8_t>(crc >> 8);
  raw[35] = static_cast<uint8_t>(crc);
  return base64url_encode(raw, sizeof(raw), out, out_size);
}

bool ton_format_nanotons(const uint8_t amount_be[16], char *out,
                         size_t out_size) {
  return chain_format_units128(amount_be, 9, "TON", out, out_size);
}

}  // namespace hexwallet
