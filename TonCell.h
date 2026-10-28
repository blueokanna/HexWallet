#ifndef HEXWALLET_TON_CELL_H
#define HEXWALLET_TON_CELL_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// TON cell hashing needs only the data bits and the child hashes/depths. This
// is deliberately not a full BoC implementation: the phone assembles the
// external message, while the device reviews and signs the wallet body hash.
constexpr size_t kTonMaxCellBits = 1023;
constexpr size_t kTonMaxCellData = (kTonMaxCellBits + 7) / 8;
constexpr size_t kTonMaxRefs = 4;
constexpr uint32_t kTonDefaultWalletId = 698983191;

struct TonRef {
  uint8_t hash[32];
  uint16_t depth;
};

struct TonCell {
  uint8_t data[kTonMaxCellData];
  uint16_t bits;
  uint8_t ref_count;
  TonRef refs[kTonMaxRefs];
};

struct TonBitWriter {
  TonCell *cell;
  bool ok;
};

void ton_cell_init(TonCell *cell);
bool ton_write_bits(TonBitWriter *writer, uint64_t value, uint8_t count);
bool ton_write_bytes(TonBitWriter *writer, const uint8_t *data, size_t size);
bool ton_write_var_uint(TonBitWriter *writer, const uint8_t *big_endian,
                        size_t size);
bool ton_add_ref(TonBitWriter *writer, const uint8_t hash[32], uint16_t depth);
// Representation hash and own depth.
bool ton_cell_hash(const TonCell *cell, uint8_t out_hash[32],
                   uint16_t *out_depth);

// Wallet v4R2 code identity (code cell hash and depth).
extern const uint8_t kTonWalletV4R2CodeHash[32];
constexpr uint16_t kTonWalletV4R2CodeDepth = 7;

// Builds the v4R2 data cell, state-init hash and user-friendly address.
// flags: 0x51 non-bounceable, 0x11 bounceable (mainnet, workchain 0).
bool ton_wallet_data_cell(const uint8_t public_key[32], uint32_t wallet_id,
                          TonCell *out);
bool ton_wallet_address_hash(const uint8_t public_key[32], uint32_t wallet_id,
                             uint8_t out_hash[32]);
bool ton_user_friendly_address(uint8_t flags, uint8_t workchain,
                               const uint8_t hash[32], char *out,
                               size_t out_size);
bool ton_format_nanotons(const uint8_t amount_be[16], char *out,
                         size_t out_size);

}  // namespace hexwallet

#endif
