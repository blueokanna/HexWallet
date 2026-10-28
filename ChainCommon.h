#ifndef HEXWALLET_CHAIN_COMMON_H
#define HEXWALLET_CHAIN_COMMON_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Minimal RLP writer shared by the account-model chain adapters (VeChain,
// ICON and later chains). It only appends pre-encoded items; callers build
// nested lists in a scratch buffer and wrap them with rlp_wrap_list().
class RlpWriter {
 public:
  RlpWriter(uint8_t *out, size_t capacity) : out_(out), capacity_(capacity) {}
  bool bytes(const uint8_t *data, size_t size);
  // Minimal big-endian integer; zero is encoded as the empty string.
  bool integer(const uint8_t *big_endian, size_t size);
  // Append an item that is already RLP encoded.
  bool raw(const uint8_t *data, size_t size);
  size_t size() const { return size_; }
  bool ok() const { return ok_; }

 private:
  uint8_t *out_;
  size_t capacity_;
  size_t size_ = 0;
  bool ok_ = true;
};

size_t chain_hex_length(size_t bytes);
void chain_hex(const uint8_t *data, size_t size, char *out, size_t out_size);
bool chain_parse_hex(const char *text, uint8_t *out, size_t capacity, size_t *out_size);
bool chain_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t size);
// Deterministic low-S secp256k1 ECDSA over a 32-byte digest, DER encoded.
// Host builds that only exercise parsing can leave this unused; the device
// build provides mbedtls and esp_fill_random.
bool chain_secp256k1_sign_der(const uint8_t private_key[32],
                              const uint8_t digest[32], uint8_t *der,
                              size_t *in_out_size);
// Graphene (HIVE/Steem) requires "canonical" signatures: the DER-encoded r and
// s must each be exactly 32 bytes, so the high bit of the first byte must be
// clear. RFC 6979 nonces are ground with an extra-entropy counter until that
// holds. Returns the recovery id (0 or 1) through out_recovery.
bool chain_secp256k1_sign_der_canonical(const uint8_t private_key[32],
                                        const uint8_t digest[32], uint8_t *der,
                                        size_t *in_out_size,
                                        uint8_t *out_recovery);
// Render an integer with the requested number of decimals and symbol. Trailing
// fractional zeros are removed but at least one digit is kept.
bool chain_format_units(uint64_t value, uint8_t decimals, const char *symbol,
                        char *out, size_t out_size);

// 128-bit unsigned helpers for chains whose native amounts exceed 64 bits
// (VET wei and ICX loop both need this). Inputs are 16-byte big-endian.
constexpr size_t kChainUint128Size = 16;
bool chain_u128_is_zero(const uint8_t value[kChainUint128Size]);
bool chain_format_units128(const uint8_t value[kChainUint128Size],
                           uint8_t decimals, const char *symbol, char *out,
                           size_t out_size);
// Smallest big-endian slice of a 128-bit value, for RLP integers.
void chain_u128_minimal(const uint8_t value[kChainUint128Size],
                        const uint8_t **out, size_t *out_size);
// Minimal lowercase hex without a 0x prefix; zero renders as "0".
bool chain_u128_hex(const uint8_t value[kChainUint128Size], char *out,
                    size_t out_size);
uint64_t chain_read_u32_le(const uint8_t *data);
uint64_t chain_read_u64_le(const uint8_t *data);
void chain_write_u32_le(uint32_t value, uint8_t *out);
void chain_write_u64_le(uint64_t value, uint8_t *out);
bool rlp_wrap_list(const uint8_t *payload, size_t payload_size, uint8_t *out,
                   size_t capacity, size_t *out_size);

}  // namespace hexwallet

#endif
