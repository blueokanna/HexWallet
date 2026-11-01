#ifndef HEXWALLET_CHAIN_COMMON_H
#define HEXWALLET_CHAIN_COMMON_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{

  // Minimal RLP writer shared by the account-model chain adapters (VeChain,
  // ICON and later chains). It only appends pre-encoded items; callers build
  // nested lists in a scratch buffer and wrap them with rlp_wrap_list().
  class RlpWriter
  {
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

  inline bool chain_copy_text(char *out, size_t capacity, const char *text)
  {
    if (out == nullptr || capacity == 0 || text == nullptr)
      return false;
    size_t length = 0;
    while (length < capacity && text[length] != '\0')
      ++length;
    if (length >= capacity)
      return false;
    for (size_t index = 0; index <= length; ++index)
      out[index] = text[index];
    return true;
  }
  size_t chain_hex_length(size_t bytes);
  void chain_hex(const uint8_t *data, size_t size, char *out, size_t out_size);
  bool chain_parse_hex(const char *text, uint8_t *out, size_t capacity, size_t *out_size);
  bool chain_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t size);
  bool chain_secp256k1_sign_der(const uint8_t private_key[32],
                                const uint8_t digest[32], uint8_t *der,
                                size_t *in_out_size);
  bool chain_secp256k1_sign_der_canonical(const uint8_t private_key[32],
                                          const uint8_t digest[32], uint8_t *der,
                                          size_t *in_out_size,
                                          uint8_t *out_recovery);
  bool chain_format_units(uint64_t value, uint8_t decimals, const char *symbol,
                          char *out, size_t out_size);

  constexpr size_t kChainUint128Size = 16;
  constexpr size_t kChainUint256Size = 32;
  bool chain_u128_is_zero(const uint8_t value[kChainUint128Size]);
  bool chain_format_units128(const uint8_t value[kChainUint128Size],
                             uint8_t decimals, const char *symbol, char *out,
                             size_t out_size);
  // 256-bit counterpart used by the chains whose amounts are not 128-bit
  // (QRL v2, Starknet). `size` is validated against kChainUint256Size.
  bool chain_format_units256(const uint8_t value[kChainUint256Size],
                             uint8_t decimals, const char *symbol, char *out,
                             size_t out_size);
  bool chain_format_units_bytes(const uint8_t *value, size_t size,
                                uint8_t decimals, const char *symbol, char *out,
                                size_t out_size);
  void chain_u128_minimal(const uint8_t value[kChainUint128Size],
                          const uint8_t **out, size_t *out_size);
  bool chain_u128_hex(const uint8_t value[kChainUint128Size], char *out,
                      size_t out_size);
  uint64_t chain_read_u32_le(const uint8_t *data);
  uint64_t chain_read_u64_le(const uint8_t *data);
  void chain_write_u32_le(uint32_t value, uint8_t *out);
  void chain_write_u64_le(uint64_t value, uint8_t *out);
  bool rlp_wrap_list(const uint8_t *payload, size_t payload_size, uint8_t *out,
                     size_t capacity, size_t *out_size);

} // namespace hexwallet

#endif
