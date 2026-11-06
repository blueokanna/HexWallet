#include "AeternityTransaction.h"

#include <stdio.h>
#include <string.h>

#include "Blake2b.h"
#include "base58.h"
#include "ChainCommon.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "WalletAltAddresses.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {

    // Tag and version of the two objects this adapter touches.
    constexpr uint8_t kSpendTxTag = 12;
    constexpr uint8_t kSignedTxTag = 11;
    constexpr uint8_t kObjectVersion = 1;
    constexpr char kNetworkId[] = "ae_mainnet";
    constexpr size_t kNetworkIdSize = sizeof(kNetworkId) - 1;

    constexpr uint8_t kRlpShortString = 0x80;
    constexpr uint8_t kRlpLongString = 0xb8;
    constexpr uint8_t kRlpShortList = 0xc0;
    constexpr uint8_t kRlpLongList = 0xf8;
    constexpr size_t kRlpMaxLengthOfLength = 4;

    struct RlpItem
    {
      bool is_list;
      const uint8_t *payload;
      size_t payload_size;
      size_t total; // header + payload, so the caller advances by this much
    };

    size_t long_length_bytes(size_t value)
    {
      size_t bytes = 1;
      while (bytes < kRlpMaxLengthOfLength && (value >> (8 * bytes)) != 0)
      {
        ++bytes;
      }
      return bytes;
    }

    size_t rlp_header_size(size_t payload, bool is_list)
    {
      if (payload <= 55)
      {
        return 1;
      }
      return 1 + long_length_bytes(payload);
    }

    // Writes the header for `payload` bytes and returns its size. The caller has
    // already checked that `out` has rlp_header_size() bytes of room.
    size_t rlp_write_header(uint8_t *out, size_t payload, bool is_list)
    {
      if (payload <= 55)
      {
        out[0] = static_cast<uint8_t>((is_list ? kRlpShortList : kRlpShortString) + payload);
        return 1;
      }
      const size_t length_bytes = long_length_bytes(payload);
      out[0] = static_cast<uint8_t>((is_list ? kRlpLongList : kRlpLongString) + length_bytes - 1);
      for (size_t index = 0; index < length_bytes; ++index)
      {
        out[1 + index] = static_cast<uint8_t>(payload >> (8 * (length_bytes - 1 - index)));
      }
      return 1 + length_bytes;
    }

    // Appends a string item and advances `offset`.
    bool rlp_append_string(uint8_t *out, size_t capacity, size_t *offset,
                           const uint8_t *data, size_t size)
    {
      if (size == 1 && data[0] < kRlpShortString)
      {
        if (*offset + 1 > capacity)
          return false;
        out[(*offset)++] = data[0];
        return true;
      }
      const size_t header = rlp_header_size(size, false);
      if (*offset + header + size > capacity)
        return false;
      *offset += rlp_write_header(out + *offset, size, false);
      if (size != 0)
      {
        memcpy(out + *offset, data, size);
      }
      *offset += size;
      return true;
    }

    bool rlp_append_raw(uint8_t *out, size_t capacity, size_t *offset,
                        const uint8_t *data, size_t size)
    {
      if (*offset + size > capacity)
        return false;
      memcpy(out + *offset, data, size);
      *offset += size;
      return true;
    }

    size_t minimal_u64(uint8_t *out, uint64_t value)
    {
      if (value == 0)
        return 0;
      size_t bytes = 1;
      while (bytes < 8 && (value >> (8 * bytes)) != 0)
      {
        ++bytes;
      }
      for (size_t index = 0; index < bytes; ++index)
      {
        out[index] = static_cast<uint8_t>(value >> (8 * (bytes - 1 - index)));
      }
      return bytes;
    }

    bool read_minimal_u64(const uint8_t *data, size_t size, uint64_t *out)
    {
      if (size > 8 || out == nullptr)
        return false;
      if (size != 0 && data[0] == 0)
        return false;
      uint64_t value = 0;
      for (size_t index = 0; index < size; ++index)
      {
        value = (value << 8) | data[index];
      }
      *out = value;
      return true;
    }

    bool rlp_read_item(const uint8_t *data, size_t size, RlpItem *item)
    {
      if (data == nullptr || item == nullptr || size == 0)
        return false;
      const uint8_t prefix = data[0];
      if (prefix < kRlpShortString)
      {
        item->is_list = false;
        item->payload = data;
        item->payload_size = 1;
        item->total = 1;
        return true;
      }
      if (prefix <= 0xbf)
      {
        size_t header = 1;
        size_t length = 0;
        if (prefix <= 0xb7)
        {
          length = static_cast<size_t>(prefix - kRlpShortString);
          if (length == 1 && size > 1 && data[1] < kRlpShortString)
            return false;
        }
        else
        {
          const size_t length_bytes = static_cast<size_t>(prefix - 0xb7);
          if (length_bytes > sizeof(size_t) || size < 1 + length_bytes)
            return false;
          for (size_t index = 0; index < length_bytes; ++index)
          {
            length = (length << 8) | data[1 + index];
          }
          if (length <= 55 || data[1] == 0)
            return false;
          header = 1 + length_bytes;
        }
        if (length > size - header)
          return false;
        item->is_list = false;
        item->payload = data + header;
        item->payload_size = length;
        item->total = header + length;
        return true;
      }
      size_t header = 1;
      size_t length = 0;
      if (prefix <= 0xf7)
      {
        length = static_cast<size_t>(prefix - kRlpShortList);
      }
      else
      {
        const size_t length_bytes = static_cast<size_t>(prefix - 0xf7);
        if (length_bytes > sizeof(size_t) || size < 1 + length_bytes)
          return false;
        for (size_t index = 0; index < length_bytes; ++index)
        {
          length = (length << 8) | data[1 + index];
        }
        if (length <= 55 || data[1] == 0)
          return false;
        header = 1 + length_bytes;
      }
      if (length > size - header)
        return false;
      item->is_list = true;
      item->payload = data + header;
      item->payload_size = length;
      item->total = header + length;
      return true;
    }

    bool read_identifier(const RlpItem &item, uint8_t *tag, uint8_t *key)
    {
      if (item.is_list || item.payload_size != 1 + kAeternityPublicKeySize)
        return false;
      if (item.payload[0] < 1 || item.payload[0] > 6)
        return false;
      *tag = item.payload[0];
      memcpy(key, item.payload + 1, kAeternityPublicKeySize);
      return true;
    }

    bool encode_spend(const AeternitySpend &spend, uint8_t *out, size_t capacity,
                      size_t *out_size)
    {
      uint8_t body[kAeternityMaxPayload];
      size_t offset = 0;
      if (!rlp_append_string(body, sizeof(body), &offset, &kSpendTxTag, 1))
        return false;
      if (!rlp_append_string(body, sizeof(body), &offset, &kObjectVersion, 1))
        return false;
      uint8_t identifier[1 + kAeternityPublicKeySize];
      identifier[0] = kAeternityIdAccount;
      memcpy(identifier + 1, spend.sender, kAeternityPublicKeySize);
      if (!rlp_append_string(body, sizeof(body), &offset, identifier, sizeof(identifier)))
      {
        return false;
      }
      identifier[0] = spend.recipient_tag;
      memcpy(identifier + 1, spend.recipient, kAeternityPublicKeySize);
      if (!rlp_append_string(body, sizeof(body), &offset, identifier, sizeof(identifier)))
      {
        return false;
      }
      uint8_t number[8];
      const uint64_t values[] = {spend.amount, spend.fee, spend.ttl, spend.nonce};
      for (const uint64_t value : values)
      {
        const size_t size = minimal_u64(number, value);
        if (!rlp_append_string(body, sizeof(body), &offset, number, size))
          return false;
      }
      if (!rlp_append_string(body, sizeof(body), &offset, spend.payload,
                             spend.payload_size))
      {
        return false;
      }
      const size_t header = rlp_header_size(offset, true);
      if (header + offset > capacity)
        return false;
      *out_size = rlp_write_header(out, offset, true);
      memcpy(out + *out_size, body, offset);
      *out_size += offset;
      return true;
    }

    bool message_digest(const uint8_t *payload, size_t size, uint8_t out[32])
    {
      return blake2b_keyed_hash(nullptr, 0, payload, size, out, 32);
    }

    bool base64_encode(const uint8_t *data, size_t size, char *out, size_t out_size)
    {
      constexpr char kAlphabet[] =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      const size_t encoded = 4 * ((size + 2) / 3);
      if (out_size < encoded + 1)
        return false;
      size_t written = 0;
      for (size_t index = 0; index < size; index += 3)
      {
        const uint32_t chunk = (static_cast<uint32_t>(data[index]) << 16) |
                               (index + 1 < size ? static_cast<uint32_t>(data[index + 1]) << 8 : 0) |
                               (index + 2 < size ? static_cast<uint32_t>(data[index + 2]) : 0);
        out[written++] = kAlphabet[(chunk >> 18) & 0x3f];
        out[written++] = kAlphabet[(chunk >> 12) & 0x3f];
        out[written++] = index + 1 < size ? kAlphabet[(chunk >> 6) & 0x3f] : '=';
        out[written++] = index + 2 < size ? kAlphabet[chunk & 0x3f] : '=';
      }
      out[written] = '\0';
      return true;
    }

    bool encode_prefixed_base58check(const char *prefix, const uint8_t *payload,
                                     size_t size, char *out, size_t out_size)
    {
      const size_t prefix_size = strlen(prefix);
      uint8_t checked[1 + 32 + 4];
      if (size > sizeof(checked) - 4)
        return false;
      uint8_t digest[kSha256Size];
      memcpy(checked, payload, size);
      if (!crypto_double_sha256(payload, size, digest))
      {
        secure_zero(digest, sizeof(digest));
        return false;
      }
      memcpy(checked + size, digest, 4);
      secure_zero(digest, sizeof(digest));
      if (out_size <= prefix_size)
        return false;
      memcpy(out, prefix, prefix_size);
      size_t encoded = out_size - prefix_size;
      return b58enc(out + prefix_size, &encoded, checked, size + 4);
    }

  } // namespace

  bool aeternity_transaction_hash(const uint8_t *signed_tx, size_t size,
                                  uint8_t out[32])
  {
    if (signed_tx == nullptr || out == nullptr || size == 0)
      return false;
    return blake2b_keyed_hash(nullptr, 0, signed_tx, size, out, 32);
  }

  bool aeternity_encode_tx_text(const uint8_t *signed_tx, size_t size, char *out,
                                size_t out_size)
  {
    constexpr char kPrefix[] = "tx_";
    if (signed_tx == nullptr || out == nullptr || size == 0)
      return false;
    uint8_t checked[kAeternityMaxSignedSize + 4];
    if (size > sizeof(checked) - 4)
      return false;
    uint8_t digest[kSha256Size];
    memcpy(checked, signed_tx, size);
    if (!crypto_double_sha256(signed_tx, size, digest))
    {
      secure_zero(digest, sizeof(digest));
      return false;
    }
    memcpy(checked + size, digest, 4);
    secure_zero(digest, sizeof(digest));
    const size_t prefix = sizeof(kPrefix) - 1;
    if (out_size <= prefix)
      return false;
    memcpy(out, kPrefix, prefix);
    const bool ok = base64_encode(checked, size + 4, out + prefix, out_size - prefix);
    secure_zero(checked, sizeof(checked));
    return ok;
  }

  bool aeternity_encode_hash_text(const uint8_t hash[32], char *out,
                                  size_t out_size)
  {
    if (hash == nullptr)
      return false;
    return encode_prefixed_base58check("th_", hash, 32, out, out_size);
  }

  ChainError aeternity_review_payload(const uint8_t *payload, size_t size,
                                      const uint8_t sender_public_key[32],
                                      ChainReview *review, uint8_t digest[32])
  {
    if (payload == nullptr || sender_public_key == nullptr || review == nullptr ||
        digest == nullptr)
    {
      return ChainError::InvalidArgument;
    }
    if (size == 0 || size > kAeternityMaxPayload)
      return ChainError::InvalidArgument;

    RlpItem outer;
    if (!rlp_read_item(payload, size, &outer) || !outer.is_list ||
        outer.total != size)
    {
      return ChainError::Malformed;
    }

    AeternitySpend spend;
    memset(&spend, 0, sizeof(spend));
    const uint8_t *cursor = outer.payload;
    size_t remaining = outer.payload_size;

    RlpItem item;
    uint64_t tag_value = 0;
    if (!rlp_read_item(cursor, remaining, &item) || item.is_list ||
        !read_minimal_u64(item.payload, item.payload_size, &tag_value))
    {
      return ChainError::Malformed;
    }
    if (tag_value != kSpendTxTag)
      return ChainError::Unsupported;
    cursor += item.total;
    remaining -= item.total;

    if (!rlp_read_item(cursor, remaining, &item) || item.is_list)
    {
      return ChainError::Malformed;
    }
    uint64_t version = 0;
    if (!read_minimal_u64(item.payload, item.payload_size, &version))
    {
      return ChainError::Malformed;
    }
    if (version != kObjectVersion)
      return ChainError::Unsupported;
    cursor += item.total;
    remaining -= item.total;

    uint8_t tag_byte = 0;
    if (!rlp_read_item(cursor, remaining, &item) ||
        !read_identifier(item, &tag_byte, spend.sender))
    {
      return ChainError::Malformed;
    }
    if (tag_byte != kAeternityIdAccount)
      return ChainError::Unsupported;
    if (!chain_constant_time_equal(spend.sender, sender_public_key,
                                   kAeternityPublicKeySize))
    {
      return ChainError::WrongWallet;
    }
    cursor += item.total;
    remaining -= item.total;

    if (!rlp_read_item(cursor, remaining, &item) ||
        !read_identifier(item, &spend.recipient_tag, spend.recipient))
    {
      return ChainError::Malformed;
    }
    if (spend.recipient_tag != kAeternityIdAccount)
    {
      return ChainError::Unsupported;
    }
    cursor += item.total;
    remaining -= item.total;

    uint64_t *targets[] = {&spend.amount, &spend.fee, &spend.ttl, &spend.nonce};
    for (uint64_t *target : targets)
    {
      if (!rlp_read_item(cursor, remaining, &item) || item.is_list ||
          !read_minimal_u64(item.payload, item.payload_size, target))
      {
        return ChainError::Malformed;
      }
      cursor += item.total;
      remaining -= item.total;
    }

    if (!rlp_read_item(cursor, remaining, &item) || item.is_list)
    {
      return ChainError::Malformed;
    }
    if (item.payload_size > kAeternityMaxTxPayload)
      return ChainError::Unsupported;
    spend.payload_size = item.payload_size;
    if (item.payload_size != 0)
      memcpy(spend.payload, item.payload, item.payload_size);
    cursor += item.total;
    remaining -= item.total;
    if (remaining != 0)
      return ChainError::Malformed;

    uint8_t canonical[kAeternityMaxPayload];
    size_t canonical_size = 0;
    if (!encode_spend(spend, canonical, sizeof(canonical), &canonical_size) ||
        canonical_size != size ||
        !chain_constant_time_equal(canonical, payload, size))
    {
      secure_zero(canonical, sizeof(canonical));
      return ChainError::Malformed;
    }
    secure_zero(canonical, sizeof(canonical));

    uint8_t big_endian[8];
    size_t big_endian_size = minimal_u64(big_endian, spend.amount);
    if (!chain_format_units_bytes(big_endian, big_endian_size, kAeternityDecimals,
                                  "AE", review->amount, sizeof(review->amount)))
    {
      return ChainError::InvalidAmount;
    }
    big_endian_size = minimal_u64(big_endian, spend.fee);
    if (!chain_format_units_bytes(big_endian, big_endian_size, kAeternityDecimals,
                                  "AE", review->fee, sizeof(review->fee)))
    {
      return ChainError::FeePolicy;
    }

    if (!chain_copy_text(review->symbol, sizeof(review->symbol), "AE"))
    {
      return ChainError::Malformed;
    }
    if (address_aeternity(spend.sender, review->sender, sizeof(review->sender)) !=
            WalletError::Ok ||
        address_aeternity(spend.recipient, review->recipient,
                          sizeof(review->recipient)) != WalletError::Ok)
    {
      return ChainError::CryptoFailure;
    }
    snprintf(review->extra, sizeof(review->extra),
             "ttl=%llu nonce=%llu payload-bytes=%u",
             static_cast<unsigned long long>(spend.ttl),
             static_cast<unsigned long long>(spend.nonce),
             static_cast<unsigned>(spend.payload_size));

    uint8_t message[kNetworkIdSize + kAeternityMaxPayload];
    memcpy(message, kNetworkId, kNetworkIdSize);
    memcpy(message + kNetworkIdSize, payload, size);
    const bool hashed = message_digest(message, kNetworkIdSize + size, digest);
    secure_zero(message, sizeof(message));
    return hashed ? ChainError::Ok : ChainError::CryptoFailure;
  }

  ChainError aeternity_sign_payload(const uint8_t *payload, size_t size,
                                    const uint8_t private_seed[32], uint8_t *out,
                                    size_t *in_out_size)
  {
    if (payload == nullptr || private_seed == nullptr || out == nullptr ||
        in_out_size == nullptr)
    {
      return ChainError::InvalidArgument;
    }
    const size_t capacity = *in_out_size;
    *in_out_size = 0;
    if (size == 0 || size > kAeternityMaxPayload)
      return ChainError::InvalidArgument;
    constexpr size_t kWrapper = 2 + 2 + kAeternitySignatureSize + 2;
    const size_t signed_body = kWrapper + size;
    const size_t needed = signed_body + rlp_header_size(signed_body, true);
    if (capacity < needed)
      return ChainError::BufferTooSmall;

    uint8_t public_key[kAeternityPublicKeySize];
    if (!ed25519_public_key(private_seed, public_key))
      return ChainError::CryptoFailure;

    uint8_t message[kNetworkIdSize + kAeternityMaxPayload];
    memcpy(message, kNetworkId, kNetworkIdSize);
    memcpy(message + kNetworkIdSize, payload, size);
    uint8_t signature[kAeternitySignatureSize];
    const bool signed_ok =
        ed25519_sign(private_seed, message, kNetworkIdSize + size, signature);
    secure_zero(message, sizeof(message));
    if (!signed_ok)
    {
      secure_zero(public_key, sizeof(public_key));
      return ChainError::CryptoFailure;
    }

    uint8_t body[kAeternityMaxSignedSize];
    size_t offset = 0;
    bool ok = rlp_append_string(body, sizeof(body), &offset, &kSignedTxTag, 1) &&
              rlp_append_string(body, sizeof(body), &offset, &kObjectVersion, 1);
    if (ok)
    {
      uint8_t sig_item[kAeternitySignatureSize + 3];
      size_t sig_offset = 0;
      ok = rlp_append_string(sig_item, sizeof(sig_item), &sig_offset, signature,
                             sizeof(signature));
      if (ok)
      {
        const size_t list_header = rlp_header_size(sig_offset, true);
        uint8_t list[kAeternitySignatureSize + 6];
        if (list_header + sig_offset > sizeof(list))
        {
          ok = false;
        }
        else
        {
          size_t list_size = rlp_write_header(list, sig_offset, true);
          memcpy(list + list_size, sig_item, sig_offset);
          list_size += sig_offset;
          ok = rlp_append_raw(body, sizeof(body), &offset, list, list_size);
        }
        secure_zero(list, sizeof(list));
      }
      secure_zero(sig_item, sizeof(sig_item));
    }
    if (ok)
    {
      ok = rlp_append_string(body, sizeof(body), &offset, payload, size);
    }
    if (ok)
    {
      const size_t header = rlp_header_size(offset, true);
      if (header + offset > capacity)
      {
        ok = false;
      }
      else
      {
        *in_out_size = rlp_write_header(out, offset, true);
        memcpy(out + *in_out_size, body, offset);
        *in_out_size += offset;
      }
    }
    secure_zero(body, sizeof(body));
    secure_zero(signature, sizeof(signature));
    secure_zero(public_key, sizeof(public_key));
    return ok ? ChainError::Ok : ChainError::BufferTooSmall;
  }

  bool run_aeternity_self_tests()
  {
    static const uint8_t kSender[kAeternityPublicKeySize] = {
        0x7b,
        0xa5,
        0x80,
        0x93,
        0x83,
        0xf6,
        0x64,
        0x75,
        0x0f,
        0x61,
        0x82,
        0x22,
        0xa8,
        0x4e,
        0x58,
        0x2a,
        0x41,
        0xfe,
        0x60,
        0xcf,
        0xf3,
        0x18,
        0xb2,
        0xd9,
        0x89,
        0x08,
        0x33,
        0x24,
        0xc1,
        0xc5,
        0x73,
        0xd6,
    };
    static const uint8_t kSignature[kAeternitySignatureSize] = {
        0x85,
        0xad,
        0x1d,
        0xb2,
        0x26,
        0xc7,
        0x9c,
        0x4a,
        0x19,
        0x70,
        0x1c,
        0xda,
        0x29,
        0xfa,
        0xcb,
        0x06,
        0xb8,
        0x1d,
        0x2f,
        0xb5,
        0xcc,
        0x4e,
        0x85,
        0x4b,
        0x3e,
        0xbd,
        0x97,
        0x8c,
        0x9f,
        0x55,
        0x45,
        0x0a,
        0x84,
        0x35,
        0xf9,
        0xef,
        0xc1,
        0x18,
        0xf2,
        0x60,
        0x66,
        0x31,
        0xc0,
        0x2e,
        0x3a,
        0x5f,
        0xdd,
        0xe5,
        0xc4,
        0xee,
        0x95,
        0xe2,
        0x46,
        0x90,
        0x0e,
        0x2b,
        0x1f,
        0x56,
        0xb0,
        0x60,
        0x88,
        0x6b,
        0x8d,
        0x06,
    };
    static const uint8_t kInner[] = {
        0xf8,
        0xd8,
        0x0c,
        0x01,
        0xa1,
        0x01,
        0x7b,
        0xa5,
        0x80,
        0x93,
        0x83,
        0xf6,
        0x64,
        0x75,
        0x0f,
        0x61,
        0x82,
        0x22,
        0xa8,
        0x4e,
        0x58,
        0x2a,
        0x41,
        0xfe,
        0x60,
        0xcf,
        0xf3,
        0x18,
        0xb2,
        0xd9,
        0x89,
        0x08,
        0x33,
        0x24,
        0xc1,
        0xc5,
        0x73,
        0xd6,
        0xa1,
        0x01,
        0x7b,
        0xa5,
        0x80,
        0x93,
        0x83,
        0xf6,
        0x64,
        0x75,
        0x0f,
        0x61,
        0x82,
        0x22,
        0xa8,
        0x4e,
        0x58,
        0x2a,
        0x41,
        0xfe,
        0x60,
        0xcf,
        0xf3,
        0x18,
        0xb2,
        0xd9,
        0x89,
        0x08,
        0x33,
        0x24,
        0xc1,
        0xc5,
        0x73,
        0xd6,
        0x82,
        0x4e,
        0x20,
        0x86,
        0x11,
        0x9b,
        0x99,
        0xec,
        0x40,
        0x00,
        0x83,
        0x15,
        0x06,
        0x11,
        0x84,
        0x01,
        0x3d,
        0x2e,
        0x0e,
        0xb8,
        0x7d,
        0x31,
        0x33,
        0x37,
        0x37,
        0x37,
        0x39,
        0x39,
        0x3a,
        0x6b,
        0x68,
        0x5f,
        0x32,
        0x55,
        0x75,
        0x78,
        0x6b,
        0x68,
        0x72,
        0x68,
        0x59,
        0x32,
        0x68,
        0x70,
        0x48,
        0x76,
        0x69,
        0x64,
        0x44,
        0x69,
        0x66,
        0x66,
        0x43,
        0x4a,
        0x69,
        0x66,
        0x4e,
        0x77,
        0x74,
        0x67,
        0x74,
        0x73,
        0x48,
        0x54,
        0x70,
        0x4b,
        0x63,
        0x68,
        0x51,
        0x56,
        0x32,
        0x42,
        0x39,
        0x67,
        0x57,
        0x61,
        0x35,
        0x50,
        0x61,
        0x35,
        0x44,
        0x53,
        0x3a,
        0x6d,
        0x68,
        0x5f,
        0x33,
        0x50,
        0x7a,
        0x43,
        0x41,
        0x53,
        0x74,
        0x34,
        0x57,
        0x52,
        0x47,
        0x38,
        0x39,
        0x46,
        0x62,
        0x4b,
        0x71,
        0x75,
        0x58,
        0x64,
        0x76,
        0x4a,
        0x57,
        0x54,
        0x77,
        0x6e,
        0x43,
        0x63,
        0x31,
        0x4e,
        0x59,
        0x46,
        0x48,
        0x33,
        0x4b,
        0x69,
        0x73,
        0x33,
        0x78,
        0x4e,
        0x6b,
        0x77,
        0x42,
        0x44,
        0x6f,
        0x62,
        0x74,
        0x6f,
        0x42,
        0x3a,
        0x31,
        0x37,
        0x39,
        0x33,
        0x39,
        0x33,
        0x36,
        0x39,
        0x34,
        0x32,
    };
    static const uint8_t kSigned[] = {
        0xf9,
        0x01,
        0x22,
        0x0b,
        0x01,
        0xf8,
        0x42,
        0xb8,
        0x40,
        0x85,
        0xad,
        0x1d,
        0xb2,
        0x26,
        0xc7,
        0x9c,
        0x4a,
        0x19,
        0x70,
        0x1c,
        0xda,
        0x29,
        0xfa,
        0xcb,
        0x06,
        0xb8,
        0x1d,
        0x2f,
        0xb5,
        0xcc,
        0x4e,
        0x85,
        0x4b,
        0x3e,
        0xbd,
        0x97,
        0x8c,
        0x9f,
        0x55,
        0x45,
        0x0a,
        0x84,
        0x35,
        0xf9,
        0xef,
        0xc1,
        0x18,
        0xf2,
        0x60,
        0x66,
        0x31,
        0xc0,
        0x2e,
        0x3a,
        0x5f,
        0xdd,
        0xe5,
        0xc4,
        0xee,
        0x95,
        0xe2,
        0x46,
        0x90,
        0x0e,
        0x2b,
        0x1f,
        0x56,
        0xb0,
        0x60,
        0x88,
        0x6b,
        0x8d,
        0x06,
        0xb8,
        0xda,
        0xf8,
        0xd8,
        0x0c,
        0x01,
        0xa1,
        0x01,
        0x7b,
        0xa5,
        0x80,
        0x93,
        0x83,
        0xf6,
        0x64,
        0x75,
        0x0f,
        0x61,
        0x82,
        0x22,
        0xa8,
        0x4e,
        0x58,
        0x2a,
        0x41,
        0xfe,
        0x60,
        0xcf,
        0xf3,
        0x18,
        0xb2,
        0xd9,
        0x89,
        0x08,
        0x33,
        0x24,
        0xc1,
        0xc5,
        0x73,
        0xd6,
        0xa1,
        0x01,
        0x7b,
        0xa5,
        0x80,
        0x93,
        0x83,
        0xf6,
        0x64,
        0x75,
        0x0f,
        0x61,
        0x82,
        0x22,
        0xa8,
        0x4e,
        0x58,
        0x2a,
        0x41,
        0xfe,
        0x60,
        0xcf,
        0xf3,
        0x18,
        0xb2,
        0xd9,
        0x89,
        0x08,
        0x33,
        0x24,
        0xc1,
        0xc5,
        0x73,
        0xd6,
        0x82,
        0x4e,
        0x20,
        0x86,
        0x11,
        0x9b,
        0x99,
        0xec,
        0x40,
        0x00,
        0x83,
        0x15,
        0x06,
        0x11,
        0x84,
        0x01,
        0x3d,
        0x2e,
        0x0e,
        0xb8,
        0x7d,
        0x31,
        0x33,
        0x37,
        0x37,
        0x37,
        0x39,
        0x39,
        0x3a,
        0x6b,
        0x68,
        0x5f,
        0x32,
        0x55,
        0x75,
        0x78,
        0x6b,
        0x68,
        0x72,
        0x68,
        0x59,
        0x32,
        0x68,
        0x70,
        0x48,
        0x76,
        0x69,
        0x64,
        0x44,
        0x69,
        0x66,
        0x66,
        0x43,
        0x4a,
        0x69,
        0x66,
        0x4e,
        0x77,
        0x74,
        0x67,
        0x74,
        0x73,
        0x48,
        0x54,
        0x70,
        0x4b,
        0x63,
        0x68,
        0x51,
        0x56,
        0x32,
        0x42,
        0x39,
        0x67,
        0x57,
        0x61,
        0x35,
        0x50,
        0x61,
        0x35,
        0x44,
        0x53,
        0x3a,
        0x6d,
        0x68,
        0x5f,
        0x33,
        0x50,
        0x7a,
        0x43,
        0x41,
        0x53,
        0x74,
        0x34,
        0x57,
        0x52,
        0x47,
        0x38,
        0x39,
        0x46,
        0x62,
        0x4b,
        0x71,
        0x75,
        0x58,
        0x64,
        0x76,
        0x4a,
        0x57,
        0x54,
        0x77,
        0x6e,
        0x43,
        0x63,
        0x31,
        0x4e,
        0x59,
        0x46,
        0x48,
        0x33,
        0x4b,
        0x69,
        0x73,
        0x33,
        0x78,
        0x4e,
        0x6b,
        0x77,
        0x42,
        0x44,
        0x6f,
        0x62,
        0x74,
        0x6f,
        0x42,
        0x3a,
        0x31,
        0x37,
        0x39,
        0x33,
        0x39,
        0x33,
        0x36,
        0x39,
        0x34,
        0x32,
    };
    static const uint8_t kHash[32] = {
        0x5d,
        0x09,
        0xa7,
        0x9d,
        0xee,
        0xe8,
        0x1f,
        0xfb,
        0xde,
        0xff,
        0xe6,
        0xc9,
        0x28,
        0xfa,
        0x54,
        0x33,
        0xe6,
        0x41,
        0x1e,
        0x9d,
        0xd3,
        0x5d,
        0xd2,
        0xfd,
        0xd4,
        0x60,
        0xc4,
        0xa7,
        0x64,
        0x56,
        0x3b,
        0x6c,
    };
    static const char kExpectedAddress[] =
        "ak_wTPFpksUJFjjntonTvwK4LJvDw11DPma7kZBneKbumb8yPeFq";
    static const char kExpectedHashText[] =
        "th_hyXNAEdi3bhJvs54qzY5ftBNcgfqQJ6VC8VcjfUCw5RcdD9HW";
    static const char kExpectedTxText[] =
        "tx_+QEiCwH4QrhAha0dsibHnEoZcBzaKfrLBrgdL7XMToVLPr2XjJ9VRQqENfnvwRjyYGYxwC46"
        "X93lxO6V4kaQDisfVrBgiGuNBrja+NgMAaEBe6WAk4P2ZHUPYYIiqE5YKkH+YM/zGLLZiQgzJMHF"
        "c9ahAXulgJOD9mR1D2GCIqhOWCpB/mDP8xiy2YkIMyTBxXPWgk4ghhGbmexAAIMVBhGEAT0uDrh9M"
        "TM3Nzc5OTpraF8yVXV4a2hyaFkyaHBIdmlkRGlmZkNKaWZOd3RndHNIVHBLY2hRVjJCOWdXYTVQYT"
        "VEUzptaF8zUHpDQVN0NFdSRzg5RmJLcXVYZHZKV1R3bkNjMU5ZRkgzS2lzM3hOa3dCRG9idG9COj"
        "E3OTM5MzY5NDKPWsjL";

    bool passed = true;
    ChainReview review;
    memset(&review, 0, sizeof(review));
    uint8_t digest[32];
    passed = passed &&
             aeternity_review_payload(kInner, sizeof(kInner), kSender, &review,
                                      digest) == ChainError::Ok;
    passed = passed && strcmp(review.symbol, "AE") == 0;
    passed = passed && strcmp(review.sender, kExpectedAddress) == 0;
    passed = passed && strcmp(review.recipient, kExpectedAddress) == 0;
    passed = passed && strncmp(review.amount, "0.00000000000002", 16) == 0;

    uint8_t message[kNetworkIdSize + sizeof(kInner)];
    memcpy(message, kNetworkId, kNetworkIdSize);
    memcpy(message + kNetworkIdSize, kInner, sizeof(kInner));
    uint8_t expected_digest[32];
    passed = passed && message_digest(message, sizeof(message), expected_digest);
    passed = passed && memcmp(digest, expected_digest, 32) == 0;
    passed = passed && ed25519_verify(kSender, message, sizeof(message), kSignature);

    uint8_t rebuilt[kAeternityMaxSignedSize];
    size_t rebuilt_size = 0;
    {
      uint8_t body[kAeternityMaxSignedSize];
      size_t offset = 0;
      const uint8_t tag = kSignedTxTag;
      const uint8_t version = kObjectVersion;
      bool ok = rlp_append_string(body, sizeof(body), &offset, &tag, 1) &&
                rlp_append_string(body, sizeof(body), &offset, &version, 1);
      if (ok)
      {
        uint8_t sig_item[kAeternitySignatureSize + 3];
        size_t sig_offset = 0;
        ok = rlp_append_string(sig_item, sizeof(sig_item), &sig_offset, kSignature,
                               sizeof(kSignature));
        if (ok)
        {
          uint8_t list[kAeternitySignatureSize + 6];
          size_t list_size = rlp_write_header(list, sig_offset, true);
          memcpy(list + list_size, sig_item, sig_offset);
          list_size += sig_offset;
          ok = rlp_append_raw(body, sizeof(body), &offset, list, list_size);
          secure_zero(list, sizeof(list));
        }
        secure_zero(sig_item, sizeof(sig_item));
      }
      if (ok)
      {
        ok = rlp_append_string(body, sizeof(body), &offset, kInner, sizeof(kInner));
      }
      if (ok)
      {
        rebuilt_size = rlp_write_header(rebuilt, offset, true);
        memcpy(rebuilt + rebuilt_size, body, offset);
        rebuilt_size += offset;
      }
      secure_zero(body, sizeof(body));
      passed = passed && ok && rebuilt_size == sizeof(kSigned) &&
               memcmp(rebuilt, kSigned, sizeof(kSigned)) == 0;
    }

    uint8_t hash[32];
    passed = passed && aeternity_transaction_hash(rebuilt, rebuilt_size, hash);
    passed = passed && memcmp(hash, kHash, sizeof(kHash)) == 0;

    char text[4 * ((kAeternityMaxSignedSize + 4 + 2) / 3) + 8];
    passed = passed && aeternity_encode_hash_text(hash, text, sizeof(text)) &&
             strcmp(text, kExpectedHashText) == 0;
    passed = passed && aeternity_encode_tx_text(rebuilt, rebuilt_size, text, sizeof(text)) &&
             strcmp(text, kExpectedTxText) == 0;

    uint8_t seed[32];
    for (size_t index = 0; index < sizeof(seed); ++index)
    {
      seed[index] = static_cast<uint8_t>(index);
    }
    uint8_t public_key[32];
    passed = passed && ed25519_public_key(seed, public_key);
    ChainReview own_review;
    memset(&own_review, 0, sizeof(own_review));
    uint8_t own_digest[32];
    passed = passed && aeternity_review_payload(kInner, sizeof(kInner), public_key,
                                                &own_review, own_digest) ==
                           ChainError::WrongWallet;

    // A canonical payload for our own key has to round trip through sign.
    uint8_t own_payload[kAeternityMaxPayload];
    size_t own_size = 0;
    {
      AeternitySpend spend;
      memset(&spend, 0, sizeof(spend));
      memcpy(spend.sender, public_key, kAeternityPublicKeySize);
      memcpy(spend.recipient, kSender, kAeternityPublicKeySize);
      spend.recipient_tag = kAeternityIdAccount;
      spend.amount = 123456789;
      spend.fee = 16700000000000ULL;
      spend.ttl = 100;
      spend.nonce = 7;
      spend.payload_size = 3;
      spend.payload[0] = 'h';
      spend.payload[1] = 'i';
      spend.payload[2] = '!';
      passed = passed && encode_spend(spend, own_payload, sizeof(own_payload), &own_size);
    }
    passed = passed && aeternity_review_payload(own_payload, own_size, public_key,
                                                &own_review, own_digest) ==
                           ChainError::Ok;
    uint8_t signed_own[kAeternityMaxSignedSize];
    size_t signed_own_size = sizeof(signed_own);
    passed = passed && aeternity_sign_payload(own_payload, own_size, seed, signed_own,
                                              &signed_own_size) == ChainError::Ok;
    if (signed_own_size > sizeof(signed_own))
    {
      passed = false;
    }
    else
    {
      RlpItem outer;
      passed = passed && rlp_read_item(signed_own, signed_own_size, &outer) &&
               outer.is_list && outer.total == signed_own_size;
      passed = passed && outer.payload_size > 0 && outer.payload[0] == kSignedTxTag;
    }

    ChainReview tampered_review;
    uint8_t tampered_digest[32];
    passed = passed &&
             aeternity_review_payload(own_payload, own_size - 1, public_key,
                                      &tampered_review, tampered_digest) !=
                 ChainError::Ok;

    uint8_t foreign[sizeof(own_payload)];
    memcpy(foreign, own_payload, own_size);
    foreign[6] ^= 0x01; // first byte of the sender key (header is 3 bytes)
    passed = passed && aeternity_review_payload(foreign, own_size, public_key,
                                                &tampered_review,
                                                tampered_digest) ==
                           ChainError::WrongWallet;

    uint8_t non_canonical[2 + 34 + 34 + 4 + 1];
    size_t non_canonical_size = 0;
    {
      uint8_t body[sizeof(non_canonical)];
      size_t offset = 0;
      const uint8_t tag = kSpendTxTag;
      const uint8_t version = kObjectVersion;
      uint8_t identifier[1 + kAeternityPublicKeySize];
      identifier[0] = kAeternityIdAccount;
      memcpy(identifier + 1, public_key, kAeternityPublicKeySize);
      const uint8_t zero = 0x00;
      const uint8_t empty = 0x80;
      bool ok = rlp_append_string(body, sizeof(body), &offset, &tag, 1) &&
                rlp_append_string(body, sizeof(body), &offset, &version, 1) &&
                rlp_append_string(body, sizeof(body), &offset, identifier,
                                  sizeof(identifier)) &&
                rlp_append_string(body, sizeof(body), &offset, identifier,
                                  sizeof(identifier));
      for (int field = 0; ok && field < 4; ++field)
      {
        ok = rlp_append_string(body, sizeof(body), &offset, &zero, 1);
      }
      ok = ok && rlp_append_string(body, sizeof(body), &offset, &empty, 0);
      if (ok)
      {
        non_canonical_size = rlp_write_header(non_canonical, offset, true);
        memcpy(non_canonical + non_canonical_size, body, offset);
        non_canonical_size += offset;
      }
      secure_zero(body, sizeof(body));
    }
    passed = passed &&
             aeternity_review_payload(non_canonical, non_canonical_size, public_key,
                                      &tampered_review, tampered_digest) ==
                 ChainError::Malformed;

    secure_zero(seed, sizeof(seed));
    secure_zero(message, sizeof(message));
    secure_zero(rebuilt, sizeof(rebuilt));
    secure_zero(signed_own, sizeof(signed_own));
    return passed;
  }

}
