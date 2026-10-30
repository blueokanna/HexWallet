#include "WalletAltAddresses.h"

#include <stdio.h>
#include <string.h>

#include "base58.h"
#include "Blake256.h"
#include "CardanoDerivation.h"
#include "Blake2b.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "local_bech32.h"
#include "local_ripemd160.h"
#include "TonCell.h"
#include "WalletAddresses.h"
#include "WalletEngine.h"

namespace hexwallet
{
  namespace
  {

    static bool selftest_report(const char *name, bool ok)
    {
      if (!ok)
        ::printf("FAIL: %s\n", name);
      return ok;
    }

    constexpr size_t kAltMaxPayloadSize = 64;

    // base58check with a double-SHA256 checksum (Bitcoin family).
    bool base58check_sha256(const uint8_t *payload, size_t payload_size,
                            char *out, size_t *in_out_size)
    {
      if (payload == nullptr || out == nullptr || in_out_size == nullptr || payload_size > kAltMaxPayloadSize)
      {
        return false;
      }
      uint8_t checksum[kSha256Size];
      if (!crypto_double_sha256(payload, payload_size, checksum))
        return false;
      uint8_t encoded[kAltMaxPayloadSize + 4];
      memcpy(encoded, payload, payload_size);
      memcpy(encoded + payload_size, checksum, 4);
      const bool ok = b58enc(out, in_out_size, encoded, payload_size + 4);
      secure_zero(checksum, sizeof(checksum));
      secure_zero(encoded, sizeof(encoded));
      return ok;
    }

    // base58check with a double BLAKE-256 checksum (Decred).
    bool base58check_blake256(const uint8_t *payload, size_t payload_size,
                              char *out, size_t *in_out_size)
    {
      if (payload == nullptr || out == nullptr || in_out_size == nullptr || payload_size > kAltMaxPayloadSize)
      {
        return false;
      }
      uint8_t first[32];
      uint8_t second[32];
      if (!blake256_hash(payload, payload_size, first) ||
          !blake256_hash(first, sizeof(first), second))
      {
        return false;
      }
      uint8_t encoded[kAltMaxPayloadSize + 4];
      memcpy(encoded, payload, payload_size);
      memcpy(encoded + payload_size, second, 4);
      const bool ok = b58enc(out, in_out_size, encoded, payload_size + 4);
      secure_zero(first, sizeof(first));
      secure_zero(second, sizeof(second));
      secure_zero(encoded, sizeof(encoded));
      return ok;
    }

    // base58check with a blake2b-256 checksum (Ergo).
    bool base58check_blake2b(const uint8_t *payload, size_t payload_size,
                             char *out, size_t *in_out_size)
    {
      if (payload == nullptr || out == nullptr || in_out_size == nullptr || payload_size > kAltMaxPayloadSize)
      {
        return false;
      }
      uint8_t checksum[32];
      if (!crypto_blake2b(payload, payload_size, checksum, sizeof(checksum)))
      {
        return false;
      }
      uint8_t encoded[kAltMaxPayloadSize + 4];
      memcpy(encoded, payload, payload_size);
      memcpy(encoded + payload_size, checksum, 4);
      const bool ok = b58enc(out, in_out_size, encoded, payload_size + 4);
      secure_zero(checksum, sizeof(checksum));
      secure_zero(encoded, sizeof(encoded));
      return ok;
    }

    bool hash160_of(const uint8_t *data, size_t size, uint8_t out[kRipemd160Size])
    {
      return crypto_hash160(data, size, out);
    }

  } // namespace

  WalletError address_zcash_transparent(uint16_t p2pkh_version,
                                        uint16_t p2sh_version,
                                        const uint8_t public_key[kCompressedPublicKeySize],
                                        char *out, size_t *in_out_size)
  {
    if (public_key == nullptr || p2pkh_version == 0 || p2sh_version == 0)
    {
      return WalletError::InvalidArgument;
    }
    uint8_t hash[kRipemd160Size];
    if (!hash160_of(public_key, kCompressedPublicKeySize, hash))
    {
      return WalletError::CryptoFailure;
    }
    uint8_t payload[2 + kRipemd160Size];
    payload[0] = static_cast<uint8_t>(p2pkh_version >> 8);
    payload[1] = static_cast<uint8_t>(p2pkh_version & 0xff);
    memcpy(payload + 2, hash, kRipemd160Size);
    const bool ok = base58check_sha256(payload, sizeof(payload), out, in_out_size);
    secure_zero(payload, sizeof(payload));
    secure_zero(hash, sizeof(hash));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_zcash_transparent_from_script(uint16_t p2pkh_version,
                                                    uint16_t p2sh_version,
                                                    const uint8_t *script,
                                                    size_t script_size,
                                                    char *out, size_t out_size)
  {
    if (script == nullptr || out == nullptr || out_size == 0 ||
        p2pkh_version == 0 || p2sh_version == 0)
    {
      return WalletError::InvalidArgument;
    }
    const uint8_t *hash;
    uint16_t version;
    if (script_size == 25 && script[0] == 0x76 && script[1] == 0xa9 &&
        script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac)
    {
      version = p2pkh_version;
      hash = script + 3;
    }
    else if (script_size == 23 && script[0] == 0xa9 && script[1] == 0x14 &&
             script[22] == 0x87)
    {
      version = p2sh_version;
      hash = script + 2;
    }
    else
    {
      return WalletError::InvalidArgument;
    }
    uint8_t payload[2 + kRipemd160Size];
    payload[0] = static_cast<uint8_t>(version >> 8);
    payload[1] = static_cast<uint8_t>(version & 0xff);
    memcpy(payload + 2, hash, kRipemd160Size);
    size_t encoded_size = out_size;
    const bool ok = base58check_sha256(payload, sizeof(payload), out, &encoded_size);
    secure_zero(payload, sizeof(payload));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_cashaddr(const char *prefix,
                               const uint8_t public_key[kCompressedPublicKeySize],
                               char *out, size_t out_size)
  {
    if (prefix == nullptr || public_key == nullptr)
      return WalletError::InvalidArgument;
    uint8_t hash[kRipemd160Size];
    if (!hash160_of(public_key, kCompressedPublicKeySize, hash))
    {
      return WalletError::CryptoFailure;
    }
    const bool ok = cashaddr_encode(prefix, 0, hash, sizeof(hash), out, out_size);
    secure_zero(hash, sizeof(hash));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_cashaddr_from_script(const char *prefix, const uint8_t *script,
                                           size_t script_size, char *out,
                                           size_t out_size)
  {
    if (prefix == nullptr || script == nullptr || out == nullptr)
    {
      return WalletError::InvalidArgument;
    }
    uint8_t type_bits;
    const uint8_t *hash;
    if (script_size == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
        script[23] == 0x88 && script[24] == 0xac)
    {
      type_bits = 0;
      hash = script + 3;
    }
    else if (script_size == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87)
    {
      type_bits = 8;
      hash = script + 2;
    }
    else
    {
      return WalletError::InvalidArgument;
    }
    return cashaddr_encode(prefix, type_bits, hash, kRipemd160Size, out, out_size)
               ? WalletError::Ok
               : WalletError::BufferTooSmall;
  }

  WalletError address_solana(const uint8_t public_key[32], char *out,
                             size_t *in_out_size)
  {
    if (public_key == nullptr || out == nullptr || in_out_size == nullptr)
    {
      return WalletError::InvalidArgument;
    }
    const bool ok = b58enc(out, in_out_size, public_key, 32);
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_aeternity(const uint8_t public_key[32], char *out,
                                size_t out_size)
  {
    constexpr size_t kChecksumSize = 4;
    constexpr char kPrefix[] = "ak_";
    constexpr size_t kPrefixSize = sizeof(kPrefix) - 1;
    if (public_key == nullptr || out == nullptr)
    {
      return WalletError::InvalidArgument;
    }
    if (out_size <= kPrefixSize + 1)
    {
      return WalletError::BufferTooSmall;
    }
    uint8_t payload[32 + kChecksumSize];
    uint8_t digest[kSha256Size];
    if (!crypto_double_sha256(public_key, 32, digest))
    {
      secure_zero(digest, sizeof(digest));
      return WalletError::CryptoFailure;
    }
    memcpy(payload, public_key, 32);
    memcpy(payload + 32, digest, kChecksumSize);
    memcpy(out, kPrefix, kPrefixSize);
    size_t encoded_size = out_size - kPrefixSize;
    const bool ok = b58enc(out + kPrefixSize, &encoded_size, payload,
                           sizeof(payload));
    secure_zero(payload, sizeof(payload));
    secure_zero(digest, sizeof(digest));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_algorand(const uint8_t public_key[32], char *out,
                               size_t out_size)
  {
    if (public_key == nullptr || out == nullptr)
      return WalletError::InvalidArgument;
    uint8_t checksum[32];
    uint8_t payload[32 + 4];
    if (!crypto_sha512_256(public_key, 32, checksum))
    {
      return WalletError::CryptoFailure;
    }
    memcpy(payload, public_key, 32);
    memcpy(payload + 32, checksum + 28, 4); // last 4 bytes
    const bool ok = base32_encode(payload, sizeof(payload), out, out_size, false, false);
    secure_zero(checksum, sizeof(checksum));
    secure_zero(payload, sizeof(payload));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_tezos_tz1(const uint8_t public_key[32], char *out,
                                size_t *in_out_size)
  {
    if (public_key == nullptr || out == nullptr || in_out_size == nullptr)
    {
      return WalletError::InvalidArgument;
    }
    uint8_t hash[20];
    if (!crypto_blake2b(public_key, 32, hash, sizeof(hash)))
    {
      return WalletError::CryptoFailure;
    }
    uint8_t payload[3 + 20];
    payload[0] = 0x06;
    payload[1] = 0xa1;
    payload[2] = 0x9f;
    memcpy(payload + 3, hash, 20);
    const bool ok = base58check_sha256(payload, sizeof(payload), out, in_out_size);
    secure_zero(payload, sizeof(payload));
    secure_zero(hash, sizeof(hash));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_ripple(const uint8_t public_key[kCompressedPublicKeySize],
                             char *out, size_t *in_out_size)
  {
    if (public_key == nullptr || out == nullptr || in_out_size == nullptr)
    {
      return WalletError::InvalidArgument;
    }
    uint8_t hash[kRipemd160Size] = {};
    uint8_t payload[1 + kRipemd160Size + 4] = {};
    uint8_t checksum[kSha256Size] = {};
    if (!crypto_hash160(public_key, kCompressedPublicKeySize, hash))
    {
      return WalletError::CryptoFailure;
    }
    memcpy(payload + 1, hash, sizeof(hash));
    if (!crypto_double_sha256(payload, 1 + kRipemd160Size, checksum))
    {
      secure_zero(hash, sizeof(hash));
      secure_zero(payload, sizeof(payload));
      return WalletError::CryptoFailure;
    }
    memcpy(payload + 1 + kRipemd160Size, checksum, 4);
    const bool ok = ripple_b58enc(out, in_out_size, payload, sizeof(payload));
    secure_zero(hash, sizeof(hash));
    secure_zero(payload, sizeof(payload));
    secure_zero(checksum, sizeof(checksum));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_cardano_raw(const uint8_t *bytes, size_t size, char *out,
                                  size_t out_size)
  {
    if (bytes == nullptr || out == nullptr || size == 0 || size > 64)
      return WalletError::InvalidArgument;
    uint8_t five_bit[104];
    size_t five_size = 0;
    uint32_t accumulator = 0;
    uint8_t bits = 0;
    for (size_t i = 0; i < size; ++i)
    {
      accumulator = (accumulator << 8) | bytes[i];
      bits += 8;
      while (bits >= 5)
      {
        bits -= 5;
        five_bit[five_size++] = static_cast<uint8_t>((accumulator >> bits) & 0x1f);
      }
    }
    if (bits != 0)
      five_bit[five_size++] = static_cast<uint8_t>((accumulator << (5 - bits)) & 0x1f);
    const std::string encoded =
        bech32::encode("addr", std::vector<uint8_t>(five_bit, five_bit + five_size),
                       bech32::Encoding::BECH32);
    if (encoded.empty() || encoded.size() >= out_size)
      return WalletError::BufferTooSmall;
    memcpy(out, encoded.c_str(), encoded.size() + 1);
    return WalletError::Ok;
  }

  WalletError address_cardano_base(const uint8_t payment_key[32],
                                   const uint8_t stake_key[32], char *out,
                                   size_t out_size)
  {
    if (payment_key == nullptr || stake_key == nullptr || out == nullptr)
    {
      return WalletError::InvalidArgument;
    }
    uint8_t payment_hash[28];
    uint8_t stake_hash[28];
    if (!crypto_blake2b(payment_key, 32, payment_hash, sizeof(payment_hash)) || !crypto_blake2b(stake_key, 32, stake_hash, sizeof(stake_hash)))
    {
      secure_zero(payment_hash, sizeof(payment_hash));
      secure_zero(stake_hash, sizeof(stake_hash));
      return WalletError::CryptoFailure;
    }
    uint8_t payload[1 + 28 + 28];
    payload[0] = 0x01; // mainnet base: payment key hash + stake key hash
    memcpy(payload + 1, payment_hash, 28);
    memcpy(payload + 1 + 28, stake_hash, 28);
    const bool ok = bech32_encode("addr", payload, sizeof(payload), out, out_size, false);
    secure_zero(payload, sizeof(payload));
    secure_zero(payment_hash, sizeof(payment_hash));
    secure_zero(stake_hash, sizeof(stake_hash));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_cosmos_bech32(const char *hrp,
                                    const uint8_t public_key[kCompressedPublicKeySize],
                                    char *out, size_t out_size)
  {
    if (hrp == nullptr || public_key == nullptr || out == nullptr)
    {
      return WalletError::InvalidArgument;
    }
    uint8_t hash[kRipemd160Size];
    if (!hash160_of(public_key, kCompressedPublicKeySize, hash))
    {
      return WalletError::CryptoFailure;
    }
    const bool ok = bech32_encode(hrp, hash, sizeof(hash), out, out_size, false);
    secure_zero(hash, sizeof(hash));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_avalanche_xp(const char *hrp,
                                   const uint8_t public_key[kCompressedPublicKeySize],
                                   char *out, size_t out_size)
  {
    if (hrp == nullptr || public_key == nullptr || out == nullptr)
    {
      return WalletError::InvalidArgument;
    }
    uint8_t hash[kRipemd160Size];
    if (!hash160_of(public_key, kCompressedPublicKeySize, hash))
    {
      return WalletError::CryptoFailure;
    }
    uint8_t payload[1 + kRipemd160Size];
    payload[0] = 0x00; // shortID version byte
    memcpy(payload + 1, hash, kRipemd160Size);
    if (out_size < 2 + 1)
    {
      secure_zero(payload, sizeof(payload));
      return WalletError::BufferTooSmall;
    }
    out[0] = 'X';
    out[1] = '-';
    const bool ok = bech32_encode(hrp, payload, sizeof(payload), out + 2, out_size - 2, false);
    secure_zero(payload, sizeof(payload));
    secure_zero(hash, sizeof(hash));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_kaspa(const uint8_t public_key[kCompressedPublicKeySize],
                            char *out, size_t out_size)
  {
    if (public_key == nullptr || out == nullptr)
      return WalletError::InvalidArgument;
    // x-only: drop the SEC1 prefix byte.
    const bool ok = kaspa_bech32_encode("kaspa", 0, public_key + 1, 32, out, out_size);
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_filecoin(const uint8_t public_key[kUncompressedPublicKeySize],
                               char *out, size_t out_size)
  {
    if (public_key == nullptr || out == nullptr || public_key[0] != 0x04)
      return WalletError::InvalidArgument;
    if (out_size < 42) return WalletError::BufferTooSmall;
    uint8_t hash[20];
    if (!crypto_blake2b(public_key, kUncompressedPublicKeySize, hash, sizeof(hash)))
    {
      return WalletError::CryptoFailure;
    }
    uint8_t payload[1 + 20];
    payload[0] = 0x01; // f1 protocol byte
    memcpy(payload + 1, hash, 20);
    uint8_t checked[24];
    memcpy(checked, hash, sizeof(hash));
    if (!crypto_blake2b(payload, sizeof(payload), checked + 20, 4))
      return WalletError::CryptoFailure;
    out[0] = 'f'; out[1] = '1';
    const bool ok = base32_encode(checked, sizeof(checked), out + 2, out_size - 2, true, false);
    secure_zero(payload, sizeof(payload));
    secure_zero(hash, sizeof(hash));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_vechain(const uint8_t public_key[kUncompressedPublicKeySize],
                              char *out, size_t out_size)
  {
    if (public_key == nullptr || out == nullptr || public_key[0] != 0x04)
      return WalletError::InvalidArgument;
    uint8_t digest[32];
    if (!crypto_keccak256(public_key + 1, kUncompressedPublicKeySize - 1, digest))
      return WalletError::CryptoFailure;
    static const char kHex[] = "0123456789abcdef";
    if (out_size < 2 + 40 + 1)
    {
      secure_zero(digest, sizeof(digest));
      return WalletError::BufferTooSmall;
    }
    out[0] = '0';
    out[1] = 'x';
    for (size_t index = 0; index < 20; ++index)
    {
      out[2 + 2 * index] = kHex[digest[12 + index] >> 4];
      out[3 + 2 * index] = kHex[digest[12 + index] & 0x0f];
    }
    out[42] = '\0';
    secure_zero(digest, sizeof(digest));
    return WalletError::Ok;
  }

  WalletError address_icon(const uint8_t public_key[kUncompressedPublicKeySize],
                           char *out, size_t out_size)
  {
    if (public_key == nullptr || out == nullptr || public_key[0] != 0x04)
      return WalletError::InvalidArgument;
    uint8_t digest[32];
    if (!crypto_sha3_256(public_key + 1, kUncompressedPublicKeySize - 1, digest))
      return WalletError::CryptoFailure;
    static const char kHex[] = "0123456789abcdef";
    if (out_size < 2 + 40 + 1)
    {
      secure_zero(digest, sizeof(digest));
      return WalletError::BufferTooSmall;
    }
    out[0] = 'h';
    out[1] = 'x';
    for (size_t index = 0; index < 20; ++index)
    {
      out[2 + 2 * index] = kHex[digest[12 + index] >> 4];
      out[3 + 2 * index] = kHex[digest[12 + index] & 0x0f];
    }
    out[42] = '\0';
    secure_zero(digest, sizeof(digest));
    return WalletError::Ok;
  }

  WalletError address_ss58(uint8_t prefix, const uint8_t public_key[32],
                           char *out, size_t out_size)
  {
    if (public_key == nullptr || out == nullptr || out_size == 0 || prefix > 63)
      return WalletError::InvalidArgument;
    static const char kSs58Prefix[] = "SS58PRE";
    uint8_t payload[1 + 32 + 2];
    payload[0] = prefix;
    memcpy(payload + 1, public_key, 32);
    uint8_t preimage[7 + 1 + 32];
    memcpy(preimage, kSs58Prefix, 7);
    memcpy(preimage + 7, payload, 33);
    uint8_t checksum[64];
    if (!crypto_blake2b(preimage, sizeof(preimage), checksum, sizeof(checksum)))
    {
      return WalletError::CryptoFailure;
    }
    payload[33] = checksum[0];
    payload[34] = checksum[1];
    size_t encoded_size = out_size;
    const bool ok = b58enc(out, &encoded_size, payload, sizeof(payload));
    secure_zero(checksum, sizeof(checksum));
    secure_zero(payload, sizeof(payload));
    secure_zero(preimage, sizeof(preimage));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_decred(uint16_t version,
                             const uint8_t public_key[kCompressedPublicKeySize],
                             char *out, size_t *in_out_size)
  {
    if (public_key == nullptr || out == nullptr || in_out_size == nullptr)
      return WalletError::InvalidArgument;
    uint8_t blake[32];
    uint8_t hash[20];
    if (!blake256_hash(public_key, kCompressedPublicKeySize, blake))
    {
      secure_zero(blake, sizeof(blake));
      return WalletError::CryptoFailure;
    }
    local_ripemd160(blake, sizeof(blake), hash);
    uint8_t payload[2 + 20];
    payload[0] = static_cast<uint8_t>(version >> 8);
    payload[1] = static_cast<uint8_t>(version);
    memcpy(payload + 2, hash, sizeof(hash));
    const bool ok = base58check_blake256(payload, sizeof(payload), out, in_out_size);
    secure_zero(blake, sizeof(blake));
    secure_zero(hash, sizeof(hash));
    secure_zero(payload, sizeof(payload));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_decred_from_script(uint16_t p2pkh_version,
                                         uint16_t p2sh_version,
                                         const uint8_t *script, size_t script_size,
                                         char *out, size_t out_size)
  {
    if (script == nullptr || out == nullptr || out_size == 0)
      return WalletError::InvalidArgument;
    uint16_t version = 0;
    const uint8_t *hash = nullptr;
    if (script_size == 25 && script[0] == 0x76 && script[1] == 0xa9 &&
        script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac)
    {
      version = p2pkh_version;
      hash = script + 3;
    }
    else if (script_size == 23 && script[0] == 0xa9 && script[1] == 0x14 &&
             script[22] == 0x87)
    {
      version = p2sh_version;
      hash = script + 2;
    }
    else
    {
      return WalletError::InvalidArgument;
    }
    uint8_t payload[2 + 20];
    payload[0] = static_cast<uint8_t>(version >> 8);
    payload[1] = static_cast<uint8_t>(version);
    memcpy(payload + 2, hash, 20);
    size_t encoded_size = out_size;
    const bool ok = base58check_blake256(payload, sizeof(payload), out, &encoded_size);
    secure_zero(payload, sizeof(payload));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_ton(const uint8_t public_key[32], uint32_t wallet_id,
                          uint8_t flags, char *out, size_t out_size)
  {
    if (public_key == nullptr || out == nullptr)
      return WalletError::InvalidArgument;
    uint8_t hash[32];
    if (!ton_wallet_address_hash(public_key, wallet_id, hash))
      return WalletError::CryptoFailure;
    const bool ok = ton_user_friendly_address(flags, 0, hash, out, out_size);
    secure_zero(hash, sizeof(hash));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_ergo(const uint8_t public_key[kCompressedPublicKeySize],
                           char *out, size_t *in_out_size)
  {
    if (public_key == nullptr || out == nullptr || in_out_size == nullptr)
    {
      return WalletError::InvalidArgument;
    }
    // mainnet P2PK: prefix byte = network(0x00) + type(0x01); content is the
    // compressed public key itself; checksum = blake2b256(prefix||content)[:4].
    uint8_t payload[1 + kCompressedPublicKeySize];
    payload[0] = 0x01;
    memcpy(payload + 1, public_key, kCompressedPublicKeySize);
    const bool ok = base58check_blake2b(payload, sizeof(payload), out, in_out_size);
    secure_zero(payload, sizeof(payload));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_ckb_from_args(const uint8_t args[20], char *out,
                                    size_t out_size)
  {
    if (args == nullptr || out == nullptr || out_size == 0)
      return WalletError::InvalidArgument;
    // Short payload: format 0x01, code hash index 0x00 (SECP256K1 blake160),
    // then the 20-byte lock args.
    uint8_t payload[22];
    payload[0] = 0x01;
    payload[1] = 0x00;
    memcpy(payload + 2, args, 20);
    uint8_t five_bit[36];
    size_t five_size = 0;
    uint32_t accumulator = 0;
    uint8_t bits = 0;
    for (size_t i = 0; i < sizeof(payload); ++i)
    {
      accumulator = (accumulator << 8) | payload[i];
      bits += 8;
      while (bits >= 5)
      {
        bits -= 5;
        five_bit[five_size++] = static_cast<uint8_t>((accumulator >> bits) & 0x1f);
      }
    }
    if (bits != 0)
      five_bit[five_size++] = static_cast<uint8_t>((accumulator << (5 - bits)) & 0x1f);
    const std::string encoded =
        bech32::encode("ckb", std::vector<uint8_t>(five_bit, five_bit + five_size),
                       bech32::Encoding::BECH32);
    if (encoded.empty() || encoded.size() >= out_size)
      return WalletError::BufferTooSmall;
    memcpy(out, encoded.c_str(), encoded.size() + 1);
    return WalletError::Ok;
  }

  WalletError address_ckb(const uint8_t public_key[kCompressedPublicKeySize],
                          char *out, size_t out_size)
  {
    if (public_key == nullptr || out == nullptr)
      return WalletError::InvalidArgument;
    Blake2bState state;
    uint8_t hash[32];
    static const uint8_t kPersonal[16] = {
        'c', 'k', 'b', '-', 'd', 'e', 'f', 'a',
        'u', 'l', 't', '-', 'h', 'a', 's', 'h'};
    if (!blake2b_init_personal(&state, sizeof(hash), kPersonal)) {
      return WalletError::CryptoFailure;
    }
    blake2b_update(&state, public_key, kCompressedPublicKeySize);
    if (!blake2b_final(&state, hash)) {
      return WalletError::CryptoFailure;
    }
    const WalletError result = address_ckb_from_args(hash, out, out_size);
    secure_zero(hash, sizeof(hash));
    return result;
  }

  WalletError address_graphene(const char *prefix,
                               const uint8_t public_key[kCompressedPublicKeySize],
                               char *out, size_t out_size)
  {
    if (prefix == nullptr || public_key == nullptr || out == nullptr ||
        out_size == 0)
      return WalletError::InvalidArgument;
    const size_t prefix_size = strlen(prefix);
    // base58 of 37 bytes is at most 51 characters; require room for the whole
    // result plus the terminator before writing anything.
    if (prefix_size == 0 || prefix_size + 52 > out_size)
      return WalletError::BufferTooSmall;
    uint8_t payload[kCompressedPublicKeySize + 4];
    memcpy(payload, public_key, kCompressedPublicKeySize);
    uint8_t digest[20];
    local_ripemd160(public_key, kCompressedPublicKeySize, digest);
    memcpy(payload + kCompressedPublicKeySize, digest, 4);
    memcpy(out, prefix, prefix_size);
    size_t encoded_size = out_size - prefix_size;
    const bool ok = b58enc(out + prefix_size, &encoded_size, payload, sizeof(payload));
    secure_zero(payload, sizeof(payload));
    secure_zero(digest, sizeof(digest));
    return ok ? WalletError::Ok : WalletError::BufferTooSmall;
  }

  WalletError address_icp(const uint8_t public_key[32], char *out,
                          size_t out_size)
  {
    // 33-byte payload -> 53 base32 characters, plus 10 dashes and a terminator.
    if (public_key == nullptr || out == nullptr || out_size < 64)
      return WalletError::InvalidArgument;
    uint8_t principal[29];
    // Self-authenticating principals commit to SubjectPublicKeyInfo DER,
    // including the algorithm identifier, not the bare 32-byte Ed25519 key.
    uint8_t der[44] = {0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0};
    memcpy(der + 12, public_key, 32);
    if (!crypto_sha224_local(der, sizeof(der), principal)) return WalletError::CryptoFailure;
    principal[28] = 0x02;  // self-authenticating tag, trailing byte
    uint32_t crc = 0xffffffffUL;
    for (size_t i = 0; i < sizeof(principal); ++i)
    {
      crc ^= principal[i];
      for (uint8_t bit = 0; bit < 8; ++bit)
        crc = (crc >> 1) ^ (0xedb88320UL & (0UL - (crc & 1UL)));
    }
    crc ^= 0xffffffffUL;
    uint8_t payload[4 + 29];
    payload[0] = static_cast<uint8_t>(crc >> 24);
    payload[1] = static_cast<uint8_t>(crc >> 16);
    payload[2] = static_cast<uint8_t>(crc >> 8);
    payload[3] = static_cast<uint8_t>(crc);
    memcpy(payload + 4, principal, sizeof(principal));
    char raw[64];
    if (!base32_encode(payload, sizeof(payload), raw, sizeof(raw), true, false))
    {
      secure_zero(payload, sizeof(payload));
      return WalletError::CryptoFailure;
    }
    size_t written = 0;
    const size_t length = strlen(raw);
    for (size_t i = 0; i < length; ++i)
    {
      if (i != 0 && i % 5 == 0) out[written++] = '-';
      out[written++] = raw[i];
    }
    out[written] = '\0';
    secure_zero(payload, sizeof(payload));
    secure_zero(principal, sizeof(principal));
    secure_zero(raw, sizeof(raw));
    return WalletError::Ok;
  }

  bool run_alt_address_self_tests()
  {
    // secp256k1 private key = 1 -> compressed public key.
    static const uint8_t kPkOne[kCompressedPublicKeySize] = {
        0x02,
        0x79,
        0xbe,
        0x66,
        0x7e,
        0xf9,
        0xdc,
        0xbb,
        0xac,
        0x55,
        0xa0,
        0x62,
        0x95,
        0xce,
        0x87,
        0x0b,
        0x07,
        0x02,
        0x9b,
        0xfc,
        0xdb,
        0x2d,
        0xce,
        0x28,
        0xd9,
        0x59,
        0xf2,
        0x81,
        0x5b,
        0x16,
        0xf8,
        0x17,
        0x98,
    };
    static const uint8_t kPkOneUncompressed[kUncompressedPublicKeySize] = {
        0x04,
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
        0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce,
        0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb,
        0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85,
        0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
    };
    // ed25519 seed = 32 x 0x01 -> public key.
    static const uint8_t kEdSeed[32] = {
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
    };
    static const uint8_t kEdPk[32] = {
        0x8a,
        0x88,
        0xe3,
        0xdd,
        0x74,
        0x09,
        0xf1,
        0x95,
        0xfd,
        0x52,
        0xdb,
        0x2d,
        0x3c,
        0xba,
        0x5d,
        0x72,
        0xca,
        0x67,
        0x09,
        0xbf,
        0x1d,
        0x94,
        0x12,
        0x1b,
        0xf3,
        0x74,
        0x88,
        0x01,
        0xb4,
        0x0f,
        0x6f,
        0x5c,
    };
    char address[kAddressTextSize];
    size_t address_size = sizeof(address);
    bool passed = true;

    passed = selftest_report("solana", address_solana(kEdPk, address, &address_size) == WalletError::Ok && strcmp(address, "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9") == 0) && passed;
    passed = selftest_report("aeternity", address_aeternity(kEdPk, address, sizeof(address)) == WalletError::Ok && strcmp(address, "ak_241gerYcVAvfk7Vc6gFuqBje5CfVJxT1fgzkym5cq2qtfxfKgD") == 0) && passed;
    address_size = sizeof(address);
    passed = selftest_report("tezos", address_tezos_tz1(kEdPk, address, &address_size) == WalletError::Ok && strcmp(address, "tz1c8PEDNfj6UxoQM2XCyfTHM5KbGGgoqDrH") == 0) && passed;
    address_size = sizeof(address);
    passed = selftest_report("ripple r-address", address_ripple(kPkOne, address, &address_size) == WalletError::Ok && strcmp(address, "rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH") == 0) && passed;
    passed = selftest_report("algorand ed01", address_algorand(kEdPk, address, sizeof(address)) == WalletError::Ok && strcmp(address, "RKEOHXLUBHYZL7KS3MWTZOS5OLFGOCN7DWKBEG7TOSEADNAPN5OOTUNSLE") == 0) && passed;
    // Algorand known vector (public key from go-algorand address tests).
    static const uint8_t kAlgoPk[32] = {
        0x26,
        0xf7,
        0x8a,
        0xce,
        0x0d,
        0xc1,
        0xf4,
        0x13,
        0xa3,
        0x7b,
        0x70,
        0xb0,
        0xbf,
        0xa6,
        0x10,
        0x91,
        0x19,
        0x71,
        0xf0,
        0x8d,
        0xff,
        0x05,
        0x98,
        0x6f,
        0xe5,
        0x17,
        0x89,
        0x92,
        0x9d,
        0x01,
        0x13,
        0x6c,
    };
    passed = selftest_report("algorand go-algo", address_algorand(kAlgoPk, address, sizeof(address)) == WalletError::Ok && strcmp(address, "E33YVTQNYH2BHI33OCYL7JQQSEMXD4EN74CZQ37FC6EZFHIBCNWOWXIZ5M") == 0) && passed;

    address_size = sizeof(address);
    passed = selftest_report("zcash t1", address_zcash_transparent(0x1cb8, 0x1cbd, kPkOne, address, &address_size) == WalletError::Ok && strcmp(address, "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs") == 0) && passed;
    uint8_t zcash_hash[kRipemd160Size] = {};
    uint8_t zcash_script[25] = {0x76, 0xa9, 0x14};
    zcash_script[23] = 0x88;
    zcash_script[24] = 0xac;
    const bool zcash_hash_ok =
        crypto_hash160(kPkOne, sizeof(kPkOne), zcash_hash);
    memcpy(zcash_script + 3, zcash_hash, sizeof(zcash_hash));
    passed = selftest_report("zcash t1 script",
                             zcash_hash_ok &&
                                 address_zcash_transparent_from_script(
                                     0x1cb8, 0x1cbd, zcash_script, sizeof(zcash_script),
                                     address, sizeof(address)) == WalletError::Ok &&
                                 strcmp(address, "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs") == 0) &&
             passed;
    uint8_t zcash_p2sh[23] = {0xa9, 0x14};
    zcash_p2sh[22] = 0x87;
    for (size_t index = 0; index < kRipemd160Size; ++index)
    {
      zcash_p2sh[2 + index] = static_cast<uint8_t>(index);
    }
    passed = selftest_report("zcash t3 script",
                             address_zcash_transparent_from_script(
                                 0x1cb8, 0x1cbd, zcash_p2sh, sizeof(zcash_p2sh),
                                 address, sizeof(address)) == WalletError::Ok &&
                                 strcmp(address, "t3JZe8uVCra9T1mot8DC99s7GVsDKFy2Xa2") == 0) &&
             passed;
    secure_zero(zcash_hash, sizeof(zcash_hash));
    secure_zero(zcash_script, sizeof(zcash_script));
    secure_zero(zcash_p2sh, sizeof(zcash_p2sh));
    passed = selftest_report("cashaddr bch", address_cashaddr("bitcoincash", kPkOne, address, sizeof(address)) == WalletError::Ok && strcmp(address, "bitcoincash:qw508d6qejxtdg4y5r3zarvary0c5xw7k9e8dplv0") == 0) && passed;
    passed = selftest_report("cashaddr xec", address_cashaddr("ecash", kPkOne, address, sizeof(address)) == WalletError::Ok && strcmp(address, "ecash:qw508d6qejxtdg4y5r3zarvary0c5xw7kjp6rx7xg") == 0) && passed;
    passed = selftest_report("cosmos cro", address_cosmos_bech32("cro", kPkOne, address, sizeof(address)) == WalletError::Ok && strcmp(address, "cro1w508d6qejxtdg4y5r3zarvary0c5xw7kzxlrnf") == 0) && passed;
    passed = selftest_report("cosmos sei", address_cosmos_bech32("sei", kPkOne, address, sizeof(address)) == WalletError::Ok && strcmp(address, "sei1w508d6qejxtdg4y5r3zarvary0c5xw7kh3xvfe") == 0) && passed;
    passed = selftest_report("cosmos hub", address_cosmos_bech32("cosmos", kPkOne, address, sizeof(address)) == WalletError::Ok && strcmp(address, "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c") == 0) && passed;
    passed = selftest_report("cosmos osmo", address_cosmos_bech32("osmo", kPkOne, address, sizeof(address)) == WalletError::Ok && strcmp(address, "osmo1w508d6qejxtdg4y5r3zarvary0c5xw7kjxy2e2") == 0) && passed;
    passed = selftest_report("cosmos celestia", address_cosmos_bech32("celestia", kPkOne, address, sizeof(address)) == WalletError::Ok && strcmp(address, "celestia1w508d6qejxtdg4y5r3zarvary0c5xw7kthx244") == 0) && passed;
    passed = selftest_report("avax", address_avalanche_xp("avax", kPkOne, address, sizeof(address)) == WalletError::Ok && strcmp(address, "X-avax1qp63uahgrxged4z5jswyt5dn5v3lzsem6cl7ra9f") == 0) && passed;
    passed = selftest_report("kaspa pk1", address_kaspa(kPkOne, address, sizeof(address)) == WalletError::Ok && strcmp(address, "kaspa:qpumuen7l8wthtz45p3ftn58pvrs9xlumvkuu2xet8egzkcklqtes4ypce9sf") == 0) && passed;
    // Official rusty-kaspa address vectors (crypto/addresses/src/lib.rs).
    static const uint8_t kKaspaZero[32] = {};
    passed = selftest_report("kaspa zero", kaspa_bech32_encode("kaspa", 0, kKaspaZero, 32, address, sizeof(address)) && strcmp(address, "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e") == 0) && passed;
    static const uint8_t kKaspaOfficial[32] = {
        0x5f,
        0xff,
        0x3c,
        0x4d,
        0xa1,
        0x8f,
        0x45,
        0xad,
        0xcd,
        0xd4,
        0x99,
        0xe4,
        0x46,
        0x11,
        0xe9,
        0xff,
        0xf1,
        0x48,
        0xba,
        0x69,
        0xdb,
        0x3c,
        0x4e,
        0xa2,
        0xdd,
        0xd9,
        0x55,
        0xfc,
        0x46,
        0xa5,
        0x95,
        0x22,
    };
    passed = selftest_report("kaspa official", kaspa_bech32_encode("kaspa", 0, kKaspaOfficial, 32, address, sizeof(address)) && strcmp(address, "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj") == 0) && passed;
    // Zondax filecoin-signing-tools 2.4.3, keyRecover(private key 1, false).
    passed = selftest_report("filecoin", address_filecoin(kPkOneUncompressed, address, sizeof(address)) == WalletError::Ok && strcmp(address, "f1wcuzrs736zqzbbjjdgl2wvyyufuk4pefbymzf2i") == 0) && passed;
    address_size = sizeof(address);
    passed = selftest_report("ergo", address_ergo(kPkOne, address, &address_size) == WalletError::Ok && strcmp(address, "9fSgJ7BmUxBQJ454prQDQ7fQMBkXPLaAmDnimgTtjym6FYPHjAV") == 0) && passed;
    passed = selftest_report("cardano", address_cardano_base(kEdPk, kEdPk, address, sizeof(address)) == WalletError::Ok && strcmp(address, "addr1qyxk54m7j3q6mrkevcunryrwf4p7e68c93cjk8gzxkhlkpsddftha9zp4k8dje3exxgxun2ran50str39vwsydd0lvrqyqym9s") == 0) && passed;
    passed = selftest_report("cardano derivation", run_cardano_derivation_self_tests()) && passed;
    passed = selftest_report("vechain", address_vechain(kPkOneUncompressed, address, sizeof(address)) == WalletError::Ok && strcmp(address, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf") == 0) && passed;
    passed = selftest_report("icon", address_icon(kPkOneUncompressed, address, sizeof(address)) == WalletError::Ok && strcmp(address, "hx0502987e630ea7ebb2bf1d84a65a727109385bcf") == 0) && passed;
    // substrate-interface ed25519 Keypair.create_from_seed(bytes(range(32)))
    static const uint8_t kSubstrateEdPk[32] = {
        0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18,
        0xe7, 0x4b, 0xc0, 0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f,
        0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8};
    passed = selftest_report("ss58 dot", address_ss58(0, kSubstrateEdPk, address, sizeof(address)) == WalletError::Ok && strcmp(address, "15kypVvwBLVS1eFtT9tb2ZS2HLXLbsy5iZaddcFzRrm5izi") == 0) && passed;
    passed = selftest_report("ss58 ksm", address_ss58(2, kSubstrateEdPk, address, sizeof(address)) == WalletError::Ok && strcmp(address, "Cf5Voajhm5wk8TBhWuwLq6HKFd7Sy91Tbfqrztrv93jeZkE") == 0) && passed;
    // tonsdk WalletV4ContractR2(public_key = 32 x 0x01), default wallet id.
    static const uint8_t kTonPk[32] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    passed = selftest_report("ton v4r2", address_ton(kTonPk, 698983191, 0x51, address, sizeof(address)) == WalletError::Ok && strcmp(address, "UQDy/zN0Mel7MItGcTQr0kxEJxa7dg/+OGv7/XToTMTKT1Cz") == 0) && passed;
    address_size = sizeof(address);
    passed = selftest_report("decred", address_decred(0x073f, kPkOne, address, &address_size) == WalletError::Ok && strcmp(address, "DsmcYVbP1Nmag2H4AS17UTvmWXmGeA7nLDx") == 0) && passed;
    static const uint8_t kCkbArgs[20] = {
        0xb3, 0x9b, 0xbc, 0x0b, 0x36, 0x73, 0xc7, 0xd3, 0x64, 0x50,
        0xbc, 0x14, 0xcf, 0xcd, 0xad, 0x2d, 0x55, 0x9c, 0x6c, 0x64};
    passed = selftest_report("ckb args", address_ckb_from_args(kCkbArgs, address, sizeof(address)) == WalletError::Ok && strcmp(address, "ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v") == 0) && passed;
    passed = selftest_report("ckb key1", address_ckb(kPkOne, address, sizeof(address)) == WalletError::Ok && strcmp(address, "ckb1qyq829u0x32fchlfe5dqc4awh5q70h0eyj0q2zdh7f") == 0) && passed;
    passed = selftest_report("hive pubkey", address_graphene("STM", kPkOne, address, sizeof(address)) == WalletError::Ok && strcmp(address, "STM5p78kHbL33Rn3JWkTWRE2B9uz6gy4r1KbfAKLNQGE3ovMBS5bu") == 0) && passed;
    // @icp-sdk/core 6.1.1: Principal.selfAuthenticating(Ed25519 SPKI DER).
    static const uint8_t kIcpPk[32] = {
        0x0a, 0x10, 0x7b, 0xff, 0x3c, 0xe1, 0x0b, 0xe1, 0xd7, 0x0d, 0xd1,
        0x8e, 0x74, 0xbc, 0x09, 0x96, 0x7e, 0x4d, 0x63, 0x09, 0xba, 0x50,
        0xd5, 0xf1, 0xdd, 0xc8, 0x66, 0x41, 0x25, 0x53, 0xea, 0x08};
    passed = selftest_report(
                 "icp principal",
                 address_icp(kIcpPk, address, sizeof(address)) == WalletError::Ok &&
                     strcmp(address,
                            "zlocg-yqozk-rvuw2-ua6op-m2yqg-4wvyj-utqli-kfd4u-ijfn5-dc3fa-sae") == 0) &&
             passed;

    secure_zero(address, sizeof(address));
    (void)kEdSeed;
    return passed;
  }

} // namespace hexwallet
