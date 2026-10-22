#include "WalletLinkCrypto.h"

#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {

    constexpr size_t kChaChaBlockSize = 64;
    constexpr uint32_t kChaChaConstant[4] = {
        0x61707865UL,
        0x3320646eUL,
        0x79622d32UL,
        0x6b206574UL,
    };

    uint32_t load_le32(const uint8_t *data)
    {
      return static_cast<uint32_t>(data[0]) |
             (static_cast<uint32_t>(data[1]) << 8) |
             (static_cast<uint32_t>(data[2]) << 16) |
             (static_cast<uint32_t>(data[3]) << 24);
    }

    uint32_t rotate_left(uint32_t value, unsigned bits)
    {
      return (value << bits) | (value >> (32U - bits));
    }

    void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
    {
      *a += *b;
      *d ^= *a;
      *d = rotate_left(*d, 16);
      *c += *d;
      *b ^= *c;
      *b = rotate_left(*b, 12);
      *a += *b;
      *d ^= *a;
      *d = rotate_left(*d, 8);
      *c += *d;
      *b ^= *c;
      *b = rotate_left(*b, 7);
    }

    void chacha20_block(const uint8_t key[kLinkKeySize],
                        const uint8_t nonce[kLinkNonceSize], uint32_t counter,
                        uint8_t out[kChaChaBlockSize])
    {
      uint32_t state[16];
      for (size_t index = 0; index < 4; ++index)
        state[index] = kChaChaConstant[index];
      for (size_t index = 0; index < 8; ++index)
        state[4 + index] = load_le32(key + index * 4);
      state[12] = counter;
      for (size_t index = 0; index < 3; ++index)
        state[13 + index] = load_le32(nonce + index * 4);

      uint32_t working[16];
      memcpy(working, state, sizeof(working));
      for (size_t round = 0; round < 10; ++round)
      {
        quarter_round(&working[0], &working[4], &working[8], &working[12]);
        quarter_round(&working[1], &working[5], &working[9], &working[13]);
        quarter_round(&working[2], &working[6], &working[10], &working[14]);
        quarter_round(&working[3], &working[7], &working[11], &working[15]);
        quarter_round(&working[0], &working[5], &working[10], &working[15]);
        quarter_round(&working[1], &working[6], &working[11], &working[12]);
        quarter_round(&working[2], &working[7], &working[8], &working[13]);
        quarter_round(&working[3], &working[4], &working[9], &working[14]);
      }
      for (size_t index = 0; index < 16; ++index)
      {
        const uint32_t value = working[index] + state[index];
        out[index * 4] = static_cast<uint8_t>(value);
        out[index * 4 + 1] = static_cast<uint8_t>(value >> 8);
        out[index * 4 + 2] = static_cast<uint8_t>(value >> 16);
        out[index * 4 + 3] = static_cast<uint8_t>(value >> 24);
      }
      secure_zero(working, sizeof(working));
      secure_zero(state, sizeof(state));
    }

    bool derive_mac_key(const uint8_t key[kLinkKeySize], uint8_t out[kLinkKeySize])
    {
      static const uint8_t kLabel[] = "HexWallet Link authentication";
      return crypto_hmac_sha256(key, kLinkKeySize, kLabel, sizeof(kLabel) - 1, out);
    }

    bool derive_enc_key(const uint8_t key[kLinkKeySize], uint8_t out[kLinkKeySize])
    {
      static const uint8_t kLabel[] = "HexWallet Link encryption";
      return crypto_hmac_sha256(key, kLinkKeySize, kLabel, sizeof(kLabel) - 1, out);
    }

    bool compute_tag(const uint8_t mac_key[kLinkKeySize],
                     const uint8_t nonce[kLinkNonceSize],
                     const uint8_t *aad, size_t aad_size,
                     const uint8_t *ciphertext, size_t ciphertext_size,
                     uint8_t out_tag[kLinkTagSize])
    {
      if ((aad == nullptr && aad_size != 0) ||
          (ciphertext == nullptr && ciphertext_size != 0))
      {
        return false;
      }
      // HMAC-SHA256 here is one-shot; the maximum link frame is 2 KiB, so a
      // bounded stack buffer is preferable to a streaming state machine.
      constexpr size_t kMaxAuthInput = 18 + kLinkNonceSize + 4608;
      if (aad_size + kLinkNonceSize + ciphertext_size > kMaxAuthInput)
        return false;
      uint8_t buffer[kMaxAuthInput];
      size_t offset = 0;
      if (aad_size != 0)
      {
        memcpy(buffer, aad, aad_size);
        offset += aad_size;
      }
      memcpy(buffer + offset, nonce, kLinkNonceSize);
      offset += kLinkNonceSize;
      if (ciphertext_size != 0)
      {
        memcpy(buffer + offset, ciphertext, ciphertext_size);
        offset += ciphertext_size;
      }
      const bool ok = crypto_hmac_sha256(mac_key, kLinkKeySize, buffer, offset, out_tag);
      secure_zero(buffer, sizeof(buffer));
      return ok;
    }

  } // namespace

  bool link_hkdf_sha256(const uint8_t *ikm, size_t ikm_size,
                        const uint8_t *salt, size_t salt_size,
                        const uint8_t *info, size_t info_size,
                        uint8_t *out, size_t out_size)
  {
    if ((ikm == nullptr && ikm_size != 0) || (salt == nullptr && salt_size != 0) ||
        (info == nullptr && info_size != 0) || out == nullptr ||
        out_size == 0 || out_size > 96)
    {
      return false;
    }

    uint8_t zero_salt[32] = {0};
    const uint8_t *effective_salt = salt;
    size_t effective_salt_size = salt_size;
    if (effective_salt_size == 0)
    {
      effective_salt = zero_salt;
      effective_salt_size = sizeof(zero_salt);
    }

    uint8_t prk[32];
    bool ok = crypto_hmac_sha256(effective_salt, effective_salt_size,
                                 ikm, ikm_size, prk);
    uint8_t previous[32];
    size_t previous_size = 0;
    size_t written = 0;
    uint8_t block = 1;
    while (ok && written < out_size)
    {
      uint8_t input[32 + 64 + 1];
      size_t offset = 0;
      if (previous_size != 0)
      {
        memcpy(input, previous, previous_size);
        offset += previous_size;
      }
      if (info_size != 0)
      {
        if (info_size > 64)
        {
          ok = false;
          break;
        }
        memcpy(input + offset, info, info_size);
        offset += info_size;
      }
      input[offset++] = block;
      uint8_t digest[32];
      ok = crypto_hmac_sha256(prk, sizeof(prk), input, offset, digest);
      if (!ok)
      {
        secure_zero(input, sizeof(input));
        break;
      }
      const size_t take = out_size - written < sizeof(digest)
                              ? out_size - written
                              : sizeof(digest);
      memcpy(out + written, digest, take);
      memcpy(previous, digest, sizeof(digest));
      previous_size = sizeof(digest);
      written += take;
      ++block;
      secure_zero(digest, sizeof(digest));
      secure_zero(input, sizeof(input));
    }
    secure_zero(prk, sizeof(prk));
    secure_zero(previous, sizeof(previous));
    secure_zero(zero_salt, sizeof(zero_salt));
    return ok && written == out_size;
  }

  bool link_chacha20_xor(const uint8_t key[kLinkKeySize],
                         const uint8_t nonce[kLinkNonceSize], uint32_t counter,
                         const uint8_t *input, size_t size, uint8_t *output)
  {
    if (key == nullptr || nonce == nullptr ||
        (input == nullptr && size != 0) || (output == nullptr && size != 0))
    {
      return false;
    }
    uint8_t block[kChaChaBlockSize];
    size_t offset = 0;
    while (offset < size)
    {
      chacha20_block(key, nonce, counter, block);
      const size_t take = size - offset < sizeof(block) ? size - offset : sizeof(block);
      for (size_t index = 0; index < take; ++index)
      {
        output[offset + index] = static_cast<uint8_t>(input[offset + index] ^ block[index]);
      }
      offset += take;
      ++counter;
    }
    secure_zero(block, sizeof(block));
    return true;
  }

  bool link_aead_seal(const uint8_t key[kLinkKeySize],
                      const uint8_t nonce[kLinkNonceSize],
                      const uint8_t *aad, size_t aad_size,
                      const uint8_t *plaintext, size_t plaintext_size,
                      uint8_t *ciphertext, uint8_t out_tag[kLinkTagSize])
  {
    if (key == nullptr || nonce == nullptr || out_tag == nullptr ||
        (aad == nullptr && aad_size != 0) ||
        (plaintext == nullptr && plaintext_size != 0) ||
        (ciphertext == nullptr && plaintext_size != 0))
    {
      return false;
    }
    uint8_t enc_key[kLinkKeySize];
    uint8_t mac_key[kLinkKeySize];
    bool ok = derive_enc_key(key, enc_key) && derive_mac_key(key, mac_key);
    if (ok)
    {
      ok = link_chacha20_xor(enc_key, nonce, 0, plaintext, plaintext_size, ciphertext);
    }
    if (ok)
    {
      ok = compute_tag(mac_key, nonce, aad, aad_size, ciphertext, plaintext_size,
                       out_tag);
    }
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    return ok;
  }

  bool link_aead_open(const uint8_t key[kLinkKeySize],
                      const uint8_t nonce[kLinkNonceSize],
                      const uint8_t *aad, size_t aad_size,
                      const uint8_t *ciphertext, size_t ciphertext_size,
                      const uint8_t tag[kLinkTagSize], uint8_t *plaintext)
  {
    if (key == nullptr || nonce == nullptr || tag == nullptr ||
        (aad == nullptr && aad_size != 0) ||
        (ciphertext == nullptr && ciphertext_size != 0) ||
        (plaintext == nullptr && ciphertext_size != 0))
    {
      return false;
    }
    uint8_t enc_key[kLinkKeySize];
    uint8_t mac_key[kLinkKeySize];
    uint8_t expected[kLinkTagSize];
    bool ok = derive_enc_key(key, enc_key) && derive_mac_key(key, mac_key) &&
              compute_tag(mac_key, nonce, aad, aad_size, ciphertext,
                          ciphertext_size, expected) &&
              crypto_constant_time_equal(expected, tag, sizeof(expected));
    if (ok)
    {
      ok = link_chacha20_xor(enc_key, nonce, 0, ciphertext, ciphertext_size,
                             plaintext);
    }
    else if (plaintext != nullptr && ciphertext_size != 0)
    {
      memset(plaintext, 0, ciphertext_size);
    }
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    secure_zero(expected, sizeof(expected));
    return ok;
  }

  bool run_link_crypto_self_test()
  {
    bool passed = true;
    static const uint8_t kKey[32] = {
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1a,
        0x1b,
        0x1c,
        0x1d,
        0x1e,
        0x1f,
    };
    static const uint8_t kNonce[12] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,
    };
    static const uint8_t kExpectedBlock[64] = {
        0x10,
        0xf1,
        0xe7,
        0xe4,
        0xd1,
        0x3b,
        0x59,
        0x15,
        0x50,
        0x0f,
        0xdd,
        0x1f,
        0xa3,
        0x20,
        0x71,
        0xc4,
        0xc7,
        0xd1,
        0xf4,
        0xc7,
        0x33,
        0xc0,
        0x68,
        0x03,
        0x04,
        0x22,
        0xaa,
        0x9a,
        0xc3,
        0xd4,
        0x6c,
        0x4e,
        0xd2,
        0x82,
        0x64,
        0x46,
        0x07,
        0x9f,
        0xaa,
        0x09,
        0x14,
        0xc2,
        0xd7,
        0x05,
        0xd9,
        0x8b,
        0x02,
        0xa2,
        0xb5,
        0x12,
        0x9c,
        0xd1,
        0xde,
        0x16,
        0x4e,
        0xb9,
        0xcb,
        0xd0,
        0x83,
        0xe8,
        0xa2,
        0x50,
        0x3c,
        0x4e,
    };
    uint8_t zero[64] = {0};
    uint8_t block[64];
    passed = link_chacha20_xor(kKey, kNonce, 1, zero, sizeof(zero), block) &&
             crypto_constant_time_equal(block, kExpectedBlock, sizeof(block)) &&
             passed;

    // RFC 5869 test case 1.
    static const uint8_t kHkdfIkm[22] = {
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
        0x0b,
    };
    static const uint8_t kHkdfSalt[13] = {
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
    };
    static const uint8_t kHkdfInfo[10] = {
        0xf0,
        0xf1,
        0xf2,
        0xf3,
        0xf4,
        0xf5,
        0xf6,
        0xf7,
        0xf8,
        0xf9,
    };
    static const uint8_t kHkdfExpected[42] = {
        0x3c,
        0xb2,
        0x5f,
        0x25,
        0xfa,
        0xac,
        0xd5,
        0x7a,
        0x90,
        0x43,
        0x4f,
        0x64,
        0xd0,
        0x36,
        0x2f,
        0x2a,
        0x2d,
        0x2d,
        0x0a,
        0x90,
        0xcf,
        0x1a,
        0x5a,
        0x4c,
        0x5d,
        0xb0,
        0x2d,
        0x56,
        0xec,
        0xc4,
        0xc5,
        0xbf,
        0x34,
        0x00,
        0x72,
        0x08,
        0xd5,
        0xb8,
        0x87,
        0x18,
        0x58,
        0x65,
    };
    uint8_t hkdf_out[42];
    passed = link_hkdf_sha256(kHkdfIkm, sizeof(kHkdfIkm), kHkdfSalt,
                              sizeof(kHkdfSalt), kHkdfInfo, sizeof(kHkdfInfo),
                              hkdf_out, sizeof(hkdf_out)) &&
             crypto_constant_time_equal(hkdf_out, kHkdfExpected, sizeof(hkdf_out)) &&
             passed;

    static const uint8_t kAad[5] = {'H', 'W', 'L', 'K', 1};
    static const uint8_t kPlaintext[] = "signed transaction payload";
    uint8_t ciphertext[sizeof(kPlaintext)];
    uint8_t recovered[sizeof(kPlaintext)];
    uint8_t tag[kLinkTagSize];
    uint8_t bad_tag[kLinkTagSize];
    const bool sealed = link_aead_seal(kKey, kNonce, kAad, sizeof(kAad),
                                       kPlaintext, sizeof(kPlaintext),
                                       ciphertext, tag);
    const bool opened = sealed && link_aead_open(kKey, kNonce, kAad, sizeof(kAad), ciphertext, sizeof(ciphertext), tag, recovered) &&
                        crypto_constant_time_equal(recovered, kPlaintext,
                                                   sizeof(kPlaintext));
    memcpy(bad_tag, tag, sizeof(bad_tag));
    bad_tag[0] ^= 1;
    const bool tamper_rejected = sealed &&
                                 !link_aead_open(kKey, kNonce, kAad, sizeof(kAad),
                                                 ciphertext, sizeof(ciphertext),
                                                 bad_tag, recovered);
    ciphertext[0] ^= 1;
    const bool ciphertext_rejected = sealed &&
                                     !link_aead_open(kKey, kNonce, kAad, sizeof(kAad),
                                                     ciphertext, sizeof(ciphertext),
                                                     tag, recovered);
    passed = sealed && opened && tamper_rejected && ciphertext_rejected && passed;

    secure_zero(zero, sizeof(zero));
    secure_zero(block, sizeof(block));
    secure_zero(hkdf_out, sizeof(hkdf_out));
    secure_zero(ciphertext, sizeof(ciphertext));
    secure_zero(recovered, sizeof(recovered));
    secure_zero(tag, sizeof(tag));
    secure_zero(bad_tag, sizeof(bad_tag));
    return passed;
  }

} // namespace hexwallet
