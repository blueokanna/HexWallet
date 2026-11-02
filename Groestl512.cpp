#include "Groestl512.h"

#include <string.h>

namespace hexwallet
{
  namespace
  {
    constexpr size_t kCols = 16;
    constexpr size_t kRounds = 14;

    uint8_t xtime(uint8_t value)
    {
      return static_cast<uint8_t>((value << 1) ^ ((value >> 7) * 0x1B));
    }

    // GF(2^8) with the AES polynomial x^8 + x^4 + x^3 + x + 1.
    uint8_t gf_mul(uint8_t a, uint8_t b)
    {
      uint8_t result = 0;
      for (unsigned bit = 0; bit < 8; ++bit)
      {
        if (b & 1)
          result ^= a;
        a = xtime(a);
        b >>= 1;
      }
      return result;
    }

    uint8_t gf_inv(uint8_t value)
    {
      if (value == 0)
        return 0;
      uint8_t result = 1;
      uint8_t base = value;
      for (unsigned exponent = 254; exponent != 0; exponent >>= 1)
      {
        if (exponent & 1)
          result = gf_mul(result, base);
        base = gf_mul(base, base);
      }
      return result;
    }

    uint8_t rotl8(uint8_t value, unsigned count)
    {
      return static_cast<uint8_t>((value << count) | (value >> (8 - count)));
    }

    struct SBox
    {
      uint8_t value[256];
      SBox()
      {
        for (unsigned index = 0; index < 256; ++index)
        {
          const uint8_t inverse = gf_inv(static_cast<uint8_t>(index));
          value[index] = static_cast<uint8_t>(inverse ^ rotl8(inverse, 1) ^
                                              rotl8(inverse, 2) ^ rotl8(inverse, 3) ^
                                              rotl8(inverse, 4) ^ 0x63);
        }
      }
    };

    const uint8_t *sbox()
    {
      static const SBox table;
      return table.value;
    }

    constexpr uint8_t kShiftP[8] = {0, 1, 2, 3, 4, 5, 6, 11};
    constexpr uint8_t kShiftQ[8] = {1, 3, 5, 11, 0, 2, 4, 6};
    constexpr uint8_t kMix[8] = {2, 2, 3, 4, 5, 3, 5, 7};

    void permute(uint8_t state[8][kCols], bool wide_q)
    {
      const uint8_t *shift = wide_q ? kShiftQ : kShiftP;
      const uint8_t *box = sbox();
      uint8_t shifted[8][kCols];
      uint8_t mixed[8][kCols];
      for (unsigned round = 0; round < kRounds; ++round)
      {
        if (!wide_q)
        {
          for (size_t col = 0; col < kCols; ++col)
          {
            state[0][col] ^= static_cast<uint8_t>((col << 4) ^ round);
          }
        }
        else
        {
          for (size_t col = 0; col < kCols; ++col)
          {
            const uint8_t constant = static_cast<uint8_t>((col << 4) ^ round);
            for (size_t row = 0; row < 7; ++row)
              state[row][col] ^= 0xFF;
            state[7][col] ^= static_cast<uint8_t>(0xFF ^ constant);
          }
        }
        for (size_t row = 0; row < 8; ++row)
        {
          for (size_t col = 0; col < kCols; ++col)
            state[row][col] = box[state[row][col]];
        }
        for (size_t row = 0; row < 8; ++row)
        {
          const size_t amount = shift[row] % kCols;
          for (size_t col = 0; col < kCols; ++col)
          {
            shifted[row][col] = state[row][(col + amount) % kCols];
          }
        }
        for (size_t col = 0; col < kCols; ++col)
        {
          for (size_t row = 0; row < 8; ++row)
          {
            uint8_t accumulator = 0;
            for (size_t k = 0; k < 8; ++k)
            {
              accumulator ^= gf_mul(shifted[k][col], kMix[(k + 8 - row) % 8]);
            }
            mixed[row][col] = accumulator;
          }
        }
        memcpy(state, mixed, sizeof(mixed));
      }
    }

    void load_block(const uint8_t *block, uint8_t state[8][kCols])
    {
      for (size_t col = 0; col < kCols; ++col)
      {
        for (size_t row = 0; row < 8; ++row)
          state[row][col] = block[col * 8 + row];
      }
    }

    void store_state(const uint8_t state[8][kCols], uint8_t *out)
    {
      for (size_t col = 0; col < kCols; ++col)
      {
        for (size_t row = 0; row < 8; ++row)
          out[col * 8 + row] = state[row][col];
      }
    }

    void compress(uint8_t chain[kGroestl512Block], const uint8_t *block)
    {
      uint8_t mixed[8][kCols];
      uint8_t plain[8][kCols];
      load_block(chain, mixed);
      for (size_t col = 0; col < kCols; ++col)
      {
        for (size_t row = 0; row < 8; ++row)
        {
          mixed[row][col] ^= block[col * 8 + row];
        }
      }
      load_block(block, plain);
      permute(mixed, false);
      permute(plain, true);
      for (size_t col = 0; col < kCols; ++col)
      {
        for (size_t row = 0; row < 8; ++row)
        {
          chain[col * 8 + row] = static_cast<uint8_t>(
              mixed[row][col] ^ plain[row][col] ^ chain[col * 8 + row]);
        }
      }
    }

    uint16_t hex_nibble(char c)
    {
      if (c >= '0' && c <= '9')
        return static_cast<uint16_t>(c - '0');
      if (c >= 'A' && c <= 'F')
        return static_cast<uint16_t>(c - 'A' + 10);
      if (c >= 'a' && c <= 'f')
        return static_cast<uint16_t>(c - 'a' + 10);
      return 0xFFFF;
    }
  } // namespace

  bool groestl512(const uint8_t *data, size_t size, uint8_t out[kGroestl512Digest])
  {
    if (out == nullptr || (data == nullptr && size != 0))
      return false;
    // The IV carries the digest length in its last eight bytes; the padding tail
    // carries the block count, not the bit length.
    uint8_t chain[kGroestl512Block] = {};
    chain[kGroestl512Block - 2] = 0x02;
    chain[kGroestl512Block - 1] = 0x00;

    uint8_t block[kGroestl512Block];
    size_t consumed = 0;
    while (size - consumed > kGroestl512Block - 9)
    {
      memcpy(block, data + consumed, kGroestl512Block);
      compress(chain, block);
      consumed += kGroestl512Block;
    }
    const size_t remainder = size - consumed;
    memset(block, 0, sizeof(block));
    if (remainder != 0)
      memcpy(block, data + consumed, remainder);
    block[remainder] = 0x80;
    const uint64_t blocks = static_cast<uint64_t>((size + 8) / kGroestl512Block) + 1;
    for (unsigned index = 0; index < 8; ++index)
    {
      block[kGroestl512Block - 1 - index] = static_cast<uint8_t>(blocks >> (8 * index));
    }
    compress(chain, block);

    uint8_t state[8][kCols];
    load_block(chain, state);
    permute(state, false);
    uint8_t transformed[kGroestl512Block];
    store_state(state, transformed);
    for (size_t index = 0; index < kGroestl512Block; ++index)
    {
      transformed[index] ^= chain[index];
    }
    // Omega() keeps the final t bytes, so the digest is the tail of the state.
    memcpy(out, transformed + (kGroestl512Block - kGroestl512Digest), kGroestl512Digest);
    return true;
  }

  namespace
  {
    struct KatVector
    {
      const char *message_hex;
      const char *digest_hex;
    };

    const KatVector kKat[] = {
        {"", "6D3AD29D279110EEF3ADBD66DE2A0345A77BAEDE1557F5D099FCE0C03D6DC2BA"
             "8E6D4A6633DFBD66053C20FAA87D1A11F39A7FBE4A6C2F009801370308FC4AD8"},
        {"CC", "B23EEEB675C272C6E37A6EE9AB4DC505C9D6A10020F6BED3948205D04CDD1E9"
               "0B06E494D186EF4F19266D7DA200C89DC009E2B1A538CDEA199E773FC076F802E"},
        {"41FB", "272BA3FD8A6E392278F234E5053411E8267375A4F9B05D960AFD2E664A6744"
                 "8F500F8BCDD5B8A68D0BDDF3BAF873CDDDE5C235943C58353AD90AED79A6C39CF3"},
        {"1F877C", "413907C17D8CA9E5477DE5491914DC4EB621F35C96267F8E807AFFC0335DD8"
                   "F6781C053CED249FF3C8C5A4D4AC62FE3D9E6660B30CC09621DE7162E6C271D3C7"},
        {"9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10",
         "2F84CFC1EA8E271E47E66BDEA3CAC8015B5B881C3E6CC074AB311BB436AC6CF59DDECB75"
         "BCD6989E9C97D89BDE523A8C53C837494A77E7B73481B2E89DBD7FD6"},
        {"E926AE8B0AF6E53176DBFFCC2A6B88C6BD765F939D3D178A9BDE9EF3AA131C61"
         "E31C1E42CDFAF4B4DCDE579A37E150EFBEF5555B4C1CB40439D835A724E2FAE7",
         "E8EEDDEF7104F8EE0A93C4BE5028DB073B7AC44B73787B3ADCAFDB8AADE084C19550EBB1"
         "D968E2B26B9F99BA48D5686E1D7658725F6934A845CB5EE475B8B7F0"},
        {"2B6DB7CED8665EBE9DEB080295218426BDAA7C6DA9ADD2088932CDFFBAA1C14129BCCDD7"
         "0F369EFB149285858D2B1D155D14DE2FDB680A8B027284055182A0CAE275234CC9C92863"
         "C1B4AB66F304CF0621CD54565F5BFF461D3B461BD40DF28198E3732501B4860EADD503D2"
         "6D6E69338F4E0456E9E9BAF3D827AE685FB1D817",
         "FF410B511135DBC0B8644C28EFA3EC632326FEB98E50EDC6390C441610D7C514ACDF0A61"
         "A0BF01AA9DC1F55D92E085248EBA1C24EE23978B4986AF41C13A6176"},
        {"616263", "70E1C68C60DF3B655339D67DC291CC3F1DDE4EF343F11B23FDD44957693815A7"
                   "5A8339C682FC28322513FD1F283C18E53CFF2B264E06BF83A2F0AC8C1F6FBFF6"},
    };

    bool matches(const uint8_t *digest, const char *expected_hex)
    {
      uint8_t expected[kGroestl512Digest];
      for (size_t index = 0; index < kGroestl512Digest; ++index)
      {
        const uint16_t high = hex_nibble(expected_hex[index * 2]);
        const uint16_t low = hex_nibble(expected_hex[index * 2 + 1]);
        if (high == 0xFFFF || low == 0xFFFF)
          return false;
        expected[index] = static_cast<uint8_t>((high << 4) | low);
      }
      return memcmp(digest, expected, kGroestl512Digest) == 0;
    }
  } // namespace

  bool run_groestl512_self_tests()
  {
    uint8_t message[kGroestl512Block];
    uint8_t digest[kGroestl512Digest];
    for (const KatVector &vector : kKat)
    {
      size_t length = 0;
      for (const char *cursor = vector.message_hex; *cursor != 0; cursor += 2)
      {
        const uint16_t high = hex_nibble(cursor[0]);
        const uint16_t low = hex_nibble(cursor[1]);
        if (high == 0xFFFF || low == 0xFFFF || length >= sizeof(message))
          return false;
        message[length++] = static_cast<uint8_t>((high << 4) | low);
      }
      if (!groestl512(message, length, digest))
        return false;
      if (!matches(digest, vector.digest_hex))
        return false;
    }
    return !groestl512(message, 0, nullptr) && !groestl512(nullptr, 1, digest);
  }
}
