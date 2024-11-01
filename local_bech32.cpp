#include <tuple>
#include <vector>

#include <assert.h>
#include <stdint.h>

#include "local_bech32.h"

namespace bech32 {

namespace {

typedef std::vector<uint8_t> data;

const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const int8_t CHARSET_REV[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
  1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
  1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1
};

/** Concatenate two byte arrays. */
data cat(data x, const data& y) {
  x.insert(x.end(), y.begin(), y.end());
  return x;
}

/* Determine the final constant to use for the specified encoding. */
uint32_t encoding_constant(Encoding encoding) {
  assert(encoding == Encoding::BECH32 || encoding == Encoding::BECH32M);
  return encoding == Encoding::BECH32 ? 1 : 0x2bc830a3;
}


uint32_t polymod(const data& values) {
  uint32_t c = 1;
  for (const auto v_i : values) {
    uint8_t c0 = c >> 25;

    // Then compute c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i:
    c = ((c & 0x1ffffff) << 5) ^ v_i;

    // Finally, for each set bit n in c0, conditionally add {2^n}k(x):
    if (c0 & 1) c ^= 0x3b6a57b2;   //     k(x) = {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + {18}
    if (c0 & 2) c ^= 0x26508e6d;   //  {2}k(x) = {19}x^5 +  {5}x^4 +     x^3 +  {3}x^2 + {19}x + {13}
    if (c0 & 4) c ^= 0x1ea119fa;   //  {4}k(x) = {15}x^5 + {10}x^4 +  {2}x^3 +  {6}x^2 + {15}x + {26}
    if (c0 & 8) c ^= 0x3d4233dd;   //  {8}k(x) = {30}x^5 + {20}x^4 +  {4}x^3 + {12}x^2 + {30}x + {29}
    if (c0 & 16) c ^= 0x2a1462b3;  // {16}k(x) = {21}x^5 +     x^4 +  {8}x^3 + {24}x^2 + {21}x + {19}
  }
  return c;
}

/** Convert to lower case. */
unsigned char lc(unsigned char c) {
  return (c >= 'A' && c <= 'Z') ? (c - 'A') + 'a' : c;
}

/** Expand a HRP for use in checksum computation. */
data expand_hrp(const std::string& hrp) {
  data ret;
  ret.reserve(hrp.size() + 90);
  ret.resize(hrp.size() * 2 + 1);
  for (size_t i = 0; i < hrp.size(); ++i) {
    unsigned char c = hrp[i];
    ret[i] = c >> 5;
    ret[i + hrp.size() + 1] = c & 0x1f;
  }
  ret[hrp.size()] = 0;
  return ret;
}

/** Verify a checksum. */
Encoding verify_checksum(const std::string& hrp, const data& values) {
  uint32_t check = polymod(cat(expand_hrp(hrp), values));
  if (check == encoding_constant(Encoding::BECH32)) return Encoding::BECH32;
  if (check == encoding_constant(Encoding::BECH32M)) return Encoding::BECH32M;
  return Encoding::INVALID;
}

data create_checksum(const std::string& hrp, const data& values, Encoding encoding) {
  data enc = cat(expand_hrp(hrp), values);
  enc.resize(enc.size() + 6);
  uint32_t mod = polymod(enc) ^ encoding_constant(encoding);
  data ret;
  ret.resize(6);
  for (size_t i = 0; i < 6; ++i) {
    // Convert the 5-bit groups in mod to checksum values.
    ret[i] = (mod >> (5 * (5 - i))) & 31;
  }
  return ret;
}

}  // namespace

/** Encode a Bech32 or Bech32m string. */
std::string encode(const std::string& hrp, const data& values, Encoding encoding) {
  for (const char& c : hrp) assert(c < 'A' || c > 'Z');
  data checksum = create_checksum(hrp, values, encoding);
  data combined = cat(values, checksum);
  std::string ret = hrp + '1';
  ret.reserve(ret.size() + combined.size());
  for (const auto c : combined) {
    ret += CHARSET[c];
  }
  return ret;
}

/** Decode a Bech32 or Bech32m string. */
DecodeResult decode(const std::string& str) {
  bool lower = false, upper = false;
  for (size_t i = 0; i < str.size(); ++i) {
    unsigned char c = str[i];
    if (c >= 'a' && c <= 'z') lower = true;
    else if (c >= 'A' && c <= 'Z') upper = true;
    else if (c < 33 || c > 126) return {};
  }
  if (lower && upper) return {};
  size_t pos = str.rfind('1');
  if (str.size() > 90 || pos == str.npos || pos == 0 || pos + 7 > str.size()) {
    return {};
  }
  data values(str.size() - 1 - pos);
  for (size_t i = 0; i < str.size() - 1 - pos; ++i) {
    unsigned char c = str[i + pos + 1];
    int8_t rev = CHARSET_REV[c];

    if (rev == -1) {
      return {};
    }
    values[i] = rev;
  }
  std::string hrp;
  for (size_t i = 0; i < pos; ++i) {
    hrp += lc(str[i]);
  }
  Encoding result = verify_checksum(hrp, values);
  if (result == Encoding::INVALID) return {};
  return { result, std::move(hrp), data(values.begin(), values.end() - 6) };
}

}