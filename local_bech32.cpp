#include <tuple>
#include <vector>

#include <stdint.h>
#include <string.h>

#include "local_bech32.h"

namespace bech32 {

namespace {

typedef std::vector<uint8_t> data;

constexpr char kCharset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr uint32_t kBech32Constant = 1;
constexpr uint32_t kBech32mConstant = 0x2bc830a3;
constexpr uint32_t kGenerator[] = {
    0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3,
};
constexpr size_t kChecksumLength = 6;
constexpr size_t kMaximumTextLength = 90;
constexpr uint8_t kValueBits = 5;
constexpr uint8_t kPolymodTopShift = 25;
constexpr uint32_t kValueMask = (1U << kValueBits) - 1;
constexpr uint32_t kPolymodLowMask = (1U << kPolymodTopShift) - 1;

data cat(data x, const data& y) {
  x.insert(x.end(), y.begin(), y.end());
  return x;
}

uint32_t encoding_constant(Encoding encoding) {
  if (encoding == Encoding::BECH32) return kBech32Constant;
  if (encoding == Encoding::BECH32M) return kBech32mConstant;
  return 0;
}


uint32_t polymod(const data& values) {
  uint32_t c = 1;
  for (const auto v_i : values) {
    uint8_t c0 = c >> kPolymodTopShift;

    c = ((c & kPolymodLowMask) << kValueBits) ^ v_i;

    for (uint8_t bit = 0; bit < sizeof(kGenerator) / sizeof(kGenerator[0]); ++bit) {
      if ((c0 & (1U << bit)) != 0) c ^= kGenerator[bit];
    }
  }
  return c;
}

unsigned char lc(unsigned char c) {
  return (c >= 'A' && c <= 'Z') ? (c - 'A') + 'a' : c;
}

data expand_hrp(const std::string& hrp) {
  data ret;
  ret.reserve(hrp.size() + 90);
  ret.resize(hrp.size() * 2 + 1);
  for (size_t i = 0; i < hrp.size(); ++i) {
    unsigned char c = hrp[i];
    ret[i] = c >> kValueBits;
    ret[i + hrp.size() + 1] = c & kValueMask;
  }
  ret[hrp.size()] = 0;
  return ret;
}

Encoding verify_checksum(const std::string& hrp, const data& values) {
  uint32_t check = polymod(cat(expand_hrp(hrp), values));
  if (check == encoding_constant(Encoding::BECH32)) return Encoding::BECH32;
  if (check == encoding_constant(Encoding::BECH32M)) return Encoding::BECH32M;
  return Encoding::INVALID;
}

data create_checksum(const std::string& hrp, const data& values, Encoding encoding) {
  data enc = cat(expand_hrp(hrp), values);
  enc.resize(enc.size() + kChecksumLength);
  uint32_t mod = polymod(enc) ^ encoding_constant(encoding);
  data ret;
  ret.resize(kChecksumLength);
  for (size_t i = 0; i < kChecksumLength; ++i) {
    ret[i] = (mod >> (kValueBits * (kChecksumLength - 1 - i))) & kValueMask;
  }
  return ret;
}

}  // namespace

std::string encode(const std::string& hrp, const data& values, Encoding encoding) {
  if (hrp.empty() || encoding_constant(encoding) == 0) return {};
  for (const unsigned char c : hrp) {
    if (c < 33 || c > 126 || (c >= 'A' && c <= 'Z')) return {};
  }
  data checksum = create_checksum(hrp, values, encoding);
  data combined = cat(values, checksum);
  std::string ret = hrp + '1';
  ret.reserve(ret.size() + combined.size());
  for (const auto c : combined) {
    if (c >= sizeof(kCharset) - 1) return {};
    ret += kCharset[c];
  }
  return ret;
}

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
  if (str.size() > kMaximumTextLength || pos == str.npos || pos == 0 ||
      pos + 1 + kChecksumLength > str.size()) {
    return {};
  }
  data values(str.size() - 1 - pos);
  for (size_t i = 0; i < str.size() - 1 - pos; ++i) {
    unsigned char c = str[i + pos + 1];
    const char *position = strchr(kCharset, lc(c));
    if (position == nullptr) return {};
    values[i] = static_cast<uint8_t>(position - kCharset);
  }
  std::string hrp;
  for (size_t i = 0; i < pos; ++i) {
    hrp += lc(str[i]);
  }
  Encoding result = verify_checksum(hrp, values);
  if (result == Encoding::INVALID) return {};
  return { result, std::move(hrp), data(values.begin(), values.end() - kChecksumLength) };
}

}
