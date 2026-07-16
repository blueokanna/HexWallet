#ifndef __LOCAL_BECH32_H_
#define __LOCAL_BECH32_H_

#include <string>
#include <tuple>
#include <vector>
#include <stdint.h>

namespace bech32 {

enum class Encoding {
  INVALID,
  BECH32,
  BECH32M,
};

std::string encode(const std::string& hrp, const std::vector<uint8_t>& values, Encoding encoding);

struct DecodeResult {
  Encoding encoding;
  std::string hrp;
  std::vector<uint8_t> data;

  DecodeResult()
    : encoding(Encoding::INVALID) {}
  DecodeResult(Encoding enc, std::string&& h, std::vector<uint8_t>&& d)
    : encoding(enc), hrp(std::move(h)), data(std::move(d)) {}
};

DecodeResult decode(const std::string& str);

}

#endif
