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

/** A type for the result of decoding. */
struct DecodeResult {
  Encoding encoding;          //!< What encoding was detected in the result; Encoding::INVALID if failed.
  std::string hrp;            //!< The human readable part
  std::vector<uint8_t> data;  //!< The payload (excluding checksum)

  DecodeResult()
    : encoding(Encoding::INVALID) {}
  DecodeResult(Encoding enc, std::string&& h, std::vector<uint8_t>&& d)
    : encoding(enc), hrp(std::move(h)), data(std::move(d)) {}
};

DecodeResult decode(const std::string& str);

}

#endif