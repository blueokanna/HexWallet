#include "local_segwit.h"
#include "local_bech32.h"

#include <tuple>

namespace {

typedef std::vector<uint8_t> data;

template<int frombits, int tobits, bool pad>
bool convertbits(data& out, const data& in) {
  int acc = 0;
  int bits = 0;
  const int maxv = (1 << tobits) - 1;
  const int max_acc = (1 << (frombits + tobits - 1)) - 1;
  for (size_t i = 0; i < in.size(); ++i) {
    int value = in[i];
    acc = ((acc << frombits) | value) & max_acc;
    bits += frombits;
    while (bits >= tobits) {
      bits -= tobits;
      out.push_back((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits) out.push_back((acc << (tobits - bits)) & maxv);
  } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
    return false;
  }
  return true;
}

}

namespace segwit_address {

/** Encode a SegWit address. */
std::string encode(const std::string& hrp, int witver, const data& witprogram) {
  data enc;
  enc.push_back(witver);
  convertbits<8, 5, true>(enc, witprogram);
  std::string ret = bech32::encode(hrp, enc, witver > 0 ? bech32::Encoding::BECH32M : bech32::Encoding::BECH32);
  if (decode(hrp, ret).first == -1) return "";
  return ret;
}

/** Decode a SegWit address. */
std::pair<int, data> decode(const std::string& hrp, const std::string& addr) {
  const auto dec = bech32::decode(addr);
  if (dec.hrp != hrp || dec.data.size() < 1) return std::make_pair(-1, data());
  data conv;
  uint8_t witver = dec.data[0];
  if (!convertbits<5, 8, false>(conv, data(dec.data.begin() + 1, dec.data.end())) || conv.size() < 2 || conv.size() > 40 || witver > 16 || (witver == 0 && conv.size() != 20 && conv.size() != 32) || (witver == 0 && dec.encoding != bech32::Encoding::BECH32) || (witver != 0 && dec.encoding != bech32::Encoding::BECH32M)) {
    return std::make_pair(-1, data());
  }
  return std::make_pair(dec.data[0], conv);
}
}