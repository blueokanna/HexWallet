#ifndef __LOCAL_SEGWIT_H_
#define __LOCAL_SEGWIT_H_

#include <stdint.h>
#include <vector>
#include <string>

namespace segwit_address {
/** Encode a SegWit address. Empty string means failure. */
std::string encode(const std::string& hrp, int witver, const std::vector<uint8_t>& witprog);


/** Decode a SegWit address. Returns (witver, witprog). witver = -1 means failure. */
std::pair<int, std::vector<uint8_t> > decode(const std::string& hrp, const std::string& addr);

}
#endif