#ifndef __LOCAL_SEGWIT_H_
#define __LOCAL_SEGWIT_H_

#include <stdint.h>
#include <vector>
#include <string>

namespace segwit_address {
std::string encode(const std::string& hrp, int witver, const std::vector<uint8_t>& witprog);

std::pair<int, std::vector<uint8_t> > decode(const std::string& hrp, const std::string& addr);

}
#endif
