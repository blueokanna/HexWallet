#ifndef HEXWALLET_SOLANA_DERIVATION_H
#define HEXWALLET_SOLANA_DERIVATION_H
#include <stdint.h>
namespace hexwallet {
// Preserve the existing wallet's five-component receive-address path.
// Changing this to a four-component wallet default would change its accounts.
inline bool solana_derivation_path(uint32_t account, uint32_t index, uint32_t out[5]) {
  constexpr uint32_t hardened = 0x80000000UL;
  if (out == nullptr || account >= hardened || index >= hardened) return false;
  out[0] = hardened | 44; out[1] = hardened | 501;
  out[2] = hardened | account; out[3] = hardened; out[4] = hardened | index;
  return true;
}
}
#endif
