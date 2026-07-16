#ifndef HEXWALLET_NETWORKS_H
#define HEXWALLET_NETWORKS_H

#include <stddef.h>
#include <stdint.h>

#include "WalletAddresses.h"

namespace hexwallet {

enum class AddressEncoding : uint8_t {
  P2pkh,
  P2shP2wpkh,
  P2wpkh,
  Evm,
  Tron,
};

struct NetworkProfile {
  const char *id;
  const char *symbol;
  const char *name;
  uint32_t slip44_coin_type;
  uint32_t bip_purpose;
  AddressEncoding encoding;
  UtxoAddressProfile utxo;
  uint8_t account_version;
};

extern const NetworkProfile kNetworkProfiles[];
extern const size_t kNetworkProfileCount;

const NetworkProfile *find_network_profile(const char *id);

}  // namespace hexwallet

#endif
