#ifndef HEXWALLET_TOKENS_H
#define HEXWALLET_TOKENS_H

#include <stddef.h>
#include <stdint.h>

#include "TokenCalldata.h"
#include "WalletNetworks.h"

namespace hexwallet {

enum class TokenStandard : uint8_t {
  Erc20,
  Erc721,
  Erc1155,
  Erc4626,
  Erc777,
  Erc3525,
  Erc6551,
  LayerZeroOft,
  LayerZeroOnft,
  Spl,
};

enum TokenCapability : uint8_t {
  TokenCapabilityNone = 0,
  TokenCapabilityAccountAddress = 1 << 0,
  TokenCapabilityTransferSigning = 1 << 1,
};

struct TokenProfile {
  const char *id;
  const char *network_id;
  const char *symbol;
  const char *name;
  TokenStandard standard;
  const char *contract_or_mint;
  uint8_t decimals;
  uint8_t capabilities;
  const char *status;
};

extern const TokenProfile kTokenProfiles[];
extern const size_t kTokenProfileCount;

const TokenProfile *find_token_profile(const char *id);
const NetworkProfile *token_network(const TokenProfile &token);
bool token_supports_account_address(const TokenProfile &token);
bool token_supports_transfer_signing(const TokenProfile &token);
WalletError token_spl_account_address(const TokenProfile &token,
                                      const uint8_t owner_seed[32],
                                      char *out, size_t out_size);
const char *token_standard_text(TokenStandard standard);
EvmTokenStandard token_evm_standard(TokenStandard standard);
bool run_token_profile_self_tests();

}  // namespace hexwallet

#endif
