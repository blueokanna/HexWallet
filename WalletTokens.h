#ifndef HEXWALLET_TOKENS_H
#define HEXWALLET_TOKENS_H

#include <stddef.h>
#include <stdint.h>

#include "WalletNetworks.h"

namespace hexwallet {

enum class TokenStandard : uint8_t {
  Erc20,
  Spl,
};

enum TokenCapability : uint8_t {
  TokenCapabilityNone = 0,
  TokenCapabilityAccountAddress = 1 << 0,
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
const char *token_standard_text(TokenStandard standard);
bool run_token_profile_self_tests();

}  // namespace hexwallet

#endif
