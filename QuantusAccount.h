#pragma once

#include "WalletSecurity.h"

namespace hexwallet {
void quantus_account_id(const uint8_t *public_key, uint8_t account_id[32]);
WalletError quantus_derive_account(const uint8_t seed[kSeedSize], uint32_t account,
                                   uint32_t change, uint32_t index, char *address,
                                   size_t capacity, uint8_t child_seed[32]);
}
