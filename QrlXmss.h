#ifndef HEXWALLET_QRL_XMSS_H
#define HEXWALLET_QRL_XMSS_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet {

// QRL account keys are XMSS trees with SHAKE-256, w=16 and height 10
// (1024 one-time signatures).  The descriptor byte encodes the hash function
// (2 = SHAKE-256), the signature scheme (0 = XMSS), the height/2 nibble and
// the address format (0 = SHA256_2X).  A QRL address is the raw 39-byte
// descriptor||hash||checksum rendered as 'Q' + 78 hex characters.
//
// The NXP SE050 has no SHAKE-256 or XMSS engine, so this key material can only
// be generated in MCU RAM.  Signing is not implemented: an XMSS signature also
// consumes a stateful leaf index and requires the BDS traversal state, which
// this module deliberately does not fake.
constexpr size_t kQrlSeedSize = 48;
constexpr size_t kQrlRootSize = 32;
constexpr size_t kQrlPublicKeySize = 67;    // descriptor || root || pub_seed
constexpr size_t kQrlAddressBytes = 39;     // descriptor || sha256 || checksum
constexpr size_t kQrlAddressTextSize = 80;  // 'Q' + 78 hex + NUL
constexpr uint8_t kQrlDefaultHeight = 10;

using QrlProgressHook = bool (*)(uint32_t completed, uint32_t total, void *context);

WalletError qrl_xmss_public_key_ex(const uint8_t seed[kQrlSeedSize], uint8_t height,
                                   QrlProgressHook progress, void *context,
                                   uint8_t out_public_key[kQrlPublicKeySize]);
WalletError qrl_xmss_public_key(const uint8_t seed[kQrlSeedSize], uint8_t height,
                                uint8_t out_public_key[kQrlPublicKeySize]);

// Encode an extended public key as QRL's display address (Q + lowercase hex).
WalletError qrl_address_from_public_key(
  const uint8_t public_key[kQrlPublicKeySize], char *out, size_t out_size);

// One-shot public-key + address derivation.
WalletError qrl_xmss_address_ex(const uint8_t seed[kQrlSeedSize], uint8_t height,
                                QrlProgressHook progress, void *context,
                                char *out, size_t out_size);
WalletError qrl_xmss_address(const uint8_t seed[kQrlSeedSize], uint8_t height,
                             char *out, size_t out_size);

WalletError qrl_seed_from_bip39(const uint8_t bip39_seed[kSeedSize],
                                uint8_t out_seed[kQrlSeedSize]);

// Verify the checksum and address-format nibble of a QRL display address.
bool qrl_address_validate(const char *address);

bool run_qrl_xmss_self_tests();

}  // namespace hexwallet

#endif
