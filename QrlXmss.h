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

// QRL has no BIP32 path, so the address index is folded into the domain
// separator instead. Version 1 ignored the index and every index produced the
// same address. Index zero preserves v1 for recovery; nonzero tree indices use
// v2. Old nonzero paths must be recovered as tree zero. This is a wallet-specific
// seed mapping, not QRL mnemonic compatibility, and is NOT an OTS leaf index.
WalletError qrl_seed_from_bip39(const uint8_t bip39_seed[kSeedSize],
                                uint32_t address_index,
                                uint8_t out_seed[kQrlSeedSize]);

// Verify the checksum and address-format nibble of a QRL display address.
bool qrl_address_validate(const char *address);

// Bytes of an XMSS signature for this height:
//   4 (leaf index) || 32 (r) || kWotsLen*32 (WOTS+ signature) ||
//   height*32 (auth path)
// which is 2308 at height 4 and 2372 at height 6, matching qrllib's own
// XmssBasicSHAKE256 SignatureLen test. Returns 0 for an unsupported height.
size_t qrl_xmss_signature_size(uint8_t height);

// Number of one-time signatures in a tree of this height (2^height), i.e. the
// number of leaves a key generation has to build. Returns 0 for a bad height.
uint32_t qrl_xmss_leaf_count(uint8_t height);

// XMSS one-time-signature indices are single-use: signing twice with the same
// leaf exposes the WOTS+ private key. RFC 8391 4.1.9 updates the private-key
// state before the signature is released, and 4.1.12 makes the caller
// responsible for that state. `burned_high_water` is the number of indices a
// durable ledger has already reserved or skipped, so it is also the first index
// that is still unused.
//
// qrl_ots_index_usable() answers whether `candidate` may be signed with.
// qrl_ots_next_high_water() returns the value that *must* be persisted before
// the signature leaves the device; skipped indices are burned, never reused.
bool qrl_ots_index_usable(uint8_t height, uint32_t burned_high_water,
                          uint32_t candidate);
bool qrl_ots_next_high_water(uint8_t height, uint32_t burned_high_water,
                             uint32_t candidate, uint32_t *next_high_water);

bool run_qrl_xmss_self_tests();

}  // namespace hexwallet

#endif
