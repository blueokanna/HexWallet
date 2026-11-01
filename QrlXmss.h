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
// be generated in MCU RAM. Signing requires an independent durable OTS store;
// tree traversal is recomputed with bounded RAM rather than persisted as BDS.
constexpr size_t kQrlSeedSize = 48;
constexpr size_t kQrlRootSize = 32;
constexpr size_t kQrlPublicKeySize = 67;    // descriptor || root || pub_seed
constexpr size_t kQrlAddressBytes = 39;     // descriptor || sha256 || checksum
constexpr size_t kQrlAddressTextSize = 80;  // 'Q' + 78 hex + NUL
constexpr uint8_t kQrlDefaultHeight = 10;
constexpr size_t kQrlMaxSignatureSize = 4 + 32 + 67 * 32 + 12 * 32;

using QrlProgressHook = bool (*)(uint32_t completed, uint32_t total, void *context);

enum class QrlSignError : uint8_t {
  Ok, InvalidArgument, BufferTooSmall, WrongKey, OtsUnavailable, OtsReuse,
  OtsCommitFailed, Aborted, CryptoFailure
};

// This is a storage contract, not a RAM counter or a claim that flash is safe.
// key_id = SHA256(extended public key). read must fail for unknown/restored keys.
// reserve must atomically compare the current mark with expected, persist next,
// and make rollback impossible before returning true. A failed/timed-out write
// may already have burned the index; callers must read state again, never undo.
// Stores must coordinate every signer/backup that can reconstruct this tree.
// No default backend is provided. NVS alone does not satisfy this contract.
//
// This is only the port. QrlOtsJournal.h owns the durable two-slot record and
// QrlOtsStore.h adapts one to the other; naming the port separately keeps the
// two contracts from being confused with each other.
struct QrlOtsPort {
  void *context;
  bool (*read)(void *, const uint8_t key_id[32], uint32_t *high_water);
  bool (*reserve)(void *, const uint8_t key_id[32], uint32_t expected,
                  uint32_t next_high_water);
};

// QRL v1 signs the 32-byte transaction data hash. It is not QRL v2 ML-DSA.
// The expected extended public key must have been shown to the user. A leaf is
// durably reserved before any WOTS signature is computed; failure burns it.
QrlSignError qrl_xmss_sign_digest(const uint8_t seed[kQrlSeedSize],
    const uint8_t public_key[kQrlPublicKeySize], uint32_t leaf_index,
    const uint8_t digest[32], const QrlOtsPort &storage,
    uint8_t *signature, size_t *in_out_size,
    QrlProgressHook progress = nullptr, void *context = nullptr);
bool qrl_xmss_verify_digest(const uint8_t public_key[kQrlPublicKeySize],
    const uint8_t digest[32], const uint8_t *signature, size_t signature_size);

WalletError qrl_xmss_public_key_ex(const uint8_t seed[kQrlSeedSize], uint8_t height,
                                   QrlProgressHook progress, void *context,
                                   uint8_t out_public_key[kQrlPublicKeySize]);
WalletError qrl_xmss_public_key(const uint8_t seed[kQrlSeedSize], uint8_t height,
                                uint8_t out_public_key[kQrlPublicKeySize]);

// Encode an extended public key as QRL's display address (Q + lowercase hex).
WalletError qrl_address_from_public_key(
  const uint8_t public_key[kQrlPublicKeySize], char *out, size_t out_size);
// The 39 bytes that address renders: descriptor || sha256(public key) ||
// checksum. Transaction preimages use these bytes, never the text.
WalletError qrl_address_bytes_from_public_key(
  const uint8_t public_key[kQrlPublicKeySize],
  uint8_t out_address[kQrlAddressBytes]);
// Text form of arbitrary account bytes. Validates descriptor and checksum first,
// so what the approval screen shows is the byte string that gets hashed.
WalletError qrl_address_text(const uint8_t address[kQrlAddressBytes], char *out,
                             size_t out_size);

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

// QRL v1 consensus address validation: length, format nibble and checksum only.
// Receiving addresses may have descriptors this signer cannot itself create.
bool qrl_address_validate(const char *address);
// Inverse of the text encoding. Checks the same descriptor nibble and checksum,
// so a decoded address is byte-for-byte the one that was displayed.
bool qrl_address_decode(const char *address, uint8_t out[kQrlAddressBytes]);
// The byte-level test both functions share: descriptor nibble and checksum.
// Transaction adapters validate payload recipients with this, so a destination
// accepted from a host is exactly a destination this wallet would display.
bool qrl_address_bytes_valid(const uint8_t address[kQrlAddressBytes]);

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

// --- WOTS+ (the one-time signature inside every XMSS leaf) -----------------
//
// A leaf of the XMSS tree is a WOTS+ key pair. Signing means walking each of the
// 67 hash chains a number of steps given by the message digits, so the signature
// is 67 * 32 bytes. The remaining steps rebuild the public key, which is what
// verification does - and it is also how these functions are tested here: the
// key rebuilt from a signature must equal the one wots_pkgen() derives from the
// same seed.
//
// Signed digest is the XMSS message digest, not the raw transaction hash: on
// QRL that digest is H_msg(r || root || toByte(idx, 32) || message), which is
// the piece still missing before a full XMSS signature exists. Keeping WOTS+
// separate means that gap cannot be papered over.
constexpr size_t kWotsChainCount = 67;
constexpr size_t kWotsSignatureSize = kWotsChainCount * 32;

// Produces the WOTS+ signature for one leaf of the tree identified by
// `tree_height` (QRL uses 10) and `leaf_index`.
bool qrl_wots_sign(uint8_t *signature, const uint8_t digest[32],
                   const uint8_t sk_seed[32], const uint8_t pub_seed[32],
                   uint8_t tree_height, uint32_t leaf_index);

// Rebuilds the WOTS+ public key from a signature. Comparing it with the output
// of the key generator is the only honest check that a signature is well formed
// without trusting the signer's own bookkeeping.
bool qrl_wots_recover(uint8_t *public_key, const uint8_t *signature,
                       const uint8_t digest[32], const uint8_t pub_seed[32],
                       uint8_t tree_height, uint32_t leaf_index);

// Host-safe: signature -> public key must reproduce the generated key, and a
// tampered signature must not.
bool run_qrl_wots_self_tests();
bool run_qrl_xmss_self_tests();

}  // namespace hexwallet

#endif
