#ifndef HEXWALLET_SECURITY_H
#define HEXWALLET_SECURITY_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

constexpr size_t kPrivateKeySize = 32;
constexpr size_t kChainCodeSize = 32;
constexpr size_t kSeedSize = 64;
constexpr size_t kCompressedPublicKeySize = 33;
constexpr size_t kUncompressedPublicKeySize = 65;
constexpr size_t kExtendedKeyTextSize = 113;
constexpr size_t kCompactSignatureSize = 64;
constexpr uint32_t kHardenedOffset = 0x80000000UL;

enum class WalletError : uint8_t {
  Ok = 0,
  InvalidArgument,
  InvalidMnemonic,
  UnsupportedUnicode,
  BufferTooSmall,
  RandomFailure,
  CryptoFailure,
  InvalidKey,
  InvalidChild,
  InvalidPath,
  HardenedPublicDerivation,
};

struct HdPrivateNode {
  uint8_t private_key[kPrivateKeySize];
  uint8_t chain_code[kChainCodeSize];
  uint8_t depth;
  uint32_t parent_fingerprint;
  uint32_t child_number;
};

struct HdPublicNode {
  uint8_t public_key[kCompressedPublicKeySize];
  uint8_t chain_code[kChainCodeSize];
  uint8_t depth;
  uint32_t parent_fingerprint;
  uint32_t child_number;
};

struct RecoverableSignature {
  uint8_t r[kPrivateKeySize];
  uint8_t s[kPrivateKeySize];
  uint8_t y_parity;
};

enum class ExtendedKeyFormat : uint8_t {
  Xprv,
  Xpub,
  Zprv,
  Zpub,
  Tprv,
  Tpub,
  Vprv,
  Vpub,
};

void secure_zero(void *data, size_t length);
bool is_ascii(const char *text);

// BIP39 English implementation. Non-ASCII text is rejected because BIP39
// requires NFKD normalization, which is not provided by Arduino core.
WalletError bip39_generate_english_24(char *out, size_t out_size);
WalletError bip39_validate_english(const char *mnemonic);
WalletError bip39_seed_from_english(const char *mnemonic, const char *passphrase,
                                    uint8_t out_seed[kSeedSize]);
bool run_bip39_self_test();

WalletError public_key_from_private(const uint8_t private_key[kPrivateKeySize],
                                    uint8_t out_public_key[kCompressedPublicKeySize]);
WalletError uncompressed_public_key_from_private(
    const uint8_t private_key[kPrivateKeySize],
    uint8_t out_public_key[kUncompressedPublicKeySize]);
WalletError secp256k1_sign_digest_recoverable(
    const uint8_t private_key[kPrivateKeySize],
    const uint8_t digest[kPrivateKeySize], RecoverableSignature *out_signature);
WalletError hd_private_from_seed(const uint8_t *seed, size_t seed_size,
                                 HdPrivateNode *out_node);
WalletError hd_private_derive(const HdPrivateNode *parent, uint32_t index,
                              HdPrivateNode *out_node);
WalletError hd_public_neuter(const HdPrivateNode *private_node, HdPublicNode *out_node);
WalletError hd_public_derive(const HdPublicNode *parent, uint32_t index,
                             HdPublicNode *out_node);
WalletError hd_private_derive_path(const HdPrivateNode *master, const char *path,
                                   HdPrivateNode *out_node);
WalletError hd_serialize_private(const HdPrivateNode *node, ExtendedKeyFormat format,
                                 char *out, size_t *in_out_size);
WalletError hd_serialize_public(const HdPublicNode *node, ExtendedKeyFormat format,
                                char *out, size_t *in_out_size);

// Checks the BIP32 non-hardened public/private derivation invariant. It never
// emits key material to serial; external official vectors remain mandatory in CI.
bool run_bip32_self_test();
bool run_secp256k1_self_test();

}  // namespace hexwallet

#endif
