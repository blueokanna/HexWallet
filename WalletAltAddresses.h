#ifndef HEXWALLET_ALT_ADDRESSES_H
#define HEXWALLET_ALT_ADDRESSES_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet {

// Address encoders for the non-UTXO / non-EVM networks. Each encoder is
// verified against external reference vectors in run_alt_address_self_tests().
// secp256k1 inputs are compressed unless the declaration explicitly requests
// a 65-byte uncompressed key (Filecoin/VET/ICON); Ed25519 inputs are 32 bytes.

// Zcash/Flux transparent t1/t3: base58check with a 2-byte version.
WalletError address_zcash_transparent(uint16_t p2pkh_version,
                                      uint16_t p2sh_version,
                                      const uint8_t public_key[kCompressedPublicKeySize],
                                      char *out, size_t *in_out_size);

// Render a t1/t3 address from the 25-byte P2PKH or 23-byte P2SH transparent
// scriptPubKey carried by a v4 transaction.
WalletError address_zcash_transparent_from_script(uint16_t p2pkh_version,
                                                  uint16_t p2sh_version,
                                                  const uint8_t *script,
                                                  size_t script_size,
                                                  char *out, size_t out_size);

// CashAddr (BCH/XEC) P2PKH from a compressed public key.
WalletError address_cashaddr(const char *prefix,
                             const uint8_t public_key[kCompressedPublicKeySize],
                             char *out, size_t out_size);

// CashAddr rendered straight from a P2PKH/P2SH scriptPubKey, used by the PSBT
// reviewer so a BCH input/output is never displayed as a base58 address.
WalletError address_cashaddr_from_script(const char *prefix, const uint8_t *script,
                                         size_t script_size, char *out,
                                         size_t out_size);

// Solana: plain base58 of the ed25519 public key.
WalletError address_solana(const uint8_t public_key[32], char *out,
                           size_t *in_out_size);

// Algorand: base32(ed25519 pubkey || last-4-bytes of sha512/256(pubkey)).
WalletError address_algorand(const uint8_t public_key[32], char *out,
                             size_t out_size);

// Tezos tz1: base58check(0x06a19f || blake2b-160(ed25519 pubkey)).
WalletError address_tezos_tz1(const uint8_t public_key[32], char *out,
                              size_t *in_out_size);

// XRP Ledger classic r-address: Ripple-base58check(0x00 || hash160(pubkey)).
WalletError address_ripple(const uint8_t public_key[kCompressedPublicKeySize],
                           char *out, size_t *in_out_size);

// Cardano Shelley base address: bech32("addr", header || blake2b-224(payment)
// || blake2b-224(stake)). Header byte is 0x01 for mainnet base.
WalletError address_cardano_base(const uint8_t payment_key[32],
                                 const uint8_t stake_key[32], char *out,
                                 size_t out_size);
// Bech32 "addr" encoding of already-constructed Shelley address bytes.
WalletError address_cardano_raw(const uint8_t *bytes, size_t size, char *out,
                                size_t out_size);

// Cosmos-style bech32: bech32(hrp, ripemd160(sha256(pubkey))) (CRO, SEI).
WalletError address_cosmos_bech32(const char *hrp,
                                  const uint8_t public_key[kCompressedPublicKeySize],
                                  char *out, size_t out_size);

// Avalanche X/P: "X-" + bech32(hrp, 0x00 || ripemd160(sha256(pubkey))).
WalletError address_avalanche_xp(const char *hrp,
                                 const uint8_t public_key[kCompressedPublicKeySize],
                                 char *out, size_t out_size);

// Kaspa: bech32(hrp, version 0 || x-only secp256k1 pubkey) with the Kaspa
// poly-mod checksum.
WalletError address_kaspa(const uint8_t public_key[kCompressedPublicKeySize],
                          char *out, size_t out_size);

// Qubic: base26(sha3-256(ed25519 pubkey)).
WalletError address_qubic(const uint8_t public_key[32], char *out,
                          size_t out_size);

// Filecoin f1: "f1" + base32(payload || checksum), with payload = BLAKE2b-160
// of the full 65-byte uncompressed SEC1 public key (including 0x04).
WalletError address_filecoin(const uint8_t public_key[kUncompressedPublicKeySize],
                             char *out, size_t out_size);

// Ergo mainnet P2PK: base58(0x01 || compressed pubkey || blake2b256[:4]).
WalletError address_ergo(const uint8_t public_key[kCompressedPublicKeySize],
                         char *out, size_t *in_out_size);

// VeChain: 0x + lowercase hex of keccak256(uncompressed pubkey[1..64])[12..31].
WalletError address_vechain(const uint8_t public_key[kUncompressedPublicKeySize],
                            char *out, size_t out_size);

// ICON: "hx" + lowercase hex of sha3-256(uncompressed pubkey[1..64])[12..31].
WalletError address_icon(const uint8_t public_key[kUncompressedPublicKeySize],
                         char *out, size_t out_size);

// Substrate SS58 for a 32-byte Ed25519 public key. Prefix 0 = Polkadot,
// 2 = Kusama. Only single-byte prefixes (0..63) are admitted.
WalletError address_ss58(uint8_t prefix, const uint8_t public_key[32],
                         char *out, size_t out_size);

// TON wallet v4R2 user-friendly address for a 32-byte Ed25519 public key.
// flags: 0x51 non-bounceable, 0x11 bounceable.
WalletError address_ton(const uint8_t public_key[32], uint32_t wallet_id,
                        uint8_t flags, char *out, size_t out_size);

// Decred P2PKH/P2SH: base58check with a 2-byte version and a double
// BLAKE-256 checksum. Version 0x073f is mainnet P2PKH, 0x071a is P2SH.
WalletError address_decred(uint16_t version,
                           const uint8_t public_key[kCompressedPublicKeySize],
                           char *out, size_t *in_out_size);
WalletError address_decred_from_script(uint16_t p2pkh_version,
                                       uint16_t p2sh_version,
                                       const uint8_t *script, size_t script_size,
                                       char *out, size_t out_size);

// Nervos CKB short address: bech32("ckb", 0x01 || 0x00 || args), where args
// is the first 160 bits of the personalized BLAKE2b-256 ("ckb-default-hash")
// of the compressed secp256k1 public key.
WalletError address_ckb(const uint8_t public_key[kCompressedPublicKeySize],
                        char *out, size_t out_size);
WalletError address_ckb_from_args(const uint8_t args[20], char *out,
                                  size_t out_size);

// Graphene (HIVE) public key string: "<prefix>" + base58(pubkey33 ||
// RIPEMD160(pubkey33)[0..3]). No version byte and no SHA-256 step.
WalletError address_graphene(const char *prefix,
                             const uint8_t public_key[kCompressedPublicKeySize],
                             char *out, size_t out_size);

// Internet Computer self-authenticating principal of an Ed25519 key:
// SHA-224(pubkey) || 0x02, rendered as lowercase base32(crc32 || principal)
// in dash-separated groups of five.
WalletError address_icp(const uint8_t public_key[32], char *out,
                        size_t out_size);

bool run_alt_address_self_tests();

}  // namespace hexwallet

#endif
