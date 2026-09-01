#ifndef HEXWALLET_ALT_ADDRESSES_H
#define HEXWALLET_ALT_ADDRESSES_H

#include <stddef.h>
#include <stdint.h>

#include "WalletSecurity.h"

namespace hexwallet {

// Address encoders for the non-UTXO / non-EVM networks. Each encoder is
// verified against external reference vectors in run_alt_address_self_tests().
// All secp256k1 inputs are compressed public keys; ed25519 inputs are the
// 32-byte public key.

// Zcash/Flux transparent t1/t3: base58check with a 2-byte version.
WalletError address_zcash_transparent(uint16_t p2pkh_version,
                                      uint16_t p2sh_version,
                                      const uint8_t public_key[kCompressedPublicKeySize],
                                      char *out, size_t *in_out_size);

// CashAddr (BCH/XEC) P2PKH from a compressed public key.
WalletError address_cashaddr(const char *prefix,
                             const uint8_t public_key[kCompressedPublicKeySize],
                             char *out, size_t out_size);

// Solana: plain base58 of the ed25519 public key.
WalletError address_solana(const uint8_t public_key[32], char *out,
                           size_t *in_out_size);

// Algorand: base32(ed25519 pubkey || last-4-bytes of sha512/256(pubkey)).
WalletError address_algorand(const uint8_t public_key[32], char *out,
                             size_t out_size);

// Tezos tz1: base58check(0x06a19f || blake2b-160(ed25519 pubkey)).
WalletError address_tezos_tz1(const uint8_t public_key[32], char *out,
                              size_t *in_out_size);

// Cardano Shelley base address: bech32("addr", header || blake2b-224(payment)
// || blake2b-224(stake)). Header byte is 0x01 for mainnet base.
WalletError address_cardano_base(const uint8_t payment_key[32],
                                 const uint8_t stake_key[32], char *out,
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

// Filecoin f1: base32-lower-nopad(0x01 || blake2b-160(secp256k1 pubkey)).
WalletError address_filecoin(const uint8_t public_key[kCompressedPublicKeySize],
                             char *out, size_t out_size);

// Ergo mainnet P2PK: base58(0x01 || compressed pubkey || blake2b256[:4]).
WalletError address_ergo(const uint8_t public_key[kCompressedPublicKeySize],
                         char *out, size_t *in_out_size);

bool run_alt_address_self_tests();

}  // namespace hexwallet

#endif
