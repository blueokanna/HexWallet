#ifndef HEXWALLET_QRL_V2_TRANSACTION_H
#define HEXWALLET_QRL_V2_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"
#include "MlDsa87.h"
#include "WalletSecurity.h"

namespace hexwallet {

// QRL v2.0 ("Zond") accounts and dynamic-fee transactions.
//
// An account is not a hash of a secp256k1 key. BIP32 derives a 32-byte child
// key at m/44'/238'/account'/change/index, that child becomes the ML-DSA-87
// seed, and the address is
//
//   address = SHAKE256(descriptor || public_key, 64),  descriptor = 01 00 00
//   text    = 'Q' + 128 hex digits, cases chosen EIP-55 style from another
//             SHAKE256 block over the lowercase hex body
//
// The signed object is the unsigned EIP-1559-shaped envelope, type byte 0x02:
//
//   preimage = 0x02 || rlp([chain_id, nonce, tip_cap, fee_cap, gas, to,
//                           value, data, access_list, descriptor, extra])
//   digest   = keccak256(preimage)
//   M'       = 00 08 "ZOND" 01 01 00 00 || digest      (FIPS 204, ctx "ZOND")
//   output   = signature(4627) || public_key(2592)
//
// The device hashes exactly the bytes it reviewed. `to` is either 64 bytes or
// empty for contract creation; `descriptor` is fixed to ML-DSA-87 and
// `extra_params` must be empty, because any other value would change what the
// signature means without the screen being able to explain it.
constexpr size_t kQrlV2AddressSize = 64;
constexpr size_t kQrlV2AddressTextSize = 1 + 2 * kQrlV2AddressSize + 1;
constexpr size_t kQrlV2PublicKeySize = 2592;
constexpr size_t kQrlV2SignatureSize = 4627;
constexpr size_t kQrlV2SignedSize = kQrlV2SignatureSize + kQrlV2PublicKeySize;
constexpr size_t kQrlV2MaxPreimageSize = 510;
constexpr uint32_t kQrlV2MainnetChainId = 1;
constexpr uint8_t kQrlV2Decimals = 18;

// Derives the account text from the ML-DSA seed. WalletEngine stores the seed
// as the private key, so this is the only place the mapping lives.
WalletError qrl_v2_address_from_seed(const uint8_t seed[kMlDsa87SeedSize],
                                     char *out, size_t out_size);

// Formats an ML-DSA-87 public key as a checksummed Q address.
bool qrl_v2_address_from_public_key(
    const uint8_t public_key[kQrlV2PublicKeySize], char *out, size_t out_size);

// Decodes a Q address and rejects a wrong prefix, length, character set or
// checksum casing. The raw 64-byte account is written to `out`.
bool qrl_v2_address_decode(const char *text,
                           uint8_t out[kQrlV2AddressSize]);

// Parses the preimage, rebuilds the review from the bytes that will be signed
// and stores keccak256(preimage) in `digest`.
ChainError qrl_v2_review_payload(const uint8_t *payload, size_t size,
                                 const char *sender, ChainReview *review,
                                 uint8_t digest[32]);

// Re-derives the account from `master`, refuses a sender mismatch, signs the
// reviewed digest with fresh hedging randomness, verifies its own signature
// and returns signature || public key.
ChainError qrl_v2_sign_payload(const uint8_t *payload, size_t size,
                               const char *sender, const HdPrivateNode &master,
                               uint32_t address_index, uint8_t *out,
                               size_t *in_out_size);

bool run_qrl_v2_self_tests();

}  // namespace hexwallet

#endif
