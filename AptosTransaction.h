#ifndef HEXWALLET_APTOS_TRANSACTION_H
#define HEXWALLET_APTOS_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet {

// Aptos native APT transfers.
//
// Aptos signs a hash, not a serialized transaction:
//   authenticator = Ed25519(sha3_256("APTOS::RawTransaction" || BCS(RawTransaction)))
// and the account address is sha3_256(public_key || 0x00). Both the domain
// separator and the trailing scheme byte are easy to drop and produce a
// signature the VM rejects, so this adapter builds the RawTransaction itself
// from the fields it displays and never signs a host-supplied hash.
//
// RawTransaction BCS (aptos-core generate-format tests/staged/aptos.yaml):
//   sender: 32 | sequence_number: u64 | payload: enum |
//   max_gas_amount: u64 | gas_unit_price: u64 |
//   expiration_timestamp_secs: u64 | chain_id: u8
// The admitted payload is TransactionPayload::EntryFunction (variant 2) for
// 0x1::aptos_account::transfer with arguments [recipient(32), amount(u64)].
//
// Payload "APT1":
//   0  "APT1"
//   4  u8  chain_id            (1 = mainnet, 2 = testnet)
//   5  u8  kind                (must be 0: aptos_account::transfer)
//   6  u64 max_gas_be
//   14 u64 gas_unit_price_be
//   22 u64 expiration_seconds_be   (unix seconds; cannot be checked offline)
//   30 u32 sequence_be             (account sequence number)
//   34 u8  recipient[32]
//   66 u64 amount_be               (octas, 1 APT = 1e8 octas)
constexpr size_t kAptosAddressTextSize = 67;   // "0x" + 64 hex + NUL
constexpr size_t kAptosAddressSize = 32;
constexpr size_t kAptosPayloadSize = 74;
constexpr uint8_t kAptosDecimals = 8;
constexpr uint8_t kAptosMainnetChainId = 1;
constexpr uint8_t kAptosTestnetChainId = 2;
constexpr size_t kAptosAuthenticatorSize = 1 + 64 + 32;

// 0x + sha3_256(public_key || 0x00), the single-signer account address.
bool aptos_address(const uint8_t public_key[kAptosAddressSize], char *out,
                   size_t capacity);

// Parses the payload and derives the signing message. No signing happens here.
ChainError aptos_review_payload(const uint8_t *payload, size_t size,
                                const char *sender, ChainReview *review,
                                uint8_t digest[32]);

// Rebuilds the RawTransaction from the payload, checks that `sender` is the
// account `private_key` controls, and returns the 0x00 || signature || public
// key authenticator the host embeds in a SignedTransaction.
ChainError aptos_sign_payload(const uint8_t *payload, size_t size,
                              const char *sender,
                              const uint8_t private_key[kPrivateKeySize],
                              uint8_t *out, size_t *in_out_size);

bool run_aptos_self_tests();

}  // namespace hexwallet

#endif
