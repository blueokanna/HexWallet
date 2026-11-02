#ifndef HEXWALLET_CUSTOM_TOKENS_H
#define HEXWALLET_CUSTOM_TOKENS_H

#include <stddef.h>
#include <stdint.h>

#include "WalletNetworks.h"

namespace hexwallet {

// User-declared tokens, across every chain this firmware can sign token
// movements on.
//
// The shipped registry (WalletTokens.cpp) is the set of contracts the firmware
// can vouch for: the issuer's address was taken from its own publication and
// the on-chain symbol/decimals/name were verified. That list can never cover
// every token a user holds, and "add whatever address the phone sends" is how a
// hardware wallet ends up signing a lookalike.
//
// This module is the middle ground. A custom token is bound to one network and
// one chain-native identifier (EVM/TRON/Starknet contract, SPL mint, Stellar
// issuer+asset code), carries the decimals its owner declared, and is marked
// UNVERIFIED everywhere it is shown. It is a convenience for the user who
// already knows the contract or mint - not an endorsement, and not a way to
// make the device trust an arbitrary selector.
//
// Records are labels, never authorization: the amount that gets signed is
// always the base-unit integer the chain carries, and a review that used a
// declared label says so on screen.
//
// Standards and identifier widths:
//   EVM        ERC-20   20-byte contract
//   TRON       TRC-20   21-byte account address (0x41 || 20-byte payload)
//   Solana     SPL      32-byte mint
//   Stellar    asset    32-byte issuer key + up to 12-byte asset code
//   Starknet   ERC-20   32-byte contract address (felt-width, not 20 bytes)
//
// Fixed resource budget: 64 user-declared assets, in addition to the shipped
// registry. Persistence buffers are allocated off the ESP task stack.
constexpr size_t kCustomTokenMax = 64;
static_assert(kCustomTokenMax <= 255, "The serialized record count is one byte");
constexpr size_t kCustomTokenNetworkSize = 16;
constexpr size_t kCustomTokenSymbolSize = 12;
constexpr size_t kCustomTokenNameSize = 24;
constexpr size_t kCustomTokenIdentifierSize = 32;
constexpr size_t kCustomTokenIssuerSize = 32;
constexpr size_t kCustomTokenCodeSize = 13;
constexpr size_t kCustomTokenContractSize = 20;  // legacy EVM width
constexpr uint8_t kCustomTokenMaxDecimals = 36;

enum class CustomTokenStandard : uint8_t {
  EvmErc20 = 0,
  TronTrc20 = 1,
  SolanaSpl = 2,
  StellarAsset = 3,
  StarknetErc20 = 4,
};

struct CustomTokenRecord {
  char network_id[kCustomTokenNetworkSize];
  CustomTokenStandard standard;
  uint8_t identifier[kCustomTokenIdentifierSize];
  uint8_t identifier_size;
  uint8_t issuer[kCustomTokenIssuerSize];  // Stellar only
  uint8_t issuer_size;
  char code[kCustomTokenCodeSize];  // Stellar asset code
  char symbol[kCustomTokenSymbolSize];
  char name[kCustomTokenNameSize];
  uint8_t decimals;
};

// Serialized size of a full table. Persistence ports size their buffer with it.
constexpr size_t kCustomTokenBlobMax =
    6 + kCustomTokenMax * (kCustomTokenNetworkSize + 1 +
                           kCustomTokenIdentifierSize + 1 +
                           kCustomTokenIssuerSize + 1 + kCustomTokenCodeSize +
                           kCustomTokenSymbolSize + kCustomTokenNameSize + 1) +
    8;

// Blob codec. The trailing digest detects corruption, not malicious edits by
// someone able to recompute it. Every load also revalidates network binding and
// uniqueness. Version 1 blobs (EVM-only records) are upgraded on load.
bool custom_token_serialize(uint8_t *out, size_t capacity, size_t *out_size);
bool custom_token_deserialize(const uint8_t *blob, size_t size,
                              CustomTokenRecord *records, size_t capacity,
                              size_t *count);

// One blob, written whole. `load` returns false when nothing has been stored or
// when the blob does not verify; the caller then starts from an empty table
// rather than guessing. `save` must be durable before it returns true.
struct CustomTokenStore {
  void *context;
  bool (*load)(void *, CustomTokenRecord *records, size_t capacity, size_t *count);
  bool (*save)(void *, const CustomTokenRecord *records, size_t count);
};

enum class CustomTokenError : uint8_t {
  Ok = 0,
  InvalidArgument,
  UnsupportedNetwork,  // no signable token path for this network
  Duplicate,
  Full,
  NotFound,
  StorageFailure,
};

// Installs the persistence backend and loads the table. Without a store the
// table lives in RAM only, which is what the host self-tests use.
bool custom_tokens_bind_store(const CustomTokenStore &store);
// Device backend: one NVS blob under the "hxctok" namespace. Returns false when
// nothing was stored yet, which the caller treats as an empty table.
bool custom_tokens_nvs_begin();

size_t custom_token_count();
bool custom_token_at(size_t index, CustomTokenRecord *out);
// Returns the stored record, or null. `identifier_size` is the chain-native
// width (20 EVM, 21 TRON, 32 Solana).
const CustomTokenRecord *custom_token_find(const char *network_id,
                                           const uint8_t *identifier,
                                           size_t identifier_size);
// Position of a record inside the table, or kCustomTokenMax when it is foreign.
// Callers that keep per-record state (a synthesised profile, for instance) use
// it instead of holding a pointer that a removal could invalidate.
size_t custom_token_index(const CustomTokenRecord *record);
// Same lookup by key, for callers that have not loaded the record yet.
size_t custom_token_index_of(const char *network_id, const uint8_t *identifier,
                             size_t identifier_size);
// Stellar assets are keyed by issuer key and asset code, not by a single
// identifier.
const CustomTokenRecord *custom_token_find_stellar(const char *network_id,
                                                   const uint8_t issuer[32],
                                                   const char *code);

// Adds a token, or replaces the one already bound to the same network+key.
// The standard is derived from the network profile's address encoding: EVM
// networks take a 20-byte contract, TRON a 21-byte address, Solana a 32-byte
// mint. Refuses everything else, empty or over-long labels, non-printable
// characters and decimals above kCustomTokenMaxDecimals. A failed write leaves
// the table unchanged.
CustomTokenError custom_token_add(const char *network_id,
                                  const uint8_t *identifier,
                                  size_t identifier_size, const char *symbol,
                                  const char *name, uint8_t decimals);
// Stellar classic assets: issuer ed25519 key + 1..12 alphanumeric asset code.
// Decimals must be 7, as required by the classic asset amount representation.
// `symbol`/`name` are display labels.
CustomTokenError custom_token_add_stellar(const char *network_id,
                                          const uint8_t issuer[32],
                                          const char *code, const char *symbol,
                                          const char *name, uint8_t decimals);

CustomTokenError custom_token_remove(const char *network_id,
                                     const uint8_t *identifier,
                                     size_t identifier_size);
CustomTokenError custom_token_remove_stellar(const char *network_id,
                                             const uint8_t issuer[32],
                                             const char *code);
const char *custom_token_error_text(CustomTokenError error);

bool run_custom_token_self_tests();

}  // namespace hexwallet

#endif
