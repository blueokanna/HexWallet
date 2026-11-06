#include "QuantusAccount.h"
#include <stdlib.h>
#include <string.h>
#include "CryptoPrimitives.h"
#include "MlDsa87.h"
#include "WalletAltAddresses.h"

namespace hexwallet {
namespace {
#include "src/generated/QuantusPoseidonConstants.inc"
constexpr uint64_t kPrime = UINT64_C(0xffffffff00000001);

uint64_t add(uint64_t a, uint64_t b) {
  return a >= kPrime - b ? a - (kPrime - b) : a + b;
}

// Public key hashing only. Double-and-add avoids a platform-specific 128-bit
// integer type on Xtensa, RV32 and MSVC.
uint64_t multiply(uint64_t a, uint64_t b) {
  uint64_t result = 0;
  while (b) {
    if (b & 1) result = add(result, a);
    a = add(a, a);
    b >>= 1;
  }
  return result;
}

uint64_t sbox(uint64_t x) {
  const uint64_t square = multiply(x, x);
  return multiply(multiply(square, square), multiply(square, x));
}

void mix(uint64_t state[12]) {
  uint64_t sums[4]{};
  for (unsigned block = 0; block < 12; block += 4) {
    uint64_t *row = state + block;
    const uint64_t total = add(add(row[0], row[1]), add(row[2], row[3]));
    uint64_t mixed[4];
    for (unsigned i = 0; i < 4; ++i) {
      const uint64_t next = row[(i + 1) % 4];
      mixed[i] = add(add(total, row[i]), add(next, next));
      sums[i] = add(sums[i], mixed[i]);
    }
    memcpy(row, mixed, sizeof(mixed));
  }
  for (unsigned i = 0; i < 12; ++i) state[i] = add(state[i], sums[i % 4]);
}

void full_rounds(uint64_t state[12], const uint64_t constants[48]) {
  for (unsigned offset = 0; offset < 48; offset += 12) {
    for (unsigned i = 0; i < 12; ++i) state[i] = sbox(add(state[i], constants[offset + i]));
    mix(state);
  }
}

void permute(uint64_t state[12]) {
  mix(state);
  full_rounds(state, kFirst);
  for (uint64_t rc : kInner) {
    state[0] = sbox(add(state[0], rc));
    uint64_t sum = 0;
    for (unsigned i = 0; i < 12; ++i) sum = add(sum, state[i]);
    for (unsigned i = 0; i < 12; ++i) state[i] = add(sum, multiply(state[i], kDiag[i]));
  }
  full_rounds(state, kLast);
}

void account_id(const uint8_t *pk, uint8_t id[32]) {
  static_assert(kMlDsa87PublicKeySize % 32 == 0, "whole sponge blocks");
  uint64_t state[12]{};
  for (size_t offset = 0; offset < kMlDsa87PublicKeySize; offset += 32) {
    for (unsigned lane = 0; lane < 8; ++lane) {
      uint64_t word = 0;
      for (unsigned byte = 0; byte < 4; ++byte)
        word |= uint64_t(pk[offset + lane * 4 + byte]) << (8 * byte);
      state[lane] = add(state[lane], word);
    }
    permute(state);
  }
  state[0] = add(state[0], 1); // aligned byte-string terminator
  state[1] = add(state[1], 1); // field sponge padding
  permute(state);
  for (unsigned i = 0; i < 32; ++i) id[i] = uint8_t(state[i / 8] >> (8 * (i % 8)));
}
}

void quantus_account_id(const uint8_t *public_key, uint8_t out[32]) { account_id(public_key, out); }

WalletError quantus_derive_account(const uint8_t seed[kSeedSize], uint32_t account,
                                   uint32_t change, uint32_t index, char *address,
                                   size_t capacity, uint8_t child_seed[32]) {
  if (address && capacity) address[0] = 0;
  if (child_seed) secure_zero(child_seed, 32);
  if (!seed || !address || !capacity || !child_seed ||
      (account | change | index) >= kHardenedOffset) return WalletError::InvalidArgument;
  static const uint8_t domain[] = "Dilithium seed";
  uint8_t node[64], input[37]{}, chain_code[32];
  bool ok = crypto_hmac_sha512(domain, sizeof(domain) - 1, seed, kSeedSize, node);
  const uint32_t path[] = {44, 189189, account, change, index};
  for (uint32_t segment : path) {
    if (!ok) break;
    segment |= kHardenedOffset;
    memcpy(input + 1, node, 32);
    memcpy(chain_code, node + 32, 32);
    for (unsigned i = 0; i < 4; ++i) input[36 - i] = uint8_t(segment >> (i * 8));
    ok = crypto_hmac_sha512(chain_code, 32, input, sizeof(input), node);
  }
  WalletError result = WalletError::CryptoFailure;
  constexpr size_t bytes = kMlDsa87PublicKeySize + kMlDsa87SecretKeySize;
  uint8_t *keys = ok ? static_cast<uint8_t *>(malloc(bytes)) : nullptr;
  if (keys) {
    if (ml_dsa_87_keypair_from_seed(node, keys, keys + kMlDsa87PublicKeySize)) {
      uint8_t id[32];
      account_id(keys, id);
      result = address_ss58(189, id, address, capacity);
      if (result == WalletError::Ok) memcpy(child_seed, node, 32);
    }
    secure_zero(keys, bytes);
    free(keys);
  }
  secure_zero(chain_code, sizeof(chain_code));
  secure_zero(input, sizeof(input));
  secure_zero(node, sizeof(node));
  return result;
}
}
