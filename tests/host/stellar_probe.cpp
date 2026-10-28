#include "StellarTransaction.h"
#include "CryptoExtended.h"
#include "WalletEngine.h"
#include "WalletCustody.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
namespace {
int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}
bool unhex(const char *s, uint8_t *out, size_t capacity, size_t *size) {
  const size_t n = strlen(s);
  if ((n & 1) || n/2 > capacity) return false;
  for (size_t i = 0; i < n/2; ++i) {
    const int hi = nibble(s[2*i]), lo = nibble(s[2*i+1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  *size = n/2; return true;
}
void hex(const uint8_t *b, size_t size) {
  for (size_t i = 0; i < size; ++i) printf("%02x", b[i]);
  puts("");
}
}
int main(int argc, char **argv) {
  using namespace hexwallet;
  if (argc < 4 || argc > 5) return 2;
  uint8_t data[kStellarMaxRequest], seed[kSeedSize], child[32], owner[32];
  size_t size, seed_size;
  const uint32_t index = static_cast<uint32_t>(strtoul(argv[3], nullptr, 10));
  if (!unhex(argv[1], data, sizeof(data), &size) ||
      !unhex(argv[2], seed, sizeof(seed), &seed_size) || seed_size != sizeof(seed)) return 2;
  if (!stellar_derive_key(seed, index, child) || !ed25519_public_key(child, owner)) {
    puts("error=derive"); return 1;
  }
  StellarTransaction tx;
  memset(&tx, 0xa5, sizeof(tx));
  const StellarError e = stellar_review_request(data, size, owner, &tx);
  if (e != StellarError::Ok) {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&tx);
    for (size_t i = 0; i < sizeof(tx); ++i) if (p[i]) return 3;
    printf("error=%u\n", unsigned(e)); return 1;
  }
  tx.address_index = index;
  const NetworkProfile *network = find_network_profile("xlm");
  HdPrivateNode unused_master = {};
  DerivedAddress derived = {};
  if (!network || key_scheme_for(*network) != KeyScheme::Ed25519Eddsa ||
      derive_address(unused_master, seed, *network, 0, 0, index, &derived) != WalletError::Ok ||
      strcmp(derived.address, tx.review.source) || memcmp(derived.private_key, child, 32)) return 3;
  printf("path=%s\n", derived.path);
  clear_derived_address(&derived);
  if (derive_address(unused_master, seed, *network, 1, 0, index, &derived) == WalletError::Ok ||
      derive_address(unused_master, seed, *network, 0, 1, index, &derived) == WalletError::Ok) return 3;
  printf("source=%s\nfee=%u\nsequence=%llu\nmin_time=%llu\nmax_time=%llu\nmemo_type=%u\nmemo=%s\ncount=%u\n",
      tx.review.source, unsigned(tx.review.fee), static_cast<unsigned long long>(tx.review.sequence),
      static_cast<unsigned long long>(tx.review.min_time), static_cast<unsigned long long>(tx.review.max_time),
      unsigned(tx.review.memo_type), tx.review.memo, unsigned(tx.review.operation_count));
  printf("hash="); hex(tx.signing_hash, 32);
  for (size_t i = 0; i < tx.review.operation_count; ++i) {
    const auto &op = tx.review.operations[i];
    printf("destination_%zu=%s\nissuer_%zu=%s\nasset_%zu=%s\namount_%zu=%llu\nformatted_%zu=%s\ntype_%zu=%u\n",
        i, op.destination, i, op.issuer, i, op.asset, i, static_cast<unsigned long long>(op.amount),
        i, op.amount_text, i, unsigned(op.type));
  }
  const char *mode = argc == 5 ? argv[4] : "";
  if (!strcmp(mode,"amount")) tx.review.operations[0].amount++;
  if (!strcmp(mode,"destination")) tx.review.operations[0].destination[2] ^= 1;
  if (!strcmp(mode,"issuer")) tx.review.operations[0].issuer[0] ^= 1;
  if (!strcmp(mode,"asset")) tx.review.operations[0].asset[0] ^= 1;
  if (!strcmp(mode,"formatted")) tx.review.operations[0].amount_text[0] ^= 1;
  if (!strcmp(mode,"type")) tx.review.operations[0].type ^= 1;
  if (!strcmp(mode,"source")) tx.review.source[2] ^= 1;
  if (!strcmp(mode,"fee")) tx.review.fee++;
  if (!strcmp(mode,"sequence")) tx.review.sequence++;
  if (!strcmp(mode,"min_time")) tx.review.min_time++;
  if (!strcmp(mode,"max_time")) tx.review.max_time++;
  if (!strcmp(mode,"memo_type")) tx.review.memo_type ^= 1;
  if (!strcmp(mode,"memo")) tx.review.memo[0] ^= 1;
  if (!strcmp(mode,"count")) tx.review.operation_count++;
  if (!strcmp(mode,"hash")) tx.signing_hash[0] ^= 1;
  if (!strcmp(mode,"raw")) tx.request[80] ^= 1;
  if (!strcmp(mode,"index")) tx.address_index++;
  if (!strcmp(mode,"size")) tx.request_size = kStellarMaxRequest + 1;
  uint8_t wire[kStellarMaxEnvelope]; memset(wire, 0xa5, sizeof(wire));
  size_t wire_size = !strcmp(mode,"small") ? 1 : sizeof(wire);
  const StellarError result = stellar_sign_transaction(tx, seed, wire, &wire_size);
  if (result != StellarError::Ok) {
    if (wire_size != 0) return 3;
    for (uint8_t b : wire) if (b != 0xa5) return 3;
    printf("sign_error=%u\n", unsigned(result)); return 1;
  }
  printf("transaction="); hex(wire, wire_size);
  return 0;
}
