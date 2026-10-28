#include "SolanaTransaction.h"
#include "CryptoExtended.h"
#include <stdio.h>
#include <string.h>
namespace {
int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}
bool unhex(const char *s, uint8_t *out, size_t capacity, size_t *size) {
  size_t n = strlen(s);
  if ((n & 1) || n/2 > capacity) return false;
  for (size_t i = 0; i < n/2; ++i) {
    int hi = nibble(s[2*i]), lo = nibble(s[2*i+1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  *size = n/2; return true;
}
void hex(const uint8_t *data, size_t size) {
  for (size_t i = 0; i < size; ++i) printf("%02x", data[i]);
  puts("");
}
}
int main(int argc, char **argv) {
  using namespace hexwallet;
  if (argc < 3 || argc > 4) return 2;
  uint8_t message[kSolanaMaxMessage], seed[kSeedSize], child[32], payer[32];
  size_t size, seed_size;
  if (!unhex(argv[1], message, sizeof(message), &size) ||
      !unhex(argv[2], seed, sizeof(seed), &seed_size) || seed_size != sizeof(seed) ||
      !solana_derive_key(seed, 0, child)) return 2;
  // Use the actual firmware Ed25519 implementation, not the SDK oracle.
  if (!hexwallet::ed25519_public_key(child, payer)) return 2;
  SolanaTransaction tx;
  memset(&tx, 0xa5, sizeof(tx));
  const SolanaError result = solana_review_message(message, size, payer, &tx);
  if (result != SolanaError::Ok) {
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&tx);
    for (size_t i = 0; i < sizeof(tx); ++i) if (bytes[i] != 0) return 3;
    printf("error=%u\n", unsigned(result)); return 1;
  }
  printf("payer="); hex(tx.payer, 32);
  printf("fee=%llu\n", static_cast<unsigned long long>(tx.estimated_fee));
  printf("total=%llu\n", static_cast<unsigned long long>(tx.total_lamports));
  for (size_t i = 0; i < tx.transfer_count; ++i) {
    printf("amount_%zu=%llu\n", i, static_cast<unsigned long long>(tx.transfers[i].amount));
    printf("recipient_%zu=", i); hex(tx.transfers[i].recipient, 32);
    printf("source_%zu=", i); hex(tx.transfers[i].source, 32);
    printf("mint_%zu=", i); hex(tx.transfers[i].mint, 32);
    printf("decimals_%zu=%u\n", i, unsigned(tx.transfers[i].decimals));
    printf("kind_%zu=%u\n", i, unsigned(tx.transfers[i].kind));
    char formatted[64];
    if (!solana_format_amount(tx.transfers[i], formatted, sizeof(formatted))) return 3;
    printf("formatted_%zu=%s\n", i, formatted);
    char small[1] = {'x'};
    if (solana_format_amount(tx.transfers[i], small, sizeof(small)) || small[0]) return 3;
  }
  if (argc == 4 && !strcmp(argv[3], "tamper")) tx.transfers[0].amount++;
  if (argc == 4 && !strcmp(argv[3], "mint")) tx.transfers[0].mint[0] ^= 1;
  if (argc == 4 && !strcmp(argv[3], "source")) tx.transfers[0].source[0] ^= 1;
  if (argc == 4 && !strcmp(argv[3], "destination")) tx.transfers[0].recipient[0] ^= 1;
  if (argc == 4 && !strcmp(argv[3], "decimals")) tx.transfers[0].decimals ^= 1;
  if (argc == 4 && !strcmp(argv[3], "kind")) tx.transfers[0].kind = SolanaTransferKind::Native;
  uint8_t wire[kSolanaMaxTransaction]; size_t wire_size = sizeof(wire);
  if (argc == 4 && !strcmp(argv[3], "small")) wire_size = 1;
  const SolanaError signed_result = solana_sign_transaction(tx, seed, wire, &wire_size);
  if (signed_result != SolanaError::Ok) {
    if (wire_size != 0) return 3;
    printf("sign_error=%u\n", unsigned(signed_result)); return 1;
  }
  printf("transaction="); hex(wire, wire_size);
  return 0;
}
