// Temporary diagnostic harness: prints hex output of each extended primitive
// so failures can be located without instrumenting the production self-tests.
#include <stdio.h>
#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/md.h>

#include "../../CryptoExtended.h"
#include "../../CryptoPrimitives.h"
#include "../../WalletAltAddresses.h"

static void print_hex(const char *label, const uint8_t *data, size_t size) {
  printf("%-28s ", label);
  for (size_t i = 0; i < size; ++i) printf("%02x", data[i]);
  printf("\n");
}

int main() {
  uint8_t out[64];
  char text[256];

  const uint8_t abc[] = {'a', 'b', 'c'};

  if (hexwallet::crypto_sha3_256(abc, 3, out))
    print_hex("sha3_256(abc)", out, 32);

  if (hexwallet::crypto_sha512_256(abc, 3, out))
    print_hex("sha512_256(abc)", out, 32);

  if (hexwallet::crypto_blake2b(abc, 3, out, 64))
    print_hex("blake2b512(abc)", out, 64);
  if (hexwallet::crypto_blake2b(abc, 3, out, 32))
    print_hex("blake2b256(abc)", out, 32);

  if (hexwallet::base32_encode(abc, 3, text, sizeof(text), false, true))
    printf("%-28s %s\n", "base32(foo)", text);

  const uint8_t cash[20] = {0x76,0xa0,0x40,0x53,0xbd,0xa0,0xa8,0x8b,0xda,0x51,
                            0x77,0xb8,0x6a,0x15,0xc3,0xb2,0x9f,0x55,0x98,0x73};
  if (hexwallet::cashaddr_encode("bitcoincash", 0, cash, 20, text, sizeof(text)))
    printf("%-28s %s\n", "cashaddr", text);

  const uint8_t bech[20] = {0x75,0x1e,0x76,0xe8,0x19,0x91,0x96,0xd4,0x54,0x94,
                            0x1c,0x45,0xd1,0xb3,0xa3,0x23,0xf1,0x43,0x3b,0xd6};
  if (hexwallet::bech32_encode("bc", bech, 20, text, sizeof(text), false))
    printf("%-28s %s\n", "bech32", text);
  uint8_t bechv[21] = {0};
  memcpy(bechv + 1, bech, 20);
  if (hexwallet::bech32_encode("bc", bechv, 21, text, sizeof(text), false))
    printf("%-28s %s\n", "bech32-ver", text);

  const uint8_t bech32m[32] = {0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,
                               0x62,0x95,0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,
                               0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,0x16,0xf8,
                               0x17,0x98};
  if (hexwallet::bech32_encode("bc", bech32m, 32, text, sizeof(text), true))
    printf("%-28s %s\n", "bech32m", text);
  uint8_t bech32mv[33] = {0};
  bech32mv[0] = 1;
  memcpy(bech32mv + 1, bech32m, 32);
  if (hexwallet::bech32_encode("bc", bech32mv, 33, text, sizeof(text), true))
    printf("%-28s %s\n", "bech32m-ver", text);

  uint8_t zeros[32] = {0};
  if (hexwallet::kaspa_bech32_encode("kaspa", 0, zeros, 32, text, sizeof(text)))
    printf("%-28s %s\n", "kaspa-zero", text);

  // mbedtls shim sanity (used by Ed25519/BLS down the line).
  if (hexwallet::crypto_sha256(abc, 3, out))
    print_hex("sha256(abc)", out, 32);

  const mbedtls_md_info_t *info512 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  if (info512 && mbedtls_md(info512, abc, 3, out) == 0)
    print_hex("md sha512(abc)", out, 64);
  const mbedtls_md_info_t *info256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info256 && mbedtls_md(info256, abc, 3, out) == 0)
    print_hex("md sha256(abc)", out, 32);

  // Incremental SHA-512: feed "abc" one byte at a time.
  {
    uint8_t inc[64];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int r = mbedtls_md_setup(&ctx, info512, 0);
    if (r == 0) r = mbedtls_md_starts(&ctx);
    for (int i = 0; i < 3 && r == 0; ++i) r = mbedtls_md_update(&ctx, abc + i, 1);
    if (r == 0) r = mbedtls_md_finish(&ctx, inc);
    mbedtls_md_free(&ctx);
    printf("%-28s ", "md sha512 inc(abc)");
    for (int i = 0; i < 64; ++i) printf("%02x", inc[i]);
    printf("\n");
  }

  // Exact R || A bytes from the sign path.
  {
    uint8_t R2[32] = {0x42,0x9a,0xea,0x64,0xed,0x4e,0xe7,0x6b,0x8e,0x80,0x28,0x5d,0xda,0xd3,0x34,0xcd,0xf1,0x46,0x0e,0x2f,0xfe,0x9d,0xe0,0xf0,0x69,0x2c,0xd3,0xba,0xff,0x04,0x2a,0x73};
    uint8_t A2[32] = {0x40,0xb0,0xf4,0x98,0xa1,0x6f,0x2b,0x94,0x3d,0x74,0xdc,0x4f,0x9d,0x4a,0xcc,0x05,0xd0,0xde,0x9c,0x93,0x5d,0xd5,0x69,0xae,0x83,0x1c,0xf8,0xfc,0xdd,0x4e,0x3f,0xeb};
    uint8_t combo[64], one[64], inc[64];
    memcpy(combo, R2, 32);
    memcpy(combo + 32, A2, 32);
    mbedtls_md(info512, combo, 64, one);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int r = mbedtls_md_setup(&ctx, info512, 0);
    if (r == 0) r = mbedtls_md_starts(&ctx);
    if (r == 0) r = mbedtls_md_update(&ctx, R2, 32);
    if (r == 0) r = mbedtls_md_update(&ctx, A2, 32);
    if (r == 0) r = mbedtls_md_finish(&ctx, inc);
    mbedtls_md_free(&ctx);
    printf("%-28s ", "sha512(R||A) one-shot");
    for (int i = 0; i < 64; ++i) printf("%02x", one[i]);
    printf("\n%-28s ", "sha512(R||A) incremental");
    for (int i = 0; i < 64; ++i) printf("%02x", inc[i]);
    printf("\n%-28s %s\n", "expect first32", "7ae02b1b15a0bd9d7bf184bebc3f3f5d48f29c4f8f7b09e8c5c3e0c98b273a22");
  }

  static const uint8_t key[] = {'k', 'e', 'y'};
  static const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";
  if (hexwallet::crypto_hmac_sha256(key, 3, msg, 43, out))
    print_hex("hmac_sha256", out, 32);

  // RFC 4231 test case 1: HMAC-SHA-512, key = 0x0b * 20, data = "Hi There".
  uint8_t hmac_key[20];
  memset(hmac_key, 0x0b, sizeof(hmac_key));
  static const uint8_t hi_there[] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
  if (hexwallet::crypto_hmac_sha512(hmac_key, sizeof(hmac_key), hi_there,
                                    sizeof(hi_there), out))
    print_hex("hmac_sha512(TC1)", out, 64);
  static const uint8_t hmac_abc_key[] = {'k', 'e', 'y'};
  static const uint8_t abc_msg[] = {'a', 'b', 'c'};
  if (hexwallet::crypto_hmac_sha512(hmac_abc_key, 3, abc_msg, 3, out))
    print_hex("hmac_sha512(key,abc)", out, 64);

  // Ed25519 RFC 8032 TC1: seed all-0x9d, pubkey d75a9801...
  uint8_t seed[32];
  memset(seed, 0x9d, 32);
  if (hexwallet::ed25519_public_key(seed, out))
    print_hex("ed25519_pk(TC1)", out, 32);
  uint8_t sig[64];
  if (hexwallet::ed25519_sign(seed, (const uint8_t *)"", 0, sig))
    print_hex("ed25519_sig(TC1,empty)", sig, 64);

  // Real RFC 8032 TC1 seed.
  {
    static const uint8_t tc1seed[32] = {0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60};
    if (hexwallet::ed25519_public_key(tc1seed, out))
      print_hex("ed25519_pk(realTC1)", out, 32);
    if (hexwallet::ed25519_sign(tc1seed, (const uint8_t *)"", 0, sig))
      print_hex("ed25519_sig(realTC1)", sig, 64);
  }

  // SLIP-10 vector 1: 16-byte seed 000102...0f.
  uint8_t slip_seed[16];
  for (int i = 0; i < 16; ++i) slip_seed[i] = (uint8_t)i;
  uint32_t path[] = {0x80000000u};
  if (hexwallet::slip10_ed25519_derive(slip_seed, sizeof(slip_seed), path, 1, out))
    print_hex("slip10 child 0'", out, 32);

  // BLS sk=1.
  uint8_t sk1[32] = {0};
  sk1[31] = 1;
  if (hexwallet::bls12_381_g1_public_key(sk1, out))
    print_hex("bls pk(sk=1)", out, 48);

  // mbedtls_mpi shim sanity checks.
  {
    mbedtls_mpi a, b, c;
    mbedtls_mpi_init(&a); mbedtls_mpi_init(&b); mbedtls_mpi_init(&c);
    // 3^100 mod 7 == 4
    mbedtls_mpi_lset(&a, 3);
    mbedtls_mpi_lset(&b, 7);
    mbedtls_mpi t;
    mbedtls_mpi_init(&t);
    mbedtls_mpi_lset(&t, 100);
    int r1 = mbedtls_mpi_exp_mod(&c, &a, &t, &b, NULL);
    uint8_t cbin[64];
    memset(cbin, 0, sizeof(cbin));
    mbedtls_mpi_write_binary(&c, cbin, sizeof(cbin));
    printf("%-28s rc=%d bytes: ", "mpi 3^100 mod 7", r1);
    for (int k = 0; k < 64; ++k) printf("%02x", cbin[k]);
    printf("\n");
    // P mod P == 0
    mbedtls_mpi P, zero;
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&zero);
    mbedtls_mpi_read_string(&P, 16,
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
    mbedtls_mpi_mod_mpi(&zero, &P, &P);
    printf("%-28s %s\n", "mpi P mod P", mbedtls_mpi_cmp_int(&zero, 0) == 0 ? "0 OK" : "WRONG");
    mbedtls_mpi_free(&a); mbedtls_mpi_free(&b); mbedtls_mpi_free(&c);
    mbedtls_mpi_free(&t); mbedtls_mpi_free(&P); mbedtls_mpi_free(&zero);
  }

  // EIP-2333 master from seed = 000102..0f.
  if (hexwallet::eip2333_master_key(slip_seed, sizeof(slip_seed), out))
    print_hex("eip2333 master", out, 32);

  // Chia address for the same seed.
  if (hexwallet::chia_standard_address(slip_seed, sizeof(slip_seed), 0, text, sizeof(text)))
    printf("%-28s %s\n", "chia addr", text);

  // Chia addresses for the self-test seeds.
  {
    static const uint8_t eip_seed[64] = {
        0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72, 0x02, 0x9a, 0xeb,
        0xc1, 0xb5, 0x3c, 0x05, 0xed, 0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad,
        0x3e, 0x3e, 0x9e, 0xfa, 0x37, 0x08, 0xe5, 0x34, 0x95, 0x53, 0x1f,
        0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82, 0x64, 0xc1, 0xe1, 0xc9,
        0x2f, 0x2c, 0xf1, 0x41, 0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8,
        0x1b, 0x2f, 0x00, 0x16, 0x98, 0xe7, 0x46, 0x3b, 0x04,
    };
    if (hexwallet::chia_standard_address(eip_seed, sizeof(eip_seed), 0, text, sizeof(text)))
      printf("%-28s %s\n", "chia v0", text);
    uint8_t ones[64];
    memset(ones, 0x01, sizeof(ones));
    if (hexwallet::chia_standard_address(ones, sizeof(ones), 0, text, sizeof(text)))
      printf("%-28s %s\n", "chia ones", text);
  }

  // Alt addresses: raw ed25519 pubkey from TC1-style seed 000102..1f.
  if (hexwallet::ed25519_public_key(slip_seed, out)) {
    char addr[256];
    size_t addr_size = sizeof(addr);
    if (hexwallet::address_solana(out, addr, &addr_size) == hexwallet::WalletError::Ok)
      printf("%-28s %s\n", "solana", addr);
    if (hexwallet::address_algorand(out, addr, sizeof(addr)) == hexwallet::WalletError::Ok)
      printf("%-28s %s\n", "algorand", addr);
    addr_size = sizeof(addr);
    if (hexwallet::address_tezos_tz1(out, addr, &addr_size) == hexwallet::WalletError::Ok)
      printf("%-28s %s\n", "tezos", addr);
    if (hexwallet::address_qubic(out, addr, sizeof(addr)) == hexwallet::WalletError::Ok)
      printf("%-28s %s\n", "qubic", addr);
  }

  // cashaddr for kPkOne (priv=1 compressed secp256k1 pubkey).
  {
    static const uint8_t pk1[33] = {0x02,0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98};
    char a[256];
    if (hexwallet::address_cashaddr("bitcoincash", pk1, a, sizeof(a)) == hexwallet::WalletError::Ok)
      printf("%-28s %s\n", "cashaddr bch", a);
    if (hexwallet::address_cashaddr("ecash", pk1, a, sizeof(a)) == hexwallet::WalletError::Ok)
      printf("%-28s %s\n", "cashaddr xec", a);
    if (hexwallet::address_avalanche_xp("avax", pk1, a, sizeof(a)) == hexwallet::WalletError::Ok)
      printf("%-28s %s\n", "avax", a);
    if (hexwallet::address_cosmos_bech32("cro", pk1, a, sizeof(a)) == hexwallet::WalletError::Ok)
      printf("%-28s %s\n", "cro", a);
    if (hexwallet::address_cosmos_bech32("sei", pk1, a, sizeof(a)) == hexwallet::WalletError::Ok)
      printf("%-28s %s\n", "sei", a);
  }

  // Cardano base (payment == stake == kEdPk) diagnostic.
  {
    static const uint8_t ked[32] = {
        0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb,
        0x2d, 0x3c, 0xba, 0x5d, 0x72, 0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94,
        0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
    };
    char a[256];
    if (hexwallet::address_cardano_base(ked, ked, a, sizeof(a)) == hexwallet::WalletError::Ok)
      printf("%-28s %s\n", "cardano", a);
  }

  return 0;
}
