/* Host-side implementation of the mbedtls subset used by HexWallet, for
 * compiling and running the firmware self-tests on a developer machine.
 * This file is NOT shipped to the device; on ESP32 the real mbedtls library
 * (bundled with the Arduino core) provides these symbols. It compiles against
 * the exact mbedtls headers from the ESP32 core so the API surface matches. */
#include "mbedtls/md.h"
#include "mbedtls/bignum.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* SHA-256                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
  uint32_t state[8];
  uint64_t total;
  uint8_t buffer[64];
  size_t used;
} host_sha256_ctx;

static const uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static uint32_t rotr32(uint32_t v, int n) {
  return (v >> n) | (v << (32 - n));
}

static void sha256_block(host_sha256_ctx *ctx, const uint8_t block[64]) {
  uint32_t w[64];
  int i;
  for (i = 0; i < 16; i++) {
    w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
           ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
  }
  for (i = 16; i < 64; i++) {
    uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
  uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
  for (i = 0; i < 64; i++) {
    uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + s1 + ch + kSha256K[i] + w[i];
    uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = s0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
  ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(host_sha256_ctx *ctx) {
  ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
  ctx->total = 0;
  ctx->used = 0;
}

static void sha256_update(host_sha256_ctx *ctx, const uint8_t *data, size_t size) {
  ctx->total += size;
  while (size > 0) {
    size_t take = 64 - ctx->used;
    if (take > size) take = size;
    memcpy(ctx->buffer + ctx->used, data, take);
    ctx->used += take;
    data += take;
    size -= take;
    if (ctx->used == 64) {
      sha256_block(ctx, ctx->buffer);
      ctx->used = 0;
    }
  }
}

static void sha256_finish(host_sha256_ctx *ctx, uint8_t out[32]) {
  uint64_t bits = ctx->total * 8;
  uint8_t pad = 0x80;
  sha256_update(ctx, &pad, 1);
  uint8_t zero = 0;
  while (ctx->used != 56) sha256_update(ctx, &zero, 1);
  uint8_t len[8];
  int i;
  for (i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - i * 8));
  sha256_update(ctx, len, 8);
  for (i = 0; i < 8; i++) {
    out[i * 4] = (uint8_t)(ctx->state[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
    out[i * 4 + 3] = (uint8_t)ctx->state[i];
  }
}

/* ------------------------------------------------------------------ */
/* SHA-512                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
  uint64_t state[8];
  uint64_t total;
  uint8_t buffer[128];
  size_t used;
} host_sha512_ctx;

static const uint64_t kSha512K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static uint64_t rotr64(uint64_t v, int n) {
  return (v >> n) | (v << (64 - n));
}

static void sha512_block(host_sha512_ctx *ctx, const uint8_t block[128]) {
  uint64_t w[80];
  int i;
  for (i = 0; i < 16; i++) {
    w[i] = 0;
    int j;
    for (j = 0; j < 8; j++) w[i] = (w[i] << 8) | block[i * 8 + j];
  }
  for (i = 16; i < 80; i++) {
    uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
    uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint64_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
  uint64_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
  for (i = 0; i < 80; i++) {
    uint64_t s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
    uint64_t ch = (e & f) ^ (~e & g);
    uint64_t t1 = h + s1 + ch + kSha512K[i] + w[i];
    uint64_t s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
    uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint64_t t2 = s0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
  ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha512_init(host_sha512_ctx *ctx) {
  ctx->state[0] = 0x6a09e667f3bcc908ULL; ctx->state[1] = 0xbb67ae8584caa73bULL;
  ctx->state[2] = 0x3c6ef372fe94f82bULL; ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
  ctx->state[4] = 0x510e527fade682d1ULL; ctx->state[5] = 0x9b05688c2b3e6c1fULL;
  ctx->state[6] = 0x1f83d9abfb41bd6bULL; ctx->state[7] = 0x5be0cd19137e2179ULL;
  ctx->total = 0;
  ctx->used = 0;
}

static void sha512_update(host_sha512_ctx *ctx, const uint8_t *data, size_t size) {
  ctx->total += size;
  while (size > 0) {
    size_t take = 128 - ctx->used;
    if (take > size) take = size;
    memcpy(ctx->buffer + ctx->used, data, take);
    ctx->used += take;
    data += take;
    size -= take;
    if (ctx->used == 128) {
      sha512_block(ctx, ctx->buffer);
      ctx->used = 0;
    }
  }
}

static void sha512_finish(host_sha512_ctx *ctx, uint8_t out[64]) {
  uint64_t bits = ctx->total * 8;
  uint8_t pad = 0x80;
  sha512_update(ctx, &pad, 1);
  uint8_t zero = 0;
  if (ctx->used > 112) {
    /* 0x80 overflowed this block: flush it, then start a fresh padding block. */
    while (ctx->used != 0) sha512_update(ctx, &zero, 1);
  }
  while (ctx->used != 112) sha512_update(ctx, &zero, 1);
  /* 128-bit big-endian length: the 64-bit bit count goes in the LOW half
     (bytes 120..127), the high half is zero (messages are < 2^64 bits).
     NB: shifting the 64-bit counter by >= 64 (e.g. `bits >> 120`) is
     undefined behaviour and clang fills those bytes with garbage, so write
     only the low 8 bytes into a zero-initialized array. */
  uint8_t len[16] = {0};
  int i;
  for (i = 0; i < 8; i++) len[i + 8] = (uint8_t)(bits >> (56 - i * 8));
  sha512_update(ctx, len, 16);
  for (i = 0; i < 8; i++) {
    int j;
    for (j = 0; j < 8; j++) out[i * 8 + j] = (uint8_t)(ctx->state[i] >> (56 - j * 8));
  }
}

/* ------------------------------------------------------------------ */
/* HMAC                                                                */
/* ------------------------------------------------------------------ */

static void hmac(const uint8_t *key, size_t key_len, const uint8_t *data,
                 size_t data_len, int is512, uint8_t out[64]) {
  uint8_t k[128];
  uint8_t ipad[128], opad[128];
  size_t block = is512 ? 128 : 64;
  size_t i;
  memset(k, 0, sizeof(k));
  if (key_len > block) {
    if (is512) {
      host_sha512_ctx ctx;
      sha512_init(&ctx);
      sha512_update(&ctx, key, key_len);
      sha512_finish(&ctx, k);
    } else {
      host_sha256_ctx ctx;
      sha256_init(&ctx);
      sha256_update(&ctx, key, key_len);
      sha256_finish(&ctx, k);
    }
  } else {
    memcpy(k, key, key_len);
  }
  for (i = 0; i < block; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  if (is512) {
    host_sha512_ctx ctx;
    uint8_t inner[64];
    sha512_init(&ctx);
    sha512_update(&ctx, ipad, 128);
    sha512_update(&ctx, data, data_len);
    sha512_finish(&ctx, inner);
    sha512_init(&ctx);
    sha512_update(&ctx, opad, 128);
    sha512_update(&ctx, inner, 64);
    sha512_finish(&ctx, out);
  } else {
    host_sha256_ctx ctx;
    uint8_t inner[32];
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_finish(&ctx, inner);
    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_finish(&ctx, out);
  }
}

/* ------------------------------------------------------------------ */
/* mbedtls_md                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
  int type;
  host_sha256_ctx sha256;
  host_sha512_ctx sha512;
} host_md_state;

const mbedtls_md_info_t *mbedtls_md_info_from_type(mbedtls_md_type_t type) {
  /* Distinct sentinels so callers can tell SHA-256 and SHA-512 apart. */
  if (type == MBEDTLS_MD_SHA256) return (const mbedtls_md_info_t *)1;
  if (type == MBEDTLS_MD_SHA512) return (const mbedtls_md_info_t *)2;
  return NULL;
}

static int md_sentinel_is_sha256(const mbedtls_md_info_t *info) {
  return info == (const mbedtls_md_info_t *)1;
}

int mbedtls_md(const mbedtls_md_info_t *info, const unsigned char *input,
               size_t ilen, unsigned char *output) {
  if (info == NULL || output == NULL || (input == NULL && ilen != 0)) {
    return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
  }
  if (md_sentinel_is_sha256(info)) {
    host_sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, ilen);
    sha256_finish(&ctx, output);
    return 0;
  }
  host_sha512_ctx ctx;
  sha512_init(&ctx);
  sha512_update(&ctx, input, ilen);
  sha512_finish(&ctx, output);
  return 0;
}

void mbedtls_md_init(mbedtls_md_context_t *ctx) {
  memset(ctx, 0, sizeof(*ctx));
}

int mbedtls_md_setup(mbedtls_md_context_t *ctx, const mbedtls_md_info_t *info,
                     int hmac) {
  if (ctx == NULL || info == NULL) return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
  host_md_state *state = calloc(1, sizeof(host_md_state));
  if (state == NULL) return MBEDTLS_ERR_MD_ALLOC_FAILED;
  state->type = md_sentinel_is_sha256(info) ? 256 : 512;
  ctx->md_info = info;
  ctx->md_ctx = state;
  ctx->hmac_ctx = NULL;
  (void)hmac;
  return 0;
}

int mbedtls_md_starts(mbedtls_md_context_t *ctx) {
  if (ctx == NULL || ctx->md_ctx == NULL) return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
  host_md_state *state = (host_md_state *)ctx->md_ctx;
  if (state->type == 256) sha256_init(&state->sha256);
  else sha512_init(&state->sha512);
  return 0;
}

int mbedtls_md_update(mbedtls_md_context_t *ctx, const unsigned char *input,
                      size_t ilen) {
  if (ctx == NULL || ctx->md_ctx == NULL || (input == NULL && ilen != 0)) {
    return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
  }
  host_md_state *state = (host_md_state *)ctx->md_ctx;
  if (state->type == 256) sha256_update(&state->sha256, input, ilen);
  else sha512_update(&state->sha512, input, ilen);
  return 0;
}

int mbedtls_md_finish(mbedtls_md_context_t *ctx, unsigned char *output) {
  if (ctx == NULL || ctx->md_ctx == NULL || output == NULL) {
    return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
  }
  host_md_state *state = (host_md_state *)ctx->md_ctx;
  if (state->type == 256) sha256_finish(&state->sha256, output);
  else sha512_finish(&state->sha512, output);
  return 0;
}

void mbedtls_md_free(mbedtls_md_context_t *ctx) {
  if (ctx == NULL) return;
  if (ctx->md_ctx != NULL) {
    mbedtls_platform_zeroize(ctx->md_ctx, sizeof(host_md_state));
    free(ctx->md_ctx);
  }
  if (ctx->hmac_ctx != NULL) free(ctx->hmac_ctx);
  memset(ctx, 0, sizeof(*ctx));
}

int mbedtls_md_hmac(const mbedtls_md_info_t *info, const unsigned char *key,
                    size_t keylen, const unsigned char *input, size_t ilen,
                    unsigned char *output) {
  if (info == NULL || output == NULL || (input == NULL && ilen != 0)) {
    return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
  }
  const int is512 = !md_sentinel_is_sha256(info);
  uint8_t out[64];
  hmac(key, keylen, input, ilen, is512, out);
  memcpy(output, out, is512 ? 64 : 32);
  return 0;
}

int mbedtls_md_hmac_starts(mbedtls_md_context_t *ctx, const unsigned char *key,
                           size_t keylen) {
  (void)ctx; (void)key; (void)keylen;
  return 0;
}
int mbedtls_md_hmac_update(mbedtls_md_context_t *ctx, const unsigned char *input,
                           size_t ilen) {
  (void)ctx; (void)input; (void)ilen;
  return 0;
}
int mbedtls_md_hmac_finish(mbedtls_md_context_t *ctx, unsigned char *output) {
  (void)ctx; (void)output;
  return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
}

/* ------------------------------------------------------------------ */
/* PBKDF2-HMAC-SHA256 (single output pass, matches mbedtls usage)      */
/* ------------------------------------------------------------------ */

int mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_type_t md_type,
                                  const unsigned char *password, size_t plen,
                                  const unsigned char *salt, size_t slen,
                                  unsigned int iteration_count,
                                  uint32_t key_length, unsigned char *output) {
  if (md_type != MBEDTLS_MD_SHA256 || output == NULL) {
    return MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA;
  }
  uint8_t block_index_big[4];
  uint32_t blocks = (key_length + 31) / 32;
  for (uint32_t block = 1; block <= blocks; block++) {
    block_index_big[0] = (uint8_t)(block >> 24);
    block_index_big[1] = (uint8_t)(block >> 16);
    block_index_big[2] = (uint8_t)(block >> 8);
    block_index_big[3] = (uint8_t)block;
    uint8_t u[32];
    uint8_t t[32];
    uint8_t *salt_block = malloc(slen + 4);
    if (salt_block == NULL) return MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA;
    memcpy(salt_block, salt, slen);
    memcpy(salt_block + slen, block_index_big, 4);
    hmac(password, plen, salt_block, slen + 4, 0, u);
    memcpy(t, u, 32);
    for (unsigned int iter = 1; iter < iteration_count; iter++) {
      hmac(password, plen, u, 32, 0, u);
      for (int i = 0; i < 32; i++) t[i] ^= u[i];
    }
    free(salt_block);
    uint32_t offset = (block - 1) * 32;
    uint32_t take = key_length - offset;
    if (take > 32) take = 32;
    memcpy(output + offset, t, take);
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Minimal bignum (64-bit limbs, matching this mbedtls build)          */
/* ------------------------------------------------------------------ */

#define LIMBS_CAP 64

static int mpi_grow(mbedtls_mpi *X, size_t n) {
  if (n <= X->n) return 0;
  if (n > LIMBS_CAP) return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  mbedtls_mpi_uint *p = calloc(n, sizeof(mbedtls_mpi_uint));
  if (p == NULL) return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  if (X->p != NULL) {
    memcpy(p, X->p, X->n * sizeof(mbedtls_mpi_uint));
    free(X->p);
  }
  X->p = p;
  X->n = n;
  return 0;
}

static void mpi_normalize(mbedtls_mpi *X) {
  while (X->n > 0 && X->p[X->n - 1] == 0) X->n--;
}

void mbedtls_mpi_init(mbedtls_mpi *X) {
  X->s = 1;
  X->n = 0;
  X->p = NULL;
}

void mbedtls_mpi_free(mbedtls_mpi *X) {
  if (X == NULL) return;
  if (X->p != NULL) {
    mbedtls_platform_zeroize(X->p, X->n * sizeof(mbedtls_mpi_uint));
    free(X->p);
  }
  X->p = NULL;
  X->n = 0;
  X->s = 1;
}

int mbedtls_mpi_copy(mbedtls_mpi *X, const mbedtls_mpi *Y) {
  if (X == Y) return 0;
  if (Y->n == 0) {
    mbedtls_mpi_free(X);
    return 0;
  }
  int rc = mpi_grow(X, Y->n);
  if (rc != 0) return rc;
  memset(X->p, 0, X->n * sizeof(mbedtls_mpi_uint));
  memcpy(X->p, Y->p, Y->n * sizeof(mbedtls_mpi_uint));
  X->n = Y->n;
  X->s = Y->s;
  mpi_normalize(X);
  return 0;
}

int mbedtls_mpi_lset(mbedtls_mpi *X, mbedtls_mpi_sint z) {
  int rc = mpi_grow(X, 1);
  if (rc != 0) return rc;
  memset(X->p, 0, X->n * sizeof(mbedtls_mpi_uint));
  if (z < 0) { X->s = -1; z = -z; } else X->s = 1;
  X->p[0] = (mbedtls_mpi_uint)z;
  X->n = 1;
  mpi_normalize(X);
  return 0;
}

int mbedtls_mpi_read_binary(mbedtls_mpi *X, const unsigned char *buf, size_t buflen) {
  mbedtls_mpi_free(X);
  if (buflen == 0) return 0;
  size_t limbs = (buflen + 7) / 8;
  int rc = mpi_grow(X, limbs);
  if (rc != 0) return rc;
  memset(X->p, 0, limbs * sizeof(mbedtls_mpi_uint));
  for (size_t i = 0; i < buflen; i++) {
    size_t byte_from_right = buflen - 1 - i;
    size_t limb = byte_from_right / 8;
    X->p[limb] |= (mbedtls_mpi_uint)buf[i] << ((byte_from_right % 8) * 8);
  }
  X->s = 1;
  X->n = limbs;
  mpi_normalize(X);
  return 0;
}

int mbedtls_mpi_write_binary(const mbedtls_mpi *X, unsigned char *buf, size_t buflen) {
  if (buflen == 0) return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
  memset(buf, 0, buflen);
  for (size_t i = 0; i < X->n && i * 8 < buflen; i++) {
    uint64_t v = X->p[i];
    size_t offset = buflen - 1 - i * 8;
    for (int j = 0; j < 8 && (size_t)j <= offset; j++) {
      buf[offset - j] = (unsigned char)(v >> (j * 8));
    }
  }
  return 0;
}

int mbedtls_mpi_read_string(mbedtls_mpi *X, int radix, const char *s) {
  if (radix != 16) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
  if (s == NULL) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
  mbedtls_mpi_free(X);
  while (*s == ' ') s++;
  int sign = 1;
  if (*s == '-') { sign = -1; s++; }
  mbedtls_mpi acc;
  mbedtls_mpi_init(&acc);
  int rc = mbedtls_mpi_lset(&acc, 0);
  while (rc == 0 && *s) {
    int digit = -1;
    if (*s >= '0' && *s <= '9') digit = *s - '0';
    else if (*s >= 'a' && *s <= 'f') digit = *s - 'a' + 10;
    else if (*s >= 'A' && *s <= 'F') digit = *s - 'A' + 10;
    if (digit < 0) { rc = MBEDTLS_ERR_MPI_INVALID_CHARACTER; break; }
    rc = mbedtls_mpi_mul_int(&acc, &acc, 16);
    if (rc == 0) rc = mbedtls_mpi_add_int(&acc, &acc, digit);
    s++;
  }
  if (rc == 0) {
    rc = mbedtls_mpi_copy(X, &acc);
    X->s = sign;
  }
  mbedtls_mpi_free(&acc);
  return rc;
}

int mbedtls_mpi_cmp_mpi(const mbedtls_mpi *X, const mbedtls_mpi *Y) {
  if (X->s != Y->s) return X->s > Y->s ? 1 : -1;
  size_t xn = X->n, yn = Y->n;
  if (xn > yn) return X->s;
  if (xn < yn) return -X->s;
  for (size_t i = xn; i-- > 0;) {
    if (X->p[i] > Y->p[i]) return X->s;
    if (X->p[i] < Y->p[i]) return -X->s;
  }
  return 0;
}

int mbedtls_mpi_cmp_int(const mbedtls_mpi *X, mbedtls_mpi_sint z) {
  mbedtls_mpi tmp;
  mbedtls_mpi_init(&tmp);
  mbedtls_mpi_lset(&tmp, z);
  int rc = mbedtls_mpi_cmp_mpi(X, &tmp);
  mbedtls_mpi_free(&tmp);
  return rc;
}

/* ------------------------------------------------------------------ */
/* Portable 64-bit add/mul with carry (no __int128 on MSVC)            */
/* ------------------------------------------------------------------ */

static uint64_t add64_carry(uint64_t a, uint64_t b, uint64_t carry_in,
                            uint64_t *carry_out) {
  uint64_t s = a + b;
  uint64_t c = (s < a) ? 1 : 0;
  uint64_t s2 = s + carry_in;
  *carry_out = c | ((s2 < s) ? 1 : 0);
  return s2;
}

/* High 64 bits of the 128-bit product a * b. */
static uint64_t mul64_hi(uint64_t a, uint64_t b) {
  uint64_t a_lo = a & 0xFFFFFFFFULL, a_hi = a >> 32;
  uint64_t b_lo = b & 0xFFFFFFFFULL, b_hi = b >> 32;
  uint64_t ll = a_lo * b_lo;
  uint64_t lh = a_lo * b_hi;
  uint64_t hl = a_hi * b_lo;
  uint64_t hh = a_hi * b_hi;
  uint64_t mid = (ll >> 32) + (lh & 0xFFFFFFFFULL) + (hl & 0xFFFFFFFFULL);
  return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

/* result = a * b + add + carry_in (mod 2^64); carry_out = high 64 bits. */
static uint64_t mul64_add_carry(uint64_t a, uint64_t b, uint64_t add,
                                uint64_t carry_in, uint64_t *carry_out) {
  uint64_t lo = a * b;
  uint64_t hi = mul64_hi(a, b);
  uint64_t s1 = lo + add;
  hi += (s1 < lo) ? 1 : 0;
  uint64_t s2 = s1 + carry_in;
  hi += (s2 < s1) ? 1 : 0;
  *carry_out = hi;
  return s2;
}

int mbedtls_mpi_add_mpi(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B) {
  if (X == A || X == B) {
    mbedtls_mpi ta, tb;
    mbedtls_mpi_init(&ta);
    mbedtls_mpi_init(&tb);
    int rc = mbedtls_mpi_copy(&ta, A);
    if (rc == 0) rc = mbedtls_mpi_copy(&tb, B);
    if (rc == 0) rc = mbedtls_mpi_add_mpi(X, &ta, &tb);
    mbedtls_mpi_free(&ta);
    mbedtls_mpi_free(&tb);
    return rc;
  }
  if (A->s == B->s) {
    int rc = mpi_grow(X, (A->n > B->n ? A->n : B->n) + 1);
    if (rc != 0) return rc;
    memset(X->p, 0, X->n * sizeof(mbedtls_mpi_uint));
    uint64_t carry = 0;
    size_t max = A->n > B->n ? A->n : B->n;
    for (size_t i = 0; i < max; i++) {
      uint64_t a = i < A->n ? A->p[i] : 0;
      uint64_t b = i < B->n ? B->p[i] : 0;
      X->p[i] = add64_carry(a, b, carry, &carry);
    }
    if (carry) X->p[max] = carry;
    X->n = max + (carry ? 1 : 0);
    X->s = A->s;
    mpi_normalize(X);
    return 0;
  }
  /* Opposite signs: the result is the difference of the magnitudes, with the
     sign of the operand that has the LARGER magnitude. mbedtls_mpi_cmp_mpi
     is a signed comparison, so compare magnitudes here explicitly. */
  int mag_cmp = 0;
  {
    size_t xn = A->n, yn = B->n;
    if (xn > yn) mag_cmp = 1;
    else if (xn < yn) mag_cmp = -1;
    else {
      for (size_t i = xn; i-- > 0;) {
        if (A->p[i] > B->p[i]) { mag_cmp = 1; break; }
        if (A->p[i] < B->p[i]) { mag_cmp = -1; break; }
      }
    }
  }
  if (mag_cmp == 0) return mbedtls_mpi_lset(X, 0);
  const mbedtls_mpi *big = mag_cmp > 0 ? A : B;
  const mbedtls_mpi *small = mag_cmp > 0 ? B : A;
  int rc = mpi_grow(X, big->n);
  if (rc != 0) return rc;
  memset(X->p, 0, X->n * sizeof(mbedtls_mpi_uint));
  uint64_t borrow = 0;
  for (size_t i = 0; i < big->n; i++) {
    uint64_t a = big->p[i];
    uint64_t b = (i < small->n ? small->p[i] : 0) + borrow;
    uint64_t diff = a - b;
    X->p[i] = diff;
    borrow = a < b ? 1 : 0;
  }
  X->n = big->n;
  X->s = big->s;
  mpi_normalize(X);
  return 0;
}

int mbedtls_mpi_sub_mpi(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B) {
  mbedtls_mpi neg;
  mbedtls_mpi_init(&neg);
  int rc = mbedtls_mpi_copy(&neg, B);
  if (rc == 0) { neg.s = -neg.s; rc = mbedtls_mpi_add_mpi(X, A, &neg); }
  mbedtls_mpi_free(&neg);
  return rc;
}

int mbedtls_mpi_add_int(mbedtls_mpi *X, const mbedtls_mpi *A, mbedtls_mpi_sint b) {
  mbedtls_mpi tmp;
  mbedtls_mpi_init(&tmp);
  mbedtls_mpi_lset(&tmp, b);
  int rc = mbedtls_mpi_add_mpi(X, A, &tmp);
  mbedtls_mpi_free(&tmp);
  return rc;
}

int mbedtls_mpi_mul_mpi(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B) {
  if (X == A || X == B) {
    mbedtls_mpi ta, tb;
    mbedtls_mpi_init(&ta);
    mbedtls_mpi_init(&tb);
    int rc = mbedtls_mpi_copy(&ta, A);
    if (rc == 0) rc = mbedtls_mpi_copy(&tb, B);
    if (rc == 0) rc = mbedtls_mpi_mul_mpi(X, &ta, &tb);
    mbedtls_mpi_free(&ta);
    mbedtls_mpi_free(&tb);
    return rc;
  }
  if (A->n == 0 || B->n == 0) return mbedtls_mpi_lset(X, 0);
  int rc = mpi_grow(X, A->n + B->n);
  if (rc != 0) return rc;
  memset(X->p, 0, X->n * sizeof(mbedtls_mpi_uint));
  for (size_t i = 0; i < A->n; i++) {
    uint64_t carry = 0;
    for (size_t j = 0; j < B->n; j++) {
      X->p[i + j] = mul64_add_carry(A->p[i], B->p[j], X->p[i + j], carry, &carry);
    }
    /* Column i + B->n is always zero here, so plain assignment is exact. */
    X->p[i + B->n] = carry;
  }
  X->n = A->n + B->n;
  X->s = A->s * B->s;
  mpi_normalize(X);
  return 0;
}

int mbedtls_mpi_mul_int(mbedtls_mpi *X, const mbedtls_mpi *A, mbedtls_mpi_uint b) {
  mbedtls_mpi tmp;
  mbedtls_mpi_init(&tmp);
  int rc = mbedtls_mpi_lset(&tmp, (mbedtls_mpi_sint)b);
  if (rc == 0) rc = mbedtls_mpi_mul_mpi(X, A, &tmp);
  mbedtls_mpi_free(&tmp);
  return rc;
}

/* Left-shift in place (used by the long-division mod below). */
static void mpi_shl_inplace(mbedtls_mpi *X, size_t bits) {
  if (X->n == 0 || bits == 0) return;
  size_t limb_shift = bits / 64;
  size_t bit_shift = bits % 64;
  size_t new_n = X->n + limb_shift + (bit_shift ? 1 : 0);
  if (new_n > LIMBS_CAP) return;
  mbedtls_mpi_uint *p = calloc(new_n, sizeof(mbedtls_mpi_uint));
  if (p == NULL) return;
  for (size_t i = 0; i < X->n; ++i) p[i + limb_shift] = X->p[i];
  if (bit_shift) {
    uint64_t carry = 0;
    for (size_t i = limb_shift; i < new_n; ++i) {
      uint64_t v = p[i];
      p[i] = (v << bit_shift) | carry;
      carry = bit_shift == 64 ? 0 : (v >> (64 - bit_shift));
    }
  }
  free(X->p);
  X->p = p;
  X->n = new_n;
  mpi_normalize(X);
}

/* Schoolbook binary long division: Q = A / B, R = A % B (A, B non-negative).
   This is O(bitlen) iterations with small per-step work and is exact for all
   inputs, unlike the bulk subtract-and-align form which mis-divides when the
   shifted divisor overshoots (e.g. when A and B share a bit length but
   A < B). */
static int mpi_divmod(mbedtls_mpi *Q, mbedtls_mpi *R, const mbedtls_mpi *A,
                      const mbedtls_mpi *B) {
  if (B->n == 0) return MBEDTLS_ERR_MPI_DIVISION_BY_ZERO;
  mbedtls_mpi q, r;
  mbedtls_mpi_init(&q);
  mbedtls_mpi_init(&r);
  int rc = mbedtls_mpi_lset(&q, 0);
  if (rc == 0) rc = mbedtls_mpi_lset(&r, 0);
  if (rc == 0 && mbedtls_mpi_cmp_mpi(A, B) >= 0) {
    const size_t bits = mbedtls_mpi_bitlen(A);
    for (size_t bit = bits; rc == 0 && bit-- > 0;) {
      mpi_shl_inplace(&r, 1);
      if (rc == 0 && mbedtls_mpi_get_bit(A, bit)) {
        rc = mbedtls_mpi_add_int(&r, &r, 1);
      }
      if (rc == 0 && mbedtls_mpi_cmp_mpi(&r, B) >= 0) {
        rc = mbedtls_mpi_sub_mpi(&r, &r, B);
        mpi_shl_inplace(&q, 1);
        if (rc == 0) rc = mbedtls_mpi_add_int(&q, &q, 1);
      } else {
        mpi_shl_inplace(&q, 1);
      }
    }
  }
  if (rc == 0) rc = mbedtls_mpi_copy(R, &r);
  if (rc == 0) rc = mbedtls_mpi_copy(Q, &q);
  mbedtls_mpi_free(&q);
  mbedtls_mpi_free(&r);
  return rc;
}

int mbedtls_mpi_mod_mpi(mbedtls_mpi *R, const mbedtls_mpi *A, const mbedtls_mpi *B) {
  if (R == A || R == B) {
    mbedtls_mpi ta, tb;
    mbedtls_mpi_init(&ta);
    mbedtls_mpi_init(&tb);
    int rc = mbedtls_mpi_copy(&ta, A);
    if (rc == 0) rc = mbedtls_mpi_copy(&tb, B);
    if (rc == 0) rc = mbedtls_mpi_mod_mpi(R, &ta, &tb);
    mbedtls_mpi_free(&ta);
    mbedtls_mpi_free(&tb);
    return rc;
  }
  if (B->n == 0) return MBEDTLS_ERR_MPI_DIVISION_BY_ZERO;
  /* Reduce |A| modulo B, then normalise the sign so the result is always in
     [0, B) for a positive modulus.  mbedtls semantics: X = A mod B is the
     least non-negative residue of A modulo B.  The point arithmetic in
     BlsG1.cpp relies on this (x3/y3/lambda can be negative before the mod). */
  const int a_neg = A->s < 0;
  mbedtls_mpi ta;
  mbedtls_mpi_init(&ta);
  int rc = mbedtls_mpi_copy(&ta, A);
  if (rc == 0) ta.s = 1;
  if (rc == 0 && mbedtls_mpi_cmp_mpi(&ta, B) >= 0) {
    mbedtls_mpi q;
    mbedtls_mpi_init(&q);
    rc = mpi_divmod(&q, &ta, &ta, B);
    mbedtls_mpi_free(&q);
  }
  if (rc == 0 && a_neg && ta.n != 0) {
    rc = mbedtls_mpi_sub_mpi(&ta, B, &ta);
  }
  if (rc == 0) rc = mbedtls_mpi_copy(R, &ta);
  mbedtls_mpi_free(&ta);
  return rc;
}

int mbedtls_mpi_inv_mod(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *N) {
  // Host shim: modular inverse via the extended Euclidean algorithm with a
  // real (schoolbook) division for the quotient. This is O(bitlen^2) instead
  // of Fermat exponentiation's O(bitlen^2) with a ~570x larger constant, and
  // it never degenerates to the O(quotient) repeated-subtraction form.
  mbedtls_mpi t, newt, r, newr, q, qnewt, qt, rem;
  mbedtls_mpi_init(&t); mbedtls_mpi_init(&newt);
  mbedtls_mpi_init(&r); mbedtls_mpi_init(&newr);
  mbedtls_mpi_init(&q); mbedtls_mpi_init(&qnewt); mbedtls_mpi_init(&qt);
  mbedtls_mpi_init(&rem);
  int rc = mbedtls_mpi_lset(&t, 0);
  if (rc == 0) rc = mbedtls_mpi_lset(&newt, 1);
  if (rc == 0) rc = mbedtls_mpi_copy(&r, N);
  if (rc == 0) rc = mbedtls_mpi_mod_mpi(&newr, A, N);
  while (rc == 0 && newr.n != 0) {
    /* q = r / newr ; rem = r % newr (both non-negative) */
    rc = mpi_divmod(&q, &rem, &r, &newr);
    /* t, newt = newt, t - q*newt ;  r, newr = newr, rem */
    if (rc == 0) rc = mbedtls_mpi_mul_mpi(&qnewt, &q, &newt);
    if (rc == 0) rc = mbedtls_mpi_sub_mpi(&qt, &t, &qnewt);
    if (rc == 0) rc = mbedtls_mpi_copy(&t, &newt);
    if (rc == 0) rc = mbedtls_mpi_copy(&newt, &qt);
    if (rc == 0) rc = mbedtls_mpi_copy(&r, &newr);
    if (rc == 0) rc = mbedtls_mpi_copy(&newr, &rem);
  }
  if (rc == 0) {
    if (r.n == 1 && r.p[0] == 1) {
      if (t.s < 0) rc = mbedtls_mpi_add_mpi(&t, &t, N);
      if (rc == 0 && mbedtls_mpi_cmp_mpi(&t, N) >= 0) {
        rc = mbedtls_mpi_mod_mpi(&t, &t, N);
      }
      if (rc == 0) rc = mbedtls_mpi_copy(X, &t);
    } else {
      rc = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
    }
  }
  mbedtls_mpi_free(&t); mbedtls_mpi_free(&newt);
  mbedtls_mpi_free(&r); mbedtls_mpi_free(&newr);
  mbedtls_mpi_free(&q); mbedtls_mpi_free(&qnewt); mbedtls_mpi_free(&qt);
  mbedtls_mpi_free(&rem);
  return rc;
}

int mbedtls_mpi_exp_mod(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *E,
                        const mbedtls_mpi *N, mbedtls_mpi *_RR) {
  (void)_RR;
  mbedtls_mpi result, base;
  mbedtls_mpi_init(&result);
  mbedtls_mpi_init(&base);
  int rc = mbedtls_mpi_lset(&result, 1);
  if (rc == 0) rc = mbedtls_mpi_mod_mpi(&base, A, N);
  size_t bits = mbedtls_mpi_bitlen(E);
  for (size_t bit = bits; rc == 0 && bit-- > 0;) {
    mbedtls_mpi tmp, tmp2;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&tmp2);
    rc = mbedtls_mpi_mul_mpi(&tmp, &result, &result);
    if (rc == 0) rc = mbedtls_mpi_mod_mpi(&result, &tmp, N);
    if (rc == 0 && mbedtls_mpi_get_bit(E, bit)) {
      rc = mbedtls_mpi_mul_mpi(&tmp2, &result, &base);
      if (rc == 0) rc = mbedtls_mpi_mod_mpi(&result, &tmp2, N);
    }
    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&tmp2);
  }
  if (rc == 0) rc = mbedtls_mpi_copy(X, &result);
  mbedtls_mpi_free(&result);
  mbedtls_mpi_free(&base);
  return rc;
}

size_t mbedtls_mpi_bitlen(const mbedtls_mpi *X) {
  if (X->n == 0) return 0;
  uint64_t top = X->p[X->n - 1];
  size_t bits = (X->n - 1) * 64;
  while (top) { top >>= 1; bits++; }
  return bits;
}

int mbedtls_mpi_get_bit(const mbedtls_mpi *X, size_t pos) {
  size_t limb = pos / 64;
  if (limb >= X->n) return 0;
  return (int)((X->p[limb] >> (pos % 64)) & 1);
}

int mbedtls_mpi_set_bit(mbedtls_mpi *X, size_t pos, unsigned char val) {
  size_t limb = pos / 64;
  if (limb >= LIMBS_CAP) return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  int rc = mpi_grow(X, limb + 1);
  if (rc != 0) return rc;
  if (val) X->p[limb] |= ((mbedtls_mpi_uint)1 << (pos % 64));
  else X->p[limb] &= ~((mbedtls_mpi_uint)1 << (pos % 64));
  mpi_normalize(X);
  return 0;
}

int mbedtls_mpi_shift_r(mbedtls_mpi *X, size_t count) {
  if (count == 0 || X->n == 0) return 0;
  size_t limb_shift = count / 64;
  size_t bit_shift = count % 64;
  if (limb_shift >= X->n) return mbedtls_mpi_lset(X, 0);
  for (size_t i = 0; i + limb_shift < X->n; i++) {
    X->p[i] = X->p[i + limb_shift] >> bit_shift;
    if (bit_shift != 0 && i + limb_shift + 1 < X->n) {
      X->p[i] |= X->p[i + limb_shift + 1] << (64 - bit_shift);
    }
  }
  X->n -= limb_shift;
  mpi_normalize(X);
  return 0;
}

void mbedtls_platform_zeroize(void *buf, size_t len) {
  volatile unsigned char *p = (volatile unsigned char *)buf;
  while (len--) *p++ = 0;
}
