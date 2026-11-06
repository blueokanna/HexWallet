#ifndef HEXWALLET_BLAKE3_H
#define HEXWALLET_BLAKE3_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

constexpr size_t kBlake3BlockLen = 64;
constexpr size_t kBlake3ChunkLen = 1024;
constexpr size_t kBlake3OutLen = 32;
constexpr size_t kBlake3KeyLen = 32;
// ceil(log2(2^64 / CHUNK_LEN)): a 64-bit byte counter can never need more.
constexpr size_t kBlake3MaxDepth = 54;

enum class Blake3Mode : uint8_t { Hash, KeyedHash, DeriveKey };

// Portable BLAKE3 (hash, keyed hash, derive_key and the extended output
// function) with no dynamic allocation, so the same code runs on the device and
// in the host suite. Alephium hashes addresses and transaction ids with BLAKE3,
// which is why this exists: that adapter cannot be written before the primitive.
struct Blake3State {
  uint32_t key_words[8];
  uint32_t flags;
  uint32_t chunk_cv[8];
  uint64_t chunk_counter;
  uint8_t block[kBlake3BlockLen];
  uint8_t block_len;
  uint8_t blocks_compressed;
  uint8_t stack_len;
  uint32_t cv_stack[kBlake3MaxDepth][8];
};

// `key` is required for KeyedHash and ignored otherwise; `context` is required
// for DeriveKey and ignored otherwise. Returns false on a missing argument.
bool blake3_init(Blake3State *state, Blake3Mode mode, const uint8_t *key,
                 const char *context);
void blake3_update(Blake3State *state, const uint8_t *data, size_t size);
// Reads the state without consuming it, so a caller can hash a prefix, copy the
// state and finish twice. out_len may exceed 32: the extended output function is
// what Alephium needs and what the official vectors pin at 131 bytes.
void blake3_final(const Blake3State *state, uint8_t *out, size_t out_len);

void blake3_hash(const uint8_t *data, size_t size, uint8_t out[kBlake3OutLen]);
void blake3_hash_xof(const uint8_t *data, size_t size, uint8_t *out,
                     size_t out_len);
void blake3_keyed_hash(const uint8_t key[kBlake3KeyLen], const uint8_t *data,
                       size_t size, uint8_t *out, size_t out_len);
void blake3_derive_key(const char *context, const uint8_t *data, size_t size,
                       uint8_t *out, size_t out_len);

// Official BLAKE3 repository vectors: 35 input lengths, each with hash,
// keyed_hash and derive_key output of 131 bytes, so the XOF is covered too. The
// firmware links three of those cases and the host suite all 35; both compare
// against upstream bytes, never against output this repository produced.
bool run_blake3_self_tests();

}  // namespace hexwallet

#endif