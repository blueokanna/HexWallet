#include "CryptoExtended.h"

#include "BlsBackend.h"
#include <mbedtls/md.h>
#include <stdlib.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

// ---------------------------------------------------------------------------
// EIP-2333 helpers (SHA-256 / HMAC-SHA256 based).
// ---------------------------------------------------------------------------

bool sha256(const uint8_t *data, size_t size, uint8_t out[32]) {
  return crypto_sha256(data, size, out);
}

bool hmac_sha256(const uint8_t *key, size_t key_size, const uint8_t *data,
                 size_t data_size, uint8_t out[32]) {
  return crypto_hmac_sha256(key, key_size, data, data_size, out);
}

// HKDF-Expand with SHA-256; info is prebuilt. Output length <= 255*32.
bool hkdf_expand_sha256(const uint8_t prk[32], const uint8_t *info,
                        size_t info_size, uint8_t *out, size_t out_size) {
  uint8_t block[32];
  uint8_t previous[32];
  size_t produced = 0;
  uint8_t counter = 1;
  bool first = true;
  while (produced < out_size) {
    uint8_t input[32 + 256 + 1];
    size_t input_size = 0;
    if (!first) {
      memcpy(input, previous, 32);
      input_size = 32;
    }
    memcpy(input + input_size, info, info_size);
    input_size += info_size;
    input[input_size++] = counter;
    if (!hmac_sha256(prk, 32, input, input_size, block)) return false;
    const size_t take = out_size - produced < 32 ? out_size - produced : 32;
    memcpy(out + produced, block, take);
    produced += take;
    memcpy(previous, block, 32);
    ++counter;
    first = false;
  }
  secure_zero(block, sizeof(block));
  secure_zero(previous, sizeof(previous));
  return true;
}

// HKDF-mod-r as Chia/bls-signatures implements it: the first extraction uses
// the raw ASCII salt "BLS-SIG-KEYGEN-SALT-"; only a zero result rehashes the
// salt. Hashing the salt first (literal EIP-2333 text) yields keys that no
// Chia wallet derives, so the raw-first order is the compatible one.
bool hkdf_mod_r(const uint8_t *ikm, size_t ikm_size, uint8_t out_sk[32]) {
  if (out_sk == nullptr) return false;
  if (ikm == nullptr || ikm_size < 32 || ikm_size > 256) {
    secure_zero(out_sk, 32);
    return false;
  }
  // Chia uses the original v3 raw salt. EIP-2333 v4's hashed salt is a
  // different key space, so the v4 derivation would produce other keys.
  return bls_keygen_v3(ikm, ikm_size, out_sk);
}
constexpr size_t kLamportCount = 255;
constexpr size_t kLamportSkSize = kLamportCount * 32;

// PRK = HMAC(salt, IKM); OKM = HKDF-Expand(PRK, "", 255*32); split into chunks.
bool ikm_to_lamport_sk(const uint8_t *ikm, size_t ikm_size,
                       const uint8_t *salt, size_t salt_size,
                       uint8_t lamport[kLamportSkSize]) {
  uint8_t prk[32];
  if (!hmac_sha256(salt, salt_size, ikm, ikm_size, prk)) return false;
  const bool ok = hkdf_expand_sha256(prk, nullptr, 0, lamport, kLamportSkSize);
  secure_zero(prk, sizeof(prk));
  return ok;
}

bool parent_sk_to_lamport_pk(const uint8_t parent_sk[32], uint32_t index,
                             uint8_t out_compressed[32]) {
  // salt = I2OSP(index, 4) exactly (EIP-2333).
  uint8_t salt[4];
  salt[0] = static_cast<uint8_t>(index >> 24);
  salt[1] = static_cast<uint8_t>(index >> 16);
  salt[2] = static_cast<uint8_t>(index >> 8);
  salt[3] = static_cast<uint8_t>(index);
  uint8_t not_ikm[32];
  for (size_t index_byte = 0; index_byte < 32; ++index_byte) {
    not_ikm[index_byte] = static_cast<uint8_t>(~parent_sk[index_byte]);
  }
  // The three Lamport buffers are 8 KB + 8 KB + 16 KB. On the ESP32 the loop
  // task stack is only a few KB of SRAM, so these MUST live on the heap: a
  // ~32 KB stack frame overflows the loop task and panics with a
  // LoadStoreError at a garbage address (seen on real hardware, invisible on
  // the PC host tests which enjoy a multi-MB process stack).
  constexpr size_t kLamportPkSize = 2 * kLamportCount * 32;
  uint8_t *lamport0 = static_cast<uint8_t *>(malloc(kLamportSkSize));
  uint8_t *lamport1 = static_cast<uint8_t *>(malloc(kLamportSkSize));
  uint8_t *lamport_pk = static_cast<uint8_t *>(malloc(kLamportPkSize));
  if (lamport0 == nullptr || lamport1 == nullptr || lamport_pk == nullptr) {
    free(lamport0);
    free(lamport1);
    free(lamport_pk);
    secure_zero(not_ikm, sizeof(not_ikm));
    return false;
  }
  memset(lamport0, 0, kLamportSkSize);
  memset(lamport1, 0, kLamportSkSize);
  memset(lamport_pk, 0, kLamportPkSize);
  bool ok = ikm_to_lamport_sk(parent_sk, 32, salt, sizeof(salt), lamport0);
  if (ok) ok = ikm_to_lamport_sk(not_ikm, 32, salt, sizeof(salt), lamport1);
  if (ok) {
    for (size_t index_chunk = 0; index_chunk < kLamportCount; ++index_chunk) {
      if (!sha256(lamport0 + index_chunk * 32, 32,
                  lamport_pk + index_chunk * 32) ||
          !sha256(lamport1 + index_chunk * 32, 32,
                  lamport_pk + kLamportCount * 32 + index_chunk * 32)) {
        ok = false;
        break;
      }
    }
  }
  if (ok) ok = sha256(lamport_pk, kLamportPkSize, out_compressed);
  secure_zero(lamport0, kLamportSkSize);
  secure_zero(lamport1, kLamportSkSize);
  secure_zero(lamport_pk, kLamportPkSize);
  secure_zero(not_ikm, sizeof(not_ikm));
  free(lamport0);
  free(lamport1);
  free(lamport_pk);
  return ok;
}

// ---------------------------------------------------------------------------
// Chia tree hashes (SHA-256 based CLVM shatree).
// ---------------------------------------------------------------------------

void shatree_atom(const uint8_t *atom, size_t size, uint8_t out[32]) {
  uint8_t input[1 + 64];
  input[0] = 0x01;
  if (size != 0) memcpy(input + 1, atom, size);
  sha256(input, 1 + size, out);
}

void shatree_pair(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) {
  uint8_t input[65];
  input[0] = 0x02;
  memcpy(input + 1, left, 32);
  memcpy(input + 33, right, 32);
  sha256(input, sizeof(input), out);
}

}  // namespace

bool eip2333_master_key(const uint8_t *seed, size_t seed_size,
                        uint8_t out_sk[32]) {
  if (seed == nullptr || out_sk == nullptr || seed_size == 0) return false;
  return hkdf_mod_r(seed, seed_size, out_sk);
}

bool eip2333_derive_child(const uint8_t parent_sk[32], uint32_t index,
                          uint8_t out_sk[32]) {
  if (parent_sk == nullptr || out_sk == nullptr) return false;
  uint8_t compressed[32];
  if (!parent_sk_to_lamport_pk(parent_sk, index, compressed)) return false;
  const bool ok = hkdf_mod_r(compressed, sizeof(compressed), out_sk);
  secure_zero(compressed, sizeof(compressed));
  return ok;
}

// EIP-2333 12381'/8444'/0'/index' secret key. The standard puzzle's synthetic
// key is derived from this key plus the hidden puzzle hash, so address and
// signing must both start here.
bool chia_standard_private_key(const uint8_t *seed, size_t seed_size,
                               uint32_t address_index, uint8_t out_sk[32]) {
  if (seed == nullptr || out_sk == nullptr || seed_size == 0) return false;
  if (!hkdf_mod_r(seed, seed_size, out_sk)) return false;
  const uint32_t path[4] = { 12381, 8444, 0, address_index };
  for (size_t index = 0; index < 4; ++index) {
    if (!eip2333_derive_child(out_sk, path[index], out_sk)) {
      secure_zero(out_sk, 32);
      return false;
    }
  }
  return true;
}

bool chia_standard_address(const uint8_t *seed, size_t seed_size,
                           uint32_t address_index, char *out, size_t out_size) {
  if (seed == nullptr || out == nullptr || seed_size == 0) return false;
  uint8_t sk[32];
  if (!chia_standard_private_key(seed, seed_size, address_index, sk)) {
    return false;
  }
  uint8_t pubkey[48];
  if (!bls12_381_g1_public_key(sk, pubkey)) {
    secure_zero(sk, sizeof(sk));
    return false;
  }
  // DEFAULT_HIDDEN_PUZZLE = ff0980 => tree hash = pair(atom 0x09, nil).
  uint8_t atom09[1] = { 0x09 };
  uint8_t nil_hash[32];
  uint8_t atom09_hash[32];
  uint8_t hidden_hash[32];
  shatree_atom(nullptr, 0, nil_hash);
  shatree_atom(atom09, 1, atom09_hash);
  shatree_pair(atom09_hash, nil_hash, hidden_hash);

  // synthetic_offset = int(SHA256(pubkey || hidden_hash)) mod r
  uint8_t offset_input[48 + 32];
  memcpy(offset_input, pubkey, 48);
  memcpy(offset_input + 48, hidden_hash, 32);
  uint8_t offset_digest[32];
  uint8_t offset_bytes[32];
  bool ok = sha256(offset_input, sizeof(offset_input), offset_digest) &&
            bls_scalar_reduce(offset_digest, sizeof(offset_digest), offset_bytes) &&
            bls12_381_g1_add_generator(pubkey, offset_bytes, pubkey);
  // puzzle_hash = curry_and_treehash(QUOTED_MOD_HASH, shatree_atom(pubkey))
  static const uint8_t kModHash[32] = {
    0xe9,
    0xaa,
    0xa4,
    0x9f,
    0x45,
    0xba,
    0xd5,
    0xc8,
    0x89,
    0xb8,
    0x6e,
    0xe3,
    0x34,
    0x15,
    0x50,
    0xc1,
    0x55,
    0xcf,
    0xdd,
    0x10,
    0xc3,
    0xa6,
    0x75,
    0x7d,
    0xe6,
    0x18,
    0xd2,
    0x06,
    0x12,
    0xff,
    0xfd,
    0x52,
  };
  uint8_t one_hash[32];
  uint8_t quoted_mod_hash[32];
  uint8_t arg_hash[32];
  uint8_t c_kw_hash[32];
  uint8_t a_kw_hash[32];
  uint8_t curried_values[32];
  uint8_t puzzle_hash[32];
  const uint8_t one_atom[1] = { 0x01 };
  const uint8_t two_atom[1] = { 0x02 };
  const uint8_t four_atom[1] = { 0x04 };
  if (ok) {
    shatree_atom(one_atom, 1, one_hash);                // shatree_int(1)
    shatree_pair(one_hash, kModHash, quoted_mod_hash);  // (q . MOD)
    shatree_atom(pubkey, 48, arg_hash);
    shatree_atom(four_atom, 1, c_kw_hash);
    shatree_atom(two_atom, 1, a_kw_hash);
    // curried_values = (c (q arg) (1 . nil))
    uint8_t quoted_arg[32];
    uint8_t tail[32];
    uint8_t cv_pair[32];
    uint8_t inner[32];
    shatree_pair(one_hash, arg_hash, quoted_arg);  // (q . arg)
    shatree_pair(one_hash, nil_hash, tail);        // (1 . nil)
    shatree_pair(quoted_arg, tail, cv_pair);       // ((q arg) . (1 nil))
    shatree_pair(c_kw_hash, cv_pair, curried_values);
    // puzzle_hash = (a (q . MOD) (curried . nil))
    shatree_pair(curried_values, nil_hash, inner);
    shatree_pair(quoted_mod_hash, inner, puzzle_hash);
    shatree_pair(a_kw_hash, puzzle_hash, puzzle_hash);
  }

  if (ok) {
    ok = bech32_encode("xch", puzzle_hash, 32, out, out_size, true);
  }
  secure_zero(sk, sizeof(sk));
  secure_zero(pubkey, sizeof(pubkey));
  secure_zero(hidden_hash, sizeof(hidden_hash));
  secure_zero(offset_digest, sizeof(offset_digest));
  secure_zero(offset_bytes, sizeof(offset_bytes));
  secure_zero(arg_hash, sizeof(arg_hash));
  secure_zero(curried_values, sizeof(curried_values));
  secure_zero(puzzle_hash, sizeof(puzzle_hash));
  return ok;
}

}  // namespace hexwallet
