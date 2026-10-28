#include "CryptoNoteMasari.h"

#include <string.h>
#if defined(HEXWALLET_HOST_TEST)
#include <stdio.h>
#endif

#include "CryptoExtended.h"
#include "CryptoNoteAddress.h"
#include "CryptoNoteAmounts.h"
#include "CryptoPrimitives.h"
#include "WalletConfig.h"
#include "WalletSecurity.h"
#include "keccak256.h"

namespace hexwallet
{
  namespace
  {
    constexpr uint8_t kTxinToKey = 2;
    constexpr uint8_t kTxoutToKey = 2;
    constexpr uint8_t kExtraTagPublicKey = 0x01;
    constexpr uint8_t kIdentityPoint[kCryptoNoteKeySize] = {1};
    constexpr uint8_t kBasePoint[kCryptoNoteKeySize] = {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
    // RingCT's amount generator H (rct::H), shared with the BP+ implementation.
    const uint8_t kGeneratorH[kCryptoNoteKeySize] = {
        0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f,
        0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
        0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94};
    const uint8_t kScalarZero[kCryptoNoteKeySize] = {0};
    const uint8_t kScalarOne[kCryptoNoteKeySize] = {1};
    const uint8_t kScalarL[kCryptoNoteKeySize] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
        0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
    const uint8_t kScalarInvEight[kCryptoNoteKeySize] = {
        0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d,
        0xb3, 0x9d, 0xd3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06};

    int g_masari_stage = 0;
    int g_masari_error = -1;
    size_t g_last_rct_type_offset = 0;
#define MASARI_STAGE(n) do { g_masari_stage = (n); } while (0)

    void sc_add(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
    {
      ed25519_scalar_muladd(out, a, kScalarOne, b);
    }
    void sc_sub(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
    {
      ed25519_scalar_mulsub(out, kScalarOne, b, a);
    }
    void sc_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
    {
      ed25519_scalar_muladd(out, a, b, kScalarZero);
    }
    void sc_neg(uint8_t out[32], const uint8_t a[32])
    {
      ed25519_scalar_mulsub(out, kScalarOne, a, kScalarZero);
    }
    bool sc_is_zero(const uint8_t a[32])
    {
      uint8_t acc = 0;
      for (size_t i = 0; i < 32; ++i) acc |= a[i];
      return acc == 0;
    }
    bool sc_is_reduced(const uint8_t a[32])
    {
      for (size_t i = 32; i-- > 0;)
      {
        if (a[i] < kScalarL[i]) return true;
        if (a[i] > kScalarL[i]) return false;
      }
      return false;
    }
    void scalar_u64(uint8_t out[32], uint64_t value)
    {
      memset(out, 0, 32);
      for (size_t i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>(value >> (8 * i));
    }
    bool point_equals(const uint8_t a[32], const uint8_t b[32])
    {
      return crypto_constant_time_equal(a, b, 32);
    }
    bool point_mul8(const uint8_t in[32], uint8_t out[32])
    {
      uint8_t doubled[32], quadrupled[32];
      return ed25519_point_add_compressed(in, in, doubled) &&
             ed25519_point_add_compressed(doubled, doubled, quadrupled) &&
             ed25519_point_add_compressed(quadrupled, quadrupled, out);
    }

    size_t encode_varint(uint8_t *out, size_t value)
    {
      size_t n = 0;
      do
      {
        uint8_t byte = static_cast<uint8_t>(value & 0x7f);
        value >>= 7;
        if (value != 0) byte |= 0x80;
        out[n++] = byte;
      } while (value != 0);
      return n;
    }

    // rct::hashToPoint: Keccak once, map to the curve, clear the cofactor.
    bool hash_to_p3(const uint8_t key[32], uint8_t out[32])
    {
      uint8_t inner[32];
      if (!crypto_keccak256(key, 32, inner)) return false;
      uint8_t mapped[32];
      if (!ed25519_hash_to_point(inner, mapped)) return false;
      return point_mul8(mapped, out);
    }

    // Masari bulletproofs.cc get_exponent(H, idx).
    bool get_exponent(size_t idx, uint8_t out[32])
    {
      uint8_t buffer[32 + 10 + 10];
      memcpy(buffer, kGeneratorH, 32);
      memcpy(buffer + 32, "bulletproof", 10);
      const size_t used = encode_varint(buffer + 42, idx);
      uint8_t digest[32];
      if (!crypto_keccak256(buffer, 42 + used, digest)) return false;
      return hash_to_p3(digest, out);
    }

    struct Accumulator
    {
      uint8_t point[32];
      bool primed;
    };
    bool accumulate(Accumulator &acc, const uint8_t scalar[32], const uint8_t point[32])
    {
      if (sc_is_zero(scalar)) return true;
      uint8_t term[32];
      if (!ed25519_point_mul_compressed(point, scalar, term)) return false;
      if (!acc.primed)
      {
        memcpy(acc.point, term, 32);
        acc.primed = true;
        return true;
      }
      uint8_t sum[32];
      if (!ed25519_point_add_compressed(acc.point, term, sum)) return false;
      memcpy(acc.point, sum, 32);
      return true;
    }

    struct Reader
    {
      const uint8_t *data;
      size_t size;
      size_t offset;
      bool ok;

      bool bytes(const uint8_t **out, size_t count)
      {
        if (!ok || count > size - offset) { ok = false; return false; }
        *out = data + offset;
        offset += count;
        return true;
      }
      bool byte(uint8_t *value)
      {
        const uint8_t *p = nullptr;
        if (!bytes(&p, 1)) return false;
        *value = p[0];
        return true;
      }
      bool u32(uint32_t *value)
      {
        const uint8_t *p = nullptr;
        if (!bytes(&p, 4)) return false;
        *value = static_cast<uint32_t>(p[0]) |
                 (static_cast<uint32_t>(p[1]) << 8) |
                 (static_cast<uint32_t>(p[2]) << 16) |
                 (static_cast<uint32_t>(p[3]) << 24);
        return true;
      }
      bool varint(uint64_t *value)
      {
        uint64_t v = 0;
        unsigned shift = 0;
        size_t consumed = 0;
        for (;;)
        {
          uint8_t b = 0;
          if (!byte(&b)) return false;
          ++consumed;
          if (consumed > 10 || shift >= 64) { ok = false; return false; }
          const uint64_t payload = static_cast<uint64_t>(b & 0x7f);
          if (shift == 63 && payload > 1) { ok = false; return false; }
          v |= payload << shift;
          if ((b & 0x80) == 0)
          {
            if (consumed > 1 && payload == 0) { ok = false; return false; }
            *value = v;
            return true;
          }
          shift += 7;
        }
      }
      bool finished() const { return ok && offset == size; }
    };

    bool keccak_key_list(const uint8_t *keys, size_t count, uint8_t out[32])
    {
      uint8_t digest[32];
      if (!crypto_keccak256(keys, count * 32, digest)) return false;
      memcpy(out, digest, 32);
      ed25519_scalar_reduce_mod_l(out);
      return true;
    }

    // ---------------------------------------------------------------------
    // Borromean range proof (RCT full/simple). Verified in place; the proof
    // is never copied or stored.
    // ---------------------------------------------------------------------
    bool verify_borromean(const uint8_t commitment[32], const uint8_t *proof)
    {
      const uint8_t *s0 = proof;
      const uint8_t *s1 = proof + 64 * 32;
      const uint8_t *ee = proof + 128 * 32;
      const uint8_t *ci = proof + 129 * 32;
      for (size_t i = 0; i < 64; ++i)
      {
        if (!sc_is_reduced(s0 + i * 32) || !sc_is_reduced(s1 + i * 32))
          return false;
      }
      if (!sc_is_reduced(ee)) return false;

      uint8_t sum[32];
      memcpy(sum, kIdentityPoint, 32);
      for (size_t i = 0; i < 64; ++i)
      {
        uint8_t next[32];
        if (!ed25519_point_add_compressed(sum, ci + i * 32, next)) return false;
        memcpy(sum, next, 32);
      }
      if (!point_equals(sum, commitment)) return false;

      SHA3_CTX ctx;
      keccak_init(&ctx);
      uint8_t zero_mask[32] = {0};
      for (size_t i = 0; i < 64; ++i)
      {
        uint8_t h2[32], p2[32], l0[32], challenge[32], l1[32];
        if (!ringct_commitment(zero_mask, static_cast<uint64_t>(1) << i, h2))
          return false;
        if (!ed25519_point_sub_compressed(ci + i * 32, h2, p2)) return false;
        if (!ed25519_double_scalar_mul(ci + i * 32, ee, kBasePoint,
                                       s0 + i * 32, l0))
          return false;
        if (!cryptonote_hash_to_scalar(l0, 32, challenge)) return false;
        if (!ed25519_double_scalar_mul(p2, challenge, kBasePoint,
                                       s1 + i * 32, l1))
          return false;
        if (!keccak_update(&ctx, l1, 32)) return false;
      }
      uint8_t computed[32];
      if (!keccak_final(&ctx, computed)) return false;
      ed25519_scalar_reduce_mod_l(computed);
      return crypto_constant_time_equal(computed, ee, 32);
    }

    // ---------------------------------------------------------------------
    // Bulletproof verification (RCT type 3). Ported from the pinned Masari
    // bulletproofs.cc equation with the batch weights set to one; each proof
    // is checked on its own, so no randomisation is needed for soundness.
    // ---------------------------------------------------------------------
    bool verify_bulletproof(const uint8_t (*commitments)[32], size_t count,
                            const MasariBulletproof &proof)
    {
      if (count == 0 || count > kMasariMaxTxOutputs) return false;
      if (proof.l_count != proof.r_count || proof.l_count < 6 ||
          proof.l_count > 8)
        return false;
      if (!sc_is_reduced(proof.taux) || !sc_is_reduced(proof.mu) ||
          !sc_is_reduced(proof.a_scalar) || !sc_is_reduced(proof.b) ||
          !sc_is_reduced(proof.t))
        return false;

      size_t log_m = 0;
      while ((static_cast<size_t>(1) << log_m) < count) ++log_m;
      const size_t rounds = 6 + log_m;
      if (rounds > 8 || proof.l_count != rounds) return false;
      const size_t m = static_cast<size_t>(1) << log_m;
      const size_t mn = m * 64;

      uint8_t v_divided[4][32];
      for (size_t i = 0; i < count; ++i)
        if (!ed25519_point_mul_compressed(commitments[i], kScalarInvEight,
                                          v_divided[i]))
          return false;

      uint8_t hash_cache[32];
      if (!keccak_key_list(&v_divided[0][0], count, hash_cache)) return false;

      uint8_t buffer[5 * 32];
      memcpy(buffer, hash_cache, 32);
      memcpy(buffer + 32, proof.a, 32);
      memcpy(buffer + 64, proof.s, 32);
      uint8_t y[32];
      if (!keccak_key_list(buffer, 3, y) || sc_is_zero(y)) return false;
      uint8_t z[32];
      if (!cryptonote_hash_to_scalar(y, 32, z) || sc_is_zero(z)) return false;
      memcpy(buffer, z, 32);
      memcpy(buffer + 32, z, 32);
      memcpy(buffer + 64, proof.t1, 32);
      memcpy(buffer + 96, proof.t2, 32);
      uint8_t x[32];
      if (!keccak_key_list(buffer, 4, x) || sc_is_zero(x)) return false;
      memcpy(buffer, x, 32);
      memcpy(buffer + 32, x, 32);
      memcpy(buffer + 64, proof.taux, 32);
      memcpy(buffer + 96, proof.mu, 32);
      memcpy(buffer + 128, proof.t, 32);
      uint8_t x_ip[32];
      if (!keccak_key_list(buffer, 5, x_ip) || sc_is_zero(x_ip)) return false;

      uint8_t w[8][32], w_inv[8][32];
      uint8_t hash_cache_next[32];
      memcpy(hash_cache_next, x_ip, 32);
      for (size_t j = 0; j < rounds; ++j)
      {
        memcpy(buffer, hash_cache_next, 32);
        memcpy(buffer + 32, proof.l[j], 32);
        memcpy(buffer + 64, proof.r[j], 32);
        if (!keccak_key_list(buffer, 3, w[j]) || sc_is_zero(w[j])) return false;
        // inverse via Fermat
        uint8_t lm2[32];
        memcpy(lm2, kScalarL, 32);
        lm2[0] -= 2;
        uint8_t result[32] = {1};
        uint8_t base[32];
        memcpy(base, w[j], 32);
        for (int bit = 252; bit >= 0; --bit)
        {
          sc_mul(result, result, result);
          if ((lm2[bit >> 3] >> (bit & 7)) & 1u) sc_mul(result, result, base);
        }
        memcpy(w_inv[j], result, 32);
        memcpy(hash_cache_next, w[j], 32);
#if defined(HEXWALLET_HOST_TEST)
#endif
      }
      uint8_t y_inv[32];
      {
        uint8_t lm2[32];
        memcpy(lm2, kScalarL, 32);
        lm2[0] -= 2;
        uint8_t result[32] = {1};
        for (int bit = 252; bit >= 0; --bit)
        {
          sc_mul(result, result, result);
          if ((lm2[bit >> 3] >> (bit & 7)) & 1u) sc_mul(result, result, y);
        }
        memcpy(y_inv, result, 32);
      }

      // z powers up to M+2
      uint8_t zpow[kMasariMaxTxOutputs + 3][32];
      memcpy(zpow[0], kScalarOne, 32);
      if (sizeof(zpow) / 32 > 1) memcpy(zpow[1], z, 32);
      for (size_t i = 2; i < sizeof(zpow) / 32; ++i) sc_mul(zpow[i], zpow[i - 1], z);

      uint8_t ip1y[32] = {0};
      {
        uint8_t power[32] = {1};
        uint8_t next[32];
        for (size_t i = 0; i < mn; ++i)
        {
          sc_add(ip1y, ip1y, power);
          if (i + 1 < mn) { sc_mul(next, power, y); memcpy(power, next, 32); }
        }
      }
      uint8_t ip12[32];
      scalar_u64(ip12, UINT64_MAX);

      uint8_t k[32];
      sc_neg(k, zpow[2]);
      sc_mul(k, k, ip1y);
      for (size_t j = 1; j <= m; ++j)
      {
        uint8_t term[32];
        sc_mul(term, zpow[j + 2], ip12);
        sc_sub(k, k, term);
      }
      uint8_t y1[32], tmp[32], z3[32];
      sc_mul(tmp, z, ip1y);
      sc_add(tmp, tmp, k);
      sc_sub(y1, proof.t, tmp);
      {
        uint8_t product[32];
        sc_mul(product, proof.a_scalar, proof.b);
        sc_sub(tmp, proof.t, product);  // t - a*b
        sc_mul(z3, tmp, x_ip);
      }

      Accumulator acc;
      acc.primed = false;
      memset(acc.point, 0, 32);
      {
        uint8_t scalar[32];
        sc_neg(scalar, proof.taux);           // m_y0
        sc_sub(scalar, scalar, proof.mu);     // - m_y0 - z1
        if (!accumulate(acc, scalar, kBasePoint)) return false;
        sc_sub(scalar, z3, y1);
        if (!accumulate(acc, scalar, kGeneratorH)) return false;
      }

      // w_cache expansion, exactly as the Masari verifier does it.
      static uint8_t w_cache[1 << 8][32];
      memcpy(w_cache[0], w_inv[0], 32);
      memcpy(w_cache[1], w[0], 32);
      for (size_t j = 1; j < rounds; ++j)
      {
        const size_t slots = static_cast<size_t>(1) << (j + 1);
        for (size_t s = slots - 1; s > 0; )
        {
          uint8_t base[32];
          memcpy(base, w_cache[s / 2], 32);
          sc_mul(w_cache[s], base, w[j]);
          sc_mul(w_cache[s - 1], base, w_inv[j]);
          if (s < 2) break;
          s -= 2;
        }
      }

      uint8_t yinvpow[32] = {1};
      uint8_t ypow[32] = {1};
      for (size_t i = 0; i < mn; ++i)
      {
        uint8_t g_scalar[32], h_scalar[32];
        memcpy(g_scalar, proof.a_scalar, 32);
        if (i == 0) memcpy(h_scalar, proof.b, 32);
        else sc_mul(h_scalar, proof.b, yinvpow);
        sc_mul(g_scalar, g_scalar, w_cache[i]);
        sc_mul(h_scalar, h_scalar, w_cache[(~i) & (mn - 1)]);
        sc_add(g_scalar, g_scalar, z);
        // z^(2+i/64) * 2^(i%64)
        uint8_t two[32];
        scalar_u64(two, static_cast<uint64_t>(1) << (i % 64));
        sc_mul(tmp, zpow[2 + i / 64], two);
        if (i == 0)
        {
          sc_add(tmp, tmp, z);
          sc_sub(h_scalar, h_scalar, tmp);
        }
        else
        {
          uint8_t shifted[32], zterm[32];
          scalar_u64(shifted, static_cast<uint64_t>(1) << (i % 64));
          sc_mul(zterm, zpow[2 + i / 64], shifted);
          sc_add(tmp, tmp, zterm);
          sc_mul(zterm, z, ypow);
          sc_add(tmp, tmp, zterm);
          sc_mul(tmp, tmp, yinvpow);
          sc_sub(h_scalar, h_scalar, tmp);
        }
        uint8_t gi[32], hi[32], term[32];
        if (!get_exponent(i * 2 + 1, gi) || !get_exponent(i * 2, hi)) return false;
        if (!ed25519_double_scalar_mul(gi, g_scalar, hi, h_scalar, term))
          return false;
        uint8_t negative[32];
        sc_neg(negative, kScalarOne);
        if (!accumulate(acc, negative, term)) return false;
        if (i + 1 < mn)
        {
          sc_mul(yinvpow, yinvpow, y_inv);
          sc_mul(ypow, ypow, y);
        }
      }

      // V, T1, T2, A, S, L, R. The equation is written over 8*A, 8*S,
      // 8*T1, 8*T2, 8*L and 8*R (Masari's proof8_* values).
      uint8_t eight[32];
      scalar_u64(eight, 8);
      uint8_t scaled_point[32];
      for (size_t i = 0; i < count; ++i)
      {
        if (!accumulate(acc, zpow[i + 2], commitments[i])) return false;
      }
      if (!ed25519_point_mul_compressed(proof.t1, eight, scaled_point) ||
          !accumulate(acc, x, scaled_point))
        return false;
      {
        uint8_t x2[32];
        sc_mul(x2, x, x);
        if (!ed25519_point_mul_compressed(proof.t2, eight, scaled_point) ||
            !accumulate(acc, x2, scaled_point))
          return false;
      }
      if (!ed25519_point_mul_compressed(proof.a, eight, scaled_point) ||
          !accumulate(acc, kScalarOne, scaled_point))
        return false;
      if (!ed25519_point_mul_compressed(proof.s, eight, scaled_point) ||
          !accumulate(acc, x, scaled_point))
        return false;
      for (size_t j = 0; j < rounds; ++j)
      {
        uint8_t squared[32];
        sc_mul(squared, w[j], w[j]);
        if (!ed25519_point_mul_compressed(proof.l[j], eight, scaled_point) ||
            !accumulate(acc, squared, scaled_point))
          return false;
        sc_mul(squared, w_inv[j], w_inv[j]);
        if (!ed25519_point_mul_compressed(proof.r[j], eight, scaled_point) ||
            !accumulate(acc, squared, scaled_point))
          return false;
      }
      return acc.primed && point_equals(acc.point, kIdentityPoint);
    }

    // ---------------------------------------------------------------------
    // MLSAG
    // ---------------------------------------------------------------------
    void mlsag_random(const uint8_t nonce_seed[32], const uint8_t message[32],
                      uint8_t column, uint8_t row, uint8_t tag, uint8_t out[32])
    {
      uint8_t buffer[32 + 32 + 3];
      memcpy(buffer, nonce_seed, 32);
      memcpy(buffer + 32, message, 32);
      buffer[64] = column;
      buffer[65] = row;
      buffer[66] = tag;
      cryptonote_hash_to_scalar(buffer, sizeof(buffer), out);
      if (sc_is_zero(out)) out[0] = 1;
    }

    bool mlsag_sign(const uint8_t message[32],
                    const uint8_t (*matrix)[32], size_t columns, size_t rows,
                    size_t ds_rows, size_t index,
                    const uint8_t (*secrets)[32],
                    const uint8_t (*expected_images)[32],
                    const uint8_t nonce_seed[32],
                    uint8_t cc[32], uint8_t (*ss)[32])
    {
      if (columns < 2 || columns > kMasariMaxRingSize || index >= columns ||
          rows == 0 || rows > kMasariMaxTxInputs + 1 || ds_rows > rows)
        return false;
      uint8_t alpha[kMasariMaxTxInputs + 1][32];
      uint8_t a_g[kMasariMaxTxInputs + 1][32];
      uint8_t a_hp[kMasariMaxTxInputs][32];
      uint8_t images[kMasariMaxTxInputs][32];
      uint8_t generators[kMasariMaxTxInputs][32];
      uint8_t hashes[1 + 3 * kMasariMaxTxInputs + 2][32];

      for (size_t j = 0; j < rows; ++j)
        mlsag_random(nonce_seed, message, static_cast<uint8_t>(index),
                     static_cast<uint8_t>(j), 0xa1, alpha[j]);
      for (size_t j = 0; j < ds_rows; ++j)
      {
        if (!cryptonote_key_image_generator(matrix[index * rows + j],
                                            generators[j]))
          return false;
        if (!ed25519_point_mul_compressed(generators[j], secrets[j], images[j]))
          return false;
        if (expected_images != nullptr &&
            !point_equals(images[j], expected_images[j]))
          return false;
        if (!ed25519_point_mul_compressed(kBasePoint, alpha[j], a_g[j]) ||
            !ed25519_point_mul_compressed(generators[j], alpha[j], a_hp[j]))
          return false;
      }
      for (size_t j = ds_rows; j < rows; ++j)
      {
        if (!ed25519_point_mul_compressed(kBasePoint, alpha[j], a_g[j]))
          return false;
      }

      size_t position = 0;
      memcpy(hashes[position++], message, 32);
      for (size_t j = 0; j < ds_rows; ++j)
      {
        memcpy(hashes[position++], matrix[index * rows + j], 32);
        memcpy(hashes[position++], a_g[j], 32);
        memcpy(hashes[position++], a_hp[j], 32);
      }
      for (size_t j = ds_rows; j < rows; ++j)
      {
        memcpy(hashes[position++], matrix[index * rows + j], 32);
        memcpy(hashes[position++], a_g[j], 32);
      }
      uint8_t c[32];
      if (!keccak_key_list(&hashes[0][0], position, c)) return false;
      // cc is the challenge at the last column; verification starts there and
      // walks the entire ring once. ss[real] uses the challenge that precedes
      // the real index, i.e. the final value computed by this loop.
      if (index == columns - 1) memcpy(cc, c, 32);

      size_t cursor = (index + 1) % columns;
      while (cursor != index)
      {
        for (size_t j = 0; j < rows; ++j)
          mlsag_random(nonce_seed, message, static_cast<uint8_t>(cursor),
                       static_cast<uint8_t>(j), 0xb2 + static_cast<uint8_t>(j),
                       ss[cursor * rows + j]);
        position = 0;
        memcpy(hashes[position++], message, 32);
        for (size_t j = 0; j < ds_rows; ++j)
        {
          uint8_t left[32], right[32], generator[32];
          if (!cryptonote_key_image_generator(matrix[cursor * rows + j],
                                              generator) ||
              !ed25519_double_scalar_mul(kBasePoint, ss[cursor * rows + j],
                                         matrix[cursor * rows + j], c, left) ||
              !ed25519_double_scalar_mul(generator, ss[cursor * rows + j],
                                         images[j], c, right))
            return false;
          memcpy(hashes[position++], matrix[cursor * rows + j], 32);
          memcpy(hashes[position++], left, 32);
          memcpy(hashes[position++], right, 32);
        }
        for (size_t j = ds_rows; j < rows; ++j)
        {
          uint8_t left[32];
          if (!ed25519_double_scalar_mul(kBasePoint, ss[cursor * rows + j],
                                         matrix[cursor * rows + j], c, left))
            return false;
          memcpy(hashes[position++], matrix[cursor * rows + j], 32);
          memcpy(hashes[position++], left, 32);
        }
        if (!keccak_key_list(&hashes[0][0], position, c)) return false;
        if (cursor == columns - 1) memcpy(cc, c, 32);
        cursor = (cursor + 1) % columns;
      }

      for (size_t j = 0; j < rows; ++j)
        ed25519_scalar_mulsub(ss[index * rows + j], c, secrets[j], alpha[j]);
      return true;
    }

    bool mlsag_verify(const uint8_t message[32],
                      const uint8_t (*matrix)[32], size_t columns, size_t rows,
                      size_t ds_rows, const uint8_t cc[32],
                      const uint8_t (*ss)[32],
                      const uint8_t (*images)[32])
    {
      if (columns < 2 || columns > kMasariMaxRingSize || rows == 0 ||
          ds_rows > rows)
        return false;
      for (size_t i = 0; i < columns * rows; ++i)
        if (!sc_is_reduced(&ss[i][0])) return false;
      if (!sc_is_reduced(cc)) return false;
      uint8_t hashes[1 + 3 * kMasariMaxTxInputs + 2][32];
      uint8_t c[32];
      memcpy(c, cc, 32);
      for (size_t i = 0; i < columns; ++i)
      {
        size_t position = 0;
        memcpy(hashes[position++], message, 32);
        for (size_t j = 0; j < ds_rows; ++j)
        {
          uint8_t left[32], right[32], generator[32];
          if (!cryptonote_key_image_generator(matrix[i * rows + j], generator) ||
              !ed25519_double_scalar_mul(kBasePoint, ss[i * rows + j],
                                         matrix[i * rows + j], c, left) ||
              !ed25519_double_scalar_mul(generator, ss[i * rows + j],
                                         images[j], c, right))
            return false;
          memcpy(hashes[position++], matrix[i * rows + j], 32);
          memcpy(hashes[position++], left, 32);
          memcpy(hashes[position++], right, 32);
        }
        for (size_t j = ds_rows; j < rows; ++j)
        {
          uint8_t left[32];
          if (!ed25519_double_scalar_mul(kBasePoint, ss[i * rows + j],
                                         matrix[i * rows + j], c, left))
            return false;
          memcpy(hashes[position++], matrix[i * rows + j], 32);
          memcpy(hashes[position++], left, 32);
        }
          if (!keccak_key_list(&hashes[0][0], position, c)) return false;
        }
        return point_equals(c, cc);
    }

    bool derive_one_time(const uint8_t view_secret[32],
                         const uint8_t spend_secret[32],
                         const uint8_t base_public[32],
                         const uint8_t tx_public[32], uint64_t output_index,
                         uint8_t out_public[32], uint8_t out_secret[32],
                         uint8_t out_amount_key[32])
    {
      uint8_t derivation[32];
      if (!cryptonote_generate_key_derivation(tx_public, view_secret, derivation))
        return false;
      uint8_t amount_key[32];
      const bool ok =
          cryptonote_derivation_to_scalar(derivation, output_index, amount_key) &&
          cryptonote_derive_public_key(derivation, output_index, base_public,
                                       out_public) &&
          cryptonote_derive_secret_key(derivation, output_index, spend_secret,
                                       out_secret);
      if (ok)
      {
        memcpy(out_amount_key, amount_key, 32);
      }
      secure_zero(derivation, sizeof(derivation));
      secure_zero(amount_key, sizeof(amount_key));
      return ok;
    }

    // Legacy Masari ECDH (rctOps.cpp ecdhEncode): scalar addition, not ChaCha.
    bool decode_legacy_amount(const uint8_t amount_key[32],
                              const uint8_t wire_mask[32],
                              const uint8_t wire_amount[32],
                              uint64_t *amount, uint8_t mask[32])
    {
      uint8_t shared1[32], shared2[32];
      if (!cryptonote_hash_to_scalar(amount_key, 32, shared1) ||
          !cryptonote_hash_to_scalar(shared1, 32, shared2))
        return false;
      ed25519_scalar_mulsub(mask, kScalarOne, shared1, wire_mask);
      uint8_t amount_scalar[32];
      ed25519_scalar_mulsub(amount_scalar, kScalarOne, shared2, wire_amount);
      bool ok = true;
      for (size_t i = 8; i < 32; ++i) if (amount_scalar[i] != 0) ok = false;
      uint64_t value = 0;
      for (size_t i = 0; i < 8; ++i) value |= static_cast<uint64_t>(amount_scalar[i]) << (8 * i);
      *amount = value;
      secure_zero(shared1, sizeof(shared1));
      secure_zero(shared2, sizeof(shared2));
      secure_zero(amount_scalar, sizeof(amount_scalar));
      return ok;
    }

    bool is_change_output(const uint8_t spend_public[32],
                          const uint8_t view_public[32],
                          const uint8_t our_spend[32], const uint8_t our_view[32])
    {
      return point_equals(spend_public, our_spend) &&
             point_equals(view_public, our_view);
    }

    // Change may sit on the standard address or on one of our subaddresses.
    // The host names the subaddress; the device re-derives the key pair and
    // compares, so a foreign key can never be labelled change.
    bool owned_change(const MasariReviewOutput &declared,
                      const uint8_t spend_secret[32],
                      const uint8_t view_secret[32],
                      const uint8_t our_spend[32], const uint8_t our_view[32])
    {
      if (declared.subaddress_major == 0 && declared.subaddress_minor == 0)
        return is_change_output(declared.spend_public, declared.view_public,
                                our_spend, our_view);
      uint8_t sub_secret[32], sub_spend[32], sub_view[32];
      const bool derived =
          cryptonote_subaddress_keys(spend_secret, view_secret,
                                     declared.subaddress_major,
                                     declared.subaddress_minor, sub_secret,
                                     sub_spend, sub_view) == WalletError::Ok;
      const bool match = derived &&
                         point_equals(declared.spend_public, sub_spend) &&
                         point_equals(declared.view_public, sub_view);
      secure_zero(sub_secret, sizeof(sub_secret));
      secure_zero(sub_spend, sizeof(sub_spend));
      secure_zero(sub_view, sizeof(sub_view));
      return match;
    }

    // Spend material for one input: the master pair for (0, 0), otherwise the
    // subaddress pair b + m / B + m*G.
    bool input_spend_keys(const MasariReviewInput &source,
                          const uint8_t spend_secret[32],
                          const uint8_t view_secret[32],
                          const uint8_t our_spend[32],
                          uint8_t out_secret[32], uint8_t out_public[32])
    {
      if (source.subaddress_major == 0 && source.subaddress_minor == 0)
      {
        memcpy(out_secret, spend_secret, 32);
        memcpy(out_public, our_spend, 32);
        return true;
      }
      uint8_t sub_view[32];
      const bool ok =
          cryptonote_subaddress_keys(spend_secret, view_secret,
                                     source.subaddress_major,
                                     source.subaddress_minor, out_secret,
                                     out_public, sub_view) == WalletError::Ok;
      secure_zero(sub_view, sizeof(sub_view));
      if (!ok)
      {
        secure_zero(out_secret, 32);
        secure_zero(out_public, 32);
      }
      return ok;
    }

    bool key_offsets_valid(const MasariInput &wire, const MasariReviewInput &source)
    {
      if (wire.offset_count != source.ring_size || source.ring_size > kMasariMaxRingSize ||
          source.real_index >= source.ring_size)
        return false;
      uint64_t absolute = 0;
      for (uint16_t i = 0; i < source.ring_size; ++i)
      {
        if (wire.key_offsets[i] != source.key_offsets[i]) return false;
        if (i != 0 && (source.key_offsets[i] == 0 ||
                       UINT64_MAX - absolute < source.key_offsets[i]))
          return false;
        absolute += source.key_offsets[i];
      }
      return true;
    }
  } // namespace

  int masari_last_stage() { return g_masari_stage; }
  int masari_last_error() { return g_masari_error; }

  bool masari_rct_type3_enabled()
  {
#if HEXWALLET_MSR_ENABLE_RCT_TYPE3
    return true;
#else
    return false;
#endif
  }

  size_t masari_last_rct_type_offset() { return g_last_rct_type_offset; }

  bool masari_tx_extra_public_key(const MasariTransaction &tx, uint8_t out[32])
  {
    if (tx.extra_size > sizeof(tx.extra)) return false;
    return cryptonote_review_extra_public_key(tx.extra, tx.extra_size, out);
  }

  CryptoNoteTxError masari_parse_transaction(const uint8_t *data, size_t size,
                                             MasariTransaction *out)
  {
    MASARI_STAGE(1);
    if (data == nullptr || out == nullptr) return CryptoNoteTxError::InvalidArgument;
    memset(out, 0, sizeof(*out));
    if (size < 16) return CryptoNoteTxError::Truncated;
    if (size > kMasariMaxTxBytes) return CryptoNoteTxError::TooLarge;

    Reader reader = {data, size, 0, true};
    uint64_t version = 0;
    uint64_t unlock_time = 0;
    uint64_t count = 0;
    if (!reader.varint(&version) || !reader.varint(&unlock_time))
      return CryptoNoteTxError::Truncated;
    if (version != 2) return CryptoNoteTxError::Unsupported;
    if (!reader.varint(&count) || count == 0 || count > kMasariMaxTxInputs)
      return CryptoNoteTxError::TooManyItems;
    out->input_count = static_cast<uint16_t>(count);
    for (uint16_t i = 0; i < out->input_count; ++i)
    {
      uint64_t type = 0, amount = 0, offsets = 0;
      if (!reader.varint(&type) || !reader.varint(&amount) || !reader.varint(&offsets))
        return CryptoNoteTxError::Truncated;
      if (type != kTxinToKey || amount != 0) return CryptoNoteTxError::Unsupported;
      if (offsets == 0 || offsets > kMasariMaxRingSize)
        return CryptoNoteTxError::TooManyItems;
      out->inputs[i].offset_count = static_cast<uint16_t>(offsets);
      for (uint16_t m = 0; m < out->inputs[i].offset_count; ++m)
        if (!reader.varint(&out->inputs[i].key_offsets[m]))
          return CryptoNoteTxError::Truncated;
      const uint8_t *key_image = nullptr;
      if (!reader.bytes(&key_image, 32)) return CryptoNoteTxError::Truncated;
      memcpy(out->inputs[i].key_image, key_image, 32);
    }
    if (!reader.varint(&count) || count == 0 || count > kMasariMaxTxOutputs)
      return CryptoNoteTxError::TooManyItems;
    out->output_count = static_cast<uint16_t>(count);
    for (uint16_t i = 0; i < out->output_count; ++i)
    {
      uint64_t amount = 0, target = 0;
      if (!reader.varint(&amount) || !reader.varint(&target))
        return CryptoNoteTxError::Truncated;
      if (amount != 0 || target != kTxoutToKey)
        return CryptoNoteTxError::Unsupported;
      const uint8_t *public_key = nullptr;
      if (!reader.bytes(&public_key, 32)) return CryptoNoteTxError::Truncated;
      memcpy(out->outputs[i].public_key, public_key, 32);
    }
    uint64_t extra_size = 0;
    if (!reader.varint(&extra_size)) return CryptoNoteTxError::Truncated;
    if (extra_size > kMasariMaxTxExtra) return CryptoNoteTxError::TooLarge;
    const uint8_t *extra = nullptr;
    if (!reader.bytes(&extra, static_cast<size_t>(extra_size)))
      return CryptoNoteTxError::Truncated;
    out->extra_size = static_cast<uint16_t>(extra_size);
    memcpy(out->extra, extra, out->extra_size);
    const size_t prefix_size = reader.offset;
    for (uint16_t i = 1; i < out->input_count; ++i)
      if (out->inputs[i].offset_count != out->inputs[0].offset_count)
        return CryptoNoteTxError::NonCanonical;

    MASARI_STAGE(2);
    const size_t rct_start = reader.offset;
    g_last_rct_type_offset = rct_start;
    uint8_t rct_type = 0;
    uint64_t fee = 0;
    if (!reader.byte(&rct_type)) return CryptoNoteTxError::Truncated;
    if (rct_type < kMasariRctFull || rct_type > kMasariRctBulletproof)
      return CryptoNoteTxError::Unsupported;
    if (rct_type == kMasariRctBulletproof && !masari_rct_type3_enabled())
      return CryptoNoteTxError::Unsupported;
    out->rct_type = rct_type;
    if (!reader.varint(&fee)) return CryptoNoteTxError::Truncated;
    if (fee > kCryptoNoteMaxFee) return CryptoNoteTxError::InvalidAmount;
    out->fee = fee;
    if (rct_type == kMasariRctSimple)
    {
      for (uint16_t i = 0; i < out->input_count; ++i)
      {
        const uint8_t *pseudo = nullptr;
        if (!reader.bytes(&pseudo, 32)) return CryptoNoteTxError::Truncated;
        memcpy(out->pseudo_outs[i], pseudo, 32);
      }
    }
    for (uint16_t i = 0; i < out->output_count; ++i)
    {
      const uint8_t *p = nullptr;
      if (!reader.bytes(&p, 64)) return CryptoNoteTxError::Truncated;
      memcpy(out->outputs[i].ecdh_mask, p, 32);
      memcpy(out->outputs[i].ecdh_amount, p + 32, 32);
    }
    for (uint16_t i = 0; i < out->output_count; ++i)
    {
      const uint8_t *p = nullptr;
      if (!reader.bytes(&p, 32)) return CryptoNoteTxError::Truncated;
      memcpy(out->outputs[i].commitment, p, 32);
    }
    const size_t rct_base_end = reader.offset;

    MASARI_STAGE(3);
    SHA3_CTX proof_ctx;
    keccak_init(&proof_ctx);
    if (rct_type == kMasariRctBulletproof)
    {
      uint32_t proofs = 0;
      if (!reader.u32(&proofs)) return CryptoNoteTxError::Truncated;
      if (proofs != 1) return CryptoNoteTxError::TooManyItems;
      out->bp_count = 1;
      MasariBulletproof &bp = out->bps[0];
      const uint8_t *p = nullptr;
      if (!reader.bytes(&p, 6 * 32)) return CryptoNoteTxError::Truncated;
      memcpy(bp.a, p, 32);
      memcpy(bp.s, p + 32, 32);
      memcpy(bp.t1, p + 64, 32);
      memcpy(bp.t2, p + 96, 32);
      memcpy(bp.taux, p + 128, 32);
      memcpy(bp.mu, p + 160, 32);
      if (!keccak_update(&proof_ctx, p, 6 * 32)) return CryptoNoteTxError::CryptoFailure;
      uint64_t l_count = 0, r_count = 0;
      if (!reader.varint(&l_count) || l_count < 6 || l_count > kMasariMaxProofRounds)
        return CryptoNoteTxError::TooManyItems;
      bp.l_count = static_cast<uint8_t>(l_count);
      if (!reader.bytes(&p, 32 * bp.l_count)) return CryptoNoteTxError::Truncated;
      memcpy(&bp.l[0][0], p, 32 * bp.l_count);
      // The proof hash hashes the L entries without the length prefix.
      if (!keccak_update(&proof_ctx, p, 32 * bp.l_count))
        return CryptoNoteTxError::CryptoFailure;
      if (!reader.varint(&r_count) || r_count != l_count)
        return CryptoNoteTxError::TooManyItems;
      bp.r_count = static_cast<uint8_t>(r_count);
      if (!reader.bytes(&p, 32 * bp.r_count)) return CryptoNoteTxError::Truncated;
      memcpy(&bp.r[0][0], p, 32 * bp.r_count);
      if (!keccak_update(&proof_ctx, p, 32 * bp.r_count))
        return CryptoNoteTxError::CryptoFailure;
      if (!reader.bytes(&p, 3 * 32)) return CryptoNoteTxError::Truncated;
      memcpy(bp.a_scalar, p, 32);
      memcpy(bp.b, p + 32, 32);
      memcpy(bp.t, p + 64, 32);
      if (!keccak_update(&proof_ctx, p, 3 * 32))
        return CryptoNoteTxError::CryptoFailure;
    }
    else
    {
      for (uint16_t i = 0; i < out->output_count; ++i)
      {
        const uint8_t *proof = nullptr;
        if (!reader.bytes(&proof, kMasariBorromeanProofSize))
          return CryptoNoteTxError::Truncated;
        if (!keccak_update(&proof_ctx, proof, kMasariBorromeanProofSize))
          return CryptoNoteTxError::CryptoFailure;
        MASARI_STAGE(4);
        if (!verify_borromean(out->outputs[i].commitment, proof))
          return CryptoNoteTxError::InvalidAmount;
      }
    }

    MASARI_STAGE(5);
    const size_t mg_count = rct_type == kMasariRctFull ? 1 : out->input_count;
    const size_t rows = rct_type == kMasariRctFull ? out->input_count + 1 : 2;
    out->mg_count = static_cast<uint8_t>(mg_count);
    for (size_t m = 0; m < mg_count; ++m)
    {
      MasariMg &mg = out->mgs[m];
      mg.rows = static_cast<uint8_t>(rows);
      for (uint16_t i = 0; i < out->inputs[0].offset_count; ++i)
      {
        const uint8_t *p = nullptr;
        if (!reader.bytes(&p, rows * 32)) return CryptoNoteTxError::Truncated;
        memcpy(&mg.ss[i * rows][0], p, rows * 32);
      }
      const uint8_t *p = nullptr;
      if (!reader.bytes(&p, 32)) return CryptoNoteTxError::Truncated;
      memcpy(mg.cc, p, 32);
    }
    if (rct_type == kMasariRctBulletproof)
    {
      for (uint16_t i = 0; i < out->input_count; ++i)
      {
        const uint8_t *pseudo = nullptr;
        if (!reader.bytes(&pseudo, 32)) return CryptoNoteTxError::Truncated;
        memcpy(out->pseudo_outs[i], pseudo, 32);
      }
    }
    if (!reader.finished()) return CryptoNoteTxError::NonCanonical;

    uint8_t proofs_hash[32];
    if (!keccak_final(&proof_ctx, proofs_hash))
      return CryptoNoteTxError::CryptoFailure;
    uint8_t prefix_hash[32], base_hash[32], message_input[96];
    if (!crypto_keccak256(data, prefix_size, prefix_hash) ||
        !crypto_keccak256(data + rct_start, rct_base_end - rct_start, base_hash))
      return CryptoNoteTxError::CryptoFailure;
    memcpy(message_input, prefix_hash, 32);
    memcpy(message_input + 32, base_hash, 32);
    memcpy(message_input + 64, proofs_hash, 32);
    if (!crypto_keccak256(message_input, sizeof(message_input), out->message))
      return CryptoNoteTxError::CryptoFailure;

    // A proof for the wrong number of outputs is a structural error.
    if (rct_type == kMasariRctBulletproof)
    {
      const size_t rounds = out->bps[0].l_count;
      if (rounds < 6 || rounds > kMasariMaxProofRounds) return CryptoNoteTxError::InvalidArgument;
      const size_t max_outputs = static_cast<size_t>(1) << (rounds - 6);
      if (max_outputs < out->output_count) return CryptoNoteTxError::InvalidArgument;
      MASARI_STAGE(6);
      uint8_t table[kMasariMaxTxOutputs][32];
      for (uint16_t i = 0; i < out->output_count; ++i)
        memcpy(table[i], out->outputs[i].commitment, 32);
      if (!verify_bulletproof(table, out->output_count, out->bps[0]))
        return CryptoNoteTxError::InvalidAmount;
    }
    MASARI_STAGE(7);
    return CryptoNoteTxError::Ok;
  }

  CryptoNoteTxError masari_review_transaction(
      MasariTransaction *tx,
      const uint8_t view_secret[32], const uint8_t spend_secret[32],
      const uint8_t tx_secret[32],
      const MasariReviewInput *inputs, size_t input_count,
      const MasariReviewOutput *outputs, size_t output_count,
      MasariReviewResult *result)
  {
    MASARI_STAGE(10);
    if (tx == nullptr || view_secret == nullptr || spend_secret == nullptr ||
        tx_secret == nullptr || inputs == nullptr || outputs == nullptr ||
        result == nullptr)
      return CryptoNoteTxError::InvalidArgument;
    memset(result, 0, sizeof(*result));
    if (input_count == 0 || input_count > kMasariMaxTxInputs ||
        output_count == 0 || output_count > kMasariMaxTxOutputs)
      return CryptoNoteTxError::TooManyItems;
    if (tx->input_count != input_count || tx->output_count != output_count)
      return CryptoNoteTxError::InvalidArgument;
    for (size_t i = 0; i < output_count; ++i)
      if (outputs[i].address_type != 0 || outputs[i].subaddress_major != 0 ||
          outputs[i].subaddress_minor != 0)
        return CryptoNoteTxError::Unsupported;
    const CryptoNoteTxError fee_policy =
        cryptonote_review_fee_policy(CryptoNoteReviewNetwork::MasariMainnet, tx->fee);
    if (fee_policy != CryptoNoteTxError::Ok) return fee_policy;
    MASARI_STAGE(11);

    uint8_t tx_public[32], derived_public[32];
    if (!masari_tx_extra_public_key(*tx, tx_public) ||
        !cryptonote_scalar_to_point(tx_secret, derived_public) ||
        !point_equals(tx_public, derived_public))
      return CryptoNoteTxError::InvalidArgument;

    uint8_t our_spend[32], our_view[32];
    if (!cryptonote_scalar_to_point(spend_secret, our_spend) ||
        !cryptonote_scalar_to_point(view_secret, our_view))
      return CryptoNoteTxError::CryptoFailure;

    uint64_t output_total = 0, change_total = 0;
    uint8_t output_mask_sum[32] = {0};
    for (size_t i = 0; i < output_count; ++i)
    {
      const MasariOutput &wire = tx->outputs[i];
      const MasariReviewOutput &declared = outputs[i];
      if (UINT64_MAX - output_total < declared.amount)
        return CryptoNoteTxError::InvalidAmount;
      output_total += declared.amount;

      uint8_t derivation[32], amount_key[32], expected_public[32];
      if (!cryptonote_generate_key_derivation(declared.view_public, tx_secret,
                                              derivation) ||
          !cryptonote_derivation_to_scalar(derivation, i, amount_key) ||
          !cryptonote_derive_public_key(derivation, i, declared.spend_public,
                                        expected_public))
      {
        MASARI_STAGE(111);
        return CryptoNoteTxError::CryptoFailure;
      }

      uint64_t decoded_amount = 0;
      uint8_t decoded_mask[32], expected_commitment[32];
      if (!decode_legacy_amount(amount_key, wire.ecdh_mask, wire.ecdh_amount,
                                &decoded_amount, decoded_mask) ||
          !ringct_commitment(decoded_mask, decoded_amount, expected_commitment) ||
          !point_equals(expected_commitment, wire.commitment) ||
          !point_equals(expected_public, wire.public_key))
      {
        MASARI_STAGE(112);
        return CryptoNoteTxError::InvalidAmount;
      }
      if (decoded_amount != declared.amount)
      {
        MASARI_STAGE(113);
        return CryptoNoteTxError::InvalidAmount;
      }

      if (declared.change)
      {
        if (!owned_change(declared, spend_secret, view_secret, our_spend,
                          our_view))
          return CryptoNoteTxError::InvalidArgument;
        if (UINT64_MAX - change_total < declared.amount)
          return CryptoNoteTxError::InvalidAmount;
        change_total += declared.amount;
      }
      if (tx->rct_type == kMasariRctFull)
      {
        uint8_t expected[32];
        if (!ringct_commitment(declared.mask, declared.amount, expected) ||
            !point_equals(expected, wire.commitment))
          return CryptoNoteTxError::InvalidArgument;
        sc_add(output_mask_sum, output_mask_sum, declared.mask);
      }
      secure_zero(derivation, sizeof(derivation));
      secure_zero(amount_key, sizeof(amount_key));
      secure_zero(decoded_mask, sizeof(decoded_mask));
    }
    MASARI_STAGE(12);

    uint64_t input_total = 0;
    uint8_t input_mask_sum[32] = {0};
    for (size_t i = 0; i < input_count; ++i)
    {
      const MasariReviewInput &source = inputs[i];
      const MasariInput &wire = tx->inputs[i];
      if (source.ring == nullptr || source.key_offsets == nullptr ||
          !key_offsets_valid(wire, source))
        return CryptoNoteTxError::InvalidArgument;
      if (source.ring_size != tx->inputs[0].offset_count)
        return CryptoNoteTxError::InvalidArgument;
      if (tx->rct_type == kMasariRctFull &&
          source.real_index != inputs[0].real_index)
        return CryptoNoteTxError::InvalidArgument;
      if (UINT64_MAX - input_total < source.amount)
        return CryptoNoteTxError::InvalidAmount;
      input_total += source.amount;

      uint8_t expected_public[32], one_time[32], amount_key[32];
      uint8_t mask[32], commitment[32], image[32];
      uint8_t input_spend_secret[32], input_spend_public[32];
      const bool keys_ok = input_spend_keys(source, spend_secret, view_secret,
                                            our_spend, input_spend_secret,
                                            input_spend_public);
      const bool derived =
          keys_ok &&
          derive_one_time(view_secret, input_spend_secret, input_spend_public,
                          source.original_tx_public, source.output_index,
                          expected_public, one_time, amount_key);
      secure_zero(input_spend_secret, sizeof(input_spend_secret));
      secure_zero(input_spend_public, sizeof(input_spend_public));
      if (!derived ||
          !ringct_commitment_mask(amount_key, mask) ||
          !ringct_commitment(mask, source.amount, commitment) ||
          !point_equals(expected_public, source.ring[source.real_index].dest) ||
          !point_equals(commitment, source.ring[source.real_index].mask) ||
          !cryptonote_generate_key_image(source.ring[source.real_index].dest,
                                         one_time, image) ||
          !point_equals(image, wire.key_image))
        return CryptoNoteTxError::InvalidAmount;
      sc_add(input_mask_sum, input_mask_sum, mask);

      if (tx->rct_type != kMasariRctFull)
      {
        uint8_t pseudo[32];
        if (!ringct_commitment(source.pseudo_out_mask, source.amount, pseudo) ||
            !point_equals(pseudo, tx->pseudo_outs[i]))
          return CryptoNoteTxError::InvalidAmount;
        ed25519_scalar_mulsub(result->signing_mask[i], kScalarOne,
                              source.pseudo_out_mask, mask);
      }
      secure_zero(one_time, sizeof(one_time));
      secure_zero(amount_key, sizeof(amount_key));
      secure_zero(mask, sizeof(mask));
      secure_zero(commitment, sizeof(commitment));
    }
    MASARI_STAGE(13);

    if (UINT64_MAX - output_total < tx->fee ||
        input_total != output_total + tx->fee)
      return CryptoNoteTxError::InvalidAmount;

    if (tx->rct_type == kMasariRctFull)
    {
      // The single full-RCT signature signs the summed commitment row.
      uint8_t z[32];
      ed25519_scalar_mulsub(z, kScalarOne, output_mask_sum, input_mask_sum);
      memcpy(result->signing_mask[0], z, 32);
      secure_zero(z, sizeof(z));
    }
    memcpy(result->message, tx->message, 32);
    result->summary.total_input = input_total;
    result->summary.total_output = output_total;
    result->summary.change = change_total;
    result->summary.fee = tx->fee;
    result->summary.input_count = static_cast<uint8_t>(input_count);
    result->summary.output_count = static_cast<uint8_t>(output_count);
    result->summary.decoys_host_supplied = true;
    MASARI_STAGE(11);
    return CryptoNoteTxError::Ok;
  }

  CryptoNoteTxError masari_sign_transaction(
      MasariTransaction *tx, const MasariReviewResult &review,
      const uint8_t view_secret[32], const uint8_t spend_secret[32],
      const MasariReviewInput *inputs, size_t input_count,
      const uint8_t nonce_seed[32], uint8_t *out, size_t *in_out_size)
  {
    if (tx == nullptr || view_secret == nullptr || spend_secret == nullptr ||
        inputs == nullptr || nonce_seed == nullptr || out == nullptr ||
        in_out_size == nullptr || input_count == 0 ||
        input_count > kMasariMaxTxInputs)
      return CryptoNoteTxError::InvalidArgument;
    if (tx->rct_type != kMasariRctFull && tx->rct_type != kMasariRctSimple &&
        tx->rct_type != kMasariRctBulletproof)
      return CryptoNoteTxError::Unsupported;
    const size_t columns = tx->inputs[0].offset_count;
    if (columns < 2 || columns > kMasariMaxRingSize) return CryptoNoteTxError::InvalidArgument;
    for (size_t j = 1; j < input_count; ++j)
      if (tx->inputs[j].offset_count != columns)
        return CryptoNoteTxError::InvalidArgument;
    const bool full = tx->rct_type == kMasariRctFull;
    const size_t rows = full ? input_count + 1 : 2;
    const size_t ds_rows = full ? input_count : 1;

    uint8_t our_spend[32];
    if (!cryptonote_scalar_to_point(spend_secret, our_spend))
      return CryptoNoteTxError::CryptoFailure;
    uint8_t one_time[kMasariMaxTxInputs][32];
    for (size_t j = 0; j < input_count; ++j)
    {
      uint8_t expected_public[32], amount_key[32];
      uint8_t input_spend_secret[32], input_spend_public[32];
      const bool keys_ok = input_spend_keys(inputs[j], spend_secret,
                                            view_secret, our_spend,
                                            input_spend_secret,
                                            input_spend_public);
      const bool derived =
          keys_ok &&
          derive_one_time(view_secret, input_spend_secret, input_spend_public,
                          inputs[j].original_tx_public, inputs[j].output_index,
                          expected_public, one_time[j], amount_key);
      secure_zero(input_spend_secret, sizeof(input_spend_secret));
      secure_zero(input_spend_public, sizeof(input_spend_public));
      if (!derived) return CryptoNoteTxError::CryptoFailure;
      if (!point_equals(expected_public,
                        inputs[j].ring[inputs[j].real_index].dest))
        return CryptoNoteTxError::InvalidArgument;
      secure_zero(amount_key, sizeof(amount_key));
    }

    uint8_t matrix[
kMasariMaxRingSize * (kMasariMaxTxInputs + 1)][32];    uint8_t secrets[kMasariMaxTxInputs + 1][32];
    uint8_t images[kMasariMaxTxInputs][32];
    memset(matrix, 0, sizeof(matrix));
    memset(secrets, 0, sizeof(secrets));

    if (!full)
    {
      for (size_t j = 0; j < input_count; ++j)
      {
        const MasariReviewInput &source = inputs[j];
        for (size_t i = 0; i < columns; ++i)
        {
          memcpy(matrix[i * rows + 0], source.ring[i].dest, 32);
          if (!ed25519_point_sub_compressed(source.ring[i].mask,
                                            tx->pseudo_outs[j],
                                            matrix[i * rows + 1]))
            return CryptoNoteTxError::InvalidArgument;
        }
        memcpy(secrets[0], one_time[j], 32);
        memcpy(secrets[1], review.signing_mask[j], 32);
        memcpy(images[0], tx->inputs[j].key_image, 32);
        if (!mlsag_sign(tx->message, matrix, columns, rows, ds_rows,
                        source.real_index, secrets, images, nonce_seed,
                        tx->mgs[j].cc, tx->mgs[j].ss))
          return CryptoNoteTxError::CryptoFailure;
        tx->mgs[j].rows = 2;
      }
    }
    else
    {
      if (input_count < 2) return CryptoNoteTxError::Unsupported;
      for (size_t j = 1; j < input_count; ++j)
        if (inputs[j].real_index != inputs[0].real_index)
          return CryptoNoteTxError::InvalidArgument;
      uint8_t zero[32] = {0};
      uint8_t fee_key[32], sum_outputs[32];
      if (!ringct_commitment(zero, tx->fee, fee_key))
        return CryptoNoteTxError::CryptoFailure;
      memcpy(sum_outputs, kIdentityPoint, 32);
      for (uint16_t i = 0; i < tx->output_count; ++i)
      {
        uint8_t next[32];
        if (!ed25519_point_add_compressed(sum_outputs, tx->outputs[i].commitment, next))
          return CryptoNoteTxError::CryptoFailure;
        memcpy(sum_outputs, next, 32);
      }
      for (size_t i = 0; i < columns; ++i)
      {
        uint8_t row[kCryptoNoteKeySize];
        memcpy(row, kIdentityPoint, 32);
        for (size_t j = 0; j < input_count; ++j)
        {
          memcpy(matrix[i * rows + j], inputs[j].ring[i].dest, 32);
          uint8_t next[32];
          if (!ed25519_point_add_compressed(row, inputs[j].ring[i].mask, next))
            return CryptoNoteTxError::CryptoFailure;
          memcpy(row, next, 32);
        }
        uint8_t next[32];
        if (!ed25519_point_sub_compressed(row, sum_outputs, next) ||
            !ed25519_point_sub_compressed(next, fee_key, next))
          return CryptoNoteTxError::CryptoFailure;
        memcpy(matrix[i * rows + input_count], next, 32);
      }
      for (size_t j = 0; j < input_count; ++j)
      {
        memcpy(secrets[j], one_time[j], 32);
        memcpy(images[j], tx->inputs[j].key_image, 32);
      }
      memcpy(secrets[input_count], review.signing_mask[0], 32);
      if (!mlsag_sign(tx->message, matrix, columns, rows, ds_rows,
                      inputs[0].real_index, secrets, images, nonce_seed,
                      tx->mgs[0].cc, tx->mgs[0].ss))
        return CryptoNoteTxError::CryptoFailure;
      tx->mgs[0].rows = static_cast<uint8_t>(rows);
    }

    // Emit the compact signature blob the phone merges into its transaction.
    const size_t mg_count = full ? 1 : input_count;
    const size_t per_mg = 32 + columns * rows * 32;
    const size_t total = 4 + 32 + mg_count * per_mg;
    if (*in_out_size < total) { *in_out_size = total; return CryptoNoteTxError::BufferTooSmall; }
    size_t offset = 0;
    out[offset++] = 1;
    out[offset++] = static_cast<uint8_t>(mg_count);
    out[offset++] = static_cast<uint8_t>(rows);
    out[offset++] = static_cast<uint8_t>(columns);
    memcpy(out + offset, tx->message, 32);
    offset += 32;
    for (size_t m = 0; m < mg_count; ++m)
    {
      memcpy(out + offset, tx->mgs[m].cc, 32);
      offset += 32;
      for (size_t i = 0; i < columns * rows; ++i)
      {
        memcpy(out + offset, tx->mgs[m].ss[i], 32);
        offset += 32;
      }
    }
    *in_out_size = offset;
    secure_zero(matrix, sizeof(matrix));
    secure_zero(secrets, sizeof(secrets));
    secure_zero(one_time, sizeof(one_time));
    secure_zero(our_spend, sizeof(our_spend));
    return CryptoNoteTxError::Ok;
  }
  bool masari_mlsag_verify(const uint8_t message[32],
                           const uint8_t (*matrix)[32], size_t columns,
                           size_t rows, size_t ds_rows, const uint8_t cc[32],
                           const uint8_t (*ss)[32],
                           const uint8_t (*images)[32])
  {
    return mlsag_verify(message, matrix, columns, rows, ds_rows, cc, ss, images);
  }


  bool run_masari_self_tests()
  {
    // 0. Shamir double-scalar multiplication must match two scalar mults.
    MASARI_STAGE(49);
    {
      uint8_t point[32];
      const uint8_t point_seed[32] = {0x31, 0x7a};
      const uint8_t s1[32] = {3};
      const uint8_t s2[32] = {5};
      uint8_t combined[32], first[32], second[32], expected[32];
      if (!cryptonote_scalar_to_point(point_seed, point) ||
          !ed25519_double_scalar_mul(point, s1, kBasePoint, s2, combined) ||
          !ed25519_point_mul_compressed(point, s1, first) ||
          !ed25519_point_mul_compressed(kBasePoint, s2, second) ||
          !ed25519_point_add_compressed(first, second, expected))
        return false;
      if (!point_equals(combined, expected)) return false;
      uint8_t big1[32], big2[32];
      if (!cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>("ds1"), 3, big1) ||
          !cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>("ds2"), 3, big2) ||
          !ed25519_double_scalar_mul(point, big1, kBasePoint, big2, combined) ||
          !ed25519_point_mul_compressed(point, big1, first) ||
          !ed25519_point_mul_compressed(kBasePoint, big2, second) ||
          !ed25519_point_add_compressed(first, second, expected))
        return false;
      if (!point_equals(combined, expected)) return false;
    }

    // 1. MLSAG sign/verify round trip with three ring members.
    MASARI_STAGE(50);
    uint8_t matrix[3 * 2][32];
    uint8_t secrets[2][32] = {{0x11}, {0x22}};
    uint8_t images[2][32];
    uint8_t nonce[32] = {0x9a, 0x77};
    uint8_t message[32];
    if (!cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>("masari-mlsag"),
                                   13, message))
      return false;
    for (size_t i = 0; i < 3; ++i)
    {
      uint8_t label[2] = {static_cast<uint8_t>(i), 0x31};
      uint8_t point_seed[32];
      if (!cryptonote_hash_to_scalar(label, sizeof(label), point_seed) ||
          !cryptonote_scalar_to_point(point_seed, matrix[i * 2]))
        return false;
      uint8_t mask_label[2] = {static_cast<uint8_t>(i), 0x42};
      uint8_t mask_seed[32];
      if (!cryptonote_hash_to_scalar(mask_label, sizeof(mask_label), mask_seed) ||
          !ringct_commitment(mask_seed, 1000 + i, matrix[i * 2 + 1]))
        return false;
    }
    uint8_t cc[32];
    uint8_t ss[3 * 2][32];
    // The real column must correspond to the secrets for both rows; the other
    // columns stay random decoys.
    if (!cryptonote_scalar_to_point(secrets[0], matrix[1 * 2]) ||
        !cryptonote_scalar_to_point(secrets[1], matrix[1 * 2 + 1]))
      return false;
    MASARI_STAGE(51);
    if (!mlsag_sign(message, matrix, 3, 2, 1, 1, secrets, nullptr, nonce, cc, ss))
      return false;
    // Recompute the expected key image for the verification call.
    MASARI_STAGE(52);
    {
      uint8_t generator[32];
      if (!cryptonote_key_image_generator(matrix[1 * 2], generator) ||
          !ed25519_point_mul_compressed(generator, secrets[0], images[0]))
        return false;
    }
    MASARI_STAGE(53);
    if (!mlsag_verify(message, matrix, 3, 2, 1, cc, ss, images)) return false;
    MASARI_STAGE(54);
    {
      uint8_t saved = ss[0][0];
      ss[0][0] ^= 1;
      const bool rejected = !mlsag_verify(message, matrix, 3, 2, 1, cc, ss, images);
      ss[0][0] = saved;
      if (!rejected) return false;
    }

    // 2. Legacy ECDH decode binds the amount to the commitment.
    MASARI_STAGE(51);
    {
      const uint8_t amount_key[32] = {0x5d, 0x01};
      uint8_t shared1[32], shared2[32];
      const uint64_t amount = 123456789ULL;
      uint8_t mask[32] = {0x03, 0x00};
      uint8_t wire_mask[32], wire_amount[32];
      if (!cryptonote_hash_to_scalar(amount_key, 32, shared1) ||
          !cryptonote_hash_to_scalar(shared1, 32, shared2))
        return false;
      ed25519_scalar_muladd(wire_mask, kScalarOne, shared1, mask);
      uint8_t amount_scalar[32] = {0};
      scalar_u64(amount_scalar, amount);
      ed25519_scalar_muladd(wire_amount, kScalarOne, shared2, amount_scalar);
      uint64_t decoded = 0;
      uint8_t decoded_mask[32];
      if (!decode_legacy_amount(amount_key, wire_mask, wire_amount, &decoded,
                                decoded_mask) ||
          decoded != amount || !point_equals(decoded_mask, mask))
        return false;
    }
    MASARI_STAGE(55);
#if defined(HEXWALLET_HOST_TEST)
    // Real serialized Masari transaction from the upstream fuzz corpus
    // (masari-project/masari tests/data/fuzz/transaction/TX2). Two inputs,
    // two outputs, ring size 3, RCTTypeSimple with Borromean proofs.
    {
      FILE *file = fopen("tests/fixtures/masari/tx2.bin", "rb");
      if (file == nullptr) return false;
      static uint8_t blob[kMasariMaxTxBytes];
      const size_t size = fread(blob, 1, sizeof(blob), file);
      fclose(file);
      if (size != 13255) return false;
      static MasariTransaction tx;
      if (masari_parse_transaction(blob, size, &tx) != CryptoNoteTxError::Ok)
        return false;
      if (tx.rct_type != kMasariRctSimple || tx.input_count != 2 ||
          tx.output_count != 2 || tx.fee != 6076330000ULL ||
          tx.inputs[0].offset_count != 3 || tx.mg_count != 2)
        return false;
      // Tampering with one proof byte must be rejected.
      blob[455] ^= 0x01;
      static MasariTransaction rejected;
      if (masari_parse_transaction(blob, size, &rejected) ==
          CryptoNoteTxError::Ok)
        return false;
      blob[455] ^= 0x01;

      // RCT type 3 (standard Bulletproofs) stays fail-closed until a mainnet
      // vector is pinned. Flipping the RCT type byte must be refused, and no
      // reviewed state may leak out of that rejection.
      const size_t rct_type_offset = masari_last_rct_type_offset();
      if (rct_type_offset == 0 || rct_type_offset >= size) return false;
      const uint8_t saved_type = blob[rct_type_offset];
      if (saved_type != kMasariRctSimple) return false;
      blob[rct_type_offset] = kMasariRctBulletproof;
      const CryptoNoteTxError type3 = masari_parse_transaction(blob, size, &rejected);
      blob[rct_type_offset] = saved_type;
      if (masari_rct_type3_enabled()) {
        // Enabled builds must get past the type gate; TX2 is a type-2 body, so
        // the parse still fails, but not with "unsupported".
        if (type3 == CryptoNoteTxError::Unsupported) return false;
      } else if (type3 != CryptoNoteTxError::Unsupported) {
        return false;
      }
    }

    // Optional mainnet type-3 vector. Its presence must not change the default
    // build's behaviour: without the gate the path stays fail-closed, with the
    // gate it must parse, verify and reject tampering.
    {
      FILE *file3 = fopen("tests/fixtures/masari/tx3.bin", "rb");
      if (file3 == nullptr) {
#if HEXWALLET_MSR_ENABLE_RCT_TYPE3
        return false;  // an enabled build without a validated vector is an error
#endif
      } else {
        static uint8_t blob3[kMasariMaxTxBytes];
        const size_t size3 = fread(blob3, 1, sizeof(blob3), file3);
        fclose(file3);
        static MasariTransaction tx3;
        const CryptoNoteTxError parsed3 =
            masari_parse_transaction(blob3, size3, &tx3);
        if (!masari_rct_type3_enabled()) {
          if (parsed3 != CryptoNoteTxError::Unsupported) return false;
        } else {
          if (parsed3 != CryptoNoteTxError::Ok) return false;
          if (tx3.rct_type != kMasariRctBulletproof || tx3.output_count == 0)
            return false;
          // The last bytes of the blob are the trailing MLSAG material: any
          // single-bit edit there must break parsing or verification.
          static MasariTransaction tampered;
          for (size_t delta = 1; delta < 64 && delta < size3; delta += 7) {
            const size_t offset = size3 - delta;
            blob3[offset] ^= 0x01;
            const bool rejected_proof =
                masari_parse_transaction(blob3, size3, &tampered) !=
                CryptoNoteTxError::Ok;
            blob3[offset] ^= 0x01;
            if (!rejected_proof) return false;
          }
        }
      }
    }
#endif
    MASARI_STAGE(56);
    // 3. End-to-end Masari review + MLSAG signing on a synthetic type-2 spend.
    MASARI_STAGE(57);
    {
      const uint8_t view_secret[32] = {0x33, 0x77, 0x01, 0xe8};
      const uint8_t spend_secret[32] = {0x5a, 0x11, 0x9c, 0x42};
      const uint8_t sender_secret[32] = {0x0b, 0xad, 0xf0, 0x0d};
      const uint8_t recipient_spend_secret[32] = {0x91, 0x02};
      const uint8_t recipient_view_secret[32] = {0x47, 0xee};
      constexpr uint64_t kInputAmount = 900000ULL;
      constexpr uint64_t kOutputAmount = 800000ULL;
      constexpr uint64_t kFee = 100000ULL;

      uint8_t spend_public[32], view_public[32];
      uint8_t recipient_spend[32], recipient_view[32];
      if (!cryptonote_scalar_to_point(spend_secret, spend_public) ||
          !cryptonote_scalar_to_point(view_secret, view_public) ||
          !cryptonote_scalar_to_point(recipient_spend_secret, recipient_spend) ||
          !cryptonote_scalar_to_point(recipient_view_secret, recipient_view))
        return false;

      static MasariTransaction tx;
      memset(&tx, 0, sizeof(tx));
      tx.input_count = 1;
      tx.output_count = 1;
      tx.rct_type = kMasariRctSimple;
      tx.fee = kFee;
      tx.inputs[0].offset_count = 3;
      tx.inputs[0].key_offsets[0] = 5;
      tx.inputs[0].key_offsets[1] = 1;
      tx.inputs[0].key_offsets[2] = 2;

      uint8_t tx_public[32], derivation[32], amount_key[32];
      if (!cryptonote_scalar_to_point(sender_secret, tx_public) ||
          !cryptonote_scalar_to_point(sender_secret, tx_public) ||
          !cryptonote_generate_key_derivation(view_public, sender_secret, derivation) ||
          !cryptonote_derivation_to_scalar(derivation, 0, amount_key))
        return false;
      tx.extra[0] = kExtraTagPublicKey;
      memcpy(tx.extra + 1, tx_public, 32);
      tx.extra_size = 33;

      // The input lives on a subaddress, so review and signing must use
      // b + Hs("SubAddr" || a || major || minor) rather than the master key.
      const uint32_t kSubMajor = 0;
      const uint32_t kSubMinor = 1;
      uint8_t input_spend_secret[32], input_spend_public[32], sub_view_public[32];
      if (cryptonote_subaddress_keys(spend_secret, view_secret, kSubMajor,
                                     kSubMinor, input_spend_secret,
                                     input_spend_public,
                                     sub_view_public) != WalletError::Ok)
        return false;
      secure_zero(sub_view_public, sizeof(sub_view_public));
      if (crypto_constant_time_equal(input_spend_public, spend_public,
                                     sizeof(input_spend_public)))
        return false;  // a subaddress key pair must differ from the master pair

      uint8_t input_mask[32], input_commitment[32];
      uint8_t one_time_public[32], one_time_secret[32];
      if (!ringct_commitment_mask(amount_key, input_mask) ||
          !ringct_commitment(input_mask, kInputAmount, input_commitment) ||
          !cryptonote_derive_public_key(derivation, 0, input_spend_public,
                                        one_time_public) ||
          !cryptonote_derive_secret_key(derivation, 0, input_spend_secret,
                                        one_time_secret))
        return false;

      static CryptoNoteRingMember ring[3];
      for (size_t i = 0; i < 3; ++i)
      {
        uint8_t label[2] = {static_cast<uint8_t>(i), 0x71};
        uint8_t seed_label[2] = {static_cast<uint8_t>(i), 0x72};
        uint8_t point_seed[32], mask_seed[32];
        if (!cryptonote_hash_to_scalar(label, 2, point_seed) ||
            !cryptonote_scalar_to_point(point_seed, ring[i].dest) ||
            !cryptonote_hash_to_scalar(seed_label, 2, mask_seed) ||
            !ringct_commitment(mask_seed, 10 + i, ring[i].mask))
          return false;
      }
      memcpy(ring[1].dest, one_time_public, 32);
      memcpy(ring[1].mask, input_commitment, 32);
      if (!cryptonote_generate_key_image(ring[1].dest, one_time_secret,
                                         tx.inputs[0].key_image))
        return false;
      uint64_t offsets[3] = {5, 1, 2};

      // Sender-side legacy ECDH for the payment output.
      uint8_t out_derivation[32], out_amount_key[32], out_mask[32];
      uint8_t out_commitment[32], out_public[32];
      if (!cryptonote_generate_key_derivation(recipient_view, sender_secret,
                                              out_derivation) ||
          !cryptonote_derivation_to_scalar(out_derivation, 0, out_amount_key) ||
          !ringct_commitment_mask(out_amount_key, out_mask) ||
          !ringct_commitment(out_mask, kOutputAmount, out_commitment) ||
          !cryptonote_derive_public_key(out_derivation, 0, recipient_spend,
                                        out_public))
        return false;
      uint8_t shared1[32], shared2[32], amount_scalar[32];
      if (!cryptonote_hash_to_scalar(out_amount_key, 32, shared1) ||
          !cryptonote_hash_to_scalar(shared1, 32, shared2))
        return false;
      scalar_u64(amount_scalar, kOutputAmount);
      ed25519_scalar_muladd(tx.outputs[0].ecdh_mask, kScalarOne, shared1, out_mask);
      ed25519_scalar_muladd(tx.outputs[0].ecdh_amount, kScalarOne, shared2,
                            amount_scalar);
      memcpy(tx.outputs[0].public_key, out_public, 32);
      memcpy(tx.outputs[0].commitment, out_commitment, 32);
      {
        uint64_t decoded = 0;
        uint8_t decoded_mask[32], check_public[32], check_commitment[32];
        uint8_t check_derivation[32], check_amount_key[32];
        if (!decode_legacy_amount(out_amount_key, tx.outputs[0].ecdh_mask,
                                  tx.outputs[0].ecdh_amount, &decoded,
                                  decoded_mask) ||
            decoded != kOutputAmount || !point_equals(decoded_mask, out_mask))
          return false;
        if (!cryptonote_generate_key_derivation(recipient_view, sender_secret,
                                                check_derivation) ||
            !cryptonote_derivation_to_scalar(check_derivation, 0, check_amount_key) ||
            !cryptonote_derive_public_key(check_derivation, 0, recipient_spend,
                                          check_public) ||
            !ringct_commitment(decoded_mask, decoded, check_commitment))
          return false;
        if (!point_equals(check_public, tx.outputs[0].public_key) ||
            !point_equals(check_commitment, tx.outputs[0].commitment))
          return false;
      }

      uint8_t pseudo_mask[32] = {0x77, 0x03};
      if (!ringct_commitment(pseudo_mask, kInputAmount, tx.pseudo_outs[0]))
        return false;
      if (!cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>("masari-review"),
                                     13, tx.message))
        return false;
      tx.mg_count = 1;
      tx.mgs[0].rows = 2;

      MasariReviewInput review_input = {};
      review_input.amount = kInputAmount;
      review_input.real_index = 1;
      review_input.ring_size = 3;
      memcpy(review_input.original_tx_public, tx_public, 32);
      review_input.output_index = 0;
      review_input.ring = ring;
      review_input.key_offsets = offsets;
      memcpy(review_input.pseudo_out_mask, pseudo_mask, 32);
      review_input.subaddress_major = kSubMajor;
      review_input.subaddress_minor = kSubMinor;

      MasariReviewOutput review_output = {};
      review_output.change = false;
      memcpy(review_output.spend_public, recipient_spend, 32);
      memcpy(review_output.view_public, recipient_view, 32);
      review_output.amount = kOutputAmount;

      MasariReviewResult review;
      const CryptoNoteTxError reviewed = masari_review_transaction(
          &tx, view_secret, spend_secret, sender_secret, &review_input, 1,
          &review_output, 1, &review);
      g_masari_error = static_cast<int>(reviewed);
      if (reviewed != CryptoNoteTxError::Ok) return false;
      if (review.summary.total_input != kInputAmount ||
          review.summary.total_output != kOutputAmount ||
          review.summary.fee != kFee)
        return false;

      // A lying host amount must be rejected.
      {
        MasariReviewResult rejected;
        review_output.amount = kOutputAmount + 1;
        const CryptoNoteTxError error = masari_review_transaction(
            &tx, view_secret, spend_secret, sender_secret, &review_input, 1,
            &review_output, 1, &rejected);
        review_output.amount = kOutputAmount;
        if (error == CryptoNoteTxError::Ok) return false;
      }
      MASARI_STAGE(58);

      MASARI_STAGE(60);
      static uint8_t signature_blob[4096];
      size_t signature_size = sizeof(signature_blob);
      const uint8_t nonce[32] = {0xc3, 0x19};
      const CryptoNoteTxError signed_result = masari_sign_transaction(
          &tx, review, view_secret, spend_secret, &review_input, 1, nonce,
          signature_blob, &signature_size);
      g_masari_error = static_cast<int>(signed_result);
      if (signed_result != CryptoNoteTxError::Ok) return false;
      MASARI_STAGE(61);
      if (signature_size != 4 + 32 + 32 + 3 * 2 * 32) return false;
      MASARI_STAGE(62);
      // Verify the produced MLSAG against the ring used above.
      uint8_t matrix[3 * 2][32];
      for (size_t i = 0; i < 3; ++i)
      {
        memcpy(matrix[i * 2 + 0], ring[i].dest, 32);
        if (!ed25519_point_sub_compressed(ring[i].mask, tx.pseudo_outs[0],
                                          matrix[i * 2 + 1]))
          return false;
      }
      uint8_t cc[32], ss[3 * 2][32];
      memcpy(cc, signature_blob + 36, 32);
      memcpy(&ss[0][0], signature_blob + 68, sizeof(ss));
      uint8_t image[1][32];
      memcpy(image[0], tx.inputs[0].key_image, 32);
      if (!mlsag_verify(tx.message, matrix, 3, 2, 1, cc, ss, image))
        return false;
      MASARI_STAGE(63);
      secure_zero(input_spend_secret, sizeof(input_spend_secret));
      secure_zero(input_spend_public, sizeof(input_spend_public));
      secure_zero(one_time_secret, sizeof(one_time_secret));
    }
    MASARI_STAGE(71);
    return true;
  }

} // namespace hexwallet
