#include "CryptoNoteBulletproofPlus.h"

#include <string.h>

#include "CryptoExtended.h"
#include "CryptoNoteRingCt.h"
#include "CryptoNoteTransaction.h"
#include "CryptoPrimitives.h"

namespace hexwallet
{
  namespace
  {
    constexpr size_t kKeySize = kCryptoNoteKeySize;
    constexpr size_t kLogN = 6;
    constexpr size_t kN = 64;
    constexpr size_t kMaxCommitments = 16;
    constexpr size_t kMaxMn = kMaxCommitments * kN;
    constexpr size_t kMaxRounds = kLogN + 4;

    const uint8_t kScalarL[kKeySize] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
    // l - 2: the Fermat exponent for inversion modulo the group order.
    const uint8_t kScalarLm2[kKeySize] = {
        0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
    const uint8_t kScalarOne[kKeySize] = {0x01};
    const uint8_t kScalarZero[kKeySize] = {0x00};
    const uint8_t kScalarMinusOne[kKeySize] = {
        0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
    // 2**64 - 1 == sum of 2**i for i in [0, 64).
    const uint8_t kTwoSixtyFourMinusOne[kKeySize] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    // RingCT's fixed amount generator H: the base of every BP+ generator.
    const uint8_t kGeneratorH[kKeySize] = {
        0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
        0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94};
    // The Edwards25519 base point, rct::G.
    const uint8_t kBasePoint[kKeySize] = {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
    const uint8_t kIdentity[kKeySize] = {0x01};

    const char kExponentDomain[] = "bulletproof_plus";
    const char kTranscriptDomain[] = "bulletproof_plus_transcript";

    // -----------------------------------------------------------------------
    // Scalars. Every value here is reduced mod l, so these mirror sc_mul,
    // sc_add, sc_sub and sc_neg from Monero's scalar arithmetic.
    // -----------------------------------------------------------------------

    void sc_mul(uint8_t out[kKeySize], const uint8_t a[kKeySize], const uint8_t b[kKeySize])
    {
      ed25519_scalar_muladd(out, a, b, kScalarZero);
    }

    void sc_add(uint8_t out[kKeySize], const uint8_t a[kKeySize], const uint8_t b[kKeySize])
    {
      ed25519_scalar_muladd(out, a, kScalarOne, b);
    }

    void sc_sub(uint8_t out[kKeySize], const uint8_t a[kKeySize], const uint8_t b[kKeySize])
    {
      ed25519_scalar_muladd(out, kScalarMinusOne, b, a);
    }

    void sc_neg(uint8_t out[kKeySize], const uint8_t a[kKeySize])
    {
      ed25519_scalar_muladd(out, kScalarMinusOne, a, kScalarZero);
    }

    bool sc_is_zero(const uint8_t a[kKeySize])
    {
      uint8_t acc = 0;
      for (size_t i = 0; i < kKeySize; ++i)
        acc |= a[i];
      return acc == 0;
    }

    bool sc_is_reduced(const uint8_t a[kKeySize])
    {
      for (size_t i = kKeySize; i-- > 0;)
      {
        if (a[i] < kScalarL[i])
          return true;
        if (a[i] > kScalarL[i])
          return false;
      }
      return false; // exactly l is out of range
    }

    void sc_invert(uint8_t out[kKeySize], const uint8_t a[kKeySize])
    {
      uint8_t result[kKeySize] = {0x01};
      uint8_t base[kKeySize];
      memcpy(base, a, kKeySize);
      for (int bit = 252; bit >= 0; --bit)
      {
        sc_mul(result, result, result);
        if ((kScalarLm2[bit >> 3] >> (bit & 7)) & 1u)
          sc_mul(result, result, base);
      }
      memcpy(out, result, kKeySize);
    }

    void scalar_from_u64(uint8_t out[kKeySize], uint64_t value)
    {
      memset(out, 0, kKeySize);
      for (size_t i = 0; i < 8; ++i)
        out[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xff);
    }

    // -----------------------------------------------------------------------
    // Hashing. hash_to_scalar is Keccak-256 reduced mod l; hash_to_p3 is
    // ge_fromfe_frombytes_vartime over a Keccak-256 digest.
    // -----------------------------------------------------------------------

    bool transcript_update(uint8_t transcript[kKeySize], const uint8_t *update, size_t size)
    {
      if (update == nullptr || size > 2 * kKeySize)
        return false;
      uint8_t buffer[3 * kKeySize];
      memcpy(buffer, transcript, kKeySize);
      memcpy(buffer + kKeySize, update, size);
      uint8_t next[kKeySize];
      if (!cryptonote_hash_to_scalar(buffer, kKeySize + size, next))
        return false;
      memcpy(transcript, next, kKeySize);
      return true;
    }

    // tools::get_varint_data: LEB128, as consumed by get_exponent.
    size_t encode_varint(uint8_t *out, size_t value)
    {
      size_t n = 0;
      do
      {
        uint8_t byte = static_cast<uint8_t>(value & 0x7f);
        value >>= 7;
        if (value != 0)
          byte |= 0x80;
        out[n++] = byte;
      } while (value != 0);
      return n;
    }

    // -----------------------------------------------------------------------
    // Points.
    // -----------------------------------------------------------------------

    // Monero's scalarmult8. Untrusted points must be cleared of any torsion
    // component before they enter the verification equation.
    bool point_mul8(const uint8_t in[kKeySize], uint8_t out[kKeySize])
    {
      return ed25519_point_mul8_compressed(in, out);
    }

    struct Accumulator
    {
      Ed25519ExtendedPoint point;
      bool primed;
    };

    bool accumulator_to_compressed(const Accumulator *acc, uint8_t out[kKeySize])
    {
      return acc->primed && ed25519_extended_to_compressed(&acc->point, out);
    }

    bool hash_to_p3(const uint8_t key[kKeySize], uint8_t out[kKeySize])
    {
      uint8_t inner[kKeySize];
      if (!crypto_keccak256(key, kKeySize, inner))
        return false;
      uint8_t mapped[kKeySize];
      if (!ed25519_hash_to_point(inner, mapped))
        return false;
      return point_mul8(mapped, out);
    }

    bool accumulate(Accumulator *acc, const uint8_t scalar[kKeySize], const uint8_t point[kKeySize])
    {
      if (sc_is_zero(scalar))
        return true;
      acc->primed = true;
      return ed25519_extended_add_scaled(&acc->point, point, scalar);
    }

    bool hex_nibble(char c, uint8_t *out)
    {
      if (c >= '0' && c <= '9')
      {
        *out = static_cast<uint8_t>(c - '0');
        return true;
      }
      if (c >= 'a' && c <= 'f')
      {
        *out = static_cast<uint8_t>(c - 'a' + 10);
        return true;
      }
      if (c >= 'A' && c <= 'F')
      {
        *out = static_cast<uint8_t>(c - 'A' + 10);
        return true;
      }
      return false;
    }

    bool decode_hex(const char *text, uint8_t *out, size_t out_size, size_t *written)
    {
      if (text == nullptr || out == nullptr || written == nullptr)
        return false;
      const size_t length = strlen(text);
      if ((length & 1u) != 0 || length / 2 > out_size)
        return false;
      for (size_t i = 0; i < length / 2; ++i)
      {
        uint8_t high = 0;
        uint8_t low = 0;
        if (!hex_nibble(text[2 * i], &high) || !hex_nibble(text[2 * i + 1], &low))
          return false;
        out[i] = static_cast<uint8_t>((high << 4) | low);
      }
      *written = length / 2;
      return true;
    }
  } // namespace

  bool bulletproof_plus_generator(size_t index, uint8_t out[kKeySize])
  {
    if (out == nullptr || index > 2 * kMaxMn + 1)
      return false;
    uint8_t buffer[kKeySize + sizeof(kExponentDomain) + 10];
    size_t offset = 0;
    memcpy(buffer, kGeneratorH, kKeySize);
    offset += kKeySize;
    memcpy(buffer + offset, kExponentDomain, sizeof(kExponentDomain) - 1);
    offset += sizeof(kExponentDomain) - 1;
    offset += encode_varint(buffer + offset, index);

    uint8_t digest[kKeySize];
    if (!crypto_keccak256(buffer, offset, digest))
      return false;
    return hash_to_p3(digest, out);
  }

  bool bulletproof_plus_commitment_to_view(const uint8_t commitment[kKeySize],
                                           uint8_t out[kKeySize])
  {
    if (commitment == nullptr || out == nullptr)
      return false;
    // 1/8 mod l, the same value as crypto-ops MINUS_INV_EIGHT negated. Monero's
    // expand_transaction_1 multiplies every on-chain outPk by it to rebuild the
    // V the proof actually holds, and the verifier multiplies by 8 again.
    const uint8_t inv_eight[kKeySize] = {
        0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61,
        0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x06};
    return ed25519_point_mul_compressed(commitment, inv_eight, out);
  }

  bool bulletproof_plus_initial_transcript(uint8_t out[kKeySize])
  {
    if (out == nullptr)
      return false;
    uint8_t digest[kKeySize];
    if (!crypto_keccak256(reinterpret_cast<const uint8_t *>(kTranscriptDomain),
                          sizeof(kTranscriptDomain) - 1, digest))
      return false;
    return hash_to_p3(digest, out);
  }

  // Monero bulletproof_plus_VERIFY for a single proof, with the batch weight
  // fixed at 1 (the only case that matters for one proof).
  bool bulletproof_plus_verify(const BulletproofPlusView &proof
#if defined(HEXWALLET_HOST_TEST)
                               ,
                               BulletproofPlusTrace trace
#endif
  )
  {
#if defined(HEXWALLET_HOST_TEST)
#define BP_TRACE(name, value)       \
  do                                \
  {                                 \
    if (trace)                      \
      trace(name, value, kKeySize); \
  } while (0)
#else
#define BP_TRACE(name, value) \
  do                          \
  {                           \
  } while (0)
#endif
    if (proof.v == nullptr || proof.a == nullptr || proof.a1 == nullptr || proof.b == nullptr ||
        proof.r1 == nullptr || proof.s1 == nullptr || proof.d1 == nullptr || proof.l == nullptr ||
        proof.r == nullptr)
      return false;
    if (proof.commitment_count == 0 || proof.commitment_count > kMaxCommitments)
      return false;
    if (!sc_is_reduced(proof.r1) || !sc_is_reduced(proof.s1) || !sc_is_reduced(proof.d1))
      return false;

    size_t log_m = 0;
    while (log_m < 5 && (static_cast<size_t>(1) << log_m) < proof.commitment_count)
      ++log_m;
    const size_t slots = static_cast<size_t>(1) << log_m;
    if (slots > kMaxCommitments)
      return false;

    const size_t rounds = kLogN + log_m;
    if (rounds > kMaxRounds || proof.rounds != rounds)
      return false;
    const size_t mn = slots * kN;
    if (mn > kMaxMn)
      return false;

    // ---- Fiat-Shamir transcript -----------------------------------------
    uint8_t transcript[kKeySize];
    if (!bulletproof_plus_initial_transcript(transcript))
      return false;
    BP_TRACE("initial", transcript);

    uint8_t v_digest[kKeySize];
    if (!cryptonote_hash_to_scalar(proof.v, proof.commitment_count * kKeySize, v_digest))
      return false;
    BP_TRACE("V_hash", v_digest);
    if (!transcript_update(transcript, v_digest, kKeySize))
      return false;
    BP_TRACE("after_V", transcript);

    if (!transcript_update(transcript, proof.a, kKeySize))
      return false;
    uint8_t y[kKeySize];
    memcpy(y, transcript, kKeySize);
    BP_TRACE("y", y);
    if (sc_is_zero(y))
      return false;

    uint8_t z[kKeySize];
    if (!cryptonote_hash_to_scalar(y, kKeySize, z))
      return false;
    BP_TRACE("z", z);
    if (sc_is_zero(z))
      return false;
    memcpy(transcript, z, kKeySize);

    uint8_t challenges[kMaxRounds][kKeySize];
    uint8_t challenges_inv[kMaxRounds][kKeySize];
    for (size_t j = 0; j < rounds; ++j)
    {
      uint8_t pair[2 * kKeySize];
      memcpy(pair, proof.l + j * kKeySize, kKeySize);
      memcpy(pair + kKeySize, proof.r + j * kKeySize, kKeySize);
      if (!transcript_update(transcript, pair, sizeof(pair)))
        return false;
      memcpy(challenges[j], transcript, kKeySize);
      BP_TRACE("challenge", transcript);
      if (sc_is_zero(challenges[j]))
        return false;
      sc_invert(challenges_inv[j], challenges[j]);
    }

    uint8_t e[kKeySize];
    {
      uint8_t pair[2 * kKeySize];
      memcpy(pair, proof.a1, kKeySize);
      memcpy(pair + kKeySize, proof.b, kKeySize);
      if (!transcript_update(transcript, pair, sizeof(pair)))
        return false;
      memcpy(e, transcript, kKeySize);
      BP_TRACE("e", e);
      if (sc_is_zero(e))
        return false;
    }

    // ---- Derived scalars -------------------------------------------------
    uint8_t y_mn[kKeySize];
    {
      memcpy(y_mn, y, kKeySize);
      size_t remaining = mn;
      while (remaining > 1)
      {
        sc_mul(y_mn, y_mn, y_mn);
        remaining /= 2;
      }
    }
    uint8_t y_mn_1[kKeySize];
    sc_mul(y_mn_1, y_mn, y);
    uint8_t y_inv[kKeySize];
    sc_invert(y_inv, y);

    uint8_t e_squared[kKeySize];
    sc_mul(e_squared, e, e);
    uint8_t neg_e[kKeySize];
    sc_neg(neg_e, e);
    uint8_t neg_e_squared[kKeySize];
    sc_neg(neg_e_squared, e_squared);
    uint8_t z_squared[kKeySize];
    sc_mul(z_squared, z, z);

    // Monero sum_of_scalar_powers: y + ... + y**mn (no constant term).
    uint8_t sum_y[kKeySize];
    memcpy(sum_y, y, kKeySize);
    {
      uint8_t power[kKeySize];
      memcpy(power, y, kKeySize);
      uint8_t next[kKeySize];
      for (size_t i = 1; i < mn; ++i)
      {
        sc_mul(next, power, y);
        memcpy(power, next, kKeySize);
        sc_add(sum_y, sum_y, power);
      }
    }

    BP_TRACE("sum_y", sum_y);
    uint8_t sum_d[kKeySize];
    {
      uint8_t even[kKeySize];
      uint8_t power[kKeySize];
      uint8_t next[kKeySize];
      memcpy(even, z_squared, kKeySize);
      sc_mul(power, z_squared, z_squared);
      for (size_t j = 1; j < slots; ++j)
      {
        sc_add(even, even, power);
        sc_mul(next, power, z_squared);
        memcpy(power, next, kKeySize);
      }
      sc_mul(sum_d, kTwoSixtyFourMinusOne, even);
    }

    // H coefficient:
    //   r1*y*s1 + e**2 * ( y**(mn+1)*z*sum_d + (z**2 - z)*sum_y )
    uint8_t h_coefficient[kKeySize];
    {
      uint8_t inner[kKeySize];
      uint8_t term[kKeySize];
      sc_sub(term, z_squared, z);
      sc_mul(inner, term, sum_y);
      sc_mul(term, y_mn_1, z);
      sc_mul(term, term, sum_d);
      sc_add(inner, inner, term);
      sc_mul(inner, inner, e_squared);
      sc_mul(term, proof.r1, y);
      sc_mul(term, term, proof.s1);
      sc_add(h_coefficient, inner, term);
    }

    Accumulator acc;
    acc.primed = false;
    ed25519_extended_identity(&acc.point);

    uint8_t scaled[kKeySize];
    uint8_t scalar[kKeySize];

    // V_j: -e**2 * z**(2*(j+1)) * y**(mn+1)
    sc_mul(scalar, neg_e_squared, y_mn_1);
    for (size_t j = 0; j < proof.commitment_count; ++j)
    {
      sc_mul(scalar, scalar, z_squared);
      if (!point_mul8(proof.v + j * kKeySize, scaled))
        return false;
      if (!accumulate(&acc, scalar, scaled))
        return false;
    }

    // B: -1
    if (!point_mul8(proof.b, scaled))
      return false;
    if (!accumulate(&acc, kScalarMinusOne, scaled))
      return false;

    // A1: -e
    if (!point_mul8(proof.a1, scaled))
      return false;
    if (!accumulate(&acc, neg_e, scaled))
      return false;

    // A: -e**2
    if (!point_mul8(proof.a, scaled))
      return false;
    if (!accumulate(&acc, neg_e_squared, scaled))
      return false;

    // G: d1, H: h_coefficient
    if (!accumulate(&acc, proof.d1, kBasePoint))
      return false;
    if (!accumulate(&acc, h_coefficient, kGeneratorH))
      return false;

    // L_j: -e**2 * challenges[j]**2, R_j: -e**2 * challenges_inv[j]**2
    for (size_t j = 0; j < rounds; ++j)
    {
      uint8_t squared[kKeySize];
      sc_mul(squared, challenges[j], challenges[j]);
      sc_mul(squared, squared, neg_e_squared);
      if (!point_mul8(proof.l + j * kKeySize, scaled))
        return false;
      if (!accumulate(&acc, squared, scaled))
        return false;

      sc_mul(squared, challenges_inv[j], challenges_inv[j]);
      sc_mul(squared, squared, neg_e_squared);
      if (!point_mul8(proof.r + j * kKeySize, scaled))
        return false;
      if (!accumulate(&acc, squared, scaled))
        return false;
    }

    uint8_t e_r1_y[kKeySize];
    sc_mul(e_r1_y, e, proof.r1);
    uint8_t e_s1[kKeySize];
    sc_mul(e_s1, e, proof.s1);
    uint8_t e2z[kKeySize];
    sc_mul(e2z, e_squared, z);
    uint8_t minus_e2z[kKeySize];
    sc_neg(minus_e2z, e2z);
    uint8_t minus_e2_ymn[kKeySize];
    sc_mul(minus_e2_ymn, neg_e_squared, y_mn);

    // z**(2*(block+1)) for each 64-wide block, computed once.
    uint8_t block_powers[kMaxCommitments][kKeySize];
    {
      uint8_t power[kKeySize];
      memcpy(power, z_squared, kKeySize);
      for (size_t block = 0; block < slots; ++block)
      {
        memcpy(block_powers[block], power, kKeySize);
        sc_mul(power, power, z_squared);
      }
    }

    const size_t complement_mask = mn - 1;
    uint8_t g_scalar[kKeySize];
    uint8_t hi_scalar[kKeySize];
    uint8_t cache_index[kKeySize];
    uint8_t cache_complement[kKeySize];
    for (size_t i = 0; i < mn; ++i)
    {
      const size_t complement = (~i) & complement_mask;
      memcpy(cache_index, kScalarOne, kKeySize);
      memcpy(cache_complement, kScalarOne, kKeySize);
      for (size_t j = 0; j < rounds; ++j)
      {
        const bool bit = ((i >> (rounds - 1 - j)) & 1u) != 0;
        sc_mul(cache_index, cache_index, bit ? challenges[j] : challenges_inv[j]);
        const bool complement_bit = ((complement >> (rounds - 1 - j)) & 1u) != 0;
        sc_mul(cache_complement, cache_complement,
               complement_bit ? challenges[j] : challenges_inv[j]);
      }

      sc_mul(g_scalar, e_r1_y, cache_index);
      sc_add(g_scalar, g_scalar, e2z);

      sc_mul(hi_scalar, e_s1, cache_complement);
      sc_add(hi_scalar, hi_scalar, minus_e2z);

      uint8_t window[kKeySize];
      uint8_t two_power[kKeySize];
      scalar_from_u64(two_power, static_cast<uint64_t>(1) << (i % kN));
      sc_mul(window, block_powers[i / kN], two_power);
      sc_mul(window, minus_e2_ymn, window);
      sc_add(hi_scalar, hi_scalar, window);

      if (!bulletproof_plus_generator(i * 2 + 1, scaled))
        return false;
      if (!accumulate(&acc, g_scalar, scaled))
        return false;
      if (!bulletproof_plus_generator(i * 2, scaled))
        return false;
      if (!accumulate(&acc, hi_scalar, scaled))
        return false;

      sc_mul(e_r1_y, e_r1_y, y_inv);
      sc_mul(minus_e2_ymn, minus_e2_ymn, y_inv);
    }

    if (!acc.primed)
      return false;
    uint8_t multiexp[kKeySize];
    if (!accumulator_to_compressed(&acc, multiexp))
      return false;
    BP_TRACE("multiexp", multiexp);
#undef BP_TRACE
    return memcmp(multiexp, kIdentity, kKeySize) == 0;
  }

  namespace
  {
    struct MainnetVector
    {
      const char *txid;
      size_t size;
      const char *hex;
      const char *prefix_txid;
    };

    static const MainnetVector kMainnetVectors[] = {
#include "src/generated/MoneroTxVectorsTest.inc"
    };
    const uint8_t kReferenceInitTranscript[kKeySize] = {
        0x4a, 0x67, 0x7c, 0x90, 0xeb, 0x73, 0x05, 0x1e, 0x79, 0x0d, 0xa4, 0x55, 0x91, 0x10, 0x7f, 0x6e,
        0xe1, 0x05, 0x90, 0x4d, 0x91, 0x87, 0xc5, 0xd3, 0x54, 0x71, 0x09, 0x6c, 0x44, 0x5a, 0x22, 0x75};
    const uint8_t kReferenceGeneratorZero[kKeySize] = {
        0x48, 0x62, 0x8d, 0xf3, 0x80, 0xa5, 0x01, 0x6d, 0x25, 0x45, 0x1a, 0xaa, 0x50, 0x17, 0x31, 0xa1,
        0x1b, 0x72, 0xbf, 0x66, 0xdc, 0x41, 0xd8, 0x1f, 0x71, 0x9a, 0xbd, 0x35, 0xce, 0x92, 0xb0, 0xed};
    const uint8_t kReferenceGeneratorOne[kKeySize] = {
        0x38, 0xc5, 0xd4, 0xdb, 0x53, 0xae, 0xb8, 0x6f, 0x5a, 0x80, 0xde, 0xf9, 0xbe, 0x49, 0x53, 0xf2,
        0x28, 0x8e, 0xd5, 0xa4, 0x4c, 0x66, 0xaf, 0x72, 0x3f, 0x46, 0x3d, 0x01, 0x70, 0x82, 0x90, 0x10};

    bool gather_commitments(const CryptoNoteTransaction &tx, uint8_t *out, size_t out_size)
    {
      if (tx.output_count == 0 || tx.output_count * kKeySize > out_size)
        return false;
      for (size_t i = 0; i < tx.output_count; ++i)
        if (!bulletproof_plus_commitment_to_view(tx.outputs[i].commitment,
                                                 out + i * kKeySize))
          return false;
      return true;
    }

    bool build_view(const CryptoNoteTransaction &tx, const uint8_t *commitments,
                    BulletproofPlusView *view)
    {
      if (tx.rct.proof_count == 0)
        return false;
      const CryptoNoteBpPlusProof &proof = tx.rct.proofs[0];
      if (proof.l_count != proof.r_count || proof.l_count == 0)
        return false;
      view->v = commitments;
      view->commitment_count = tx.output_count;
      view->a = proof.a;
      view->a1 = proof.a1;
      view->b = proof.b;
      view->r1 = proof.r1;
      view->s1 = proof.s1;
      view->d1 = proof.d1;
      view->l = proof.l[0];
      view->r = proof.r[0];
      view->rounds = proof.l_count;
      return true;
    }
  } // namespace
  bool run_bulletproof_plus_self_tests()
  {
    uint8_t generator[kKeySize];
    if (!bulletproof_plus_generator(0, generator))
      return false;
    if (memcmp(generator, kReferenceGeneratorZero, kKeySize) != 0)
      return false;
    if (!bulletproof_plus_generator(1, generator))
      return false;
    if (memcmp(generator, kReferenceGeneratorOne, kKeySize) != 0)
      return false;

    uint8_t transcript[kKeySize];
    if (!bulletproof_plus_initial_transcript(transcript))
      return false;
    if (memcmp(transcript, kReferenceInitTranscript, kKeySize) != 0)
      return false;

    static CryptoNoteTransaction tx;
    static uint8_t blob[kCryptoNoteMaxTxBytes];
    static uint8_t commitments[kCryptoNoteMaxTxOutputs * kKeySize];
    const MainnetVector &vector = kMainnetVectors[0];
    size_t blob_size = 0;
    if (!decode_hex(vector.hex, blob, sizeof(blob), &blob_size))
      return false;
    if (blob_size != vector.size)
      return false;
    if (cryptonote_parse_transaction(blob, blob_size, &tx) != CryptoNoteTxError::Ok)
      return false;
    if (!gather_commitments(tx, commitments, sizeof(commitments)))
      return false;

    BulletproofPlusView view;
    if (!build_view(tx, commitments, &view))
      return false;
    if (!bulletproof_plus_verify(view))
      return false;
    CryptoNoteBpPlusProof &proof = tx.rct.proofs[0];
    uint8_t *mutable_fields[] = {proof.a, proof.a1, proof.b, proof.r1,
                                 proof.s1, proof.d1, proof.l[0], proof.r[0]};
    for (size_t index = 0;
         index < sizeof(mutable_fields) / sizeof(mutable_fields[0]); ++index)
    {
      const uint8_t saved = mutable_fields[index][0];
      mutable_fields[index][0] = static_cast<uint8_t>(saved ^ 0x01);
      if (!build_view(tx, commitments, &view))
        return false;
      if (bulletproof_plus_verify(view))
        return false;
      mutable_fields[index][0] = saved;
    }

    const uint8_t saved_commitment = tx.outputs[0].commitment[0];
    tx.outputs[0].commitment[0] = static_cast<uint8_t>(saved_commitment ^ 0x01);
    if (!gather_commitments(tx, commitments, sizeof(commitments)))
      return false;
    if (!build_view(tx, commitments, &view))
      return false;
    if (bulletproof_plus_verify(view))
      return false;
    tx.outputs[0].commitment[0] = saved_commitment;
    if (!gather_commitments(tx, commitments, sizeof(commitments)))
      return false;

    BulletproofPlusView malformed = view;
    malformed.rounds = view.rounds + 1;
    if (bulletproof_plus_verify(malformed))
      return false;
    malformed = view;
    malformed.commitment_count = 0;
    if (bulletproof_plus_verify(malformed))
      return false;

    const uint8_t saved = tx.rct.proofs[0].s1[31];
    tx.rct.proofs[0].s1[31] = 0xff;
    if (!build_view(tx, commitments, &view))
      return false;
    if (bulletproof_plus_verify(view))
      return false;
    tx.rct.proofs[0].s1[31] = saved;

    // Null views must fail closed.
    BulletproofPlusView empty = {};
    if (bulletproof_plus_verify(empty))
      return false;

    // After all the tampering the pristine proof must verify again.
    if (!build_view(tx, commitments, &view))
      return false;
    return bulletproof_plus_verify(view);
  }

  bool run_bulletproof_plus_mainnet_probe()
  {
    static CryptoNoteTransaction tx;
    static uint8_t blob[kCryptoNoteMaxTxBytes];
    static uint8_t commitments[kCryptoNoteMaxTxOutputs * kKeySize];
    for (size_t index = 0; index < sizeof(kMainnetVectors) / sizeof(kMainnetVectors[0]); ++index)
    {
      const MainnetVector &vector = kMainnetVectors[index];
      size_t blob_size = 0;
      if (!decode_hex(vector.hex, blob, sizeof(blob), &blob_size))
        return false;
      if (cryptonote_parse_transaction(blob, blob_size, &tx) != CryptoNoteTxError::Ok)
        return false;
      if (!gather_commitments(tx, commitments, sizeof(commitments)))
        return false;
      BulletproofPlusView view;
      if (!build_view(tx, commitments, &view))
        return false;
      if (!bulletproof_plus_verify(view))
        return false;
    }
    return true;
  }
#if defined(HEXWALLET_HOST_TEST)
  namespace
  {
    struct BpReferenceVector
    {
      size_t commitment_count;
      size_t rounds;
      uint8_t v[kMaxCommitments][kKeySize];
      uint8_t a[kKeySize];
      uint8_t a1[kKeySize];
      uint8_t b[kKeySize];
      uint8_t r1[kKeySize];
      uint8_t s1[kKeySize];
      uint8_t d1[kKeySize];
      uint8_t l[kMaxRounds][kKeySize];
      uint8_t r[kMaxRounds][kKeySize];
      uint8_t initial[kKeySize];
      uint8_t v_hash[kKeySize];
      uint8_t after_v[kKeySize];
      uint8_t y[kKeySize];
      uint8_t z[kKeySize];
      uint8_t e[kKeySize];
      uint8_t sum_y[kKeySize];
      uint8_t multiexp[kKeySize];
      uint8_t challenges[kMaxRounds][kKeySize];
    };

    static BpReferenceVector kReferenceVectors[] = {
#include "src/generated/BulletproofPlusReferenceTest.inc"
    };

    const BpReferenceVector *g_capture_vector = nullptr;
    size_t g_capture_index = 0;
    size_t g_capture_seen = 0;
    size_t g_capture_mismatches = 0;

    void capture_trace(const char *name, const uint8_t *value, size_t size)
    {
      if (g_capture_vector == nullptr || value == nullptr || size != kKeySize)
        return;
      const BpReferenceVector &reference = *g_capture_vector;
      const uint8_t *expected = nullptr;
      if (strcmp(name, "initial") == 0)
        expected = reference.initial;
      else if (strcmp(name, "V_hash") == 0)
        expected = reference.v_hash;
      else if (strcmp(name, "after_V") == 0)
        expected = reference.after_v;
      else if (strcmp(name, "y") == 0)
        expected = reference.y;
      else if (strcmp(name, "z") == 0)
        expected = reference.z;
      else if (strcmp(name, "e") == 0)
        expected = reference.e;
      else if (strcmp(name, "sum_y") == 0)
        expected = reference.sum_y;
      else if (strcmp(name, "multiexp") == 0)
        expected = reference.multiexp;
      else if (strcmp(name, "challenge") == 0)
      {
        if (g_capture_index < kMaxRounds)
          expected = reference.challenges[g_capture_index++];
      }
      else
      {
        return;
      }
      ++g_capture_seen;
      if (expected != nullptr && memcmp(expected, value, kKeySize) != 0)
        ++g_capture_mismatches;
    }
  } // namespace

  bool run_bulletproof_plus_reference_vector_self_test()
  {
    bool ok = true;
    for (size_t index = 0; index < sizeof(kReferenceVectors) / sizeof(kReferenceVectors[0]);
         ++index)
    {
      BpReferenceVector &reference = kReferenceVectors[index];
      if (reference.commitment_count == 0 || reference.commitment_count > kMaxCommitments)
        return false;
      if (reference.rounds == 0 || reference.rounds > kMaxRounds)
        return false;

      BulletproofPlusView view = {};
      view.v = reference.v[0];
      view.commitment_count = reference.commitment_count;
      view.a = reference.a;
      view.a1 = reference.a1;
      view.b = reference.b;
      view.r1 = reference.r1;
      view.s1 = reference.s1;
      view.d1 = reference.d1;
      view.l = reference.l[0];
      view.r = reference.r[0];
      view.rounds = reference.rounds;

      g_capture_vector = &reference;
      g_capture_index = 0;
      g_capture_seen = 0;
      g_capture_mismatches = 0;
      const bool accepted = bulletproof_plus_verify(view, capture_trace);
      g_capture_vector = nullptr;

      // A proof from Monero's own prover must verify, every intermediate it
      // exposes must match, and the trace must be complete.
      if (!accepted)
        ok = false;
      if (g_capture_mismatches != 0)
        ok = false;
      if (g_capture_index != reference.rounds)
        ok = false;
      // initial, V_hash, after_V, y, z, e, sum_y, multiexp + one per round.
      if (g_capture_seen != 8 + reference.rounds)
        ok = false;

      // The same proof with any single field disturbed must be rejected, so a
      // match cannot come from a verifier that ignores its inputs.
      BpReferenceVector &mutable_reference = kReferenceVectors[index];
      uint8_t saved = mutable_reference.a[0];
      mutable_reference.a[0] = static_cast<uint8_t>(saved ^ 0x01);
      if (bulletproof_plus_verify(view))
        ok = false;
      mutable_reference.a[0] = saved;

      saved = mutable_reference.l[0][0];
      mutable_reference.l[0][0] = static_cast<uint8_t>(saved ^ 0x01);
      if (bulletproof_plus_verify(view))
        ok = false;
      mutable_reference.l[0][0] = saved;

      // ...and intact again, proving the restore really happened.
      if (!bulletproof_plus_verify(view))
        ok = false;
    }
    return ok;
  }
#endif

} // namespace hexwallet
