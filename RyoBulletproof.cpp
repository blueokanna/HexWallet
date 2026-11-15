#include "RyoBulletproof.h"
#include "src/privacy/RingOps.h"

namespace hexwallet
{
  namespace
  {
    using namespace privacy;
    constexpr size_t kMaxOutputs = 16;
    constexpr size_t kMaxRounds = 10;
    constexpr uint8_t kH[32] = {
        0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
        0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94};
    constexpr uint8_t kSumTwo[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    void add(const uint8_t *a, const uint8_t *b, uint8_t *out)
    {
      ed25519_scalar_muladd(out, a, kOne, b);
    }
    void sub(const uint8_t *a, const uint8_t *b, uint8_t *out)
    {
      ed25519_scalar_mulsub(out, kOne, b, a);
    }
    void inverse(const uint8_t *s, uint8_t *out)
    {
      uint8_t power[32];
      memcpy(power, kOrder, 32);
      power[0] -= 2;
      memcpy(out, kOne, 32);
      for (int bit = 252; bit >= 0; --bit)
      {
        smul(out, out, out);
        if ((power[bit / 8] >> (bit % 8)) & 1)
          smul(out, s, out);
      }
    }
    bool mash(uint8_t cache[32], const uint8_t *a, const uint8_t *b,
              const uint8_t *c = nullptr, const uint8_t *d = nullptr)
    {
      Transcript h;
      h.add(cache);
      h.add(a);
      h.add(b);
      if (c)
        h.add(c);
      if (d)
        h.add(d);
      return h.challenge(cache) && !equal(cache, kZero);
    }

    class Equation
    {
    public:
      Equation() { ed25519_extended_identity(&acc_); }
      bool term(const uint8_t *p, const uint8_t *s, bool negative = false)
      {
        uint8_t coefficient[32];
        if (negative)
          sub(kZero, s, coefficient);
        else
          memcpy(coefficient, s, 32);
        return ed25519_extended_add_scaled(&acc_, p, coefficient);
      }
      bool cofactored(const uint8_t *p, const uint8_t *s, bool negative = false)
      {
        uint8_t cleared[32];
        return ed25519_point_mul8_compressed(p, cleared) && term(cleared, s, negative);
      }
      bool holds() const
      {
        uint8_t encoded[32];
        return ed25519_extended_to_compressed(&acc_, encoded) && equal(encoded, kOne);
      }

    private:
      Ed25519ExtendedPoint acc_{};
    };
  } // namespace

  bool ryo_bulletproof_generator(size_t index, uint8_t out[32])
  {
    if (!out || index >= 2 * 64 * kMaxOutputs)
      return false;
    uint8_t buffer[32 + 11 + 3];
    memcpy(buffer, kH, 32);
    memcpy(buffer + 32, "bulletproof", 11);
    size_t size = 43;
    do
    {
      uint8_t byte = static_cast<uint8_t>(index & 0x7f);
      index >>= 7;
      buffer[size++] = byte | (index ? 0x80 : 0);
    } while (index);
    uint8_t hash[32];
    // Ryo get_exponent hashes the domain bytes, then hashToPoint hashes that
    // digest again before the CryptoNote map and cofactor clearing.
    return crypto_keccak256(buffer, size, hash) &&
           cryptonote_key_image_generator(hash, out);
  }

  bool ryo_bulletproof_verify(const RyoBulletproofView &p)
  {
    if (!p.commitments || !p.commitment_count || p.commitment_count > kMaxOutputs ||
        !p.a_point || !p.s_point || !p.t1_point || !p.t2_point || !p.left || !p.right ||
        !scalar(p.taux) || !scalar(p.mu) || !scalar(p.a) || !scalar(p.b) || !scalar(p.t))
      return false;
    size_t m = 1, rounds = 6;
    while (m < p.commitment_count)
    {
      m <<= 1;
      ++rounds;
    }
    if (p.rounds != rounds || rounds > kMaxRounds)
      return false;
    const size_t mn = m * 64;
    uint8_t cache[32], y[32], z[32], x[32], xip[32];
    Transcript initial;
    initial.add(p.commitments, p.commitment_count * 32);
    if (!initial.challenge(cache) || !mash(cache, p.a_point, p.s_point))
      return false;
    memcpy(y, cache, 32);
    if (!cryptonote_hash_to_scalar(y, 32, z) || equal(z, kZero))
      return false;
    memcpy(cache, z, 32);
    if (!mash(cache, z, p.t1_point, p.t2_point))
      return false;
    memcpy(x, cache, 32);
    if (!mash(cache, x, p.taux, p.mu, p.t))
      return false;
    memcpy(xip, cache, 32);
    uint8_t zpow[kMaxOutputs + 3][32]{};
    memcpy(zpow[0], kOne, 32);
    for (size_t j = 1; j < m + 3; ++j)
      smul(zpow[j - 1], z, zpow[j]);

    // Polynomial commitment equation, checked separately from the inner product.
    uint8_t ypower[32] = {1}, sum[32]{}, k[32], temp[32], coefficient[32];
    for (size_t i = 0; i < mn; ++i)
    {
      add(sum, ypower, sum);
      smul(ypower, y, ypower);
    }
    ed25519_scalar_mulsub(k, zpow[2], sum, kZero);
    for (size_t j = 1; j <= m; ++j)
      ed25519_scalar_mulsub(k, zpow[j + 2], kSumTwo, k);
    ed25519_scalar_muladd(temp, z, sum, k);
    sub(p.t, temp, coefficient);
    Equation polynomial;
    if (!polynomial.term(kG, p.taux) || !polynomial.term(kH, coefficient) ||
        !polynomial.cofactored(p.t1_point, x, true))
      return false;
    smul(x, x, temp);
    if (!polynomial.cofactored(p.t2_point, temp, true))
      return false;
    for (size_t j = 0; j < p.commitment_count; ++j)
      if (!polynomial.cofactored(p.commitments + j * 32, zpow[j + 2], true))
        return false;
    if (!polynomial.holds())
      return false;

    uint8_t w[kMaxRounds][32], winv[kMaxRounds][32], yinv[32];
    for (size_t j = 0; j < rounds; ++j)
    {
      if (!mash(cache, p.left + j * 32, p.right + j * 32))
        return false;
      memcpy(w[j], cache, 32);
      inverse(w[j], winv[j]);
    }
    inverse(y, yinv);
    Equation inner;
    ed25519_scalar_mulsub(temp, p.a, p.b, p.t);
    smul(temp, xip, coefficient);
    if (!inner.term(kH, coefficient) || !inner.term(kG, p.mu, true) ||
        !inner.cofactored(p.a_point, kOne) || !inner.cofactored(p.s_point, x))
      return false;
    for (size_t j = 0; j < rounds; ++j)
    {
      smul(w[j], w[j], temp);
      if (!inner.cofactored(p.left + j * 32, temp))
        return false;
      smul(winv[j], winv[j], temp);
      if (!inner.cofactored(p.right + j * 32, temp))
        return false;
    }
    uint8_t yinvpower[32] = {1}, twopower[32] = {1};
    memcpy(ypower, kOne, 32);
    for (size_t i = 0; i < mn; ++i)
    {
      uint8_t gs[32], hs[32], generator[32];
      memcpy(gs, p.a, 32);
      smul(p.b, yinvpower, hs);
      for (size_t j = 0; j < rounds; ++j)
      {
        const bool bit = (i >> (rounds - j - 1)) & 1;
        smul(gs, bit ? w[j] : winv[j], gs);
        smul(hs, bit ? winv[j] : w[j], hs);
      }
      add(gs, z, gs);
      smul(zpow[2 + i / 64], twopower, temp);
      ed25519_scalar_muladd(temp, z, ypower, temp);
      ed25519_scalar_mulsub(hs, temp, yinvpower, hs);
      if (!ryo_bulletproof_generator(2 * i + 1, generator) || !inner.term(generator, gs, true) ||
          !ryo_bulletproof_generator(2 * i, generator) || !inner.term(generator, hs, true))
        return false;
      smul(ypower, y, ypower);
      smul(yinvpower, yinv, yinvpower);
      if ((i + 1) % 64 == 0)
        memcpy(twopower, kOne, 32);
      else
        add(twopower, twopower, twopower);
    }
    return inner.holds();
  }
}
