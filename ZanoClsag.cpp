#include "ZanoClsag.h"
#include "src/privacy/RingOps.h"

namespace hexwallet
{
  namespace
  {
    using namespace privacy;
    constexpr auto &kX = kZanoX;
    constexpr char kDomains[3][32] = {"ZANO_HDS_CLSAG_GGX_LAYER_ZERO__",
                                      "ZANO_HDS_CLSAG_GGX_LAYER_ONE___", "ZANO_HDS_CLSAG_GGX_LAYER_TWO___"};
    constexpr char kChallenge[32] = "ZANO_HDS_CLSAG_GGX_CHALLENGE___";

    struct Context
    {
      uint8_t hash[32], mu[3][32], amount[32], asset[32], image_g[32], image_x[32];
    };

    bool validate(const uint8_t *message, const ZanoRingMember *ring, size_t n,
                  const uint8_t *amount, const uint8_t *asset)
    {
      if (!message || !ring || !n || n > kZanoMaxRingSize ||
          !point(amount) || !point(asset))
        return false;
      for (size_t i = 0; i < n; ++i)
      {
        if (!point(ring[i].destination) || !point(ring[i].amount_commitment) ||
            !point(ring[i].blinded_asset))
          return false;
        for (size_t j = 0; j < i; ++j)
          if (equal(ring[i].destination, ring[j].destination))
            return false;
      }
      return true;
    }

    bool prepare(const uint8_t *message, const ZanoRingMember *ring, size_t n,
                 const uint8_t *amount, const uint8_t *asset,
                 const ZanoClsagSignature &sig, Context &ctx)
    {
      if (!point(sig.key_image) || !point(sig.auxiliary_image_1, true) ||
          !point(sig.auxiliary_image_2, true) ||
          !ed25519_point_mul8_compressed(amount, ctx.amount) ||
          !ed25519_point_mul8_compressed(asset, ctx.asset))
        return false;
      Transcript binding;
      // Upstream add_scalar(m) implicitly converts the prefix hash to
      // scalar_t, reducing its little-endian representation modulo L.
      uint8_t message_scalar[32];
      memcpy(message_scalar, message, sizeof(message_scalar));
      ed25519_scalar_reduce_mod_l(message_scalar);
      binding.add(message_scalar);
      for (size_t i = 0; i < n; ++i)
      {
        binding.add(ring[i].destination);
        binding.add(ring[i].amount_commitment);
        binding.add(ring[i].blinded_asset);
      }
      binding.add(amount);
      binding.add(asset);
      binding.add(sig.key_image);
      binding.add(sig.auxiliary_image_1);
      binding.add(sig.auxiliary_image_2);
      if (!binding.hash(ctx.hash))
        return false;
      for (size_t i = 0; i < 3; ++i)
      {
        Transcript coefficient;
        coefficient.add(reinterpret_cast<const uint8_t *>(kDomains[i]));
        coefficient.add(ctx.hash);
        if (!coefficient.challenge(ctx.mu[i]))
          return false;
      }
      uint8_t k1[32], k2[32];
      return ed25519_point_mul8_compressed(sig.auxiliary_image_1, k1) &&
             ed25519_point_mul8_compressed(sig.auxiliary_image_2, k2) &&
             ed25519_double_scalar_mul(sig.key_image, ctx.mu[0], k1, ctx.mu[1], ctx.image_g) &&
             mul(k2, ctx.mu[2], ctx.image_x);
    }

    bool difference(const uint8_t *divided, const uint8_t *offset, uint8_t *out)
    {
      uint8_t full[32];
      return ed25519_point_mul8_compressed(divided, full) &&
             ed25519_point_sub_compressed(full, offset, out);
    }

    bool challenge(const Context &ctx, const uint8_t *lg, const uint8_t *rg,
                   const uint8_t *lx, const uint8_t *rx, uint8_t *c)
    {
      Transcript h;
      h.add(reinterpret_cast<const uint8_t *>(kChallenge));
      h.add(ctx.hash);
      h.add(lg);
      h.add(rg);
      h.add(lx);
      h.add(rx);
      return h.challenge(c);
    }

    bool round(const Context &ctx, const ZanoRingMember &member, const uint8_t *c,
               const uint8_t *sg, const uint8_t *sx, uint8_t *next, bool signing)
    {
      uint8_t dg[32], dx[32], wg[32], wx[32], hp[32];
      uint8_t lg[32], rg[32], lx[32], rx[32];
      if (!difference(member.amount_commitment, ctx.amount, dg) ||
          !difference(member.blinded_asset, ctx.asset, dx) ||
          !ed25519_double_scalar_mul(member.destination, ctx.mu[0], dg, ctx.mu[1], wg) ||
          !mul(dx, ctx.mu[2], wx) ||
          !cryptonote_key_image_generator(member.destination, hp) ||
          !combination(kG, sg, wg, c, lg, signing) ||
          !combination(hp, sg, ctx.image_g, c, rg, signing) ||
          !combination(kX, sx, wx, c, lx, signing) ||
          !combination(hp, sx, ctx.image_x, c, rx, signing))
        return false;
      return challenge(ctx, lg, rg, lx, rx, next);
    }
  } // namespace

  bool zano_clsag_ggx_verify(const uint8_t message[32], const ZanoRingMember *ring,
                             size_t n, const uint8_t amount[32], const uint8_t asset[32],
                             const ZanoClsagSignature &sig)
  {
    Context ctx{};
    if (!validate(message, ring, n, amount, asset) || sig.ring_size != n ||
        !scalar(sig.challenge) || !prepare(message, ring, n, amount, asset, sig, ctx))
      return false;
    uint8_t c[32];
    memcpy(c, sig.challenge, 32);
    for (size_t i = 0; i < n; ++i)
    {
      if (!scalar(sig.responses_g[i]) || !scalar(sig.responses_x[i]) ||
          !round(ctx, ring[i], c, sig.responses_g[i], sig.responses_x[i], c, false))
        return false;
    }
    return equal(c, sig.challenge);
  }

  bool zano_clsag_ggx_sign(const uint8_t message[32], const ZanoRingMember *ring,
                           size_t n, size_t index, const uint8_t spend[32], const uint8_t amount_delta[32],
                           const uint8_t asset_delta[32], const uint8_t amount[32], const uint8_t asset[32],
                           const uint8_t entropy[32], ZanoClsagSignature *out)
  {
    size_t output_size = sizeof(ZanoClsagSignature);
    SigningOutputGuard guard(reinterpret_cast<uint8_t *>(out), &output_size);
    if (!out)
      return false;
    memset(out, 0, sizeof(*out));
    if (!validate(message, ring, n, amount, asset) || index >= n || !entropy ||
        !scalar(spend, false) || !scalar(amount_delta) || !scalar(asset_delta))
      return false;
    uint8_t expected[32], delta[32], full[32], hp[32];
    if (!mul(kG, spend, expected) || !equal(expected, ring[index].destination) ||
        !ed25519_point_mul8_compressed(amount, full) ||
        !difference(ring[index].amount_commitment, full, delta) ||
        !mul(kG, amount_delta, expected) || !equal(expected, delta) ||
        !ed25519_point_mul8_compressed(asset, full) ||
        !difference(ring[index].blinded_asset, full, delta) ||
        !mul(kX, asset_delta, expected) || !equal(expected, delta) ||
        !cryptonote_key_image_generator(ring[index].destination, hp) ||
        !mul(hp, spend, out->key_image))
      return false;
    struct Secrets
    {
      uint8_t witnesses[96], divided[32], alpha[2][32], wg[32], wx[32], temp[32];
    };
    SensitiveValue<Secrets> secret;
    auto &s = secret.get();
    memcpy(s.witnesses, spend, 32);
    memcpy(s.witnesses + 32, amount_delta, 32);
    memcpy(s.witnesses + 64, asset_delta, 32);
    smul(kInv8, amount_delta, s.divided);
    if (!mul(hp, s.divided, out->auxiliary_image_1))
      return false;
    smul(kInv8, asset_delta, s.divided);
    if (!mul(hp, s.divided, out->auxiliary_image_2))
      return false;
    Context ctx{};
    if (!prepare(message, ring, n, amount, asset, *out, ctx))
      return false;
    smul(ctx.mu[1], amount_delta, s.temp);
    ed25519_scalar_muladd(s.wg, ctx.mu[0], spend, s.temp);
    smul(ctx.mu[2], asset_delta, s.wx);
    Nonces nonces;
    if (!nonces.init("HexWallet/Zano/CLSAG_GGX/v1", s.witnesses, 96, ctx.hash,
                     entropy, index) ||
        !nonces.get(0, index, s.alpha[0]) ||
        !nonces.get(1, index, s.alpha[1]))
      return false;
    uint8_t lg[32], rg[32], lx[32], rx[32], c[32];
    if (!mul(kG, s.alpha[0], lg) || !mul(hp, s.alpha[0], rg) ||
        !mul(kX, s.alpha[1], lx) || !mul(hp, s.alpha[1], rx) ||
        !challenge(ctx, lg, rg, lx, rx, c))
      return false;
    for (size_t j = 1; j < n; ++j)
    {
      const size_t i = (index + j) % n;
      if (i == 0)
        memcpy(out->challenge, c, 32);
      if (!nonces.get(2, i, out->responses_g[i]) ||
          !nonces.get(3, i, out->responses_x[i]) ||
          !round(ctx, ring[i], c, out->responses_g[i], out->responses_x[i], c, true))
        return false;
    }
    if (index == 0)
      memcpy(out->challenge, c, 32);
    ed25519_scalar_mulsub(out->responses_g[index], c, s.wg, s.alpha[0]);
    ed25519_scalar_mulsub(out->responses_x[index], c, s.wx, s.alpha[1]);
    out->ring_size = static_cast<uint16_t>(n);
    if (!zano_clsag_ggx_verify(message, ring, n, amount, asset, *out))
      return false;
    return guard.commit();
  }
}
