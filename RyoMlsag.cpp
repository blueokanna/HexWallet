#include "RyoMlsag.h"
#include "src/privacy/RingOps.h"

namespace hexwallet
{
  namespace
  {
    using namespace privacy;

    bool round(const uint8_t *message, const RyoRingMember &member,
               const uint8_t *pseudo, const uint8_t *image, const uint8_t *c,
               const uint8_t *s0, const uint8_t *s1, uint8_t *next, bool signing)
    {
      uint8_t hp[32], delta[32], l0[32], r0[32], l1[32];
      if (!cryptonote_key_image_generator(member.destination, hp) ||
          !ed25519_point_sub_compressed(member.commitment, pseudo, delta) ||
          !combination(kG, s0, member.destination, c, l0, signing) ||
          !combination(hp, s0, image, c, r0, signing) ||
          !combination(kG, s1, delta, c, l1, signing))
        return false;
      Transcript h;
      h.add(message);
      h.add(member.destination);
      h.add(l0);
      h.add(r0);
      h.add(delta);
      h.add(l1);
      return h.challenge(next);
    }
  }

  bool ryo_validate_ring(const RyoRingMember *ring, size_t n)
  {
    if (!ring || n < 2 || n > kRyoMaxRingSize) return false;
    for (size_t i = 0; i < n; ++i) {
      if (!point(ring[i].destination) || !point(ring[i].commitment)) return false;
      for (size_t j = 0; j < i; ++j)
        if (equal(ring[i].destination, ring[j].destination)) return false;
    }
    return true;
  }

  bool ryo_mlsag_verify(const uint8_t message[32], const RyoRingMember *ring,
                        size_t n, const uint8_t pseudo[32],
                        const RyoMlsagSignature &sig)
  {
    const RyoMlsagSignatureView view{&sig.responses[0][0][0], sig.challenge,
                                     sig.key_image, sig.ring_size};
    return ryo_mlsag_verify(message, ring, n, pseudo, view);
  }

  bool ryo_mlsag_verify(const uint8_t message[32], const RyoRingMember *ring,
                        size_t n, const uint8_t pseudo[32],
                        const RyoMlsagSignatureView &sig)
  {
    if (!message || !point(pseudo) || !ryo_validate_ring(ring, n) || sig.ring_size != n ||
        !sig.responses || !point(sig.key_image) || !scalar(sig.challenge))
      return false;
    uint8_t c[32];
    memcpy(c, sig.challenge, 32);
    for (size_t i = 0; i < n; ++i)
    {
      const uint8_t *s0 = sig.responses + i * 64, *s1 = s0 + 32;
      if (!scalar(s0) || !scalar(s1) ||
          !round(message, ring[i], pseudo, sig.key_image, c,
                 s0, s1, c, false))
        return false;
    }
    return equal(c, sig.challenge);
  }

  bool ryo_mlsag_sign(const uint8_t message[32], const RyoRingMember *ring,
                      size_t n, size_t index, const uint8_t spend[32],
                      const uint8_t mask_delta[32], const uint8_t pseudo[32],
                      const uint8_t entropy[32], RyoMlsagSignature *out)
  {
    size_t output_size = sizeof(RyoMlsagSignature);
    SigningOutputGuard guard(reinterpret_cast<uint8_t *>(out), &output_size);
    if (!out)
      return false;
    memset(out, 0, sizeof(*out));
    if (!message || !point(pseudo) || !ryo_validate_ring(ring, n) || index >= n || !entropy ||
        !scalar(spend, false) || !scalar(mask_delta))
      return false;
    uint8_t expected[32], delta[32], hp[32];
    if (!mul(kG, spend, expected) || !equal(expected, ring[index].destination) ||
        !ed25519_point_sub_compressed(ring[index].commitment, pseudo, delta) ||
        !mul(kG, mask_delta, expected) || !equal(expected, delta) ||
        !cryptonote_key_image_generator(ring[index].destination, hp) ||
        !mul(hp, spend, out->key_image))
      return false;
    Transcript binding;
    binding.add(message);
    binding.add(pseudo);
    binding.add(out->key_image);
    for (size_t i = 0; i < n; ++i)
    {
      binding.add(ring[i].destination);
      binding.add(ring[i].commitment);
    }
    uint8_t digest[32];
    if (!binding.hash(digest))
      return false;
    struct Secrets
    {
      uint8_t witnesses[64], alpha[2][32];
    };
    SensitiveValue<Secrets> secret;
    memcpy(secret.get().witnesses, spend, 32);
    memcpy(secret.get().witnesses + 32, mask_delta, 32);
    Nonces nonces;
    if (!nonces.init("HexWallet/Ryo/MLSAG/v1", secret.get().witnesses, 64,
                     digest, entropy, index) ||
        !nonces.get(0, index, secret.get().alpha[0]) ||
        !nonces.get(1, index, secret.get().alpha[1]))
      return false;
    uint8_t l0[32], r0[32], l1[32], c[32];
    if (!mul(kG, secret.get().alpha[0], l0) ||
        !mul(hp, secret.get().alpha[0], r0) ||
        !mul(kG, secret.get().alpha[1], l1))
      return false;
    Transcript start;
    start.add(message);
    start.add(ring[index].destination);
    start.add(l0);
    start.add(r0);
    start.add(delta);
    start.add(l1);
    if (!start.challenge(c))
      return false;
    for (size_t j = 1; j < n; ++j)
    {
      const size_t i = (index + j) % n;
      if (i == 0)
        memcpy(out->challenge, c, 32);
      if (!nonces.get(2, i, out->responses[i][0]) ||
          !nonces.get(3, i, out->responses[i][1]) ||
          !round(message, ring[i], pseudo, out->key_image, c,
                 out->responses[i][0], out->responses[i][1], c, true))
        return false;
    }
    if (index == 0)
      memcpy(out->challenge, c, 32);
    ed25519_scalar_mulsub(out->responses[index][0], c, spend, secret.get().alpha[0]);
    ed25519_scalar_mulsub(out->responses[index][1], c, mask_delta, secret.get().alpha[1]);
    out->ring_size = static_cast<uint16_t>(n);
    if (!ryo_mlsag_verify(message, ring, n, pseudo, *out))
      return false;
    return guard.commit();
  }
}
