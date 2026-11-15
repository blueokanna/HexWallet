#ifndef HEXWALLET_RYO_MLSAG_H
#define HEXWALLET_RYO_MLSAG_H
#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{
  constexpr size_t kRyoMaxRingSize = 241;
  struct RyoRingMember
  {
    uint8_t destination[32];
    uint8_t commitment[32];
  };
  struct RyoMlsagSignature
  {
    uint8_t responses[kRyoMaxRingSize][2][32];
    uint8_t challenge[32];
    uint8_t key_image[32];
    uint16_t ring_size;
  };
  struct RyoMlsagSignatureView
  {
    const uint8_t *responses;
    const uint8_t *challenge;
    const uint8_t *key_image;
    size_t ring_size;
  };

  // Two-row Simple/Bulletproof MLSAG: spend*G = P and mask_delta*G = C-Cpseudo.
  // prehash is the validated RingCT pre-MLSAG hash, NOT an arbitrary host digest
  // accepted by the wallet UI. entropy must come from the device RNG. Nonces are
  // additionally bound to the witnesses and all public inputs. On failure the
  // complete output is erased. Inputs and output must not overlap.
  bool ryo_mlsag_sign(const uint8_t prehash[32], const RyoRingMember *ring,
                      size_t count, size_t real_index, const uint8_t spend[32],
                      const uint8_t mask_delta[32], const uint8_t pseudo_out[32],
                      const uint8_t entropy[32], RyoMlsagSignature *out);
  bool ryo_mlsag_verify(const uint8_t prehash[32], const RyoRingMember *ring,
                        size_t count, const uint8_t pseudo_out[32],
                        const RyoMlsagSignature &signature);
  // Borrowed immutable wire signature; avoids a 15 KB signature copy on the MCU.
  bool ryo_mlsag_verify(const uint8_t prehash[32], const RyoRingMember *ring,
                        size_t count, const uint8_t pseudo_out[32],
                        const RyoMlsagSignatureView &signature);
}
#endif
