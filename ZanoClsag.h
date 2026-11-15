#ifndef HEXWALLET_ZANO_CLSAG_H
#define HEXWALLET_ZANO_CLSAG_H
#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{
  constexpr size_t kZanoMaxRingSize = 256; // Backend capacity, not a consensus rule.
  struct ZanoRingMember
  {
    uint8_t destination[32];
    uint8_t amount_commitment[32]; // Consensus encoding: commitment divided by 8.
    uint8_t blinded_asset[32];     // Consensus encoding: asset point divided by 8.
  };
  struct ZanoClsagSignature
  {
    uint8_t challenge[32];
    uint8_t responses_g[kZanoMaxRingSize][32];
    uint8_t responses_x[kZanoMaxRingSize][32];
    uint8_t key_image[32];
    uint8_t auxiliary_image_1[32]; // K1 / 8, as serialized by Zano.
    uint8_t auxiliary_image_2[32]; // K2 / 8, as serialized by Zano.
    uint16_t ring_size;
  };

  bool zano_clsag_ggx_sign(const uint8_t message[32], const ZanoRingMember *ring,
                           size_t count, size_t real_index, const uint8_t spend[32],
                           const uint8_t amount_delta[32], const uint8_t asset_delta[32],
                           const uint8_t pseudo_amount[32], const uint8_t pseudo_asset[32],
                           const uint8_t entropy[32], ZanoClsagSignature *out);
  bool zano_clsag_ggx_verify(const uint8_t message[32], const ZanoRingMember *ring,
                             size_t count, const uint8_t pseudo_amount[32], const uint8_t pseudo_asset[32],
                             const ZanoClsagSignature &signature);
}
#endif
