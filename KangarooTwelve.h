#ifndef HEXWALLET_KANGAROO_TWELVE_H
#define HEXWALLET_KANGAROO_TWELVE_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{

  constexpr size_t kK12ChunkSize = 8192;
  constexpr size_t kK12DigestSize = 32;
  constexpr size_t kTurboShake128Rate = 168;

  struct TurboShake128
  {
    uint64_t state[25];
    uint8_t block[kTurboShake128Rate];
    size_t used;
    size_t read;
    bool finalized;
  };

  void turboshake128_init(TurboShake128 *sponge);
  void turboshake128_absorb(TurboShake128 *sponge, const uint8_t *data, size_t size);
  void turboshake128_absorb_marker(TurboShake128 *sponge, uint8_t marker);
  void turboshake128_finalize(TurboShake128 *sponge, uint8_t domain);
  void turboshake128_squeeze(TurboShake128 *sponge, uint8_t *out, size_t out_len);

  struct KangarooTwelve
  {
    TurboShake128 root; // absorbs the first chunk, then the leaf CVs
    TurboShake128 leaf; // one 8192-byte chunk at a time
    size_t buffered;    // bytes in the node currently being filled
    uint64_t block_number;
  };

  void k12_init(KangarooTwelve *state);
  void k12_update(KangarooTwelve *state, const uint8_t *data, size_t size);
  void k12_final(KangarooTwelve *state, const uint8_t *custom, size_t custom_size, uint8_t *out, size_t out_len);
  void k12_hash(const uint8_t *data, size_t size, uint8_t out[kK12DigestSize]);
#if defined(HEXWALLET_HOST_TEST)
  bool run_kangaroo_twelve_self_tests();
#endif

}

#endif
