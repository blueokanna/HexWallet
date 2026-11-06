#include "KangarooTwelve.h"

#include <string.h>

#include "keccak256.h"

namespace hexwallet
{
  namespace
  {

    constexpr uint8_t kMarkerMessageHop = 0x03; // '110' message hop, simple padding
    constexpr uint8_t kMarkerLeaf = 0x0B;       // '110' message hop, inner node
    constexpr uint8_t kMarkerRootTree = 0x06;   // '01' chaining hop, final node
    constexpr uint8_t kMarkerRootSingle = 0x07; // '11' message hop, final node

    uint64_t load_le64(const uint8_t *data)
    {
      uint64_t value = 0;
      for (size_t index = 0; index < 8; ++index)
      {
        value |= static_cast<uint64_t>(data[index]) << (index * 8U);
      }
      return value;
    }

    void xor_block_into_state(TurboShake128 *sponge)
    {
      for (size_t lane = 0; lane < kTurboShake128Rate / 8; ++lane)
      {
        sponge->state[lane] ^= load_le64(sponge->block + lane * 8);
      }
    }

    void permute(TurboShake128 *sponge)
    {
      keccak_p1600(sponge->state, 12);
    }

    size_t right_encode(uint8_t *out, uint64_t value)
    {
      size_t length = 0;
      for (uint64_t remaining = value; remaining != 0; remaining >>= 8)
      {
        ++length;
      }
      for (size_t index = 0; index < length; ++index)
      {
        out[index] = static_cast<uint8_t>(value >> (8 * (length - 1 - index)));
      }
      out[length] = static_cast<uint8_t>(length);
      return length + 1;
    }

    void commit_leaf(KangarooTwelve *state)
    {
      turboshake128_finalize(&state->leaf, kMarkerLeaf);
      uint8_t cv[kK12DigestSize];
      turboshake128_squeeze(&state->leaf, cv, kK12DigestSize);
      turboshake128_absorb(&state->root, cv, sizeof(cv));
      state->buffered = 0;
      ++state->block_number;
    }

  }

  void turboshake128_init(TurboShake128 *sponge)
  {
    if (sponge == nullptr)
    {
      return;
    }
    memset(sponge, 0, sizeof(*sponge));
  }

  void turboshake128_absorb(TurboShake128 *sponge, const uint8_t *data, size_t size)
  {
    if (sponge == nullptr || data == nullptr || sponge->finalized)
    {
      return;
    }
    while (size > 0)
    {
      const size_t room = kTurboShake128Rate - sponge->used;
      const size_t take = size < room ? size : room;
      memcpy(sponge->block + sponge->used, data, take);
      sponge->used += take;
      data += take;
      size -= take;
      if (sponge->used == kTurboShake128Rate)
      {
        xor_block_into_state(sponge);
        permute(sponge);
        memset(sponge->block, 0, sizeof(sponge->block));
        sponge->used = 0;
      }
    }
  }

  void turboshake128_absorb_marker(TurboShake128 *sponge, uint8_t marker)
  {
    if (sponge == nullptr || sponge->finalized)
      return;
    turboshake128_absorb(sponge, &marker, 1);
    while (sponge->used % 8 != 0)
    {
      const uint8_t zero = 0;
      turboshake128_absorb(sponge, &zero, 1);
    }
  }

  void turboshake128_finalize(TurboShake128 *sponge, uint8_t domain)
  {
    if (sponge == nullptr || sponge->finalized)
    {
      return;
    }
    sponge->block[sponge->used] ^= domain;
    sponge->block[kTurboShake128Rate - 1] ^= 0x80;
    xor_block_into_state(sponge);
    permute(sponge);
    sponge->finalized = true;
    sponge->read = 0;
  }

  void turboshake128_squeeze(TurboShake128 *sponge, uint8_t *out, size_t out_len)
  {
    if (sponge == nullptr || out == nullptr || !sponge->finalized)
    {
      return;
    }
    while (out_len > 0)
    {
      if (sponge->read == kTurboShake128Rate)
      {
        permute(sponge);
        sponge->read = 0;
      }
      const size_t room = kTurboShake128Rate - sponge->read;
      const size_t take = out_len < room ? out_len : room;
      for (size_t index = 0; index < take; ++index)
      {
        const size_t offset = sponge->read + index;
        out[index] = static_cast<uint8_t>(sponge->state[offset / 8] >> (8 * (offset % 8)));
      }
      sponge->read += take;
      out += take;
      out_len -= take;
    }
  }

  void k12_init(KangarooTwelve *state)
  {
    if (state == nullptr)
    {
      return;
    }
    turboshake128_init(&state->root);
    turboshake128_init(&state->leaf);
    state->buffered = 0;
    state->block_number = 0;
  }

  void k12_update(KangarooTwelve *state, const uint8_t *data, size_t size)
  {
    if (state == nullptr || data == nullptr || state->root.finalized)
    {
      return;
    }
    while (size > 0)
    {
      if (state->block_number == 0)
      {
        if (state->buffered == kK12ChunkSize)
        {
          turboshake128_absorb_marker(&state->root, kMarkerMessageHop);
          state->buffered = 0;
          state->block_number = 1;
          continue;
        }
        const size_t room = kK12ChunkSize - state->buffered;
        const size_t take = size < room ? size : room;
        turboshake128_absorb(&state->root, data, take);
        state->buffered += take;
        data += take;
        size -= take;
        continue;
      }
      if (state->buffered == 0)
      {
        turboshake128_init(&state->leaf);
        const size_t take = size < kK12ChunkSize ? size : kK12ChunkSize;
        turboshake128_absorb(&state->leaf, data, take);
        state->buffered = take;
        data += take;
        size -= take;
      }
      else
      {
        const size_t room = kK12ChunkSize - state->buffered;
        const size_t take = size < room ? size : room;
        turboshake128_absorb(&state->leaf, data, take);
        state->buffered += take;
        data += take;
        size -= take;
      }
      if (state->buffered == kK12ChunkSize)
      {
        commit_leaf(state);
      }
    }
  }

  void k12_final(KangarooTwelve *state, const uint8_t *custom, size_t custom_size,
                 uint8_t *out, size_t out_len)
  {
    if (state == nullptr || out == nullptr || out_len == 0 ||
        state->root.finalized || (custom == nullptr && custom_size != 0))
    {
      return;
    }
    if (custom != nullptr && custom_size != 0)
    {
      k12_update(state, custom, custom_size);
    }
    uint8_t encoded[9];
    const size_t encoded_size = right_encode(encoded, custom_size);
    k12_update(state, encoded, encoded_size);

    if (state->block_number == 0)
    {
      turboshake128_finalize(&state->root, kMarkerRootSingle);
      turboshake128_squeeze(&state->root, out, out_len);
      return;
    }
    if (state->buffered != 0)
    {
      commit_leaf(state);
    }
    uint8_t tail[11];
    size_t tail_size = right_encode(tail, state->block_number - 1);
    tail[tail_size++] = 0xFF;
    tail[tail_size++] = 0xFF;
    turboshake128_absorb(&state->root, tail, tail_size);
    turboshake128_finalize(&state->root, kMarkerRootTree);
    turboshake128_squeeze(&state->root, out, out_len);
  }

  void k12_hash(const uint8_t *data, size_t size, uint8_t out[kK12DigestSize])
  {
    KangarooTwelve state;
    k12_init(&state);
    k12_update(&state, data, size);
    k12_final(&state, nullptr, 0, out, kK12DigestSize);
  }

#if defined(HEXWALLET_HOST_TEST)
  namespace {
  size_t read_hex_byte(const char *hex, size_t index, bool *ok)
  {
    unsigned value = 0;
    for (size_t nibble = 0; nibble < 2; ++nibble)
    {
      const char c = hex[index * 2 + nibble];
      unsigned digit = 0;
      if (c >= '0' && c <= '9')
      {
        digit = static_cast<unsigned>(c - '0');
      }
      else if (c >= 'a' && c <= 'f')
      {
        digit = static_cast<unsigned>(c - 'a' + 10);
      }
      else
      {
        *ok = false;
        return 0;
      }
      value = (value << 4) | digit;
    }
    return value;
  }

  bool digest_equals(const uint8_t *bytes, size_t size, const char *hex)
  {
    bool ok = true;
    for (size_t index = 0; index < size && ok; ++index)
    {
      if (bytes[index] != static_cast<uint8_t>(read_hex_byte(hex, index, &ok)))
      {
        return false;
      }
    }
    return ok;
  }

  void feed_k12(KangarooTwelve *state, size_t length, bool all_ff)
  {
    uint8_t piece[251];
    size_t offset = 0;
    while (offset < length)
    {
      size_t take = length - offset;
      if (take > sizeof(piece))
      {
        take = sizeof(piece);
      }
      for (size_t index = 0; index < take; ++index)
      {
        const uint8_t value = static_cast<uint8_t>((offset + index) % sizeof(piece));
        piece[index] = all_ff ? 0xFF : value;
      }
      k12_update(state, piece, take);
      offset += take;
    }
  }

  void build_cycle(uint8_t *out, size_t size)
  {
    for (size_t index = 0; index < size; ++index)
    {
      out[index] = static_cast<uint8_t>(index % 251);
    }
  }

  bool k12_vector_matches(size_t message, bool all_ff, size_t custom,
                          const char *expected, size_t out_len,
                          bool last_words_only)
  {
    static uint8_t digest[10032];
    static uint8_t customization[68921];
    KangarooTwelve state;
    k12_init(&state);
    feed_k12(&state, message, all_ff);
    if (custom != 0)
    {
      build_cycle(customization, custom);
    }
    k12_final(&state, custom != 0 ? customization : nullptr, custom, digest, out_len);
    const uint8_t *compared = digest;
    size_t compared_size = out_len;
    if (last_words_only)
    {
      compared = digest + out_len - kK12DigestSize;
      compared_size = kK12DigestSize;
    }
    return digest_equals(compared, compared_size, expected);
  }

  } // namespace

  bool run_kangaroo_twelve_self_tests()
  {
    bool passed = true;
    passed = passed && k12_vector_matches(0, false, 0,
                                          "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5", 32, false);
    passed = passed && k12_vector_matches(0, false, 0,
                                          "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"
                                          "4269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71",
                                          64, false);
    passed = passed && k12_vector_matches(0, false, 0,
                                          "e8dc563642f7228c84684c898405d3a834799158c079b12880277a1d28e2ff6d", 10032, true);

    passed = passed && k12_vector_matches(1, false, 0,
                                          "2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f", 32, false);
    passed = passed && k12_vector_matches(17, false, 0,
                                          "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888", 32, false);
    passed = passed && k12_vector_matches(289, false, 0,
                                          "0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c", 32, false);
    passed = passed && k12_vector_matches(4913, false, 0,
                                          "cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0", 32, false);
    passed = passed && k12_vector_matches(83521, false, 0,
                                          "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe", 32, false);
    passed = passed && k12_vector_matches(1419857, false, 0,
                                          "844d610933b1b9963cbdeb5ae3b6b05cc7cbd67ceedf883eb678a0a8e0371682", 32, false);
    passed = passed && k12_vector_matches(24137569, false, 0,
                                          "3c390782a8a4e89fa6367f72feaaf13255c8d95878481d3cd8ce85f58e880af8", 32, false);

    passed = passed && k12_vector_matches(0, true, 1,
                                          "fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583", 32, false);
    passed = passed && k12_vector_matches(1, true, 41,
                                          "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4", 32, false);
    passed = passed && k12_vector_matches(3, true, 1681,
                                          "c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74", 32, false);
    passed = passed && k12_vector_matches(7, true, 68921,
                                          "75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf", 32, false);
    uint8_t abc[3] = {0x61, 0x62, 0x63};
    uint8_t one_shot[kK12DigestSize];
    uint8_t streamed[kK12DigestSize];
    k12_hash(abc, sizeof(abc), one_shot);
    KangarooTwelve state;
    k12_init(&state);
    k12_update(&state, abc, 1);
    k12_update(&state, abc + 1, 2);
    k12_final(&state, nullptr, 0, streamed, sizeof(streamed));
    passed = passed && memcmp(one_shot, streamed, sizeof(one_shot)) == 0;
    turboshake128_absorb_marker(nullptr, kMarkerMessageHop);
    uint8_t sentinel = 0xa5;
    k12_update(&state, abc, sizeof(abc));
    k12_final(&state, nullptr, 0, &sentinel, 1);
    return passed && sentinel == 0xa5;
  }
#endif

}
