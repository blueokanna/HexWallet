#include "Blake3.h"

#include <string.h>

namespace hexwallet
{
  namespace
  {

    constexpr uint32_t kIv[8] = {
        0x6a09e667u,
        0xbb67ae85u,
        0x3c6ef372u,
        0xa54ff53au,
        0x510e527fu,
        0x9b05688cu,
        0x1f83d9abu,
        0x5be0cd19u,
    };

    constexpr uint8_t kMessageSchedule[16] = {
        2,
        6,
        3,
        10,
        7,
        0,
        4,
        13,
        1,
        11,
        12,
        5,
        9,
        14,
        15,
        8,
    };

    constexpr uint32_t kFlagChunkStart = 1u << 0;
    constexpr uint32_t kFlagChunkEnd = 1u << 1;
    constexpr uint32_t kFlagParent = 1u << 2;
    constexpr uint32_t kFlagRoot = 1u << 3;
    constexpr uint32_t kFlagKeyedHash = 1u << 4;
    constexpr uint32_t kFlagDeriveKeyContext = 1u << 5;
    constexpr uint32_t kFlagDeriveKeyMaterial = 1u << 6;

    struct Output
    {
      uint32_t input_cv[8];
      uint32_t block[16];
      uint64_t counter;
      uint32_t block_len;
      uint32_t flags;
    };

    uint32_t load32(const uint8_t *data)
    {
      return static_cast<uint32_t>(data[0]) |
             (static_cast<uint32_t>(data[1]) << 8) |
             (static_cast<uint32_t>(data[2]) << 16) |
             (static_cast<uint32_t>(data[3]) << 24);
    }

    void store32(uint8_t *data, uint32_t value)
    {
      data[0] = static_cast<uint8_t>(value);
      data[1] = static_cast<uint8_t>(value >> 8);
      data[2] = static_cast<uint8_t>(value >> 16);
      data[3] = static_cast<uint8_t>(value >> 24);
    }

    uint32_t rotate_right(uint32_t value, int bits)
    {
      return (value >> bits) | (value << (32 - bits));
    }

    void mix(uint32_t *state, size_t a, size_t b, size_t c, size_t d,
             uint32_t message_x, uint32_t message_y)
    {
      state[a] = state[a] + state[b] + message_x;
      state[d] = rotate_right(state[d] ^ state[a], 16);
      state[c] = state[c] + state[d];
      state[b] = rotate_right(state[b] ^ state[c], 12);
      state[a] = state[a] + state[b] + message_y;
      state[d] = rotate_right(state[d] ^ state[a], 8);
      state[c] = state[c] + state[d];
      state[b] = rotate_right(state[b] ^ state[c], 7);
    }

    void round_function(uint32_t *state, const uint32_t *message)
    {
      mix(state, 0, 4, 8, 12, message[0], message[1]);
      mix(state, 1, 5, 9, 13, message[2], message[3]);
      mix(state, 2, 6, 10, 14, message[4], message[5]);
      mix(state, 3, 7, 11, 15, message[6], message[7]);
      mix(state, 0, 5, 10, 15, message[8], message[9]);
      mix(state, 1, 6, 11, 12, message[10], message[11]);
      mix(state, 2, 7, 8, 13, message[12], message[13]);
      mix(state, 3, 4, 9, 14, message[14], message[15]);
    }

    void permute_message(uint32_t *message)
    {
      uint32_t permuted[16];
      for (size_t index = 0; index < 16; ++index)
      {
        permuted[index] = message[kMessageSchedule[index]];
      }
      memcpy(message, permuted, sizeof(permuted));
    }

    void compress(const uint32_t cv[8], const uint32_t block[16], uint64_t counter,
                  uint32_t block_len, uint32_t flags, uint32_t out[16])
    {
      uint32_t state[16];
      for (size_t index = 0; index < 8; ++index)
      {
        state[index] = cv[index];
      }
      for (size_t index = 0; index < 4; ++index)
      {
        state[8 + index] = kIv[index];
      }
      state[12] = static_cast<uint32_t>(counter);
      state[13] = static_cast<uint32_t>(counter >> 32);
      state[14] = block_len;
      state[15] = flags;

      uint32_t message[16];
      memcpy(message, block, sizeof(message));
      for (int round = 0; round < 7; ++round)
      {
        round_function(state, message);
        if (round != 6)
        {
          permute_message(message);
        }
      }

      for (size_t index = 0; index < 8; ++index)
      {
        out[index] = state[index] ^ state[index + 8];
        out[index + 8] = state[index + 8] ^ cv[index];
      }
    }

    size_t chunk_bytes(const Blake3State *state)
    {
      return static_cast<size_t>(state->blocks_compressed) * kBlake3BlockLen +
             state->block_len;
    }

    void chunk_reset(Blake3State *state, uint64_t counter)
    {
      memcpy(state->chunk_cv, state->key_words, sizeof(state->chunk_cv));
      state->chunk_counter = counter;
      state->block_len = 0;
      state->blocks_compressed = 0;
      memset(state->block, 0, sizeof(state->block));
    }

    void chunk_update(Blake3State *state, const uint8_t *data, size_t size)
    {
      while (size > 0)
      {
        if (state->block_len == kBlake3BlockLen)
        {
          uint32_t block_words[16];
          for (size_t index = 0; index < 16; ++index)
          {
            block_words[index] = load32(state->block + index * 4);
          }
          const uint32_t chunk_flags =
              state->flags | (state->blocks_compressed == 0 ? kFlagChunkStart : 0u);
          uint32_t compressed[16];
          compress(state->chunk_cv, block_words, state->chunk_counter,
                   kBlake3BlockLen, chunk_flags, compressed);
          memcpy(state->chunk_cv, compressed, sizeof(state->chunk_cv));
          state->blocks_compressed =
              static_cast<uint8_t>(state->blocks_compressed + 1);
          memset(state->block, 0, sizeof(state->block));
          state->block_len = 0;
        }
        const size_t want = kBlake3BlockLen - state->block_len;
        const size_t take = size < want ? size : want;
        memcpy(state->block + state->block_len, data, take);
        state->block_len = static_cast<uint8_t>(state->block_len + take);
        data += take;
        size -= take;
      }
    }

    void chunk_output(const Blake3State *state, Output *output)
    {
      memcpy(output->input_cv, state->chunk_cv, sizeof(output->input_cv));
      for (size_t index = 0; index < 16; ++index)
      {
        output->block[index] = load32(state->block + index * 4);
      }
      output->counter = state->chunk_counter;
      output->block_len = state->block_len;
      output->flags = state->flags |
                      (state->blocks_compressed == 0 ? kFlagChunkStart : 0u) |
                      kFlagChunkEnd;
    }

    void output_chaining_value(const Output *output, uint32_t cv[8])
    {
      uint32_t compressed[16];
      compress(output->input_cv, output->block, output->counter, output->block_len,
               output->flags, compressed);
      memcpy(cv, compressed, sizeof(uint32_t) * 8);
    }

    void parent_output(const uint32_t left[8], const uint32_t right[8],
                       const uint32_t key_words[8], uint32_t flags, Output *output)
    {
      memcpy(output->input_cv, key_words, sizeof(output->input_cv));
      for (size_t index = 0; index < 8; ++index)
      {
        output->block[index] = left[index];
        output->block[index + 8] = right[index];
      }
      output->counter = 0;
      output->block_len = kBlake3BlockLen;
      output->flags = flags | kFlagParent;
    }

    void merge_stack(Blake3State *state, uint64_t completed_chunks)
    {
      size_t target = 0;
      for (uint64_t remaining = completed_chunks; remaining != 0; remaining >>= 1)
      {
        target += static_cast<size_t>(remaining & 1u);
      }
      while (state->stack_len > target)
      {
        state->stack_len = static_cast<uint8_t>(state->stack_len - 1);
        Output parent;
        uint32_t cv[8];
        parent_output(state->cv_stack[state->stack_len - 1],
                      state->cv_stack[state->stack_len], state->key_words,
                      state->flags, &parent);
        output_chaining_value(&parent, cv);
        memcpy(state->cv_stack[state->stack_len - 1], cv, sizeof(cv));
      }
    }

    void push_stack(Blake3State *state, const uint32_t cv[8])
    {
      merge_stack(state, state->chunk_counter);
      if (state->stack_len >= kBlake3MaxDepth)
      {
        return;
      }
      memcpy(state->cv_stack[state->stack_len], cv, sizeof(state->cv_stack[0]));
      state->stack_len = static_cast<uint8_t>(state->stack_len + 1);
    }

  } // namespace

  bool blake3_init(Blake3State *state, Blake3Mode mode, const uint8_t *key,
                   const char *context)
  {
    if (state == nullptr)
    {
      return false;
    }
    memset(state, 0, sizeof(*state));
    switch (mode)
    {
    case Blake3Mode::Hash:
      memcpy(state->key_words, kIv, sizeof(kIv));
      state->flags = 0;
      break;
    case Blake3Mode::KeyedHash:
      if (key == nullptr)
      {
        return false;
      }
      for (size_t index = 0; index < 8; ++index)
      {
        state->key_words[index] = load32(key + index * 4);
      }
      state->flags = kFlagKeyedHash;
      break;
    case Blake3Mode::DeriveKey:
    {
      if (context == nullptr)
      {
        return false;
      }
      Blake3State context_state;
      if (!blake3_init(&context_state, Blake3Mode::Hash, nullptr, nullptr))
      {
        return false;
      }
      context_state.flags = kFlagDeriveKeyContext;
      blake3_update(&context_state,
                    reinterpret_cast<const uint8_t *>(context), strlen(context));
      uint8_t context_key[kBlake3OutLen];
      blake3_final(&context_state, context_key, sizeof(context_key));
      for (size_t index = 0; index < 8; ++index)
      {
        state->key_words[index] = load32(context_key + index * 4);
      }
      memset(context_key, 0, sizeof(context_key));
      state->flags = kFlagDeriveKeyMaterial;
      break;
    }
    default:
      return false;
    }
    chunk_reset(state, 0);
    return true;
  }

  void blake3_update(Blake3State *state, const uint8_t *data, size_t size)
  {
    if (state == nullptr || data == nullptr || size == 0)
    {
      return;
    }
    while (size > 0)
    {
      if (chunk_bytes(state) == kBlake3ChunkLen)
      {
        Output output;
        uint32_t cv[8];
        chunk_output(state, &output);
        output_chaining_value(&output, cv);
        push_stack(state, cv);
        chunk_reset(state, state->chunk_counter + 1);
      }
      const size_t want = kBlake3ChunkLen - chunk_bytes(state);
      const size_t take = size < want ? size : want;
      chunk_update(state, data, take);
      data += take;
      size -= take;
    }
    merge_stack(state, state->chunk_counter);
  }

  void blake3_final(const Blake3State *state, uint8_t *out, size_t out_len)
  {
    if (state == nullptr || out == nullptr || out_len == 0)
    {
      return;
    }
    Output output;
    chunk_output(state, &output);
    uint32_t cv[8];
    output_chaining_value(&output, cv);
    size_t remaining = state->stack_len;
    while (remaining > 0)
    {
      remaining -= 1;
      parent_output(state->cv_stack[remaining], cv, state->key_words,
                    state->flags, &output);
      output_chaining_value(&output, cv);
    }

    size_t offset = 0;
    uint64_t output_block = 0;
    while (offset < out_len)
    {
      uint32_t words[16];
      compress(output.input_cv, output.block, output_block, output.block_len,
               output.flags | kFlagRoot, words);
      uint8_t bytes[kBlake3BlockLen];
      for (size_t index = 0; index < 16; ++index)
      {
        store32(bytes + index * 4, words[index]);
      }
      const size_t take =
          out_len - offset < kBlake3BlockLen ? out_len - offset : kBlake3BlockLen;
      memcpy(out + offset, bytes, take);
      offset += take;
      output_block += 1;
    }
  }

  void blake3_hash(const uint8_t *data, size_t size, uint8_t out[kBlake3OutLen])
  {
    blake3_hash_xof(data, size, out, kBlake3OutLen);
  }

  void blake3_hash_xof(const uint8_t *data, size_t size, uint8_t *out,
                       size_t out_len)
  {
    Blake3State state;
    if (!blake3_init(&state, Blake3Mode::Hash, nullptr, nullptr))
    {
      return;
    }
    blake3_update(&state, data, size);
    blake3_final(&state, out, out_len);
  }

  void blake3_keyed_hash(const uint8_t key[kBlake3KeyLen], const uint8_t *data,
                         size_t size, uint8_t *out, size_t out_len)
  {
    Blake3State state;
    if (!blake3_init(&state, Blake3Mode::KeyedHash, key, nullptr))
    {
      return;
    }
    blake3_update(&state, data, size);
    blake3_final(&state, out, out_len);
  }

  void blake3_derive_key(const char *context, const uint8_t *data, size_t size,
                         uint8_t *out, size_t out_len)
  {
    Blake3State state;
    if (!blake3_init(&state, Blake3Mode::DeriveKey, nullptr, context))
    {
      return;
    }
    blake3_update(&state, data, size);
    blake3_final(&state, out, out_len);
  }

  namespace
  {

#if defined(HEXWALLET_HOST_TEST)
#include "src/generated/Blake3VectorsTest.inc"
#else
#include "src/generated/Blake3Kat.inc"
#endif

    void feed_pattern(Blake3State *state, uint32_t length)
    {
      uint8_t piece[251];
      for (uint32_t offset = 0; offset < length;)
      {
        size_t take = length - offset;
        if (take > sizeof(piece))
        {
          take = sizeof(piece);
        }
        for (size_t byte = 0; byte < take; ++byte)
        {
          piece[byte] = static_cast<uint8_t>((offset + byte) % 251u);
        }
        blake3_update(state, piece, take);
        offset += static_cast<uint32_t>(take);
      }
    }

  }

  bool run_blake3_self_tests()
  {
    bool passed = true;
    uint8_t output[kBlake3TestOutputLen];
    for (size_t index = 0; index < kBlake3TestCount; ++index)
    {
      const uint32_t length = kBlake3TestInputLengths[index];
      Blake3State state;

      passed = passed && blake3_init(&state, Blake3Mode::Hash, nullptr, nullptr);
      feed_pattern(&state, length);
      blake3_final(&state, output, sizeof(output));
      passed = passed && memcmp(output, kBlake3TestHash[index], sizeof(output)) == 0;

      passed = passed && blake3_init(&state, Blake3Mode::KeyedHash, kBlake3TestKey,
                                     nullptr);
      feed_pattern(&state, length);
      blake3_final(&state, output, sizeof(output));
      passed =
          passed && memcmp(output, kBlake3TestKeyedHash[index], sizeof(output)) == 0;

      passed = passed &&
               blake3_init(&state, Blake3Mode::DeriveKey, nullptr, kBlake3TestContext);
      feed_pattern(&state, length);
      blake3_final(&state, output, sizeof(output));
      passed =
          passed && memcmp(output, kBlake3TestDeriveKey[index], sizeof(output)) == 0;
    }

    uint8_t sample[300];
    for (size_t index = 0; index < sizeof(sample); ++index)
    {
      sample[index] = static_cast<uint8_t>(index % 251u);
    }
    uint8_t expected[kBlake3OutLen];
    uint8_t actual[kBlake3OutLen];
    blake3_hash(sample, sizeof(sample), expected);
    Blake3State state;
    passed = passed && blake3_init(&state, Blake3Mode::Hash, nullptr, nullptr);
    for (size_t index = 0; index < sizeof(sample); ++index)
    {
      blake3_update(&state, sample + index, 1);
    }
    blake3_final(&state, actual, sizeof(actual));
    passed = passed && memcmp(expected, actual, sizeof(expected)) == 0;

    uint8_t extended[131];
    blake3_hash_xof(sample, sizeof(sample), extended, sizeof(extended));
    passed = passed && memcmp(extended, expected, sizeof(expected)) == 0;

    passed = passed && !blake3_init(&state, Blake3Mode::KeyedHash, nullptr, nullptr);
    passed = passed && !blake3_init(&state, Blake3Mode::DeriveKey, nullptr, nullptr);
    return passed;
  }

}
