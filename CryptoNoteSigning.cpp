#include "CryptoNoteSigning.h"

#include <string.h>

#include "CryptoExtended.h"
#include "CryptoNoteAddress.h"
#include "CryptoNoteAmounts.h"
#include "CryptoNoteRingCt.h"
#include "CryptoNoteSpend.h"
#include "CryptoPrimitives.h"
#include "WalletConfig.h"

namespace hexwallet
{
  namespace
  {
    int g_signing_stage = 0;
    int g_signing_error = -1;
#define SIGNING_STAGE(n) do { g_signing_stage = (n); } while (0)

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
      bool u8(uint8_t *value)
      {
        const uint8_t *p = nullptr;
        if (!bytes(&p, 1)) return false;
        *value = p[0];
        return true;
      }
      bool u16(uint16_t *value)
      {
        const uint8_t *p = nullptr;
        if (!bytes(&p, 2)) return false;
        *value = static_cast<uint16_t>(p[0]) |
                 static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8);
        return true;
      }
      bool u32(uint32_t *value)
      {
        const uint8_t *p = nullptr;
        if (!bytes(&p, 4)) return false;
        uint32_t v = 0;
        for (size_t i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p[i]) << (8 * i);
        *value = v;
        return true;
      }
      bool u64(uint64_t *value)
      {
        const uint8_t *p = nullptr;
        if (!bytes(&p, 8)) return false;
        uint64_t v = 0;
        for (size_t i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
        *value = v;
        return true;
      }
      bool finished() const { return ok && offset == size; }
    };

    bool nonzero_scalar(const uint8_t scalar[kCryptoNoteKeySize])
    {
      uint8_t acc = 0;
      for (size_t i = 0; i < kCryptoNoteKeySize; ++i) acc |= scalar[i];
      return acc != 0;
    }

    CryptoNoteTxError map_tx_error(CryptoNoteTxError error)
    {
      return error;
    }
  } // namespace

  int cryptonote_signing_last_stage() { return g_signing_stage; }
  int cryptonote_signing_last_error() { return g_signing_error; }

  void cryptonote_signing_clear(CryptoNoteSigningState *state)
  {
    if (state != nullptr) secure_zero(state, sizeof(*state));
  }

  CryptoNoteTxError cryptonote_signing_prepare(
      const char *network_id, const uint8_t *payload, size_t payload_size,
      const uint8_t seed[kSeedSize], CryptoNoteSigningState *state)
  {
    cryptonote_signing_clear(state);
    if (seed == nullptr) return CryptoNoteTxError::InvalidArgument;
    uint8_t view_secret[kCryptoNoteKeySize] = {};
    uint8_t spend_secret[kCryptoNoteKeySize] = {};
    if (cryptonote_private_keys_from_seed(seed, spend_secret, view_secret) !=
        WalletError::Ok)
    {
      secure_zero(view_secret, sizeof(view_secret));
      secure_zero(spend_secret, sizeof(spend_secret));
      return CryptoNoteTxError::CryptoFailure;
    }
    const CryptoNoteTxError error = cryptonote_signing_prepare_with_keys(
        network_id, payload, payload_size, view_secret, spend_secret, state);
    secure_zero(view_secret, sizeof(view_secret));
    secure_zero(spend_secret, sizeof(spend_secret));
    return error;
  }

  CryptoNoteTxError cryptonote_signing_prepare_with_keys(
      const char *network_id, const uint8_t *payload, size_t payload_size,
      const uint8_t view_secret[kCryptoNoteKeySize],
      const uint8_t spend_secret[kCryptoNoteKeySize],
      CryptoNoteSigningState *state)
  {
    SIGNING_STAGE(1);
    cryptonote_signing_clear(state);
    if (network_id == nullptr || payload == nullptr || state == nullptr ||
        view_secret == nullptr || spend_secret == nullptr || payload_size == 0 ||
        payload_size > kCryptoNoteMaxSigningPayload)
      return CryptoNoteTxError::InvalidArgument;

    const CryptoNoteReviewPolicy *policy = cryptonote_review_policy(network_id);
    if (policy == nullptr) return CryptoNoteTxError::Unsupported;
    const bool monero = policy->network == CryptoNoteReviewNetwork::MoneroMainnet;

    memset(state, 0, sizeof(*state));
    Reader reader = { payload, payload_size, 0, true };

    uint8_t version = 0;
    if (!reader.u8(&version) ||
        (version != kCryptoNoteSigningPayloadVersion &&
         version != kCryptoNoteSigningPayloadVersionStandardOnly))
      return CryptoNoteTxError::Unsupported;
    const bool has_subaddress = version >= kCryptoNoteSigningPayloadVersion;

    uint16_t tx_size = 0;
    const uint8_t *tx_bytes = nullptr;
    if (!reader.u16(&tx_size) || tx_size == 0 ||
        !reader.bytes(&tx_bytes, tx_size))
      return CryptoNoteTxError::Truncated;

    SIGNING_STAGE(2);
    CryptoNoteTxError error;
    uint16_t chain_inputs = 0;
    uint16_t chain_outputs = 0;
    uint16_t chain_ring_size = 0;
    if (monero)
    {
      error = cryptonote_parse_transaction(tx_bytes, tx_size, &state->chain.monero);
      chain_inputs = state->chain.monero.input_count;
      chain_outputs = state->chain.monero.output_count;
      chain_ring_size = state->chain.monero.rct.ring_size;
    }
    else
    {
      error = masari_parse_transaction(tx_bytes, tx_size, &state->chain.masari);
      chain_inputs = state->chain.masari.input_count;
      chain_outputs = state->chain.masari.output_count;
      chain_ring_size = state->chain.masari.input_count == 0
                            ? 0
                            : state->chain.masari.inputs[0].offset_count;
    }
    if (error != CryptoNoteTxError::Ok)
    {
      cryptonote_signing_clear(state);
      return error;
    }

    const uint8_t *tx_secret = nullptr;
    if (!reader.bytes(&tx_secret, kCryptoNoteKeySize)) { cryptonote_signing_clear(state); return CryptoNoteTxError::Truncated; }
    memcpy(state->tx_secret, tx_secret, kCryptoNoteKeySize);

    uint8_t input_count = 0;
    uint8_t output_count = 0;
    uint8_t flags = 0;
    if (!reader.u8(&input_count) || !reader.u8(&output_count) ||
        !reader.u8(&flags))
    {
      cryptonote_signing_clear(state);
      return CryptoNoteTxError::Truncated;
    }
    if (input_count == 0 || input_count > kCryptoNoteMaxSignInputs ||
        output_count == 0 || output_count > kCryptoNoteMaxSignOutputs)
    {
      cryptonote_signing_clear(state);
      return CryptoNoteTxError::TooManyItems;
    }
    if (input_count != chain_inputs || output_count != chain_outputs)
    {
      cryptonote_signing_clear(state);
      return CryptoNoteTxError::InvalidArgument;
    }
    const bool output_masks = (flags & 0x01) != 0;
    if ((flags & ~0x01u) != 0 || (monero && output_masks))
    {
      cryptonote_signing_clear(state);
      return CryptoNoteTxError::NonCanonical;
    }
    if (chain_ring_size > kCryptoNoteMaxRingSize)
    {
      cryptonote_signing_clear(state);
      return CryptoNoteTxError::InvalidArgument;
    }
    state->input_count = input_count;
    state->output_count = output_count;
    state->ring_size = static_cast<uint8_t>(chain_ring_size);

    SIGNING_STAGE(3);
    for (uint8_t index = 0; index < input_count; ++index)
    {
      CryptoNoteSigningInput &input = state->inputs[index];
      const uint8_t *field = nullptr;
      if (!reader.u64(&input.amount) || !reader.u16(&input.real_index) ||
          !reader.u16(&input.ring_size) ||
          !reader.bytes(&field, kCryptoNoteKeySize))
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::Truncated;
      }
      memcpy(input.original_tx_public, field, kCryptoNoteKeySize);
      if (!reader.u64(&input.output_index) ||
          !reader.bytes(&field, kCryptoNoteKeySize))
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::Truncated;
      }
      memcpy(input.pseudo_out_mask, field, kCryptoNoteKeySize);
      if (has_subaddress &&
          (!reader.u32(&input.subaddress_major) ||
           !reader.u32(&input.subaddress_minor)))
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::Truncated;
      }
      if (input.ring_size > kCryptoNoteMaxRingSize ||
          input.ring_size != state->ring_size ||
          input.real_index >= input.ring_size)
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::InvalidArgument;
      }
      const uint8_t ring_size = static_cast<uint8_t>(input.ring_size);
      for (uint8_t member = 0; member < ring_size; ++member)
      {
        if (!reader.u64(&input.key_offsets[member]))
        {
          cryptonote_signing_clear(state);
          return CryptoNoteTxError::Truncated;
        }
      }
      for (uint8_t member = 0; member < ring_size; ++member)
      {
        if (!reader.bytes(&field, kCryptoNoteKeySize))
        {
          cryptonote_signing_clear(state);
          return CryptoNoteTxError::Truncated;
        }
        memcpy(input.ring[member].dest, field, kCryptoNoteKeySize);
        if (!reader.bytes(&field, kCryptoNoteKeySize))
        {
          cryptonote_signing_clear(state);
          return CryptoNoteTxError::Truncated;
        }
        memcpy(input.ring[member].mask, field, kCryptoNoteKeySize);
      }
    }

    SIGNING_STAGE(4);
    for (uint8_t index = 0; index < output_count; ++index)
    {
      CryptoNoteSigningOutput &output = state->outputs[index];
      const uint8_t *field = nullptr;
      uint8_t output_flags = 0;
      if (!reader.u8(&output_flags) ||
          !reader.bytes(&field, kCryptoNoteKeySize))
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::Truncated;
      }
      memcpy(output.spend_public, field, kCryptoNoteKeySize);
      if (!reader.bytes(&field, kCryptoNoteKeySize))
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::Truncated;
      }
      memcpy(output.view_public, field, kCryptoNoteKeySize);
      if (!reader.u64(&output.amount))
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::Truncated;
      }
      output.change = (output_flags & 0x01) != 0;
      if ((output_flags & ~0x03u) != 0)
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::NonCanonical;
      }
      output.address_type = static_cast<uint8_t>((output_flags >> 1) & 0x03);
      if (output.address_type > 1)
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::Unsupported;
      }
      if (has_subaddress &&
          (!reader.u32(&output.subaddress_major) ||
           !reader.u32(&output.subaddress_minor)))
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::Truncated;
      }
      if (output_masks)
      {
        if (!reader.bytes(&field, kCryptoNoteKeySize))
        {
          cryptonote_signing_clear(state);
          return CryptoNoteTxError::Truncated;
        }
        memcpy(output.mask, field, kCryptoNoteKeySize);
      }
    }
    if (!reader.finished())
    {
      cryptonote_signing_clear(state);
      return CryptoNoteTxError::NonCanonical;
    }
    // Rendering and ownership must agree: a change line only claims a
    // subaddress when the record carries one, and external outputs must not
    // smuggle subaddress fields in.
    for (uint8_t index = 0; index < output_count; ++index)
    {
      const CryptoNoteSigningOutput &output = state->outputs[index];
      if (output.address_type != 0)
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::Unsupported;
      }
      const bool has_subaddress_fields =
          output.subaddress_major != 0 || output.subaddress_minor != 0;
      if (has_subaddress_fields && !output.change)
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::InvalidArgument;
      }
      if (output.change && (output.address_type == 1) != has_subaddress_fields)
      {
        cryptonote_signing_clear(state);
        return CryptoNoteTxError::InvalidArgument;
      }
    }
    // Subaddress inputs are supported. Destinations/change still require the
    // additional transaction-key protocol before they can be admitted.

    SIGNING_STAGE(5);
    CryptoNoteReviewInput review_inputs[kCryptoNoteMaxSignInputs];
    CryptoNoteReviewOutput review_outputs[kCryptoNoteMaxSignOutputs];
    memset(review_inputs, 0, sizeof(review_inputs));
    memset(review_outputs, 0, sizeof(review_outputs));
    for (uint8_t index = 0; index < input_count; ++index)
    {
      const CryptoNoteSigningInput &input = state->inputs[index];
      review_inputs[index].amount = input.amount;
      review_inputs[index].real_index = input.real_index;
      review_inputs[index].ring_size = input.ring_size;
      memcpy(review_inputs[index].original_tx_public, input.original_tx_public,
             kCryptoNoteKeySize);
      review_inputs[index].output_index = input.output_index;
      review_inputs[index].ring = input.ring;
      review_inputs[index].key_offsets = input.key_offsets;
      memcpy(review_inputs[index].pseudo_out_mask, input.pseudo_out_mask,
             kCryptoNoteKeySize);
      review_inputs[index].subaddress_major = input.subaddress_major;
      review_inputs[index].subaddress_minor = input.subaddress_minor;
    }
    for (uint8_t index = 0; index < output_count; ++index)
    {
      const CryptoNoteSigningOutput &output = state->outputs[index];
      review_outputs[index].change = output.change;
      review_outputs[index].address_type = output.address_type;
      memcpy(review_outputs[index].spend_public, output.spend_public,
             kCryptoNoteKeySize);
      memcpy(review_outputs[index].view_public, output.view_public,
             kCryptoNoteKeySize);
      review_outputs[index].amount = output.amount;
      memcpy(review_outputs[index].mask, output.mask, kCryptoNoteKeySize);
      review_outputs[index].subaddress_major = output.subaddress_major;
      review_outputs[index].subaddress_minor = output.subaddress_minor;
    }

    SIGNING_STAGE(6);
    if (monero)
    {
      CryptoNoteReviewResult result;
      error = cryptonote_review_transaction(
          state->chain.monero, view_secret, spend_secret, state->tx_secret,
          review_inputs, input_count, review_outputs, output_count, &result);
      if (error == CryptoNoteTxError::Ok)
      {
        memcpy(state->signing_mask, result.signing_mask,
               sizeof(state->signing_mask));
        state->summary = result.summary;
      }
      secure_zero(&result, sizeof(result));
    }
    else
    {
      MasariReviewInput masari_inputs[kCryptoNoteMaxSignInputs];
      MasariReviewOutput masari_outputs[kCryptoNoteMaxSignOutputs];
      memset(masari_inputs, 0, sizeof(masari_inputs));
      memset(masari_outputs, 0, sizeof(masari_outputs));
      for (uint8_t index = 0; index < input_count; ++index)
      {
        masari_inputs[index].amount = state->inputs[index].amount;
        masari_inputs[index].real_index = state->inputs[index].real_index;
        masari_inputs[index].ring_size = state->inputs[index].ring_size;
        memcpy(masari_inputs[index].original_tx_public,
               state->inputs[index].original_tx_public, kCryptoNoteKeySize);
        masari_inputs[index].output_index = state->inputs[index].output_index;
        masari_inputs[index].ring = state->inputs[index].ring;
        masari_inputs[index].key_offsets = state->inputs[index].key_offsets;
        memcpy(masari_inputs[index].pseudo_out_mask,
               state->inputs[index].pseudo_out_mask, kCryptoNoteKeySize);
        masari_inputs[index].subaddress_major =
            state->inputs[index].subaddress_major;
        masari_inputs[index].subaddress_minor =
            state->inputs[index].subaddress_minor;
      }
      for (uint8_t index = 0; index < output_count; ++index)
      {
        masari_outputs[index].change = state->outputs[index].change;
        masari_outputs[index].address_type = state->outputs[index].address_type;
        memcpy(masari_outputs[index].spend_public,
               state->outputs[index].spend_public, kCryptoNoteKeySize);
        memcpy(masari_outputs[index].view_public,
               state->outputs[index].view_public, kCryptoNoteKeySize);
        masari_outputs[index].amount = state->outputs[index].amount;
        memcpy(masari_outputs[index].mask, state->outputs[index].mask,
               kCryptoNoteKeySize);
        masari_outputs[index].subaddress_major =
            state->outputs[index].subaddress_major;
        masari_outputs[index].subaddress_minor =
            state->outputs[index].subaddress_minor;
      }
      MasariReviewResult result;
      error = masari_review_transaction(
          &state->chain.masari, view_secret, spend_secret, state->tx_secret,
          masari_inputs, input_count, masari_outputs, output_count, &result);
      if (error == CryptoNoteTxError::Ok)
      {
        memcpy(state->signing_mask, result.signing_mask,
               sizeof(state->signing_mask));
        state->summary = result.summary;
      }
      secure_zero(&result, sizeof(result));
      secure_zero(masari_inputs, sizeof(masari_inputs));
      secure_zero(masari_outputs, sizeof(masari_outputs));
    }
    if (error != CryptoNoteTxError::Ok)
    {
      g_signing_error = static_cast<int>(error);
      g_signing_stage = 100 + (monero ? cryptonote_review_last_stage()
                                      : masari_last_stage());
      cryptonote_signing_clear(state);
      return map_tx_error(error);
    }

    state->network = policy->network;
    SIGNING_STAGE(7);
    return CryptoNoteTxError::Ok;
  }

  CryptoNoteTxError cryptonote_signing_sign(
      CryptoNoteSigningState *state, const uint8_t seed[kSeedSize],
      const uint8_t nonce_seed[kCryptoNoteKeySize], uint8_t *out,
      size_t *in_out_size)
  {
    if (seed == nullptr) {
      cryptonote_signing_clear(state);
      return CryptoNoteTxError::InvalidArgument;
    }
    uint8_t view_secret[kCryptoNoteKeySize] = {};
    uint8_t spend_secret[kCryptoNoteKeySize] = {};
    if (cryptonote_private_keys_from_seed(seed, spend_secret, view_secret) !=
        WalletError::Ok)
    {
      cryptonote_signing_clear(state);
      secure_zero(view_secret, sizeof(view_secret));
      secure_zero(spend_secret, sizeof(spend_secret));
      return CryptoNoteTxError::CryptoFailure;
    }
    const CryptoNoteTxError error = cryptonote_signing_sign_with_keys(
        state, view_secret, spend_secret, nonce_seed, out, in_out_size);
    secure_zero(view_secret, sizeof(view_secret));
    secure_zero(spend_secret, sizeof(spend_secret));
    return error;
  }

  CryptoNoteTxError cryptonote_signing_sign_with_keys(
      CryptoNoteSigningState *state,
      const uint8_t view_secret[kCryptoNoteKeySize],
      const uint8_t spend_secret[kCryptoNoteKeySize],
      const uint8_t nonce_seed[kCryptoNoteKeySize], uint8_t *out,
      size_t *in_out_size)
  {
    if (state == nullptr || view_secret == nullptr || spend_secret == nullptr ||
        nonce_seed == nullptr || out == nullptr || in_out_size == nullptr)
    {
      cryptonote_signing_clear(state);
      return CryptoNoteTxError::InvalidArgument;
    }
    if (state->input_count == 0 || state->input_count > kCryptoNoteMaxSignInputs ||
        (state->network != CryptoNoteReviewNetwork::MoneroMainnet &&
         state->network != CryptoNoteReviewNetwork::MasariMainnet))
    {
      cryptonote_signing_clear(state);
      return CryptoNoteTxError::InvalidArgument;
    }
    if (state->network != CryptoNoteReviewNetwork::MoneroMainnet) {
      cryptonote_signing_clear(state);
      return CryptoNoteTxError::Unsupported;
    }

    if (state->network == CryptoNoteReviewNetwork::MasariMainnet)
    {
      MasariReviewInput review_inputs[kCryptoNoteMaxSignInputs];
      memset(review_inputs, 0, sizeof(review_inputs));
      for (uint8_t index = 0; index < state->input_count; ++index)
      {
        review_inputs[index].amount = state->inputs[index].amount;
        review_inputs[index].real_index = state->inputs[index].real_index;
        review_inputs[index].ring_size = state->inputs[index].ring_size;
        memcpy(review_inputs[index].original_tx_public,
               state->inputs[index].original_tx_public, kCryptoNoteKeySize);
        review_inputs[index].output_index = state->inputs[index].output_index;
        review_inputs[index].ring = state->inputs[index].ring;
        review_inputs[index].key_offsets = state->inputs[index].key_offsets;
        memcpy(review_inputs[index].pseudo_out_mask,
               state->inputs[index].pseudo_out_mask, kCryptoNoteKeySize);
        review_inputs[index].subaddress_major =
            state->inputs[index].subaddress_major;
        review_inputs[index].subaddress_minor =
            state->inputs[index].subaddress_minor;
      }
      MasariReviewResult review;
      memset(&review, 0, sizeof(review));
      memcpy(review.signing_mask, state->signing_mask, sizeof(review.signing_mask));
      memcpy(review.message, state->chain.masari.message, kCryptoNoteKeySize);
      const CryptoNoteTxError error = masari_sign_transaction(
          &state->chain.masari, review, view_secret, spend_secret,
          review_inputs, state->input_count, nonce_seed, out, in_out_size);
      secure_zero(&review, sizeof(review));
      secure_zero(review_inputs, sizeof(review_inputs));
      cryptonote_signing_clear(state);
      return error;
    }

    CryptoNoteTxError error = CryptoNoteTxError::Ok;
    for (uint8_t index = 0; index < state->input_count && error == CryptoNoteTxError::Ok; ++index)
    {
      const CryptoNoteSigningInput &input = state->inputs[index];
      uint8_t derivation[kCryptoNoteKeySize];
      uint8_t one_time_secret[kCryptoNoteKeySize];
      uint8_t input_nonce[kCryptoNoteKeySize];
      uint8_t nonce_input[kCryptoNoteKeySize + 2];
      // Subaddress outputs spend with b + Hs("SubAddr" || a || major || minor).
      uint8_t input_spend_secret[kCryptoNoteKeySize];
      const bool subaddress =
          input.subaddress_major != 0 || input.subaddress_minor != 0;
      bool spend_key_ok = true;
      if (subaddress)
      {
        uint8_t sub_spend_public[kCryptoNoteKeySize];
        uint8_t sub_view_public[kCryptoNoteKeySize];
        spend_key_ok =
            cryptonote_subaddress_keys(spend_secret, view_secret,
                                      input.subaddress_major,
                                      input.subaddress_minor,
                                      input_spend_secret, sub_spend_public,
                                      sub_view_public) == WalletError::Ok;
        secure_zero(sub_spend_public, sizeof(sub_spend_public));
        secure_zero(sub_view_public, sizeof(sub_view_public));
      }
      else
      {
        memcpy(input_spend_secret, spend_secret, kCryptoNoteKeySize);
      }
      memcpy(nonce_input, nonce_seed, kCryptoNoteKeySize);
      nonce_input[kCryptoNoteKeySize] = index;
      nonce_input[kCryptoNoteKeySize + 1] = 0x5c;
      const bool derived =
          spend_key_ok &&
          cryptonote_generate_key_derivation(input.original_tx_public,
                                             view_secret, derivation) &&
          cryptonote_derive_secret_key(derivation, input.output_index,
                                       input_spend_secret, one_time_secret) &&
          cryptonote_hash_to_scalar(nonce_input, sizeof(nonce_input),
                                    input_nonce) &&
          nonzero_scalar(input_nonce);
      secure_zero(input_spend_secret, sizeof(input_spend_secret));
      if (!derived)
      {
        error = CryptoNoteTxError::CryptoFailure;
      }
      else
      {
        error = cryptonote_sign_input(
            &state->chain.monero, index, input.real_index, input.ring, one_time_secret,
            state->signing_mask[index], input_nonce);
      }
      secure_zero(derivation, sizeof(derivation));
      secure_zero(one_time_secret, sizeof(one_time_secret));
      secure_zero(input_nonce, sizeof(input_nonce));
      secure_zero(nonce_input, sizeof(nonce_input));
    }

    if (error == CryptoNoteTxError::Ok)
      error = cryptonote_serialize_transaction(state->chain.monero, out, in_out_size);

    cryptonote_signing_clear(state);
    return error;
  }

  // ---------------------------------------------------------------------------
  // Self-tests
  // ---------------------------------------------------------------------------
  bool run_cryptonote_signing_self_tests()
  {
    static CryptoNoteSigningState state;
    static uint8_t payload[kCryptoNoteMaxSigningPayload];

    // Failure at the API boundary must invalidate any previous reviewed state.
    const auto cleared = [&]() {
      const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&state);
      uint8_t remaining = 0;
      for (size_t i = 0; i < sizeof(state); ++i) remaining |= bytes[i];
      return remaining == 0;
    };
    memset(&state, 0xa5, sizeof(state));
    if (cryptonote_signing_prepare_with_keys(nullptr, nullptr, 0, nullptr,
        nullptr, &state) != CryptoNoteTxError::InvalidArgument || !cleared()) return false;
    memset(&state, 0xa5, sizeof(state));
    if (cryptonote_signing_sign_with_keys(&state, nullptr, nullptr, nullptr,
        nullptr, nullptr) != CryptoNoteTxError::InvalidArgument || !cleared()) return false;
    memset(&state, 0xa5, sizeof(state));
    if (cryptonote_signing_sign(&state, nullptr, nullptr, nullptr, nullptr) !=
        CryptoNoteTxError::InvalidArgument || !cleared()) return false;

    const uint8_t seed[kSeedSize] = {
        0x4c, 0x1f, 0x92, 0x03, 0xbe, 0x77, 0x51, 0xaa,
        0x0d, 0x66, 0x94, 0x31, 0xc8, 0x2f, 0x05, 0x7e,
        0xa1, 0x48, 0x9b, 0x22, 0x73, 0xd0, 0x6e, 0x15,
        0xb4, 0x05, 0xe9, 0x38, 0x7c, 0x21, 0x4f, 0x80,
    };
    // Public reference-fixture keys (TEST ONLY). They match the pinned
    // Monero prover output in src/generated/MoneroReviewProofTest.inc.
    const uint8_t view_secret[kCryptoNoteKeySize] = {0x33, 0x77, 0x01, 0xe8};
    const uint8_t spend_secret[kCryptoNoteKeySize] = {0x5a, 0x11, 0x9c, 0x42};
    SIGNING_STAGE(100);

    uint8_t our_spend_public[kCryptoNoteKeySize];
    uint8_t our_view_public[kCryptoNoteKeySize];
    uint8_t recipient_spend_public[kCryptoNoteKeySize];
    uint8_t recipient_view_public[kCryptoNoteKeySize];
    const uint8_t kRecipientSpendSecret[kCryptoNoteKeySize] = {0x91, 0x02};
    const uint8_t kRecipientViewSecret[kCryptoNoteKeySize] = {0x47, 0xee};
    const uint8_t kSenderTxSecret[kCryptoNoteKeySize] = {0x0b, 0xad, 0xf0, 0x0d};
    constexpr uint64_t kInputAmount = 900000000000ULL;
    constexpr uint64_t kSendAmount = 400000000000ULL;
    constexpr uint64_t kChangeAmount = 400000000000ULL;
    constexpr uint64_t kFee = 100000000000ULL;

    bool ok = true;
    ok = cryptonote_scalar_to_point(spend_secret, our_spend_public) &&
        cryptonote_scalar_to_point(view_secret, our_view_public) &&
        cryptonote_scalar_to_point(kRecipientSpendSecret, recipient_spend_public) &&
        cryptonote_scalar_to_point(kRecipientViewSecret, recipient_view_public);
    if (!ok) return false;
    SIGNING_STAGE(101);

    uint8_t original_tx_public[kCryptoNoteKeySize];
    uint8_t derivation[kCryptoNoteKeySize];
    uint8_t amount_key[kCryptoNoteKeySize];
    uint8_t our_mask[kCryptoNoteKeySize];
    uint8_t our_commitment[kCryptoNoteKeySize];
    uint8_t our_one_time[kCryptoNoteKeySize];
    const uint64_t our_output_index = 0;
    ok = cryptonote_scalar_to_point(kSenderTxSecret, original_tx_public) &&
         cryptonote_generate_key_derivation(our_view_public, kSenderTxSecret,
                                            derivation) &&
         cryptonote_derivation_to_scalar(derivation, our_output_index,
                                         amount_key) &&
         ringct_commitment_mask(amount_key, our_mask) &&
         ringct_commitment(our_mask, kInputAmount, our_commitment) &&
         cryptonote_derive_public_key(derivation, our_output_index,
                                      our_spend_public, our_one_time);
    if (!ok) return false;

    static CryptoNoteRingMember ring[kCryptoNoteMaxRingSize];
    static uint64_t offsets[kCryptoNoteMaxRingSize];
    for (uint16_t member = 0; member < 16; ++member)
    {
      uint8_t label[2] = {static_cast<uint8_t>(member), 0x5a};
      uint8_t mask_label[2] = {static_cast<uint8_t>(member), 0x6b};
      uint8_t point_seed[kCryptoNoteKeySize];
      uint8_t mask_seed[kCryptoNoteKeySize];
      ok = ok && cryptonote_hash_to_scalar(label, sizeof(label), point_seed) &&
           cryptonote_scalar_to_point(point_seed, ring[member].dest) &&
           cryptonote_hash_to_scalar(mask_label, sizeof(mask_label), mask_seed) &&
           ringct_commitment(mask_seed, 1000 + member, ring[member].mask);
      offsets[member] = member + 1;
    }
    memcpy(ring[2].dest, our_one_time, kCryptoNoteKeySize);
    memcpy(ring[2].mask, our_commitment, kCryptoNoteKeySize);
    uint8_t one_time_secret[kCryptoNoteKeySize];
    ok = ok && cryptonote_derive_secret_key(derivation, our_output_index,
                                            spend_secret, one_time_secret);
    if (!ok) return false;
    SIGNING_STAGE(102);

    CryptoNoteSpendInput spend = {};
    spend.amount = kInputAmount;
    spend.real_index = 2;
    spend.ring_size = 16;
    memcpy(spend.mask, our_mask, kCryptoNoteKeySize);
    memcpy(spend.commitment, our_commitment, kCryptoNoteKeySize);
    memcpy(spend.spend_secret, one_time_secret, kCryptoNoteKeySize);
    memcpy(spend.ring, ring, sizeof(ring));
    memcpy(spend.key_offsets, offsets, sizeof(offsets));

    CryptoNoteSpendOutput built[2] = {};
    memcpy(built[0].spend_public, recipient_spend_public, kCryptoNoteKeySize);
    memcpy(built[0].view_public, recipient_view_public, kCryptoNoteKeySize);
    built[0].amount = kSendAmount;
    built[0].change = false;
    memcpy(built[1].spend_public, our_spend_public, kCryptoNoteKeySize);
    memcpy(built[1].view_public, our_view_public, kCryptoNoteKeySize);
    built[1].amount = kChangeAmount;
    built[1].change = true;

    uint8_t entropy[kCryptoNoteKeySize];
    CryptoNoteTransaction tx;
    uint8_t tx_secret[kCryptoNoteKeySize];
    uint8_t pseudo_masks[kCryptoNoteMaxTxInputs * kCryptoNoteKeySize];
    const CryptoNoteBpPlusProof proof =
#include "src/generated/MoneroReviewProofTest.inc"
        ;
    ok = cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>("review-fixture"),
                                   14, entropy) &&
         cryptonote_spend_tx_secret(entropy, tx_secret) &&
         cryptonote_build_spend_transaction(&spend, 1, built, 2, kFee, entropy,
                                            &tx, &proof, 1, pseudo_masks) ==
             CryptoNoteTxError::Ok;
    if (!ok) return false;

    // ---- build the wire request ------------------------------------------
    SIGNING_STAGE(103);
    static uint8_t tx_bytes[kCryptoNoteMaxTxBytes];
    size_t tx_size = sizeof(tx_bytes);
    const CryptoNoteTxError serialize_error =
        cryptonote_serialize_transaction(tx, tx_bytes, &tx_size);
    if (serialize_error != CryptoNoteTxError::Ok)
    {
      g_signing_error = static_cast<int>(serialize_error);
      return false;
    }

    size_t offset = 0;
    payload[offset++] = kCryptoNoteSigningPayloadVersion;
    payload[offset++] = static_cast<uint8_t>(tx_size);
    payload[offset++] = static_cast<uint8_t>(tx_size >> 8);
    memcpy(payload + offset, tx_bytes, tx_size);
    offset += tx_size;
    memcpy(payload + offset, tx_secret, kCryptoNoteKeySize);
    offset += kCryptoNoteKeySize;
    payload[offset++] = 1;
    payload[offset++] = 2;
    payload[offset++] = 0;  // no output masks
    const auto put_u16 = [&](uint16_t v) {
      payload[offset++] = static_cast<uint8_t>(v);
      payload[offset++] = static_cast<uint8_t>(v >> 8);
    };
    const auto put_u32 = [&](uint32_t v) {
      for (size_t i = 0; i < 4; ++i) payload[offset++] = static_cast<uint8_t>(v >> (8 * i));
    };
    const auto put_u64 = [&](uint64_t v) {
      for (size_t i = 0; i < 8; ++i) payload[offset++] = static_cast<uint8_t>(v >> (8 * i));
    };
    put_u64(kInputAmount);
    put_u16(2);
    put_u16(16);
    memcpy(payload + offset, original_tx_public, kCryptoNoteKeySize);
    offset += kCryptoNoteKeySize;
    put_u64(our_output_index);
    memcpy(payload + offset, pseudo_masks, kCryptoNoteKeySize);
    offset += kCryptoNoteKeySize;
    put_u32(0);  // subaddress_major (standard address)
    put_u32(0);  // subaddress_minor
    for (size_t member = 0; member < 16; ++member) put_u64(offsets[member]);
    for (size_t member = 0; member < 16; ++member)
    {
      memcpy(payload + offset, ring[member].dest, kCryptoNoteKeySize);
      offset += kCryptoNoteKeySize;
      memcpy(payload + offset, ring[member].mask, kCryptoNoteKeySize);
      offset += kCryptoNoteKeySize;
    }
    const size_t external_flags_offset = offset;
    payload[offset++] = 0x00;  // external
    memcpy(payload + offset, recipient_spend_public, kCryptoNoteKeySize);
    offset += kCryptoNoteKeySize;
    memcpy(payload + offset, recipient_view_public, kCryptoNoteKeySize);
    offset += kCryptoNoteKeySize;
    put_u64(kSendAmount);
    put_u32(0);  // external output: subaddress fields are ignored
    put_u32(0);
    payload[offset++] = 0x01;  // change
    memcpy(payload + offset, our_spend_public, kCryptoNoteKeySize);
    offset += kCryptoNoteKeySize;
    memcpy(payload + offset, our_view_public, kCryptoNoteKeySize);
    offset += kCryptoNoteKeySize;
    put_u64(kChangeAmount);
    put_u32(0);  // change to the standard address
    put_u32(0);

    const CryptoNoteTxError prepared = cryptonote_signing_prepare_with_keys(
        "xmr", payload, offset, view_secret, spend_secret, &state);
    g_signing_error = static_cast<int>(prepared);
    if (prepared != CryptoNoteTxError::Ok) return false;
    if (state.summary.total_input != kInputAmount ||
        state.summary.total_output != kSendAmount + kChangeAmount ||
        state.summary.change != kChangeAmount ||
        state.summary.fee != kFee ||
        !state.summary.decoys_host_supplied ||
        state.input_count != 1 || state.output_count != 2)
      return false;

    // A seed that does not own the change output must not be reviewable.
    {
      static CryptoNoteSigningState rejected;
      const CryptoNoteTxError error =
          cryptonote_signing_prepare("xmr", payload, offset, seed, &rejected);
      if (error == CryptoNoteTxError::Ok) return false;
    }
    // Reserved wire flags must not acquire ambiguous semantics across versions.
    {
      static CryptoNoteSigningState rejected;
      const size_t flags_offset = 3 + tx_size + kCryptoNoteKeySize + 2;
      const uint8_t saved = payload[flags_offset];
      payload[flags_offset] = 0x80;
      const CryptoNoteTxError error = cryptonote_signing_prepare_with_keys(
          "xmr", payload, offset, view_secret, spend_secret, &rejected);
      payload[flags_offset] = saved;
      if (error != CryptoNoteTxError::NonCanonical) return false;
    }
    // Do not display a subaddress prefix for an output built with rG.
    {
      static CryptoNoteSigningState rejected;
      payload[external_flags_offset] = 0x02;
      const CryptoNoteTxError error = cryptonote_signing_prepare_with_keys(
          "xmr", payload, offset, view_secret, spend_secret, &rejected);
      payload[external_flags_offset] = 0;
      if (error != CryptoNoteTxError::Unsupported) return false;
    }
    // A wrong sender secret must not be reviewable.
    {
      static CryptoNoteSigningState rejected;
      uint8_t saved = payload[3 + tx_size];
      payload[3 + tx_size] ^= 0x01;
      const CryptoNoteTxError error = cryptonote_signing_prepare_with_keys(
          "xmr", payload, offset, view_secret, spend_secret, &rejected);
      payload[3 + tx_size] = saved;
      if (error == CryptoNoteTxError::Ok) return false;
    }
    // The fee ceiling applies before any curve work.
    {
      const uint64_t saved = tx.rct.fee;
      tx.rct.fee = HEXWALLET_XMR_MAX_FEE_ATOMIC + 1;
      static uint8_t bad_tx[kCryptoNoteMaxTxBytes];
      size_t bad_size = sizeof(bad_tx);
      if (cryptonote_serialize_transaction(tx, bad_tx, &bad_size) !=
          CryptoNoteTxError::Ok)
        return false;
      tx.rct.fee = saved;
      static uint8_t bad_payload[kCryptoNoteMaxSigningPayload];
      size_t bad_offset = 0;
      bad_payload[bad_offset++] = kCryptoNoteSigningPayloadVersion;
      bad_payload[bad_offset++] = static_cast<uint8_t>(bad_size);
      bad_payload[bad_offset++] = static_cast<uint8_t>(bad_size >> 8);
      memcpy(bad_payload + bad_offset, bad_tx, bad_size);
      bad_offset += bad_size;
      memcpy(bad_payload + bad_offset, payload + 3 + tx_size, offset - (3 + tx_size));
      bad_offset += offset - (3 + tx_size);
      static CryptoNoteSigningState rejected;
      if (cryptonote_signing_prepare_with_keys(
              "xmr", bad_payload, bad_offset, view_secret, spend_secret,
              &rejected) != CryptoNoteTxError::FeePolicy)
        return false;
    }

    // ---- sign and verify every CLSAG --------------------------------------
    static uint8_t signed_tx[kCryptoNoteMaxTxBytes];
    size_t signed_size = sizeof(signed_tx);
    const uint8_t nonce_seed[kCryptoNoteKeySize] = {0x6d, 0x11, 0x9a};
    const CryptoNoteTxError signed_error = cryptonote_signing_sign_with_keys(
        &state, view_secret, spend_secret, nonce_seed, signed_tx,
        &signed_size);
    g_signing_error = static_cast<int>(signed_error);
    if (signed_error != CryptoNoteTxError::Ok) return false;

    CryptoNoteTransaction reparsed;
    if (cryptonote_parse_transaction(signed_tx, signed_size, &reparsed) !=
        CryptoNoteTxError::Ok)
      return false;
    uint8_t message[kCryptoNoteKeySize];
    if (cryptonote_transaction_signing_hash(reparsed, message) !=
        CryptoNoteTxError::Ok)
      return false;
    for (uint16_t index = 0; index < reparsed.input_count; ++index)
    {
      CryptoNoteClsag signature = {};
      const CryptoNoteTxInput &wire = reparsed.inputs[index];
      signature.ring_size = static_cast<uint8_t>(wire.key_offset_count);
      for (uint16_t member = 0; member < wire.key_offset_count; ++member)
        memcpy(signature.s[member], wire.s[member], kCryptoNoteKeySize);
      memcpy(signature.c1, wire.c1, kCryptoNoteKeySize);
      memcpy(signature.I, wire.key_image, kCryptoNoteKeySize);
      memcpy(signature.D, wire.d, kCryptoNoteKeySize);
      if (!cryptonote_clsag_verify(message, ring, 16,
                                   reparsed.rct.pseudo_outs[index], signature))
        return false;
    }

    // ---- subaddress spend path -------------------------------------------
    // b + Hs("SubAddr" || a || major || minor) must produce a one-time key that
    // signs, and the standard spend secret must not.
    {
      SIGNING_STAGE(110);
      uint8_t sub_secret[kCryptoNoteKeySize];
      uint8_t sub_spend[kCryptoNoteKeySize];
      uint8_t sub_view[kCryptoNoteKeySize];
      uint8_t sub_derivation[kCryptoNoteKeySize];
      uint8_t sub_one_time_public[kCryptoNoteKeySize];
      uint8_t sub_one_time_secret[kCryptoNoteKeySize];
      uint8_t wrong_one_time_secret[kCryptoNoteKeySize];
      uint8_t check[kCryptoNoteKeySize];
      bool sub_ok =
          cryptonote_subaddress_keys(spend_secret, view_secret, 0, 1,
                                     sub_secret, sub_spend, sub_view) ==
              WalletError::Ok &&
          cryptonote_generate_key_derivation(sub_view, kSenderTxSecret,
                                             sub_derivation) &&
          cryptonote_derive_public_key(sub_derivation, 0, sub_spend,
                                       sub_one_time_public) &&
          cryptonote_derive_secret_key(sub_derivation, 0, sub_secret,
                                       sub_one_time_secret) &&
          cryptonote_derive_secret_key(sub_derivation, 0, spend_secret,
                                       wrong_one_time_secret) &&
          cryptonote_scalar_to_point(sub_one_time_secret, check) &&
          crypto_constant_time_equal(check, sub_one_time_public,
                                     kCryptoNoteKeySize);
      if (!sub_ok) return false;
      sub_ok = cryptonote_scalar_to_point(wrong_one_time_secret, check) &&
               !crypto_constant_time_equal(check, sub_one_time_public,
                                           kCryptoNoteKeySize);
      if (!sub_ok) return false;

      CryptoNoteRingMember sub_ring[3] = {};
      uint8_t z[kCryptoNoteKeySize];
      uint8_t c_offset[kCryptoNoteKeySize];
      uint8_t z_point[kCryptoNoteKeySize];
      uint8_t c_offset_point[kCryptoNoteKeySize];
      uint8_t ring_seed[2] = {0x31, 0x07};
      SIGNING_STAGE(111);
      sub_ok = cryptonote_hash_to_scalar(ring_seed, sizeof(ring_seed), z) &&
               cryptonote_scalar_to_point(z, z_point) &&
               cryptonote_hash_to_scalar(ring_seed, 1, c_offset) &&
               cryptonote_scalar_to_point(c_offset, c_offset_point) &&
               ed25519_point_add_compressed(z_point, c_offset_point,
                                            sub_ring[2].mask);
      if (!sub_ok) return false;
      memcpy(sub_ring[2].dest, sub_one_time_public, kCryptoNoteKeySize);
      // Two decoys on the curve, distinct from the signer.
      for (size_t member = 0; member < 2 && sub_ok; ++member)
      {
        uint8_t label[2] = {static_cast<uint8_t>(0x40 + member), 0x2b};
        uint8_t scalar[kCryptoNoteKeySize];
        sub_ok = cryptonote_hash_to_scalar(label, sizeof(label), scalar) &&
                 cryptonote_scalar_to_point(scalar, sub_ring[member].dest);
        secure_zero(scalar, sizeof(scalar));
        if (sub_ok)
        {
          uint8_t mask_scalar[kCryptoNoteKeySize];
          sub_ok = cryptonote_hash_to_scalar(label, sizeof(label),
                                             mask_scalar) &&
                   cryptonote_scalar_to_point(mask_scalar,
                                              sub_ring[member].mask);
          secure_zero(mask_scalar, sizeof(mask_scalar));
        }
      }
      if (!sub_ok) return false;

      SIGNING_STAGE(112);
      uint8_t sub_message[kCryptoNoteKeySize];
      uint8_t s_nonces[3 * kCryptoNoteKeySize];
      uint8_t sign_nonce[kCryptoNoteKeySize] = {0x9d, 0x41};
      memset(s_nonces, 0x5a, sizeof(s_nonces));
      CryptoNoteClsag sub_signature = {};
      sub_ok = cryptonote_hash_to_scalar(ring_seed, 1, sub_message);
      if (!sub_ok) return false;
      SIGNING_STAGE(120);
      sub_ok = cryptonote_clsag_sign(sub_message, sub_ring, 3, 2,
                                     sub_one_time_secret, z, sign_nonce,
                                     s_nonces, c_offset_point, &sub_signature);
      if (!sub_ok) return false;
      SIGNING_STAGE(121);
      sub_ok = cryptonote_clsag_verify(sub_message, sub_ring, 3, c_offset_point,
                                       sub_signature);
      if (!sub_ok) return false;
      // The master spend secret must not be able to sign the subaddress output.
      SIGNING_STAGE(113);
      CryptoNoteClsag wrong_signature = {};
      if (cryptonote_clsag_sign(sub_message, sub_ring, 3, 2,
                                wrong_one_time_secret, z, sign_nonce, s_nonces,
                                c_offset_point, &wrong_signature))
        return false;

      secure_zero(sub_secret, sizeof(sub_secret));
      secure_zero(sub_spend, sizeof(sub_spend));
      secure_zero(sub_view, sizeof(sub_view));
      secure_zero(sub_derivation, sizeof(sub_derivation));
      secure_zero(sub_one_time_public, sizeof(sub_one_time_public));
      secure_zero(sub_one_time_secret, sizeof(sub_one_time_secret));
      secure_zero(wrong_one_time_secret, sizeof(wrong_one_time_secret));
      secure_zero(check, sizeof(check));
      secure_zero(z, sizeof(z));
      secure_zero(c_offset, sizeof(c_offset));
      secure_zero(z_point, sizeof(z_point));
      secure_zero(c_offset_point, sizeof(c_offset_point));
      secure_zero(sub_ring, sizeof(sub_ring));
      secure_zero(sub_message, sizeof(sub_message));
      secure_zero(s_nonces, sizeof(s_nonces));
      secure_zero(sign_nonce, sizeof(sign_nonce));
      secure_zero(&sub_signature, sizeof(sub_signature));
      secure_zero(&wrong_signature, sizeof(wrong_signature));
    }
    return true;
  }

} // namespace hexwallet
