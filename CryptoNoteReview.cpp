#include "CryptoNoteReview.h"

#include <string.h>

#include "CryptoExtended.h"
#include "CryptoNoteAddress.h"
#include "CryptoNoteAmounts.h"
#include "CryptoNoteBulletproofPlus.h"
#include "CryptoNoteSpend.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"
#include "WalletConfig.h"

namespace hexwallet
{
  namespace
  {
    const CryptoNoteReviewPolicy kPolicies[] = {
        {CryptoNoteReviewNetwork::MoneroMainnet, HEXWALLET_XMR_MAX_FEE_ATOMIC, 16, kCryptoNoteMaxTxInputs,
         kCryptoNoteMaxTxOutputs},
        {CryptoNoteReviewNetwork::MasariMainnet, HEXWALLET_MSR_MAX_FEE_ATOMIC, 16, kCryptoNoteMaxTxInputs,
         kCryptoNoteMaxTxOutputs},
    };
  } // namespace

  const CryptoNoteReviewPolicy *cryptonote_review_policy(const char *network_id)
  {
    if (network_id == nullptr)
      return nullptr;
    if (strcmp(network_id, "xmr") == 0)
      return &kPolicies[0];
    // MSR was withdrawn from product support; the enum policy remains solely
    // for isolated legacy regression tests, never host protocol selection.
    return nullptr;
  }

  const CryptoNoteReviewPolicy *cryptonote_review_policy(
      CryptoNoteReviewNetwork network)
  {
    for (const CryptoNoteReviewPolicy &policy : kPolicies)
      if (policy.network == network)
        return &policy;
    return nullptr;
  }

  CryptoNoteTxError cryptonote_review_fee_policy(CryptoNoteReviewNetwork network,
                                                 uint64_t fee)
  {
    const CryptoNoteReviewPolicy *policy = cryptonote_review_policy(network);
    if (policy == nullptr)
      return CryptoNoteTxError::Unsupported;
    return fee <= policy->max_fee_atomic ? CryptoNoteTxError::Ok
                                         : CryptoNoteTxError::FeePolicy;
  }

  namespace
  {
    int g_review_stage = 0;
    int g_review_error = -1;
  }
#define REVIEW_STAGE(n)   \
  do                      \
  {                       \
    g_review_stage = (n); \
  } while (0)

  namespace
  {
    constexpr uint8_t kExtraTagPublicKey = 0x01;
    constexpr size_t kOutputsPerProof = 16;

    bool log2_ceil(size_t count, size_t *out)
    {
      if (out == nullptr || count == 0)
        return false;
      size_t log = 0;
      while ((static_cast<size_t>(1) << log) < count)
      {
        ++log;
        if (log > 5)
          return false;
      }
      *out = log;
      return true;
    }

    bool equals(const uint8_t *left, const uint8_t *right)
    {
      return crypto_constant_time_equal(left, right, kCryptoNoteKeySize);
    }
  } // namespace

  bool cryptonote_tx_extra_public_key(const CryptoNoteTransaction &tx,
                                      uint8_t out[kCryptoNoteKeySize])
  {
    if (tx.extra_size > sizeof(tx.extra))
      return false;
    return cryptonote_review_extra_public_key(tx.extra, tx.extra_size, out);
  }

  bool cryptonote_review_extra_public_key(const uint8_t *extra, size_t size,
                                          uint8_t out[kCryptoNoteKeySize])
  {
    if (out == nullptr)
      return false;
    memset(out, 0, kCryptoNoteKeySize);
    if (extra == nullptr || size < 1 + kCryptoNoteKeySize ||
        extra[0] != kExtraTagPublicKey)
      return false;
    size_t offset = 1 + kCryptoNoteKeySize;
    bool nonce_seen = false;
    while (offset < size)
    {
      const uint8_t tag = extra[offset++];
      if (tag == 0)
      {
        if (size - offset >= 255)
          return false;
        while (offset < size)
          if (extra[offset++] != 0)
            return false;
        break;
      }
      if (tag != 2 || nonce_seen || offset == size)
        return false;
      nonce_seen = true;
      const size_t length = extra[offset++];
      if (length > size - offset)
        return false;
      offset += length;
    }
    memcpy(out, extra + 1, kCryptoNoteKeySize);
    return true;
  }

  namespace
  {
    CryptoNoteTxError review_impl(
        const CryptoNoteTransaction &tx,
        const uint8_t view_secret[kCryptoNoteKeySize],
        const uint8_t spend_secret[kCryptoNoteKeySize],
        const uint8_t tx_secret[kCryptoNoteKeySize],
        const CryptoNoteReviewInput *inputs, size_t input_count,
        const CryptoNoteReviewOutput *outputs, size_t output_count,
        CryptoNoteReviewResult *result)
    {
      REVIEW_STAGE(5);
      if (view_secret == nullptr || spend_secret == nullptr || tx_secret == nullptr ||
          inputs == nullptr || outputs == nullptr || result == nullptr)
        return CryptoNoteTxError::InvalidArgument;
      REVIEW_STAGE(6);
      if (input_count == 0 || input_count > kCryptoNoteMaxTxInputs)
        return CryptoNoteTxError::TooManyItems;
      if (output_count == 0 || output_count > kCryptoNoteMaxTxOutputs)
        return CryptoNoteTxError::TooManyItems;
      REVIEW_STAGE(7);
      if (tx.version != 2 || tx.rct.type != 6)
        return CryptoNoteTxError::Unsupported;
      const CryptoNoteReviewPolicy *policy =
          cryptonote_review_policy(CryptoNoteReviewNetwork::MoneroMainnet);
      if (policy == nullptr)
        return CryptoNoteTxError::Unsupported;
      const CryptoNoteTxError fee_policy = cryptonote_review_fee_policy(
          CryptoNoteReviewNetwork::MoneroMainnet, tx.rct.fee);
      if (fee_policy != CryptoNoteTxError::Ok)
        return fee_policy;
      REVIEW_STAGE(8);
      if (tx.input_count != input_count || tx.output_count != output_count)
        return CryptoNoteTxError::InvalidArgument;
      if (input_count > policy->max_inputs || output_count > policy->max_outputs)
        return CryptoNoteTxError::TooManyItems;
      REVIEW_STAGE(9);
      if (tx.rct.ring_size != policy->ring_size)
        return CryptoNoteTxError::InvalidArgument;
      // The current output derivation uses a single R = rG. Subaddress
      // destinations require R = rD / per-output additional transaction keys;
      // ownership checks alone cannot make such an output discoverable.
      for (size_t index = 0; index < output_count; ++index)
        if (outputs[index].address_type != 0 || outputs[index].subaddress_major != 0 ||
            outputs[index].subaddress_minor != 0)
          return CryptoNoteTxError::Unsupported;

      memset(result, 0, sizeof(*result));
      REVIEW_STAGE(10);

      // ---- the supplied tx secret must actually be this transaction's key ----
      uint8_t tx_public[kCryptoNoteKeySize];
      uint8_t derived_public[kCryptoNoteKeySize];
      REVIEW_STAGE(11);
      if (!cryptonote_tx_extra_public_key(tx, tx_public))
        return CryptoNoteTxError::InvalidArgument;
      if (!cryptonote_scalar_to_point(tx_secret, derived_public))
        return CryptoNoteTxError::CryptoFailure;
      const bool tx_key_matches = equals(tx_public, derived_public);
      secure_zero(derived_public, sizeof(derived_public));
      if (!tx_key_matches)
        return CryptoNoteTxError::InvalidArgument;
      REVIEW_STAGE(12);

      uint8_t our_spend_public[kCryptoNoteKeySize];
      uint8_t our_view_public[kCryptoNoteKeySize];
      if (!cryptonote_scalar_to_point(spend_secret, our_spend_public) ||
          !cryptonote_scalar_to_point(view_secret, our_view_public))
        return CryptoNoteTxError::CryptoFailure;

      // Change may go to the standard address or to one of our own
      // subaddresses. The host names the subaddress; the device re-derives the
      // key pair and compares, so a foreign key can never be labelled change.
      auto owned_change = [&](const CryptoNoteReviewOutput &declared)
      {
        if (declared.subaddress_major == 0 && declared.subaddress_minor == 0)
          return equals(declared.spend_public, our_spend_public) &&
                 equals(declared.view_public, our_view_public);
        uint8_t sub_spend_secret[kCryptoNoteKeySize];
        uint8_t sub_spend_public[kCryptoNoteKeySize];
        uint8_t sub_view_public[kCryptoNoteKeySize];
        const bool derived =
            cryptonote_subaddress_keys(spend_secret, view_secret,
                                       declared.subaddress_major,
                                       declared.subaddress_minor, sub_spend_secret,
                                       sub_spend_public, sub_view_public) ==
            WalletError::Ok;
        const bool match =
            derived && equals(declared.spend_public, sub_spend_public) &&
            equals(declared.view_public, sub_view_public);
        secure_zero(sub_spend_secret, sizeof(sub_spend_secret));
        secure_zero(sub_spend_public, sizeof(sub_spend_public));
        secure_zero(sub_view_public, sizeof(sub_view_public));
        return match;
      };

      // ---- outputs: every byte recomputed from the claimed amount -----------
      const uint8_t kOne[kCryptoNoteKeySize] = {1};
      // 8^-1 mod l: CLSAG's D is (z * key_image_generator) / 8.
      const uint8_t kInvEight[kCryptoNoteKeySize] = {
          0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d,
          0xb3, 0x9d, 0xd3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06};
      uint64_t output_total = 0;
      uint64_t change_total = 0;

      for (size_t index = 0; index < output_count; ++index)
      {
        const CryptoNoteReviewOutput &declared = outputs[index];
        const CryptoNoteTxOutput &on_wire = tx.outputs[index];
        if (UINT64_MAX - output_total < declared.amount)
          return CryptoNoteTxError::InvalidAmount;

        if (declared.change)
        {
          if (!owned_change(declared))
            return CryptoNoteTxError::InvalidArgument;
          if (UINT64_MAX - change_total < declared.amount)
            return CryptoNoteTxError::InvalidAmount;
          change_total += declared.amount;
        }

        uint8_t derivation[kCryptoNoteKeySize];
        uint8_t amount_key[kCryptoNoteKeySize];
        uint8_t expected_public[kCryptoNoteKeySize];
        uint8_t expected_commitment[kCryptoNoteKeySize];
        uint8_t expected_amount[8];
        uint8_t expected_view_tag = 0;

        // encode emits both the 8-byte ciphertext and the commitment it committed
        // to, which is exactly the pair the wire carries.
        const bool step_ok =
            cryptonote_generate_key_derivation(declared.view_public, tx_secret, derivation) &&
            cryptonote_derivation_to_scalar(derivation, index, amount_key) &&
            cryptonote_derive_public_key(derivation, index, declared.spend_public, expected_public) &&
            ringct_encode_amount(RingCtAmountEncoding::Compact, amount_key, declared.amount,
                                 nullptr, expected_amount, sizeof(expected_amount),
                                 expected_commitment) &&
            cryptonote_derive_view_tag(derivation, static_cast<uint64_t>(index), &expected_view_tag);
        if (!step_ok)
        {
          secure_zero(derivation, sizeof(derivation));
          secure_zero(amount_key, sizeof(amount_key));
          return CryptoNoteTxError::CryptoFailure;
        }

        const bool matches =
            equals(expected_public, on_wire.public_key) &&
            equals(expected_commitment, on_wire.commitment) &&
            crypto_constant_time_equal(expected_amount, on_wire.ecdh_amount, sizeof(expected_amount)) &&
            expected_view_tag == on_wire.view_tag &&
            on_wire.tagged;
        secure_zero(derivation, sizeof(derivation));
        secure_zero(amount_key, sizeof(amount_key));
        if (!matches)
          return CryptoNoteTxError::InvalidAmount;
        REVIEW_STAGE(14 + static_cast<int>(index));
        output_total += declared.amount;
      }

      // ---- range proofs ----------------------------------------------------
      size_t expected_proofs = (output_count + kOutputsPerProof - 1) / kOutputsPerProof;
      if (expected_proofs == 0 || expected_proofs > kCryptoNoteMaxBpProofs)
        return CryptoNoteTxError::TooManyItems;
      if (tx.rct.proof_count != expected_proofs)
        return CryptoNoteTxError::InvalidArgument;
      REVIEW_STAGE(20);

      uint8_t commitments[kOutputsPerProof * kCryptoNoteKeySize];
      for (size_t proof_index = 0; proof_index < expected_proofs; ++proof_index)
      {
        const size_t first = proof_index * kOutputsPerProof;
        const size_t count = (output_count - first) < kOutputsPerProof ? (output_count - first) : kOutputsPerProof;
        size_t log = 0;
        if (!log2_ceil(count, &log))
          return CryptoNoteTxError::TooManyItems;

        const CryptoNoteBpPlusProof &proof = tx.rct.proofs[proof_index];
        if (proof.l_count != 6 + log || proof.r_count != proof.l_count)
          return CryptoNoteTxError::InvalidArgument;

        for (size_t index = 0; index < count; ++index)
        {
          if (!bulletproof_plus_commitment_to_view(tx.outputs[first + index].commitment,
                                                   commitments + index * kCryptoNoteKeySize))
            return CryptoNoteTxError::CryptoFailure;
        }

        BulletproofPlusView view = {};
        view.v = commitments;
        view.commitment_count = count;
        view.a = proof.a;
        view.a1 = proof.a1;
        view.b = proof.b;
        view.r1 = proof.r1;
        view.s1 = proof.s1;
        view.d1 = proof.d1;
        view.l = proof.l[0];
        view.r = proof.r[0];
        view.rounds = proof.l_count;
        if (!bulletproof_plus_verify(view))
          return CryptoNoteTxError::InvalidAmount;
      }

      // ---- value conservation ---------------------------------------------
      REVIEW_STAGE(21);
      if (!cryptonote_transaction_balance_ok(tx))
        return CryptoNoteTxError::InvalidAmount;
      REVIEW_STAGE(22);

      // ---- inputs ----------------------------------------------------------
      CryptoNoteRingMember ring[kCryptoNoteMaxRingSize];
      uint64_t input_total = 0;
      uint8_t seen_key_images[kCryptoNoteMaxTxInputs][kCryptoNoteKeySize];
      memset(seen_key_images, 0, sizeof(seen_key_images));

      for (size_t index = 0; index < input_count; ++index)
      {
        const CryptoNoteReviewInput &source = inputs[index];
        const CryptoNoteTxInput &on_wire = tx.inputs[index];
        if (source.ring == nullptr || source.key_offsets == nullptr)
        {
          secure_zero(ring, sizeof(ring));
          return CryptoNoteTxError::InvalidArgument;
        }
        if (source.ring_size != policy->ring_size ||
            source.real_index >= source.ring_size)
        {
          secure_zero(ring, sizeof(ring));
          return CryptoNoteTxError::InvalidArgument;
        }
        if (on_wire.key_offset_count != source.ring_size)
        {
          secure_zero(ring, sizeof(ring));
          return CryptoNoteTxError::InvalidArgument;
        }
        {
          uint64_t absolute = 0;
          for (uint16_t member = 0; member < source.ring_size; ++member)
          {
            if (member != 0 &&
                (source.key_offsets[member] == 0 ||
                 UINT64_MAX - absolute < source.key_offsets[member]))
            {
              secure_zero(ring, sizeof(ring));
              return CryptoNoteTxError::InvalidArgument;
            }
            absolute += source.key_offsets[member];
            if (on_wire.key_offsets[member] != source.key_offsets[member])
            {
              secure_zero(ring, sizeof(ring));
              return CryptoNoteTxError::InvalidArgument;
            }
          }
        }
        if (UINT64_MAX - input_total < source.amount)
        {
          secure_zero(ring, sizeof(ring));
          return CryptoNoteTxError::InvalidAmount;
        }
        input_total += source.amount;

        memcpy(ring, source.ring, sizeof(CryptoNoteRingMember) * source.ring_size);

        // A ring must never repeat a member, and no two inputs may spend the
        // same output. Both are cheap, local, and reject malformed rings before
        // any curve work.
        for (uint16_t left = 0; left < source.ring_size; ++left)
        {
          for (uint16_t right = static_cast<uint16_t>(left + 1);
               right < source.ring_size; ++right)
          {
            if (equals(ring[left].dest, ring[right].dest))
            {
              secure_zero(ring, sizeof(ring));
              return CryptoNoteTxError::InvalidArgument;
            }
          }
        }
        for (size_t previous = 0; previous < index; ++previous)
        {
          if (equals(seen_key_images[previous], on_wire.key_image))
          {
            secure_zero(ring, sizeof(ring));
            return CryptoNoteTxError::InvalidArgument;
          }
        }
        memcpy(seen_key_images[index], on_wire.key_image, kCryptoNoteKeySize);

        // The input may belong to the standard address or to a subaddress.
        uint8_t input_spend_secret[kCryptoNoteKeySize];
        uint8_t input_spend_public[kCryptoNoteKeySize];
        if (source.subaddress_major == 0 && source.subaddress_minor == 0)
        {
          memcpy(input_spend_secret, spend_secret, kCryptoNoteKeySize);
          memcpy(input_spend_public, our_spend_public, kCryptoNoteKeySize);
        }
        else
        {
          uint8_t sub_view_public[kCryptoNoteKeySize];
          const bool derived =
              cryptonote_subaddress_keys(spend_secret, view_secret,
                                         source.subaddress_major,
                                         source.subaddress_minor,
                                         input_spend_secret, input_spend_public,
                                         sub_view_public) == WalletError::Ok;
          secure_zero(sub_view_public, sizeof(sub_view_public));
          if (!derived)
          {
            secure_zero(input_spend_secret, sizeof(input_spend_secret));
            secure_zero(ring, sizeof(ring));
            return CryptoNoteTxError::CryptoFailure;
          }
        }

        uint8_t derivation[kCryptoNoteKeySize];
        uint8_t amount_key[kCryptoNoteKeySize];
        uint8_t mask[kCryptoNoteKeySize];
        uint8_t expected_commitment[kCryptoNoteKeySize];
        uint8_t expected_public[kCryptoNoteKeySize];
        uint8_t expected_image[kCryptoNoteKeySize];
        uint8_t one_time_secret[kCryptoNoteKeySize];
        uint8_t expected_pseudo[kCryptoNoteKeySize];
        uint8_t expected_d[kCryptoNoteKeySize];
        bool ok =
            cryptonote_generate_key_derivation(source.original_tx_public, view_secret, derivation) &&
            cryptonote_derivation_to_scalar(derivation, source.output_index, amount_key) &&
            ringct_commitment_mask(amount_key, mask) &&
            ringct_commitment(mask, source.amount, expected_commitment) &&
            cryptonote_derive_public_key(derivation, source.output_index, input_spend_public,
                                         expected_public) &&
            cryptonote_derive_secret_key(derivation, source.output_index, input_spend_secret,
                                         one_time_secret);
        secure_zero(input_spend_secret, sizeof(input_spend_secret));
        secure_zero(input_spend_public, sizeof(input_spend_public));
        ok = ok && equals(expected_public, ring[source.real_index].dest) &&
             equals(expected_commitment, ring[source.real_index].mask);
        ok = ok && cryptonote_generate_key_image(ring[source.real_index].dest, one_time_secret, expected_image) &&
             equals(expected_image, on_wire.key_image);
        ok = ok && ringct_commitment(source.pseudo_out_mask, source.amount, expected_pseudo) &&
             equals(expected_pseudo, tx.rct.pseudo_outs[index]);

        if (ok)
        {
          ed25519_scalar_mulsub(result->signing_mask[index], kOne, source.pseudo_out_mask, mask);
        }
        else
        {
          secure_zero(result->signing_mask[index], kCryptoNoteKeySize);
        }
        // CLSAG publishes D = z*Hp(P)/8 in the prunable signature. It is not
        // part of the message hash, so a lying host could otherwise make the
        // device sign a transaction whose D field it chose. Bind it here.
        if (ok)
        {
          uint8_t generator[kCryptoNoteKeySize];
          uint8_t d_full[kCryptoNoteKeySize];
          ok = cryptonote_key_image_generator(ring[source.real_index].dest, generator) &&
               ed25519_point_mul_compressed(generator, result->signing_mask[index], d_full) &&
               ed25519_point_mul_compressed(d_full, kInvEight, expected_d) &&
               equals(expected_d, on_wire.d);
          secure_zero(generator, sizeof(generator));
          secure_zero(d_full, sizeof(d_full));
        }

        secure_zero(derivation, sizeof(derivation));
        secure_zero(amount_key, sizeof(amount_key));
        secure_zero(mask, sizeof(mask));
        secure_zero(expected_commitment, sizeof(expected_commitment));
        secure_zero(expected_public, sizeof(expected_public));
        secure_zero(expected_image, sizeof(expected_image));
        secure_zero(one_time_secret, sizeof(one_time_secret));
        secure_zero(expected_pseudo, sizeof(expected_pseudo));
        secure_zero(expected_d, sizeof(expected_d));
        if (!ok)
        {
          REVIEW_STAGE(30 + static_cast<int>(index));
          secure_zero(ring, sizeof(ring));
          memset(result, 0, sizeof(*result));
          return CryptoNoteTxError::InvalidAmount;
        }
      }
      // The blinding factors cancel through the pseudo outputs, not through the
      // ring entries: Sum(pseudoOut) == Sum(outPk) + fee*H (checked above) is what
      // ties sum(c_out) to the output masks. The ring's own blinding factors c_a
      // are unrelated scalars and must not be compared with them.

      // ---- money check -----------------------------------------------------
      REVIEW_STAGE(40);
      if (UINT64_MAX - output_total < tx.rct.fee ||
          input_total != output_total + tx.rct.fee)
        return CryptoNoteTxError::InvalidAmount;
      REVIEW_STAGE(41);

      result->summary.total_input = input_total;
      result->summary.total_output = output_total;
      result->summary.change = change_total;
      result->summary.fee = tx.rct.fee;
      result->summary.output_count = static_cast<uint8_t>(output_count);
      result->summary.input_count = static_cast<uint8_t>(input_count);
      result->summary.decoys_host_supplied = true;
      return CryptoNoteTxError::Ok;
    }
  } // namespace
  CryptoNoteTxError cryptonote_review_transaction(
      const CryptoNoteTransaction &tx,
      const uint8_t view_secret[kCryptoNoteKeySize],
      const uint8_t spend_secret[kCryptoNoteKeySize],
      const uint8_t tx_secret[kCryptoNoteKeySize],
      const CryptoNoteReviewInput *inputs, size_t input_count,
      const CryptoNoteReviewOutput *outputs, size_t output_count,
      CryptoNoteReviewResult *result)
  {
    if (result == nullptr)
      return CryptoNoteTxError::InvalidArgument;
    secure_zero(result, sizeof(*result));
    const CryptoNoteTxError error = review_impl(tx, view_secret, spend_secret,
                                                tx_secret, inputs, input_count, outputs, output_count, result);
    if (error != CryptoNoteTxError::Ok)
      secure_zero(result, sizeof(*result));
    return error;
  }

  namespace
  {
    const uint8_t kViewSecret[kCryptoNoteKeySize] = {0x33, 0x77, 0x01, 0xe8};
    const uint8_t kSpendSecret[kCryptoNoteKeySize] = {0x5a, 0x11, 0x9c, 0x42};
    const uint8_t kSenderTxSecret[kCryptoNoteKeySize] = {0x0b, 0xad, 0xf0, 0x0d};
    const uint8_t kRecipientSpendSecret[kCryptoNoteKeySize] = {0x91, 0x02};
    const uint8_t kRecipientViewSecret[kCryptoNoteKeySize] = {0x47, 0xee};

    constexpr uint64_t kInputAmount = 900000000000ULL;
    constexpr uint64_t kSendAmount = 400000000000ULL;
    constexpr uint64_t kChangeAmount = 400000000000ULL;
    constexpr uint64_t kFee = 100000000000ULL;

    struct Fixture
    {
      CryptoNoteTransaction tx;
      CryptoNoteReviewInput input;
      CryptoNoteReviewOutput outputs[2];
      uint8_t ring[kCryptoNoteMaxRingSize * sizeof(CryptoNoteRingMember)];
      uint64_t offsets[kCryptoNoteMaxRingSize];
      uint8_t tx_secret[kCryptoNoteKeySize];
    };

    static Fixture g_fixture;
    static uint8_t g_pseudo_masks[kCryptoNoteMaxTxInputs * kCryptoNoteKeySize];

    bool build_fixture()
    {
      Fixture &f = g_fixture;
      memset(&f, 0, sizeof(f));

      uint8_t our_spend_public[kCryptoNoteKeySize];
      uint8_t our_view_public[kCryptoNoteKeySize];
      uint8_t recipient_spend_public[kCryptoNoteKeySize];
      uint8_t recipient_view_public[kCryptoNoteKeySize];
      if (!cryptonote_scalar_to_point(kSpendSecret, our_spend_public) ||
          !cryptonote_scalar_to_point(kViewSecret, our_view_public) ||
          !cryptonote_scalar_to_point(kRecipientSpendSecret, recipient_spend_public) ||
          !cryptonote_scalar_to_point(kRecipientViewSecret, recipient_view_public))
        return false;

      uint8_t original_tx_public[kCryptoNoteKeySize];
      uint8_t derivation[kCryptoNoteKeySize];
      uint8_t amount_key[kCryptoNoteKeySize];
      uint8_t our_mask[kCryptoNoteKeySize];
      uint8_t our_commitment[kCryptoNoteKeySize];
      uint8_t our_one_time[kCryptoNoteKeySize];
      const uint64_t our_output_index = 0;
      if (!cryptonote_scalar_to_point(kSenderTxSecret, original_tx_public) ||
          !cryptonote_generate_key_derivation(our_view_public, kSenderTxSecret, derivation) ||
          !cryptonote_derivation_to_scalar(derivation, our_output_index, amount_key) ||
          !ringct_commitment_mask(amount_key, our_mask) ||
          !ringct_commitment(our_mask, kInputAmount, our_commitment) ||
          !cryptonote_derive_public_key(derivation, our_output_index, our_spend_public,
                                        our_one_time))
        return false;

      CryptoNoteRingMember *ring = reinterpret_cast<CryptoNoteRingMember *>(f.ring);
      for (uint16_t member = 0; member < 16; ++member)
      {
        uint8_t seed[kCryptoNoteKeySize];
        uint8_t label[2] = {static_cast<uint8_t>(member), 0x5a};
        uint8_t mask_seed[kCryptoNoteKeySize];
        uint8_t mask_label[2] = {static_cast<uint8_t>(member), 0x6b};
        if (!cryptonote_hash_to_scalar(label, sizeof(label), seed) ||
            !cryptonote_scalar_to_point(seed, ring[member].dest) ||
            !cryptonote_hash_to_scalar(mask_label, sizeof(mask_label), mask_seed) ||
            !ringct_commitment(mask_seed, 1000 + member, ring[member].mask))
          return false;
        f.offsets[member] = member + 1;
      }
      memcpy(ring[2].dest, our_one_time, kCryptoNoteKeySize);
      memcpy(ring[2].mask, our_commitment, kCryptoNoteKeySize);

      uint8_t one_time_secret[kCryptoNoteKeySize];
      if (!cryptonote_derive_secret_key(derivation, our_output_index, kSpendSecret,
                                        one_time_secret))
        return false;

      CryptoNoteSpendInput spend = {};
      spend.amount = kInputAmount;
      spend.real_index = 2;
      spend.ring_size = 16;
      memcpy(spend.mask, our_mask, kCryptoNoteKeySize);
      memcpy(spend.commitment, our_commitment, kCryptoNoteKeySize);
      memcpy(spend.spend_secret, one_time_secret, kCryptoNoteKeySize);
      memcpy(spend.ring, ring, sizeof(CryptoNoteRingMember) * 16);
      memcpy(spend.key_offsets, f.offsets, sizeof(uint64_t) * 16);

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
      if (!cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>("review-fixture"), 14,
                                     entropy) ||
          !cryptonote_spend_tx_secret(entropy, f.tx_secret))
        return false;
      const CryptoNoteBpPlusProof proof =
#include "src/generated/MoneroReviewProofTest.inc"
          ;

      if (cryptonote_build_spend_transaction(&spend, 1, built, 2, kFee, entropy, &f.tx, &proof,
                                             1, g_pseudo_masks) != CryptoNoteTxError::Ok)
        return false;

      f.input.amount = kInputAmount;
      f.input.real_index = 2;
      f.input.ring_size = 16;
      memcpy(f.input.original_tx_public, original_tx_public, kCryptoNoteKeySize);
      f.input.output_index = our_output_index;
      f.input.ring = reinterpret_cast<CryptoNoteRingMember *>(f.ring);
      f.input.key_offsets = f.offsets;
      memcpy(f.input.pseudo_out_mask, g_pseudo_masks, kCryptoNoteKeySize);

      memset(f.outputs, 0, sizeof(f.outputs));
      memcpy(f.outputs[0].spend_public, recipient_spend_public, kCryptoNoteKeySize);
      memcpy(f.outputs[0].view_public, recipient_view_public, kCryptoNoteKeySize);
      f.outputs[0].amount = kSendAmount;
      f.outputs[0].change = false;
      memcpy(f.outputs[1].spend_public, our_spend_public, kCryptoNoteKeySize);
      memcpy(f.outputs[1].view_public, our_view_public, kCryptoNoteKeySize);
      f.outputs[1].amount = kChangeAmount;
      f.outputs[1].change = true;

      secure_zero(derivation, sizeof(derivation));
      secure_zero(amount_key, sizeof(amount_key));
      return true;
    }

    CryptoNoteTxError review_fixture(CryptoNoteReviewResult *result)
    {
      Fixture &f = g_fixture;
      return cryptonote_review_transaction(f.tx, kViewSecret, kSpendSecret, f.tx_secret,
                                           &f.input, 1, f.outputs, 2, result);
    }
  } // namespace

  int cryptonote_review_last_stage() { return g_review_stage; }

  int cryptonote_review_last_error() { return g_review_error; }

  bool run_cryptonote_review_self_tests()
  {
    // Extra parsing must examine the complete field, not return after finding
    // the first key and silently accept another key that changes scanning.
    {
      uint8_t extra[300] = {1, 1};
      uint8_t key[kCryptoNoteKeySize];
      if (!cryptonote_review_extra_public_key(extra, 33, key) || key[0] != 1)
        return false;
      extra[33] = 1;
      if (cryptonote_review_extra_public_key(extra, 66, key))
        return false;
      for (uint8_t value : key)
        if (value != 0)
          return false;
      extra[33] = 4; // unsupported additional transaction public keys
      if (cryptonote_review_extra_public_key(extra, 34, key))
        return false;
      extra[33] = 2;
      if (cryptonote_review_extra_public_key(extra, 34, key))
        return false;
      extra[34] = 16;
      if (cryptonote_review_extra_public_key(extra, 50, key) ||
          !cryptonote_review_extra_public_key(extra, 51, key))
        return false;
      extra[51] = 2;
      extra[52] = 0; // duplicate nonce
      if (cryptonote_review_extra_public_key(extra, 53, key))
        return false;
      memset(extra + 33, 0, sizeof(extra) - 33);
      if (!cryptonote_review_extra_public_key(extra, 288, key) ||
          cryptonote_review_extra_public_key(extra, 289, key))
        return false;
      extra[34] = 1; // nonzero bytes after padding
      if (cryptonote_review_extra_public_key(extra, 35, key))
        return false;
    }
    if (cryptonote_review_fee_policy(CryptoNoteReviewNetwork::MoneroMainnet,
                                     HEXWALLET_XMR_MAX_FEE_ATOMIC) != CryptoNoteTxError::Ok ||
        cryptonote_review_fee_policy(CryptoNoteReviewNetwork::MoneroMainnet,
                                     HEXWALLET_XMR_MAX_FEE_ATOMIC + 1) != CryptoNoteTxError::FeePolicy ||
        cryptonote_review_fee_policy(CryptoNoteReviewNetwork::MasariMainnet,
                                     HEXWALLET_MSR_MAX_FEE_ATOMIC) != CryptoNoteTxError::Ok ||
        cryptonote_review_fee_policy(CryptoNoteReviewNetwork::MasariMainnet,
                                     HEXWALLET_MSR_MAX_FEE_ATOMIC + 1) != CryptoNoteTxError::FeePolicy)
      return false;
    CryptoNoteReviewResult result = {};

    // ---- the honest transaction must be accepted -------------------------
    REVIEW_STAGE(1);
    if (!build_fixture())
    {
      g_review_error = 100;
      return false;
    }
    REVIEW_STAGE(3);
    g_review_error = static_cast<int>(review_fixture(&result));
    if (g_review_error != 0)
      return false;
    if (result.summary.total_input != kInputAmount)
      return false;
    if (result.summary.total_output != kSendAmount + kChangeAmount)
      return false;
    if (result.summary.change != kChangeAmount)
      return false;
    if (result.summary.fee != kFee)
      return false;
    if (result.summary.input_count != 1 || result.summary.output_count != 2)
      return false;
    {
      uint8_t derivation[kCryptoNoteKeySize];
      uint8_t one_time_secret[kCryptoNoteKeySize];
      uint8_t expected[kCryptoNoteKeySize];
      if (!cryptonote_generate_key_derivation(g_fixture.input.original_tx_public, kViewSecret,
                                              derivation) ||
          !cryptonote_derive_secret_key(derivation, g_fixture.input.output_index, kSpendSecret,
                                        one_time_secret) ||
          !cryptonote_generate_key_image(g_fixture.input.ring[2].dest, one_time_secret, expected))
        return false;
      secure_zero(one_time_secret, sizeof(one_time_secret));
      secure_zero(derivation, sizeof(derivation));
      if (!crypto_constant_time_equal(expected, g_fixture.tx.inputs[0].key_image,
                                      kCryptoNoteKeySize))
        return false;
    }

    // ---- a lying host is rejected on every bound field -------------------
    Fixture &f = g_fixture;

    f.outputs[0].address_type = 1;
    if (review_fixture(&result) != CryptoNoteTxError::Unsupported)
      return false;
    f.outputs[0].address_type = 0;
    f.outputs[1].subaddress_minor = 1;
    if (review_fixture(&result) != CryptoNoteTxError::Unsupported)
      return false;
    f.outputs[1].subaddress_minor = 0;

    // Policy failure must clear previously valid signing masks and summary.
    f.tx.rct.fee = HEXWALLET_XMR_MAX_FEE_ATOMIC + 1;
    memset(&result, 0xff, sizeof(result));
    if (review_fixture(&result) != CryptoNoteTxError::FeePolicy)
      return false;
    const uint8_t *cleared = reinterpret_cast<const uint8_t *>(&result);
    for (size_t i = 0; i < sizeof(result); ++i)
      if (cleared[i] != 0)
        return false;
    f.tx.rct.fee = kFee;
    f.outputs[0].amount = kSendAmount + 1;
    if (review_fixture(&result) == CryptoNoteTxError::Ok)
      return false;
    f.outputs[0].amount = kSendAmount;
    f.outputs[1].amount = kChangeAmount - 1;
    if (review_fixture(&result) == CryptoNoteTxError::Ok)
      return false;
    f.outputs[1].amount = kChangeAmount;

    {
      uint8_t saved[kCryptoNoteKeySize];
      memcpy(saved, f.outputs[1].view_public, kCryptoNoteKeySize);
      f.outputs[1].view_public[0] ^= 0x01;
      if (review_fixture(&result) == CryptoNoteTxError::Ok)
        return false;
      memcpy(f.outputs[1].view_public, saved, kCryptoNoteKeySize);
    }

    {
      const uint64_t saved = f.tx.rct.fee;
      f.tx.rct.fee = kFee + 1;
      if (review_fixture(&result) == CryptoNoteTxError::Ok)
        return false;
      f.tx.rct.fee = saved;
    }

    {
      uint8_t saved[kCryptoNoteKeySize];
      memcpy(saved, f.tx.inputs[0].key_image, kCryptoNoteKeySize);
      f.tx.inputs[0].key_image[0] ^= 0x01;
      if (review_fixture(&result) == CryptoNoteTxError::Ok)
        return false;
      memcpy(f.tx.inputs[0].key_image, saved, kCryptoNoteKeySize);
    }

    {
      uint8_t saved[kCryptoNoteKeySize];
      memcpy(saved, f.tx.rct.pseudo_outs[0], kCryptoNoteKeySize);
      f.tx.rct.pseudo_outs[0][0] ^= 0x01;
      if (review_fixture(&result) == CryptoNoteTxError::Ok)
        return false;
      memcpy(f.tx.rct.pseudo_outs[0], saved, kCryptoNoteKeySize);
    }

    {
      uint8_t saved[kCryptoNoteKeySize];
      memcpy(saved, f.tx.extra + 1, kCryptoNoteKeySize);
      f.tx.extra[1] ^= 0x01;
      if (review_fixture(&result) == CryptoNoteTxError::Ok)
        return false;
      memcpy(f.tx.extra + 1, saved, kCryptoNoteKeySize);
    }

    {
      uint8_t saved[kCryptoNoteKeySize];
      memcpy(saved, f.input.pseudo_out_mask, kCryptoNoteKeySize);
      f.input.pseudo_out_mask[0] ^= 0x01;
      if (review_fixture(&result) == CryptoNoteTxError::Ok)
        return false;
      memcpy(f.input.pseudo_out_mask, saved, kCryptoNoteKeySize);
    }

    if (review_fixture(&result) != CryptoNoteTxError::Ok)
      return false;
    f.input.real_index = 1;
    if (review_fixture(&result) == CryptoNoteTxError::Ok)
      return false;
    f.input.real_index = 2;

    {
      uint8_t saved[kCryptoNoteKeySize];
      memcpy(saved, f.tx.outputs[0].commitment, kCryptoNoteKeySize);
      memcpy(f.tx.outputs[0].commitment, f.tx.outputs[1].commitment, kCryptoNoteKeySize);
      if (review_fixture(&result) == CryptoNoteTxError::Ok)
        return false;
      memcpy(f.tx.outputs[0].commitment, saved, kCryptoNoteKeySize);
    }

    {
      uint8_t saved[kCryptoNoteKeySize];
      memcpy(saved, f.tx.inputs[0].d, kCryptoNoteKeySize);
      f.tx.inputs[0].d[0] ^= 0x01;
      if (review_fixture(&result) == CryptoNoteTxError::Ok)
        return false;
      memcpy(f.tx.inputs[0].d, saved, kCryptoNoteKeySize);
    }

    // A change output that claims a subaddress must carry that subaddress's
    // keys. Labelling the standard change output as a subaddress has to fail.
    {
      f.outputs[1].subaddress_minor = 1;
      if (review_fixture(&result) == CryptoNoteTxError::Ok)
        return false;
      f.outputs[1].subaddress_minor = 0;
    }

    {
      const uint64_t saved = f.offsets[0];
      f.offsets[0] = saved + 1;
      if (review_fixture(&result) == CryptoNoteTxError::Ok)
        return false;
      f.offsets[0] = saved;
    }

    // ...and the honest fixture still passes after all that tampering.
    g_review_error = static_cast<int>(review_fixture(&result));
    return g_review_error == 0;
  }
} // namespace hexwallet
