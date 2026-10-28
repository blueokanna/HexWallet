#include "CryptoNoteSpend.h"

#include <string.h>

#include "CryptoExtended.h"
#include "CryptoNoteAmounts.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {

    constexpr uint8_t kExtraTagPubkey = 0x01;
    constexpr uint8_t kExtraTagNonce = 0x02;
    constexpr uint8_t kRctTypeBpPlus = 6;
    constexpr uint8_t kTxVersionRingCt = 2;
    constexpr size_t kNonceSize = 16;
    constexpr size_t kOutputsPerBpProof = 16;

    bool labeled_scalar(const char *label, size_t label_size,
                        const uint8_t seed[kCryptoNoteKeySize], uint16_t index,
                        uint8_t out[kCryptoNoteKeySize])
    {
      uint8_t buffer[32 + 32 + 2];
      memcpy(buffer, label, label_size);
      memcpy(buffer + label_size, seed, 32);
      buffer[label_size + 32] = static_cast<uint8_t>(index);
      buffer[label_size + 33] = static_cast<uint8_t>(index >> 8);
      const bool ok = cryptonote_hash_to_scalar(buffer, label_size + 34, out);
      secure_zero(buffer, sizeof(buffer));
      return ok;
    }

    bool write_extra(uint8_t *extra, size_t capacity,
                     const uint8_t tx_public[kCryptoNoteKeySize],
                     const uint8_t nonce[kNonceSize], uint16_t *out_size)
    {
      const size_t needed = 1 + kCryptoNoteKeySize + 2 + kNonceSize;
      if (capacity < needed)
        return false;
      size_t offset = 0;
      extra[offset++] = kExtraTagPubkey;
      memcpy(extra + offset, tx_public, kCryptoNoteKeySize);
      offset += kCryptoNoteKeySize;
      extra[offset++] = kExtraTagNonce;
      extra[offset++] = static_cast<uint8_t>(kNonceSize);
      memcpy(extra + offset, nonce, kNonceSize);
      offset += kNonceSize;
      *out_size = static_cast<uint16_t>(offset);
      return true;
    }

  } // namespace

  CryptoNoteTxError cryptonote_build_spend_transaction(
      const CryptoNoteSpendInput *inputs, size_t input_count,
      const CryptoNoteSpendOutput *outputs, size_t output_count, uint64_t fee,
      const uint8_t entropy[kCryptoNoteKeySize], CryptoNoteTransaction *out,
      const CryptoNoteBpPlusProof *proofs, size_t proof_count,
      uint8_t *pseudo_masks_out)
  {
    if (inputs == nullptr || outputs == nullptr || entropy == nullptr ||
        out == nullptr)
    {
      return CryptoNoteTxError::InvalidArgument;
    }
    clear_cryptonote_transaction(out);
    if (input_count == 0 || input_count > kCryptoNoteMaxSpendInputs ||
        output_count == 0 || output_count > kCryptoNoteMaxSpendOutputs)
    {
      return CryptoNoteTxError::TooManyItems;
    }
    if (fee > kCryptoNoteMaxFee)
      return CryptoNoteTxError::InvalidAmount;

    if (proofs == nullptr || proof_count != 1 || proofs[0].l_count < 6 ||
        proofs[0].l_count > kCryptoNoteMaxBpLr || proofs[0].r_count != proofs[0].l_count)
      return CryptoNoteTxError::Unsupported;

    uint64_t input_total = 0;
    uint64_t output_total = 0;
    for (size_t index = 0; index < input_count; ++index)
    {
      if (inputs[index].ring_size == 0 ||
          inputs[index].ring_size > kCryptoNoteMaxRingSize ||
          inputs[index].real_index >= inputs[index].ring_size)
      {
        return CryptoNoteTxError::InvalidArgument;
      }
      if (UINT64_MAX - input_total < inputs[index].amount)
      {
        return CryptoNoteTxError::InvalidAmount;
      }
      input_total += inputs[index].amount;
    }
    for (size_t index = 0; index < output_count; ++index)
    {
      if (UINT64_MAX - output_total < outputs[index].amount)
      {
        return CryptoNoteTxError::InvalidAmount;
      }
      output_total += outputs[index].amount;
    }
    if (UINT64_MAX - output_total < fee || input_total != output_total + fee)
      return CryptoNoteTxError::InvalidAmount;

    CryptoNoteTxError error = CryptoNoteTxError::Ok;
    uint8_t tx_secret[kCryptoNoteKeySize];
    if (!labeled_scalar("hw-tx-secret", 12, entropy, 0, tx_secret))
    {
      error = CryptoNoteTxError::CryptoFailure;
    }

    out->version = kTxVersionRingCt;
    out->unlock_time = 0;
    out->input_count = static_cast<uint16_t>(input_count);
    out->output_count = static_cast<uint16_t>(output_count);
    out->rct.type = kRctTypeBpPlus;
    out->rct.fee = fee;
    out->rct.proof_count = static_cast<uint8_t>((output_count + kOutputsPerBpProof - 1) / kOutputsPerBpProof);
    out->rct.ring_size = inputs[0].ring_size;

    out->rct.proofs[0] = proofs[0];

    uint8_t tx_public[kCryptoNoteKeySize];
    uint8_t extra_nonce[kNonceSize];
    if (error == CryptoNoteTxError::Ok)
    {
      uint8_t nonce_input[12 + 32];
      memcpy(nonce_input, "hw-extra-nce", 12);
      memcpy(nonce_input + 12, entropy, 32);
      uint8_t digest[kCryptoNoteKeySize];
      const bool nonce_ok = crypto_keccak256(nonce_input, sizeof(nonce_input), digest);
      if (nonce_ok)
        memcpy(extra_nonce, digest, kNonceSize);
      secure_zero(nonce_input, sizeof(nonce_input));
      secure_zero(digest, sizeof(digest));
      if (!nonce_ok ||
          !cryptonote_scalar_to_point(tx_secret, tx_public) ||
          !write_extra(out->extra, sizeof(out->extra), tx_public, extra_nonce,
                       &out->extra_size))
      {
        error = CryptoNoteTxError::InvalidArgument;
      }
    }

    uint8_t output_mask_sum[kCryptoNoteKeySize];
    memset(output_mask_sum, 0, sizeof(output_mask_sum));
    const uint8_t kOne[32] = {1};
    for (size_t index = 0; error == CryptoNoteTxError::Ok && index < output_count;
         ++index)
    {
      uint8_t derivation[kCryptoNoteKeySize];
      uint8_t amount_key[kCryptoNoteKeySize];
      uint8_t mask[kCryptoNoteKeySize];
      CryptoNoteTxOutput &target = out->outputs[index];
      const uint64_t output_index = static_cast<uint64_t>(index);
      bool ok = cryptonote_generate_key_derivation(outputs[index].view_public,
                                                   tx_secret, derivation) &&
                cryptonote_derivation_to_scalar(derivation, output_index,
                                                amount_key) &&
                cryptonote_derive_public_key(derivation, output_index,
                                             outputs[index].spend_public,
                                             target.public_key) &&
                ringct_encode_amount(RingCtAmountEncoding::Compact, amount_key,
                                     outputs[index].amount, nullptr,
                                     target.ecdh_amount, sizeof(target.ecdh_amount),
                                     target.commitment) &&
                ringct_commitment_mask(amount_key, mask) &&
                cryptonote_derive_view_tag(derivation, output_index,
                                           &target.view_tag);
      if (ok)
        ed25519_scalar_muladd(output_mask_sum, kOne, mask, output_mask_sum);
      target.tagged = true;
      secure_zero(derivation, sizeof(derivation));
      secure_zero(amount_key, sizeof(amount_key));
      secure_zero(mask, sizeof(mask));
      if (!ok)
        error = CryptoNoteTxError::Truncated;
    }

    for (size_t i = 0; error == CryptoNoteTxError::Ok && i < input_count; ++i)
    {
      out->inputs[i].key_offset_count = inputs[i].ring_size;
      memcpy(out->inputs[i].key_offsets, inputs[i].key_offsets,
             inputs[i].ring_size * sizeof(uint64_t));
      if (!cryptonote_generate_key_image(inputs[i].ring[inputs[i].real_index].dest,
                                         inputs[i].spend_secret, out->inputs[i].key_image))
        error = CryptoNoteTxError::CryptoFailure;
    }
    uint8_t pseudo_mask_sum[kCryptoNoteKeySize];
    memset(pseudo_mask_sum, 0, sizeof(pseudo_mask_sum));
    for (size_t index = 0; error == CryptoNoteTxError::Ok && index < input_count;
         ++index)
    {
      const CryptoNoteSpendInput &source = inputs[index];
      CryptoNoteTxInput &target = out->inputs[index];
      target.key_offset_count = source.ring_size;
      memcpy(target.key_offsets, source.key_offsets,
             sizeof(uint64_t) * source.ring_size);

      uint8_t pseudo_mask[kCryptoNoteKeySize];
      uint8_t effective_mask[kCryptoNoteKeySize];
      uint8_t nonce_seed[kCryptoNoteKeySize];
      const uint16_t input_index = static_cast<uint16_t>(index);
      const bool last_input = index + 1 == input_count;
      bool ok = last_input
                    ? (ed25519_scalar_mulsub(pseudo_mask, kOne, pseudo_mask_sum,
                                             output_mask_sum),
                       true)
                    : labeled_scalar("hw-pseudo-mask", 14, entropy, input_index,
                                     pseudo_mask);
      if (ok && !last_input)
      {
        ed25519_scalar_muladd(pseudo_mask_sum, kOne, pseudo_mask,
                              pseudo_mask_sum);
      }
      if (ok && pseudo_masks_out != nullptr)
        memcpy(pseudo_masks_out + index * kCryptoNoteKeySize, pseudo_mask, kCryptoNoteKeySize);
      ok = ok && ringct_commitment(pseudo_mask, source.amount, out->rct.pseudo_outs[index]) &&
           labeled_scalar("hw-clsag-nonce", 13, entropy, input_index, nonce_seed);
      if (ok)
      {
        ed25519_scalar_mulsub(effective_mask, kOne, pseudo_mask, source.mask);
      }
      if (ok)
      {
        CryptoNoteRingMember ring[kCryptoNoteMaxRingSize];
        memcpy(ring, source.ring, sizeof(CryptoNoteRingMember) * source.ring_size);
        memcpy(ring[source.real_index].mask, source.commitment,
               kCryptoNoteKeySize);
        ok = cryptonote_sign_input(out, input_index, source.real_index, ring,
                                   source.spend_secret, effective_mask,
                                   nonce_seed) == CryptoNoteTxError::Ok;
        secure_zero(ring, sizeof(ring));
      }
      secure_zero(pseudo_mask, sizeof(pseudo_mask));
      secure_zero(effective_mask, sizeof(effective_mask));
      secure_zero(nonce_seed, sizeof(nonce_seed));
      if (!ok)
        error = CryptoNoteTxError::BufferTooSmall;
    }
    secure_zero(output_mask_sum, sizeof(output_mask_sum));
    secure_zero(pseudo_mask_sum, sizeof(pseudo_mask_sum));

    if (error == CryptoNoteTxError::Ok && !cryptonote_transaction_balance_ok(*out))
    {
      error = CryptoNoteTxError::Unsupported;
    }
    if (error == CryptoNoteTxError::Ok)
    {
      if (!cryptonote_transaction_ring_uniform(*out, nullptr))
      {
        error = CryptoNoteTxError::NonCanonical;
      }
    }

    secure_zero(tx_secret, sizeof(tx_secret));
    secure_zero(tx_public, sizeof(tx_public));
    secure_zero(extra_nonce, sizeof(extra_nonce));
    if (error != CryptoNoteTxError::Ok)
      clear_cryptonote_transaction(out);
    return error;
  }

  bool cryptonote_spend_tx_secret(const uint8_t entropy[kCryptoNoteKeySize],
                                  uint8_t out[kCryptoNoteKeySize])
  {
    if (entropy == nullptr || out == nullptr)
      return false;
    return labeled_scalar("hw-tx-secret", 12, entropy, 0, out);
  }

  bool run_cryptonote_spend_self_tests()
  {
    static const uint8_t kSpendSecret[32] = {0x11, 0x22, 0x33, 0x44};
    static const uint8_t kViewSecret[32] = {0x55, 0x66, 0x77, 0x88};
    static const uint8_t kEntropy[32] = {0xa1, 0xa2, 0xa3, 0xa4};
    static const uint8_t kSecondEntropy[32] = {0xa5};

    const uint64_t spend_amount = 1000;
    const uint64_t send_amount = 700;
    const uint64_t change_amount = 290;
    const uint64_t fee = 10;

    uint8_t spend_public[kCryptoNoteKeySize];
    uint8_t view_public[kCryptoNoteKeySize];
    bool ok = cryptonote_scalar_to_point(kSpendSecret, spend_public) &&
              cryptonote_scalar_to_point(kViewSecret, view_public);

    uint8_t derivation[kCryptoNoteKeySize];
    uint8_t amount_key[kCryptoNoteKeySize];
    uint8_t spend_mask[kCryptoNoteKeySize];
    uint8_t one_time_secret[kCryptoNoteKeySize];
    uint8_t one_time_public[kCryptoNoteKeySize];
    uint8_t spent_ecdh[8];
    uint8_t spent_commitment[kCryptoNoteKeySize];
    const uint8_t previous_tx_secret[32] = {0x99};
    ok = ok && cryptonote_generate_key_derivation(view_public, previous_tx_secret, derivation) &&
         cryptonote_derivation_to_scalar(derivation, 0, amount_key) &&
         ringct_commitment_mask(amount_key, spend_mask) &&
         ringct_encode_amount(RingCtAmountEncoding::Compact, amount_key,
                              spend_amount, nullptr, spent_ecdh,
                              sizeof(spent_ecdh), spent_commitment) &&
         cryptonote_derive_public_key(derivation, 0, spend_public,
                                      one_time_public) &&
         cryptonote_derive_secret_key(derivation, 0, kSpendSecret,
                                      one_time_secret);

    CryptoNoteSpendInput input;
    memset(&input, 0, sizeof(input));
    input.amount = spend_amount;
    memcpy(input.mask, spend_mask, sizeof(input.mask));
    memcpy(input.commitment, spent_commitment, sizeof(input.commitment));
    memcpy(input.spend_secret, one_time_secret, sizeof(input.spend_secret));
    input.real_index = 4;
    input.ring_size = 8;
    for (uint16_t member = 0; member < input.ring_size; ++member)
    {
      uint8_t decoy[kCryptoNoteKeySize];
      memset(decoy, 0, sizeof(decoy));
      decoy[0] = static_cast<uint8_t>(0x30 + member);
      ok = ok && cryptonote_scalar_to_point(decoy, input.ring[member].dest) &&
           ringct_commitment(decoy, 100 + member, input.ring[member].mask);
      input.key_offsets[member] = 5000 + member;
    }
    memcpy(input.ring[input.real_index].dest, one_time_public,
           kCryptoNoteKeySize);
    memcpy(input.ring[input.real_index].mask, spent_commitment,
           kCryptoNoteKeySize);

    CryptoNoteSpendOutput outputs[2];
    memset(outputs, 0, sizeof(outputs));
    for (size_t index = 0; index < 2; ++index)
    {
      memcpy(outputs[index].spend_public, spend_public, kCryptoNoteKeySize);
      memcpy(outputs[index].view_public, view_public, kCryptoNoteKeySize);
    }
    outputs[0].amount = send_amount;
    outputs[1].amount = change_amount;
    outputs[1].change = true;

    CryptoNoteBpPlusProof fixture_proof = {};
    fixture_proof.l_count = fixture_proof.r_count = kCryptoNoteMaxBpLr;
    static CryptoNoteTransaction tx;
    static uint8_t wire[kCryptoNoteMaxTxBytes];

    ok = ok && cryptonote_build_spend_transaction(&input, 1, outputs, 2, fee,
                                                  kEntropy, &tx, &fixture_proof, 1) ==
                   CryptoNoteTxError::Ok;
    ok = ok && cryptonote_transaction_balance_ok(tx);

    size_t wire_size = sizeof(wire);
    uint8_t first_digest[32];
    ok = ok && cryptonote_serialize_transaction(tx, wire, &wire_size) == CryptoNoteTxError::Ok &&
         wire_size > 0 &&
         crypto_keccak256(wire, wire_size, first_digest);

    ok = ok && cryptonote_parse_transaction(wire, wire_size, &tx) ==
                   CryptoNoteTxError::Ok;
    size_t rewritten_size = sizeof(wire);
    uint8_t second_digest[32];
    ok = ok && cryptonote_serialize_transaction(tx, wire, &rewritten_size) == CryptoNoteTxError::Ok &&
         rewritten_size == wire_size &&
         crypto_keccak256(wire, rewritten_size, second_digest) &&
         crypto_constant_time_equal(first_digest, second_digest, 32);

    if (ok)
    {
      uint8_t prefix_hash[32];
      uint8_t base_hash[32];
      uint8_t message_input[64];
      uint8_t message[32];
      ok = cryptonote_transaction_signing_hash(tx, message) == CryptoNoteTxError::Ok;

      CryptoNoteRingMember ring[kCryptoNoteMaxRingSize];
      memcpy(ring, input.ring, sizeof(CryptoNoteRingMember) * input.ring_size);
      memcpy(ring[input.real_index].mask, spent_commitment, kCryptoNoteKeySize);
      CryptoNoteClsag signature;
      memset(&signature, 0, sizeof(signature));
      signature.ring_size = static_cast<uint8_t>(input.ring_size);
      for (uint16_t member = 0; member < input.ring_size; ++member)
      {
        memcpy(signature.s[member], tx.inputs[0].s[member], kCryptoNoteKeySize);
      }
      memcpy(signature.c1, tx.inputs[0].c1, kCryptoNoteKeySize);
      memcpy(signature.D, tx.inputs[0].d, kCryptoNoteKeySize);
      memcpy(signature.I, tx.inputs[0].key_image, kCryptoNoteKeySize);
      ok = ok && cryptonote_clsag_verify(message, ring, input.ring_size,
                                         tx.rct.pseudo_outs[0], signature);
      secure_zero(ring, sizeof(ring));
      secure_zero(&signature, sizeof(signature));
      secure_zero(prefix_hash, sizeof(prefix_hash));
      secure_zero(base_hash, sizeof(base_hash));
      secure_zero(message_input, sizeof(message_input));
      secure_zero(message, sizeof(message));
    }

    CryptoNoteSpendInput pair[2] = {input, input};
    pair[1].real_index = 2;
    pair[1].amount = 102;
    memset(pair[1].mask, 0, 32);
    pair[1].mask[0] = 0x32;
    memcpy(pair[1].spend_secret, pair[1].mask, 32);
    memcpy(pair[1].commitment, pair[1].ring[2].mask, 32);
    outputs[1].amount += 102;
    ok = ok && cryptonote_build_spend_transaction(pair, 2, outputs, 2, fee,
                                                  kSecondEntropy, &tx, &fixture_proof, 1) == CryptoNoteTxError::Ok;
    uint8_t final_message[32];
    ok = ok && cryptonote_transaction_signing_hash(tx, final_message) == CryptoNoteTxError::Ok;
    for (size_t i = 0; ok && i < 2; ++i)
    {
      CryptoNoteClsag sig = {};
      sig.ring_size = static_cast<uint8_t>(pair[i].ring_size);
      memcpy(sig.s, tx.inputs[i].s, sizeof(sig.s));
      memcpy(sig.c1, tx.inputs[i].c1, 32);
      memcpy(sig.D, tx.inputs[i].d, 32);
      memcpy(sig.I, tx.inputs[i].key_image, 32);
      ok = cryptonote_clsag_verify(final_message, pair[i].ring, pair[i].ring_size,
                                   tx.rct.pseudo_outs[i], sig);
      secure_zero(&sig, sizeof(sig));
    }
    outputs[1].amount -= 102;
    secure_zero(pair, sizeof(pair));
    secure_zero(final_message, sizeof(final_message));
    ok = ok && cryptonote_build_spend_transaction(&input, 1, outputs, 2, fee,
                                                  kEntropy, &tx, nullptr, 0) == CryptoNoteTxError::Unsupported;

    ok = ok && cryptonote_build_spend_transaction(&input, 1, outputs, 2,
                                                  fee + 1, kSecondEntropy,
                                                  &tx, &fixture_proof, 1) ==
                   CryptoNoteTxError::InvalidAmount;
    ok = ok && cryptonote_build_spend_transaction(&input, 0, outputs, 2, fee,
                                                  kSecondEntropy, &tx, &fixture_proof, 1) ==
                   CryptoNoteTxError::TooManyItems;

    secure_zero(derivation, sizeof(derivation));
    secure_zero(amount_key, sizeof(amount_key));
    secure_zero(spend_mask, sizeof(spend_mask));
    secure_zero(one_time_secret, sizeof(one_time_secret));
    secure_zero(first_digest, sizeof(first_digest));
    secure_zero(second_digest, sizeof(second_digest));
    secure_zero(wire, sizeof(wire));
    clear_cryptonote_transaction(&tx);
    return ok;
  }

} // namespace hexwallet
