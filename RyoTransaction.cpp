#include "RyoTransaction.h"
#include "CryptoNoteAmounts.h"
#include "CryptoNoteOutputScan.h"
#include "src/privacy/RingOps.h"

namespace hexwallet
{
  namespace
  {
    using namespace privacy;

    struct Cursor
    {
      const uint8_t *data;
      size_t size;
      size_t position = 0;
      RyoTxError error = RyoTxError::Ok;

      const uint8_t *take(size_t count)
      {
        if (error != RyoTxError::Ok)
          return nullptr;
        if (count > size - position)
        {
          error = RyoTxError::Truncated;
          return nullptr;
        }
        const uint8_t *p = data + position;
        position += count;
        return p;
      }
      bool varint(uint64_t &value)
      {
        value = 0;
        for (size_t i = 0; i < 10; ++i)
        {
          const uint8_t *p = take(1);
          if (!p)
            return false;
          const uint8_t byte = *p;
          if (i == 9 && byte > 1)
          {
            error = RyoTxError::NonCanonical;
            return false;
          }
          value |= static_cast<uint64_t>(byte & 0x7f) << (7 * i);
          if (!(byte & 0x80))
          {
            if (i && byte == 0)
            {
              error = RyoTxError::NonCanonical;
              return false;
            }
            return true;
          }
        }
        error = RyoTxError::NonCanonical;
        return false;
      }
    };

    RyoTxError parse(const uint8_t *data, size_t size, RyoTransactionView &tx)
    {
      Cursor cursor{data, size};
      uint64_t value;
      if (!cursor.varint(value))
        return cursor.error;
      if (value != 2 && value != 3)
        return RyoTxError::Unsupported;
      tx.version = static_cast<uint8_t>(value);
      if (!cursor.varint(tx.unlock_time) || !cursor.varint(value))
        return cursor.error;
      if (!value || value > kRyoMaxTxInputs)
        return RyoTxError::TooLarge;
      tx.input_count = static_cast<uint8_t>(value);
      for (size_t i = 0; i < tx.input_count; ++i)
      {
        auto &input = tx.inputs[i];
        const uint8_t *tag = cursor.take(1);
        if (!tag)
          return cursor.error;
        if (*tag != 2)
          return RyoTxError::Unsupported; // txin_to_key
        if (!cursor.varint(value))
          return cursor.error;
        if (value != 0)
          return RyoTxError::Unsupported;
        if (!cursor.varint(value))
          return cursor.error;
        if (value < 2 || value > kRyoMaxRingSize)
          return RyoTxError::TooLarge;
        if (i && tx.ring_size != value)
          return RyoTxError::NonCanonical;
        tx.ring_size = static_cast<uint16_t>(value);
        input.relative_offsets = data + cursor.position;
        uint64_t absolute = 0;
        for (size_t j = 0; j < tx.ring_size; ++j)
        {
          if (!cursor.varint(value))
            return cursor.error;
          if ((j && !value) || value > UINT64_MAX - absolute)
            return RyoTxError::NonCanonical;
          absolute += value;
        }
        input.offsets_size = data + cursor.position - input.relative_offsets;
        input.key_image = cursor.take(32);
        if (!input.key_image)
          return cursor.error;
        for (size_t j = 0; j < i; ++j)
          if (equal(input.key_image, tx.inputs[j].key_image))
            return RyoTxError::NonCanonical;
      }
      if (!cursor.varint(value))
        return cursor.error;
      if (!value || value > kRyoMaxTxOutputs)
        return RyoTxError::TooLarge;
      tx.output_count = static_cast<uint8_t>(value);
      for (size_t i = 0; i < tx.output_count; ++i)
      {
        if (!cursor.varint(value))
          return cursor.error;
        if (value != 0)
          return RyoTxError::Unsupported;
        const uint8_t *tag = cursor.take(1);
        if (!tag)
          return cursor.error;
        if (*tag != 2)
          return RyoTxError::Unsupported;
        tx.outputs[i].destination = cursor.take(32);
        if (!tx.outputs[i].destination)
          return cursor.error;
      }
      if (!cursor.varint(value))
        return cursor.error;
      if (value > kRyoMaxTxExtra)
        return RyoTxError::TooLarge;
      tx.extra_size = static_cast<size_t>(value);
      tx.extra = cursor.take(tx.extra_size);
      if (!tx.extra)
        return cursor.error;
      tx.prefix_size = cursor.position;
      const uint8_t *type = cursor.take(1);
      if (!type)
        return cursor.error;
      if (*type != 3)
        return RyoTxError::Unsupported;
      if (!cursor.varint(tx.fee))
        return cursor.error;
      for (size_t i = 0; i < tx.output_count; ++i)
      {
        tx.outputs[i].ecdh = cursor.take(64);
        if (!tx.outputs[i].ecdh)
          return cursor.error;
      }
      for (size_t i = 0; i < tx.output_count; ++i)
      {
        tx.outputs[i].commitment = cursor.take(32);
        if (!tx.outputs[i].commitment)
          return cursor.error;
      }
      tx.base_size = cursor.position - tx.prefix_size;
      const uint8_t *count = cursor.take(4);
      if (!count)
        return cursor.error;
      if (count[0] != 1 || count[1] || count[2] || count[3])
        return RyoTxError::Unsupported;
      auto &proof = tx.proof;
      const uint8_t *points = cursor.take(6 * 32);
      if (!points)
        return cursor.error;
      proof.a_point = points;
      proof.s_point = points + 32;
      proof.t1_point = points + 64;
      proof.t2_point = points + 96;
      proof.taux = points + 128;
      proof.mu = points + 160;
      size_t rounds = 6;
      for (size_t capacity = 1; capacity < tx.output_count; capacity *= 2)
        ++rounds;
      if (!cursor.varint(value))
        return cursor.error;
      if (value != rounds)
        return RyoTxError::NonCanonical;
      proof.rounds = rounds;
      proof.left = cursor.take(rounds * 32);
      if (!proof.left || !cursor.varint(value))
        return cursor.error;
      if (value != rounds)
        return RyoTxError::NonCanonical;
      proof.right = cursor.take(rounds * 32);
      points = cursor.take(3 * 32);
      if (!proof.right || !points)
        return cursor.error;
      proof.a = points;
      proof.b = points + 32;
      proof.t = points + 64;
      for (size_t i = 0; i < tx.input_count; ++i)
      {
        tx.inputs[i].responses = cursor.take(tx.ring_size * 64);
        tx.inputs[i].challenge = cursor.take(32);
        if (!tx.inputs[i].responses || !tx.inputs[i].challenge)
          return cursor.error;
      }
      for (size_t i = 0; i < tx.input_count; ++i)
      {
        tx.inputs[i].pseudo_out = cursor.take(32);
        if (!tx.inputs[i].pseudo_out)
          return cursor.error;
      }
      if (cursor.position != size)
        return RyoTxError::NonCanonical;
      tx.bytes = data;
      tx.size = size;
      return RyoTxError::Ok;
    }

    // Upstream device_default::encrypt_payment_id uses the first 40 bytes of
    // the 200-byte Keccak state, with the Keccak-256 rate and a 0x55 suffix.
    bool open_payment_id(const uint8_t encrypted[40], const uint8_t view[32],
                         const uint8_t secret[32], uint8_t plain[40])
    {
      SensitiveValue<uint8_t[33]> input;
      SensitiveValue<SHA3_CTX> context;
      SensitiveValue<uint8_t[32]> digest;
      if (!cryptonote_generate_key_derivation(view, secret, input.get()))
        return false;
      input.get()[32] = 0x55;
      keccak_init(&context.get());
      if (!keccak_update(&context.get(), input.get(), 33) || !keccak_final(&context.get(), digest.get()))
        return false;
      for (size_t i = 0; i < 40; ++i)
        plain[i] = encrypted[i] ^ static_cast<uint8_t>(context.get().state[i / 8] >> (8 * (i % 8)));
      return true;
    }

    bool hash_triplet(const uint8_t *a, const uint8_t *b, const uint8_t *c, uint8_t *out)
    {
      uint8_t hashes[96];
      memcpy(hashes, a, 32);
      memcpy(hashes + 32, b, 32);
      memcpy(hashes + 64, c, 32);
      return crypto_keccak256(hashes, sizeof(hashes), out);
    }

    bool hashes(const RyoTransactionView &tx, RyoTransactionHashes &out)
    {
      {
        Transcript prefix;
        constexpr char domain[] = "ryo-currency";
        if (tx.version >= 3)
          prefix.add(reinterpret_cast<const uint8_t *>(domain), sizeof(domain) - 1);
        prefix.add(tx.bytes, tx.prefix_size);
        if (!prefix.hash(out.prefix))
          return false;
      }
      const size_t begin = tx.prefix_size + tx.base_size;
      if (!crypto_keccak256(tx.bytes + tx.prefix_size, tx.base_size, out.base) ||
          !crypto_keccak256(tx.bytes + begin, tx.size - begin, out.prunable) ||
          !hash_triplet(out.prefix, out.base, out.prunable, out.transaction))
        return false;
      const auto &p = tx.proof;
      Transcript proof;
      proof.add(p.a_point);
      proof.add(p.s_point);
      proof.add(p.t1_point);
      proof.add(p.t2_point);
      proof.add(p.taux);
      proof.add(p.mu);
      proof.add(p.left, p.rounds * 32);
      proof.add(p.right, p.rounds * 32);
      proof.add(p.a);
      proof.add(p.b);
      proof.add(p.t);
      uint8_t proof_hash[32];
      if (!proof.hash(proof_hash))
        return false;
      return hash_triplet(out.prefix, out.base, proof_hash, out.signing);
    }
  } // namespace

  RyoTxError ryo_parse_transaction(const uint8_t *data, size_t size, RyoTransactionView *out)
  {
    if (!out)
      return RyoTxError::InvalidArgument;
    memset(out, 0, sizeof(*out));
    if (!data || !size)
      return RyoTxError::InvalidArgument;
    if (size > kRyoMaxTxBytes)
      return RyoTxError::TooLarge;
    const RyoTxError error = parse(data, size, *out);
    if (error != RyoTxError::Ok)
      memset(out, 0, sizeof(*out));
    return error;
  }

  RyoTxError ryo_transaction_hashes(const uint8_t *data, size_t size, RyoTransactionHashes *out)
  {
    if (!out)
      return RyoTxError::InvalidArgument;
    memset(out, 0, sizeof(*out));
    RyoTransactionView tx{};
    const auto error = ryo_parse_transaction(data, size, &tx);
    if (error != RyoTxError::Ok)
      return error;
    if (hashes(tx, *out))
      return RyoTxError::Ok;
    memset(out, 0, sizeof(*out));
    return RyoTxError::InvalidArgument;
  }

  bool ryo_decode_payment(const uint8_t *data, size_t size, const uint8_t tx_secret[32],
                          const RyoPublicAddress &recipient, const RyoPublicAddress &wallet,
                          RyoPaymentDetails *out)
  {
    if (!out) return false;
    *out = {};
    RyoTransactionView tx{};
    uint8_t tx_public[32];
    if (ryo_parse_transaction(data, size, &tx) != RyoTxError::Ok || tx.version != 3 ||
        tx.unlock_time != 0 || tx.output_count > 2 || tx.extra_size != 74 ||
        tx.extra[0] != 1 || tx.extra[33] != 5 || !scalar(tx_secret, false) ||
        !mul(kG, tx_secret, tx_public) || !equal(tx.extra + 1, tx_public) ||
        !point(recipient.spend) || !point(recipient.view) || !point(wallet.spend) || !point(wallet.view) ||
        (equal(recipient.spend, wallet.spend) && equal(recipient.view, wallet.view)))
      return false;

    SensitiveValue<RyoPaymentDetails> details;
    bool paid = false, has_change = false;
    for (size_t i = 0; i < tx.output_count; ++i)
    {
      const auto &output = tx.outputs[i];
      auto decode = [&](const RyoPublicAddress &addr, uint64_t &amount) {
        return cryptonote_scan_output(tx_secret, addr.spend, addr.view, i, output.destination,
            RingCtAmountEncoding::Legacy, output.ecdh, 64, output.commitment, &amount);
      };
      if (!paid && decode(recipient, details.get().amount)) paid = true;
      else if (!has_change && decode(wallet, details.get().change)) has_change = true;
      else return false;
    }
    if (!paid || !details.get().amount) return false;
    SensitiveValue<uint8_t[40]> plain;
    if (!open_payment_id(tx.extra + 34, recipient.view, tx_secret, plain.get())) return false;
    if (crypto_constant_time_equal(plain.get(), kZero, 8))
    {
      memcpy(details.get().payment_id, plain.get() + 8, 32);
      details.get().has_payment_id = true;
    }
    else
    {
      // Ryo encrypts the default {UINT64_MAX, null_hash} with the change
      // view key if change is present. Require the entire plaintext to match.
      constexpr uint8_t absent[40] = {255,255,255,255,255,255,255,255};
      if (has_change && !open_payment_id(tx.extra + 34, wallet.view, tx_secret, plain.get())) return false;
      if (!crypto_constant_time_equal(plain.get(), absent, sizeof(absent))) return false;
    }
    details.get().fee = tx.fee;
    *out = details.get();
    return true;
  }

  RyoTxError ryo_transaction_verify_semantics(const uint8_t *data, size_t size)
  {
    RyoTransactionView tx{};
    const auto error = ryo_parse_transaction(data, size, &tx);
    if (error != RyoTxError::Ok)
      return error;
    uint8_t inputs[32], outputs[32], fee[32], divided[kRyoMaxTxOutputs][32];
    memcpy(inputs, kOne, 32);
    memcpy(outputs, kOne, 32);
    for (size_t i = 0; i < tx.input_count; ++i)
    {
      const auto &input = tx.inputs[i];
      if (!point(input.key_image) || !point(input.pseudo_out))
        return RyoTxError::InvalidPoint;
      if (!ed25519_point_add_compressed(inputs, input.pseudo_out, inputs))
        return RyoTxError::InvalidPoint;
      if (!scalar(input.challenge))
        return RyoTxError::InvalidScalar;
      for (size_t j = 0; j < tx.ring_size * 2; ++j)
        if (!scalar(input.responses + j * 32))
          return RyoTxError::InvalidScalar;
    }
    for (size_t i = 0; i < tx.output_count; ++i)
    {
      const auto &output = tx.outputs[i];
      if (!point(output.destination) || !point(output.commitment))
        return RyoTxError::InvalidPoint;
      if (!scalar(output.ecdh) || !scalar(output.ecdh + 32))
        return RyoTxError::InvalidScalar;
      if (!ed25519_point_add_compressed(outputs, output.commitment, outputs) ||
          !mul(output.commitment, kInv8, divided[i]))
        return RyoTxError::InvalidPoint;
    }
    if (!ringct_commitment(kZero, tx.fee, fee) ||
        !ed25519_point_add_compressed(outputs, fee, outputs) || !equal(inputs, outputs))
      return RyoTxError::InvalidBalance;
    tx.proof.commitments = &divided[0][0];
    tx.proof.commitment_count = tx.output_count;
    return ryo_bulletproof_verify(tx.proof) ? RyoTxError::Ok : RyoTxError::InvalidProof;
  }

  namespace {
    struct Opening { uint8_t spend[32], delta[32]; uint64_t amount; };

    bool offsets_match(const RyoSpendSource &source, const RyoTxInputView &input)
    {
      if (!source.absolute_offsets) return false;
      Cursor cursor{input.relative_offsets, input.offsets_size};
      uint64_t absolute = 0;
      for (size_t i = 0; i < source.ring_size; ++i) {
        uint64_t relative;
        if (!cursor.varint(relative) || relative > UINT64_MAX - absolute) return false;
        absolute += relative;
        if (absolute != source.absolute_offsets[i]) return false;
      }
      return cursor.position == cursor.size;
    }

    bool recover_source(const RyoSpendSource &source, const RyoTxInputView &input,
                        const uint8_t spend[32], const uint8_t view[32], Opening &opening)
    {
      if (!point(source.funding_tx_public) || !scalar(source.pseudo_mask) || source.real_index >= source.ring_size)
        return false;
      const auto &member = source.ring[source.real_index];
      SensitiveValue<uint8_t[32]> derivation, key, mask;
      uint8_t expected[32];
      if (!cryptonote_generate_key_derivation(source.funding_tx_public, view, derivation.get()) ||
          !cryptonote_derive_secret_key(derivation.get(), source.funding_output_index, spend, opening.spend) ||
          !mul(kG, opening.spend, expected) || !equal(expected, member.destination) ||
          !cryptonote_generate_key_image(member.destination, opening.spend, expected) || !equal(expected, input.key_image) ||
          !cryptonote_derivation_to_scalar(derivation.get(), source.funding_output_index, key.get()) ||
          !ringct_decode_amount(RingCtAmountEncoding::Legacy, key.get(), source.funding_ecdh, 64,
                               member.commitment, &opening.amount, mask.get()) ||
          !ringct_commitment(source.pseudo_mask, opening.amount, expected) || !equal(expected, input.pseudo_out))
        return false;
      ed25519_scalar_mulsub(opening.delta, kOne, source.pseudo_mask, mask.get());
      return true;
    }
  }

  bool ryo_review_spend(const uint8_t *wire, size_t size, const RyoSpendSource *sources, size_t count,
                        const uint8_t spend[32], const uint8_t view[32], const uint8_t tx_secret[32],
                        const RyoPublicAddress &recipient, RyoSpendReview *out)
  {
    if (!out) return false;
    *out = {};
    RyoTransactionView tx{};
    if (!sources || ryo_parse_transaction(wire, size, &tx) != RyoTxError::Ok || tx.version != 3 ||
        tx.input_count != count || tx.ring_size < 25 || !scalar(spend, false) || !scalar(view, false)) return false;
    // Ryo Blockchain::check_fee after FORK_FEE_V2 charges the common ring
    // size once, plus a prorated fee on the entire serialized transaction.
    constexpr uint64_t fee_per_ring_member = 500000;
    constexpr uint64_t fee_per_kib = 500000;
    if (tx.fee < tx.ring_size * fee_per_ring_member + size * fee_per_kib / 1024) return false;
    RyoPublicAddress wallet;
    SensitiveValue<RyoSpendReview> review;
    if (!mul(kG, spend, wallet.spend) || !mul(kG, view, wallet.view) ||
        !ryo_decode_payment(wire, size, tx_secret, recipient, wallet, &review.get().payment)) return false;
    review.get().recipient = recipient;
    review.get().wallet = wallet;
    Transcript binding;
    if (!binding.add(wire, size) || !binding.add(wallet.spend) || !binding.add(wallet.view) ||
        !binding.add(recipient.spend) || !binding.add(recipient.view)) return false;
    for (size_t i = 0; i < count; ++i) {
      const auto &input = tx.inputs[i];
      const auto &source = sources[i];
      if (source.ring_size != tx.ring_size || !source.ring || !equal(kZero, input.challenge) ||
          (i && memcmp(input.key_image, tx.inputs[i - 1].key_image, 32) >= 0) || !offsets_match(source, input)) return false;
      for (size_t j = 0; j < 2 * source.ring_size; ++j)
        if (!equal(kZero, input.responses + j * 32)) return false;
      SensitiveValue<Opening> opening;
      if (!ryo_validate_ring(source.ring, source.ring_size) || !recover_source(source, input, spend, view, opening.get()) ||
          opening.get().amount > UINT64_MAX - review.get().total_input) return false;
      review.get().total_input += opening.get().amount;
      for (size_t j = 0; j < source.ring_size; ++j)
        if (!binding.add(source.ring[j].destination) || !binding.add(source.ring[j].commitment)) return false;
    }
    const auto &payment = review.get().payment;
    const uint64_t available = review.get().total_input;
    if (payment.amount > available || payment.change > available - payment.amount ||
        available - payment.amount - payment.change != payment.fee ||
        ryo_transaction_verify_semantics(wire, size) != RyoTxError::Ok || !binding.hash(review.get().binding)) return false;
    *out = review.get();
    return true;
  }

  bool ryo_sign_spend(const uint8_t *wire, size_t size, const RyoSpendSource *sources, size_t count,
                      const uint8_t spend[32], const uint8_t view[32], const uint8_t tx_secret[32],
                      const RyoPublicAddress &recipient, const RyoSpendReview &approved,
                      const uint8_t entropy[32], RyoMlsagSignature *workspace,
                      uint8_t *signed_tx, size_t *in_out_size)
  {
    SigningOutputGuard guard(signed_tx, in_out_size);
    SensitiveValue<RyoSpendReview> checked;
    if (!guard.valid() || !workspace || !entropy || *in_out_size < size ||
        !ryo_review_spend(wire, size, sources, count, spend, view, tx_secret, recipient, &checked.get())) return false;
    const auto &a = approved.payment;
    const auto &b = checked.get().payment;
    if (!equal(checked.get().binding, approved.binding) || approved.total_input != checked.get().total_input ||
        !equal(checked.get().wallet.spend, approved.wallet.spend) || !equal(checked.get().wallet.view, approved.wallet.view) ||
        !equal(approved.recipient.spend, recipient.spend) || !equal(approved.recipient.view, recipient.view) ||
        a.amount != b.amount || a.change != b.change || a.fee != b.fee || a.has_payment_id != b.has_payment_id ||
        !equal(a.payment_id, b.payment_id)) return false;
    RyoTransactionView tx{};
    RyoTransactionHashes digest{};
    if (ryo_parse_transaction(wire, size, &tx) != RyoTxError::Ok || !hashes(tx, digest)) return false;
    memcpy(signed_tx, wire, size);
    for (size_t i = 0; i < count; ++i) {
      const auto &input = tx.inputs[i];
      const auto &source = sources[i];
      SensitiveValue<Opening> opening;
      if (!recover_source(source, input, spend, view, opening.get()) ||
          !ryo_mlsag_sign(digest.signing, source.ring, source.ring_size, source.real_index, opening.get().spend,
                          opening.get().delta, input.pseudo_out, entropy, workspace)) return false;
      if (!equal(workspace->key_image, input.key_image)) { secure_zero(workspace, sizeof(*workspace)); return false; }
      memcpy(signed_tx + (input.responses - wire), workspace->responses, source.ring_size * 64);
      memcpy(signed_tx + (input.challenge - wire), workspace->challenge, 32);
      secure_zero(workspace, sizeof(*workspace));
    }
    *in_out_size = size;
    return guard.commit();
  }

  RyoTxError ryo_transaction_verify_input(const uint8_t *data, size_t size,
                                          size_t index, const RyoRingMember *ring, size_t count)
  {
    RyoTransactionView tx{};
    const auto error = ryo_parse_transaction(data, size, &tx);
    if (error != RyoTxError::Ok)
      return error;
    if (!ring || index >= tx.input_count || count != tx.ring_size)
      return RyoTxError::InvalidArgument;
    RyoTransactionHashes digest{};
    if (!hashes(tx, digest))
      return RyoTxError::InvalidArgument;
    const auto &input = tx.inputs[index];
    const RyoMlsagSignatureView signature{input.responses, input.challenge, input.key_image, count};
    return ryo_mlsag_verify(digest.signing, ring, count, input.pseudo_out, signature)
               ? RyoTxError::Ok
               : RyoTxError::InvalidSignature;
  }
}
