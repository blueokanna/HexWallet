#include "RyoTransaction.h"
#include "CryptoNoteAmounts.h"
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
