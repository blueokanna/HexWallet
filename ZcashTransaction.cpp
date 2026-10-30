#include "ZcashTransaction.h"

#include "RandomSource.h"
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <string.h>

#include "Blake2b.h"
#include "WalletAltAddresses.h"
#include "WalletConfig.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {

    constexpr uint32_t kSighashAll = 1;
    constexpr uint32_t kSighashNone = 2;
    constexpr uint32_t kSighashSingle = 3;
    constexpr uint32_t kSighashAnyoneCanPay = 0x80;
    constexpr uint32_t kSighashMask = 0x1f;
    constexpr size_t kMaxTransparentScriptSize = 10000;
    constexpr size_t kShieldedSpendSize = 384;
    constexpr size_t kShieldedOutputSize = 948;
    constexpr size_t kJoinSplitSize = 1698;
    constexpr size_t kP2pkhScriptSize = 25;
    constexpr size_t kP2shScriptSize = 23;
    constexpr uint8_t kZcashPayloadMagic[4] = {'Z', 'E', 'C', '4'};
    // ZEC5 appends `u8 redeem_size + redeem script` to every input record so a
    // t3 P2SH prevout can be spent. ZEC4 stays valid for P2PKH-only requests.
    constexpr uint8_t kZcashPayloadMagicRedeem[4] = {'Z', 'E', 'C', '5'};

    struct Cursor
    {
      const uint8_t *data;
      size_t size;
      size_t position;
    };

    struct Writer
    {
      uint8_t *data;
      size_t size;
      size_t position;
    };

    struct TxInputView
    {
      const uint8_t *prevout;
      const uint8_t *script_sig;
      size_t script_sig_size;
      uint32_t sequence;
    };

    struct TxOutputView
    {
      const uint8_t *script;
      size_t script_size;
      uint64_t value;
    };

    struct TxView
    {
      uint32_t version;
      uint32_t version_group_id;
      uint32_t lock_time;
      uint32_t expiry_height;
      int64_t value_balance;
      TxInputView inputs[kZcashMaxInputs];
      TxOutputView outputs[kZcashMaxOutputs];
      size_t input_count;
      size_t output_count;
      size_t shielded_spend_offset;
      size_t shielded_spend_count;
      size_t shielded_output_offset;
      size_t shielded_output_count;
      size_t joinsplit_offset;
      size_t joinsplit_count;
      const uint8_t *joinsplit_pubkey;
      const uint8_t *joinsplit_sig;
      const uint8_t *binding_sig;
    };

    bool add_u64(uint64_t left, uint64_t right, uint64_t *out)
    {
      if (out == nullptr || UINT64_MAX - left < right)
        return false;
      *out = left + right;
      return true;
    }

    bool read_bytes(Cursor *cursor, size_t count, const uint8_t **out)
    {
      if (cursor == nullptr || count > cursor->size - cursor->position)
        return false;
      if (out != nullptr)
        *out = cursor->data + cursor->position;
      cursor->position += count;
      return true;
    }

    bool read_u32(Cursor *cursor, uint32_t *out)
    {
      const uint8_t *bytes;
      if (!read_bytes(cursor, 4, &bytes))
        return false;
      *out = static_cast<uint32_t>(bytes[0]) |
             (static_cast<uint32_t>(bytes[1]) << 8) |
             (static_cast<uint32_t>(bytes[2]) << 16) |
             (static_cast<uint32_t>(bytes[3]) << 24);
      return true;
    }

    bool read_u64(Cursor *cursor, uint64_t *out)
    {
      const uint8_t *bytes;
      if (!read_bytes(cursor, 8, &bytes))
        return false;
      uint64_t value = 0;
      for (size_t index = 0; index < 8; ++index)
      {
        value |= static_cast<uint64_t>(bytes[index]) << (index * 8);
      }
      *out = value;
      return true;
    }

    ZcashError read_compact_size(Cursor *cursor, uint64_t *out)
    {
      const uint8_t *first;
      if (!read_bytes(cursor, 1, &first))
        return ZcashError::Truncated;
      if (*first < 0xfd)
      {
        *out = *first;
        return ZcashError::Ok;
      }
      const size_t length = *first == 0xfd ? 2 : (*first == 0xfe ? 4 : 8);
      const uint8_t *bytes;
      if (!read_bytes(cursor, length, &bytes))
        return ZcashError::Truncated;
      uint64_t value = 0;
      for (size_t index = 0; index < length; ++index)
      {
        value |= static_cast<uint64_t>(bytes[index]) << (index * 8);
      }
      if ((length == 2 && value < 0xfd) || (length == 4 && value <= 0xffff) ||
          (length == 8 && value <= 0xffffffffULL))
      {
        return ZcashError::NonCanonical;
      }
      *out = value;
      return ZcashError::Ok;
    }

    bool write_bytes(Writer *writer, const void *data, size_t count)
    {
      if (writer == nullptr || count > writer->size - writer->position)
        return false;
      if (count != 0)
        memcpy(writer->data + writer->position, data, count);
      writer->position += count;
      return true;
    }

    bool write_u32(Writer *writer, uint32_t value)
    {
      uint8_t bytes[4] = {static_cast<uint8_t>(value),
                          static_cast<uint8_t>(value >> 8),
                          static_cast<uint8_t>(value >> 16),
                          static_cast<uint8_t>(value >> 24)};
      return write_bytes(writer, bytes, sizeof(bytes));
    }

    bool write_u64(Writer *writer, uint64_t value)
    {
      uint8_t bytes[8];
      for (size_t index = 0; index < sizeof(bytes); ++index)
      {
        bytes[index] = static_cast<uint8_t>(value >> (index * 8));
      }
      return write_bytes(writer, bytes, sizeof(bytes));
    }

    bool write_compact_size(Writer *writer, uint64_t value)
    {
      if (value < 0xfd)
      {
        const uint8_t byte = static_cast<uint8_t>(value);
        return write_bytes(writer, &byte, 1);
      }
      if (value <= 0xffff)
      {
        const uint8_t bytes[3] = {0xfd, static_cast<uint8_t>(value),
                                  static_cast<uint8_t>(value >> 8)};
        return write_bytes(writer, bytes, sizeof(bytes));
      }
      if (value <= 0xffffffffULL)
      {
        const uint8_t prefix = 0xfe;
        return write_bytes(writer, &prefix, 1) &&
               write_u32(writer, static_cast<uint32_t>(value));
      }
      const uint8_t prefix = 0xff;
      return write_bytes(writer, &prefix, 1) && write_u64(writer, value);
    }

    bool transparent_script(const uint8_t *script, size_t script_size)
    {
      if (script == nullptr)
        return false;
      const bool p2pkh = script_size == kP2pkhScriptSize &&
                         script[0] == 0x76 && script[1] == 0xa9 &&
                         script[2] == 0x14 && script[23] == 0x88 &&
                         script[24] == 0xac;
      const bool p2sh = script_size == kP2shScriptSize &&
                        script[0] == 0xa9 && script[1] == 0x14 &&
                        script[22] == 0x87;
      return p2pkh || p2sh;
    }

    bool p2pkh_script(const uint8_t *script, size_t script_size)
    {
      return script != nullptr && script_size == kP2pkhScriptSize &&
             script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
             script[23] == 0x88 && script[24] == 0xac;
    }

    bool p2sh_script(const uint8_t *script, size_t script_size)
    {
      return script != nullptr && script_size == kP2shScriptSize &&
             script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87;
    }

    // The only redeem form this device can prove it owns and can satisfy:
    // a single compressed public key followed by OP_CHECKSIG.
    bool p2pk_redeem_script(const uint8_t *script, size_t script_size)
    {
      return script != nullptr && script_size == kZcashMaxRedeemScriptSize &&
             script[0] == kCompressedPublicKeySize && script[34] == 0xac &&
             (script[1] == 0x02 || script[1] == 0x03);
    }

    ZcashError parse_v4_transaction(const uint8_t *data, size_t size, TxView *view,
                                    bool allow_script_sig)
    {
      if (data == nullptr || view == nullptr || size == 0)
      {
        return ZcashError::InvalidArgument;
      }
      memset(view, 0, sizeof(*view));
      Cursor cursor = {data, size, 0};
      if (!read_u32(&cursor, &view->version) ||
          !read_u32(&cursor, &view->version_group_id))
      {
        return ZcashError::Truncated;
      }
      if (view->version != kZcashV4Version ||
          view->version_group_id != kZcashSaplingVersionGroupId)
      {
        return ZcashError::Unsupported;
      }
      uint64_t input_count;
      ZcashError result = read_compact_size(&cursor, &input_count);
      if (result != ZcashError::Ok)
        return result;
      if (input_count > kZcashMaxInputs)
        return ZcashError::TooLarge;
      view->input_count = static_cast<size_t>(input_count);
      for (size_t index = 0; index < view->input_count; ++index)
      {
        TxInputView &input = view->inputs[index];
        if (!read_bytes(&cursor, 36, &input.prevout))
          return ZcashError::Truncated;
        uint64_t script_size;
        result = read_compact_size(&cursor, &script_size);
        if (result != ZcashError::Ok)
          return result;
        if (script_size > kMaxTransparentScriptSize)
          return ZcashError::TooLarge;
        if (!read_bytes(&cursor, static_cast<size_t>(script_size),
                        &input.script_sig))
        {
          return ZcashError::Truncated;
        }
        input.script_sig_size = static_cast<size_t>(script_size);
        if (!allow_script_sig && input.script_sig_size != 0)
        {
          return ZcashError::Unsupported;
        }
        if (!read_u32(&cursor, &input.sequence))
          return ZcashError::Truncated;
      }
      uint64_t output_count;
      result = read_compact_size(&cursor, &output_count);
      if (result != ZcashError::Ok)
        return result;
      if (output_count > kZcashMaxOutputs)
        return ZcashError::TooLarge;
      view->output_count = static_cast<size_t>(output_count);
      for (size_t index = 0; index < view->output_count; ++index)
      {
        TxOutputView &output = view->outputs[index];
        if (!read_u64(&cursor, &output.value))
          return ZcashError::Truncated;
        if (output.value > kZcashTransparentParseMaxZats)
          return ZcashError::InvalidAmount;
        uint64_t script_size;
        result = read_compact_size(&cursor, &script_size);
        if (result != ZcashError::Ok)
          return result;
        if (script_size > kMaxTransparentScriptSize)
          return ZcashError::TooLarge;
        if (!read_bytes(&cursor, static_cast<size_t>(script_size), &output.script))
        {
          return ZcashError::Truncated;
        }
        output.script_size = static_cast<size_t>(script_size);
      }
      if (!read_u32(&cursor, &view->lock_time) ||
          !read_u32(&cursor, &view->expiry_height))
      {
        return ZcashError::Truncated;
      }
      if (view->expiry_height >= 500000000UL)
        return ZcashError::Unsupported;
      uint64_t value_balance;
      if (!read_u64(&cursor, &value_balance))
        return ZcashError::Truncated;
      view->value_balance = static_cast<int64_t>(value_balance);
      uint64_t shielded_spends;
      result = read_compact_size(&cursor, &shielded_spends);
      if (result != ZcashError::Ok)
        return result;
      if (shielded_spends > (cursor.size - cursor.position) / kShieldedSpendSize)
      {
        return ZcashError::Truncated;
      }
      view->shielded_spend_offset = cursor.position;
      view->shielded_spend_count = static_cast<size_t>(shielded_spends);
      cursor.position += view->shielded_spend_count * kShieldedSpendSize;
      uint64_t shielded_outputs;
      result = read_compact_size(&cursor, &shielded_outputs);
      if (result != ZcashError::Ok)
        return result;
      if (shielded_outputs > (cursor.size - cursor.position) / kShieldedOutputSize)
      {
        return ZcashError::Truncated;
      }
      view->shielded_output_offset = cursor.position;
      view->shielded_output_count = static_cast<size_t>(shielded_outputs);
      cursor.position += view->shielded_output_count * kShieldedOutputSize;
      uint64_t joinsplits;
      result = read_compact_size(&cursor, &joinsplits);
      if (result != ZcashError::Ok)
        return result;
      if (joinsplits > (cursor.size - cursor.position) / kJoinSplitSize)
      {
        return ZcashError::Truncated;
      }
      view->joinsplit_offset = cursor.position;
      view->joinsplit_count = static_cast<size_t>(joinsplits);
      cursor.position += view->joinsplit_count * kJoinSplitSize;
      if (view->joinsplit_count > 0)
      {
        if (!read_bytes(&cursor, 32, &view->joinsplit_pubkey) ||
            !read_bytes(&cursor, 64, &view->joinsplit_sig))
        {
          return ZcashError::Truncated;
        }
      }
      if (view->shielded_spend_count > 0 || view->shielded_output_count > 0)
      {
        if (!read_bytes(&cursor, 64, &view->binding_sig))
        {
          return ZcashError::Truncated;
        }
      }
      return cursor.position == cursor.size ? ZcashError::Ok
                                            : ZcashError::NonCanonical;
    }

    ZcashError hash_prevouts(const TxView &view, uint8_t out[kSha256Size])
    {
      Blake2bState state;
      if (!blake2b_init_personal(
              &state, kSha256Size,
              reinterpret_cast<const uint8_t *>("ZcashPrevoutHash")))
      {
        return ZcashError::CryptoFailure;
      }
      for (size_t index = 0; index < view.input_count; ++index)
      {
        blake2b_update(&state, view.inputs[index].prevout, 36);
      }
      return blake2b_final(&state, out) ? ZcashError::Ok
                                        : ZcashError::CryptoFailure;
    }

    ZcashError hash_sequence(const TxView &view, uint8_t out[kSha256Size])
    {
      Blake2bState state;
      if (!blake2b_init_personal(
              &state, kSha256Size,
              reinterpret_cast<const uint8_t *>("ZcashSequencHash")))
      {
        return ZcashError::CryptoFailure;
      }
      for (size_t index = 0; index < view.input_count; ++index)
      {
        uint8_t sequence[4] = {
            static_cast<uint8_t>(view.inputs[index].sequence),
            static_cast<uint8_t>(view.inputs[index].sequence >> 8),
            static_cast<uint8_t>(view.inputs[index].sequence >> 16),
            static_cast<uint8_t>(view.inputs[index].sequence >> 24)};
        blake2b_update(&state, sequence, sizeof(sequence));
      }
      return blake2b_final(&state, out) ? ZcashError::Ok
                                        : ZcashError::CryptoFailure;
    }

    void hash_output(Blake2bState *state, const TxOutputView &output)
    {
      uint8_t value[8];
      for (size_t index = 0; index < sizeof(value); ++index)
      {
        value[index] = static_cast<uint8_t>(output.value >> (index * 8));
      }
      uint8_t size[9];
      size_t size_length;
      const uint64_t script_size = output.script_size;
      if (script_size < 0xfd)
      {
        size[0] = static_cast<uint8_t>(script_size);
        size_length = 1;
      }
      else if (script_size <= 0xffff)
      {
        size[0] = 0xfd;
        size[1] = static_cast<uint8_t>(script_size);
        size[2] = static_cast<uint8_t>(script_size >> 8);
        size_length = 3;
      }
      else if (script_size <= 0xffffffffULL)
      {
        size[0] = 0xfe;
        for (size_t index = 0; index < 4; ++index)
        {
          size[1 + index] = static_cast<uint8_t>(script_size >> (index * 8));
        }
        size_length = 5;
      }
      else
      {
        size[0] = 0xff;
        for (size_t index = 0; index < 8; ++index)
        {
          size[1 + index] = static_cast<uint8_t>(script_size >> (index * 8));
        }
        size_length = 9;
      }
      blake2b_update(state, value, sizeof(value));
      blake2b_update(state, size, size_length);
      blake2b_update(state, output.script, output.script_size);
    }

    ZcashError hash_outputs(const TxView &view, const TxOutputView *single,
                            uint8_t out[kSha256Size])
    {
      Blake2bState state;
      if (!blake2b_init_personal(
              &state, kSha256Size,
              reinterpret_cast<const uint8_t *>("ZcashOutputsHash")))
      {
        return ZcashError::CryptoFailure;
      }
      if (single != nullptr)
      {
        hash_output(&state, *single);
      }
      else
      {
        for (size_t index = 0; index < view.output_count; ++index)
        {
          hash_output(&state, view.outputs[index]);
        }
      }
      return blake2b_final(&state, out) ? ZcashError::Ok
                                        : ZcashError::CryptoFailure;
    }

    int random_callback(void *, unsigned char *output, size_t length)
    {
      random_fill(output, length);
      return 0;
    }

    size_t der_integer(const mbedtls_mpi &value, uint8_t *out)
    {
      uint8_t raw[32];
      mbedtls_mpi_write_binary(&value, raw, sizeof(raw));
      size_t first = 0;
      while (first + 1 < sizeof(raw) && raw[first] == 0)
        ++first;
      const bool prefix_zero = (raw[first] & 0x80) != 0;
      const size_t length = sizeof(raw) - first + (prefix_zero ? 1 : 0);
      out[0] = 0x02;
      out[1] = static_cast<uint8_t>(length);
      size_t position = 2;
      if (prefix_zero)
        out[position++] = 0;
      memcpy(out + position, raw + first, sizeof(raw) - first);
      secure_zero(raw, sizeof(raw));
      return 2 + length;
    }

    ZcashError sign_digest(const uint8_t private_key[kPrivateKeySize],
                           const uint8_t digest[kSha256Size], uint8_t *der,
                           size_t *der_size)
    {
      mbedtls_ecp_group group;
      mbedtls_mpi d;
      mbedtls_mpi r;
      mbedtls_mpi s;
      mbedtls_mpi half_order;
      mbedtls_ecp_point public_key;
      mbedtls_ecp_group_init(&group);
      mbedtls_mpi_init(&d);
      mbedtls_mpi_init(&r);
      mbedtls_mpi_init(&s);
      mbedtls_mpi_init(&half_order);
      mbedtls_ecp_point_init(&public_key);
      int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
      if (result == 0)
        result = mbedtls_mpi_read_binary(&d, private_key, kPrivateKeySize);
      if (result == 0)
      {
        result = mbedtls_ecdsa_sign_det_ext(
            &group, &r, &s, &d, digest, kSha256Size, MBEDTLS_MD_SHA256,
            random_callback, nullptr);
      }
      if (result == 0)
        result = mbedtls_mpi_copy(&half_order, &group.N);
      if (result == 0)
        result = mbedtls_mpi_shift_r(&half_order, 1);
      if (result == 0 && mbedtls_mpi_cmp_mpi(&s, &half_order) > 0)
      {
        result = mbedtls_mpi_sub_mpi(&s, &group.N, &s);
      }
      if (result == 0)
      {
        result = mbedtls_ecp_mul(&group, &public_key, &d, &group.G,
                                 random_callback, nullptr);
      }
      if (result == 0)
      {
        result = mbedtls_ecdsa_verify(&group, digest, kSha256Size, &public_key,
                                      &r, &s);
      }
      uint8_t integers[70];
      size_t integer_size = 0;
      if (result == 0)
      {
        integer_size = der_integer(r, integers);
        integer_size += der_integer(s, integers + integer_size);
        if (*der_size < integer_size + 2)
          result = -1;
      }
      if (result == 0)
      {
        der[0] = 0x30;
        der[1] = static_cast<uint8_t>(integer_size);
        memcpy(der + 2, integers, integer_size);
        *der_size = integer_size + 2;
      }
      secure_zero(integers, sizeof(integers));
      mbedtls_ecp_point_free(&public_key);
      mbedtls_mpi_free(&half_order);
      mbedtls_mpi_free(&s);
      mbedtls_mpi_free(&r);
      mbedtls_mpi_free(&d);
      mbedtls_ecp_group_free(&group);
      return result == 0 ? ZcashError::Ok : ZcashError::CryptoFailure;
    }

    bool verify_digest(const uint8_t public_key[kCompressedPublicKeySize],
                       const uint8_t digest[kSha256Size], const uint8_t *der,
                       size_t der_size)
    {
      mbedtls_ecp_group group;
      mbedtls_ecp_point point;
      mbedtls_mpi r;
      mbedtls_mpi s;
      mbedtls_ecp_group_init(&group);
      mbedtls_ecp_point_init(&point);
      mbedtls_mpi_init(&r);
      mbedtls_mpi_init(&s);
      int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
      if (result == 0)
      {
        result = mbedtls_ecp_point_read_binary(&group, &point, public_key,
                                               kCompressedPublicKeySize);
      }
      if (result == 0)
        result = mbedtls_ecp_check_pubkey(&group, &point);
      if (result == 0 && der_size > 6 && der[0] == 0x30 &&
          der[1] == der_size - 2 && der[2] == 0x02)
      {
        const size_t r_size = der[3];
        if (r_size != 0 && 4 + r_size + 2 <= der_size &&
            der[4 + r_size] == 0x02)
        {
          const size_t s_size = der[5 + r_size];
          if (s_size != 0 && 6 + r_size + s_size == der_size)
          {
            result = mbedtls_mpi_read_binary(&r, der + 4, r_size);
            if (result == 0)
            {
              result = mbedtls_mpi_read_binary(&s, der + 6 + r_size, s_size);
            }
            if (result == 0)
            {
              result = mbedtls_ecdsa_verify(&group, digest, kSha256Size, &point,
                                            &r, &s);
            }
          }
          else
          {
            result = -1;
          }
        }
        else
        {
          result = -1;
        }
      }
      else
      {
        result = -1;
      }
      mbedtls_mpi_free(&s);
      mbedtls_mpi_free(&r);
      mbedtls_ecp_point_free(&point);
      mbedtls_ecp_group_free(&group);
      return result == 0;
    }

    ZcashError serialize_request(
        const ZcashSigningRequest &request,
        const uint8_t signatures[kZcashMaxInputs][kZcashMaxScriptSigSize],
        const uint8_t signature_sizes[kZcashMaxInputs],
        const uint8_t public_keys[kZcashMaxInputs][kCompressedPublicKeySize],
        uint8_t *out_transaction, size_t *in_out_size)
    {
      if (out_transaction == nullptr || in_out_size == nullptr ||
          request.input_count == 0 || request.input_count > kZcashMaxInputs ||
          request.output_count == 0 || request.output_count > kZcashMaxOutputs)
      {
        return ZcashError::InvalidArgument;
      }
      Writer writer = {out_transaction, *in_out_size, 0};
      bool ok = write_u32(&writer, request.version) &&
                write_u32(&writer, request.version_group_id) &&
                write_compact_size(&writer, request.input_count);
      for (size_t index = 0; ok && index < request.input_count; ++index)
      {
        const ZcashInput &input = request.inputs[index];
        ok = write_bytes(&writer, input.previous_txid, 32) &&
             write_u32(&writer, input.previous_index);
        if (!ok)
          break;
        if (signatures == nullptr)
        {
          ok = write_compact_size(&writer, 0);
        }
        else
        {
          // P2SH scriptSig pushes the signature and then the redeem script;
          // P2PKH pushes the signature and the public key.
          const bool redeem_input = input.redeem_size != 0;
          const size_t pushed_size =
              redeem_input ? input.redeem_size : kCompressedPublicKeySize;
          const uint8_t *pushed = redeem_input ? input.redeem : public_keys[index];
          const size_t script_size =
              1 + signature_sizes[index] + 1 + pushed_size;
          ok = write_compact_size(&writer, script_size) &&
               write_compact_size(&writer, signature_sizes[index]) &&
               write_bytes(&writer, signatures[index], signature_sizes[index]) &&
               write_compact_size(&writer, pushed_size) &&
               write_bytes(&writer, pushed, pushed_size);
        }
        ok = ok && write_u32(&writer, input.sequence);
      }
      ok = ok && write_compact_size(&writer, request.output_count);
      for (size_t index = 0; ok && index < request.output_count; ++index)
      {
        const ZcashOutput &output = request.outputs[index];
        ok = write_u64(&writer, output.value) &&
             write_compact_size(&writer, output.script_size) &&
             write_bytes(&writer, output.script, output.script_size);
      }
      ok = ok && write_u32(&writer, request.lock_time) &&
           write_u32(&writer, request.expiry_height) &&
           write_u64(&writer, static_cast<uint64_t>(request.value_balance)) &&
           write_compact_size(&writer, 0) && write_compact_size(&writer, 0) &&
           write_compact_size(&writer, 0);
      if (!ok)
        return ZcashError::BufferTooSmall;
      *in_out_size = writer.position;
      return ZcashError::Ok;
    }

    bool derive_and_verify_key(const HdPrivateNode &master,
                               const ZcashInput &input, uint32_t coin_type,
                               uint8_t out_private[kPrivateKeySize],
                               uint8_t out_public[kCompressedPublicKeySize])
    {
      if (coin_type >= kHardenedOffset || input.account >= kHardenedOffset ||
          input.change > 1 || input.address_index >= kHardenedOffset)
      {
        return false;
      }
      const uint32_t path[5] = {
          44U | kHardenedOffset,
          coin_type | kHardenedOffset,
          input.account | kHardenedOffset,
          input.change,
          input.address_index};
      HdPrivateNode current = master;
      for (size_t depth = 0; depth < 5; ++depth)
      {
        HdPrivateNode next;
        const WalletError result = hd_private_derive(&current, path[depth], &next);
        secure_zero(&current, sizeof(current));
        if (result != WalletError::Ok)
          return false;
        current = next;
      }
      uint8_t hash[kRipemd160Size];
      const bool public_ok =
          public_key_from_private(current.private_key, out_public) == WalletError::Ok &&
          crypto_hash160(out_public, kCompressedPublicKeySize, hash);
      bool script_ok = false;
      if (public_ok && p2pkh_script(input.script, input.script_size))
      {
        script_ok = crypto_constant_time_equal(hash, input.script + 3,
                                              kRipemd160Size);
      }
      else if (public_ok && p2sh_script(input.script, input.script_size))
      {
        // The redeem script must carry this wallet's own key and must be the
        // script the t3 address commits to; otherwise the device would be
        // signing for a script it cannot legitimately satisfy.
        script_ok =
            zcash_p2sh_redeem_commits(input.script, input.script_size,
                                      input.redeem, input.redeem_size) &&
            crypto_constant_time_equal(input.redeem + 1, out_public,
                                       kCompressedPublicKeySize);
      }
      memcpy(out_private, current.private_key, kPrivateKeySize);
      secure_zero(&current, sizeof(current));
      secure_zero(hash, sizeof(hash));
      return script_ok;
    }

    uint32_t estimated_vbytes(const ZcashSigningRequest &request)
    {
      // version+group, vin count, vout count, lock, expiry, valueBalance and
      // the three zero component counts.
      uint64_t size = 29;
      for (size_t index = 0; index < request.input_count; ++index)
      {
        // prevout + scriptSig length + push(sig) + push(pubkey|redeem) +
        // sequence. The worst-case DER signature is what the fee policy must
        // reserve, so a t3 input is costed with its real redeem size.
        const size_t pushed = request.inputs[index].redeem_size != 0
                                  ? request.inputs[index].redeem_size
                                  : kCompressedPublicKeySize;
        size += 36 + 1 + (1 + kZcashMaxSignatureSize) + 1 + pushed + 4;
      }
      size += static_cast<uint64_t>(request.output_count) * 34;
      return size > UINT32_MAX ? 0 : static_cast<uint32_t>(size);
    }

    bool decode_hex(const char *text, uint8_t *out, size_t capacity,
                    size_t *out_size)
    {
      if (text == nullptr || out == nullptr || out_size == nullptr)
        return false;
      const size_t length = strlen(text);
      if (length == 0 || (length & 1U) != 0 || length / 2 > capacity)
        return false;
      *out_size = length / 2;
      for (size_t index = 0; index < *out_size; ++index)
      {
        const char high = text[index * 2];
        const char low = text[index * 2 + 1];
        uint8_t high_value;
        uint8_t low_value;
        if (high >= '0' && high <= '9')
          high_value = static_cast<uint8_t>(high - '0');
        else if (high >= 'a' && high <= 'f')
          high_value = static_cast<uint8_t>(high - 'a' + 10);
        else if (high >= 'A' && high <= 'F')
          high_value = static_cast<uint8_t>(high - 'A' + 10);
        else
          return false;
        if (low >= '0' && low <= '9')
          low_value = static_cast<uint8_t>(low - '0');
        else if (low >= 'a' && low <= 'f')
          low_value = static_cast<uint8_t>(low - 'a' + 10);
        else if (low >= 'A' && low <= 'F')
          low_value = static_cast<uint8_t>(low - 'A' + 10);
        else
          return false;
        out[index] = static_cast<uint8_t>((high_value << 4) | low_value);
      }
      return true;
    }

#include "src/generated/ZcashZip243VectorsTest.inc"

  } // namespace

  ZcashError zcash_zip243_sighash_v4(const uint8_t *transaction,
                                     size_t transaction_size,
                                     const uint8_t *script_code,
                                     size_t script_code_size,
                                     int32_t input_index, uint32_t hash_type,
                                     uint64_t amount, uint32_t branch_id,
                                     uint8_t out_digest[kSha256Size])
  {
    if (transaction == nullptr || out_digest == nullptr ||
        (script_code == nullptr && script_code_size != 0) ||
        script_code_size > kMaxTransparentScriptSize)
    {
      return ZcashError::InvalidArgument;
    }
    const uint32_t base_type = hash_type & kSighashMask;
    const bool anyone_can_pay = (hash_type & kSighashAnyoneCanPay) != 0;
    if ((hash_type & ~(kSighashMask | kSighashAnyoneCanPay)) != 0 ||
        (base_type != kSighashAll && base_type != kSighashNone &&
         base_type != kSighashSingle))
    {
      return ZcashError::Unsupported;
    }
    TxView view;
    ZcashError result = parse_v4_transaction(transaction, transaction_size, &view,
                                             true);
    if (result != ZcashError::Ok)
      return result;
    if (input_index < -1 ||
        (input_index >= 0 &&
         static_cast<size_t>(input_index) >= view.input_count))
    {
      return ZcashError::InvalidArgument;
    }
    uint8_t hash_prevouts_value[kSha256Size] = {};
    uint8_t hash_sequence_value[kSha256Size] = {};
    uint8_t hash_outputs_value[kSha256Size] = {};
    uint8_t hash_joinsplits_value[kSha256Size] = {};
    uint8_t hash_shielded_spends_value[kSha256Size] = {};
    uint8_t hash_shielded_outputs_value[kSha256Size] = {};
    if (!anyone_can_pay)
    {
      result = hash_prevouts(view, hash_prevouts_value);
      if (result != ZcashError::Ok)
        return result;
    }
    if (!anyone_can_pay && base_type != kSighashSingle &&
        base_type != kSighashNone)
    {
      result = hash_sequence(view, hash_sequence_value);
      if (result != ZcashError::Ok)
        return result;
    }
    if (base_type != kSighashSingle && base_type != kSighashNone)
    {
      result = hash_outputs(view, nullptr, hash_outputs_value);
      if (result != ZcashError::Ok)
        return result;
    }
    else if (base_type == kSighashSingle && input_index >= 0 &&
             static_cast<size_t>(input_index) < view.output_count)
    {
      result = hash_outputs(view, &view.outputs[input_index],
                            hash_outputs_value);
      if (result != ZcashError::Ok)
        return result;
    }
    if (view.joinsplit_count > 0)
    {
      Blake2bState state;
      if (!blake2b_init_personal(
              &state, kSha256Size,
              reinterpret_cast<const uint8_t *>("ZcashJSplitsHash")))
      {
        return ZcashError::CryptoFailure;
      }
      blake2b_update(&state, transaction + view.joinsplit_offset,
                     view.joinsplit_count * kJoinSplitSize);
      blake2b_update(&state, view.joinsplit_pubkey, 32);
      if (!blake2b_final(&state, hash_joinsplits_value))
      {
        return ZcashError::CryptoFailure;
      }
    }
    if (view.shielded_spend_count > 0)
    {
      Blake2bState state;
      if (!blake2b_init_personal(
              &state, kSha256Size,
              reinterpret_cast<const uint8_t *>("ZcashSSpendsHash")))
      {
        return ZcashError::CryptoFailure;
      }
      for (size_t index = 0; index < view.shielded_spend_count; ++index)
      {
        blake2b_update(&state,
                       transaction + view.shielded_spend_offset +
                           index * kShieldedSpendSize,
                       kShieldedSpendSize - 64);
      }
      if (!blake2b_final(&state, hash_shielded_spends_value))
      {
        return ZcashError::CryptoFailure;
      }
    }
    if (view.shielded_output_count > 0)
    {
      Blake2bState state;
      if (!blake2b_init_personal(
              &state, kSha256Size,
              reinterpret_cast<const uint8_t *>("ZcashSOutputHash")))
      {
        return ZcashError::CryptoFailure;
      }
      blake2b_update(&state, transaction + view.shielded_output_offset,
                     view.shielded_output_count * kShieldedOutputSize);
      if (!blake2b_final(&state, hash_shielded_outputs_value))
      {
        return ZcashError::CryptoFailure;
      }
    }
    uint8_t personal[16] = {};
    memcpy(personal, "ZcashSigHash", 12);
    personal[12] = static_cast<uint8_t>(branch_id);
    personal[13] = static_cast<uint8_t>(branch_id >> 8);
    personal[14] = static_cast<uint8_t>(branch_id >> 16);
    personal[15] = static_cast<uint8_t>(branch_id >> 24);
    Blake2bState sighash;
    if (!blake2b_init_personal(&sighash, kSha256Size, personal))
    {
      return ZcashError::CryptoFailure;
    }
    uint8_t bytes[8];
    for (size_t index = 0; index < 4; ++index)
    {
      bytes[index] = static_cast<uint8_t>(view.version >> (index * 8));
    }
    blake2b_update(&sighash, bytes, 4);
    for (size_t index = 0; index < 4; ++index)
    {
      bytes[index] = static_cast<uint8_t>(view.version_group_id >> (index * 8));
    }
    blake2b_update(&sighash, bytes, 4);
    blake2b_update(&sighash, hash_prevouts_value, sizeof(hash_prevouts_value));
    blake2b_update(&sighash, hash_sequence_value, sizeof(hash_sequence_value));
    blake2b_update(&sighash, hash_outputs_value, sizeof(hash_outputs_value));
    blake2b_update(&sighash, hash_joinsplits_value,
                   sizeof(hash_joinsplits_value));
    blake2b_update(&sighash, hash_shielded_spends_value,
                   sizeof(hash_shielded_spends_value));
    blake2b_update(&sighash, hash_shielded_outputs_value,
                   sizeof(hash_shielded_outputs_value));
    for (size_t index = 0; index < 4; ++index)
    {
      bytes[index] = static_cast<uint8_t>(view.lock_time >> (index * 8));
    }
    blake2b_update(&sighash, bytes, 4);
    for (size_t index = 0; index < 4; ++index)
    {
      bytes[index] = static_cast<uint8_t>(view.expiry_height >> (index * 8));
    }
    blake2b_update(&sighash, bytes, 4);
    const uint64_t value_balance = static_cast<uint64_t>(view.value_balance);
    for (size_t index = 0; index < 8; ++index)
    {
      bytes[index] = static_cast<uint8_t>(value_balance >> (index * 8));
    }
    blake2b_update(&sighash, bytes, 8);
    for (size_t index = 0; index < 4; ++index)
    {
      bytes[index] = static_cast<uint8_t>(hash_type >> (index * 8));
    }
    blake2b_update(&sighash, bytes, 4);
    if (input_index >= 0)
    {
      const TxInputView &input = view.inputs[input_index];
      blake2b_update(&sighash, input.prevout, 36);
      if (script_code_size < 0xfd)
      {
        const uint8_t size_byte = static_cast<uint8_t>(script_code_size);
        blake2b_update(&sighash, &size_byte, 1);
      }
      else
      {
        uint8_t size_bytes[3] = {0xfd, static_cast<uint8_t>(script_code_size),
                                 static_cast<uint8_t>(script_code_size >> 8)};
        blake2b_update(&sighash, size_bytes, sizeof(size_bytes));
      }
      blake2b_update(&sighash, script_code, script_code_size);
      for (size_t index = 0; index < 8; ++index)
      {
        bytes[index] = static_cast<uint8_t>(amount >> (index * 8));
      }
      blake2b_update(&sighash, bytes, 8);
      for (size_t index = 0; index < 4; ++index)
      {
        bytes[index] = static_cast<uint8_t>(input.sequence >> (index * 8));
      }
      blake2b_update(&sighash, bytes, 4);
    }
    const bool hashed = blake2b_final(&sighash, out_digest);
    secure_zero(hash_prevouts_value, sizeof(hash_prevouts_value));
    secure_zero(hash_sequence_value, sizeof(hash_sequence_value));
    secure_zero(hash_outputs_value, sizeof(hash_outputs_value));
    secure_zero(hash_joinsplits_value, sizeof(hash_joinsplits_value));
    secure_zero(hash_shielded_spends_value, sizeof(hash_shielded_spends_value));
    secure_zero(hash_shielded_outputs_value, sizeof(hash_shielded_outputs_value));
    secure_zero(personal, sizeof(personal));
    return hashed ? ZcashError::Ok : ZcashError::CryptoFailure;
  }

  bool zcash_p2sh_redeem_commits(const uint8_t *script, size_t script_size,
                                 const uint8_t *redeem, size_t redeem_size)
  {
    if (!p2sh_script(script, script_size) ||
        !p2pk_redeem_script(redeem, redeem_size))
    {
      return false;
    }
    uint8_t hash[kRipemd160Size];
    if (!crypto_hash160(redeem, redeem_size, hash))
      return false;
    const bool matches =
        crypto_constant_time_equal(hash, script + 2, kRipemd160Size);
    secure_zero(hash, sizeof(hash));
    return matches;
  }

  ZcashError zcash_parse_review_payload(const uint8_t *data, size_t size,
                                        const ZcashChainParams &chain,
                                        ZcashSigningRequest *out)
  {
    if (data == nullptr || out == nullptr || chain.network_id == nullptr ||
        chain.p2pkh_version == 0 || chain.p2sh_version == 0 ||
        chain.branch_id == 0 || chain.derivation_coin_type == 0)
    {
      return ZcashError::InvalidArgument;
    }
    const ZcashNetworkPolicy *policy =
        find_zcash_network_policy(chain.network_id);
    if (policy == nullptr || policy->branch_id != chain.branch_id)
    {
      return ZcashError::Unsupported;
    }
    Cursor cursor = {data, size, 0};
    const uint8_t *magic;
    uint32_t branch_id;
    uint32_t transaction_size;
    if (!read_bytes(&cursor, sizeof(kZcashPayloadMagic), &magic) ||
        magic == nullptr)
    {
      return ZcashError::NonCanonical;
    }
    const bool has_redeem_field =
        memcmp(magic, kZcashPayloadMagicRedeem,
               sizeof(kZcashPayloadMagicRedeem)) == 0;
    if (!has_redeem_field &&
        memcmp(magic, kZcashPayloadMagic, sizeof(kZcashPayloadMagic)) != 0)
    {
      return ZcashError::NonCanonical;
    }
    if (!read_u32(&cursor, &branch_id))
      return ZcashError::Truncated;
    if (branch_id != chain.branch_id)
      return ZcashError::Unsupported;
    if (!read_u32(&cursor, &transaction_size))
      return ZcashError::Truncated;
    if (transaction_size == 0)
      return ZcashError::MissingField;
    if (transaction_size > kZcashMaxTransactionSize)
      return ZcashError::TooLarge;
    const uint8_t *transaction;
    if (!read_bytes(&cursor, transaction_size, &transaction))
    {
      return ZcashError::Truncated;
    }
    TxView view;
    ZcashError result = parse_v4_transaction(transaction, transaction_size,
                                             &view, false);
    if (result != ZcashError::Ok)
      return result;
    if (view.input_count == 0 || view.output_count == 0)
    {
      return ZcashError::MissingField;
    }
    if (view.value_balance != 0 || view.shielded_spend_count != 0 ||
        view.shielded_output_count != 0 || view.joinsplit_count != 0)
    {
      return ZcashError::Unsupported;
    }
    const uint8_t *payload_input_count;
    if (!read_bytes(&cursor, 1, &payload_input_count))
    {
      return ZcashError::Truncated;
    }
    if (*payload_input_count != view.input_count)
    {
      return ZcashError::NonCanonical;
    }
    ZcashSigningRequest parsed = {};
    parsed.chain = chain;
    parsed.version = view.version;
    parsed.version_group_id = view.version_group_id;
    parsed.lock_time = view.lock_time;
    parsed.expiry_height = view.expiry_height;
    parsed.value_balance = view.value_balance;
    parsed.input_count = static_cast<uint8_t>(view.input_count);
    parsed.output_count = static_cast<uint8_t>(view.output_count);
    for (size_t index = 0; index < view.input_count; ++index)
    {
      ZcashInput &input = parsed.inputs[index];
      uint64_t value;
      const uint8_t *script_size;
      if (!read_u64(&cursor, &value) ||
          !read_bytes(&cursor, 1, &script_size))
      {
        return ZcashError::Truncated;
      }
      if (value > policy->max_zats)
        return ZcashError::InvalidAmount;
      if (*script_size > kZcashMaxScriptSize)
        return ZcashError::Unsupported;
      const uint8_t *script;
      if (!read_bytes(&cursor, *script_size, &script))
      {
        return ZcashError::Truncated;
      }
      const bool prevout_is_p2pkh = p2pkh_script(script, *script_size);
      const bool prevout_is_p2sh = p2sh_script(script, *script_size);
      if (!prevout_is_p2pkh && !prevout_is_p2sh)
        return ZcashError::Unsupported;
      uint32_t account;
      uint32_t address_index;
      const uint8_t *change;
      if (!read_u32(&cursor, &account) || !read_bytes(&cursor, 1, &change) ||
          !read_u32(&cursor, &address_index))
      {
        return ZcashError::Truncated;
      }
      if (has_redeem_field)
      {
        const uint8_t *redeem_size;
        if (!read_bytes(&cursor, 1, &redeem_size))
          return ZcashError::Truncated;
        if (*redeem_size > kZcashMaxRedeemScriptSize)
          return ZcashError::Unsupported;
        if (*redeem_size != 0)
        {
          const uint8_t *redeem;
          if (!read_bytes(&cursor, *redeem_size, &redeem))
            return ZcashError::Truncated;
          memcpy(input.redeem, redeem, *redeem_size);
          input.redeem_size = *redeem_size;
        }
      }
      if (prevout_is_p2pkh && input.redeem_size != 0)
        return ZcashError::NonCanonical;
      if (prevout_is_p2sh)
      {
        // A t3 prevout needs the redeem script that the address commits to.
        // Without it the device could neither hash the correct scriptCode nor
        // build a spendable scriptSig.
        if (input.redeem_size == 0)
          return ZcashError::Unsupported;
        if (!zcash_p2sh_redeem_commits(script, *script_size, input.redeem,
                                       input.redeem_size))
        {
          // A canonical single-key redeem script that does not match the
          // address is a wrong-wallet request; any other form is unsupported
          // rather than something to guess at.
          return p2pk_redeem_script(input.redeem, input.redeem_size)
                     ? ZcashError::InvalidArgument
                     : ZcashError::Unsupported;
        }
      }
      if (account >= kHardenedOffset || *change > 1 ||
          address_index >= kHardenedOffset)
      {
        return ZcashError::InvalidArgument;
      }
      memcpy(input.previous_txid, view.inputs[index].prevout, 32);
      input.previous_index = static_cast<uint32_t>(
                                 view.inputs[index].prevout[32]) |
                             (static_cast<uint32_t>(view.inputs[index].prevout[33]) << 8) |
                             (static_cast<uint32_t>(view.inputs[index].prevout[34]) << 16) |
                             (static_cast<uint32_t>(view.inputs[index].prevout[35]) << 24);
      input.sequence = view.inputs[index].sequence;
      input.value = value;
      input.script_size = *script_size;
      memcpy(input.script, script, *script_size);
      input.account = account;
      input.change = *change;
      input.address_index = address_index;
      if (!add_u64(parsed.input_total, value, &parsed.input_total))
      {
        return ZcashError::InvalidAmount;
      }
    }
    if (cursor.position != cursor.size)
      return ZcashError::NonCanonical;
    for (size_t index = 0; index < parsed.input_count; ++index)
    {
      for (size_t other = index + 1; other < parsed.input_count; ++other)
      {
        if (parsed.inputs[index].previous_index ==
                parsed.inputs[other].previous_index &&
            crypto_constant_time_equal(parsed.inputs[index].previous_txid,
                                       parsed.inputs[other].previous_txid, 32))
        {
          return ZcashError::NonCanonical;
        }
      }
    }
    for (size_t index = 0; index < view.output_count; ++index)
    {
      ZcashOutput &output = parsed.outputs[index];
      if (view.outputs[index].script_size > kZcashMaxScriptSize)
      {
        return ZcashError::Unsupported;
      }
      output.value = view.outputs[index].value;
      output.script_size = static_cast<uint8_t>(view.outputs[index].script_size);
      memcpy(output.script, view.outputs[index].script, output.script_size);
      if (!transparent_script(output.script, output.script_size) ||
          address_zcash_transparent_from_script(
              chain.p2pkh_version, chain.p2sh_version, output.script,
              output.script_size, output.address, sizeof(output.address)) !=
              WalletError::Ok)
      {
        return ZcashError::Unsupported;
      }
      if (!add_u64(parsed.output_total, output.value, &parsed.output_total))
      {
        return ZcashError::InvalidAmount;
      }
    }
    if (parsed.input_total < parsed.output_total)
    {
      return ZcashError::InvalidAmount;
    }
    parsed.fee = parsed.input_total - parsed.output_total;
    parsed.estimated_vbytes = estimated_vbytes(parsed);
    if (parsed.estimated_vbytes == 0 ||
        parsed.fee > HEXWALLET_MAX_ZCASH_FEE_ZATS ||
        parsed.fee > HEXWALLET_MAX_ZCASH_FEE_RATE *
                         static_cast<uint64_t>(parsed.estimated_vbytes))
    {
      return ZcashError::FeePolicy;
    }
    if (!crypto_sha256(data, size, parsed.request_hash))
    {
      return ZcashError::CryptoFailure;
    }
    *out = parsed;
    return ZcashError::Ok;
  }

  ZcashError zcash_sign_request(const ZcashSigningRequest &request,
                                const HdPrivateNode &master,
                                uint8_t *out_transaction, size_t *in_out_size)
  {
    if (out_transaction == nullptr || in_out_size == nullptr ||
        request.input_count == 0 || request.input_count > kZcashMaxInputs ||
        request.output_count == 0 || request.output_count > kZcashMaxOutputs ||
        request.version != kZcashV4Version ||
        request.version_group_id != kZcashSaplingVersionGroupId ||
        request.value_balance != 0 || request.chain.branch_id == 0 ||
        request.chain.derivation_coin_type == 0)
    {
      return ZcashError::InvalidArgument;
    }
    const ZcashNetworkPolicy *zcash_policy =
        find_zcash_network_policy(request.chain.network_id);
    if (zcash_policy == nullptr ||
        zcash_policy->branch_id != request.chain.branch_id)
    {
      return ZcashError::Unsupported;
    }
    for (size_t index = 0; index < request.input_count; ++index)
    {
      for (size_t other = index + 1; other < request.input_count; ++other)
      {
        if (request.inputs[index].previous_index ==
                request.inputs[other].previous_index &&
            crypto_constant_time_equal(request.inputs[index].previous_txid,
                                       request.inputs[other].previous_txid, 32))
        {
          return ZcashError::NonCanonical;
        }
      }
    }
    uint64_t input_total = 0;
    uint64_t output_total = 0;
    for (size_t index = 0; index < request.input_count; ++index)
    {
      const ZcashInput &input = request.inputs[index];
      const bool p2pkh = p2pkh_script(input.script, input.script_size);
      const bool p2sh = p2sh_script(input.script, input.script_size);
      if (input.value > zcash_policy->max_zats ||
          (!p2pkh && !p2sh) ||
          (p2pkh && input.redeem_size != 0) ||
          (p2sh && !p2pk_redeem_script(input.redeem, input.redeem_size)) ||
          !add_u64(input_total, input.value, &input_total))
      {
        return ZcashError::WrongWallet;
      }
    }
    for (size_t index = 0; index < request.output_count; ++index)
    {
      const ZcashOutput &output = request.outputs[index];
      if (output.value > zcash_policy->max_zats ||
          !transparent_script(output.script, output.script_size) ||
          !add_u64(output_total, output.value, &output_total))
      {
        return ZcashError::Unsupported;
      }
    }
    const uint32_t expected_vbytes = estimated_vbytes(request);
    if (input_total < output_total || input_total != request.input_total ||
        output_total != request.output_total ||
        input_total - output_total != request.fee ||
        expected_vbytes == 0 || request.estimated_vbytes != expected_vbytes ||
        request.fee > HEXWALLET_MAX_ZCASH_FEE_ZATS ||
        request.fee > HEXWALLET_MAX_ZCASH_FEE_RATE *
                          static_cast<uint64_t>(request.estimated_vbytes))
    {
      return ZcashError::FeePolicy;
    }
    uint8_t unsigned_transaction[kZcashMaxTransactionSize];
    size_t unsigned_size = sizeof(unsigned_transaction);
    ZcashError result = serialize_request(request, nullptr, nullptr, nullptr,
                                          unsigned_transaction, &unsigned_size);
    if (result != ZcashError::Ok)
    {
      secure_zero(unsigned_transaction, sizeof(unsigned_transaction));
      return result;
    }
    uint8_t signatures[kZcashMaxInputs][kZcashMaxScriptSigSize] = {};
    uint8_t signature_sizes[kZcashMaxInputs] = {};
    uint8_t public_keys[kZcashMaxInputs][kCompressedPublicKeySize] = {};
    for (size_t index = 0; index < request.input_count; ++index)
    {
      uint8_t private_key[kPrivateKeySize];
      if (!derive_and_verify_key(master, request.inputs[index],
                                 request.chain.derivation_coin_type, private_key,
                                 public_keys[index]))
      {
        secure_zero(private_key, sizeof(private_key));
        secure_zero(signatures, sizeof(signatures));
        secure_zero(public_keys, sizeof(public_keys));
        secure_zero(unsigned_transaction, sizeof(unsigned_transaction));
        return ZcashError::WrongWallet;
      }
      // P2SH spends commit the redeem script as scriptCode; P2PKH commits the
      // prevout script itself.
      const uint8_t *script_code = request.inputs[index].script;
      size_t script_code_size = request.inputs[index].script_size;
      if (request.inputs[index].redeem_size != 0)
      {
        script_code = request.inputs[index].redeem;
        script_code_size = request.inputs[index].redeem_size;
      }
      uint8_t digest[kSha256Size];
      result = zcash_zip243_sighash_v4(
          unsigned_transaction, unsigned_size, script_code, script_code_size,
          static_cast<int32_t>(index), kSighashAll,
          request.inputs[index].value, request.chain.branch_id, digest);
      size_t der_size = sizeof(signatures[index]) - 1;
      if (result == ZcashError::Ok)
      {
        result = sign_digest(private_key, digest, signatures[index], &der_size);
      }
      if (result == ZcashError::Ok && der_size > kZcashMaxDerSignatureSize)
      {
        result = ZcashError::BufferTooSmall;
      }
      secure_zero(private_key, sizeof(private_key));
      secure_zero(digest, sizeof(digest));
      if (result != ZcashError::Ok || der_size + 1 > sizeof(signatures[index]))
      {
        secure_zero(signatures, sizeof(signatures));
        secure_zero(public_keys, sizeof(public_keys));
        secure_zero(unsigned_transaction, sizeof(unsigned_transaction));
        return result == ZcashError::Ok ? ZcashError::BufferTooSmall : result;
      }
      signatures[index][der_size] = static_cast<uint8_t>(kSighashAll);
      signature_sizes[index] = static_cast<uint8_t>(der_size + 1);
    }
    secure_zero(unsigned_transaction, sizeof(unsigned_transaction));
    result = serialize_request(request, signatures, signature_sizes, public_keys,
                               out_transaction, in_out_size);
    secure_zero(signatures, sizeof(signatures));
    secure_zero(signature_sizes, sizeof(signature_sizes));
    secure_zero(public_keys, sizeof(public_keys));
    return result;
  }

  const char *zcash_error_text(ZcashError error)
  {
    switch (error)
    {
    case ZcashError::Ok:
      return "ok";
    case ZcashError::InvalidArgument:
      return "invalid-argument";
    case ZcashError::Truncated:
      return "truncated";
    case ZcashError::NonCanonical:
      return "non-canonical";
    case ZcashError::Unsupported:
      return "unsupported";
    case ZcashError::TooLarge:
      return "too-large";
    case ZcashError::MissingField:
      return "missing-field";
    case ZcashError::DuplicateField:
      return "duplicate-field";
    case ZcashError::WrongWallet:
      return "wrong-wallet";
    case ZcashError::InvalidAmount:
      return "invalid-amount";
    case ZcashError::FeePolicy:
      return "fee-policy";
    case ZcashError::CryptoFailure:
      return "crypto-failure";
    case ZcashError::BufferTooSmall:
      return "buffer-too-small";
    }
    return "unknown";
  }

  void clear_zcash_request(ZcashSigningRequest *request)
  {
    if (request != nullptr)
      secure_zero(request, sizeof(*request));
  }

  bool run_zcash_sighash_self_tests()
  {
    // Official ZIP-243 test vector 3: a transparent v4 testnet transaction with
    // nIn=0, SIGHASH_ALL, amount 0.5 ZEC. Source: zcash/zips zip-0243.rst.
    static const char kOfficialTransaction[] =
        "0400008085202f8901"
        "a8c685478265f4c14dada651969c45a65e1aeb8cd6791f2f5bb6a1d9952104d9"
        "01000000"
        "6b483045022100a61e5d557568c2ddc1d9b03a7173c6ce7c996c4daecab007ac8f34bee01e6b9702204d38fdc0bcf2728a69fde78462a10fb45a9baa27873e6a5fc45fb5c76764202a01210365ffea3efa3908918a8b8627724af852fc9b86d7375b103ab0543cf418bcaa7f"
        "feffffff"
        "02"
        "005a6202000000001976a9148132712c3ff19f3a151234616777420a6d7ef22688ac"
        "8b959800000000001976a9145453e4698f02a38abdaa521cd1ff2dee6fac187188ac"
        "29b0040048b00400"
        "0000000000000000"
        "000000";
    static const uint8_t kScriptCode[25] = {
        0x76, 0xa9, 0x14, 0x50, 0x71, 0x73, 0x52, 0x7b, 0x4c, 0x33,
        0x18, 0xa2, 0xae, 0xcd, 0x79, 0x3b, 0xf1, 0xcf, 0xed, 0x70,
        0x59, 0x50, 0xcf, 0x88, 0xac};
    static const uint8_t kExpectedDigest[kSha256Size] = {
        0xf3, 0x14, 0x8f, 0x80, 0xdf, 0xab, 0x5e, 0x57,
        0x3d, 0x5e, 0xdf, 0xe7, 0xa8, 0x50, 0xf5, 0xfd,
        0x39, 0x23, 0x4f, 0x80, 0xb5, 0x42, 0x9d, 0x3a,
        0x57, 0xed, 0xcc, 0x11, 0xe3, 0x4c, 0x58, 0x5b};
    // The boot self-test runs on the loop task's 32 KiB stack. Keep the large
    // review buffers in BSS; the signing selftest still has the full stack for
    // mbedtls.
    static uint8_t transaction[4096];
    static uint8_t scratch[4096];
    size_t transaction_size = 0;
    bool passed = decode_hex(kOfficialTransaction, transaction,
                             sizeof(transaction), &transaction_size);
    uint8_t digest[kSha256Size] = {};
    passed = passed &&
             zcash_zip243_sighash_v4(transaction, transaction_size, kScriptCode,
                                     sizeof(kScriptCode), 0, kSighashAll,
                                     50000000, 0x76b809bb, digest) ==
                 ZcashError::Ok &&
             crypto_constant_time_equal(digest, kExpectedDigest,
                                        sizeof(kExpectedDigest));
    // Published zcash-test-vectors rows 2-4 additionally exercise
    // NOT_AN_INPUT, SIGHASH_NONE, shielded spend/output hashing and JoinSplits.
    for (size_t index = 0; index < sizeof(kZip243Vectors) / sizeof(kZip243Vectors[0]); ++index)
    {
      const ZcashSighashVector &vector = kZip243Vectors[index];
      uint8_t vector_digest[kSha256Size] = {};
      passed = passed &&
               zcash_zip243_sighash_v4(
                   vector.transaction, vector.transaction_size,
                   vector.script_code, vector.script_code_size,
                   vector.input_index, vector.hash_type, vector.amount,
                   vector.branch_id, vector_digest) == ZcashError::Ok &&
               crypto_constant_time_equal(vector_digest, vector.digest,
                                          kSha256Size);
      secure_zero(vector_digest, sizeof(vector_digest));
    }
    // Rebuild the same transaction without a scriptSig so it is a valid signing
    // request. The branch id is not serialized in v4; the chain policy supplies
    // the currently active one.
    const ZcashChainParams chain = {
        "zec", 0x1cb8, 0x1cbd, 0x5437f330, 133};
    static const uint8_t kPrevout[36] = {
        0xa8, 0xc6, 0x85, 0x47, 0x82, 0x65, 0xf4, 0xc1,
        0x4d, 0xad, 0xa6, 0x51, 0x96, 0x9c, 0x45, 0xa6,
        0x5e, 0x1a, 0xeb, 0x8c, 0xd6, 0x79, 0x1f, 0x2f,
        0x5b, 0xb6, 0xa1, 0xd9, 0x95, 0x21, 0x04, 0xd9,
        0x01, 0x00, 0x00, 0x00};
    static const uint8_t kOutputA[25] = {
        0x76, 0xa9, 0x14, 0x81, 0x32, 0x71, 0x2c, 0x3f, 0xf1, 0x9f,
        0x3a, 0x15, 0x12, 0x34, 0x61, 0x67, 0x77, 0x42, 0x0a, 0x6d,
        0x7e, 0xf2, 0x26, 0x88, 0xac};
    static const uint8_t kOutputB[25] = {
        0x76, 0xa9, 0x14, 0x54, 0x53, 0xe4, 0x69, 0x8f, 0x02, 0xa3,
        0x8a, 0xbd, 0xaa, 0x52, 0x1c, 0xd1, 0xff, 0x2d, 0xee, 0x6f,
        0xac, 0x18, 0x71, 0x88, 0xac};
    uint8_t unsigned_transaction[256];
    Writer unsigned_writer = {unsigned_transaction,
                              sizeof(unsigned_transaction), 0};
    bool built = write_u32(&unsigned_writer, kZcashV4Version) &&
                 write_u32(&unsigned_writer, kZcashSaplingVersionGroupId) &&
                 write_compact_size(&unsigned_writer, 1) &&
                 write_bytes(&unsigned_writer, kPrevout, sizeof(kPrevout)) &&
                 write_compact_size(&unsigned_writer, 0) &&
                 write_u32(&unsigned_writer, 0xfffffffeU) &&
                 write_compact_size(&unsigned_writer, 2) &&
                 write_u64(&unsigned_writer, 40000000) &&
                 write_compact_size(&unsigned_writer, sizeof(kOutputA)) &&
                 write_bytes(&unsigned_writer, kOutputA, sizeof(kOutputA)) &&
                 write_u64(&unsigned_writer, 9999755) &&
                 write_compact_size(&unsigned_writer, sizeof(kOutputB)) &&
                 write_bytes(&unsigned_writer, kOutputB, sizeof(kOutputB)) &&
                 write_u32(&unsigned_writer, 307241) &&
                 write_u32(&unsigned_writer, 307272) &&
                 write_u64(&unsigned_writer, 0) &&
                 write_compact_size(&unsigned_writer, 0) &&
                 write_compact_size(&unsigned_writer, 0) &&
                 write_compact_size(&unsigned_writer, 0);
    // No official ZIP-243 vector covers P2SH, so this digest was produced by a
    // separate Python BLAKE2b implementation of ZIP-243 that first reproduced
    // the official transparent vector above byte for byte. It pins the t3 rule:
    // the scriptCode is the redeem script, not the previous scriptPubKey.
    static const uint8_t kP2shScriptCode[kZcashMaxRedeemScriptSize] = {
        0x21, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0xac};
    static const uint8_t kP2shDigest[kSha256Size] = {
        0xaa, 0xbf, 0x33, 0xb8, 0x7a, 0xce, 0xeb, 0xc6,
        0x59, 0xf8, 0xb3, 0x2a, 0x5d, 0xcc, 0xa5, 0x6a,
        0xf5, 0x78, 0xc8, 0xfe, 0x71, 0xae, 0xa0, 0x21,
        0x93, 0xd3, 0x73, 0xd2, 0xd4, 0x36, 0x62, 0xe6};
    uint8_t p2sh_digest[kSha256Size] = {};
    passed = passed && built &&
             zcash_zip243_sighash_v4(unsigned_transaction,
                                     unsigned_writer.position, kP2shScriptCode,
                                     sizeof(kP2shScriptCode), 0, kSighashAll,
                                     50000000, chain.branch_id,
                                     p2sh_digest) == ZcashError::Ok &&
             crypto_constant_time_equal(p2sh_digest, kP2shDigest,
                                        sizeof(kP2shDigest));
    secure_zero(p2sh_digest, sizeof(p2sh_digest));
    static uint8_t payload[4096];
    Writer payload_writer = {payload, sizeof(payload), 0};
    built = built &&
            write_bytes(&payload_writer, kZcashPayloadMagic,
                        sizeof(kZcashPayloadMagic)) &&
            write_u32(&payload_writer, chain.branch_id) &&
            write_u32(&payload_writer,
                      static_cast<uint32_t>(unsigned_writer.position)) &&
            write_bytes(&payload_writer, unsigned_transaction,
                        unsigned_writer.position) &&
            write_compact_size(&payload_writer, 1) &&
            write_u64(&payload_writer, 50000000) &&
            write_compact_size(&payload_writer, sizeof(kScriptCode)) &&
            write_bytes(&payload_writer, kScriptCode, sizeof(kScriptCode)) &&
            write_u32(&payload_writer, 0) &&
            write_bytes(&payload_writer, "\0", 1) &&
            write_u32(&payload_writer, 0);
    const size_t payload_size = payload_writer.position;
    ZcashSigningRequest parsed;
    passed = passed && built && payload_size <= sizeof(payload) &&
             zcash_parse_review_payload(payload, payload_size, chain, &parsed) ==
                 ZcashError::Ok &&
             parsed.input_count == 1 && parsed.output_count == 2 &&
             parsed.input_total == 50000000 && parsed.output_total == 49999755 &&
             parsed.fee == 245 && parsed.estimated_vbytes == 246 &&
             parsed.outputs[0].address[0] == 't' &&
             parsed.outputs[1].address[0] == 't';
    // ZEC5 t3 prevout. The redeem script travels in the request and must hash
    // to the scriptPubKey; the fee budget grows by the larger scriptSig.
    static uint8_t p2sh_script_pubkey[kP2shScriptSize] = {0xa9, 0x14};
    uint8_t redeem_hash[kRipemd160Size] = {};
    bool redeem_ready =
        crypto_hash160(kP2shScriptCode, sizeof(kP2shScriptCode), redeem_hash);
    p2sh_script_pubkey[22] = 0x87;
    memcpy(p2sh_script_pubkey + 2, redeem_hash, sizeof(redeem_hash));
    const auto build_redeem_payload =
        [&](const uint8_t magic[4], const uint8_t *script, size_t script_size,
            const uint8_t *redeem, size_t redeem_size, size_t *out_size)
    {
      Writer writer = {scratch, sizeof(scratch), 0};
      const uint8_t size_byte = static_cast<uint8_t>(redeem_size);
      const bool ok =
          write_bytes(&writer, magic, 4) &&
          write_u32(&writer, chain.branch_id) &&
          write_u32(&writer, static_cast<uint32_t>(unsigned_writer.position)) &&
          write_bytes(&writer, unsigned_transaction, unsigned_writer.position) &&
          write_compact_size(&writer, 1) &&
          write_u64(&writer, 50000000) &&
          write_compact_size(&writer, script_size) &&
          write_bytes(&writer, script, script_size) &&
          write_u32(&writer, 0) &&
          write_bytes(&writer, "\0", 1) &&
          write_u32(&writer, 0) &&
          write_bytes(&writer, &size_byte, 1) &&
          write_bytes(&writer, redeem, redeem_size);
      *out_size = writer.position;
      return ok;
    };
    size_t redeem_payload_size = 0;
    ZcashSigningRequest p2sh_parsed;
    ZcashSigningRequest rejected;
    passed = passed && redeem_ready &&
             build_redeem_payload(kZcashPayloadMagicRedeem, p2sh_script_pubkey,
                                  sizeof(p2sh_script_pubkey), kP2shScriptCode,
                                  sizeof(kP2shScriptCode),
                                  &redeem_payload_size) &&
             zcash_parse_review_payload(scratch, redeem_payload_size, chain,
                                        &p2sh_parsed) == ZcashError::Ok &&
             p2sh_parsed.inputs[0].redeem_size == kZcashMaxRedeemScriptSize &&
             p2sh_parsed.estimated_vbytes == 248;
    clear_zcash_request(&p2sh_parsed);
    // ZEC4 cannot express a t3 prevout: signing it without the redeem script
    // would commit the wrong scriptCode.
    size_t probe_size = 0;
    passed = passed && redeem_ready &&
             build_redeem_payload(kZcashPayloadMagic, p2sh_script_pubkey,
                                  sizeof(p2sh_script_pubkey), nullptr, 0,
                                  &probe_size) &&
             zcash_parse_review_payload(scratch, probe_size, chain, &rejected) ==
                 ZcashError::Unsupported;
    // A canonical redeem script for a different key cannot match the address.
    uint8_t wrong_redeem[kZcashMaxRedeemScriptSize];
    memcpy(wrong_redeem, kP2shScriptCode, sizeof(wrong_redeem));
    wrong_redeem[5] ^= 0x01;
    passed = passed && redeem_ready &&
             build_redeem_payload(kZcashPayloadMagicRedeem, p2sh_script_pubkey,
                                  sizeof(p2sh_script_pubkey), wrong_redeem,
                                  sizeof(wrong_redeem), &probe_size) &&
             zcash_parse_review_payload(scratch, probe_size, chain, &rejected) ==
                 ZcashError::InvalidArgument;
    secure_zero(wrong_redeem, sizeof(wrong_redeem));
    // Anything that is not single-key CHECKSIG is refused, not guessed at.
    uint8_t multisig_redeem[kZcashMaxRedeemScriptSize] = {0x51, 0x21};
    passed = passed && redeem_ready &&
             build_redeem_payload(kZcashPayloadMagicRedeem, p2sh_script_pubkey,
                                  sizeof(p2sh_script_pubkey), multisig_redeem,
                                  sizeof(multisig_redeem), &probe_size) &&
             zcash_parse_review_payload(scratch, probe_size, chain, &rejected) ==
                 ZcashError::Unsupported;
    secure_zero(multisig_redeem, sizeof(multisig_redeem));
    // A P2PKH prevout must not smuggle a redeem script in.
    passed = passed && redeem_ready &&
             build_redeem_payload(kZcashPayloadMagicRedeem, kScriptCode,
                                  sizeof(kScriptCode), kP2shScriptCode,
                                  sizeof(kP2shScriptCode), &probe_size) &&
             zcash_parse_review_payload(scratch, probe_size, chain, &rejected) ==
                 ZcashError::NonCanonical;
    secure_zero(redeem_hash, sizeof(redeem_hash));
    secure_zero(p2sh_script_pubkey, sizeof(p2sh_script_pubkey));
    // Redeem/address binding over synthetic key material: pure hashing, so the
    // rule is pinned on every build even though key derivation is device-only.
    {
      uint8_t synthetic_pubkey[kCompressedPublicKeySize] = {0x02};
      for (size_t index = 1; index < kCompressedPublicKeySize; ++index)
        synthetic_pubkey[index] = static_cast<uint8_t>(index);
      uint8_t synthetic_redeem[kZcashMaxRedeemScriptSize] = {0x21};
      memcpy(synthetic_redeem + 1, synthetic_pubkey, sizeof(synthetic_pubkey));
      synthetic_redeem[kZcashMaxRedeemScriptSize - 1] = 0xac;
      uint8_t synthetic_hash[kRipemd160Size] = {};
      uint8_t synthetic_script[kP2shScriptSize] = {0xa9, 0x14};
      synthetic_script[22] = 0x87;
      const bool hashed = crypto_hash160(synthetic_redeem,
                                         sizeof(synthetic_redeem),
                                         synthetic_hash);
      memcpy(synthetic_script + 2, synthetic_hash, sizeof(synthetic_hash));
      passed = passed && hashed &&
               zcash_p2sh_redeem_commits(synthetic_script,
                                         sizeof(synthetic_script),
                                         synthetic_redeem,
                                         sizeof(synthetic_redeem));
      // The same address with a different key must not pass.
      synthetic_redeem[5] ^= 0x01;
      passed = passed && !zcash_p2sh_redeem_commits(synthetic_script,
                                                    sizeof(synthetic_script),
                                                    synthetic_redeem,
                                                    sizeof(synthetic_redeem));
      synthetic_redeem[5] ^= 0x01;
      // A multisig-shaped or truncated script is not a single-key redeem.
      uint8_t multisig_like[kZcashMaxRedeemScriptSize] = {0x51, 0x21};
      passed = passed && !zcash_p2sh_redeem_commits(synthetic_script,
                                                    sizeof(synthetic_script),
                                                    multisig_like,
                                                    sizeof(multisig_like));
      passed = passed && !zcash_p2sh_redeem_commits(synthetic_script,
                                                    sizeof(synthetic_script),
                                                    synthetic_redeem,
                                                    sizeof(synthetic_redeem) - 1);
      // A P2PKH prevout never uses a redeem script.
      passed = passed && !zcash_p2sh_redeem_commits(kScriptCode,
                                                    sizeof(kScriptCode),
                                                    synthetic_redeem,
                                                    sizeof(synthetic_redeem));
      secure_zero(synthetic_redeem, sizeof(synthetic_redeem));
      secure_zero(synthetic_pubkey, sizeof(synthetic_pubkey));
      secure_zero(synthetic_hash, sizeof(synthetic_hash));
      secure_zero(synthetic_script, sizeof(synthetic_script));
      secure_zero(multisig_like, sizeof(multisig_like));
    }
    // The published signed transaction must be refused by the signing parser
    // because a review payload may never carry an existing scriptSig.
    Writer signed_writer = {scratch, sizeof(scratch), 0};
    built = write_bytes(&signed_writer, kZcashPayloadMagic,
                        sizeof(kZcashPayloadMagic)) &&
            write_u32(&signed_writer, chain.branch_id) &&
            write_u32(&signed_writer, static_cast<uint32_t>(transaction_size)) &&
            write_bytes(&signed_writer, transaction, transaction_size) &&
            write_compact_size(&signed_writer, 1) &&
            write_u64(&signed_writer, 50000000) &&
            write_compact_size(&signed_writer, sizeof(kScriptCode)) &&
            write_bytes(&signed_writer, kScriptCode, sizeof(kScriptCode)) &&
            write_u32(&signed_writer, 0) &&
            write_bytes(&signed_writer, "\0", 1) &&
            write_u32(&signed_writer, 0);
    ZcashSigningRequest signed_parse;
    passed = passed && built &&
             zcash_parse_review_payload(scratch, signed_writer.position,
                                        chain, &signed_parse) ==
                 ZcashError::Unsupported;
    secure_zero(scratch, sizeof(scratch));
    // Failure paths: magic, branch id, truncation, fee cap, shielded balance.
    ZcashSigningRequest unused;
    memcpy(scratch, payload, payload_size);
    scratch[0] = 'X';
    passed = passed &&
             zcash_parse_review_payload(scratch, payload_size, chain, &unused) ==
                 ZcashError::NonCanonical;
    secure_zero(scratch, sizeof(scratch));
    ZcashChainParams wrong_branch = chain;
    wrong_branch.branch_id = 0x76b809bb;
    passed = passed &&
             zcash_parse_review_payload(payload, payload_size, wrong_branch,
                                        &unused) == ZcashError::Unsupported;
    passed = passed &&
             zcash_parse_review_payload(payload, payload_size - 1, chain,
                                        &unused) == ZcashError::Truncated;
    memcpy(scratch, payload, payload_size);
    const size_t value_balance_offset =
        sizeof(kZcashPayloadMagic) + 4 + 4 + unsigned_writer.position - 11;
    scratch[value_balance_offset] = 1;
    passed = passed &&
             zcash_parse_review_payload(scratch, payload_size, chain, &unused) ==
                 ZcashError::Unsupported;
    secure_zero(scratch, sizeof(scratch));
    memcpy(scratch, payload, payload_size);
    const size_t input_value_offset =
        sizeof(kZcashPayloadMagic) + 4 + 4 + unsigned_writer.position + 1;
    const uint64_t excessive_value = 100000000ULL;
    for (size_t index = 0; index < 8; ++index)
    {
      scratch[input_value_offset + index] =
          static_cast<uint8_t>(excessive_value >> (index * 8));
    }
    passed = passed &&
             zcash_parse_review_payload(scratch, payload_size, chain, &unused) ==
                 ZcashError::FeePolicy;
    secure_zero(scratch, sizeof(scratch));
    // A transparent script larger than the 34-byte review buffer must not reach
    // the memcpy in the output loop.
    uint8_t oversized_tx[128];
    Writer oversized_writer = {oversized_tx, sizeof(oversized_tx), 0};
    static const uint8_t kOversizedScript[35] = {
        0x6a, 0x21, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    built = write_u32(&oversized_writer, kZcashV4Version) &&
            write_u32(&oversized_writer, kZcashSaplingVersionGroupId) &&
            write_compact_size(&oversized_writer, 1) &&
            write_bytes(&oversized_writer, kPrevout, sizeof(kPrevout)) &&
            write_compact_size(&oversized_writer, 0) &&
            write_u32(&oversized_writer, 0xfffffffeU) &&
            write_compact_size(&oversized_writer, 1) &&
            write_u64(&oversized_writer, 1000) &&
            write_compact_size(&oversized_writer, sizeof(kOversizedScript)) &&
            write_bytes(&oversized_writer, kOversizedScript,
                        sizeof(kOversizedScript)) &&
            write_u32(&oversized_writer, 0) &&
            write_u32(&oversized_writer, 307272) &&
            write_u64(&oversized_writer, 0) &&
            write_compact_size(&oversized_writer, 0) &&
            write_compact_size(&oversized_writer, 0) &&
            write_compact_size(&oversized_writer, 0);
    uint8_t oversized_payload[512];
    Writer oversized_payload_writer = {oversized_payload,
                                       sizeof(oversized_payload), 0};
    built = built &&
            write_bytes(&oversized_payload_writer, kZcashPayloadMagic,
                        sizeof(kZcashPayloadMagic)) &&
            write_u32(&oversized_payload_writer, chain.branch_id) &&
            write_u32(&oversized_payload_writer,
                      static_cast<uint32_t>(oversized_writer.position)) &&
            write_bytes(&oversized_payload_writer, oversized_tx,
                        oversized_writer.position) &&
            write_compact_size(&oversized_payload_writer, 1) &&
            write_u64(&oversized_payload_writer, 50000000) &&
            write_compact_size(&oversized_payload_writer, sizeof(kScriptCode)) &&
            write_bytes(&oversized_payload_writer, kScriptCode,
                        sizeof(kScriptCode)) &&
            write_u32(&oversized_payload_writer, 0) &&
            write_bytes(&oversized_payload_writer, "\0", 1) &&
            write_u32(&oversized_payload_writer, 0);
    passed = passed && built &&
             zcash_parse_review_payload(oversized_payload,
                                        oversized_payload_writer.position,
                                        chain, &unused) ==
                 ZcashError::Unsupported;
    passed = passed &&
             zcash_zip243_sighash_v4(transaction, transaction_size, kScriptCode,
                                     sizeof(kScriptCode), 0, 0x21, 50000000,
                                     0x76b809bb, digest) ==
                 ZcashError::Unsupported;
    passed = passed &&
             zcash_zip243_sighash_v4(transaction, transaction_size - 1,
                                     kScriptCode, sizeof(kScriptCode), 0,
                                     kSighashAll, 50000000, 0x76b809bb,
                                     digest) == ZcashError::Truncated;
    secure_zero(transaction, sizeof(transaction));
    secure_zero(payload, sizeof(payload));
    secure_zero(scratch, sizeof(scratch));
    secure_zero(unsigned_transaction, sizeof(unsigned_transaction));
    secure_zero(oversized_tx, sizeof(oversized_tx));
    secure_zero(oversized_payload, sizeof(oversized_payload));
    secure_zero(digest, sizeof(digest));
    clear_zcash_request(&parsed);
    clear_zcash_request(&signed_parse);
    return passed;
  }

  bool run_zcash_transaction_self_test()
  {
    // Deterministic BIP32 master used only by this self-test.
    HdPrivateNode master = {};
    for (size_t index = 0; index < kPrivateKeySize; ++index)
    {
      master.private_key[index] = static_cast<uint8_t>(index + 1);
      master.chain_code[index] = static_cast<uint8_t>(0x80 + index);
    }
    const uint32_t path[5] = {
        44U | kHardenedOffset, 133U | kHardenedOffset, kHardenedOffset, 0, 0};
    HdPrivateNode current = master;
    bool derived = true;
    for (size_t depth = 0; depth < 5; ++depth)
    {
      HdPrivateNode next;
      if (hd_private_derive(&current, path[depth], &next) != WalletError::Ok)
      {
        derived = false;
        secure_zero(&current, sizeof(current));
        break;
      }
      secure_zero(&current, sizeof(current));
      current = next;
    }
    uint8_t public_key[kCompressedPublicKeySize] = {};
    uint8_t hash[kRipemd160Size] = {};
    derived = derived &&
              public_key_from_private(current.private_key, public_key) ==
                  WalletError::Ok &&
              crypto_hash160(public_key, sizeof(public_key), hash);
    uint8_t input_script[25] = {0x76, 0xa9, 0x14};
    input_script[23] = 0x88;
    input_script[24] = 0xac;
    memcpy(input_script + 3, hash, sizeof(hash));
    static const uint8_t kSecondScript[25] = {
        0x76, 0xa9, 0x14, 0x54, 0x53, 0xe4, 0x69, 0x8f, 0x02, 0xa3,
        0x8a, 0xbd, 0xaa, 0x52, 0x1c, 0xd1, 0xff, 0x2d, 0xee, 0x6f,
        0xac, 0x18, 0x71, 0x88, 0xac};
    ZcashSigningRequest request = {};
    request.chain = {"zec", 0x1cb8, 0x1cbd, 0x5437f330, 133};
    request.version = kZcashV4Version;
    request.version_group_id = kZcashSaplingVersionGroupId;
    request.lock_time = 0;
    request.expiry_height = 1000000;
    request.input_count = 1;
    request.output_count = 2;
    request.inputs[0].value = 100000000;
    request.inputs[0].sequence = 0xfffffffeU;
    request.inputs[0].script_size = sizeof(input_script);
    memcpy(request.inputs[0].script, input_script, sizeof(input_script));
    request.outputs[0].value = 40000000;
    request.outputs[0].script_size = sizeof(input_script);
    memcpy(request.outputs[0].script, input_script, sizeof(input_script));
    request.outputs[1].value = 59999000;
    request.outputs[1].script_size = sizeof(kSecondScript);
    memcpy(request.outputs[1].script, kSecondScript, sizeof(kSecondScript));
    request.input_total = 100000000;
    request.output_total = 99999000;
    request.fee = 1000;
    request.estimated_vbytes = estimated_vbytes(request);
    static uint8_t signed_transaction[kZcashMaxTransactionSize];
    size_t signed_size = sizeof(signed_transaction);
    bool passed = derived &&
                  zcash_sign_request(request, master, signed_transaction,
                                     &signed_size) == ZcashError::Ok &&
                  signed_size > 0 && signed_size < sizeof(signed_transaction);
    if (passed)
    {
      TxView view;
      passed = parse_v4_transaction(signed_transaction, signed_size, &view, true) ==
                   ZcashError::Ok &&
               view.input_count == 1 && view.output_count == 2 &&
               view.inputs[0].script_sig_size > 0;
      if (passed)
      {
        const uint8_t *script_sig = view.inputs[0].script_sig;
        const size_t script_sig_size = view.inputs[0].script_sig_size;
        passed = script_sig_size > 35 && script_sig[0] >= 0x40 &&
                 script_sig[0] <= 0x49 &&
                 1 + script_sig[0] + 1 + 33 == script_sig_size &&
                 script_sig[1 + script_sig[0]] == 33;
        if (passed)
        {
          const uint8_t *der = script_sig + 1;
          const size_t der_size = script_sig[0] - 1;
          const uint8_t *pubkey = script_sig + 2 + script_sig[0];
          uint8_t digest[kSha256Size];
          passed = zcash_zip243_sighash_v4(
                       signed_transaction, signed_size, input_script,
                       sizeof(input_script), 0, kSighashAll,
                       request.inputs[0].value, request.chain.branch_id,
                       digest) == ZcashError::Ok &&
                   verify_digest(pubkey, digest, der, der_size);
          secure_zero(digest, sizeof(digest));
        }
      }
    }
    // t3 P2SH spend of the same key: the redeem script is the scriptCode, and
    // the scriptSig must push the signature followed by that redeem script.
    if (passed)
    {
      ZcashSigningRequest p2sh = request;
      uint8_t redeem[kZcashMaxRedeemScriptSize] = {0x21};
      memcpy(redeem + 1, public_key, kCompressedPublicKeySize);
      redeem[kZcashMaxRedeemScriptSize - 1] = 0xac;
      uint8_t redeem_hash[kRipemd160Size] = {};
      bool p2sh_ok = crypto_hash160(redeem, sizeof(redeem), redeem_hash);
      if (p2sh_ok)
      {
        uint8_t *script = p2sh.inputs[0].script;
        script[0] = 0xa9;
        script[1] = 0x14;
        memcpy(script + 2, redeem_hash, sizeof(redeem_hash));
        script[22] = 0x87;
        p2sh.inputs[0].script_size = static_cast<uint8_t>(kP2shScriptSize);
        memcpy(p2sh.inputs[0].redeem, redeem, sizeof(redeem));
        p2sh.inputs[0].redeem_size =
            static_cast<uint8_t>(kZcashMaxRedeemScriptSize);
        p2sh.estimated_vbytes = estimated_vbytes(p2sh);
        size_t p2sh_size = sizeof(signed_transaction);
        p2sh_ok = zcash_sign_request(p2sh, master, signed_transaction,
                                     &p2sh_size) == ZcashError::Ok &&
                  p2sh_size > 0;
        TxView view = {};
        if (p2sh_ok)
        {
          p2sh_ok = parse_v4_transaction(signed_transaction, p2sh_size, &view,
                                         true) == ZcashError::Ok &&
                    view.input_count == 1 &&
                    view.inputs[0].script_sig_size > 36;
        }
        if (p2sh_ok)
        {
          const uint8_t *script_sig = view.inputs[0].script_sig;
          const size_t script_sig_size = view.inputs[0].script_sig_size;
          p2sh_ok = script_sig[0] >= 0x40 && script_sig[0] <= 0x49 &&
                    1 + script_sig[0] + 1 + kZcashMaxRedeemScriptSize ==
                        script_sig_size &&
                    script_sig[1 + script_sig[0]] == kZcashMaxRedeemScriptSize;
          if (p2sh_ok)
          {
            const uint8_t *der = script_sig + 1;
            const size_t der_size = script_sig[0] - 1;
            const uint8_t *pushed = script_sig + 2 + script_sig[0];
            uint8_t digest[kSha256Size];
            p2sh_ok =
                crypto_constant_time_equal(pushed, redeem, sizeof(redeem)) &&
                zcash_zip243_sighash_v4(signed_transaction, p2sh_size, redeem,
                                        sizeof(redeem), 0, kSighashAll,
                                        p2sh.inputs[0].value,
                                        p2sh.chain.branch_id,
                                        digest) == ZcashError::Ok &&
                verify_digest(public_key, digest, der, der_size);
            secure_zero(digest, sizeof(digest));
          }
        }
      }
      passed = p2sh_ok;
      secure_zero(redeem, sizeof(redeem));
      secure_zero(redeem_hash, sizeof(redeem_hash));
      clear_zcash_request(&p2sh);
    }
    // A t3 prevout without a redeem script, or with a redeem script that does
    // not hash to the address, must never be signed.
    if (passed)
    {
      ZcashSigningRequest no_redeem = request;
      uint8_t redeem[kZcashMaxRedeemScriptSize] = {0x21};
      memcpy(redeem + 1, public_key, kCompressedPublicKeySize);
      redeem[kZcashMaxRedeemScriptSize - 1] = 0xac;
      uint8_t redeem_hash[kRipemd160Size] = {};
      bool rejected = crypto_hash160(redeem, sizeof(redeem), redeem_hash);
      if (rejected)
      {
        uint8_t *script = no_redeem.inputs[0].script;
        script[0] = 0xa9;
        script[1] = 0x14;
        memcpy(script + 2, redeem_hash, sizeof(redeem_hash));
        script[22] = 0x87;
        no_redeem.inputs[0].script_size = static_cast<uint8_t>(kP2shScriptSize);
        no_redeem.estimated_vbytes = estimated_vbytes(no_redeem);
        size_t probe_size = sizeof(signed_transaction);
        rejected =
            zcash_sign_request(no_redeem, master, signed_transaction,
                               &probe_size) == ZcashError::WrongWallet;
      }
      if (rejected)
      {
        ZcashSigningRequest wrong_hash = no_redeem;
        memcpy(wrong_hash.inputs[0].redeem, redeem, sizeof(redeem));
        wrong_hash.inputs[0].redeem_size =
            static_cast<uint8_t>(kZcashMaxRedeemScriptSize);
        wrong_hash.inputs[0].script[5] ^= 0x01;
        wrong_hash.estimated_vbytes = estimated_vbytes(wrong_hash);
        size_t probe_size = sizeof(signed_transaction);
        rejected =
            zcash_sign_request(wrong_hash, master, signed_transaction,
                               &probe_size) == ZcashError::WrongWallet;
        clear_zcash_request(&wrong_hash);
      }
      passed = rejected;
      secure_zero(redeem, sizeof(redeem));
      secure_zero(redeem_hash, sizeof(redeem_hash));
      clear_zcash_request(&no_redeem);
    }
    // Wrong-wallet and fee-policy failure paths.
    if (passed)
    {
      ZcashSigningRequest wrong = request;
      wrong.inputs[0].script[3] ^= 0x01;
      size_t wrong_size = sizeof(signed_transaction);
      passed = zcash_sign_request(wrong, master, signed_transaction,
                                  &wrong_size) == ZcashError::WrongWallet;
    }
    if (passed)
    {
      ZcashSigningRequest expensive = request;
      expensive.outputs[1].value = 1;
      expensive.output_total = 40000001;
      expensive.fee = 59999999;
      size_t expensive_size = sizeof(signed_transaction);
      passed = zcash_sign_request(expensive, master, signed_transaction,
                                  &expensive_size) == ZcashError::FeePolicy;
    }
    secure_zero(&master, sizeof(master));
    secure_zero(&current, sizeof(current));
    secure_zero(public_key, sizeof(public_key));
    secure_zero(hash, sizeof(hash));
    secure_zero(input_script, sizeof(input_script));
    secure_zero(signed_transaction, sizeof(signed_transaction));
    clear_zcash_request(&request);
    return passed;
  }

} // namespace hexwallet
