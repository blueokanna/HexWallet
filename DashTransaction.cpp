#include "DashTransaction.h"
#include <string.h>

#include "src/BytesText.h"
#include "src/Secp256k1Sign.h"
#include "WalletAddresses.h"
#include "WalletConfig.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {

    constexpr uint32_t kSighashAll = 1;
    constexpr size_t kMaxViewInputs = 64;
    constexpr size_t kMaxViewOutputs = 64;
    constexpr size_t kMaxForeignScriptSize = 10000;
    constexpr size_t kPreimageMax =
        kDashMaxTransactionSize + kDashMaxScriptSize + 8;
    constexpr uint8_t kDashPayloadMagic[4] = {'D', 'A', 'S', 'H'};

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
      const uint8_t *outpoint;
      uint32_t sequence;
      const uint8_t *script_sig;
      size_t script_sig_size;
    };

    struct TxOutputView
    {
      uint64_t value;
      const uint8_t *script;
      size_t script_size;
    };

    struct TxView
    {
      uint32_t version;
      uint32_t type;
      uint32_t lock_time;
      TxInputView inputs[kMaxViewInputs];
      TxOutputView outputs[kMaxViewOutputs];
      size_t input_count;
      size_t output_count;
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

    bool read_u8(Cursor *cursor, uint8_t *out)
    {
      const uint8_t *bytes;
      if (!read_bytes(cursor, 1, &bytes))
        return false;
      *out = bytes[0];
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

    // Bitcoin/Dash compact integer: only the canonical encoding is accepted, so
    // two different byte strings can never describe the same transaction.
    bool read_compact_size(Cursor *cursor, uint64_t *out)
    {
      uint8_t first;
      if (!read_u8(cursor, &first))
        return false;
      if (first < 0xfd)
      {
        *out = first;
        return true;
      }
      size_t width;
      if (first == 0xfd)
      {
        width = 2;
      }
      else if (first == 0xfe)
      {
        width = 4;
      }
      else
      {
        width = 8;
      }
      const uint8_t *bytes;
      if (!read_bytes(cursor, width, &bytes))
        return false;
      uint64_t value = 0;
      for (size_t index = 0; index < width; ++index)
      {
        value |= static_cast<uint64_t>(bytes[index]) << (index * 8);
      }
      const uint64_t minimum =
          width == 2 ? 0xfdULL : (width == 4 ? 0x10000ULL : 0x100000000ULL);
      if (value < minimum)
        return false;
      *out = value;
      return true;
    }

    bool write_bytes(Writer *writer, const uint8_t *data, size_t size)
    {
      if (writer == nullptr || size > writer->size - writer->position)
        return false;
      if (size != 0 && data == nullptr)
        return false;
      if (size != 0)
        memcpy(writer->data + writer->position, data, size);
      writer->position += size;
      return true;
    }

    bool write_u32(Writer *writer, uint32_t value)
    {
      const uint8_t bytes[4] = {
          static_cast<uint8_t>(value),
          static_cast<uint8_t>(value >> 8),
          static_cast<uint8_t>(value >> 16),
          static_cast<uint8_t>(value >> 24)};
      return write_bytes(writer, bytes, sizeof(bytes));
    }

    bool write_u64(Writer *writer, uint64_t value)
    {
      uint8_t bytes[8];
      for (size_t index = 0; index < 8; ++index)
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
      if (value <= 0xffffULL)
      {
        const uint8_t bytes[3] = {0xfd,
                                  static_cast<uint8_t>(value),
                                  static_cast<uint8_t>(value >> 8)};
        return write_bytes(writer, bytes, sizeof(bytes));
      }
      if (value <= 0xffffffffULL)
      {
        const uint8_t bytes[5] = {0xfe,
                                  static_cast<uint8_t>(value),
                                  static_cast<uint8_t>(value >> 8),
                                  static_cast<uint8_t>(value >> 16),
                                  static_cast<uint8_t>(value >> 24)};
        return write_bytes(writer, bytes, sizeof(bytes));
      }
      uint8_t bytes[9];
      bytes[0] = 0xff;
      for (size_t index = 0; index < 8; ++index)
      {
        bytes[1 + index] = static_cast<uint8_t>(value >> (index * 8));
      }
      return write_bytes(writer, bytes, sizeof(bytes));
    }

    bool p2pkh_script(const uint8_t *script, size_t size)
    {
      return script != nullptr && size == kDashP2pkhScriptSize &&
             script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
             script[23] == 0x88 && script[24] == 0xac;
    }

    bool p2sh_script(const uint8_t *script, size_t size)
    {
      return script != nullptr && size == kDashP2shScriptSize &&
             script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87;
    }

    // Parses an arbitrary Dash plain transaction. Any nType other than zero
    // means an `extraPayload` follows that this module refuses to interpret, so
    // such transactions never parse.
    DashError parse_transaction(const uint8_t *data, size_t size, TxView *out)
    {
      if (data == nullptr || out == nullptr || size < 10)
        return DashError::Truncated;
      Cursor cursor = {data, size, 0};
      uint32_t version_field;
      if (!read_u32(&cursor, &version_field))
        return DashError::Truncated;
      out->version = version_field & 0xffffU;
      out->type = version_field >> 16;
      if (out->type != 0)
        return DashError::Unsupported;
      if (out->version < 1 || out->version > kDashVersion)
        return DashError::Unsupported;
      uint64_t count;
      if (!read_compact_size(&cursor, &count))
        return DashError::Truncated;
      if (count == 0 || count > kMaxViewInputs)
        return DashError::TooLarge;
      out->input_count = static_cast<size_t>(count);
      for (size_t index = 0; index < out->input_count; ++index)
      {
        TxInputView &input = out->inputs[index];
        if (!read_bytes(&cursor, 36, &input.outpoint))
          return DashError::Truncated;
        uint64_t script_size;
        if (!read_compact_size(&cursor, &script_size))
          return DashError::Truncated;
        if (script_size > kMaxForeignScriptSize)
          return DashError::TooLarge;
        if (!read_bytes(&cursor, static_cast<size_t>(script_size),
                        &input.script_sig))
          return DashError::Truncated;
        input.script_sig_size = static_cast<size_t>(script_size);
        if (!read_u32(&cursor, &input.sequence))
          return DashError::Truncated;
      }
      if (!read_compact_size(&cursor, &count))
        return DashError::Truncated;
      if (count == 0 || count > kMaxViewOutputs)
        return DashError::TooLarge;
      out->output_count = static_cast<size_t>(count);
      for (size_t index = 0; index < out->output_count; ++index)
      {
        TxOutputView &output = out->outputs[index];
        if (!read_u64(&cursor, &output.value))
          return DashError::Truncated;
        uint64_t script_size;
        if (!read_compact_size(&cursor, &script_size))
          return DashError::Truncated;
        if (script_size > kMaxForeignScriptSize)
          return DashError::TooLarge;
        if (!read_bytes(&cursor, static_cast<size_t>(script_size),
                        &output.script))
          return DashError::Truncated;
        output.script_size = static_cast<size_t>(script_size);
      }
      if (!read_u32(&cursor, &out->lock_time))
        return DashError::Truncated;
      // A plain transaction ends after nLockTime; anything left is a
      // non-canonical encoding, not a field this wallet may ignore.
      return cursor.position == cursor.size ? DashError::Ok
                                            : DashError::NonCanonical;
    }

    DashError write_legacy_preimage(const TxView &view, size_t input_index,
                                    const uint8_t *script_code,
                                    size_t script_code_size,
                                    uint8_t hash_type, Writer *writer)
    {
      if (input_index >= view.input_count || script_code == nullptr ||
          script_code_size == 0 || script_code_size > kDashMaxScriptSize)
      {
        return DashError::InvalidArgument;
      }
      if (!write_u32(writer, view.version | (view.type << 16)) ||
          !write_compact_size(writer, view.input_count))
      {
        return DashError::BufferTooSmall;
      }
      for (size_t index = 0; index < view.input_count; ++index)
      {
        const TxInputView &input = view.inputs[index];
        if (!write_bytes(writer, input.outpoint, 36))
          return DashError::BufferTooSmall;
        if (index == input_index)
        {
          if (!write_compact_size(writer, script_code_size) ||
              !write_bytes(writer, script_code, script_code_size))
          {
            return DashError::BufferTooSmall;
          }
        }
        else if (!write_compact_size(writer, 0))
        {
          return DashError::BufferTooSmall;
        }
        if (!write_u32(writer, input.sequence))
          return DashError::BufferTooSmall;
      }
      if (!write_compact_size(writer, view.output_count))
        return DashError::BufferTooSmall;
      for (size_t index = 0; index < view.output_count; ++index)
      {
        const TxOutputView &output = view.outputs[index];
        if (!write_u64(writer, output.value) ||
            !write_compact_size(writer, output.script_size) ||
            !write_bytes(writer, output.script, output.script_size))
        {
          return DashError::BufferTooSmall;
        }
      }
      if (!write_u32(writer, view.lock_time) || !write_u32(writer, hash_type))
        return DashError::BufferTooSmall;
      return DashError::Ok;
    }

    uint32_t estimated_vbytes(const DashTransaction &request)
    {
      uint64_t size = kDashBaseVbytes;
      size += static_cast<uint64_t>(request.input_count) * kDashP2pkhInputVbytes;
      for (size_t index = 0; index < request.output_count; ++index)
      {
        size += 9 + request.outputs[index].script_size;
      }
      return size > UINT32_MAX ? 0 : static_cast<uint32_t>(size);
    }

    DashError serialize_request(
        const DashTransaction &request,
        const uint8_t (*signatures)[kDashMaxSignatureSize],
        const uint8_t *signature_sizes,
        const uint8_t (*public_keys)[kCompressedPublicKeySize],
        uint8_t *out_transaction, size_t *in_out_size)
    {
      Writer writer = {out_transaction, *in_out_size, 0};
      bool ok = write_u32(&writer, request.version) &&
                write_compact_size(&writer, request.input_count);
      for (size_t index = 0; ok && index < request.input_count; ++index)
      {
        const DashInput &input = request.inputs[index];
        uint8_t script_sig[kDashMaxSignatureSize + 1 + kCompressedPublicKeySize];
        size_t script_sig_size = 0;
        if (signatures != nullptr && public_keys != nullptr)
        {
          if (signature_sizes[index] == 0 ||
              signature_sizes[index] > kDashMaxSignatureSize)
          {
            return DashError::InvalidArgument;
          }
          script_sig[script_sig_size++] = signature_sizes[index];
          memcpy(script_sig + script_sig_size, signatures[index],
                 signature_sizes[index]);
          script_sig_size += signature_sizes[index];
          script_sig[script_sig_size++] = kCompressedPublicKeySize;
          memcpy(script_sig + script_sig_size, public_keys[index],
                 kCompressedPublicKeySize);
          script_sig_size += kCompressedPublicKeySize;
        }
        ok = write_bytes(&writer, input.previous_txid, 32) &&
             write_u32(&writer, input.previous_index) &&
             write_compact_size(&writer, script_sig_size) &&
             write_bytes(&writer, script_sig, script_sig_size) &&
             write_u32(&writer, input.sequence);
        secure_zero(script_sig, sizeof(script_sig));
      }
      ok = ok && write_compact_size(&writer, request.output_count);
      for (size_t index = 0; ok && index < request.output_count; ++index)
      {
        const DashOutput &output = request.outputs[index];
        ok = write_u64(&writer, output.value) &&
             write_compact_size(&writer, output.script_size) &&
             write_bytes(&writer, output.script, output.script_size);
      }
      ok = ok && write_u32(&writer, request.lock_time);
      if (!ok)
        return DashError::BufferTooSmall;
      *in_out_size = writer.position;
      return DashError::Ok;
    }

    bool derive_and_verify_key(const HdPrivateNode &master,
                               const DashInput &input,
                               uint8_t out_private[kPrivateKeySize],
                               uint8_t out_public[kCompressedPublicKeySize])
    {
      if (input.account >= kHardenedOffset || input.change > 1 ||
          input.address_index >= kHardenedOffset)
      {
        return false;
      }
      const uint32_t path[5] = {
          44U | kHardenedOffset,
          kDashCoinType | kHardenedOffset,
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
      const bool owned =
          public_key_from_private(current.private_key, out_public) ==
              WalletError::Ok &&
          crypto_hash160(out_public, kCompressedPublicKeySize, hash) &&
          p2pkh_script(input.script, input.script_size) &&
          crypto_constant_time_equal(hash, input.script + 3, kRipemd160Size);
      memcpy(out_private, current.private_key, kPrivateKeySize);
      secure_zero(&current, sizeof(current));
      secure_zero(hash, sizeof(hash));
      return owned;
    }

    DashError validate_request(const DashTransaction &request,
                               const HdPrivateNode &master,
                               uint8_t (*private_keys)[kPrivateKeySize],
                               uint8_t (*public_keys)[kCompressedPublicKeySize])
    {
      if (request.input_count == 0 || request.input_count > kDashMaxInputs ||
          request.output_count == 0 || request.output_count > kDashMaxOutputs ||
          request.version != kDashVersion ||
          request.lock_time > kDashMaxLockTime)
      {
        return DashError::InvalidArgument;
      }
      const NetworkProfile *network = find_network_profile(request.chain.network_id);
      if (network == nullptr || network->encoding != AddressEncoding::P2pkh ||
          network->utxo.p2pkh_version != request.chain.p2pkh_version ||
          network->utxo.p2sh_version != request.chain.p2sh_version ||
          network->derivation_coin_type != kDashCoinType)
      {
        return DashError::Unsupported;
      }
      uint64_t input_total = 0;
      uint64_t output_total = 0;
      for (size_t index = 0; index < request.input_count; ++index)
      {
        const DashInput &input = request.inputs[index];
        if (input.value == 0 || input.value > kDashMaxDuffs ||
            !p2pkh_script(input.script, input.script_size) ||
            input.account >= kHardenedOffset || input.change > 1 ||
            input.address_index >= kHardenedOffset ||
            !add_u64(input_total, input.value, &input_total))
        {
          return DashError::WrongWallet;
        }
        for (size_t other = index + 1; other < request.input_count; ++other)
        {
          if (request.inputs[other].previous_index == input.previous_index &&
              bytes_equal(request.inputs[other].previous_txid,
                          input.previous_txid, 32))
          {
            return DashError::NonCanonical;
          }
        }
      }
      for (size_t index = 0; index < request.output_count; ++index)
      {
        const DashOutput &output = request.outputs[index];
        if (output.value == 0 || output.value > kDashMaxDuffs ||
            (!p2pkh_script(output.script, output.script_size) &&
             !p2sh_script(output.script, output.script_size)) ||
            !add_u64(output_total, output.value, &output_total))
        {
          return DashError::Unsupported;
        }
      }
      // Policy is checked before any key work: a request whose fee is already
      // out of bounds must cost nothing and must not touch the seed.
      const uint32_t expected_vbytes = estimated_vbytes(request);
      if (input_total < output_total || input_total != request.input_total ||
          output_total != request.output_total ||
          input_total - output_total != request.fee || expected_vbytes == 0 ||
          request.estimated_vbytes != expected_vbytes ||
          request.fee > HEXWALLET_MAX_DASH_FEE_DUFFS ||
          request.fee > HEXWALLET_MAX_DASH_FEE_RATE *
                            static_cast<uint64_t>(request.estimated_vbytes))
      {
        return DashError::FeePolicy;
      }
      // Every input must be spendable by this wallet's key at the path it
      // claims; that is what makes the review's sender line true.
      DashError result = DashError::Ok;
      for (size_t index = 0; index < request.input_count; ++index)
      {
        uint8_t private_key[kPrivateKeySize];
        uint8_t public_key[kCompressedPublicKeySize];
        if (!derive_and_verify_key(master, request.inputs[index], private_key,
                                   public_key))
        {
          secure_zero(private_key, sizeof(private_key));
          secure_zero(public_key, sizeof(public_key));
          result = DashError::WrongWallet;
          break;
        }
        if (private_keys != nullptr)
          memcpy(private_keys[index], private_key, kPrivateKeySize);
        if (public_keys != nullptr)
          memcpy(public_keys[index], public_key, kCompressedPublicKeySize);
        secure_zero(private_key, sizeof(private_key));
        secure_zero(public_key, sizeof(public_key));
      }
      if (result != DashError::Ok)
      {
        if (private_keys != nullptr)
          secure_zero(private_keys, kDashMaxInputs * kPrivateKeySize);
        if (public_keys != nullptr)
          secure_zero(public_keys, kDashMaxInputs * kCompressedPublicKeySize);
      }
      return result;
    }

#include "src/generated/DashVectorsTest.inc"
    constexpr DashChainParams kSelfTestChain = {"dash", 0x4c, 0x10};
    // Byte offsets inside kDashSelfTestPayload: magic, lock time, one P2PKH
    // input, then two outputs (P2SH then P2PKH change).
    constexpr size_t kPayloadLockTimeOffset = 4;
    constexpr size_t kPayloadInputCountOffset = 8;
    constexpr size_t kPayloadPrevoutScriptOffset = 58;
    constexpr size_t kPayloadAccountOffset = 83;
    constexpr size_t kPayloadChangeOffset = 87;
    constexpr size_t kPayloadOutputCountOffset = 92;
    constexpr size_t kPayloadLastOutputValueOffset = 125;
    constexpr size_t kPayloadLastOutputScriptOffset = 134;
    constexpr size_t kSelfTestInputRecordSize = kPayloadOutputCountOffset - 9;

    void store_u32(uint8_t *out, uint32_t value)
    {
      for (size_t index = 0; index < 4; ++index)
      {
        out[index] = static_cast<uint8_t>(value >> (index * 8));
      }
    }

    void store_u64(uint8_t *out, uint64_t value)
    {
      for (size_t index = 0; index < 8; ++index)
      {
        out[index] = static_cast<uint8_t>(value >> (index * 8));
      }
    }

    bool payload_result_is(const uint8_t *payload, size_t size,
                           DashError expected)
    {
      DashTransaction parsed;
      const DashError result =
          dash_parse_review_payload(payload, size, kSelfTestChain, &parsed);
      secure_zero(&parsed, sizeof(parsed));
      return result == expected;
    }

    bool signature_verifies(const uint8_t *transaction, size_t size,
                            const uint8_t *script_code, size_t script_code_size,
                            const uint8_t expected_digest[kSha256Size])
    {
      TxView view = {};
      if (parse_transaction(transaction, size, &view) != DashError::Ok ||
          view.input_count != 1)
      {
        return false;
      }
      const TxInputView &input = view.inputs[0];
      if (input.script_sig_size < 3 || input.script_sig[0] < 2)
        return false;
      const size_t push = input.script_sig[0];
      if (1 + push + 2 > input.script_sig_size ||
          input.script_sig[1 + push] != kCompressedPublicKeySize ||
          input.script_sig[1 + push - 1] != kSighashAll)
      {
        return false;
      }
      const uint8_t *der = input.script_sig + 1;
      const size_t der_size = push - 1;
      const uint8_t *public_key = input.script_sig + 1 + push + 1;
      uint8_t hash[kRipemd160Size];
      const bool owned =
          crypto_hash160(public_key, kCompressedPublicKeySize, hash) &&
          p2pkh_script(script_code, script_code_size) &&
          crypto_constant_time_equal(hash, script_code + 3, kRipemd160Size);
      secure_zero(hash, sizeof(hash));
      if (!owned)
        return false;
      uint8_t digest[kSha256Size];
      const bool digest_ok =
          dash_legacy_sighash(transaction, size, 0, script_code,
                              script_code_size, kSighashAll, digest) ==
              DashError::Ok &&
          crypto_constant_time_equal(digest, expected_digest, kSha256Size);
      const bool verified =
          secp256k1_verify_der(public_key, digest, der, der_size);
      secure_zero(digest, sizeof(digest));
      return digest_ok && verified;
    }

  } // namespace

  DashError dash_legacy_sighash(const uint8_t *transaction,
                                size_t transaction_size, size_t input_index,
                                const uint8_t *script_code,
                                size_t script_code_size, uint8_t hash_type,
                                uint8_t out_digest[kSha256Size])
  {
    if (transaction == nullptr || out_digest == nullptr ||
        transaction_size > kDashMaxTransactionSize || script_code == nullptr ||
        script_code_size == 0)
    {
      return DashError::InvalidArgument;
    }
    TxView view = {};
    const DashError parsed = parse_transaction(transaction, transaction_size, &view);
    if (parsed != DashError::Ok)
      return parsed;
    if (input_index >= view.input_count)
      return DashError::InvalidArgument;
    uint8_t preimage[kPreimageMax];
    Writer writer = {preimage, sizeof(preimage), 0};
    const DashError wrote = write_legacy_preimage(
        view, input_index, script_code, script_code_size, hash_type, &writer);
    if (wrote != DashError::Ok)
    {
      secure_zero(preimage, sizeof(preimage));
      return wrote;
    }
    const bool hashed = crypto_double_sha256(preimage, writer.position, out_digest);
    secure_zero(preimage, sizeof(preimage));
    return hashed ? DashError::Ok : DashError::CryptoFailure;
  }

  DashError dash_parse_review_payload(const uint8_t *data, size_t size,
                                      const DashChainParams &chain,
                                      DashTransaction *out)
  {
    if (data == nullptr || out == nullptr || chain.network_id == nullptr ||
        chain.network_id[0] == '\0')
    {
      return DashError::InvalidArgument;
    }
    clear_dash_transaction(out);
    out->chain = chain;
    out->version = kDashVersion;
    if (size < sizeof(kDashPayloadMagic) + 5)
      return DashError::Truncated;
    if (!bytes_equal(data, kDashPayloadMagic, sizeof(kDashPayloadMagic)))
      return DashError::NonCanonical;
    Cursor cursor = {data, size, sizeof(kDashPayloadMagic)};
    if (!read_u32(&cursor, &out->lock_time))
      return DashError::Truncated;
    if (out->lock_time > kDashMaxLockTime)
      return DashError::InvalidArgument;
    uint8_t input_count;
    if (!read_u8(&cursor, &input_count))
      return DashError::Truncated;
    if (input_count == 0 || input_count > kDashMaxInputs)
      return DashError::TooLarge;
    out->input_count = input_count;
    const UtxoAddressProfile profile = {chain.p2pkh_version, chain.p2sh_version,
                                        nullptr, false};
    for (size_t index = 0; index < out->input_count; ++index)
    {
      DashInput &input = out->inputs[index];
      const uint8_t *previous_txid;
      if (!read_bytes(&cursor, 32, &previous_txid))
        return DashError::Truncated;
      memcpy(input.previous_txid, previous_txid, 32);
      if (!read_u32(&cursor, &input.previous_index) ||
          !read_u32(&cursor, &input.sequence) ||
          !read_u64(&cursor, &input.value))
      {
        return DashError::Truncated;
      }
      if (input.value == 0 || input.value > kDashMaxDuffs)
        return DashError::InvalidAmount;
      uint8_t script_size;
      if (!read_u8(&cursor, &script_size) ||
          script_size != kDashP2pkhScriptSize)
      {
        return DashError::Unsupported;
      }
      const uint8_t *script;
      if (!read_bytes(&cursor, script_size, &script))
        return DashError::Truncated;
      if (!p2pkh_script(script, script_size))
        return DashError::Unsupported;
      memcpy(input.script, script, script_size);
      input.script_size = script_size;
      if (!read_u32(&cursor, &input.account) ||
          !read_u8(&cursor, &input.change) ||
          !read_u32(&cursor, &input.address_index))
      {
        return DashError::Truncated;
      }
      if (input.account >= kHardenedOffset || input.change > 1 ||
          input.address_index >= kHardenedOffset)
      {
        return DashError::InvalidArgument;
      }
      if (address_from_script(profile, input.script, input.script_size,
                              input.address, sizeof(input.address)) !=
          WalletError::Ok)
      {
        return DashError::Unsupported;
      }
      if (!add_u64(out->input_total, input.value, &out->input_total))
        return DashError::InvalidAmount;
      for (size_t other = 0; other < index; ++other)
      {
        if (out->inputs[other].previous_index == input.previous_index &&
            bytes_equal(out->inputs[other].previous_txid, input.previous_txid,
                        32))
        {
          return DashError::DuplicateField;
        }
      }
    }
    uint8_t output_count;
    if (!read_u8(&cursor, &output_count))
      return DashError::Truncated;
    if (output_count == 0 || output_count > kDashMaxOutputs)
      return DashError::TooLarge;
    out->output_count = output_count;
    for (size_t index = 0; index < out->output_count; ++index)
    {
      DashOutput &output = out->outputs[index];
      if (!read_u64(&cursor, &output.value))
        return DashError::Truncated;
      if (output.value == 0 || output.value > kDashMaxDuffs)
        return DashError::InvalidAmount;
      uint8_t script_size;
      if (!read_u8(&cursor, &script_size) || script_size > kDashMaxScriptSize)
        return DashError::Unsupported;
      const uint8_t *script;
      if (!read_bytes(&cursor, script_size, &script))
        return DashError::Truncated;
      if (!p2pkh_script(script, script_size) &&
          !p2sh_script(script, script_size))
      {
        return DashError::Unsupported;
      }
      memcpy(output.script, script, script_size);
      output.script_size = script_size;
      if (address_from_script(profile, output.script, output.script_size,
                              output.address, sizeof(output.address)) !=
          WalletError::Ok)
      {
        return DashError::Unsupported;
      }
      if (!add_u64(out->output_total, output.value, &out->output_total))
        return DashError::InvalidAmount;
    }
    if (cursor.position != cursor.size)
      return DashError::NonCanonical;
    if (out->input_total < out->output_total)
      return DashError::InvalidAmount;
    out->fee = out->input_total - out->output_total;
    if (out->fee == 0)
      return DashError::InvalidAmount;
    out->estimated_vbytes = estimated_vbytes(*out);
    if (out->estimated_vbytes == 0 ||
        out->fee > HEXWALLET_MAX_DASH_FEE_DUFFS ||
        out->fee >
            HEXWALLET_MAX_DASH_FEE_RATE * static_cast<uint64_t>(out->estimated_vbytes))
    {
      clear_dash_transaction(out);
      out->chain = chain;
      out->version = kDashVersion;
      return DashError::FeePolicy;
    }
    if (!crypto_sha256(data, size, out->payload_hash))
    {
      clear_dash_transaction(out);
      out->chain = chain;
      out->version = kDashVersion;
      return DashError::CryptoFailure;
    }
    return DashError::Ok;
  }

  DashError dash_sign_transaction(const DashTransaction &request,
                                  const HdPrivateNode &master,
                                  uint8_t *out_transaction, size_t *in_out_size)
  {
    if (out_transaction == nullptr || in_out_size == nullptr)
      return DashError::InvalidArgument;
    uint8_t private_keys[kDashMaxInputs][kPrivateKeySize] = {};
    uint8_t public_keys[kDashMaxInputs][kCompressedPublicKeySize] = {};
    DashError result =
        validate_request(request, master, private_keys, public_keys);
    if (result != DashError::Ok)
    {
      secure_zero(private_keys, sizeof(private_keys));
      secure_zero(public_keys, sizeof(public_keys));
      return result;
    }
    uint8_t unsigned_transaction[kDashMaxTransactionSize];
    size_t unsigned_size = sizeof(unsigned_transaction);
    result = serialize_request(request, nullptr, nullptr, nullptr,
                               unsigned_transaction, &unsigned_size);
    if (result != DashError::Ok)
    {
      secure_zero(unsigned_transaction, sizeof(unsigned_transaction));
      secure_zero(private_keys, sizeof(private_keys));
      secure_zero(public_keys, sizeof(public_keys));
      return result;
    }
    uint8_t signatures[kDashMaxInputs][kDashMaxSignatureSize] = {};
    uint8_t signature_sizes[kDashMaxInputs] = {};
    for (size_t index = 0; index < request.input_count; ++index)
    {
      // A P2PKH input commits its own prevout script as the scriptCode.
      uint8_t digest[kSha256Size];
      result = dash_legacy_sighash(unsigned_transaction, unsigned_size, index,
                                   request.inputs[index].script,
                                   request.inputs[index].script_size,
                                   kSighashAll, digest);
      size_t der_size = sizeof(signatures[index]) - 1;
      if (result == DashError::Ok &&
          !secp256k1_sign_der(private_keys[index], digest, signatures[index],
                              &der_size))
      {
        result = DashError::CryptoFailure;
      }
      if (result == DashError::Ok && der_size > kDashMaxDerSignatureSize)
        result = DashError::BufferTooSmall;
      secure_zero(digest, sizeof(digest));
      if (result != DashError::Ok || der_size + 1 > sizeof(signatures[index]))
      {
        secure_zero(signatures, sizeof(signatures));
        secure_zero(public_keys, sizeof(public_keys));
        secure_zero(private_keys, sizeof(private_keys));
        secure_zero(unsigned_transaction, sizeof(unsigned_transaction));
        return result == DashError::Ok ? DashError::BufferTooSmall : result;
      }
      signatures[index][der_size] = static_cast<uint8_t>(kSighashAll);
      signature_sizes[index] = static_cast<uint8_t>(der_size + 1);
    }
    secure_zero(unsigned_transaction, sizeof(unsigned_transaction));
    secure_zero(private_keys, sizeof(private_keys));
    result = serialize_request(request, signatures, signature_sizes, public_keys,
                               out_transaction, in_out_size);
    secure_zero(signatures, sizeof(signatures));
    secure_zero(signature_sizes, sizeof(signature_sizes));
    secure_zero(public_keys, sizeof(public_keys));
    return result;
  }

  DashError dash_validate_inputs(const DashTransaction &request,
                                 const HdPrivateNode &master)
  {
    return validate_request(request, master, nullptr, nullptr);
  }

  const char *dash_error_text(DashError error)
  {
    switch (error)
    {
    case DashError::Ok:
      return "ok";
    case DashError::InvalidArgument:
      return "invalid argument";
    case DashError::Truncated:
      return "truncated payload";
    case DashError::NonCanonical:
      return "non-canonical encoding";
    case DashError::Unsupported:
      return "unsupported transaction form";
    case DashError::TooLarge:
      return "payload too large";
    case DashError::MissingField:
      return "missing field";
    case DashError::DuplicateField:
      return "duplicate input";
    case DashError::WrongWallet:
      return "input does not belong to this wallet";
    case DashError::InvalidAmount:
      return "invalid amount";
    case DashError::FeePolicy:
      return "fee exceeds the local policy";
    case DashError::CryptoFailure:
      return "cryptographic failure";
    case DashError::BufferTooSmall:
      return "output buffer too small";
    }
    return "unknown";
  }

  void clear_dash_transaction(DashTransaction *request)
  {
    if (request == nullptr)
      return;
    memset(request, 0, sizeof(*request));
  }

  bool run_dash_self_tests()
  {
    uint8_t digest[kSha256Size];
    bool passed =
        dash_legacy_sighash(kDashMainnetV3Transaction,
                            sizeof(kDashMainnetV3Transaction), 0,
                            kDashMainnetV3Script, sizeof(kDashMainnetV3Script),
                            static_cast<uint8_t>(kSighashAll), digest) ==
            DashError::Ok &&
        crypto_constant_time_equal(digest, kDashMainnetV3Digest, kSha256Size);
    passed =
        passed &&
        dash_legacy_sighash(kDashMainnetV2Transaction,
                            sizeof(kDashMainnetV2Transaction), 0,
                            kDashMainnetV2Script, sizeof(kDashMainnetV2Script),
                            static_cast<uint8_t>(kSighashAll), digest) ==
            DashError::Ok &&
        crypto_constant_time_equal(digest, kDashMainnetV2Digest, kSha256Size);
    secure_zero(digest, sizeof(digest));

    // A special transaction carries an extraPayload this module cannot decode.
    // Hashing the prefix would produce a digest for bytes that are not the
    // transaction on the wire, so the form is refused outright.
    uint8_t mutated[sizeof(kDashMainnetV3Transaction) + 1];
    memcpy(mutated, kDashMainnetV3Transaction, sizeof(kDashMainnetV3Transaction));
    mutated[2] = 0x01; // nType = 1, ProRegTx
    passed = passed &&
             dash_legacy_sighash(mutated, sizeof(kDashMainnetV3Transaction), 0,
                                 kDashMainnetV3Script,
                                 sizeof(kDashMainnetV3Script), kSighashAll,
                                 digest) == DashError::Unsupported;
    mutated[2] = 0x00;
    mutated[0] = 0x04; // Dash has no transaction version 4
    passed = passed &&
             dash_legacy_sighash(mutated, sizeof(kDashMainnetV3Transaction), 0,
                                 kDashMainnetV3Script,
                                 sizeof(kDashMainnetV3Script), kSighashAll,
                                 digest) == DashError::Unsupported;
    mutated[0] = 0x03;

    bool prefixes_rejected = true;
    for (size_t length = 0; length < sizeof(kDashMainnetV3Transaction); ++length)
    {
      if (dash_legacy_sighash(mutated, length, 0, kDashMainnetV3Script,
                              sizeof(kDashMainnetV3Script), kSighashAll,
                              digest) == DashError::Ok)
      {
        prefixes_rejected = false;
      }
    }
    passed = passed && prefixes_rejected;
    mutated[sizeof(kDashMainnetV3Transaction)] = 0x00;
    passed = passed && dash_legacy_sighash(
                           mutated, sizeof(kDashMainnetV3Transaction) + 1, 0,
                           kDashMainnetV3Script, sizeof(kDashMainnetV3Script),
                           kSighashAll, digest) == DashError::NonCanonical;
    secure_zero(mutated, sizeof(mutated));
    secure_zero(digest, sizeof(digest));

    DashTransaction parsed;
    passed = passed &&
             dash_parse_review_payload(kDashSelfTestPayload,
                                       sizeof(kDashSelfTestPayload),
                                       kSelfTestChain, &parsed) == DashError::Ok;
    passed = passed && parsed.version == kDashVersion && parsed.lock_time == 0 &&
             parsed.input_count == 1 && parsed.output_count == 2;
    passed = passed && parsed.fee == kDashSelfTestFee &&
             parsed.estimated_vbytes == kDashSelfTestVbytes;
    passed = passed && strcmp(parsed.inputs[0].address, kDashSelfTestAddress) == 0;
    passed = passed &&
             strcmp(parsed.outputs[0].address, kDashSelfTestExternalAddress) == 0;
    passed = passed && strcmp(parsed.outputs[1].address, kDashSelfTestAddress) == 0;
    clear_dash_transaction(&parsed);

    bool payload_prefixes_rejected = true;
    for (size_t length = 0; length < sizeof(kDashSelfTestPayload); ++length)
    {
      DashTransaction probe;
      if (dash_parse_review_payload(kDashSelfTestPayload, length, kSelfTestChain,
                                    &probe) == DashError::Ok)
      {
        payload_prefixes_rejected = false;
      }
      secure_zero(&probe, sizeof(probe));
    }
    passed = passed && payload_prefixes_rejected;

    uint8_t payload[sizeof(kDashSelfTestPayload) + 1];
    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    payload[0] = 'X';
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::NonCanonical);
    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    payload[sizeof(kDashSelfTestPayload)] = 0x00;
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload) + 1,
                                         DashError::NonCanonical);

    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    payload[kPayloadInputCountOffset] = 0;
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::TooLarge);
    payload[kPayloadInputCountOffset] = kDashMaxInputs + 1;
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::TooLarge);

    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    payload[kPayloadOutputCountOffset] = 0;
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::TooLarge);
    payload[kPayloadOutputCountOffset] = kDashMaxOutputs + 1;
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::TooLarge);
    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    payload[kPayloadPrevoutScriptOffset] = 0x75; // OP_DROP instead of OP_DUP
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::Unsupported);
    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    payload[kPayloadPrevoutScriptOffset - 1] = 24;
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::Unsupported);

    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    payload[kPayloadLastOutputScriptOffset] = 0x75;
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::Unsupported);

    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    store_u64(payload + kPayloadLastOutputValueOffset, 0);
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::InvalidAmount);
    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    store_u64(payload + kPayloadLastOutputValueOffset, kDashMaxDuffs + 1);
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::InvalidAmount);

    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    store_u64(payload + kPayloadLastOutputValueOffset, 110000000ULL);
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::InvalidAmount);
    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    store_u64(payload + kPayloadLastOutputValueOffset, 100000000ULL);
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::FeePolicy);

    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    payload[kPayloadChangeOffset] = 2;
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::InvalidArgument);
    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    store_u32(payload + kPayloadAccountOffset, kHardenedOffset);
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::InvalidArgument);
    memcpy(payload, kDashSelfTestPayload, sizeof(kDashSelfTestPayload));
    store_u32(payload + kPayloadLockTimeOffset, 0x80000000UL);
    passed = passed && payload_result_is(payload, sizeof(kDashSelfTestPayload),
                                         DashError::InvalidArgument);

    uint8_t duplicated[sizeof(kDashSelfTestPayload) + kSelfTestInputRecordSize];
    memcpy(duplicated, kDashSelfTestPayload, kPayloadOutputCountOffset);
    memcpy(duplicated + kPayloadOutputCountOffset,
           kDashSelfTestPayload + kPayloadInputCountOffset + 1,
           kSelfTestInputRecordSize);
    memcpy(duplicated + kPayloadOutputCountOffset + kSelfTestInputRecordSize,
           kDashSelfTestPayload + kPayloadOutputCountOffset,
           sizeof(kDashSelfTestPayload) - kPayloadOutputCountOffset);
    duplicated[kPayloadInputCountOffset] = 2;
    passed = passed && payload_result_is(duplicated, sizeof(duplicated),
                                         DashError::DuplicateField);
    secure_zero(duplicated, sizeof(duplicated));
    secure_zero(payload, sizeof(payload));
    return passed;
  }

  bool run_dash_signature_self_test()
  {
    HdPrivateNode master = {};
    for (size_t index = 0; index < kPrivateKeySize; ++index)
    {
      master.private_key[index] = static_cast<uint8_t>(index + 1);
      master.chain_code[index] = static_cast<uint8_t>(0x80 + index);
    }
    DashTransaction request;
    bool passed =
        dash_parse_review_payload(kDashSelfTestPayload,
                                  sizeof(kDashSelfTestPayload), kSelfTestChain,
                                  &request) == DashError::Ok;
    passed = passed && request.fee == kDashSelfTestFee &&
             request.estimated_vbytes == kDashSelfTestVbytes;
    uint8_t signed_transaction[kDashMaxTransactionSize];
    size_t signed_size = sizeof(signed_transaction);
    passed = passed && dash_sign_transaction(request, master, signed_transaction,
                                             &signed_size) == DashError::Ok;
    passed = passed && signed_size == sizeof(kDashSelfTestSigned) &&
             crypto_constant_time_equal(signed_transaction, kDashSelfTestSigned,
                                        signed_size);
    // The pinned payload must belong to the pinned key: the prevout script has
    // to pay HASH160 of exactly the public key this vector was generated for.
    uint8_t pinned_hash[kRipemd160Size];
    passed = passed &&
             crypto_hash160(kDashSelfTestPublicKey, kCompressedPublicKeySize,
                            pinned_hash) &&
             crypto_constant_time_equal(pinned_hash, request.inputs[0].script + 3,
                                        kRipemd160Size);
    secure_zero(pinned_hash, sizeof(pinned_hash));
    passed = passed && signature_verifies(signed_transaction, signed_size,
                                          request.inputs[0].script,
                                          request.inputs[0].script_size,
                                          kDashSelfTestDigest);
    // The signer is deterministic: a second run that differs would mean the
    // key or the nonce leaked into some state that survives a call.
    uint8_t repeat[kDashMaxTransactionSize];
    size_t repeat_size = sizeof(repeat);
    passed = passed && dash_sign_transaction(request, master, repeat, &repeat_size) == DashError::Ok &&
             repeat_size == signed_size &&
             crypto_constant_time_equal(repeat, signed_transaction, signed_size);
    secure_zero(repeat, sizeof(repeat));

    // Any deviation in the request is refused rather than signed.
    DashTransaction tampered = request;
    tampered.fee += 1;
    passed = passed && dash_sign_transaction(tampered, master, signed_transaction,
                                             &signed_size) == DashError::FeePolicy;
    tampered = request;
    tampered.version = 2;
    passed = passed &&
             dash_sign_transaction(tampered, master, signed_transaction,
                                   &signed_size) == DashError::InvalidArgument;
    tampered = request;
    tampered.inputs[0].address_index = 1;
    passed = passed &&
             dash_sign_transaction(tampered, master, signed_transaction,
                                   &signed_size) == DashError::WrongWallet;
    tampered = request;
    tampered.estimated_vbytes += 1;
    passed = passed &&
             dash_sign_transaction(tampered, master, signed_transaction,
                                   &signed_size) == DashError::FeePolicy;
    tampered = request;
    tampered.chain.p2pkh_version = 0x00; // Bitcoin's prefix is not Dash's
    passed = passed &&
             dash_sign_transaction(tampered, master, signed_transaction,
                                   &signed_size) == DashError::Unsupported;
    secure_zero(&tampered, sizeof(tampered));
    clear_dash_transaction(&request);
    secure_zero(signed_transaction, sizeof(signed_transaction));
    secure_zero(&master, sizeof(master));
    return passed;
  }

} // namespace hexwallet
