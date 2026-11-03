#include "BitcoinTransaction.h"

#include "src/EcdsaCurve.h"
#include "src/Secp256k1Sign.h"
#include "PeercoinSighash.h"

#include "WalletAltAddresses.h"

#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include "RandomSource.h"
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletAddresses.h"

namespace hexwallet
{
  namespace
  {

    constexpr uint64_t kMaximumBitcoinSupply = 21000000ULL * 100000000ULL;
    constexpr uint32_t kSighashAll = 1;
    constexpr uint32_t kSighashForkIdAll = 0x41;
    constexpr size_t kLegacyP2pkhScriptSize = 25;
    constexpr size_t kMaxLegacyScriptSigSize = 1 + kBitcoinMaxDerSignatureSize + 1 + 1 + kCompressedPublicKeySize;
    constexpr uint8_t kPsbtMagic[] = {'p', 's', 'b', 't', 0xff};

    // PSBT v2 key types. BIP370 keeps PSBT_GLOBAL_VERSION (0xfb) at 2 and moves
    // the transaction itself into the maps; there is no version 1 on the wire,
    // which is why this reader accepts exactly v0 and v2.
    constexpr uint8_t kPsbtGlobalUnsignedTx = 0x00;
    constexpr uint8_t kPsbtGlobalXpub = 0x01;
    constexpr uint8_t kPsbtGlobalTxVersion = 0x02;
    constexpr uint8_t kPsbtGlobalFallbackLocktime = 0x03;
    constexpr uint8_t kPsbtGlobalInputCount = 0x04;
    constexpr uint8_t kPsbtGlobalOutputCount = 0x05;
    constexpr uint8_t kPsbtGlobalTxModifiable = 0x06;
    constexpr uint8_t kPsbtGlobalVersion = 0xfb;
    constexpr uint8_t kPsbtInNonWitnessUtxo = 0x00;
    constexpr uint8_t kPsbtInPartialSig = 0x02;
    constexpr uint8_t kPsbtInWitnessUtxo = 0x01;
    constexpr uint8_t kPsbtInSighashType = 0x03;
    constexpr uint8_t kPsbtInRedeemScript = 0x04;
    constexpr uint8_t kPsbtInBip32Derivation = 0x06;
    constexpr uint8_t kPsbtInTapKeySig = 0x13;
    constexpr uint8_t kPsbtInTapBip32Derivation = 0x16;
    constexpr uint8_t kPsbtInTapInternalKey = 0x17;
    constexpr uint8_t kPsbtInTapMerkleRoot = 0x18;
    constexpr uint8_t kPsbtInPreviousTxid = 0x0e;
    constexpr uint8_t kPsbtInOutputIndex = 0x0f;
    constexpr uint8_t kPsbtInSequence = 0x10;
    constexpr uint8_t kPsbtInRequiredTimeLocktime = 0x11;
    constexpr uint8_t kPsbtInRequiredHeightLocktime = 0x12;
    constexpr uint8_t kPsbtOutBip32Derivation = 0x02;
    constexpr uint8_t kPsbtOutAmount = 0x03;
    constexpr uint8_t kPsbtOutScript = 0x04;
    // nLockTime values below this are block heights, at or above it they are
    // Unix timestamps (Bitcoin Core's LOCKTIME_THRESHOLD).
    constexpr uint32_t kLocktimeThreshold = 500000000U;

    // Checkpoint index for run_bitcoin_transaction_self_test(), reported through
    // bitcoin_self_test_stage() so a device failure names the step it reached.
    int g_bitcoin_stage = 0;

    struct PsbtGlobalFields
    {
      bool has_unsigned_tx;
      const uint8_t *unsigned_tx;
      size_t unsigned_tx_size;
      bool has_psbt_version;
      uint32_t psbt_version;
      bool has_tx_version;
      uint32_t tx_version;
      bool has_fallback_locktime;
      uint32_t fallback_locktime;
      bool has_input_count;
      uint64_t input_count;
      bool has_output_count;
      uint64_t output_count;
      bool has_tx_modifiable;
      uint32_t tx_modifiable;
    };

    struct PsbtInputLocktime
    {
      bool has_time;
      bool has_height;
      uint32_t time;
      uint32_t height;
    };

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

    bool taproot_network(const BitcoinChainParams &chain) {
      return chain.sighash==SighashFamily::Bitcoin && chain.network_id &&
          (!strcmp(chain.network_id,"btc") || !strcmp(chain.network_id,"btc44") ||
           !strcmp(chain.network_id,"btc49") || !strcmp(chain.network_id,"btc86"));
    }

    // Render a scriptPubKey in the address format the target chain actually uses.
    WalletError chain_address_from_script(const BitcoinChainParams &chain,
                                          const uint8_t *script, size_t script_size,
                                          char *out, size_t out_size)
    {
      if(script_size==34 && script[0]==0x51 && script[1]==32 && !taproot_network(chain))
        return WalletError::InvalidArgument;
      if (chain.cashaddr_prefix != nullptr)
      {
        return address_cashaddr_from_script(chain.cashaddr_prefix, script, script_size,
                                            out, out_size);
      }
      // Groestlcoin's base58 checksum is double Groestl-512, not SHA-256. Only the
      // GroestlLegacy family reaches that path, and the network self-test refuses a
      // policy row that pairs that family with any other address encoding.
      if (chain.sighash == SighashFamily::GroestlLegacy)
      {
        return address_from_script_groestl(chain.address, script, script_size, out,
                                           out_size);
      }
      return address_from_script(chain.address, script, script_size, out, out_size);
    }

    bool add_u64(uint64_t left, uint64_t right, uint64_t *out)
    {
      if (UINT64_MAX - left < right)
        return false;
      *out = left + right;
      return true;
    }

    bool distinct_outpoints(const BitcoinSigningRequest &request)
    {
      for (size_t i = 0; i < request.input_count; ++i)
        for (size_t j = 0; j < i; ++j)
          if (request.inputs[i].previous_index == request.inputs[j].previous_index &&
              memcmp(request.inputs[i].previous_txid, request.inputs[j].previous_txid, 32) == 0)
            return false;
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
      *out = static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) | (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24);
      return true;
    }

    bool read_u64(Cursor *cursor, uint64_t *out)
    {
      const uint8_t *bytes;
      if (!read_bytes(cursor, 8, &bytes))
        return false;
      uint64_t value = 0;
      for (size_t index = 0; index < 8; ++index)
        value |= static_cast<uint64_t>(bytes[index]) << (index * 8);
      *out = value;
      return true;
    }

    TransactionError read_compact_size(Cursor *cursor, uint64_t *out)
    {
      const uint8_t *first;
      if (!read_bytes(cursor, 1, &first))
        return TransactionError::Truncated;
      if (*first < 0xfd)
      {
        *out = *first;
        return TransactionError::Ok;
      }
      const size_t length = *first == 0xfd ? 2 : (*first == 0xfe ? 4 : 8);
      const uint8_t *bytes;
      if (!read_bytes(cursor, length, &bytes))
        return TransactionError::Truncated;
      uint64_t value = 0;
      for (size_t index = 0; index < length; ++index)
        value |= static_cast<uint64_t>(bytes[index]) << (index * 8);
      if ((length == 2 && value < 0xfd) || (length == 4 && value <= 0xffff) || (length == 8 && value <= 0xffffffffULL))
        return TransactionError::NonCanonical;
      *out = value;
      return TransactionError::Ok;
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
      uint8_t bytes[4] = {static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8),
                          static_cast<uint8_t>(value >> 16), static_cast<uint8_t>(value >> 24)};
      return write_bytes(writer, bytes, sizeof(bytes));
    }

    bool write_u64(Writer *writer, uint64_t value)
    {
      uint8_t bytes[8];
      for (size_t index = 0; index < sizeof(bytes); ++index)
        bytes[index] = static_cast<uint8_t>(value >> (index * 8));
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
        const uint8_t bytes[3] = {0xfd, static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8)};
        return write_bytes(writer, bytes, sizeof(bytes));
      }
      if (value <= 0xffffffffULL)
      {
        const uint8_t prefix = 0xfe;
        return write_bytes(writer, &prefix, 1) && write_u32(writer, static_cast<uint32_t>(value));
      }
      const uint8_t prefix = 0xff;
      return write_bytes(writer, &prefix, 1) && write_u64(writer, value);
    }

    TransactionError read_map_item(Cursor *cursor, const uint8_t **key, size_t *key_size,
                                   const uint8_t **value, size_t *value_size, bool *end)
    {
      uint64_t compact_key_size;
      TransactionError result = read_compact_size(cursor, &compact_key_size);
      if (result != TransactionError::Ok)
        return result;
      if (compact_key_size == 0)
      {
        *end = true;
        return TransactionError::Ok;
      }
      if (compact_key_size > HEXWALLET_MAX_PSBT_BYTES || compact_key_size > SIZE_MAX)
        return TransactionError::TooLarge;
      if (!read_bytes(cursor, static_cast<size_t>(compact_key_size), key))
        return TransactionError::Truncated;
      uint64_t compact_value_size;
      result = read_compact_size(cursor, &compact_value_size);
      if (result != TransactionError::Ok)
        return result;
      if (compact_value_size > HEXWALLET_MAX_PSBT_BYTES || compact_value_size > SIZE_MAX)
        return TransactionError::TooLarge;
      if (!read_bytes(cursor, static_cast<size_t>(compact_value_size), value))
        return TransactionError::Truncated;
      *key_size = static_cast<size_t>(compact_key_size);
      *value_size = static_cast<size_t>(compact_value_size);
      *end = false;
      return TransactionError::Ok;
    }

    TransactionError parse_unsigned_transaction(const uint8_t *data, size_t size,
                                                const BitcoinChainParams &chain,
                                                BitcoinSigningRequest *request)
    {
      Cursor cursor = {data, size, 0};
      if (!read_u32(&cursor, &request->version) || (request->version != 1 && request->version != 2))
      {
        return TransactionError::Unsupported;
      }
      uint64_t input_count;
      TransactionError result = read_compact_size(&cursor, &input_count);
      if (result != TransactionError::Ok)
        return result;
      if (input_count == 0 || input_count > kBitcoinMaxInputs)
        return TransactionError::TooLarge;
      request->input_count = static_cast<uint8_t>(input_count);
      for (size_t index = 0; index < input_count; ++index)
      {
        const uint8_t *txid;
        if (!read_bytes(&cursor, 32, &txid) || !read_u32(&cursor, &request->inputs[index].previous_index))
        {
          return TransactionError::Truncated;
        }
        memcpy(request->inputs[index].previous_txid, txid, 32);
        uint64_t script_size;
        result = read_compact_size(&cursor, &script_size);
        if (result != TransactionError::Ok)
          return result;
        if (script_size != 0)
          return TransactionError::Unsupported;
        if (!read_u32(&cursor, &request->inputs[index].sequence))
          return TransactionError::Truncated;
      }
      if (!distinct_outpoints(*request))
        return TransactionError::DuplicateField;
      uint64_t output_count;
      result = read_compact_size(&cursor, &output_count);
      if (result != TransactionError::Ok)
        return result;
      if (output_count == 0 || output_count > kBitcoinMaxOutputs)
        return TransactionError::TooLarge;
      request->output_count = static_cast<uint8_t>(output_count);
      for (size_t index = 0; index < output_count; ++index)
      {
        BitcoinOutput &output = request->outputs[index];
        if (!read_u64(&cursor, &output.value) || output.value > kMaximumBitcoinSupply)
        {
          return TransactionError::InvalidAmount;
        }
        uint64_t script_size;
        result = read_compact_size(&cursor, &script_size);
        if (result != TransactionError::Ok)
          return result;
        if (script_size > kBitcoinMaxScriptSize)
          return TransactionError::Unsupported;
        const uint8_t *script;
        if (!read_bytes(&cursor, static_cast<size_t>(script_size), &script))
          return TransactionError::Truncated;
        output.script_size = static_cast<uint8_t>(script_size);
        memcpy(output.script, script, output.script_size);
        if (chain_address_from_script(chain, output.script, output.script_size,
                                      output.address, sizeof(output.address)) != WalletError::Ok)
        {
          return TransactionError::Unsupported;
        }
        if (!add_u64(request->output_total, output.value, &request->output_total))
          return TransactionError::InvalidAmount;
      }
      if (!read_u32(&cursor, &request->lock_time))
        return TransactionError::Truncated;
      return cursor.position == cursor.size ? TransactionError::Ok : TransactionError::NonCanonical;
    }

    bool master_fingerprint(const HdPrivateNode &master, uint8_t out[4])
    {
      uint8_t public_key[kCompressedPublicKeySize];
      uint8_t hash[kRipemd160Size];
      const bool ok = public_key_from_private(master.private_key, public_key) == WalletError::Ok && crypto_hash160(public_key, sizeof(public_key), hash);
      if (ok)
        memcpy(out, hash, 4);
      secure_zero(public_key, sizeof(public_key));
      secure_zero(hash, sizeof(hash));
      return ok;
    }

    WalletError derive_array_path(const HdPrivateNode &master, const uint32_t *path,
                                  size_t depth, HdPrivateNode *out)
    {
      if (path == nullptr || out == nullptr || depth == 0 || depth > kBitcoinMaxPathDepth)
      {
        return WalletError::InvalidPath;
      }
      HdPrivateNode current = master;
      for (size_t index = 0; index < depth; ++index)
      {
        HdPrivateNode next;
        const WalletError result = hd_private_derive(&current, path[index], &next);
        secure_zero(&current, sizeof(current));
        if (result != WalletError::Ok)
          return result;
        current = next;
      }
      *out = current;
      return WalletError::Ok;
    }

    bool valid_bitcoin_single_sig_path(const uint32_t *path, size_t depth)
    {
      return depth == 5 && (path[0] == (44U | kHardenedOffset) || path[0] == (49U | kHardenedOffset) || path[0] == (84U | kHardenedOffset) || path[0] == (86U | kHardenedOffset)) && path[1] == kHardenedOffset && path[2] >= kHardenedOffset && path[3] <= 1 && path[4] < kHardenedOffset;
    }

    bool path_matches_spend_type(const BitcoinInput &input)
    {
      if (!valid_bitcoin_single_sig_path(input.path, input.path_depth))
        return false;
      switch (input.spend_type)
      {
      case BitcoinSpendType::TaprootBip86:
        return input.path[0] == (86U | kHardenedOffset);
      case BitcoinSpendType::NativeP2wpkh:
        return input.path[0] == (84U | kHardenedOffset);
      case BitcoinSpendType::NestedP2shP2wpkh:
        return input.path[0] == (49U | kHardenedOffset);
      case BitcoinSpendType::LegacyP2pkh:
        return input.path[0] == (44U | kHardenedOffset);
      }
      return false;
    }

    TransactionError parse_derivation(const uint8_t *key, size_t key_size,
                                      const uint8_t *value, size_t value_size,
                                      const HdPrivateNode &master, BitcoinInput *input,
                                      BitcoinOutput *output, bool taproot = false)
    {
      if (taproot)
      {
        // BIP86 internal keys have no leaf hashes. Reject script-path metadata.
        if (value_size == 0 || value[0] != 0)
          return TransactionError::Unsupported;
        ++value;
        --value_size;
      }
      if (key_size != (taproot ? 33U : 34U) || value_size < 8 || (value_size - 4) % 4 != 0)
        return TransactionError::NonCanonical;
      const size_t depth = (value_size - 4) / 4;
      if (depth > kBitcoinMaxPathDepth)
        return TransactionError::TooLarge;
      uint8_t expected_fingerprint[4];
      if (!master_fingerprint(master, expected_fingerprint))
        return TransactionError::CryptoFailure;
      const bool fingerprint_ok = crypto_constant_time_equal(value, expected_fingerprint, 4);
      secure_zero(expected_fingerprint, sizeof(expected_fingerprint));
      if (!fingerprint_ok)
        return TransactionError::WrongWallet;
      uint32_t path[kBitcoinMaxPathDepth] = {};
      for (size_t index = 0; index < depth; ++index)
      {
        const uint8_t *part = value + 4 + index * 4;
        path[index] = static_cast<uint32_t>(part[0]) | (static_cast<uint32_t>(part[1]) << 8) | (static_cast<uint32_t>(part[2]) << 16) | (static_cast<uint32_t>(part[3]) << 24);
      }
      if (!valid_bitcoin_single_sig_path(path, depth))
        return TransactionError::Unsupported;
      if (taproot != (path[0] == (86U | kHardenedOffset)))
        return TransactionError::Unsupported;
      HdPrivateNode derived;
      uint8_t public_key[kCompressedPublicKeySize];
      const WalletError derive_result = derive_array_path(master, path, depth, &derived);
      const bool public_ok = derive_result == WalletError::Ok && public_key_from_private(derived.private_key, public_key) == WalletError::Ok;
      secure_zero(&derived, sizeof(derived));
      if (!public_ok)
      {
        secure_zero(public_key, sizeof(public_key));
        return TransactionError::CryptoFailure;
      }
      const bool key_ok = crypto_constant_time_equal(key + 1, public_key + (taproot ? 1 : 0), taproot ? 32 : sizeof(public_key));
      if (input != nullptr)
      {
        memcpy(input->path, path, depth * sizeof(uint32_t));
        input->path_depth = static_cast<uint8_t>(depth);
        memcpy(input->public_key, public_key, sizeof(public_key));
      }
      if (output != nullptr && key_ok)
      {
        uint8_t hash[kRipemd160Size] = {};
        uint8_t redeem_script[22] = {0, 20};
        uint8_t redeem_hash[kRipemd160Size] = {};
        const bool hashed = crypto_hash160(public_key, sizeof(public_key), hash);
        memcpy(redeem_script + 2, hash, sizeof(hash));
        const bool native = hashed && path[0] == (84U | kHardenedOffset) && output->script_size == 22 && output->script[0] == 0 && output->script[1] == 20 && crypto_constant_time_equal(output->script + 2, hash, sizeof(hash));
        const bool nested = hashed && path[0] == (49U | kHardenedOffset) && output->script_size == 23 && output->script[0] == 0xa9 && output->script[1] == 0x14 && output->script[22] == 0x87 && crypto_hash160(redeem_script, sizeof(redeem_script), redeem_hash) && crypto_constant_time_equal(output->script + 2, redeem_hash, sizeof(redeem_hash));
        const bool legacy = hashed && path[0] == (44U | kHardenedOffset) && output->script_size == kLegacyP2pkhScriptSize && output->script[0] == 0x76 && output->script[1] == 0xa9 && output->script[2] == 0x14 && output->script[23] == 0x88 && output->script[24] == 0xac && crypto_constant_time_equal(output->script + 3, hash, sizeof(hash));
        uint8_t output_key[32];
        const bool tap = taproot && output->script_size == 34 && output->script[0] == 0x51 && output->script[1] == 32 &&
                         taproot_bip86_output_key(public_key + 1, output_key) == WalletError::Ok &&
                         crypto_constant_time_equal(output_key, output->script + 2, 32);
        const bool script_ok = native || nested || legacy || tap;
        secure_zero(hash, sizeof(hash));
        secure_zero(redeem_script, sizeof(redeem_script));
        secure_zero(redeem_hash, sizeof(redeem_hash));
        if (!script_ok)
        {
          secure_zero(public_key, sizeof(public_key));
          secure_zero(path, sizeof(path));
          return TransactionError::WrongWallet;
        }
        output->wallet_owned = true;
        output->change = path[3] == 1;
      }
      secure_zero(public_key, sizeof(public_key));
      secure_zero(path, sizeof(path));
      return key_ok ? TransactionError::Ok : TransactionError::WrongWallet;
    }

    TransactionError parse_previous_transaction(const uint8_t *data, size_t size,
                                                const uint8_t expected_txid[32],
                                                uint32_t output_index,
                                                uint64_t *out_value,
                                                uint8_t *out_script,
                                                uint8_t *out_script_size)
    {
      Cursor cursor = {data, size, 0};
      uint32_t version;
      if (!read_u32(&cursor, &version))
        return TransactionError::Truncated;
      uint64_t input_count;
      TransactionError result = read_compact_size(&cursor, &input_count);
      if (result != TransactionError::Ok)
        return result;
      bool segwit = false;
      size_t inputs_offset = cursor.position;
      if (input_count == 0)
      {
        const uint8_t *flag;
        if (!read_bytes(&cursor, 1, &flag) || flag[0] != 0x01)
          return TransactionError::NonCanonical;
        // txid commits to the CompactSize input count as well as the inputs.
        inputs_offset = cursor.position;
        result = read_compact_size(&cursor, &input_count);
        if (result != TransactionError::Ok)
          return result;
        segwit = true;
      }
      if (input_count == 0 || input_count > 255)
        return TransactionError::Unsupported;
      for (uint64_t index = 0; index < input_count; ++index)
      {
        const uint8_t *txid;
        uint32_t previous_index;
        uint64_t script_size;
        const uint8_t *script;
        uint32_t sequence;
        if (!read_bytes(&cursor, 32, &txid) || !read_u32(&cursor, &previous_index))
          return TransactionError::Truncated;
        result = read_compact_size(&cursor, &script_size);
        if (result != TransactionError::Ok)
          return result;
        if (script_size > HEXWALLET_MAX_PSBT_BYTES || !read_bytes(&cursor, static_cast<size_t>(script_size), &script))
        {
          return TransactionError::Truncated;
        }
        if (!read_u32(&cursor, &sequence))
          return TransactionError::Truncated;
      }
      uint64_t output_count;
      result = read_compact_size(&cursor, &output_count);
      if (result != TransactionError::Ok)
        return result;
      if (output_count == 0 || output_count > 65535)
        return TransactionError::Unsupported;
      bool found = false;
      for (uint64_t index = 0; index < output_count; ++index)
      {
        uint64_t value;
        uint64_t script_size;
        const uint8_t *script;
        if (!read_u64(&cursor, &value))
          return TransactionError::Truncated;
        result = read_compact_size(&cursor, &script_size);
        if (result != TransactionError::Ok)
          return result;
        if (script_size > HEXWALLET_MAX_PSBT_BYTES || !read_bytes(&cursor, static_cast<size_t>(script_size), &script))
        {
          return TransactionError::Truncated;
        }
        if (index == output_index)
        {
          if (value > kMaximumBitcoinSupply || script_size > kBitcoinMaxScriptSize)
          {
            return TransactionError::Unsupported;
          }
          *out_value = value;
          *out_script_size = static_cast<uint8_t>(script_size);
          memcpy(out_script, script, static_cast<size_t>(script_size));
          found = true;
        }
      }
      const size_t witness_start = cursor.position;
      if (segwit)
      {
        bool has_witness = false;
        for (uint64_t index = 0; index < input_count; ++index)
        {
          uint64_t item_count;
          result = read_compact_size(&cursor, &item_count);
          if (result != TransactionError::Ok)
            return result;
          if (item_count > 1024)
            return TransactionError::Unsupported;
          has_witness = has_witness || item_count != 0;
          for (uint64_t item = 0; item < item_count; ++item)
          {
            uint64_t item_size;
            const uint8_t *item_data;
            result = read_compact_size(&cursor, &item_size);
            if (result != TransactionError::Ok)
              return result;
            if (item_size > HEXWALLET_MAX_PSBT_BYTES || !read_bytes(&cursor, static_cast<size_t>(item_size), &item_data))
            {
              return TransactionError::Truncated;
            }
          }
        }
        if (!has_witness)
          return TransactionError::NonCanonical;
      }
      const size_t witness_end = cursor.position;
      uint32_t lock_time;
      if (!read_u32(&cursor, &lock_time))
        return TransactionError::Truncated;
      if (cursor.position != cursor.size)
        return TransactionError::NonCanonical;
      (void)version;
      (void)lock_time;
      uint8_t txid[kSha256Size];
      const bool hashed = segwit
                              ? crypto_double_sha256_segments(data, 4, data + inputs_offset, witness_start - inputs_offset,
                                                              data + witness_end, size - witness_end, txid)
                              : crypto_double_sha256(data, size, txid);
      const bool matches = hashed && crypto_constant_time_equal(txid, expected_txid, sizeof(txid));
      secure_zero(txid, sizeof(txid));
      if (!matches)
        return TransactionError::WrongWallet;
      return found ? TransactionError::Ok : TransactionError::Truncated;
    }

    TransactionError classify_utxo_script(BitcoinInput *input, const uint8_t *script,
                                          uint8_t script_size, bool has_redeem_script,
                                          const uint8_t *redeem_script)
    {
      if (script_size == 34 && script[0] == 0x51 && script[1] == 32)
      {
        if (has_redeem_script)
          return TransactionError::Unsupported;
        input->spend_type = BitcoinSpendType::TaprootBip86;
        memcpy(input->taproot_output_key, script + 2, 32);
        return TransactionError::Ok;
      }
      if (script_size == 22 && script[0] == 0 && script[1] == 20)
      {
        if (has_redeem_script)
          return TransactionError::Unsupported;
        input->spend_type = BitcoinSpendType::NativeP2wpkh;
        memcpy(input->witness_key_hash, script + 2, sizeof(input->witness_key_hash));
        return TransactionError::Ok;
      }
      if (script_size == kLegacyP2pkhScriptSize && script[0] == 0x76 && script[1] == 0xa9 &&
          script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac)
      {
        if (has_redeem_script)
          return TransactionError::Unsupported;
        input->spend_type = BitcoinSpendType::LegacyP2pkh;
        memcpy(input->witness_key_hash, script + 3, sizeof(input->witness_key_hash));
        return TransactionError::Ok;
      }
      if (script_size == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87)
      {
        uint8_t redeem_hash[kRipemd160Size];
        const bool valid_redeem = has_redeem_script && crypto_hash160(redeem_script, 22, redeem_hash) &&
                                  crypto_constant_time_equal(redeem_hash, script + 2, sizeof(redeem_hash));
        secure_zero(redeem_hash, sizeof(redeem_hash));
        if (!valid_redeem)
          return TransactionError::MissingField;
        input->spend_type = BitcoinSpendType::NestedP2shP2wpkh;
        memcpy(input->p2sh_hash, script + 2, sizeof(input->p2sh_hash));
        memcpy(input->witness_key_hash, redeem_script + 2, sizeof(input->witness_key_hash));
        return TransactionError::Ok;
      }
      return TransactionError::Unsupported;
    }

    // Applies the BIP371 fields once the UTXO script has named the spend type.
    // Split out because both PSBT readers end their input map the same way and
    // the taproot rules must not drift between the two envelopes.
    TransactionError apply_taproot_fields(BitcoinInput *input, bool has_internal_key,
                                         const uint8_t *internal_key, bool has_sighash,
                                         uint32_t declared_sighash)
    {
      if (input == nullptr)
        return TransactionError::InvalidArgument;
      if (input->spend_type != BitcoinSpendType::TaprootBip86)
      {
        // A taproot-only field on a non-taproot input means the constructor and
        // the UTXO disagree about what is being spent.
        return has_internal_key ? TransactionError::Unsupported : TransactionError::Ok;
      }
      if (has_internal_key &&
          !crypto_constant_time_equal(internal_key, input->public_key + 1, 32))
        return TransactionError::WrongWallet;
      const uint32_t chosen = has_sighash ? declared_sighash : 0;
      if (chosen > 1)
        return TransactionError::Unsupported;
      input->taproot_sighash = static_cast<uint8_t>(chosen);
      return TransactionError::Ok;
    }

    TransactionError parse_input_map(Cursor *cursor, const HdPrivateNode &master,
                                     const BitcoinChainParams &chain, BitcoinInput *input)
    {
      bool has_witness_utxo = false;
      bool has_non_witness_utxo = false;
      bool has_derivation = false;
      bool has_sighash = false;
      bool has_redeem_script = false;
      bool has_tap_internal_key = false;
      uint8_t tap_internal_key[kPrivateKeySize] = {};
      uint32_t declared_sighash = 0;
      uint8_t partial_sig_count = 0;
      uint8_t redeem_script[22] = {};
      uint64_t utxo_value = 0;
      uint8_t utxo_script[kBitcoinMaxScriptSize + 1] = {};
      uint8_t utxo_script_size = 0;
      const uint32_t expected_sighash = chain.sighash == SighashFamily::ForkId
                                            ? (chain.fork_id << 8) | kSighashForkIdAll
                                            : kSighashAll;
      while (true)
      {
        const uint8_t *key;
        const uint8_t *value;
        size_t key_size;
        size_t value_size;
        bool end;
        TransactionError result = read_map_item(cursor, &key, &key_size, &value, &value_size, &end);
        if (result != TransactionError::Ok || end)
        {
          if (result != TransactionError::Ok)
            return result;
          if (!has_derivation)
            return TransactionError::MissingField;
          if (has_witness_utxo == has_non_witness_utxo)
            return TransactionError::MissingField;
          input->value = utxo_value;
          result = classify_utxo_script(input, utxo_script, utxo_script_size,
                                        has_redeem_script, redeem_script);
          secure_zero(redeem_script, sizeof(redeem_script));
          if (result != TransactionError::Ok)
            return result;
          result = apply_taproot_fields(input, has_tap_internal_key, tap_internal_key,
                                        has_sighash, declared_sighash);
          if(input->spend_type!=BitcoinSpendType::TaprootBip86 && has_sighash && declared_sighash!=expected_sighash)
            return TransactionError::Unsupported;
          secure_zero(tap_internal_key, sizeof(tap_internal_key));
          if (result != TransactionError::Ok)
            return result;
          const bool family_ok =
              input->spend_type == BitcoinSpendType::TaprootBip86
                  ? taproot_network(chain)
                  : (sighash_family_is_legacy(chain.sighash) ||
                     (chain.sighash == SighashFamily::ForkId &&
                      input->spend_type == BitcoinSpendType::LegacyP2pkh));
          if (!family_ok)
            return TransactionError::Unsupported;
          return path_matches_spend_type(*input) ? TransactionError::Ok : TransactionError::WrongWallet;
        }
        if (key_size == 1 && key[0] == 0x00)
        {
          if (has_non_witness_utxo)
            return TransactionError::DuplicateField;
          result = parse_previous_transaction(value, value_size, input->previous_txid,
                                              input->previous_index, &utxo_value,
                                              utxo_script, &utxo_script_size);
          if (result != TransactionError::Ok)
            return result;
          has_non_witness_utxo = true;
        }
        else if (key_size == 1 && key[0] == 0x01)
        {
          if (has_witness_utxo)
            return TransactionError::DuplicateField;
          Cursor utxo = {value, value_size, 0};
          uint64_t script_size;
          if (!read_u64(&utxo, &utxo_value) || utxo_value > kMaximumBitcoinSupply)
          {
            return TransactionError::InvalidAmount;
          }
          result = read_compact_size(&utxo, &script_size);
          if (result != TransactionError::Ok)
            return result;
          const uint8_t *script;
          if (script_size > kBitcoinMaxScriptSize || !read_bytes(&utxo, static_cast<size_t>(script_size), &script) || utxo.position != utxo.size)
          {
            return TransactionError::Unsupported;
          }
          // Legacy SIGHASH_ALL does not commit to the spent amount. A host-only
          // witness_utxo could therefore make an excessive actual fee look small.
          // ForkID commits to the amount and intentionally keeps its own policy.
          if (sighash_family_is_legacy(chain.sighash) && script_size == 25 &&
              script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
              script[23] == 0x88 && script[24] == 0xac)
            return TransactionError::MissingField;
          memcpy(utxo_script, script, static_cast<size_t>(script_size));
          utxo_script_size = static_cast<uint8_t>(script_size);
          has_witness_utxo = true;
        }
        else if (key_size == 34 && key[0] == kPsbtInBip32Derivation)
        {
          if (has_derivation)
            return TransactionError::DuplicateField;
          result = parse_derivation(key, key_size, value, value_size, master, input, nullptr);
          if (result != TransactionError::Ok)
            return result;
          has_derivation = true;
        }
        else if (key_size == 34 && key[0] == kPsbtInPartialSig)
        {
          // Already-signed PSBTs are a normal input: another party may have gone
          // first. Only the shape is checked here; whether the key belongs to
          // this wallet is decided by bitcoin_sign_psbt() before it writes.
          if ((key[1] != 0x02 && key[1] != 0x03) || value_size < 2 ||
              value_size > kBitcoinMaxDerSignatureSize + 1)
            return TransactionError::NonCanonical;
          if (partial_sig_count >= kBitcoinMaxInputs)
            return TransactionError::TooLarge;
          ++partial_sig_count;
        }
        else if (key_size == 33 && key[0] == kPsbtInTapBip32Derivation)
        {
          // BIP371: key = 0x16 || x-only internal key, value = leaf-hash count
          // (zero for BIP86) || fingerprint || path. Reusing the shared reader
          // keeps the fingerprint and path rules identical to the ECDSA paths.
          if (has_derivation)
            return TransactionError::DuplicateField;
          result = parse_derivation(key, key_size, value, value_size, master, input,
                                    nullptr, /*taproot=*/true);
          if (result != TransactionError::Ok)
            return result;
          has_derivation = true;
        }
        else if (key_size == 1 && key[0] == kPsbtInTapInternalKey)
        {
          // Recorded now, compared against the derived key once the map ends so
          // field order cannot matter.
          if (has_tap_internal_key || value_size != 32)
          {
            return has_tap_internal_key ? TransactionError::DuplicateField
                                        : TransactionError::Unsupported;
          }
          memcpy(tap_internal_key, value, 32);
          has_tap_internal_key = true;
        }
        else if (key_size == 1 && key[0] == kPsbtInTapMerkleRoot)
        {
          // BIP86 spends a key with no script tree; a merkle root here means the
          // output key is a different tweak and this wallet cannot sign it.
          return TransactionError::Unsupported;
        }
        else if (key_size == 1 && key[0] == kPsbtInTapKeySig)
        {
          // A host-supplied signature is never accepted: the device signs what
          // it reviewed, not what the constructor already collected.
          return TransactionError::Unsupported;
        }
        else if (key_size == 1 && key[0] == 0x03)
        {
          if (has_sighash || value_size != 4)
          {
            return has_sighash ? TransactionError::DuplicateField : TransactionError::Unsupported;
          }
          const uint32_t requested = static_cast<uint32_t>(value[0]) |
                                     (static_cast<uint32_t>(value[1]) << 8) |
                                     (static_cast<uint32_t>(value[2]) << 16) |
                                     (static_cast<uint32_t>(value[3]) << 24);
          // 0 and 1 are only meaningful for a taproot input; which one applies is
          // decided after the UTXO script names the spend type.
          if (requested != expected_sighash && requested > 1)
            return TransactionError::Unsupported;
          declared_sighash = requested;
          has_sighash = true;
        }
        else if (key_size == 1 && key[0] == 0x04)
        {
          if (has_redeem_script || value_size != sizeof(redeem_script) || value[0] != 0 || value[1] != 20)
          {
            return has_redeem_script ? TransactionError::DuplicateField : TransactionError::Unsupported;
          }
          memcpy(redeem_script, value, sizeof(redeem_script));
          has_redeem_script = true;
        }
        else
        {
          return TransactionError::Unsupported;
        }
      }
    }

    TransactionError verify_input_script(BitcoinInput *input)
    {
      if (input->spend_type == BitcoinSpendType::TaprootBip86)
      {
        uint8_t output_key[32];
        return path_matches_spend_type(*input) && input->taproot_sighash <= 1 &&
                       taproot_bip86_output_key(input->public_key + 1, output_key) == WalletError::Ok &&
                       crypto_constant_time_equal(output_key, input->taproot_output_key, 32)
                   ? TransactionError::Ok
                   : TransactionError::WrongWallet;
      }
      uint8_t hash[kRipemd160Size] = {};
      const bool hashed = crypto_hash160(input->public_key, sizeof(input->public_key), hash);
      const bool matches = hashed &&
                           crypto_constant_time_equal(hash, input->witness_key_hash, sizeof(hash)) &&
                           path_matches_spend_type(*input);
      secure_zero(hash, sizeof(hash));
      return matches ? TransactionError::Ok : TransactionError::WrongWallet;
    }

    TransactionError check_output_internal_key(const BitcoinOutput &output, const uint8_t internal[32]) {
      uint8_t expected[32];
      return output.script_size==34 && output.script[0]==0x51 && output.script[1]==32 &&
          taproot_bip86_output_key(internal,expected)==WalletError::Ok &&
          crypto_constant_time_equal(expected,output.script+2,32) ? TransactionError::Ok : TransactionError::WrongWallet;
    }

    TransactionError parse_output_map(Cursor *cursor, const HdPrivateNode &master, BitcoinOutput *output)
    {
      bool has_derivation = false;
      bool has_internal = false;
      while (true)
      {
        const uint8_t *key;
        const uint8_t *value;
        size_t key_size;
        size_t value_size;
        bool end;
        TransactionError result = read_map_item(cursor, &key, &key_size, &value, &value_size, &end);
        if (result != TransactionError::Ok || end)
          return result;
        if ((key_size == 34 && key[0] == 0x02) || (key_size == 33 && key[0] == 0x07))
        {
          if (has_derivation)
            return TransactionError::DuplicateField;
          result = parse_derivation(key, key_size, value, value_size, master, nullptr, output,key[0]==0x07);
          if (result != TransactionError::Ok)
            return result;
          has_derivation = true;
        }
        else if(key_size==1 && key[0]==0x05) {
          if(has_internal) return TransactionError::DuplicateField;
          if(value_size!=32) return TransactionError::NonCanonical;
          result=check_output_internal_key(*output,value);
          if(result!=TransactionError::Ok) return result;
          has_internal=true;
        }
        else
        {
          return TransactionError::Unsupported;
        }
      }
    }

    // -------------------------------------------------------------------------
    // PSBT v2 (BIP370)
    // -------------------------------------------------------------------------
    //
    // The global map carries what the unsigned transaction used to: the
    // transaction version, a fallback lock time and the input/output counts.
    // Each input map then carries its own outpoint and sequence, each output map
    // its own amount and script. Everything the signer must not be able to
    // reinterpret stays where it was: the UTXO, the BIP32 derivation and the
    // redeem script are still cross-checked against the firmware's own keys.

    // Reads one unsigned 32-bit little-endian value that must occupy its value
    // field exactly.
    bool psbt_read_u32_value(const uint8_t *value, size_t value_size, uint32_t *out)
    {
      if (value == nullptr || out == nullptr || value_size != 4)
        return false;
      *out = static_cast<uint32_t>(value[0]) |
             (static_cast<uint32_t>(value[1]) << 8) |
             (static_cast<uint32_t>(value[2]) << 16) |
             (static_cast<uint32_t>(value[3]) << 24);
      return true;
    }

    TransactionError read_psbt_global(Cursor *cursor, PsbtGlobalFields *fields)
    {
      if (cursor == nullptr || fields == nullptr)
        return TransactionError::InvalidArgument;
      while (true)
      {
        const uint8_t *key;
        const uint8_t *value;
        size_t key_size;
        size_t value_size;
        bool end;
        const TransactionError result =
            read_map_item(cursor, &key, &key_size, &value, &value_size, &end);
        if (result != TransactionError::Ok || end)
          return result;
        switch (key[0])
        {
        case kPsbtGlobalUnsignedTx:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (fields->has_unsigned_tx)
            return TransactionError::DuplicateField;
          fields->has_unsigned_tx = true;
          fields->unsigned_tx = value;
          fields->unsigned_tx_size = value_size;
          break;
        case kPsbtGlobalXpub:
          // A host-supplied account xpub is never trusted: every key this
          // firmware signs with is derived from the device seed. Accepting the
          // field keeps ordinary PSBTv2 constructors usable without letting it
          // influence a signature.
          break;
        case kPsbtGlobalTxVersion:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (fields->has_tx_version)
            return TransactionError::DuplicateField;
          if (!psbt_read_u32_value(value, value_size, &fields->tx_version))
            return TransactionError::NonCanonical;
          fields->has_tx_version = true;
          break;
        case kPsbtGlobalFallbackLocktime:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (fields->has_fallback_locktime)
            return TransactionError::DuplicateField;
          if (!psbt_read_u32_value(value, value_size, &fields->fallback_locktime))
            return TransactionError::NonCanonical;
          fields->has_fallback_locktime = true;
          break;
        case kPsbtGlobalInputCount:
        case kPsbtGlobalOutputCount:
        {
          if (key_size != 1)
            return TransactionError::NonCanonical;
          bool &seen = key[0] == kPsbtGlobalInputCount ? fields->has_input_count
                                                       : fields->has_output_count;
          uint64_t &count = key[0] == kPsbtGlobalInputCount ? fields->input_count
                                                            : fields->output_count;
          if (seen)
            return TransactionError::DuplicateField;
          // Encoded as a compact size integer, so a non-minimal encoding is a
          // canonicality error rather than a different count.
          Cursor counter = {value, value_size, 0};
          uint64_t parsed = 0;
          const TransactionError count_result = read_compact_size(&counter, &parsed);
          if (count_result != TransactionError::Ok)
            return count_result;
          if (counter.position != counter.size)
            return TransactionError::NonCanonical;
          seen = true;
          count = parsed;
          break;
        }
        case kPsbtGlobalTxModifiable:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (fields->has_tx_modifiable)
            return TransactionError::DuplicateField;
          if (value_size != 1)
            return TransactionError::NonCanonical;
          fields->tx_modifiable = value[0];
          fields->has_tx_modifiable = true;
          break;
        case kPsbtGlobalVersion:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (fields->has_psbt_version)
            return TransactionError::DuplicateField;
          if (!psbt_read_u32_value(value, value_size, &fields->psbt_version))
            return TransactionError::NonCanonical;
          fields->has_psbt_version = true;
          break;
        default:
          // Proprietary and future global types are refused, not skipped: a
          // field this signer cannot interpret has no business in a spend it is
          // about to authorize.
          return TransactionError::Unsupported;
        }
      }
    }

    // v2 input map. The v0 map reader already holds the UTXO cross-checks; this
    // one adds the outpoint, sequence and required-locktime fields and applies
    // the same UTXO rules, so a v2 input cannot reach a signature through a
    // weaker path than a v0 one.
    TransactionError parse_input_map_v2(Cursor *cursor, const HdPrivateNode &master,
                                        const BitcoinChainParams &chain,
                                        BitcoinInput *input, PsbtInputLocktime *locktime)
    {
      bool has_previous_txid = false;
      bool has_previous_index = false;
      bool has_sequence = false;
      bool has_witness_utxo = false;
      bool has_non_witness_utxo = false;
      bool has_derivation = false;
      bool has_sighash = false;
      bool has_redeem_script = false;
      bool has_tap_internal_key = false;
      uint8_t tap_internal_key[kPrivateKeySize] = {};
      uint32_t declared_sighash = 0;
      uint8_t partial_sig_count = 0;
      uint8_t redeem_script[22] = {};
      uint64_t utxo_value = 0;
      uint8_t utxo_script[kBitcoinMaxScriptSize + 1] = {};
      uint8_t utxo_script_size = 0;
      const uint8_t *non_witness_utxo = nullptr;
      size_t non_witness_utxo_size = 0;
      const uint32_t expected_sighash = chain.sighash == SighashFamily::ForkId
                                            ? (chain.fork_id << 8) | kSighashForkIdAll
                                            : kSighashAll;
      while (true)
      {
        const uint8_t *key;
        const uint8_t *value;
        size_t key_size;
        size_t value_size;
        bool end;
        TransactionError result = read_map_item(cursor, &key, &key_size, &value, &value_size, &end);
        if (result != TransactionError::Ok)
          return result;
        if (end)
          break;
        switch (key[0])
        {
        case kPsbtInPreviousTxid:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (has_previous_txid)
            return TransactionError::DuplicateField;
          if (value_size != 32)
            return TransactionError::NonCanonical;
          // BIP370 states this is the txid in standard (internal) byte order,
          // the same order v0 reads out of the unsigned transaction.
          memcpy(input->previous_txid, value, 32);
          has_previous_txid = true;
          break;
        case kPsbtInOutputIndex:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (has_previous_index)
            return TransactionError::DuplicateField;
          if (!psbt_read_u32_value(value, value_size, &input->previous_index))
            return TransactionError::NonCanonical;
          has_previous_index = true;
          break;
        case kPsbtInSequence:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (has_sequence)
            return TransactionError::DuplicateField;
          if (!psbt_read_u32_value(value, value_size, &input->sequence))
            return TransactionError::NonCanonical;
          has_sequence = true;
          break;
        case kPsbtInRequiredTimeLocktime:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (locktime->has_time)
            return TransactionError::DuplicateField;
          if (!psbt_read_u32_value(value, value_size, &locktime->time))
            return TransactionError::NonCanonical;
          // A value below the threshold is a block height wearing a timestamp
          // label; taking it as one would silently change the transaction.
          if (locktime->time < kLocktimeThreshold)
            return TransactionError::NonCanonical;
          locktime->has_time = true;
          break;
        case kPsbtInRequiredHeightLocktime:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (locktime->has_height)
            return TransactionError::DuplicateField;
          if (!psbt_read_u32_value(value, value_size, &locktime->height))
            return TransactionError::NonCanonical;
          if (locktime->height == 0 || locktime->height >= kLocktimeThreshold)
            return TransactionError::NonCanonical;
          locktime->has_height = true;
          break;
        case kPsbtInNonWitnessUtxo:
        {
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (has_non_witness_utxo)
            return TransactionError::DuplicateField;
          // Cannot be cross-checked yet: BIP370 lets the outpoint appear after
          // this field, so the previous transaction is verified once the whole
          // map is known.
          non_witness_utxo = value;
          non_witness_utxo_size = value_size;
          has_non_witness_utxo = true;
          break;
        }
        case kPsbtInWitnessUtxo:
        {
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (has_witness_utxo)
            return TransactionError::DuplicateField;
          Cursor utxo = {value, value_size, 0};
          uint64_t script_size;
          if (!read_u64(&utxo, &utxo_value) || utxo_value > kMaximumBitcoinSupply)
            return TransactionError::InvalidAmount;
          result = read_compact_size(&utxo, &script_size);
          if (result != TransactionError::Ok)
            return result;
          const uint8_t *script;
          if (script_size > kBitcoinMaxScriptSize ||
              !read_bytes(&utxo, static_cast<size_t>(script_size), &script) ||
              utxo.position != utxo.size)
            return TransactionError::Unsupported;
          if (sighash_family_is_legacy(chain.sighash) && script_size == 25 &&
              script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
              script[23] == 0x88 && script[24] == 0xac)
            return TransactionError::MissingField;
          memcpy(utxo_script, script, static_cast<size_t>(script_size));
          utxo_script_size = static_cast<uint8_t>(script_size);
          has_witness_utxo = true;
          break;
        }
        case kPsbtInBip32Derivation:
          if (has_derivation)
            return TransactionError::DuplicateField;
          if (key_size != 34)
            return TransactionError::NonCanonical;
          result = parse_derivation(key, key_size, value, value_size, master, input, nullptr);
          if (result != TransactionError::Ok)
            return result;
          has_derivation = true;
          break;

        case kPsbtInPartialSig:
          // A PSBT that already carries signatures is the normal input here, not
          // an error: another party may have signed first. The key must be
          // 0x02 || 33-byte compressed pubkey, the value DER plus the sighash
          // byte. Whether that key is one of ours is decided later, by
          // bitcoin_sign_psbt(), which compares before it writes.
          if (key_size != 34 || (key[1] != 0x02 && key[1] != 0x03) ||
              value_size < 2 || value_size > kBitcoinMaxDerSignatureSize + 1)
            return TransactionError::NonCanonical;
          if (partial_sig_count >= kBitcoinMaxInputs)
            return TransactionError::TooLarge;
          ++partial_sig_count;
          break;
        case kPsbtInTapBip32Derivation:
          if (has_derivation)
            return TransactionError::DuplicateField;
          if (key_size != 33)
            return TransactionError::NonCanonical;
          result = parse_derivation(key, key_size, value, value_size, master, input,
                                    nullptr, /*taproot=*/true);
          if (result != TransactionError::Ok)
            return result;
          has_derivation = true;
          break;
        case kPsbtInTapInternalKey:
          if (key_size != 1 || value_size != 32)
            return TransactionError::Unsupported;
          if (has_tap_internal_key)
            return TransactionError::DuplicateField;
          memcpy(tap_internal_key, value, 32);
          has_tap_internal_key = true;
          break;
        case kPsbtInTapMerkleRoot:
        case kPsbtInTapKeySig:
          // BIP86 has no script tree, and a signature collected by the host is
          // not one this device produced from its own review.
          return TransactionError::Unsupported;
        case kPsbtInSighashType:
        {
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (has_sighash)
            return TransactionError::DuplicateField;
          uint32_t requested = 0;
          if (!psbt_read_u32_value(value, value_size, &requested))
            return TransactionError::NonCanonical;
          // 0 and 1 only make sense for a taproot input; the spend type is known
          // once the UTXO script is classified, so apply_taproot_fields decides.
          if (requested != expected_sighash && requested > 1)
            return TransactionError::Unsupported;
          declared_sighash = requested;
          has_sighash = true;
          break;
        }
        case kPsbtInRedeemScript:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (has_redeem_script)
            return TransactionError::DuplicateField;
          if (value_size != sizeof(redeem_script) || value[0] != 0 || value[1] != 20)
            return TransactionError::Unsupported;
          memcpy(redeem_script, value, sizeof(redeem_script));
          has_redeem_script = true;
          break;
        default:
          return TransactionError::Unsupported;
        }
      }
      if (!has_previous_txid || !has_previous_index)
        return TransactionError::MissingField;
      if (!has_derivation)
        return TransactionError::MissingField;
      if (has_witness_utxo == has_non_witness_utxo)
        return TransactionError::MissingField;
      if (has_non_witness_utxo)
      {
        // Now that the outpoint is known, the previous transaction must hash to
        // it and contain the claimed output; otherwise the review would show a
        // value the chain never had.
        const TransactionError previous =
            parse_previous_transaction(non_witness_utxo, non_witness_utxo_size,
                                       input->previous_txid, input->previous_index,
                                       &utxo_value, utxo_script, &utxo_script_size);
        if (previous != TransactionError::Ok)
          return previous;
      }
      // BIP370: an absent PSBT_IN_SEQUENCE means the final sequence number.
      if (!has_sequence)
        input->sequence = 0xffffffffU;
      input->value = utxo_value;
      TransactionError result = classify_utxo_script(input, utxo_script, utxo_script_size,
                                                     has_redeem_script, redeem_script);
      secure_zero(redeem_script, sizeof(redeem_script));
      if (result != TransactionError::Ok)
        return result;
      result = apply_taproot_fields(input, has_tap_internal_key, tap_internal_key,
                                    has_sighash, declared_sighash);
      if(input->spend_type!=BitcoinSpendType::TaprootBip86 && has_sighash && declared_sighash!=expected_sighash)
        return TransactionError::Unsupported;
      secure_zero(tap_internal_key, sizeof(tap_internal_key));
      if (result != TransactionError::Ok)
        return result;
      const bool family_ok =
          input->spend_type == BitcoinSpendType::TaprootBip86
              ? taproot_network(chain)
              : (sighash_family_is_legacy(chain.sighash) ||
                 (chain.sighash == SighashFamily::ForkId &&
                  input->spend_type == BitcoinSpendType::LegacyP2pkh));
      if (!family_ok)
        return TransactionError::Unsupported;
      return path_matches_spend_type(*input) ? TransactionError::Ok : TransactionError::WrongWallet;
    }

    TransactionError parse_output_map_v2(Cursor *cursor, const HdPrivateNode &master,
                                         const BitcoinChainParams &chain, BitcoinOutput *output)
    {
      bool has_amount = false;
      bool has_script = false;
      bool has_derivation = false;
      bool has_internal = false;
      uint8_t internal[32] = {};
      const uint8_t *derivation_key = nullptr;
      const uint8_t *derivation_value = nullptr;
      size_t derivation_key_size = 0;
      size_t derivation_value_size = 0;
      while (true)
      {
        const uint8_t *key;
        const uint8_t *value;
        size_t key_size;
        size_t value_size;
        bool end;
        const TransactionError result = read_map_item(cursor, &key, &key_size, &value, &value_size, &end);
        if (result != TransactionError::Ok)
          return result;
        if (end)
          break;
        switch (key[0])
        {
        case kPsbtOutAmount:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (has_amount)
            return TransactionError::DuplicateField;
          if (value_size != 8)
            return TransactionError::NonCanonical;
          {
            uint64_t amount = 0;
            for (size_t index = 0; index < 8; ++index)
              amount |= static_cast<uint64_t>(value[index]) << (index * 8);
            if (amount > kMaximumBitcoinSupply)
              return TransactionError::InvalidAmount;
            output->value = amount;
          }
          has_amount = true;
          break;
        case kPsbtOutScript:
          if (key_size != 1)
            return TransactionError::NonCanonical;
          if (has_script)
            return TransactionError::DuplicateField;
          if (value_size > kBitcoinMaxScriptSize)
            return TransactionError::Unsupported;
          output->script_size = static_cast<uint8_t>(value_size);
          memcpy(output->script, value, value_size);
          if (chain_address_from_script(chain, output->script, output->script_size,
                                        output->address, sizeof(output->address)) != WalletError::Ok)
            return TransactionError::Unsupported;
          has_script = true;
          break;
        case 0x05:
          if(has_internal) return TransactionError::DuplicateField;
          if(key_size!=1 || value_size!=32) return TransactionError::NonCanonical;
          memcpy(internal,value,32); has_internal=true;
          break;
        case 0x07:
        case kPsbtOutBip32Derivation:
          // The derivation can arrive before the script it describes, so it is
          // applied once the whole map is known.
          if (has_derivation || key_size != (key[0]==0x07 ? 33U : 34U))
            return has_derivation ? TransactionError::DuplicateField
                                  : TransactionError::NonCanonical;
          derivation_key = key;
          derivation_key_size = key_size;
          derivation_value = value;
          derivation_value_size = value_size;
          has_derivation = true;
          break;
        default:
          return TransactionError::Unsupported;
        }
      }
      if (!has_amount || !has_script)
        return TransactionError::MissingField;
      if(has_internal) {
        const TransactionError result=check_output_internal_key(*output,internal);
        if(result!=TransactionError::Ok) return result;
      }
      if (has_derivation)
      {
        const TransactionError result =
            parse_derivation(derivation_key, derivation_key_size, derivation_value,
                             derivation_value_size, master, nullptr, output,derivation_key[0]==0x07);
        if (result != TransactionError::Ok)
          return result;
      }
      return TransactionError::Ok;
    }

    // BIP370 lock time selection: the fallback when no input asks for one,
    // otherwise the type every constrained input supports, choosing height when
    // both types are possible, and the largest value of that type.
    TransactionError psbt_resolve_locktime(const PsbtInputLocktime *locks, size_t count,
                                           uint32_t fallback, uint32_t *out)
    {
      if (locks == nullptr || out == nullptr || count == 0)
        return TransactionError::InvalidArgument;
      bool any = false;
      bool time_possible = true;
      bool height_possible = true;
      for (size_t index = 0; index < count; ++index)
      {
        if (locks[index].has_time || locks[index].has_height)
          any = true;
        if (locks[index].has_height && !locks[index].has_time)
          time_possible = false;
        if (locks[index].has_time && !locks[index].has_height)
          height_possible = false;
      }
      if (!any)
      {
        *out = fallback;
        return TransactionError::Ok;
      }
      bool use_height;
      if (height_possible)
        use_height = true;
      else if (time_possible)
        use_height = false;
      else
        return TransactionError::Unsupported;
      uint32_t chosen = 0;
      for (size_t index = 0; index < count; ++index)
      {
        const uint32_t value = use_height ? locks[index].height : locks[index].time;
        if (use_height ? locks[index].has_height : locks[index].has_time)
          chosen = value > chosen ? value : chosen;
      }
      *out = chosen != 0 ? chosen : fallback;
      return TransactionError::Ok;
    }

    bool serialize_outputs(const BitcoinSigningRequest &request, uint8_t *out, size_t out_size, size_t *written)
    {
      Writer writer = {out, out_size, 0};
      for (size_t index = 0; index < request.output_count; ++index)
      {
        const BitcoinOutput &output = request.outputs[index];
        if (!write_u64(&writer, output.value) || !write_compact_size(&writer, output.script_size) || !write_bytes(&writer, output.script, output.script_size))
          return false;
      }
      *written = writer.position;
      return true;
    }

    bool valid_digest_request(const BitcoinSigningRequest &request, size_t input_index,
                              uint32_t sighash_type, const uint8_t *out)
    {
      if (out == nullptr || request.input_count == 0 ||
          request.input_count > kBitcoinMaxInputs || input_index >= request.input_count ||
          request.output_count == 0 || request.output_count > kBitcoinMaxOutputs ||
          (sighash_type != kSighashAll && (sighash_type & 0xffU) != kSighashForkIdAll))
      {
        return false;
      }
      for (size_t i = 0; i < request.output_count; ++i)
      {
        if (request.outputs[i].script_size > kBitcoinMaxScriptSize)
          return false;
      }
      return true;
    }

    // The digest function of the signature hash. Bitcoin hashes the preimage twice;
    // Groestlcoin's HashWriter::GetHash() finalises once (src/hash.h), which is also
    // why a GRS transaction id is SHA256(raw). The preimage itself - both the legacy
    // form and BIP143 - is byte-identical to Bitcoin's.
    inline bool sighash_hash(SighashFamily family, const uint8_t *data, size_t size,
                             uint8_t out[kSha256Size])
    {
      return family == SighashFamily::GroestlLegacy
                 ? crypto_sha256(data, size, out)
                 : crypto_double_sha256(data, size, out);
    }

    // The witness-v0 digest lives on its own so the scriptCode is a parameter
    // instead of a hardcoded P2PKH script: a P2WSH multisig commits to the whole
    // witnessScript, and BIP143's published 6-of-6 vector is the only way to
    // prove the layout is right.
    TransactionError witness_v0_digest(const BitcoinSigningRequest &request,
                                       size_t input_index, uint32_t sighash_type,
                                       const uint8_t *script_code,
                                       size_t script_code_size, uint8_t out[kSha256Size],
                                       const uint32_t *transaction_time)
    {
      if (out == nullptr || script_code == nullptr || script_code_size == 0 ||
          script_code_size > kBitcoinMaxWitnessScriptSize || request.input_count == 0 ||
          request.input_count > kBitcoinMaxInputs || input_index >= request.input_count ||
          request.output_count == 0 || request.output_count > kBitcoinMaxOutputs)
      {
        return TransactionError::InvalidArgument;
      }
      // SIGHASH_ALL/NONE/SINGLE are bits 0-4; FORKID (0x40) and ANYONECANPAY
      // (0x80) live above them and do not change which type this is.
      const uint32_t base_type = sighash_type & 0x1fU;
      if (base_type != 1 && base_type != 2 && base_type != 3)
        return TransactionError::InvalidArgument;
      const bool anyone_can_pay = (sighash_type & 0x80U) != 0;
      // SIGHASH_SINGLE pairs input i with output i; Bitcoin's legacy "hash of
      // one" special case has no equivalent here, so this is simply invalid.
      if (base_type == 3 && input_index >= request.output_count)
        return TransactionError::InvalidArgument;
      for (size_t index = 0; index < request.output_count; ++index)
      {
        if (request.outputs[index].script_size > kBitcoinMaxScriptSize)
          return TransactionError::InvalidArgument;
      }

      uint8_t prevouts[kBitcoinMaxInputs * 36];
      uint8_t sequences[kBitcoinMaxInputs * 4];
      uint8_t outputs[kBitcoinMaxOutputs * (8 + 1 + kBitcoinMaxScriptSize)];
      uint8_t hash_prevouts[kSha256Size] = {};
      uint8_t hash_sequences[kSha256Size] = {};
      uint8_t hash_outputs[kSha256Size] = {};
      const SighashFamily family = request.chain.sighash;
      bool ok = true;
      if (!anyone_can_pay)
      {
        Writer prevout_writer = {prevouts, sizeof(prevouts), 0};
        Writer sequence_writer = {sequences, sizeof(sequences), 0};
        for (size_t index = 0; ok && index < request.input_count; ++index)
        {
          ok = write_bytes(&prevout_writer, request.inputs[index].previous_txid, 32) &&
               write_u32(&prevout_writer, request.inputs[index].previous_index) &&
               write_u32(&sequence_writer, request.inputs[index].sequence);
        }
        // BIP143 zeroes hashSequence for SINGLE and NONE as well as for
        // ANYONECANPAY: those types do not commit to any other input's sequence.
        const bool commit_sequences = base_type == 1;
        ok = ok && sighash_hash(family, prevouts, prevout_writer.position, hash_prevouts) &&
             (commit_sequences
                  ? sighash_hash(family, sequences, sequence_writer.position, hash_sequences)
                  : true);
      }
      if (base_type == 1)
      {
        size_t outputs_size = 0;
        ok = ok && serialize_outputs(request, outputs, sizeof(outputs), &outputs_size) &&
             sighash_hash(family, outputs, outputs_size, hash_outputs);
      }
      else if (base_type == 3)
      {
        Writer single = {outputs, sizeof(outputs), 0};
        const BitcoinOutput &output = request.outputs[input_index];
        ok = ok && write_u64(&single, output.value) &&
             write_compact_size(&single, output.script_size) &&
             write_bytes(&single, output.script, output.script_size) &&
             sighash_hash(family, outputs, single.position, hash_outputs);
      }
      if (!ok)
      {
        secure_zero(prevouts, sizeof(prevouts));
        secure_zero(sequences, sizeof(sequences));
        secure_zero(outputs, sizeof(outputs));
        return TransactionError::CryptoFailure;
      }

      const BitcoinInput &input = request.inputs[input_index];
      // 4 version + 4 BIP68 time (fork-id chains only) + two 32-byte aggregate
      // hashes + 36-byte outpoint + 3-byte CompactSize + script + 8 value +
      // 4 sequence + 32 output hash + 4 lock time + 4 hash type.
      uint8_t preimage[8 + 2 * kSha256Size + 36 + 3 + kBitcoinMaxWitnessScriptSize + 8 +
                       4 + kSha256Size + 4 + 4];
      Writer writer = {preimage, sizeof(preimage), 0};
      const bool serialized =
          write_u32(&writer, request.version) &&
          (transaction_time == nullptr || write_u32(&writer, *transaction_time)) &&
          write_bytes(&writer, hash_prevouts, sizeof(hash_prevouts)) &&
          write_bytes(&writer, hash_sequences, sizeof(hash_sequences)) &&
          write_bytes(&writer, input.previous_txid, sizeof(input.previous_txid)) &&
          write_u32(&writer, input.previous_index) &&
          write_compact_size(&writer, script_code_size) &&
          write_bytes(&writer, script_code, script_code_size) &&
          write_u64(&writer, input.value) && write_u32(&writer, input.sequence) &&
          write_bytes(&writer, hash_outputs, sizeof(hash_outputs)) &&
          write_u32(&writer, request.lock_time) && write_u32(&writer, sighash_type);
      const bool hashed = serialized && sighash_hash(family, preimage, writer.position, out);
      secure_zero(prevouts, sizeof(prevouts));
      secure_zero(sequences, sizeof(sequences));
      secure_zero(outputs, sizeof(outputs));
      secure_zero(preimage, sizeof(preimage));
      return hashed ? TransactionError::Ok : TransactionError::CryptoFailure;
    }

    TransactionError bip143_digest(const BitcoinSigningRequest &request, size_t input_index,
                                   uint32_t sighash_type, uint8_t out[kSha256Size],
                                   const uint32_t *transaction_time = nullptr)
    {
      if (!valid_digest_request(request, input_index, sighash_type, out))
        return TransactionError::InvalidArgument;
      const BitcoinInput &input = request.inputs[input_index];
      uint8_t key_hash[kRipemd160Size];
      if (!crypto_hash160(input.public_key, sizeof(input.public_key), key_hash))
        return TransactionError::CryptoFailure;
      // P2WPKH commits to the P2PKH script of the key hash, 0x19 prefix included.
      uint8_t script_code[25] = {0x76, 0xa9, 0x14};
      memcpy(script_code + 3, key_hash, sizeof(key_hash));
      script_code[23] = 0x88;
      script_code[24] = 0xac;
      const TransactionError result =
          witness_v0_digest(request, input_index, sighash_type, script_code,
                            sizeof(script_code), out, transaction_time);
      secure_zero(key_hash, sizeof(key_hash));
      secure_zero(script_code, sizeof(script_code));
      return result;
    }

    // Original (pre-BIP143) sighash for P2PKH: every input script is empty except
    // the one being signed, which carries its scriptCode; SIGHASH_ALL appends the
    // 4-byte hash type. The preimage is byte-identical across the chains that use
    // it - only the final digest differs: Bitcoin hashes it twice, Groestlcoin
    // once (src/hash.h in Groestlcoin Core finalises a single SHA-256).
    TransactionError legacy_digest(const BitcoinSigningRequest &request, size_t input_index,
                                   uint32_t sighash_type, uint8_t out[kSha256Size],
                                   const uint32_t *transaction_time = nullptr)
    {
      if (!valid_digest_request(request, input_index, sighash_type, out))
        return TransactionError::InvalidArgument;
      // FORKID applies BIP143 serialization even to a non-witness P2PKH input.
      // Treating it as Bitcoin's legacy serialization produces invalid signatures.
      // Groestlcoin has no SIGHASH_FORKID at all, so a 0x40 bit there is a caller
      // error rather than a request for the other preimage.
      if ((sighash_type & 0x40U) != 0)
      {
        if (request.chain.sighash == SighashFamily::GroestlLegacy)
        {
          return TransactionError::InvalidArgument;
        }
        return bip143_digest(request, input_index, sighash_type, out, transaction_time);
      }
      constexpr size_t kPreimageMax =
          4 + 4 + 1 + kBitcoinMaxInputs * (32 + 4 + 1 + kLegacyP2pkhScriptSize + 4) + 1 +
          kBitcoinMaxOutputs * (8 + 1 + kBitcoinMaxScriptSize) + 4 + 4;
      uint8_t preimage[kPreimageMax];
      Writer writer = {preimage, sizeof(preimage), 0};
      const BitcoinInput &input = request.inputs[input_index];
      uint8_t key_hash[kRipemd160Size];
      if (!crypto_hash160(input.public_key, sizeof(input.public_key), key_hash))
      {
        return TransactionError::CryptoFailure;
      }
      bool ok = write_u32(&writer, request.version) &&
                (transaction_time == nullptr || write_u32(&writer, *transaction_time)) &&
                write_compact_size(&writer, request.input_count);
      for (size_t index = 0; ok && index < request.input_count; ++index)
      {
        ok = write_bytes(&writer, request.inputs[index].previous_txid, 32) &&
             write_u32(&writer, request.inputs[index].previous_index);
        if (!ok)
          break;
        if (index == input_index)
        {
          const uint8_t prefix[] = {0x76, 0xa9, 0x14};
          const uint8_t suffix[] = {0x88, 0xac};
          ok = write_compact_size(&writer, kLegacyP2pkhScriptSize) &&
               write_bytes(&writer, prefix, sizeof(prefix)) &&
               write_bytes(&writer, key_hash, sizeof(key_hash)) &&
               write_bytes(&writer, suffix, sizeof(suffix));
        }
        else
        {
          ok = write_compact_size(&writer, 0);
        }
        ok = ok && write_u32(&writer, request.inputs[index].sequence);
      }
      ok = ok && write_compact_size(&writer, request.output_count);
      for (size_t index = 0; ok && index < request.output_count; ++index)
      {
        const BitcoinOutput &output = request.outputs[index];
        ok = write_u64(&writer, output.value) && write_compact_size(&writer, output.script_size) &&
             write_bytes(&writer, output.script, output.script_size);
      }
      ok = ok && write_u32(&writer, request.lock_time) && write_u32(&writer, sighash_type);
      const bool hashed = ok && sighash_hash(request.chain.sighash, preimage, writer.position, out);
      secure_zero(key_hash, sizeof(key_hash));
      secure_zero(preimage, sizeof(preimage));
      return hashed ? TransactionError::Ok : TransactionError::CryptoFailure;
    }

    // Serializes the scriptPubKey a BitcoinInput spends. Every spend type this
    // wallet signs has a script that is fully determined by the fields already
    // verified against the wallet key, which is why the taproot sighash can
    // commit to it without trusting a host-supplied copy.
    bool input_script_pubkey(const BitcoinInput &input, uint8_t *out, size_t capacity,
                             size_t *out_size)
    {
      if (out == nullptr || out_size == nullptr)
        return false;
      switch (input.spend_type)
      {
      case BitcoinSpendType::LegacyP2pkh:
        if (capacity < kLegacyP2pkhScriptSize)
          return false;
        out[0] = 0x76;
        out[1] = 0xa9;
        out[2] = 0x14;
        memcpy(out + 3, input.witness_key_hash, kRipemd160Size);
        out[23] = 0x88;
        out[24] = 0xac;
        *out_size = kLegacyP2pkhScriptSize;
        return true;
      case BitcoinSpendType::NativeP2wpkh:
        if (capacity < 22)
          return false;
        out[0] = 0x00;
        out[1] = 0x14;
        memcpy(out + 2, input.witness_key_hash, kRipemd160Size);
        *out_size = 22;
        return true;
      case BitcoinSpendType::NestedP2shP2wpkh:
        if (capacity < 23)
          return false;
        out[0] = 0xa9;
        out[1] = 0x14;
        memcpy(out + 2, input.p2sh_hash, kRipemd160Size);
        out[22] = 0x87;
        *out_size = 23;
        return true;
      case BitcoinSpendType::TaprootBip86:
        if (capacity < 34)
          return false;
        out[0] = 0x51;
        out[1] = 0x20;
        memcpy(out + 2, input.taproot_output_key, 32);
        *out_size = 34;
        return true;
      }
      return false;
    }

    uint32_t stripped_size(const BitcoinSigningRequest &request)
    {
      uint32_t size = 4 + 1 + 1 + 4;
      for (size_t index = 0; index < request.input_count; ++index)
      {
        const BitcoinInput &input = request.inputs[index];
        size_t script_size = 0;
        if (input.spend_type == BitcoinSpendType::NestedP2shP2wpkh)
          script_size = 23;
        else if (input.spend_type == BitcoinSpendType::LegacyP2pkh)
          script_size = kMaxLegacyScriptSigSize;
        size += 32 + 4 + 1 + script_size + 4;
      }
      for (size_t index = 0; index < request.output_count; ++index)
      {
        size += 8 + 1 + request.outputs[index].script_size;
      }
      return size;
    }

    uint32_t witness_size(const BitcoinSigningRequest &request)
    {
      // A taproot key-path spend carries one item: the 64-byte Schnorr signature
      // (65 with an explicit sighash byte). Everything else that is not legacy
      // gets the P2WPKH worst case: signature with its sighash byte plus the
      // compressed key.
      constexpr uint32_t kP2wpkhWitness = 1 + 1 + 72 + 1 + 33;
      constexpr uint32_t kTaprootWitness = 1 + 1 + 65;
      uint32_t weight = 0;
      uint32_t segwit_inputs = 0;
      for (size_t index = 0; index < request.input_count; ++index)
      {
        const BitcoinSpendType type = request.inputs[index].spend_type;
        if (type == BitcoinSpendType::LegacyP2pkh)
          continue;
        ++segwit_inputs;
        weight += type == BitcoinSpendType::TaprootBip86 ? kTaprootWitness : kP2wpkhWitness;
      }
      return segwit_inputs == 0 ? 0 : 2 + weight;
    }

    uint32_t estimated_vbytes(const BitcoinSigningRequest &request)
    {
      return (stripped_size(request) * 4 + witness_size(request) + 3) / 4;
    }

    // Signs one input of an already validated request. Extracted so the complete
    // transaction path and the PSBT path cannot diverge: they must produce the
    // same bytes for the same input.
    TransactionError sign_one_input(const BitcoinSigningRequest &request, size_t index,
                                    const HdPrivateNode &master, uint32_t sighash_type,
                                    uint8_t *signature, size_t capacity,
                                    size_t *signature_size)
    {
      if (signature == nullptr || signature_size == nullptr || index >= request.input_count)
        return TransactionError::InvalidArgument;
      HdPrivateNode derived;
      if (derive_array_path(master, request.inputs[index].path,
                            request.inputs[index].path_depth, &derived) != WalletError::Ok)
      {
        return TransactionError::WrongWallet;
      }
      uint8_t public_key[kCompressedPublicKeySize];
      const bool key_matches =
          public_key_from_private(derived.private_key, public_key) == WalletError::Ok &&
          crypto_constant_time_equal(public_key, request.inputs[index].public_key,
                                     sizeof(public_key));
      secure_zero(public_key, sizeof(public_key));
      if (!key_matches)
      {
        secure_zero(&derived, sizeof(derived));
        return TransactionError::WrongWallet;
      }
      uint8_t digest[kSha256Size];
      if (request.inputs[index].spend_type == BitcoinSpendType::TaprootBip86)
      {
        const uint8_t tap_hash_type = request.inputs[index].taproot_sighash;
        if (tap_hash_type > 1)
        {
          secure_zero(&derived, sizeof(derived));
          return TransactionError::Unsupported;
        }
        uint8_t tweaked[kPrivateKeySize];
        TransactionError result =
            taproot_network(request.chain)
                ? bitcoin_sighash_taproot(request, index, tap_hash_type, nullptr, 0, digest)
                : TransactionError::Unsupported;
        if (result == TransactionError::Ok &&
            taproot_bip86_private_key(derived.private_key, tweaked) != WalletError::Ok)
          result = TransactionError::CryptoFailure;
        uint8_t aux[kPrivateKeySize] = {};
        if (result == TransactionError::Ok &&
            (!ecdsa_bip340_sign(EcdsaCurve::Secp256k1, tweaked, digest, aux, signature)))
          result = TransactionError::CryptoFailure;
        secure_zero(aux, sizeof(aux));
        secure_zero(tweaked, sizeof(tweaked));
        secure_zero(&derived, sizeof(derived));
        secure_zero(digest, sizeof(digest));
        if (result != TransactionError::Ok)
          return result;
        // SIGHASH_DEFAULT is exactly 64 bytes; an explicit ALL appends 0x01.
        size_t size = 64;
        if (tap_hash_type != 0)
          signature[size++] = tap_hash_type;
        *signature_size = size;
        return TransactionError::Ok;
      }
      TransactionError result =
          request.inputs[index].spend_type == BitcoinSpendType::LegacyP2pkh
              ? legacy_digest(request, index, sighash_type, digest)
              : bip143_digest(request, index, sighash_type, digest);
      size_t der_size = capacity;
      if (result == TransactionError::Ok &&
          !secp256k1_sign_der(derived.private_key, digest, signature, &der_size))
        result = TransactionError::CryptoFailure;
      secure_zero(&derived, sizeof(derived));
      secure_zero(digest, sizeof(digest));
      if (result != TransactionError::Ok)
        return result;
      if (der_size + 1 > capacity)
        return TransactionError::BufferTooSmall;
      signature[der_size] = static_cast<uint8_t>(sighash_type);
      *signature_size = der_size + 1;
      return TransactionError::Ok;
    }

    // Byte ranges of the three PSBT sections, used to rewrite a PSBT without
    // disturbing entries this firmware does not touch. Every map is recorded
    // including its 0x00 terminator.
    struct PsbtSpans
    {
      size_t global_start;
      size_t global_end;
      size_t input_start[kBitcoinMaxInputs];
      size_t input_end[kBitcoinMaxInputs];
      size_t output_start[kBitcoinMaxOutputs];
      size_t output_end[kBitcoinMaxOutputs];
    };

    TransactionError scan_psbt_maps(const uint8_t *psbt, size_t psbt_size,
                                    size_t input_count, size_t output_count,
                                    PsbtSpans *spans)
    {
      if (psbt == nullptr || spans == nullptr || input_count == 0 ||
          input_count > kBitcoinMaxInputs || output_count == 0 ||
          output_count > kBitcoinMaxOutputs || psbt_size < sizeof(kPsbtMagic))
      {
        return TransactionError::InvalidArgument;
      }
      memset(spans, 0, sizeof(*spans));
      Cursor cursor = {psbt, psbt_size, sizeof(kPsbtMagic)};
      const auto skip_map = [](Cursor *inner) -> TransactionError {
        while (true)
        {
          const uint8_t *key;
          const uint8_t *value;
          size_t key_size;
          size_t value_size;
          bool end;
          const TransactionError result =
              read_map_item(inner, &key, &key_size, &value, &value_size, &end);
          if (result != TransactionError::Ok)
            return result;
          if (end)
            return TransactionError::Ok;
        }
      };
      spans->global_start = cursor.position;
      TransactionError result = skip_map(&cursor);
      if (result != TransactionError::Ok)
        return result;
      spans->global_end = cursor.position;
      for (size_t index = 0; index < input_count; ++index)
      {
        spans->input_start[index] = cursor.position;
        result = skip_map(&cursor);
        if (result != TransactionError::Ok)
          return result;
        spans->input_end[index] = cursor.position;
        if (cursor.position <= spans->input_start[index] ||
            psbt[cursor.position - 1] != 0x00)
          return TransactionError::NonCanonical;
      }
      for (size_t index = 0; index < output_count; ++index)
      {
        spans->output_start[index] = cursor.position;
        result = skip_map(&cursor);
        if (result != TransactionError::Ok)
          return result;
        spans->output_end[index] = cursor.position;
        if (cursor.position <= spans->output_start[index] ||
            psbt[cursor.position - 1] != 0x00)
          return TransactionError::NonCanonical;
      }
      // bitcoin_parse_psbt already proved the blob ends here; re-checking keeps
      // this scanner honest on its own.
      return cursor.position == cursor.size ? TransactionError::Ok
                                            : TransactionError::NonCanonical;
    }

    // Looks for one key inside a recorded map. Only the presence and the value
    // matter: the map has already been validated by bitcoin_parse_psbt().
    TransactionError find_map_entry(const uint8_t *psbt, size_t start, size_t end,
                                    const uint8_t *key, size_t key_size, bool *found,
                                    const uint8_t **value, size_t *value_size)
    {
      if (psbt == nullptr || key == nullptr || found == nullptr || value == nullptr ||
          value_size == nullptr || end <= start)
      {
        return TransactionError::InvalidArgument;
      }
      *found = false;
      Cursor cursor = {psbt, end, start};
      while (true)
      {
        const uint8_t *entry_key;
        const uint8_t *entry_value;
        size_t entry_key_size;
        size_t entry_value_size;
        bool at_end;
        const TransactionError result = read_map_item(&cursor, &entry_key,
                                                     &entry_key_size, &entry_value,
                                                     &entry_value_size, &at_end);
        if (result != TransactionError::Ok)
          return result;
        if (at_end)
          return TransactionError::Ok;
        if (entry_key_size == key_size &&
            memcmp(entry_key, key, key_size) == 0)
        {
          *found = true;
          *value = entry_value;
          *value_size = entry_value_size;
          return TransactionError::Ok;
        }
      }
    }


  }

  TransactionError bitcoin_parse_psbt(
const uint8_t *psbt, size_t psbt_size,
                                      const HdPrivateNode &master,
                                      const BitcoinChainParams &chain,
                                      BitcoinSigningRequest *out)
  {
    if (psbt == nullptr || out == nullptr || psbt_size < sizeof(kPsbtMagic) || psbt_size > HEXWALLET_MAX_PSBT_BYTES)
      return TransactionError::InvalidArgument;
    if (chain.sighash != SighashFamily::Bitcoin && chain.sighash != SighashFamily::ForkId &&
        chain.sighash != SighashFamily::GroestlLegacy)
      return TransactionError::Unsupported;
    BitcoinSigningRequest parsed;
    clear_bitcoin_request(&parsed);
    parsed.chain = chain;
    Cursor cursor = {psbt, psbt_size, 0};
    const uint8_t *magic;
    if (!read_bytes(&cursor, sizeof(kPsbtMagic), &magic) || memcmp(magic, kPsbtMagic, sizeof(kPsbtMagic)) != 0)
    {
      return TransactionError::NonCanonical;
    }
    PsbtGlobalFields global = {};
    TransactionError global_result = read_psbt_global(&cursor, &global);
    if (global_result != TransactionError::Ok)
      return global_result;

    // BIP370: v2 is the form that carries PSBT_GLOBAL_VERSION = 2 and must not
    // carry the unsigned transaction. A PSBT that says version 0 (or omits the
    // field) is v0 and must carry it. Anything else - including a v0 blob that
    // mixes in v2-only globals - is refused instead of guessed at.
    bool version_2 = false;
    if (global.has_psbt_version)
    {
      if (global.psbt_version == 2)
      {
        version_2 = true;
      }
      else if (global.psbt_version != 0)
      {
        return TransactionError::Unsupported;
      }
    }
    else if (!global.has_unsigned_tx)
    {
      return TransactionError::MissingField;
    }
    if (version_2)
    {
      if (global.has_unsigned_tx)
        return TransactionError::NonCanonical;
    }
    else
    {
      if (!global.has_unsigned_tx)
        return TransactionError::MissingField;
      if (global.has_tx_version || global.has_fallback_locktime ||
          global.has_input_count || global.has_output_count ||
          global.has_tx_modifiable)
        return TransactionError::NonCanonical;
    }

    if (version_2)
    {
      if (!global.has_tx_version || !global.has_input_count || !global.has_output_count)
        return TransactionError::MissingField;
      if (global.tx_version != 1 && global.tx_version != 2)
        return TransactionError::Unsupported;
      // A constructor that keeps the inputs or outputs modifiable has not
      // finished deciding what the user is about to approve, and this wallet
      // signs the final transaction rather than a draft of one.
      if (global.has_tx_modifiable && global.tx_modifiable != 0)
        return TransactionError::Unsupported;
      if (global.input_count == 0 || global.input_count > kBitcoinMaxInputs ||
          global.output_count == 0 || global.output_count > kBitcoinMaxOutputs)
        return TransactionError::TooLarge;
      parsed.version = global.tx_version;
      parsed.input_count = static_cast<uint8_t>(global.input_count);
      parsed.output_count = static_cast<uint8_t>(global.output_count);
      PsbtInputLocktime locks[kBitcoinMaxInputs] = {};
      for (size_t index = 0; index < parsed.input_count; ++index)
      {
        TransactionError result =
            parse_input_map_v2(&cursor, master, chain, &parsed.inputs[index], &locks[index]);
        if (result != TransactionError::Ok)
          return result;
        result = verify_input_script(&parsed.inputs[index]);
        if (result != TransactionError::Ok)
          return result;
        if (!add_u64(parsed.input_total, parsed.inputs[index].value, &parsed.input_total))
          return TransactionError::InvalidAmount;
      }
      if (!distinct_outpoints(parsed))
        return TransactionError::DuplicateField;
      const TransactionError locktime_result =
          psbt_resolve_locktime(locks, parsed.input_count,
                                global.has_fallback_locktime ? global.fallback_locktime : 0,
                                &parsed.lock_time);
      if (locktime_result != TransactionError::Ok)
        return locktime_result;
      bool required_locktime = false;
      bool locktime_enabled = false;
      for (size_t index = 0; index < parsed.input_count; ++index)
      {
        required_locktime |= locks[index].has_height || locks[index].has_time;
        locktime_enabled |= parsed.inputs[index].sequence != 0xffffffffU;
      }
      // Final sequences disable nLockTime in consensus. Never silently change
      // a supplied sequence to make the requested constraint effective.
      if (required_locktime && !locktime_enabled)
        return TransactionError::Unsupported;
      for (size_t index = 0; index < parsed.output_count; ++index)
      {
        BitcoinOutput &output = parsed.outputs[index];
        const TransactionError result = parse_output_map_v2(&cursor, master, chain, &output);
        if (result != TransactionError::Ok)
          return result;
        if (!add_u64(parsed.output_total, output.value, &parsed.output_total))
          return TransactionError::InvalidAmount;
      }
    }
    else
    {
      global_result = parse_unsigned_transaction(global.unsigned_tx, global.unsigned_tx_size,
                                                 chain, &parsed);
      if (global_result != TransactionError::Ok)
        return global_result;
      for (size_t index = 0; index < parsed.input_count; ++index)
      {
        TransactionError result = parse_input_map(&cursor, master, chain, &parsed.inputs[index]);
        if (result != TransactionError::Ok)
          return result;
        result = verify_input_script(&parsed.inputs[index]);
        if (result != TransactionError::Ok)
          return result;
        if (!add_u64(parsed.input_total, parsed.inputs[index].value, &parsed.input_total))
          return TransactionError::InvalidAmount;
      }
      for (size_t index = 0; index < parsed.output_count; ++index)
      {
        const TransactionError result = parse_output_map(&cursor, master, &parsed.outputs[index]);
        if (result != TransactionError::Ok)
          return result;
      }
    }
    if (cursor.position != cursor.size)
      return TransactionError::NonCanonical;
    if (parsed.input_total < parsed.output_total)
      return TransactionError::InvalidAmount;
    parsed.fee = parsed.input_total - parsed.output_total;
    parsed.estimated_vbytes = estimated_vbytes(parsed);
    if (parsed.fee > HEXWALLET_MAX_BITCOIN_FEE_SATS || parsed.estimated_vbytes == 0 || parsed.fee > HEXWALLET_MAX_BITCOIN_FEE_RATE * static_cast<uint64_t>(parsed.estimated_vbytes))
    {
      return TransactionError::FeePolicy;
    }
    if (!crypto_sha256(psbt, psbt_size, parsed.psbt_hash))
      return TransactionError::CryptoFailure;
    *out = parsed;
    return TransactionError::Ok;
  }

  // BIP341 taproot signature hash. The primitive is complete (all six hash
  // types plus an optional annex) because that is the only way to check it
  // against BIP341's own wallet vectors; the wallet's BIP86 policy then signs
  // only SIGHASH_DEFAULT and SIGHASH_ALL from bitcoin_sign_request().
  //
  // sha_* aggregates are built into bounded stack buffers rather than a
  // streaming hash object: the request is capped at 8 inputs and 16 outputs, so
  // the largest concatenation is 16 * (8 + 1 + 34) bytes.
  TransactionError bitcoin_sighash_taproot(const BitcoinSigningRequest &request,
                                           size_t input_index, uint8_t hash_type,
                                           const uint8_t *annex, size_t annex_size,
                                           uint8_t out[kSha256Size])
  {
    constexpr size_t kScratchMax = 16 * (8 + 1 + kBitcoinMaxScriptSize);
    if (out == nullptr || request.input_count == 0 ||
        request.input_count > kBitcoinMaxInputs || input_index >= request.input_count ||
        request.output_count == 0 || request.output_count > kBitcoinMaxOutputs ||
        !((hash_type <= 3) || (hash_type >= 0x81 && hash_type <= 0x83)) ||
        (annex_size != 0 && annex == nullptr) ||
        (annex_size != 0 && annex[0] != 0x50) || annex_size > HEXWALLET_MAX_PSBT_BYTES)
    {
      return TransactionError::InvalidArgument;
    }
    for (size_t index = 0; index < request.output_count; ++index)
    {
      if (request.outputs[index].script_size > kBitcoinMaxScriptSize)
        return TransactionError::InvalidArgument;
    }
    const bool anyone_can_pay = (hash_type & 0x80U) != 0;
    const uint8_t output_type = hash_type & 0x03U;
    if (output_type == 3 && input_index >= request.output_count)
      return TransactionError::InvalidArgument;
    uint8_t script[kBitcoinMaxScriptSize];
    size_t script_size = 0;

    uint8_t sha_prevouts[kSha256Size] = {};
    uint8_t sha_amounts[kSha256Size] = {};
    uint8_t sha_script_pubkeys[kSha256Size] = {};
    uint8_t sha_sequences[kSha256Size] = {};
    uint8_t sha_outputs[kSha256Size] = {};
    uint8_t sha_annex[kSha256Size] = {};
    uint8_t sha_single_output[kSha256Size] = {};
    uint8_t scratch[kScratchMax];

    if (!anyone_can_pay)
    {
      Writer writer = {scratch, sizeof(scratch), 0};
      bool ok = true;
      for (size_t index = 0; ok && index < request.input_count; ++index)
      {
        ok = write_bytes(&writer, request.inputs[index].previous_txid, 32) &&
             write_u32(&writer, request.inputs[index].previous_index);
      }
      if (!ok || !crypto_sha256(scratch, writer.position, sha_prevouts))
        return TransactionError::CryptoFailure;
      writer.position = 0;
      for (size_t index = 0; ok && index < request.input_count; ++index)
        ok = write_u64(&writer, request.inputs[index].value);
      if (!ok || !crypto_sha256(scratch, writer.position, sha_amounts))
        return TransactionError::CryptoFailure;
      writer.position = 0;
      for (size_t index = 0; ok && index < request.input_count; ++index)
      {
        if (!input_script_pubkey(request.inputs[index], script, sizeof(script), &script_size))
          return TransactionError::Unsupported;
        ok = write_compact_size(&writer, script_size) &&
             write_bytes(&writer, script, script_size);
      }
      if (!ok || !crypto_sha256(scratch, writer.position, sha_script_pubkeys))
        return TransactionError::CryptoFailure;
      writer.position = 0;
      for (size_t index = 0; ok && index < request.input_count; ++index)
        ok = write_u32(&writer, request.inputs[index].sequence);
      if (!ok || !crypto_sha256(scratch, writer.position, sha_sequences))
        return TransactionError::CryptoFailure;
    }
    if (output_type != 2 && output_type != 3)
    {
      Writer writer = {scratch, sizeof(scratch), 0};
      bool ok = true;
      for (size_t index = 0; ok && index < request.output_count; ++index)
      {
        const BitcoinOutput &output = request.outputs[index];
        ok = write_u64(&writer, output.value) &&
             write_compact_size(&writer, output.script_size) &&
             write_bytes(&writer, output.script, output.script_size);
      }
      if (!ok || !crypto_sha256(scratch, writer.position, sha_outputs))
        return TransactionError::CryptoFailure;
    }
    if (output_type == 3)
    {
      const BitcoinOutput &output = request.outputs[input_index];
      Writer writer = {scratch, sizeof(scratch), 0};
      const bool ok = write_u64(&writer, output.value) &&
                      write_compact_size(&writer, output.script_size) &&
                      write_bytes(&writer, output.script, output.script_size);
      if (!ok || !crypto_sha256(scratch, writer.position, sha_single_output))
        return TransactionError::CryptoFailure;
    }
    if (annex_size != 0) {
      // BIP341 commits to CompactSize(length) followed by the annex itself.
      uint8_t prefix[9]; Writer length_writer={prefix,sizeof(prefix),0};
      if (!write_compact_size(&length_writer,annex_size)) return TransactionError::InvalidArgument;
      mbedtls_md_context_t ctx; mbedtls_md_init(&ctx);
      const bool hashed=mbedtls_md_setup(&ctx,mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),0)==0 &&
          mbedtls_md_starts(&ctx)==0 && mbedtls_md_update(&ctx,prefix,length_writer.position)==0 &&
          mbedtls_md_update(&ctx,annex,annex_size)==0 && mbedtls_md_finish(&ctx,sha_annex)==0;
      mbedtls_md_free(&ctx);
      if(!hashed) return TransactionError::CryptoFailure;
    }

    // SigMsg: epoch byte, hash type, version, lock time, the four aggregates,
    // the output aggregate or the single output, spend type, input index.
    constexpr size_t kSigMsgMax = 1 + 1 + 4 + 4 + 4 * kSha256Size + kSha256Size +
                                  1 + 4 + kSha256Size;
    uint8_t sig_msg[kSigMsgMax];
    Writer writer = {sig_msg, sizeof(sig_msg), 0};
    const uint8_t epoch = 0x00;
    const uint8_t spend_type =
        static_cast<uint8_t>(annex_size != 0 ? 1 : 0); // ext_flag 0, no script path
    bool ok = write_bytes(&writer, &epoch, 1) && write_bytes(&writer, &hash_type, 1) &&
              write_u32(&writer, request.version) && write_u32(&writer, request.lock_time);
    if (ok && !anyone_can_pay)
    {
      ok = write_bytes(&writer, sha_prevouts, kSha256Size) &&
           write_bytes(&writer, sha_amounts, kSha256Size) &&
           write_bytes(&writer, sha_script_pubkeys, kSha256Size) &&
           write_bytes(&writer, sha_sequences, kSha256Size);
    }
    if (ok && output_type != 2 && output_type != 3)
      ok = write_bytes(&writer, sha_outputs, kSha256Size);
    ok = ok && write_bytes(&writer, &spend_type, 1);
    if (ok && !anyone_can_pay)
      ok = write_u32(&writer, static_cast<uint32_t>(input_index));
    if (ok && anyone_can_pay) {
      const BitcoinInput &input=request.inputs[input_index];
      if(!input_script_pubkey(input,script,sizeof(script),&script_size)) return TransactionError::Unsupported;
      ok=write_bytes(&writer,input.previous_txid,32) && write_u32(&writer,input.previous_index) &&
         write_u64(&writer,input.value) && write_compact_size(&writer,script_size) &&
         write_bytes(&writer,script,script_size) && write_u32(&writer,input.sequence);
    }
    if (ok && annex_size != 0)
      ok = write_bytes(&writer, sha_annex, kSha256Size);
    if (ok && output_type == 3)
      ok = write_bytes(&writer, sha_single_output, kSha256Size);
    if (!ok)
      return TransactionError::BufferTooSmall;
    // Same construction as the BIP340 helper, but the message here is a full
    // SigMsg (up to 175 bytes), which that helper deliberately caps at 96.
    uint8_t tag_hash[kSha256Size];
    uint8_t tagged[64 + kSigMsgMax];
    bool hashed = writer.position <= kSigMsgMax &&
                  crypto_sha256(reinterpret_cast<const uint8_t *>("TapSighash"), 10,
                                tag_hash);
    if (hashed)
    {
      memcpy(tagged, tag_hash, kSha256Size);
      memcpy(tagged + kSha256Size, tag_hash, kSha256Size);
      memcpy(tagged + 2 * kSha256Size, sig_msg, writer.position);
      hashed = crypto_sha256(tagged, 2 * kSha256Size + writer.position, out);
    }
    secure_zero(tag_hash, sizeof(tag_hash));
    secure_zero(tagged, sizeof(tagged));
    secure_zero(sig_msg, sizeof(sig_msg));
    secure_zero(scratch, sizeof(scratch));
    secure_zero(script, sizeof(script));
    secure_zero(sha_prevouts, sizeof(sha_prevouts));
    secure_zero(sha_amounts, sizeof(sha_amounts));
    secure_zero(sha_script_pubkeys, sizeof(sha_script_pubkeys));
    secure_zero(sha_sequences, sizeof(sha_sequences));
    secure_zero(sha_outputs, sizeof(sha_outputs));
    secure_zero(sha_annex, sizeof(sha_annex));
    secure_zero(sha_single_output, sizeof(sha_single_output));
    return hashed ? TransactionError::Ok : TransactionError::CryptoFailure;
  }

  TransactionError bitcoin_sign_request(const BitcoinSigningRequest &request,
                                        const HdPrivateNode &master,
                                        uint8_t *out_transaction, size_t *in_out_size)
  {
    if (out_transaction == nullptr || in_out_size == nullptr || request.input_count == 0 || request.input_count > kBitcoinMaxInputs || request.output_count == 0 || request.output_count > kBitcoinMaxOutputs || (request.version != 1 && request.version != 2))
    {
      return TransactionError::InvalidArgument;
    }
    if (request.chain.sighash != SighashFamily::Bitcoin && request.chain.sighash != SighashFamily::ForkId &&
        request.chain.sighash != SighashFamily::GroestlLegacy)
      return TransactionError::Unsupported;
    if (!distinct_outpoints(request))
      return TransactionError::DuplicateField;
    uint64_t input_total = 0;
    uint64_t output_total = 0;
    const bool fork_id_family = request.chain.sighash == SighashFamily::ForkId;
    const uint32_t sighash_type = fork_id_family
                                      ? (request.chain.fork_id << 8) | kSighashForkIdAll
                                      : kSighashAll;
    for (size_t index = 0; index < request.input_count; ++index)
    {
      const BitcoinInput &input = request.inputs[index];
      uint8_t key_hash[kRipemd160Size] = {};
      uint8_t redeem_script[22] = {0, 20};
      uint8_t redeem_hash[kRipemd160Size] = {};
      memcpy(redeem_script + 2, input.witness_key_hash, sizeof(input.witness_key_hash));
      const bool native = input.spend_type == BitcoinSpendType::NativeP2wpkh;
      const bool legacy = input.spend_type == BitcoinSpendType::LegacyP2pkh;
      const bool nested = input.spend_type == BitcoinSpendType::NestedP2shP2wpkh && crypto_hash160(redeem_script, sizeof(redeem_script), redeem_hash) && crypto_constant_time_equal(redeem_hash, input.p2sh_hash, sizeof(redeem_hash));
      // BIP86 commits the BIP340 x-only key, so the hashed-public-key check that
      // the ECDSA paths use does not apply; the tweak check below replaces it.
      uint8_t output_key[kPrivateKeySize] = {};
      const bool taproot_key =
          input.spend_type == BitcoinSpendType::TaprootBip86 &&
          request.chain.sighash == SighashFamily::Bitcoin &&
          taproot_bip86_output_key(input.public_key + 1, output_key) == WalletError::Ok &&
          crypto_constant_time_equal(output_key, input.taproot_output_key, sizeof(output_key));
      secure_zero(output_key, sizeof(output_key));
      const bool family_ok =
          input.spend_type == BitcoinSpendType::TaprootBip86
              ? request.chain.sighash == SighashFamily::Bitcoin
              : (sighash_family_is_legacy(request.chain.sighash) || legacy);
      const bool hash_ok =
          input.spend_type == BitcoinSpendType::TaprootBip86
              ? true
              : (crypto_hash160(input.public_key, sizeof(input.public_key), key_hash) &&
                 crypto_constant_time_equal(key_hash, input.witness_key_hash, sizeof(key_hash)));
      const bool valid = input.value <= kMaximumBitcoinSupply && path_matches_spend_type(input) &&
                         hash_ok && (native || nested || legacy || taproot_key) && family_ok &&
                         add_u64(input_total, input.value, &input_total);
      secure_zero(key_hash, sizeof(key_hash));
      secure_zero(redeem_script, sizeof(redeem_script));
      secure_zero(redeem_hash, sizeof(redeem_hash));
      if (!valid)
        return TransactionError::WrongWallet;
    }
    for (size_t index = 0; index < request.output_count; ++index)
    {
      const BitcoinOutput &output = request.outputs[index];
      char address[kAddressTextSize];
      const bool valid = output.value <= kMaximumBitcoinSupply && output.script_size <= kBitcoinMaxScriptSize && chain_address_from_script(request.chain, output.script, output.script_size, address, sizeof(address)) == WalletError::Ok && add_u64(output_total, output.value, &output_total);
      secure_zero(address, sizeof(address));
      if (!valid)
        return TransactionError::Unsupported;
    }
    const uint32_t expected_vbytes = estimated_vbytes(request);
    if (input_total < output_total || input_total != request.input_total || output_total != request.output_total || input_total - output_total != request.fee || request.fee > HEXWALLET_MAX_BITCOIN_FEE_SATS || request.estimated_vbytes == 0 || request.estimated_vbytes != expected_vbytes || request.fee > HEXWALLET_MAX_BITCOIN_FEE_RATE * static_cast<uint64_t>(request.estimated_vbytes))
    {
      return TransactionError::FeePolicy;
    }
    uint8_t signatures[kBitcoinMaxInputs][kBitcoinMaxDerSignatureSize + 1];
    uint8_t signature_sizes[kBitcoinMaxInputs] = {};
    for (size_t index = 0; index < request.input_count; ++index)
    {
      size_t produced = 0;
      const TransactionError result =
          sign_one_input(request, index, master, sighash_type, signatures[index],
                         sizeof(signatures[index]), &produced);
      if (result == TransactionError::Ok)
        signature_sizes[index] = static_cast<uint8_t>(produced);
      if (result != TransactionError::Ok)
      {
        secure_zero(signatures, sizeof(signatures));
        return result;
      }
    }
    Writer writer = {out_transaction, *in_out_size, 0};
    const uint8_t marker_flag[] = {0, 1};
    const bool any_segwit = witness_size(request) != 0;
    bool ok = write_u32(&writer, request.version);
    if (ok && any_segwit)
      ok = write_bytes(&writer, marker_flag, sizeof(marker_flag));
    ok = ok && write_compact_size(&writer, request.input_count);
    for (size_t index = 0; ok && index < request.input_count; ++index)
    {
      const BitcoinInput &input = request.inputs[index];
      uint8_t redeem_script[22] = {0, 20};
      uint8_t script_sig[kMaxLegacyScriptSigSize] = {};
      memcpy(redeem_script + 2, input.witness_key_hash, sizeof(input.witness_key_hash));
      size_t script_sig_size = 0;
      if (input.spend_type == BitcoinSpendType::LegacyP2pkh)
      {
        script_sig[script_sig_size++] = static_cast<uint8_t>(signature_sizes[index]);
        memcpy(script_sig + script_sig_size, signatures[index], signature_sizes[index]);
        script_sig_size += signature_sizes[index];
        script_sig[script_sig_size++] = static_cast<uint8_t>(sizeof(input.public_key));
        memcpy(script_sig + script_sig_size, input.public_key, sizeof(input.public_key));
        script_sig_size += sizeof(input.public_key);
      }
      else if (input.spend_type == BitcoinSpendType::NestedP2shP2wpkh)
      {
        script_sig[script_sig_size++] = static_cast<uint8_t>(sizeof(redeem_script));
        memcpy(script_sig + script_sig_size, redeem_script, sizeof(redeem_script));
        script_sig_size += sizeof(redeem_script);
      }
      ok = write_bytes(&writer, input.previous_txid, sizeof(input.previous_txid)) && write_u32(&writer, input.previous_index) && write_compact_size(&writer, script_sig_size) && (script_sig_size == 0 || write_bytes(&writer, script_sig, script_sig_size)) && write_u32(&writer, input.sequence);
      secure_zero(redeem_script, sizeof(redeem_script));
      secure_zero(script_sig, sizeof(script_sig));
    }
    ok = ok && write_compact_size(&writer, request.output_count);
    for (size_t index = 0; ok && index < request.output_count; ++index)
    {
      const BitcoinOutput &output = request.outputs[index];
      ok = write_u64(&writer, output.value) && write_compact_size(&writer, output.script_size) && write_bytes(&writer, output.script, output.script_size);
    }
    if (any_segwit)
    {
      for (size_t index = 0; ok && index < request.input_count; ++index)
      {
        if (request.inputs[index].spend_type == BitcoinSpendType::LegacyP2pkh)
        {
          ok = write_compact_size(&writer, 0);
          continue;
        }
        if (request.inputs[index].spend_type == BitcoinSpendType::TaprootBip86)
        {
          ok = write_compact_size(&writer, 1) &&
               write_compact_size(&writer, signature_sizes[index]) &&
               write_bytes(&writer, signatures[index], signature_sizes[index]);
          continue;
        }
        ok = write_compact_size(&writer, 2) && write_compact_size(&writer, signature_sizes[index]) && write_bytes(&writer, signatures[index], signature_sizes[index]) && write_compact_size(&writer, sizeof(request.inputs[index].public_key)) && write_bytes(&writer, request.inputs[index].public_key, sizeof(request.inputs[index].public_key));
      }
    }
    ok = ok && write_u32(&writer, request.lock_time);
    secure_zero(signatures, sizeof(signatures));
    if (!ok)
      return TransactionError::BufferTooSmall;
    *in_out_size = writer.position;
    return TransactionError::Ok;
  }

  TransactionError bitcoin_sign_psbt(const uint8_t *psbt, size_t psbt_size,
                                     const HdPrivateNode &master,
                                     const BitcoinChainParams &chain,
                                     uint8_t *out_psbt, size_t out_capacity,
                                     size_t *out_size,
                                     BitcoinPsbtSignSummary *summary)
  {
    if (summary != nullptr)
      *summary = BitcoinPsbtSignSummary{};
    if (psbt == nullptr || out_psbt == nullptr || out_size == nullptr)
      return TransactionError::InvalidArgument;
    BitcoinSigningRequest request;
    clear_bitcoin_request(&request);
    TransactionError result = bitcoin_parse_psbt(psbt, psbt_size, master, chain, &request);
    if (result != TransactionError::Ok)
      return result;
    PsbtSpans spans;
    result = scan_psbt_maps(psbt, psbt_size, request.input_count, request.output_count,
                            &spans);
    if (result != TransactionError::Ok)
      return result;

    // Same policy the complete-transaction path uses, so a PSBT signed here and
    // a PSBT assembled there can never commit to different hash types.
    const bool fork_id_family = chain.sighash == SighashFamily::ForkId;
    const uint32_t sighash_type = fork_id_family
                                      ? (chain.fork_id << 8) | kSighashForkIdAll
                                      : kSighashAll;

    struct PendingEntry
    {
      uint8_t key[34];
      size_t key_size;
      uint8_t value[kBitcoinMaxDerSignatureSize + 1];
      size_t value_size;
      bool add;
      bool unchanged;
    };
    PendingEntry pending[kBitcoinMaxInputs];
    memset(pending, 0, sizeof(pending));
    size_t needed = sizeof(kPsbtMagic) + (spans.global_end - spans.global_start);
    for (size_t index = 0; index < request.input_count; ++index)
    {
      PendingEntry &entry = pending[index];
      const BitcoinInput &input = request.inputs[index];
      if (input.spend_type == BitcoinSpendType::TaprootBip86)
      {
        entry.key[0] = kPsbtInTapKeySig;
        entry.key_size = 1;
      }
      else
      {
        // BIP174: the partial signature of a public key lives under
        // 0x02 || <compressed pubkey>, which is exactly what a verifier looks up.
        entry.key[0] = kPsbtInPartialSig;
        memcpy(entry.key + 1, input.public_key, sizeof(input.public_key));
        entry.key_size = 1 + sizeof(input.public_key);
      }
      result = sign_one_input(request, index, master, sighash_type, entry.value,
                              sizeof(entry.value), &entry.value_size);
      if (result != TransactionError::Ok)
        return result;
      bool found = false;
      const uint8_t *existing = nullptr;
      size_t existing_size = 0;
      result = find_map_entry(psbt, spans.input_start[index], spans.input_end[index],
                              entry.key, entry.key_size, &found, &existing,
                              &existing_size);
      if (result != TransactionError::Ok)
        return result;
      if (found)
      {
        // ECDSA here is deterministic (RFC 6979) and BIP340 signing is too, so an
        // existing entry for the same key and input is either identical or a
        // signature this device did not produce. Only the first is acceptable:
        // overwriting would silently discard another signer's work.
        if (existing_size != entry.value_size ||
            !crypto_constant_time_equal(existing, entry.value, entry.value_size))
        {
          secure_zero(pending, sizeof(pending));
          return TransactionError::DuplicateField;
        }
        entry.unchanged = true;
      }
      else
      {
        entry.add = true;
        needed += 3 + entry.key_size + entry.value_size;
      }
      needed += spans.input_end[index] - spans.input_start[index];
    }
    for (size_t index = 0; index < request.output_count; ++index)
      needed += spans.output_end[index] - spans.output_start[index];
    if (out_capacity < needed)
    {
      secure_zero(pending, sizeof(pending));
      return TransactionError::BufferTooSmall;
    }

    Writer writer = {out_psbt, out_capacity, 0};
    bool ok = write_bytes(&writer, kPsbtMagic, sizeof(kPsbtMagic)) &&
              write_bytes(&writer, psbt + spans.global_start,
                          spans.global_end - spans.global_start);
    if (summary != nullptr)
      summary->total_inputs = request.input_count;
    for (size_t index = 0; ok && index < request.input_count; ++index)
    {
      // Copy the map body without its terminator, then the new entry, then the
      // terminator: everything the constructor put there survives untouched.
      const PendingEntry &entry = pending[index];
      ok = write_bytes(&writer, psbt + spans.input_start[index],
                       spans.input_end[index] - spans.input_start[index] - 1);
      if (ok && entry.add)
      {
        ok = write_compact_size(&writer, entry.key_size) &&
             write_bytes(&writer, entry.key, entry.key_size) &&
             write_compact_size(&writer, entry.value_size) &&
             write_bytes(&writer, entry.value, entry.value_size);
        if (summary != nullptr)
          ++summary->signed_inputs;
      }
      else if (ok && entry.unchanged && summary != nullptr)
      {
        ++summary->unchanged_inputs;
      }
      if (ok)
      {
        const uint8_t terminator = 0x00;
        ok = write_bytes(&writer, &terminator, 1);
      }
    }
    for (size_t index = 0; ok && index < request.output_count; ++index)
      ok = write_bytes(&writer, psbt + spans.output_start[index],
                       spans.output_end[index] - spans.output_start[index]);
    secure_zero(pending, sizeof(pending));
    clear_bitcoin_request(&request);
    if (!ok)
      return TransactionError::BufferTooSmall;
    *out_size = writer.position;
    return TransactionError::Ok;
  }

  const char *transaction_error_text(TransactionError error)
  {
    switch (error)
    {
    case TransactionError::Ok:
      return "ok";
    case TransactionError::InvalidArgument:
      return "invalid-argument";
    case TransactionError::Truncated:
      return "truncated";
    case TransactionError::NonCanonical:
      return "non-canonical";
    case TransactionError::Unsupported:
      return "unsupported-field-or-script";
    case TransactionError::TooLarge:
      return "limit-exceeded";
    case TransactionError::MissingField:
      return "missing-field";
    case TransactionError::DuplicateField:
      return "duplicate-field";
    case TransactionError::WrongWallet:
      return "wrong-wallet-or-path";
    case TransactionError::InvalidAmount:
      return "invalid-amount";
    case TransactionError::FeePolicy:
      return "fee-policy";
    case TransactionError::CryptoFailure:
      return "crypto-failure";
    case TransactionError::BufferTooSmall:
      return "buffer-too-small";
    }
    return "unknown";
  }

  void clear_bitcoin_request(BitcoinSigningRequest *request)
  {
    if (request != nullptr)
      secure_zero(request, sizeof(*request));
  }

  TransactionError bitcoin_sighash_witness_v0(const BitcoinSigningRequest &request,
                                              size_t input_index,
                                              uint32_t sighash_type,
                                              const uint8_t *script_code,
                                              size_t script_code_size,
                                              uint8_t out[kSha256Size])
  {
    return witness_v0_digest(request, input_index, sighash_type, script_code,
                             script_code_size, out, nullptr);
  }

  bool bitcoin_multisig_script(const uint8_t *public_keys, size_t key_count,
                               uint8_t threshold, uint8_t *out, size_t capacity,
                               size_t *out_size)
  {
    if (public_keys == nullptr || out == nullptr || out_size == nullptr ||
        key_count == 0 || key_count > kBitcoinMaxMultisigKeys || threshold == 0 ||
        threshold > key_count)
    {
      return false;
    }
    const size_t size = 1 + key_count * 34 + 2;
    if (capacity < size)
      return false;
    size_t offset = 0;
    // OP_1..OP_16 are 0x51..0x60, so the small integer opcode is 0x50 + n.
    out[offset++] = static_cast<uint8_t>(0x50 + threshold);
    for (size_t index = 0; index < key_count; ++index)
    {
      const uint8_t *key = public_keys + index * kCompressedPublicKeySize;
      if (key[0] != 0x02 && key[0] != 0x03)
        return false;
      out[offset++] = kCompressedPublicKeySize; // 33, a direct data push
      memcpy(out + offset, key, kCompressedPublicKeySize);
      offset += kCompressedPublicKeySize;
    }
    out[offset++] = static_cast<uint8_t>(0x50 + key_count);
    out[offset++] = 0xae; // OP_CHECKMULTISIG
    *out_size = offset;
    return true;
  }

  bool bitcoin_parse_multisig_script(const uint8_t *script, size_t script_size,
                                     uint8_t *threshold, uint8_t *key_count,
                                     uint8_t *keys, size_t key_capacity)
  {
    if (script == nullptr || threshold == nullptr || key_count == nullptr ||
        keys == nullptr || script_size < 3)
    {
      return false;
    }
    // Only the canonical small-integer opcodes count. A script using
    // OP_PUSHBYTES_1 0x06 instead of OP_6 means the same thing to the VM but not
    // to this parser, and a witness script this firmware cannot reproduce
    // byte-for-byte is one it cannot honestly show as its own.
    if (script[0] < 0x51 || script[0] > 0x60)
      return false;
    const uint8_t m = static_cast<uint8_t>(script[0] - 0x50);
    size_t offset = 1;
    uint8_t found = 0;
    while (offset + 34 < script_size && found < kBitcoinMaxMultisigKeys)
    {
      if (script[offset] != kCompressedPublicKeySize)
        break;
      const uint8_t *key = script + offset + 1;
      if ((key[0] != 0x02 && key[0] != 0x03) ||
          (found + 1) * kCompressedPublicKeySize > key_capacity)
        return false;
      memcpy(keys + found * kCompressedPublicKeySize, key, kCompressedPublicKeySize);
      ++found;
      offset += 1 + kCompressedPublicKeySize;
    }
    if (found == 0 || offset + 2 != script_size)
      return false;
    if (script[offset] < 0x51 || script[offset] > 0x60 || script[offset + 1] != 0xae)
      return false;
    const uint8_t n = static_cast<uint8_t>(script[offset] - 0x50);
    if (n != found || m == 0 || m > n)
      return false;
    *threshold = m;
    *key_count = n;
    return true;
  }

  bool bitcoin_p2wsh_program(const uint8_t *witness_script,
                             size_t witness_script_size, uint8_t out[32])
  {
    if (witness_script == nullptr || out == nullptr || witness_script_size == 0 ||
        witness_script_size > kBitcoinMaxWitnessScriptSize)
    {
      return false;
    }
    return crypto_sha256(witness_script, witness_script_size, out);
  }

  bool bitcoin_p2sh_p2wsh_redeem(const uint8_t *witness_script,
                                 size_t witness_script_size, uint8_t out[34])
  {
    if (out == nullptr)
      return false;
    out[0] = 0x00;
    out[1] = 0x20;
    return bitcoin_p2wsh_program(witness_script, witness_script_size, out + 2);
  }

  TransactionError bitcoin_sighash_legacy(const BitcoinSigningRequest &request,
                                          size_t input_index, uint32_t sighash_type,
                                          uint8_t out[kSha256Size])
  {
    return legacy_digest(request, input_index, sighash_type, out);
  }

  TransactionError bitcoin_sighash_bip143(const BitcoinSigningRequest &request,
                                          size_t input_index, uint32_t sighash_type,
                                          uint8_t out[kSha256Size])
  {
    return bip143_digest(request, input_index, sighash_type, out);
  }

  uint32_t bitcoin_estimated_vbytes(const BitcoinSigningRequest &request)
  {
    return estimated_vbytes(request);
  }

  TransactionError peercoin_sighash_all(const BitcoinSigningRequest &request,
                                        uint32_t transaction_time,
                                        size_t input_index, bool witness_v0,
                                        uint8_t out[kSha256Size])
  {
    if (out != nullptr)
      secure_zero(out, kSha256Size);
    if (request.version < 1 || request.version > 3 ||
        (request.version == 3 && transaction_time != 0) ||
        !valid_digest_request(request, input_index, kSighashAll, out))
      return TransactionError::InvalidArgument;
    const BitcoinSpendType spend = request.inputs[input_index].spend_type;
    if ((!witness_v0 && spend != BitcoinSpendType::LegacyP2pkh) ||
        (witness_v0 && spend != BitcoinSpendType::NativeP2wpkh &&
         spend != BitcoinSpendType::NestedP2shP2wpkh))
      return TransactionError::Unsupported;
    const uint32_t *time = request.version < 3 ? &transaction_time : nullptr;
    return witness_v0 ? bip143_digest(request, input_index, kSighashAll, out, time)
                      : legacy_digest(request, input_index, kSighashAll, out, time);
  }

  bool run_peercoin_sighash_self_tests()
  {
#include "src/generated/PeercoinSighashVectors.inc"
    BitcoinSigningRequest request = {};
    request.input_count = 2;
    request.output_count = 2;
    request.lock_time = 12345;
    // Public key is secp256k1's generator (scalar 1), a public test fixture.
    const uint8_t pub[33] = {0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
                             0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59,
                             0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
    for (size_t i = 0; i < 2; ++i)
    {
      BitcoinInput &input = request.inputs[i];
      for (size_t j = 0; j < 32; ++j)
        input.previous_txid[j] = static_cast<uint8_t>(j + 32 * i);
      input.previous_index = static_cast<uint32_t>(i);
      input.sequence = 0xfffffffdU - static_cast<uint32_t>(i);
      input.value = 2000000 + i * 1000000;
      memcpy(input.public_key, pub, sizeof(pub));
      request.outputs[i].value = 1000000 + i * 2000000;
      request.outputs[i].script_size = 25;
      uint8_t *script = request.outputs[i].script;
      script[0] = 0x76;
      script[1] = 0xa9;
      script[2] = 0x14;
      memset(script + 3, static_cast<int>(0x11 + i), 20);
      script[23] = 0x88;
      script[24] = 0xac;
    }
    uint8_t digest[32] = {}, changed[32] = {};
    bool ok = true;
    for (uint32_t version = 1; version <= 3; ++version)
    {
      request.version = version;
      const uint32_t time = version < 3 ? 1700000000U : 0;
      for (unsigned witness = 0; witness < 2; ++witness)
      {
        for (size_t index = 0; index < 2; ++index)
        {
          request.inputs[index].spend_type = witness ? BitcoinSpendType::NativeP2wpkh
                                                     : BitcoinSpendType::LegacyP2pkh;
          ok = ok && peercoin_sighash_all(request, time, index, witness != 0, digest) == TransactionError::Ok &&
               crypto_constant_time_equal(digest, kPeercoinDigests[version - 1][witness][index], 32);
          if (version < 3)
          {
            ok = ok && peercoin_sighash_all(request, time + 1, index, witness != 0, changed) == TransactionError::Ok &&
                 !crypto_constant_time_equal(digest, changed, 32);
          }
        }
      }
    }
    memset(digest, 0xa5, sizeof(digest));
    ok = ok && peercoin_sighash_all(request, 1, 0, true, digest) == TransactionError::InvalidArgument;
    for (uint8_t byte : digest)
      ok = ok && byte == 0;
    ok = ok && peercoin_sighash_all(request, 0, 2, true, digest) == TransactionError::InvalidArgument;
    request.version = 4;
    ok = ok && peercoin_sighash_all(request, 0, 0, true, digest) == TransactionError::InvalidArgument;
    clear_bitcoin_request(&request);
    return ok;
  }

  bool run_groestlcoin_sighash_self_tests()
  {
    static const uint8_t kSpentScript[25] = {
        0x76, 0xa9, 0x14, 0x5a, 0x2f, 0xb6, 0xe3, 0x85, 0xf6, 0xd6, 0x4d, 0x2b,
        0xc0, 0x50, 0xcd, 0x77, 0x96, 0x7d, 0xe9, 0xa9, 0x0f, 0x9e, 0x4a, 0x88,
        0xac};
    // Previous outpoint 8d6026d9...2c51e9e6:0, little endian as serialized.
    static const uint8_t kPreviousTxid[32] = {
        0xe6, 0xe9, 0x51, 0x2c, 0x06, 0x73, 0x10, 0x8f, 0x7b, 0x38, 0xd5, 0xba,
        0x2e, 0x54, 0x9c, 0x92, 0x4f, 0xd9, 0x2a, 0x78, 0x8a, 0xe0, 0xea, 0x01,
        0x25, 0x4d, 0x02, 0x14, 0xd9, 0x26, 0x60, 0x8d};
    static const uint8_t kPublicKey[33] = {
        0x03, 0xf4, 0xb9, 0xdd, 0xd6, 0x6b, 0x30, 0x46, 0xde, 0x57, 0x50, 0x59,
        0x9a, 0x09, 0xe3, 0xf2, 0x15, 0x04, 0xd0, 0xbb, 0x03, 0xb8, 0xad, 0x75,
        0x58, 0x8d, 0xd3, 0x5a, 0x93, 0xe6, 0xf1, 0x88, 0xf1};
    // scriptSig of that spend: DER signature then the sighash byte, then the key.
    static const uint8_t kSignature[] = {
        0x30, 0x44, 0x02, 0x20, 0x44, 0x0c, 0x79, 0x0f, 0xc6, 0x95, 0x9e, 0x0f,
        0xd2, 0xb3, 0x80, 0xdb, 0x0b, 0x83, 0x65, 0x4a, 0x3e, 0xe8, 0xe1, 0x86,
        0x0e, 0x52, 0xa2, 0x99, 0x69, 0x4c, 0xd0, 0xd5, 0x1a, 0x93, 0x6e, 0x8b,
        0x02, 0x20, 0x37, 0x56, 0x10, 0x03, 0x42, 0x79, 0x31, 0xc8, 0xfe, 0x4e,
        0x01, 0x15, 0x3c, 0xe3, 0x84, 0x55, 0x93, 0xd7, 0x4b, 0x5c, 0xcb, 0xa3,
        0x73, 0x73, 0x45, 0x1f, 0x20, 0x2f, 0x75, 0x28, 0x07, 0x6e};
    static const uint8_t kSingleDigest[32] = {
        0xdf, 0x00, 0xbd, 0xc1, 0x26, 0x40, 0x2d, 0xef, 0xa7, 0xe9, 0x27, 0x77,
        0x2d, 0x1b, 0xaf, 0x20, 0xf6, 0xf5, 0x0a, 0x02, 0xb3, 0x75, 0xab, 0xe4,
        0xbd, 0x32, 0xe9, 0x4f, 0xa1, 0x11, 0xb3, 0xbe};
    static const uint8_t kDoubleDigest[32] = {
        0xeb, 0x24, 0x79, 0xaa, 0x45, 0xa2, 0x37, 0xe8, 0x4d, 0x60, 0xbd, 0x87,
        0xca, 0x94, 0x54, 0x94, 0x1b, 0xc2, 0x02, 0x56, 0xc8, 0x43, 0x1f, 0x55,
        0x9e, 0x8d, 0xb3, 0x31, 0x50, 0xa7, 0x9f, 0x0d};
    // Output 1 is P2WPKH, whose bech32 rendering depends on nothing but the
    // program and the "grs" prefix, so it can be pinned from the chain.
    static const char kOutputOneAddress[] = "grs1q94gj9xhh0kgfkwe7ca9f8jertlm56es75xlrpg";

    BitcoinSigningRequest request = {};
    request.version = 2;
    request.lock_time = 6324417;
    request.chain = {"grs", nullptr, kGroestlcoinMainnet, SighashFamily::GroestlLegacy, 0};
    request.input_count = 1;
    request.output_count = 2;
    memcpy(request.inputs[0].previous_txid, kPreviousTxid, sizeof(kPreviousTxid));
    request.inputs[0].previous_index = 0;
    request.inputs[0].sequence = 0xfffffffdU;
    // The legacy sighash does not commit to the spent value; any plausible one
    // yields the same digest.
    request.inputs[0].value = 7272925976ULL;
    request.inputs[0].spend_type = BitcoinSpendType::LegacyP2pkh;
    memcpy(request.inputs[0].public_key, kPublicKey, sizeof(kPublicKey));
    // hash160(public_key) must equal the hash in the spent script, or the review
    // would be signing for a key that cannot spend this output.
    request.outputs[0].value = 7272925976ULL;
    // Output 0 of the spending transaction pays a different P2PKH key.
    static const uint8_t kOutputZeroScript[25] = {
        0x76, 0xa9, 0x14, 0x90, 0xeb, 0x8c, 0x02, 0x6d, 0x08, 0xc6, 0x99, 0x32,
        0xbe, 0x74, 0x7f, 0xb0, 0x63, 0xeb, 0xbd, 0x88, 0x24, 0xfa, 0xd5, 0x88,
        0xac};
    request.outputs[0].script_size = sizeof(kOutputZeroScript);
    memcpy(request.outputs[0].script, kOutputZeroScript, sizeof(kOutputZeroScript));
    request.outputs[1].value = 131452829ULL;
    static const uint8_t kOutputOneScript[22] = {
        0x00, 0x14, 0x2d, 0x51, 0x22, 0x9a, 0xf7, 0x7d, 0x90, 0x9b, 0x3b,
        0x3e, 0xc7, 0x4a, 0x93, 0xcb, 0x23, 0x5f, 0xf7, 0x4d, 0x66, 0x1e};
    request.outputs[1].script_size = sizeof(kOutputOneScript);
    memcpy(request.outputs[1].script, kOutputOneScript, sizeof(kOutputOneScript));

    uint8_t key_hash[kRipemd160Size] = {};
    bool passed = crypto_hash160(kPublicKey, sizeof(kPublicKey), key_hash) &&
                  crypto_constant_time_equal(key_hash, kSpentScript + 3,
                                             kRipemd160Size);
    memcpy(request.inputs[0].witness_key_hash, key_hash, sizeof(key_hash));
    secure_zero(key_hash, sizeof(key_hash));

    uint8_t digest[32];
    const TransactionError groestl_result = legacy_digest(request, 0, kSighashAll, digest);
    passed = passed && groestl_result == TransactionError::Ok &&
             crypto_constant_time_equal(digest, kSingleDigest, sizeof(kSingleDigest));
    // The on-chain signature must verify against the digest this code produced.
    passed = passed &&
             ecdsa_verify_der(EcdsaCurve::Secp256k1, kPublicKey, sizeof(kPublicKey),
                              digest, kSignature, sizeof(kSignature));

    // The same bytes hashed twice produce Bitcoin's digest, and the very same
    // signature must not verify against it. This is the mistake being fixed.
    BitcoinSigningRequest bitcoin_view = request;
    bitcoin_view.chain.sighash = SighashFamily::Bitcoin;
    uint8_t double_digest[32];
    passed = passed &&
             legacy_digest(bitcoin_view, 0, kSighashAll, double_digest) ==
                 TransactionError::Ok &&
             crypto_constant_time_equal(double_digest, kDoubleDigest,
                                        sizeof(kDoubleDigest)) &&
             !ecdsa_verify_der(EcdsaCurve::Secp256k1, kPublicKey,
                               sizeof(kPublicKey), double_digest, kSignature,
                               sizeof(kSignature));

    // Groestlcoin has no SIGHASH_FORKID, so that bit is refused rather than
    // silently rerouted to the BIP143 preimage.
    passed = passed &&
             legacy_digest(request, 0, kSighashForkIdAll, digest) ==
                 TransactionError::InvalidArgument;

    // --- segwit. BIP143 with Groestlcoin's single-finalise writer on all four
    // hashes (interpreter.cpp GetPrevoutsSHA256/GetSequencesSHA256/GetOutputsSHA256
    // each call GetSHA256()). Expected values come from an independent Python
    // implementation built from the same fields; the Bitcoin-rule digest below is
    // the same preimage hashed the other way, so a regression that "fixes" the
    // sub-hashes back to double-SHA256 cannot pass both.
    BitcoinSigningRequest segwit = {};
    segwit.version = 2;
    segwit.lock_time = 6324417;
    segwit.chain = {"grs84", nullptr, kGroestlcoinMainnet,
                    SighashFamily::GroestlLegacy, 0};
    segwit.input_count = 1;
    segwit.output_count = 1;
    memcpy(segwit.inputs[0].previous_txid, kPreviousTxid, sizeof(kPreviousTxid));
    segwit.inputs[0].previous_index = 0;
    segwit.inputs[0].sequence = 0xfffffffdU;
    segwit.inputs[0].value = 7272925976ULL;
    segwit.inputs[0].spend_type = BitcoinSpendType::NativeP2wpkh;
    memcpy(segwit.inputs[0].public_key, kPublicKey, sizeof(kPublicKey));
    memcpy(segwit.inputs[0].witness_key_hash, kSpentScript + 3, kRipemd160Size);
    segwit.outputs[0].value = 1000000000ULL;
    segwit.outputs[0].script_size = sizeof(kOutputZeroScript);
    memcpy(segwit.outputs[0].script, kOutputZeroScript, sizeof(kOutputZeroScript));
    static const uint8_t kSegwitDigest[32] = {
        0x39, 0x09, 0x05, 0xce, 0x10, 0x8a, 0x6b, 0x2f, 0x4d, 0x8c, 0x24,
        0x66, 0x78, 0xfa, 0x49, 0x01, 0x48, 0x36, 0xaf, 0xa4, 0xe3, 0xd7,
        0x17, 0x3f, 0xf3, 0x02, 0x43, 0x7b, 0x64, 0x11, 0x97, 0x8f};
    static const uint8_t kSegwitDigestBitcoinRules[32] = {
        0x94, 0x82, 0x85, 0x86, 0xa8, 0xc1, 0x1d, 0x46, 0x73, 0x8c, 0x3e,
        0x70, 0xf7, 0xd8, 0x6f, 0x3c, 0x92, 0x3a, 0x14, 0x99, 0xda, 0xb5,
        0xf5, 0x64, 0x19, 0x45, 0x00, 0xef, 0x28, 0xaf, 0x3b, 0x4f};
    passed = passed &&
             bip143_digest(segwit, 0, kSighashAll, digest) == TransactionError::Ok &&
             crypto_constant_time_equal(digest, kSegwitDigest, sizeof(kSegwitDigest));
    BitcoinSigningRequest segwit_bitcoin = segwit;
    segwit_bitcoin.chain.sighash = SighashFamily::Bitcoin;
    passed = passed &&
             bip143_digest(segwit_bitcoin, 0, kSighashAll, digest) ==
                 TransactionError::Ok &&
             crypto_constant_time_equal(digest, kSegwitDigestBitcoinRules,
                                        sizeof(kSegwitDigestBitcoinRules));
    // A GRS wallet must be able to review a grs1… output, and the same script must
    // render differently under Bitcoin's checksum rules.
    char address[kAddressTextSize] = {};
    passed = passed &&
             chain_address_from_script(segwit.chain, kOutputOneScript,
                                       sizeof(kOutputOneScript), address,
                                       sizeof(address)) == WalletError::Ok &&
             strncmp(address, "grs1q", 5) == 0;
    clear_bitcoin_request(&segwit);
    clear_bitcoin_request(&segwit_bitcoin);

    // Reviewing this transaction must render Groestlcoin's address encoding for
    // both outputs: double-Groestl-512 for the P2PKH one and bech32 for the
    // witness one, whose value is fixed by the script alone.
    passed = passed &&
             chain_address_from_script(request.chain, request.outputs[1].script,
                                       request.outputs[1].script_size, address,
                                       sizeof(address)) == WalletError::Ok &&
             strcmp(address, kOutputOneAddress) == 0;
    // Version byte 0x24 always renders with a leading 'F' on this chain, so a
    // wrong checksum or a wrong version byte cannot slip through as "some address".
    passed = passed &&
             chain_address_from_script(request.chain, request.outputs[0].script,
                                       request.outputs[0].script_size, address,
                                       sizeof(address)) == WalletError::Ok &&
             address[0] == 'F' && strlen(address) > 20;
    char sha256_address[kAddressTextSize] = {};
    passed = passed &&
             chain_address_from_script(bitcoin_view.chain, request.outputs[0].script,
                                       request.outputs[0].script_size,
                                       sha256_address, sizeof(sha256_address)) ==
                 WalletError::Ok &&
             chain_address_from_script(request.chain, request.outputs[0].script,
                                       request.outputs[0].script_size, address,
                                       sizeof(address)) == WalletError::Ok &&
             strcmp(address, sha256_address) != 0;

    secure_zero(digest, sizeof(digest));
    secure_zero(double_digest, sizeof(double_digest));
    secure_zero(address, sizeof(address));
    secure_zero(sha256_address, sizeof(sha256_address));
    clear_bitcoin_request(&request);
    clear_bitcoin_request(&bitcoin_view);
    return passed;
  }

  // Digest-only vectors: no ECDSA, so this runs on the host as well as on the
  // device. Expected values were produced by an independent Python secp256k1/
  // SHA-256 implementation from the same transaction fields.
  bool run_bitcoin_sighash_self_tests()
  {
    // The same funding transaction with and without witness must yield the
    // same txid, including for one input. The witness marker cannot stand for
    // an entirely empty witness. These cases previously failed reconstruction.
    uint8_t base[85] = {};
    base[0] = 2;
    base[4] = 1;
    base[5] = 1;
    memset(base + 42, 0xff, 4);
    base[46] = 1;
    base[47] = 0xa0;
    base[48] = 0x86;
    base[49] = 1;
    base[55] = 25;
    base[56] = 0x76;
    base[57] = 0xa9;
    base[58] = 0x14;
    memset(base + 59, 0x11, 20);
    base[79] = 0x88;
    base[80] = 0xac;
    uint8_t witness[90] = {};
    memcpy(witness, base, 4);
    witness[4] = 0;
    witness[5] = 1;
    memcpy(witness + 6, base + 4, 77);
    witness[83] = 1;
    witness[84] = 1;
    witness[85] = 0xaa;
    memcpy(witness + 86, base + 81, 4);
    uint8_t txid[32] = {}, prev_script[kBitcoinMaxScriptSize] = {};
    uint64_t prev_value = 0;
    uint8_t prev_size = 0;
    if (!crypto_double_sha256(base, sizeof(base), txid) ||
        parse_previous_transaction(base, sizeof(base), txid, 0, &prev_value, prev_script, &prev_size) != TransactionError::Ok ||
        parse_previous_transaction(witness, sizeof(witness), txid, 0, &prev_value, prev_script, &prev_size) != TransactionError::Ok ||
        prev_value != 100000 || prev_size != 25 || memcmp(prev_script, base + 56, 25))
      return false;
    witness[85] ^= 1; // witness mutation is not part of txid
    if (parse_previous_transaction(witness, sizeof(witness), txid, 0, &prev_value, prev_script, &prev_size) != TransactionError::Ok)
      return false;
    witness[83] = 0; // no stack; remaining four bytes are nLockTime
    if (parse_previous_transaction(witness, 88, txid, 0, &prev_value, prev_script, &prev_size) != TransactionError::NonCanonical)
      return false;
    // A fabricated legacy witness_utxo must be rejected before any key work.
    uint8_t legacy_map[38] = {1, 1, 34};
    memcpy(legacy_map + 3, base + 47, 34);
    Cursor legacy_cursor = {legacy_map, sizeof(legacy_map), 0};
    HdPrivateNode dummy_master = {};
    BitcoinInput dummy_input = {};
    const BitcoinChainParams bitcoin_chain = {"btc44", nullptr, kBitcoinMainnet, SighashFamily::Bitcoin, 0};
    if (parse_input_map(&legacy_cursor, dummy_master, bitcoin_chain, &dummy_input) != TransactionError::MissingField)
      return false;
    BitcoinSigningRequest repeated = {};
    repeated.version = 2;
    repeated.chain = bitcoin_chain;
    repeated.input_count = 2;
    repeated.output_count = 1;
    uint8_t rejected[1] = {};
    size_t rejected_size = sizeof(rejected);
    if (bitcoin_sign_request(repeated, dummy_master, rejected, &rejected_size) != TransactionError::DuplicateField)
      return false;
    const uint8_t previous[32] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    const uint8_t script[25] = {0x76, 0xa9, 0x14, 0x1d, 0x0f, 0x17, 0x2a, 0x0e, 0xcb, 0x48, 0xae, 0xe1, 0xbe, 0x1f, 0x26, 0x87, 0xd2, 0x96, 0x3a, 0xe3, 0x3f, 0x71, 0xa1, 0x88, 0xac};
    const uint8_t public_key[33] = {0x02, 0x54, 0x76, 0xc2, 0xe8, 0x31, 0x88, 0x36, 0x8d, 0xa1, 0xff, 0x3e, 0x29, 0x2e, 0x7a, 0xca, 0xfc, 0xdb, 0x35, 0x66, 0xbb, 0x0a, 0xd2, 0x53, 0xf6, 0x2f, 0xc7, 0x0f, 0x07, 0xae, 0xee, 0x63, 0x57};
    const uint8_t expected_legacy[32] = {0x5e, 0x2c, 0xfd, 0x9b, 0x40, 0x75, 0xe4, 0xd4, 0x1c, 0x4c, 0xa0, 0x80, 0x55, 0x77, 0xb8, 0xce, 0x78, 0x7a, 0x58, 0x49, 0x19, 0x44, 0xba, 0x4d, 0xff, 0x9b, 0xe1, 0x15, 0xad, 0x6a, 0xc8, 0x66};
    const uint8_t expected_forkid[32] = {0x5f, 0xd0, 0x99, 0x40, 0x88, 0x48, 0x18, 0xf4, 0xbd, 0xf8, 0xce, 0xa7, 0xf0, 0x8f, 0x42, 0x21, 0xc9, 0x7f, 0x4f, 0xa5, 0x2d, 0xe6, 0x27, 0xf6, 0xc3, 0x9d, 0x3f, 0xc7, 0xc2, 0x2c, 0x7c, 0xc6};
    BitcoinSigningRequest request = {};
    request.version = 1;
    request.lock_time = 0;
    request.chain = {"btc", nullptr, kBitcoinMainnet, SighashFamily::Bitcoin, 0};
    request.input_count = 1;
    request.output_count = 1;
    memcpy(request.inputs[0].previous_txid, previous, sizeof(previous));
    request.inputs[0].sequence = 0xfffffffd;
    request.inputs[0].value = 100000;
    request.inputs[0].spend_type = BitcoinSpendType::LegacyP2pkh;
    memcpy(request.inputs[0].public_key, public_key, sizeof(public_key));
    memcpy(request.inputs[0].witness_key_hash, script + 3, kRipemd160Size);
    request.outputs[0].value = 90000;
    request.outputs[0].script_size = sizeof(script);
    memcpy(request.outputs[0].script, script, sizeof(script));
    uint8_t digest[32];
    bool passed = legacy_digest(request, 0, kSighashAll, digest) == TransactionError::Ok &&
                  crypto_constant_time_equal(digest, expected_legacy, sizeof(expected_legacy));
    passed = passed && bip143_digest(request, 0, kSighashForkIdAll, digest) == TransactionError::Ok &&
             crypto_constant_time_equal(digest, expected_forkid, sizeof(expected_forkid));
    passed = passed && legacy_digest(request, 0, kSighashForkIdAll, digest) == TransactionError::Ok &&
             crypto_constant_time_equal(digest, expected_forkid, sizeof(expected_forkid));
    passed = passed && estimated_vbytes(request) == 193;
    passed = passed && legacy_digest(request, 1, kSighashAll, digest) == TransactionError::InvalidArgument &&
             bip143_digest(request, 0, 2, digest) == TransactionError::InvalidArgument &&
             legacy_digest(request, 0, kSighashAll, nullptr) == TransactionError::InvalidArgument;
    request.outputs[0].script_size = kBitcoinMaxScriptSize + 1;
    passed = passed && legacy_digest(request, 0, kSighashAll, digest) == TransactionError::InvalidArgument &&
             bip143_digest(request, 0, kSighashAll, digest) == TransactionError::InvalidArgument;
    secure_zero(digest, sizeof(digest));
    clear_bitcoin_request(&request);
    return passed;
  }

  bool run_bitcoin_transaction_self_test()
  {
    g_bitcoin_stage = 1;
    BitcoinSigningRequest request = {};
    request.version = 1;
    request.lock_time = 0x11;
    request.chain = {"btc", nullptr, kBitcoinMainnet, SighashFamily::Bitcoin, 0};
    request.input_count = 2;
    request.output_count = 2;
    const uint8_t prev0[32] = {0xff, 0xf7, 0xf7, 0x88, 0x1a, 0x80, 0x99, 0xaf, 0xa6, 0x94, 0x0d, 0x42, 0xd1, 0xe7, 0xf6, 0x36, 0x2b, 0xec, 0x38, 0x17, 0x1e, 0xa3, 0xed, 0xf4, 0x33, 0x54, 0x1d, 0xb4, 0xe4, 0xad, 0x96, 0x9f};
    const uint8_t prev1[32] = {0xef, 0x51, 0xe1, 0xb8, 0x04, 0xcc, 0x89, 0xd1, 0x82, 0xd2, 0x79, 0x65, 0x5c, 0x3a, 0xa8, 0x9e, 0x81, 0x5b, 0x1b, 0x30, 0x9f, 0xe2, 0x87, 0xd9, 0xb2, 0xb5, 0x5d, 0x57, 0xb9, 0x0e, 0xc6, 0x8a};
    memcpy(request.inputs[0].previous_txid, prev0, 32);
    memcpy(request.inputs[1].previous_txid, prev1, 32);
    request.inputs[0].sequence = 0xffffffee;
    request.inputs[1].previous_index = 1;
    request.inputs[1].sequence = 0xffffffff;
    request.inputs[1].value = 600000000;
    const uint8_t public_key[33] = {0x02, 0x54, 0x76, 0xc2, 0xe8, 0x31, 0x88, 0x36, 0x8d, 0xa1, 0xff, 0x3e, 0x29, 0x2e, 0x7a, 0xca, 0xfc, 0xdb, 0x35, 0x66, 0xbb, 0x0a, 0xd2, 0x53, 0xf6, 0x2f, 0xc7, 0x0f, 0x07, 0xae, 0xee, 0x63, 0x57};
    memcpy(request.inputs[1].public_key, public_key, sizeof(public_key));
    const uint8_t output0[25] = {0x76, 0xa9, 0x14, 0x82, 0x80, 0xb3, 0x7d, 0xf3, 0x78, 0xdb, 0x99, 0xf6, 0x6f, 0x85, 0xc9, 0x5a, 0x78, 0x3a, 0x76, 0xac, 0x7a, 0x6d, 0x59, 0x88, 0xac};
    const uint8_t output1[25] = {0x76, 0xa9, 0x14, 0x3b, 0xde, 0x42, 0xdb, 0xee, 0x7e, 0x4d, 0xbe, 0x6a, 0x21, 0xb2, 0xd5, 0x0c, 0xe2, 0xf0, 0x16, 0x7f, 0xaa, 0x81, 0x59, 0x88, 0xac};
    request.outputs[0].value = 112340000;
    request.outputs[1].value = 223450000;
    request.outputs[0].script_size = sizeof(output0);
    request.outputs[1].script_size = sizeof(output1);
    memcpy(request.outputs[0].script, output0, sizeof(output0));
    memcpy(request.outputs[1].script, output1, sizeof(output1));
    const uint8_t expected[32] = {0xc3, 0x7a, 0xf3, 0x11, 0x16, 0xd1, 0xb2, 0x7c, 0xaf, 0x68, 0xaa, 0xe9, 0xe3, 0xac, 0x82, 0xf1, 0x47, 0x79, 0x29, 0x01, 0x4d, 0x5b, 0x91, 0x76, 0x57, 0xd0, 0xeb, 0x49, 0x47, 0x8c, 0xb6, 0x70};
    const uint8_t private_key[32] = {0x61, 0x9c, 0x33, 0x50, 0x25, 0xc7, 0xf4, 0x01, 0x2e, 0x55, 0x6c, 0x2a, 0x58, 0xb2, 0x50, 0x6e, 0x30, 0xb8, 0x51, 0x1b, 0x53, 0xad, 0xe9, 0x5e, 0xa3, 0x16, 0xfd, 0x8c, 0x32, 0x86, 0xfe, 0xb9};
    const uint8_t expected_signature[70] = {0x30, 0x44, 0x02, 0x20, 0x36, 0x09, 0xe1, 0x7b, 0x84, 0xf6, 0xa7, 0xd3, 0x0c, 0x80, 0xbf, 0xa6, 0x10, 0xb5, 0xb4, 0x54, 0x2f, 0x32, 0xa8, 0xa0, 0xd5, 0x44, 0x7a, 0x12, 0xfb, 0x13, 0x66, 0xd7, 0xf0, 0x1c, 0xc4, 0x4a, 0x02, 0x20, 0x57, 0x3a, 0x95, 0x4c, 0x45, 0x18, 0x33, 0x15, 0x61, 0x40, 0x6f, 0x90, 0x30, 0x0e, 0x8f, 0x33, 0x58, 0xf5, 0x19, 0x28, 0xd4, 0x3c, 0x21, 0x2a, 0x8c, 0xae, 0xd0, 0x2d, 0xe6, 0x7e, 0xeb, 0xee};
    uint8_t digest[kSha256Size];
    uint8_t signature[kBitcoinMaxDerSignatureSize];
    size_t signature_size = sizeof(signature);
    bool passed = bip143_digest(request, 1, kSighashAll, digest) == TransactionError::Ok && crypto_constant_time_equal(digest, expected, sizeof(expected)) && secp256k1_sign_der(private_key, digest, signature, &signature_size) && signature_size == sizeof(expected_signature) && crypto_constant_time_equal(signature, expected_signature, sizeof(expected_signature));
    secure_zero(digest, sizeof(digest));
    secure_zero(signature, sizeof(signature));
    clear_bitcoin_request(&request);

    BitcoinSigningRequest legacy = {};
    legacy.version = 1;
    legacy.lock_time = 0;
    legacy.chain = {"btc", nullptr, kBitcoinMainnet, SighashFamily::Bitcoin, 0};
    legacy.input_count = 1;
    legacy.output_count = 1;
    const uint8_t legacy_prev[32] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    const uint8_t legacy_script[25] = {0x76, 0xa9, 0x14, 0x1d, 0x0f, 0x17, 0x2a, 0x0e, 0xcb, 0x48, 0xae, 0xe1, 0xbe, 0x1f, 0x26, 0x87, 0xd2, 0x96, 0x3a, 0xe3, 0x3f, 0x71, 0xa1, 0x88, 0xac};
    const uint8_t legacy_key[32] = {0x61, 0x9c, 0x33, 0x50, 0x25, 0xc7, 0xf4, 0x01, 0x2e, 0x55, 0x6c, 0x2a, 0x58, 0xb2, 0x50, 0x6e, 0x30, 0xb8, 0x51, 0x1b, 0x53, 0xad, 0xe9, 0x5e, 0xa3, 0x16, 0xfd, 0x8c, 0x32, 0x86, 0xfe, 0xb9};
    const uint8_t legacy_public[33] = {0x02, 0x54, 0x76, 0xc2, 0xe8, 0x31, 0x88, 0x36, 0x8d, 0xa1, 0xff, 0x3e, 0x29, 0x2e, 0x7a, 0xca, 0xfc, 0xdb, 0x35, 0x66, 0xbb, 0x0a, 0xd2, 0x53, 0xf6, 0x2f, 0xc7, 0x0f, 0x07, 0xae, 0xee, 0x63, 0x57};
    const uint8_t expected_legacy[32] = {0x5e, 0x2c, 0xfd, 0x9b, 0x40, 0x75, 0xe4, 0xd4, 0x1c, 0x4c, 0xa0, 0x80, 0x55, 0x77, 0xb8, 0xce, 0x78, 0x7a, 0x58, 0x49, 0x19, 0x44, 0xba, 0x4d, 0xff, 0x9b, 0xe1, 0x15, 0xad, 0x6a, 0xc8, 0x66};
    const uint8_t expected_forkid[32] = {0x5f, 0xd0, 0x99, 0x40, 0x88, 0x48, 0x18, 0xf4, 0xbd, 0xf8, 0xce, 0xa7, 0xf0, 0x8f, 0x42, 0x21, 0xc9, 0x7f, 0x4f, 0xa5, 0x2d, 0xe6, 0x27, 0xf6, 0xc3, 0x9d, 0x3f, 0xc7, 0xc2, 0x2c, 0x7c, 0xc6};
    memcpy(legacy.inputs[0].previous_txid, legacy_prev, sizeof(legacy_prev));
    legacy.inputs[0].sequence = 0xfffffffd;
    legacy.inputs[0].value = 100000;
    legacy.inputs[0].spend_type = BitcoinSpendType::LegacyP2pkh;
    memcpy(legacy.inputs[0].public_key, legacy_public, sizeof(legacy_public));
    memcpy(legacy.inputs[0].witness_key_hash, legacy_script + 3, kRipemd160Size);
    legacy.outputs[0].value = 90000;
    legacy.outputs[0].script_size = sizeof(legacy_script);
    memcpy(legacy.outputs[0].script, legacy_script, sizeof(legacy_script));
    uint8_t legacy_digest_out[32];
    uint8_t forkid_digest_out[32];
    size_t legacy_signature_size = sizeof(signature);
    passed = passed && legacy_digest(legacy, 0, kSighashAll, legacy_digest_out) == TransactionError::Ok && crypto_constant_time_equal(legacy_digest_out, expected_legacy, sizeof(expected_legacy)) && legacy_digest(legacy, 0, kSighashForkIdAll, forkid_digest_out) == TransactionError::Ok && crypto_constant_time_equal(forkid_digest_out, expected_forkid, sizeof(expected_forkid)) && bip143_digest(legacy, 0, kSighashForkIdAll, forkid_digest_out) == TransactionError::Ok && crypto_constant_time_equal(forkid_digest_out, expected_forkid, sizeof(expected_forkid)) && secp256k1_sign_der(legacy_key, legacy_digest_out, signature, &legacy_signature_size);
    secure_zero(legacy_digest_out, sizeof(legacy_digest_out));
    secure_zero(forkid_digest_out, sizeof(forkid_digest_out));
    secure_zero(signature, sizeof(signature));
    clear_bitcoin_request(&legacy);

    if (passed) g_bitcoin_stage = 90;
    // BIP341 wallet-test-vectors.json, keyPathSpending[0]: nine inputs (four
    // taproot, one P2WPKH, one P2PKH, the rest taproot) and two outputs, all
    // field values taken verbatim from the BIP. hashType is SIGHASH_SINGLE,
    // which this wallet never signs, but the primitive must still compute it
    // correctly - that is what makes the published numbers a real check.
    {
      const uint8_t kVecSighash[32] = {0x25, 0x14, 0xa6, 0x27, 0x2f, 0x85, 0xcf, 0xa0, 0xf4, 0x5e, 0xb9, 0x07, 0xfc, 0xb0, 0xd1, 0x21, 0xb8, 0x08, 0xed, 0x37, 0xc6, 0xea, 0x16, 0x0a, 0x5a, 0x90, 0x46, 0xed, 0x55, 0x26, 0xd5, 0x55};
      const uint8_t kVecTweakedKey[32] = {0x24, 0x05, 0xb9, 0x71, 0x77, 0x2a, 0xd2, 0x69, 0x15, 0xc8, 0xdc, 0xdf, 0x10, 0xf2, 0x38, 0x75, 0x3a, 0x9b, 0x83, 0x7e, 0x5f, 0x8e, 0x6a, 0x86, 0xfd, 0x7c, 0x0c, 0xce, 0x5b, 0x72, 0x96, 0xd9};
      const uint8_t kVecInternalKey[32] = {0xd6, 0x88, 0x9c, 0xb0, 0x81, 0x03, 0x6e, 0x0f, 0xae, 0xfa, 0x3a, 0x35, 0x15, 0x7a, 0xd7, 0x10, 0x86, 0xb1, 0x23, 0xb2, 0xb1, 0x44, 0xb6, 0x49, 0x79, 0x8b, 0x49, 0x4c, 0x30, 0x0a, 0x96, 0x1d};
      const uint8_t kVecWitness[65] = {0xed, 0x7c, 0x16, 0x47, 0xcb, 0x97, 0x37, 0x9e, 0x76, 0x89, 0x2b, 0xe0, 0xca, 0xcf, 0xf5, 0x7e, 0xc4, 0xa7, 0x10, 0x2a, 0xa2, 0x42, 0x96, 0xca, 0x39, 0xaf, 0x75, 0x41, 0x24, 0x6d, 0x8f, 0xf1, 0x4d, 0x38, 0x95, 0x8d, 0x4c, 0xc1, 0xe2, 0xe4, 0x78, 0xe4, 0xd4, 0xa7, 0x64, 0xbb, 0xfd, 0x83, 0x5b, 0x16, 0xd4, 0xe3, 0x14, 0xb7, 0x29, 0x37, 0xb2, 0x98, 0x33, 0x06, 0x0b, 0x87, 0x27, 0x6c, 0x03};
      BitcoinSigningRequest vec = {};
      vec.version = 2;
      vec.lock_time = 500000000u;
      vec.input_count = 9;
      vec.output_count = 2;
      vec.chain = {"btc86", nullptr, kBitcoinMainnet, SighashFamily::Bitcoin, 0};
      const uint8_t kVecTxid0[32] = {0x7d, 0xe2, 0x0c, 0xbf, 0xf6, 0x86, 0xda, 0x83, 0xa5, 0x49, 0x81, 0xd2, 0xb9, 0xba, 0xb3, 0x58, 0x6f, 0x4c, 0xa7, 0xe4, 0x8f, 0x57, 0xf5, 0xb5, 0x59, 0x63, 0x11, 0x5f, 0x3b, 0x33, 0x4e, 0x9c};
      const uint8_t kVecSpk0[34] = {0x51, 0x20, 0x53, 0xa1, 0xf6, 0xe4, 0x54, 0xdf, 0x1a, 0xa2, 0x77, 0x6a, 0x28, 0x14, 0xa7, 0x21, 0x37, 0x2d, 0x62, 0x58, 0x05, 0x0d, 0xe3, 0x30, 0xb3, 0xc6, 0xd1, 0x0e, 0xe8, 0xf4, 0xe0, 0xdd, 0xa3, 0x43};
      memcpy(vec.inputs[0].previous_txid, kVecTxid0, 32);
      vec.inputs[0].previous_index = 1;
      vec.inputs[0].sequence = 0x00000000u;
      vec.inputs[0].value = 420000000ULL;
      vec.inputs[0].spend_type = BitcoinSpendType::TaprootBip86;
      memcpy(vec.inputs[0].taproot_output_key, kVecSpk0 + 2, 32);
      const uint8_t kVecTxid1[32] = {0xd7, 0xb7, 0xca, 0xb5, 0x7b, 0x13, 0x93, 0xac, 0xe2, 0xd0, 0x64, 0xf4, 0xd4, 0xa2, 0xcb, 0x8a, 0xf6, 0xde, 0xf6, 0x12, 0x73, 0xe1, 0x27, 0x51, 0x7d, 0x44, 0x75, 0x9b, 0x6d, 0xaf, 0xdd, 0x99};
      const uint8_t kVecSpk1[34] = {0x51, 0x20, 0x14, 0x7c, 0x9c, 0x57, 0x13, 0x2f, 0x6e, 0x7e, 0xcd, 0xdb, 0xa9, 0x80, 0x0b, 0xb0, 0xc4, 0x44, 0x92, 0x51, 0xc9, 0x2a, 0x1e, 0x60, 0x37, 0x1e, 0xe7, 0x75, 0x57, 0xb6, 0x62, 0x0f, 0x3e, 0xa3};
      memcpy(vec.inputs[1].previous_txid, kVecTxid1, 32);
      vec.inputs[1].previous_index = 0;
      vec.inputs[1].sequence = 0xffffffffu;
      vec.inputs[1].value = 462000000ULL;
      vec.inputs[1].spend_type = BitcoinSpendType::TaprootBip86;
      memcpy(vec.inputs[1].taproot_output_key, kVecSpk1 + 2, 32);
      const uint8_t kVecTxid2[32] = {0xf8, 0xe1, 0xf5, 0x83, 0x38, 0x43, 0x33, 0x68, 0x92, 0x28, 0xc5, 0xd2, 0x8e, 0xac, 0x13, 0x36, 0x6b, 0xe0, 0x82, 0xdc, 0x57, 0x44, 0x17, 0x60, 0xd9, 0x57, 0x27, 0x54, 0x19, 0xa4, 0x18, 0x42};
      const uint8_t kVecSpk2[25] = {0x76, 0xa9, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6, 0x88, 0xac};
      memcpy(vec.inputs[2].previous_txid, kVecTxid2, 32);
      vec.inputs[2].previous_index = 0;
      vec.inputs[2].sequence = 0xffffffffu;
      vec.inputs[2].value = 294000000ULL;
      vec.inputs[2].spend_type = BitcoinSpendType::LegacyP2pkh;
      memcpy(vec.inputs[2].witness_key_hash, kVecSpk2 + 3, 20);
      const uint8_t kVecTxid3[32] = {0xf0, 0x68, 0x91, 0x80, 0xaa, 0x63, 0xb3, 0x0c, 0xb1, 0x62, 0xa7, 0x3c, 0x6d, 0x2a, 0x38, 0xb7, 0xee, 0xda, 0x2a, 0x83, 0xec, 0xe7, 0x43, 0x10, 0xfd, 0xa0, 0x84, 0x3a, 0xd6, 0x04, 0x85, 0x3b};
      const uint8_t kVecSpk3[34] = {0x51, 0x20, 0xe4, 0xd8, 0x10, 0xfd, 0x50, 0x58, 0x62, 0x74, 0xfa, 0xce, 0x62, 0xb8, 0xa8, 0x07, 0xeb, 0x97, 0x19, 0xce, 0xf4, 0x9c, 0x04, 0x17, 0x7c, 0xc6, 0xb7, 0x6a, 0x9a, 0x42, 0x51, 0xd5, 0x45, 0x0e};
      memcpy(vec.inputs[3].previous_txid, kVecTxid3, 32);
      vec.inputs[3].previous_index = 1;
      vec.inputs[3].sequence = 0xfffffffeu;
      vec.inputs[3].value = 504000000ULL;
      vec.inputs[3].spend_type = BitcoinSpendType::TaprootBip86;
      memcpy(vec.inputs[3].taproot_output_key, kVecSpk3 + 2, 32);
      const uint8_t kVecTxid4[32] = {0xaa, 0x52, 0x02, 0xbd, 0xf6, 0xd8, 0xcc, 0xd2, 0xee, 0x0f, 0x02, 0x02, 0xaf, 0xbb, 0xb7, 0x46, 0x1d, 0x92, 0x64, 0xa2, 0x5e, 0x5b, 0xfd, 0x3c, 0x5a, 0x52, 0xee, 0x12, 0x39, 0xe0, 0xba, 0x6c};
      const uint8_t kVecSpk4[34] = {0x51, 0x20, 0x91, 0xb6, 0x4d, 0x53, 0x24, 0x72, 0x3a, 0x98, 0x51, 0x70, 0xe4, 0xdc, 0x5a, 0x0f, 0x84, 0xc0, 0x41, 0x80, 0x4f, 0x2c, 0xd1, 0x26, 0x60, 0xfa, 0x5d, 0xec, 0x09, 0xfc, 0x21, 0x78, 0x36, 0x05};
      memcpy(vec.inputs[4].previous_txid, kVecTxid4, 32);
      vec.inputs[4].previous_index = 0;
      vec.inputs[4].sequence = 0xfffffffeu;
      vec.inputs[4].value = 630000000ULL;
      vec.inputs[4].spend_type = BitcoinSpendType::TaprootBip86;
      memcpy(vec.inputs[4].taproot_output_key, kVecSpk4 + 2, 32);
      const uint8_t kVecTxid5[32] = {0x95, 0x61, 0x49, 0xbd, 0xc6, 0x6f, 0xaa, 0x96, 0x8e, 0xb2, 0xbe, 0x2d, 0x2f, 0xaa, 0x29, 0x71, 0x8a, 0xcb, 0xfe, 0x39, 0x41, 0x21, 0x58, 0x93, 0xa2, 0xa3, 0x44, 0x6d, 0x32, 0xac, 0xd0, 0x50};
      const uint8_t kVecSpk5[22] = {0x00, 0x14, 0x7d, 0xd6, 0x55, 0x92, 0xd0, 0xab, 0x2f, 0xe0, 0xd0, 0x25, 0x7d, 0x57, 0x1a, 0xbf, 0x03, 0x2c, 0xd9, 0xdb, 0x93, 0xdc};
      memcpy(vec.inputs[5].previous_txid, kVecTxid5, 32);
      vec.inputs[5].previous_index = 0;
      vec.inputs[5].sequence = 0x00000000u;
      vec.inputs[5].value = 378000000ULL;
      vec.inputs[5].spend_type = BitcoinSpendType::NativeP2wpkh;
      memcpy(vec.inputs[5].witness_key_hash, kVecSpk5 + 2, 20);
      const uint8_t kVecTxid6[32] = {0xe6, 0x64, 0xb9, 0x77, 0x3b, 0x88, 0xc0, 0x9c, 0x32, 0xcb, 0x70, 0xa2, 0xa3, 0xe4, 0xda, 0x0c, 0xed, 0x63, 0xb7, 0xba, 0x3b, 0x22, 0xf8, 0x48, 0x53, 0x1b, 0xbb, 0x1d, 0x5d, 0x5f, 0x4c, 0x94};
      const uint8_t kVecSpk6[34] = {0x51, 0x20, 0x75, 0x16, 0x9f, 0x40, 0x01, 0xaa, 0x68, 0xf1, 0x5b, 0xbe, 0xd2, 0x8b, 0x21, 0x8d, 0xf1, 0xd0, 0xa6, 0x2c, 0xbb, 0xcf, 0x11, 0x88, 0xc6, 0x66, 0x51, 0x10, 0xc2, 0x93, 0xc9, 0x07, 0xb8, 0x31};
      memcpy(vec.inputs[6].previous_txid, kVecTxid6, 32);
      vec.inputs[6].previous_index = 1;
      vec.inputs[6].sequence = 0x00000000u;
      vec.inputs[6].value = 672000000ULL;
      vec.inputs[6].spend_type = BitcoinSpendType::TaprootBip86;
      memcpy(vec.inputs[6].taproot_output_key, kVecSpk6 + 2, 32);
      const uint8_t kVecTxid7[32] = {0xe9, 0xaa, 0x6b, 0x8e, 0x6c, 0x9d, 0xe6, 0x76, 0x19, 0xe6, 0xa3, 0x92, 0x4a, 0xe2, 0x56, 0x96, 0xbb, 0x7b, 0x69, 0x4b, 0xb6, 0x77, 0xa6, 0x32, 0xa7, 0x4e, 0xf7, 0xea, 0xdf, 0xd4, 0xea, 0xbf};
      const uint8_t kVecSpk7[34] = {0x51, 0x20, 0x71, 0x24, 0x47, 0x20, 0x6d, 0x7a, 0x52, 0x38, 0xac, 0xc7, 0xff, 0x53, 0xfb, 0xe9, 0x4a, 0x3b, 0x64, 0x53, 0x9a, 0xd2, 0x91, 0xc7, 0xcd, 0xbc, 0x49, 0x0b, 0x75, 0x77, 0xe4, 0xb1, 0x7d, 0xf5};
      memcpy(vec.inputs[7].previous_txid, kVecTxid7, 32);
      vec.inputs[7].previous_index = 0;
      vec.inputs[7].sequence = 0xffffffffu;
      vec.inputs[7].value = 546000000ULL;
      vec.inputs[7].spend_type = BitcoinSpendType::TaprootBip86;
      memcpy(vec.inputs[7].taproot_output_key, kVecSpk7 + 2, 32);
      const uint8_t kVecTxid8[32] = {0xa7, 0x78, 0xeb, 0x6a, 0x26, 0x3d, 0xc0, 0x90, 0x46, 0x4c, 0xd1, 0x25, 0xc4, 0x66, 0xb5, 0xa9, 0x96, 0x67, 0x72, 0x0b, 0x1c, 0x11, 0x04, 0x68, 0x83, 0x1d, 0x05, 0x8a, 0xa1, 0xb8, 0x2a, 0xf1};
      const uint8_t kVecSpk8[34] = {0x51, 0x20, 0x77, 0xe3, 0x0a, 0x55, 0x22, 0xdd, 0x9f, 0x89, 0x4c, 0x3f, 0x8b, 0x8b, 0xd4, 0xc4, 0xb2, 0xcf, 0x82, 0xca, 0x7d, 0xa8, 0xa3, 0xea, 0x6a, 0x23, 0x96, 0x55, 0xc3, 0x9c, 0x05, 0x0a, 0xb2, 0x20};
      memcpy(vec.inputs[8].previous_txid, kVecTxid8, 32);
      vec.inputs[8].previous_index = 1;
      vec.inputs[8].sequence = 0xffffffffu;
      vec.inputs[8].value = 588000000ULL;
      vec.inputs[8].spend_type = BitcoinSpendType::TaprootBip86;
      memcpy(vec.inputs[8].taproot_output_key, kVecSpk8 + 2, 32);
      const uint8_t kVecOut0[25] = {0x76, 0xa9, 0x14, 0x06, 0xaf, 0xd4, 0x6b, 0xcd, 0xfd, 0x22, 0xef, 0x94, 0xac, 0x12, 0x2a, 0xa1, 0x1f, 0x24, 0x12, 0x44, 0xa3, 0x7e, 0xcc, 0x88, 0xac};
      vec.outputs[0].value = 1000000000ULL;
      vec.outputs[0].script_size = 25;
      memcpy(vec.outputs[0].script, kVecOut0, 25);
      const uint8_t kVecOut1[32] = {0xac, 0x9a, 0x87, 0xf5, 0x59, 0x4b, 0xe2, 0x08, 0xf8, 0x53, 0x2d, 0xb3, 0x8c, 0xff, 0x67, 0x0c, 0x45, 0x0e, 0xd2, 0xfe, 0xa8, 0xfc, 0xde, 0xfc, 0xc9, 0xa6, 0x63, 0xf7, 0x8b, 0xab, 0x96, 0x2b};
      vec.outputs[1].value = 3410000000ULL;
      vec.outputs[1].script_size = 32;
      memcpy(vec.outputs[1].script, kVecOut1, 32);
      uint8_t tap_digest[kSha256Size];
      const TransactionError tap_result =
          bitcoin_sighash_taproot(vec, 0, 3, nullptr, 0, tap_digest);
      passed = passed && tap_result == TransactionError::Ok;
      if (passed) g_bitcoin_stage = 91;
      passed = passed && crypto_constant_time_equal(tap_digest, kVecSighash, sizeof(kVecSighash));
      if (passed) g_bitcoin_stage = 92;
      // The signature the BIP publishes for this input must verify against the
      // digest computed here, under the tweaked key the paper also publishes.
      uint8_t vector_key[32];
      passed = passed &&
               ecdsa_xonly_public_key(EcdsaCurve::Secp256k1, kVecTweakedKey, vector_key, nullptr);
      if (passed) g_bitcoin_stage = 93;
      // The vector's tweaked private key belongs to the OUTPUT key, which is the
      // scriptPubKey of the spent output - not to the internal key it also
      // publishes. Recomputing TapTweak from the internal key closes the loop.
      uint8_t tweaked_public[32];
      passed = passed && crypto_constant_time_equal(vector_key, kVecSpk0 + 2, 32) &&
               taproot_bip86_output_key(kVecInternalKey, tweaked_public) == WalletError::Ok &&
               crypto_constant_time_equal(tweaked_public, kVecSpk0 + 2, 32);
      if (passed) g_bitcoin_stage = 94;
      passed = passed &&
               ecdsa_bip340_verify(EcdsaCurve::Secp256k1, vector_key, kVecSighash, kVecWitness) &&
               ecdsa_bip340_verify(EcdsaCurve::Secp256k1, vector_key, tap_digest, kVecWitness);
      secure_zero(tweaked_public, sizeof(tweaked_public));
      secure_zero(vector_key, sizeof(vector_key));
      secure_zero(tap_digest, sizeof(tap_digest));
      clear_bitcoin_request(&vec);
    }

    if (passed) g_bitcoin_stage = 95;
    // BIP86 published vector: the standard "abandon ... about" mnemonic, path
    // m/86'/0'/0'/0/0, internal key cc8a4bc6..6fc115, output key a60869f0..
    // dc684c and the address bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr.
    {
      static const char kMnemonic[] =
          "abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon about";
      const uint8_t kExpectedInternal[32] = {
          0xcc, 0x8a, 0x4b, 0xc6, 0x4d, 0x89, 0x7b, 0xdd, 0xc5, 0xfb, 0xc2,
          0xf6, 0x70, 0xf7, 0xa8, 0xba, 0x0b, 0x38, 0x67, 0x79, 0x10, 0x6c,
          0xf1, 0x22, 0x3c, 0x6f, 0xc5, 0xd7, 0xcd, 0x6f, 0xc1, 0x15};
      const uint8_t kExpectedOutput[32] = {
          0xa6, 0x08, 0x69, 0xf0, 0xdb, 0xcf, 0x1d, 0xc6, 0x59, 0xc9, 0xce,
          0xcb, 0xaf, 0x80, 0x50, 0x13, 0x5e, 0xa9, 0xe8, 0xcd, 0xc4, 0x87,
          0x05, 0x3f, 0x1d, 0xc6, 0x88, 0x09, 0x49, 0xdc, 0x68, 0x4c};
      static const char kExpectedAddress[] =
          "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
      uint8_t bip39_seed[kSeedSize] = {};
      HdPrivateNode b86_master = {};
      HdPrivateNode b86_child = {};
      const uint32_t b86_path[5] = {86U | kHardenedOffset, kHardenedOffset,
                                    kHardenedOffset, 0, 0};
      uint8_t b86_public[kCompressedPublicKeySize] = {};
      uint8_t b86_internal[32] = {};
      uint8_t b86_output[32] = {};
      char b86_address[kAddressTextSize] = {};
      passed = passed &&
               bip39_seed_from_english(kMnemonic, "", bip39_seed) == WalletError::Ok &&
               hd_private_from_seed(bip39_seed, sizeof(bip39_seed), &b86_master) == WalletError::Ok &&
               derive_array_path(b86_master, b86_path, 5, &b86_child) == WalletError::Ok &&
               public_key_from_private(b86_child.private_key, b86_public) == WalletError::Ok &&
               crypto_constant_time_equal(b86_public + 1, kExpectedInternal, 32) &&
               taproot_bip86_output_key(b86_public + 1, b86_output) == WalletError::Ok &&
               crypto_constant_time_equal(b86_output, kExpectedOutput, 32) &&
               address_p2tr_from_output_key(kBitcoinMainnet, b86_output, b86_address,
                                            sizeof(b86_address)) == WalletError::Ok &&
               strcmp(b86_address, kExpectedAddress) == 0;
      secure_zero(bip39_seed, sizeof(bip39_seed));
      secure_zero(&b86_master, sizeof(b86_master));
      secure_zero(&b86_child, sizeof(b86_child));
      secure_zero(b86_public, sizeof(b86_public));
      secure_zero(b86_output, sizeof(b86_output));
      secure_zero(b86_address, sizeof(b86_address));
    }

    // BIP86 single-key spend, end to end: a PSBTv2 that spends the taproot
    // output above (P2TR, m/86'/0'/0'/0/0), reviewed and signed by the same
    // code the device runs. The witness is checked to be exactly one 64-byte
    // Schnorr signature - SIGHASH_DEFAULT appends no sighash byte - and that
    // signature has to verify against the output key over the digest this file
    // recomputes.
    {
      static const char kMnemonic[] =
          "abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon about";
      uint8_t bip39_seed[kSeedSize] = {};
      HdPrivateNode tap_master = {};
      HdPrivateNode tap_child = {};
      const uint32_t tap_path[5] = {86U | kHardenedOffset, kHardenedOffset,
                                    kHardenedOffset, 0, 0};
      uint8_t tap_public[kCompressedPublicKeySize] = {};
      uint8_t tap_internal[32] = {};
      uint8_t tap_output[32] = {};
      uint8_t tap_script[34] = {0x51, 0x20};
      uint8_t tap_fingerprint[4] = {};
      if (bip39_seed_from_english(kMnemonic, "", bip39_seed) == WalletError::Ok &&
          hd_private_from_seed(bip39_seed, sizeof(bip39_seed), &tap_master) == WalletError::Ok &&
          derive_array_path(tap_master, tap_path, 5, &tap_child) == WalletError::Ok &&
          public_key_from_private(tap_child.private_key, tap_public) == WalletError::Ok &&
          master_fingerprint(tap_master, tap_fingerprint) &&
          taproot_bip86_output_key(tap_public + 1, tap_output) == WalletError::Ok)
      {
        memcpy(tap_script + 2, tap_output, 32);
        uint8_t psbt_tap[512];
        Writer tap_writer = {psbt_tap, sizeof(psbt_tap), 0};
        const uint8_t key_tx_version = kPsbtGlobalTxVersion;
        const uint8_t key_fallback_locktime = kPsbtGlobalFallbackLocktime;
        const uint8_t key_input_count = kPsbtGlobalInputCount;
        const uint8_t key_output_count = kPsbtGlobalOutputCount;
        const uint8_t key_psbt_version = kPsbtGlobalVersion;
        const uint8_t key_previous_txid = kPsbtInPreviousTxid;
        const uint8_t key_output_index = kPsbtInOutputIndex;
        const uint8_t key_witness_utxo = kPsbtInWitnessUtxo;
        const uint8_t key_tap_derivation = kPsbtInTapBip32Derivation;
        const uint8_t key_tap_internal = kPsbtInTapInternalKey;
        const uint8_t key_out_amount = kPsbtOutAmount;
        const uint8_t key_out_script = kPsbtOutScript;
        const uint8_t leaf_count = 0;
        uint8_t tap_prev_txid[32] = {};
        bool tap_built = write_bytes(&tap_writer, kPsbtMagic, sizeof(kPsbtMagic));
        tap_built = tap_built && write_compact_size(&tap_writer, 1) &&
                    write_bytes(&tap_writer, &key_tx_version, 1) &&
                    write_compact_size(&tap_writer, 4) && write_u32(&tap_writer, 2);
        tap_built = tap_built && write_compact_size(&tap_writer, 1) &&
                    write_bytes(&tap_writer, &key_fallback_locktime, 1) &&
                    write_compact_size(&tap_writer, 4) && write_u32(&tap_writer, 0);
        tap_built = tap_built && write_compact_size(&tap_writer, 1) &&
                    write_bytes(&tap_writer, &key_input_count, 1) &&
                    write_compact_size(&tap_writer, 1) && write_compact_size(&tap_writer, 1);
        tap_built = tap_built && write_compact_size(&tap_writer, 1) &&
                    write_bytes(&tap_writer, &key_output_count, 1) &&
                    write_compact_size(&tap_writer, 1) && write_compact_size(&tap_writer, 1);
        tap_built = tap_built && write_compact_size(&tap_writer, 1) &&
                    write_bytes(&tap_writer, &key_psbt_version, 1) &&
                    write_compact_size(&tap_writer, 4) && write_u32(&tap_writer, 2);
        tap_built = tap_built && write_compact_size(&tap_writer, 0);
        // Input map: outpoint, witness utxo (value + 5120||Q), BIP371 tap
        // derivation (0x16 || internal key) and the internal key itself.
        tap_built = tap_built && write_compact_size(&tap_writer, 1) &&
                    write_bytes(&tap_writer, &key_previous_txid, 1) &&
                    write_compact_size(&tap_writer, 32) &&
                    write_bytes(&tap_writer, tap_prev_txid, sizeof(tap_prev_txid));
        tap_built = tap_built && write_compact_size(&tap_writer, 1) &&
                    write_bytes(&tap_writer, &key_output_index, 1) &&
                    write_compact_size(&tap_writer, 4) && write_u32(&tap_writer, 0);
        tap_built = tap_built && write_compact_size(&tap_writer, 1) &&
                    write_bytes(&tap_writer, &key_witness_utxo, 1) &&
                    write_compact_size(&tap_writer, 8 + 1 + sizeof(tap_script)) &&
                    write_u64(&tap_writer, 100000) &&
                    write_compact_size(&tap_writer, sizeof(tap_script)) &&
                    write_bytes(&tap_writer, tap_script, sizeof(tap_script));
        tap_built = tap_built && write_compact_size(&tap_writer, 33) &&
                    write_bytes(&tap_writer, &key_tap_derivation, 1) &&
                    write_bytes(&tap_writer, tap_public + 1, 32) &&
                    write_compact_size(&tap_writer, 1 + 4 + 5 * 4) &&
                    write_bytes(&tap_writer, &leaf_count, 1) &&
                    write_bytes(&tap_writer, tap_fingerprint, 4);
        for (size_t index = 0; tap_built && index < 5; ++index)
          tap_built = write_u32(&tap_writer, tap_path[index]);
        tap_built = tap_built && write_compact_size(&tap_writer, 1) &&
                    write_bytes(&tap_writer, &key_tap_internal, 1) &&
                    write_compact_size(&tap_writer, 32) &&
                    write_bytes(&tap_writer, tap_public + 1, 32);
        tap_built = tap_built && write_compact_size(&tap_writer, 0);
        // Output: a second P2TR address (the same key, different path would be
        // more realistic, but the digest only needs a real script).
        tap_built = tap_built && write_compact_size(&tap_writer, 1) &&
                    write_bytes(&tap_writer, &key_out_amount, 1) &&
                    write_compact_size(&tap_writer, 8) && write_u64(&tap_writer, 90000);
        tap_built = tap_built && write_compact_size(&tap_writer, 1) &&
                    write_bytes(&tap_writer, &key_out_script, 1) &&
                    write_compact_size(&tap_writer, sizeof(tap_script)) &&
                    write_bytes(&tap_writer, tap_script, sizeof(tap_script));
        tap_built = tap_built && write_compact_size(&tap_writer, 0);

        BitcoinSigningRequest tap_request;
        uint8_t tap_tx[256];
        size_t tap_tx_size = sizeof(tap_tx);
        const TransactionError tap_parse =
            tap_built ? bitcoin_parse_psbt(psbt_tap, tap_writer.position, tap_master,
                                           {"btc86", nullptr, kBitcoinMainnet,
                                            SighashFamily::Bitcoin, 0},
                                           &tap_request)
                      : TransactionError::InvalidArgument;
        passed = passed && tap_built && tap_parse == TransactionError::Ok &&
                 tap_request.input_count == 1 &&
                 tap_request.inputs[0].spend_type == BitcoinSpendType::TaprootBip86 &&
                 tap_request.inputs[0].taproot_sighash == 0 &&
                 crypto_constant_time_equal(tap_request.inputs[0].taproot_output_key,
                                            tap_output, 32);
        if (passed) g_bitcoin_stage = 96;
        passed = passed && bitcoin_sign_request(tap_request, tap_master, tap_tx,
                                                &tap_tx_size) == TransactionError::Ok;
        if (passed) g_bitcoin_stage = 97;
        // marker+flag, 1 input, 1 output, then one witness item of 64 bytes.
        // Witness = 1 item marker + 64-byte signature; nLockTime follows it.
        passed = passed && tap_tx_size > 74 && tap_tx[4] == 0 && tap_tx[5] == 1 &&
                 tap_tx[tap_tx_size - 70] == 1 && tap_tx[tap_tx_size - 69] == 64;
        if (passed) g_bitcoin_stage = 98;
        uint8_t expected_sighash[kSha256Size];
        uint8_t parsed_signature[64];
        memcpy(parsed_signature, tap_tx + tap_tx_size - 68, 64);
        passed = passed &&
                 bitcoin_sighash_taproot(tap_request, 0, 0, nullptr, 0,
                                         expected_sighash) == TransactionError::Ok &&
                 ecdsa_bip340_verify(EcdsaCurve::Secp256k1, tap_output,
                                     expected_sighash, parsed_signature);
        secure_zero(expected_sighash, sizeof(expected_sighash));
        secure_zero(parsed_signature, sizeof(parsed_signature));
        clear_bitcoin_request(&tap_request);
      }
      else
      {
        passed = false;
      }
      if (passed) g_bitcoin_stage = 99;
      secure_zero(bip39_seed, sizeof(bip39_seed));
      secure_zero(&tap_master, sizeof(tap_master));
      secure_zero(&tap_child, sizeof(tap_child));
      secure_zero(tap_public, sizeof(tap_public));
      secure_zero(tap_output, sizeof(tap_output));
    }

    // Adversarial cases for the BIP371/taproot rules. Each one asserts that a
    // specific field is refused, so the rule cannot quietly rot into "accepted
    // but ignored". The maps are fed straight to the parsers as byte buffers.
    {
      const BitcoinChainParams tap_chain = {"btc86", nullptr, kBitcoinMainnet,
                                            SighashFamily::Bitcoin, 0};
      HdPrivateNode hd = {};
      BitcoinOutput out = {};
      BitcoinInput in = {};
      PsbtInputLocktime lock = {};
      uint8_t map[160];

      // Output map with a script but no amount: the required-field check must
      // run at end-of-map, not be skipped by the terminator.
      map[0] = 1; map[1] = kPsbtOutScript; map[2] = 34; map[3] = 0x51; map[4] = 0x20;
      memset(map + 5, 0x11, 32);
      map[37] = 0;
      if (passed) g_bitcoin_stage = 41;
      Cursor no_amount = {map, 38, 0};
      passed = passed &&
               parse_output_map_v2(&no_amount, hd, tap_chain, &out) ==
                   TransactionError::MissingField;
      // Output map with neither field.
      map[0] = 0; map[1] = 0;
      Cursor empty_output = {map, 2, 0};
      passed = passed && parse_output_map_v2(&empty_output, hd, tap_chain, &out) ==
                             TransactionError::MissingField;

      // A taproot input that declares a script tree (leaf count 1) is not a
      // BIP86 key and must be refused before any key work.
      map[0] = 33; map[1] = kPsbtInTapBip32Derivation;
      memset(map + 2, 0x22, 32);
      map[34] = 5;        // value length: leaf count + 4-byte fingerprint
      map[35] = 1;        // leaf count = 1, i.e. a script tree, not BIP86
      map[36] = 0; map[37] = 0; map[38] = 0; map[39] = 0;  // fingerprint
      map[40] = 0;
      if (passed) g_bitcoin_stage = 42;
      Cursor tree = {map, 41, 0};
      passed = passed && parse_input_map_v2(&tree, hd, tap_chain, &in, &lock) ==
                             TransactionError::Unsupported;

      // A host-supplied taproot signature is refused outright.
      map[0] = 1; map[1] = kPsbtInTapKeySig; map[2] = 64;
      memset(map + 3, 0x33, 64);
      map[67] = 0;
      if (passed) g_bitcoin_stage = 43;
      Cursor host_sig = {map, 68, 0};
      passed = passed && parse_input_map_v2(&host_sig, hd, tap_chain, &in, &lock) ==
                             TransactionError::Unsupported;

      // A merkle root says the output key is not the BIP86 tweak.
      map[0] = 1; map[1] = kPsbtInTapMerkleRoot; map[2] = 32;
      memset(map + 3, 0x44, 32);
      map[35] = 0;
      if (passed) g_bitcoin_stage = 44;
      Cursor merkle = {map, 36, 0};
      passed = passed && parse_input_map_v2(&merkle, hd, tap_chain, &in, &lock) ==
                             TransactionError::Unsupported;

      // A taproot-only field on a non-taproot input means the constructor and
      // the UTXO disagree; apply_taproot_fields is the gate for that.
      if (passed) g_bitcoin_stage = 45;
      in.spend_type = BitcoinSpendType::NativeP2wpkh;
      const uint8_t some_key[32] = {0x55};
      passed = passed && apply_taproot_fields(&in, true, some_key, false, 0) ==
                             TransactionError::Unsupported;
      passed = passed && apply_taproot_fields(&in, false, nullptr, false, 0) ==
                             TransactionError::Ok;
      // A taproot input with an out-of-policy hash type.
      in.spend_type = BitcoinSpendType::TaprootBip86;
      passed = passed && apply_taproot_fields(&in, false, nullptr, true, 2) ==
                             TransactionError::Unsupported &&
               apply_taproot_fields(&in, false, nullptr, true, 1) ==
                             TransactionError::Ok &&
               in.taproot_sighash == 1 &&
               apply_taproot_fields(&in, false, nullptr, false, 0) ==
                             TransactionError::Ok &&
               in.taproot_sighash == 0;
      // An internal key that is not the one the path derives.
      uint8_t derived_internal[32] = {0};
      in.spend_type = BitcoinSpendType::TaprootBip86;
      memset(in.public_key, 0x02, sizeof(in.public_key));
      memset(derived_internal, 0x77, sizeof(derived_internal));
      memcpy(in.public_key + 1, derived_internal, 32);
      passed = passed && apply_taproot_fields(&in, true, some_key, false, 0) ==
                             TransactionError::WrongWallet &&
               apply_taproot_fields(&in, true, derived_internal, false, 0) ==
                             TransactionError::Ok;

      // SIGHASH_SINGLE with no matching output must fail rather than hash a
      // non-existent output (BIP341 inherited Bitcoin's special case, and
      // silently applying it here would sign something the review never saw).
      BitcoinSigningRequest single = {};
      single.version = 2;
      single.input_count = 2;
      single.output_count = 1;
      single.chain = tap_chain;
      single.inputs[1].spend_type = BitcoinSpendType::TaprootBip86;
      uint8_t tap_out[kSha256Size];
      passed = passed && bitcoin_sighash_taproot(single, 1, 3, nullptr, 0, tap_out) ==
                             TransactionError::InvalidArgument &&
               bitcoin_sighash_taproot(single, 0, 3, nullptr, 0, tap_out) ==
                             TransactionError::Ok;
      // An annex must carry the 0x50 tag byte.
      if (passed) g_bitcoin_stage = 46;
      const uint8_t bad_annex[4] = {0x51, 0x01, 0x02, 0x03};
      const uint8_t good_annex[4] = {0x50, 0x01, 0x02, 0x03};
      passed = passed && bitcoin_sighash_taproot(single, 0, 0, bad_annex, sizeof(bad_annex),
                                                tap_out) ==
                             TransactionError::InvalidArgument &&
               bitcoin_sighash_taproot(single, 0, 0, good_annex, sizeof(good_annex),
                                       tap_out) == TransactionError::Ok;
      // Hash types above 0x83 have no meaning and must not be hashed.
      if (passed) g_bitcoin_stage = 47;
      passed = passed && bitcoin_sighash_taproot(single, 0, 4, nullptr, 0, tap_out) ==
                             TransactionError::InvalidArgument &&
               // 0x83 = ANYONECANPAY | SIGHASH_SINGLE, a real combination.
               bitcoin_sighash_taproot(single, 0, 0x83, nullptr, 0, tap_out) ==
                             TransactionError::Ok &&
               bitcoin_sighash_taproot(single, 0, 0x84, nullptr, 0, tap_out) ==
                             TransactionError::InvalidArgument;
      secure_zero(tap_out, sizeof(tap_out));
      clear_bitcoin_request(&single);
    }

    // BIP143's own P2SH-P2WSH vector: a 6-of-6 CHECKMULTISIG witness program
    // signed with all six hash types. The witnessScript, the redeemScript, the
    // scriptPubKey and the six digests below are copied from the BIP; this is the
    // check that says the scriptCode path for witness v0 multisig is right.
    {
      const uint8_t kVecWitnessScript[207] = {0x56, 0x21, 0x03, 0x07, 0xb8, 0xae, 0x49, 0xac, 0x90, 0xa0, 0x48, 0xe9, 0xb5, 0x33, 0x57, 0xa2, 0x35, 0x4b, 0x33, 0x34, 0xe9, 0xc8, 0xbe, 0xe8, 0x13, 0xec, 0xb9, 0x8e, 0x99, 0xa7, 0xe0, 0x7e, 0x8c, 0x3b, 0xa3, 0x21, 0x03, 0xb2, 0x8f, 0x0c, 0x28, 0xbf, 0xab, 0x54, 0x55, 0x4a, 0xe8, 0xc6, 0x58, 0xac, 0x5c, 0x3e, 0x0c, 0xe6, 0xe7, 0x9a, 0xd3, 0x36, 0x33, 0x1f, 0x78, 0xc4, 0x28, 0xdd, 0x43, 0xee, 0xa8, 0x44, 0x9b, 0x21, 0x03, 0x4b, 0x81, 0x13, 0xd7, 0x03, 0x41, 0x3d, 0x57, 0x76, 0x1b, 0x8b, 0x97, 0x81, 0x95, 0x7b, 0x8c, 0x0a, 0xc1, 0xdf, 0xe6, 0x9f, 0x49, 0x25, 0x80, 0xca, 0x41, 0x95, 0xf5, 0x03, 0x76, 0xba, 0x4a, 0x21, 0x03, 0x34, 0x00, 0xf6, 0xaf, 0xec, 0xb8, 0x33, 0x09, 0x2a, 0x9a, 0x21, 0xcf, 0xdf, 0x1e, 0xd1, 0x37, 0x6e, 0x58, 0xc5, 0xd1, 0xf4, 0x7d, 0xe7, 0x46, 0x83, 0x12, 0x39, 0x87, 0xe9, 0x67, 0xa8, 0xf4, 0x21, 0x03, 0xa6, 0xd4, 0x8b, 0x11, 0x31, 0xe9, 0x4b, 0xa0, 0x4d, 0x97, 0x37, 0xd6, 0x1a, 0xcd, 0xaa, 0x13, 0x22, 0x00, 0x8a, 0xf9, 0x60, 0x2b, 0x3b, 0x14, 0x86, 0x2c, 0x07, 0xa1, 0x78, 0x9a, 0xac, 0x16, 0x21, 0x02, 0xd8, 0xb6, 0x61, 0xb0, 0xb3, 0x30, 0x2e, 0xe2, 0xf1, 0x62, 0xb0, 0x9e, 0x07, 0xa5, 0x5a, 0xd5, 0xdf, 0xbe, 0x67, 0x3a, 0x9f, 0x01, 0xd9, 0xf0, 0xc1, 0x96, 0x17, 0x68, 0x10, 0x24, 0x30, 0x6b, 0x56, 0xae};
      const uint8_t kVecRedeem[34] = {0x00, 0x20, 0xa1, 0x6b, 0x57, 0x55, 0xf7, 0xf6, 0xf9, 0x6d, 0xbd, 0x65, 0xf5, 0xf0, 0xd6, 0xab, 0x94, 0x18, 0xb8, 0x9a, 0xf4, 0xb1, 0xf1, 0x4a, 0x1b, 0xb8, 0xa0, 0x90, 0x62, 0xc3, 0x5f, 0x0d, 0xcb, 0x54};
      const uint8_t kVecP2shHash[20] = {0x99, 0x93, 0xa4, 0x29, 0x03, 0x7b, 0x5d, 0x91, 0x24, 0x07, 0xa7, 0x1c, 0x25, 0x20, 0x19, 0x28, 0x7b, 0x8d, 0x27, 0xa5};
      const uint8_t kVecPrevTxid[32] = {0x36, 0x64, 0x18, 0x69, 0xca, 0x08, 0x1e, 0x70, 0xf3, 0x94, 0xc6, 0x94, 0x8e, 0x8a, 0xf4, 0x09, 0xe1, 0x8b, 0x61, 0x9d, 0xf2, 0xed, 0x74, 0xaa, 0x10, 0x6c, 0x1c, 0xa2, 0x97, 0x87, 0xb9, 0x6e};
      const uint8_t kVecOut0[25] = {0x76, 0xa9, 0x14, 0x38, 0x9f, 0xfc, 0xe9, 0xcd, 0x9a, 0xe8, 0x8d, 0xcc, 0x06, 0x31, 0xe8, 0x8a, 0x82, 0x1f, 0xfd, 0xbe, 0x9b, 0xfe, 0x26, 0x88, 0xac};
      const uint8_t kVecOut1[25] = {0x76, 0xa9, 0x14, 0x74, 0x80, 0xa3, 0x3f, 0x95, 0x06, 0x89, 0xaf, 0x51, 0x1e, 0x6e, 0x84, 0xc1, 0x38, 0xdb, 0xbd, 0x3c, 0x3e, 0xe4, 0x15, 0x88, 0xac};
      BitcoinSigningRequest vec = {};
      vec.version = 1;
      vec.lock_time = 0;
      vec.chain = {"btc", nullptr, kBitcoinMainnet, SighashFamily::Bitcoin, 0};
      vec.input_count = 1;
      vec.output_count = 2;
      memcpy(vec.inputs[0].previous_txid, kVecPrevTxid, 32);
      vec.inputs[0].previous_index = 1;
      vec.inputs[0].sequence = 0xffffffffu;
      vec.inputs[0].value = 987654321ULL;
      vec.outputs[0].value = 900000000ULL;
      vec.outputs[1].value = 87000000ULL;
      vec.outputs[0].script_size = sizeof(kVecOut0);
      vec.outputs[1].script_size = sizeof(kVecOut1);
      memcpy(vec.outputs[0].script, kVecOut0, sizeof(kVecOut0));
      memcpy(vec.outputs[1].script, kVecOut1, sizeof(kVecOut1));
      // The script itself has to rebuild byte for byte from its 6 keys, and its
      // hash has to be the published witness program; otherwise the digest below
      // would be over a script nobody actually funded.
      if (passed) g_bitcoin_stage = 51;
      uint8_t rebuilt[kBitcoinMaxWitnessScriptSize];
      size_t rebuilt_size = 0;
      uint8_t program[kSha256Size];
      uint8_t redeem[34];
      uint8_t p2sh_hash[kRipemd160Size];
      uint8_t parsed_threshold = 0;
      uint8_t parsed_keys_count = 0;
      uint8_t parsed_keys[kBitcoinMaxMultisigKeys * kCompressedPublicKeySize];
      passed = passed && bitcoin_parse_multisig_script(kVecWitnessScript, sizeof(kVecWitnessScript),
                                                      &parsed_threshold, &parsed_keys_count,
                                                      parsed_keys, sizeof(parsed_keys)) &&
               parsed_threshold == 6 && parsed_keys_count == 6 &&
               bitcoin_multisig_script(parsed_keys, parsed_keys_count, parsed_threshold,
                                       rebuilt, sizeof(rebuilt), &rebuilt_size) &&
               rebuilt_size == sizeof(kVecWitnessScript) &&
               crypto_constant_time_equal(rebuilt, kVecWitnessScript, sizeof(kVecWitnessScript)) &&
               bitcoin_p2wsh_program(kVecWitnessScript, sizeof(kVecWitnessScript), program) &&
               crypto_constant_time_equal(program, kVecRedeem + 2, 32) &&
               bitcoin_p2sh_p2wsh_redeem(kVecWitnessScript, sizeof(kVecWitnessScript), redeem) &&
               crypto_constant_time_equal(redeem, kVecRedeem, 34) &&
               crypto_hash160(redeem, sizeof(redeem), p2sh_hash) &&
               crypto_constant_time_equal(p2sh_hash, kVecP2shHash, sizeof(p2sh_hash));
      secure_zero(rebuilt, sizeof(rebuilt));
      secure_zero(parsed_keys, sizeof(parsed_keys));
      const uint8_t kVecHash01[32] = {0x18, 0x5c, 0x0b, 0xe5, 0x26, 0x3d, 0xce, 0x5b, 0x4b, 0xb5, 0x0a, 0x04, 0x79, 0x73, 0xc1, 0xb6, 0x27, 0x2b, 0xfb, 0xd0, 0x10, 0x3a, 0x89, 0x44, 0x45, 0x97, 0xdc, 0x40, 0xb2, 0x48, 0xee, 0x7c};
      const uint8_t kVecHash02[32] = {0xe9, 0x73, 0x3b, 0xc6, 0x0e, 0xa1, 0x3c, 0x95, 0xc6, 0x52, 0x70, 0x66, 0xbb, 0x97, 0x5a, 0x2f, 0xf2, 0x9a, 0x92, 0x5e, 0x80, 0xaa, 0x14, 0xc2, 0x13, 0xf6, 0x86, 0xcb, 0xae, 0x5d, 0x2f, 0x36};
      const uint8_t kVecHash03[32] = {0x1e, 0x1f, 0x1c, 0x30, 0x3d, 0xc0, 0x25, 0xbd, 0x66, 0x4a, 0xcb, 0x72, 0xe5, 0x83, 0xe9, 0x33, 0xfa, 0xe4, 0xcf, 0xf9, 0x14, 0x8b, 0xf7, 0x8c, 0x15, 0x7d, 0x1e, 0x8f, 0x78, 0x53, 0x0a, 0xea};
      const uint8_t kVecHash81[32] = {0x2a, 0x67, 0xf0, 0x3e, 0x63, 0xa6, 0xa4, 0x22, 0x12, 0x58, 0x78, 0xb4, 0x0b, 0x82, 0xda, 0x59, 0x3b, 0xe8, 0xd4, 0xef, 0xaa, 0xfe, 0x88, 0xee, 0x52, 0x8a, 0xf6, 0xe5, 0xa9, 0x95, 0x5c, 0x6e};
      const uint8_t kVecHash82[32] = {0x78, 0x1b, 0xa1, 0x5f, 0x37, 0x79, 0xd5, 0x54, 0x2c, 0xe8, 0xec, 0xb5, 0xc1, 0x87, 0x16, 0x73, 0x3a, 0x5e, 0xe4, 0x2a, 0x6f, 0x51, 0x48, 0x8e, 0xc9, 0x61, 0x54, 0x93, 0x4e, 0x2c, 0x89, 0x0a};
      const uint8_t kVecHash83[32] = {0x51, 0x1e, 0x8e, 0x52, 0xed, 0x57, 0x41, 0x21, 0xfc, 0x1b, 0x65, 0x49, 0x70, 0x39, 0x55, 0x02, 0x12, 0x82, 0x63, 0xf6, 0x26, 0x62, 0xe0, 0x76, 0xdc, 0x6b, 0xaf, 0x05, 0xc2, 0xe6, 0xa9, 0x9b};
      struct TapVec { uint32_t hash_type; const uint8_t *expected; };
      const TapVec cases[6] = {{0x01, kVecHash01},{0x02, kVecHash02},{0x03, kVecHash03},{0x81, kVecHash81},{0x82, kVecHash82},{0x83, kVecHash83}};
      if (passed) g_bitcoin_stage = 52;
      for (const TapVec &c : cases)
      {
        uint8_t digest[kSha256Size];
        passed = passed && bitcoin_sighash_witness_v0(vec, 0, c.hash_type,
                                                     kVecWitnessScript,
                                                     sizeof(kVecWitnessScript),
                                                     digest) == TransactionError::Ok &&
                 crypto_constant_time_equal(digest, c.expected, kSha256Size);
        secure_zero(digest, sizeof(digest));
      }
      // SINGLE with no matching output must fail rather than hash a phantom one.
      if (passed) g_bitcoin_stage = 53;
      uint8_t unused_digest[kSha256Size];
      BitcoinSigningRequest single = vec;
      single.input_count = 2;
      single.output_count = 1; // input 1 now has no matching output for SINGLE
      passed = passed && bitcoin_sighash_witness_v0(single, 1, 3, kVecWitnessScript,
                                                    sizeof(kVecWitnessScript),
                                                    unused_digest) ==
                             TransactionError::InvalidArgument &&
               bitcoin_sighash_witness_v0(vec, 0, 2, nullptr, 0, unused_digest) ==
                             TransactionError::InvalidArgument;
      // A non-canonical multisig script must not parse: OP_1 pushed as data is a
      // different encoding of the same number and would hide a script the device
      // cannot reproduce.
      if (passed) g_bitcoin_stage = 54;
      uint8_t noncanonical[4] = {0x01, 0x01, 0x51, 0xae};
      passed = passed && !bitcoin_parse_multisig_script(noncanonical, sizeof(noncanonical),
                                                        &parsed_threshold, &parsed_keys_count,
                                                        parsed_keys, sizeof(parsed_keys));
      secure_zero(unused_digest, sizeof(unused_digest));
      clear_bitcoin_request(&single);
      clear_bitcoin_request(&vec);
      secure_zero(program, sizeof(program));
      secure_zero(redeem, sizeof(redeem));
      secure_zero(p2sh_hash, sizeof(p2sh_hash));
    }


    // PSBT in, PSBT out: the partial-signature path. Three things are pinned
    // here - the entry we add, the entry another signer already added (which must
    // survive byte for byte), and the fact that a second identical call changes
    // nothing while a different value under the same key is refused.
    {
      static const char kMnemonic[] =
          "abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon about";
      const BitcoinChainParams psbt_chain = {"btc", nullptr, kBitcoinMainnet,
                                             SighashFamily::Bitcoin, 0};
      const uint32_t psbt_path[5] = {84U | kHardenedOffset, kHardenedOffset,
                                     kHardenedOffset, 0, 0};
      uint8_t seed[kSeedSize] = {};
      HdPrivateNode psbt_master = {};
      HdPrivateNode psbt_child = {};
      uint8_t psbt_public[kCompressedPublicKeySize] = {};
      uint8_t key_hash[kRipemd160Size] = {};
      uint8_t script[22] = {0x00, 0x14};
      uint8_t fingerprint[4] = {};
      if (passed && bip39_seed_from_english(kMnemonic, "", seed) == WalletError::Ok &&
          hd_private_from_seed(seed, sizeof(seed), &psbt_master) == WalletError::Ok &&
          derive_array_path(psbt_master, psbt_path, 5, &psbt_child) == WalletError::Ok &&
          public_key_from_private(psbt_child.private_key, psbt_public) == WalletError::Ok &&
          crypto_hash160(psbt_public, sizeof(psbt_public), key_hash) &&
          master_fingerprint(psbt_master, fingerprint))
      {
        memcpy(script + 2, key_hash, sizeof(key_hash));
        uint8_t raw[512];
        Writer w = {raw, sizeof(raw), 0};
        const uint8_t zero32[32] = {};
        // A foreign signer's entry: same shape, a key this device does not hold.
        uint8_t foreign_key[34] = {kPsbtInPartialSig, 0x02};
        memset(foreign_key + 2, 0xEE, 32);
        uint8_t foreign_value[71];
        memset(foreign_value, 0xAA, sizeof(foreign_value));
        foreign_value[0] = 0x30; // plausible DER opening, never verified here
        bool built = write_bytes(&w, kPsbtMagic, sizeof(kPsbtMagic));
        const uint8_t k_tx_version = kPsbtGlobalTxVersion;
        const uint8_t k_fallback = kPsbtGlobalFallbackLocktime;
        const uint8_t k_in_count = kPsbtGlobalInputCount;
        const uint8_t k_out_count = kPsbtGlobalOutputCount;
        const uint8_t k_version = kPsbtGlobalVersion;
        const uint8_t k_prev_txid = kPsbtInPreviousTxid;
        const uint8_t k_out_index = kPsbtInOutputIndex;
        const uint8_t k_sequence = kPsbtInSequence;
        const uint8_t k_witness_utxo = kPsbtInWitnessUtxo;
        const uint8_t k_derivation = kPsbtInBip32Derivation;
        const uint8_t k_amount = kPsbtOutAmount;
        const uint8_t k_script = kPsbtOutScript;
        built = built && write_compact_size(&w, 1) && write_bytes(&w, &k_tx_version, 1) &&
                write_compact_size(&w, 4) && write_u32(&w, 2);
        built = built && write_compact_size(&w, 1) && write_bytes(&w, &k_fallback, 1) &&
                write_compact_size(&w, 4) && write_u32(&w, 0);
        built = built && write_compact_size(&w, 1) && write_bytes(&w, &k_in_count, 1) &&
                write_compact_size(&w, 1) && write_compact_size(&w, 1);
        built = built && write_compact_size(&w, 1) && write_bytes(&w, &k_out_count, 1) &&
                write_compact_size(&w, 1) && write_compact_size(&w, 1);
        built = built && write_compact_size(&w, 1) && write_bytes(&w, &k_version, 1) &&
                write_compact_size(&w, 4) && write_u32(&w, 2);
        built = built && write_compact_size(&w, 0);
        built = built && write_compact_size(&w, 1) && write_bytes(&w, &k_prev_txid, 1) &&
                write_compact_size(&w, 32) && write_bytes(&w, zero32, 32);
        built = built && write_compact_size(&w, 1) && write_bytes(&w, &k_out_index, 1) &&
                write_compact_size(&w, 4) && write_u32(&w, 0);
        built = built && write_compact_size(&w, 1) && write_bytes(&w, &k_sequence, 1) &&
                write_compact_size(&w, 4) && write_u32(&w, 0xfffffffd);
        built = built && write_compact_size(&w, 1) && write_bytes(&w, &k_witness_utxo, 1) &&
                write_compact_size(&w, 8 + 1 + sizeof(script)) && write_u64(&w, 100000) &&
                write_compact_size(&w, sizeof(script)) && write_bytes(&w, script, sizeof(script));
        built = built && write_compact_size(&w, 34) && write_bytes(&w, &k_derivation, 1) &&
                write_bytes(&w, psbt_public, sizeof(psbt_public)) &&
                write_compact_size(&w, 24) && write_bytes(&w, fingerprint, 4);
        for (size_t i = 0; built && i < 5; ++i) built = write_u32(&w, psbt_path[i]);
        built = built && write_compact_size(&w, 34) &&
                write_bytes(&w, foreign_key, sizeof(foreign_key)) &&
                write_compact_size(&w, sizeof(foreign_value)) &&
                write_bytes(&w, foreign_value, sizeof(foreign_value));
        built = built && write_compact_size(&w, 0);
        built = built && write_compact_size(&w, 1) && write_bytes(&w, &k_amount, 1) &&
                write_compact_size(&w, 8) && write_u64(&w, 90000);
        built = built && write_compact_size(&w, 1) && write_bytes(&w, &k_script, 1) &&
                write_compact_size(&w, sizeof(script)) && write_bytes(&w, script, sizeof(script));
        built = built && write_compact_size(&w, 0);

        if (!built) g_bitcoin_stage = 65;
        if (built) g_bitcoin_stage = 66;
        uint8_t signed_psbt[768];
        size_t signed_size = 0;
        BitcoinPsbtSignSummary summary = {};
        const TransactionError sign_psbt_result =
            built ? bitcoin_sign_psbt(raw, w.position, psbt_master, psbt_chain, signed_psbt,
                                      sizeof(signed_psbt), &signed_size, &summary)
                  : TransactionError::InvalidArgument;
        if (sign_psbt_result != TransactionError::Ok)
          g_bitcoin_stage = 400 + static_cast<int>(sign_psbt_result);
        passed = passed && built && sign_psbt_result == TransactionError::Ok &&
                 summary.total_inputs == 1 && summary.signed_inputs == 1 &&
                 summary.unchanged_inputs == 0 && signed_size > w.position;
        if (passed) g_bitcoin_stage = 61;
        // The result must still be a PSBT this firmware accepts, and the foreign
        // signature must still be inside the input map with the same value.
        BitcoinSigningRequest roundtrip;
        passed = passed &&
                 bitcoin_parse_psbt(signed_psbt, signed_size, psbt_master, psbt_chain,
                                    &roundtrip) == TransactionError::Ok &&
                 roundtrip.fee == 10000;
        clear_bitcoin_request(&roundtrip);
        if (passed) g_bitcoin_stage = 62;
        {
          PsbtSpans spans;
          passed = passed && scan_psbt_maps(signed_psbt, signed_size, 1, 1, &spans) ==
                                 TransactionError::Ok;
          uint8_t ours[34] = {kPsbtInPartialSig};
          memcpy(ours + 1, psbt_public, sizeof(psbt_public));
          bool has_ours = false;
          bool has_foreign = false;
          const uint8_t *ours_value = nullptr;
          const uint8_t *foreign_out = nullptr;
          size_t ours_size = 0;
          size_t foreign_size = 0;
          passed = passed &&
                   find_map_entry(signed_psbt, spans.input_start[0], spans.input_end[0],
                                  ours, sizeof(ours), &has_ours, &ours_value,
                                  &ours_size) == TransactionError::Ok &&
                   // DER is 70-72 bytes depending on the integers; the sighash
                   // byte is appended after it.
                   has_ours && ours_size >= 71 && ours_size <= 73 &&
                   ours_value[ours_size - 1] == kSighashAll &&
                   find_map_entry(signed_psbt, spans.input_start[0], spans.input_end[0],
                                  foreign_key, sizeof(foreign_key), &has_foreign,
                                  &foreign_out, &foreign_size) == TransactionError::Ok &&
                   has_foreign && foreign_size == sizeof(foreign_value) &&
                   crypto_constant_time_equal(foreign_out, foreign_value,
                                              sizeof(foreign_value));
        }
        if (passed) g_bitcoin_stage = 63;
        // Idempotent: a second call adds nothing and produces the same bytes.
        {
          uint8_t again[768];
          size_t again_size = 0;
          BitcoinPsbtSignSummary again_summary = {};
          passed = passed &&
                   bitcoin_sign_psbt(signed_psbt, signed_size, psbt_master, psbt_chain,
                                     again, sizeof(again), &again_size, &again_summary) ==
                       TransactionError::Ok &&
                   again_summary.unchanged_inputs == 1 &&
                   again_summary.signed_inputs == 0 && again_size == signed_size &&
                   crypto_constant_time_equal(again, signed_psbt, signed_size);
        }
        if (passed) g_bitcoin_stage = 64;
        // Same key, different value: refused, because overwriting would discard a
        // signature this device did not produce.
        {
          uint8_t tampered[768];
          memcpy(tampered, signed_psbt, signed_size);
          PsbtSpans spans;
          bool has_ours = false;
          const uint8_t *value = nullptr;
          size_t value_size = 0;
          uint8_t ours[34] = {kPsbtInPartialSig};
          memcpy(ours + 1, psbt_public, sizeof(psbt_public));
          uint8_t discard[768];
          size_t discard_size = 0;
          BitcoinPsbtSignSummary ignored = {};
          const bool located =
              scan_psbt_maps(tampered, signed_size, 1, 1, &spans) == TransactionError::Ok &&
              find_map_entry(tampered, spans.input_start[0], spans.input_end[0], ours,
                             sizeof(ours), &has_ours, &value, &value_size) ==
                  TransactionError::Ok &&
              has_ours && value_size >= 71 && value_size <= 73;
          passed = passed && located;
          if (located)
          {
            // Flip one byte of the signature payload in place.
            uint8_t *mutable_value = tampered + (value - tampered);
            mutable_value[10] ^= 0x01;
            passed = passed &&
                     bitcoin_sign_psbt(tampered, signed_size, psbt_master, psbt_chain,
                                       discard, sizeof(discard), &discard_size,
                                       &ignored) == TransactionError::DuplicateField;
          }
        }
        secure_zero(seed, sizeof(seed));
        secure_zero(&psbt_master, sizeof(psbt_master));
        secure_zero(&psbt_child, sizeof(psbt_child));
        secure_zero(psbt_public, sizeof(psbt_public));
        secure_zero(key_hash, sizeof(key_hash));
        secure_zero(raw, sizeof(raw));
        secure_zero(foreign_value, sizeof(foreign_value));
      }
      else
      {
        passed = false;
      }
    }

    const uint8_t seed[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    const BitcoinChainParams request_chain = {"btc", nullptr, kBitcoinMainnet, SighashFamily::Bitcoin, 0};
    const uint32_t input_path[5] = {49U | kHardenedOffset, kHardenedOffset,
                                    kHardenedOffset, 0, 0};
    const uint32_t output_path[5] = {49U | kHardenedOffset, kHardenedOffset,
                                     kHardenedOffset, 1, 0};
    HdPrivateNode master;
    HdPrivateNode input_node;
    HdPrivateNode output_node;
    uint8_t input_public[kCompressedPublicKeySize];
    uint8_t output_public[kCompressedPublicKeySize];
    uint8_t input_redeem[22] = {0, 20};
    uint8_t output_redeem[22] = {0, 20};
    uint8_t input_script[23] = {0xa9, 0x14};
    uint8_t output_script[23] = {0xa9, 0x14};
    uint8_t fingerprint[4];
    passed = passed && hd_private_from_seed(seed, sizeof(seed), &master) == WalletError::Ok && derive_array_path(master, input_path, 5, &input_node) == WalletError::Ok && derive_array_path(master, output_path, 5, &output_node) == WalletError::Ok && public_key_from_private(input_node.private_key, input_public) == WalletError::Ok && public_key_from_private(output_node.private_key, output_public) == WalletError::Ok && crypto_hash160(input_public, sizeof(input_public), input_redeem + 2) && crypto_hash160(output_public, sizeof(output_public), output_redeem + 2) && crypto_hash160(input_redeem, sizeof(input_redeem), input_script + 2) && crypto_hash160(output_redeem, sizeof(output_redeem), output_script + 2) && master_fingerprint(master, fingerprint);
    input_script[22] = 0x87;
    output_script[22] = 0x87;

    uint8_t unsigned_transaction[128];
    Writer unsigned_writer = {unsigned_transaction, sizeof(unsigned_transaction), 0};
    uint8_t zero_txid[32] = {};
    bool serialized = write_u32(&unsigned_writer, 2) && write_compact_size(&unsigned_writer, 1) && write_bytes(&unsigned_writer, zero_txid, sizeof(zero_txid)) && write_u32(&unsigned_writer, 0) && write_compact_size(&unsigned_writer, 0) && write_u32(&unsigned_writer, 0xfffffffd) && write_compact_size(&unsigned_writer, 1) && write_u64(&unsigned_writer, 90000) && write_compact_size(&unsigned_writer, sizeof(output_script)) && write_bytes(&unsigned_writer, output_script, sizeof(output_script)) && write_u32(&unsigned_writer, 0);

    uint8_t psbt[384];
    Writer psbt_writer = {psbt, sizeof(psbt), 0};
    const uint8_t global_key = 0x00;
    const uint8_t witness_utxo_key = 0x01;
    const uint8_t redeem_script_key = 0x04;
    const uint8_t input_derivation_type = 0x06;
    const uint8_t output_derivation_type = 0x02;
    serialized = passed && serialized && write_bytes(&psbt_writer, kPsbtMagic, sizeof(kPsbtMagic)) && write_compact_size(&psbt_writer, 1) && write_bytes(&psbt_writer, &global_key, 1) && write_compact_size(&psbt_writer, unsigned_writer.position) && write_bytes(&psbt_writer, unsigned_transaction, unsigned_writer.position) && write_compact_size(&psbt_writer, 0) && write_compact_size(&psbt_writer, 1) && write_bytes(&psbt_writer, &witness_utxo_key, 1) && write_compact_size(&psbt_writer, 32) && write_u64(&psbt_writer, 100000) && write_compact_size(&psbt_writer, sizeof(input_script)) && write_bytes(&psbt_writer, input_script, sizeof(input_script)) && write_compact_size(&psbt_writer, 1) && write_bytes(&psbt_writer, &redeem_script_key, 1) && write_compact_size(&psbt_writer, sizeof(input_redeem)) && write_bytes(&psbt_writer, input_redeem, sizeof(input_redeem)) && write_compact_size(&psbt_writer, 34) && write_bytes(&psbt_writer, &input_derivation_type, 1) && write_bytes(&psbt_writer, input_public, sizeof(input_public)) && write_compact_size(&psbt_writer, 24) && write_bytes(&psbt_writer, fingerprint, sizeof(fingerprint));
    for (size_t index = 0; serialized && index < 5; ++index)
      serialized = write_u32(&psbt_writer, input_path[index]);
    serialized = serialized && write_compact_size(&psbt_writer, 0) && write_compact_size(&psbt_writer, 34) && write_bytes(&psbt_writer, &output_derivation_type, 1) && write_bytes(&psbt_writer, output_public, sizeof(output_public)) && write_compact_size(&psbt_writer, 24) && write_bytes(&psbt_writer, fingerprint, sizeof(fingerprint));
    for (size_t index = 0; serialized && index < 5; ++index)
      serialized = write_u32(&psbt_writer, output_path[index]);
    serialized = serialized && write_compact_size(&psbt_writer, 0);

    BitcoinSigningRequest parsed;
    uint8_t signed_transaction[384];
    size_t signed_size = sizeof(signed_transaction);
    bool v0_ok = serialized &&
                 bitcoin_parse_psbt(psbt, psbt_writer.position, master, request_chain, &parsed) == TransactionError::Ok &&
                 parsed.input_count == 1 && parsed.output_count == 1 && parsed.fee == 10000 &&
                 parsed.outputs[0].wallet_owned && parsed.outputs[0].change &&
                 bitcoin_sign_request(parsed, master, signed_transaction, &signed_size) == TransactionError::Ok &&
                 signed_size > 44 && signed_transaction[4] == 0 && signed_transaction[5] == 1 &&
                 signed_transaction[43] == 23 && signed_transaction[44] == 22;
    const uint32_t v0_vbytes = parsed.estimated_vbytes;
    if (passed)
      g_bitcoin_stage = 100;
    const size_t v0_signed_size = signed_size;
    clear_bitcoin_request(&parsed);
    passed = passed && v0_ok;

    // ---------------------------------------------------------------------
    // The same transaction as PSBT v2 (BIP370). The envelope is different and
    // every field now lives in a map, so the invariant worth pinning is that
    // the wallet reaches the same conclusion: identical parsed request and a
    // byte-identical signed transaction.
    // ---------------------------------------------------------------------
    uint8_t psbt2[512];
    Writer v2 = {psbt2, sizeof(psbt2), 0};
    const uint8_t key_tx_version = kPsbtGlobalTxVersion;
    const uint8_t key_fallback_locktime = kPsbtGlobalFallbackLocktime;
    const uint8_t key_input_count = kPsbtGlobalInputCount;
    const uint8_t key_output_count = kPsbtGlobalOutputCount;
    const uint8_t key_psbt_version = kPsbtGlobalVersion;
    const uint8_t key_previous_txid = kPsbtInPreviousTxid;
    const uint8_t key_output_index = kPsbtInOutputIndex;
    const uint8_t key_sequence = kPsbtInSequence;
    const uint8_t key_out_derivation = kPsbtOutBip32Derivation;
    if (passed)
      g_bitcoin_stage = 101;
    const uint8_t key_out_amount = kPsbtOutAmount;
    const uint8_t key_out_script = kPsbtOutScript;
    bool built2 = write_bytes(&v2, kPsbtMagic, sizeof(kPsbtMagic));
    // Global map: transaction version, fallback lock time, both counts and the
    // PSBT version that makes this v2.
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &key_tx_version, 1) &&
             write_compact_size(&v2, 4) && write_u32(&v2, 2);
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &key_fallback_locktime, 1) &&
             write_compact_size(&v2, 4) && write_u32(&v2, 0);
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &key_input_count, 1) &&
             write_compact_size(&v2, 1) && write_compact_size(&v2, 1);
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &key_output_count, 1) &&
             write_compact_size(&v2, 1) && write_compact_size(&v2, 1);
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &key_psbt_version, 1) &&
             write_compact_size(&v2, 4) && write_u32(&v2, 2);
    built2 = built2 && write_compact_size(&v2, 0);
    // Input map. The outpoint comes last on purpose: BIP370 does not fix the
    // order, so the non-witness UTXO check must not assume it arrives first.
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &key_sequence, 1) &&
             write_compact_size(&v2, 4) && write_u32(&v2, 0xfffffffd);
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &witness_utxo_key, 1) &&
             write_compact_size(&v2, 8 + 1 + sizeof(input_script)) && write_u64(&v2, 100000) &&
             write_compact_size(&v2, sizeof(input_script)) && write_bytes(&v2, input_script, sizeof(input_script));
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &redeem_script_key, 1) &&
             write_compact_size(&v2, sizeof(input_redeem)) && write_bytes(&v2, input_redeem, sizeof(input_redeem));
    built2 = built2 && write_compact_size(&v2, 34) && write_bytes(&v2, &input_derivation_type, 1) &&
             write_bytes(&v2, input_public, sizeof(input_public)) &&
             write_compact_size(&v2, 24) && write_bytes(&v2, fingerprint, sizeof(fingerprint));
    for (size_t index = 0; built2 && index < 5; ++index)
      built2 = write_u32(&v2, input_path[index]);
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &key_previous_txid, 1) &&
             write_compact_size(&v2, 32) && write_bytes(&v2, zero_txid, sizeof(zero_txid));
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &key_output_index, 1) &&
             write_compact_size(&v2, 4) && write_u32(&v2, 0);
    built2 = built2 && write_compact_size(&v2, 0);
    // Output map: derivation first, then amount and script.
    built2 = built2 && write_compact_size(&v2, 34) && write_bytes(&v2, &key_out_derivation, 1) &&
             write_bytes(&v2, output_public, sizeof(output_public)) &&
             write_compact_size(&v2, 24) && write_bytes(&v2, fingerprint, sizeof(fingerprint));
    for (size_t index = 0; built2 && index < 5; ++index)
      built2 = write_u32(&v2, output_path[index]);
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &key_out_amount, 1) &&
             write_compact_size(&v2, 8) && write_u64(&v2, 90000);
    built2 = built2 && write_compact_size(&v2, 1) && write_bytes(&v2, &key_out_script, 1) &&
             write_compact_size(&v2, sizeof(output_script)) && write_bytes(&v2, output_script, sizeof(output_script));
    built2 = built2 && write_compact_size(&v2, 0);

    if (passed)
      g_bitcoin_stage = 102;
    BitcoinSigningRequest parsed2;
    uint8_t signed_transaction2[384];
    size_t signed2_size = sizeof(signed_transaction2);
    const TransactionError v2_parse =
        built2 ? bitcoin_parse_psbt(psbt2, v2.position, master, request_chain, &parsed2)
               : TransactionError::InvalidArgument;
    passed = passed && v2_parse == TransactionError::Ok;
    if (passed)
      g_bitcoin_stage = 103;
    passed = passed && parsed2.version == 2 && parsed2.lock_time == 0 &&
             parsed2.input_count == 1 && parsed2.output_count == 1;
    if (passed)
      g_bitcoin_stage = 104;
    passed = passed && parsed2.inputs[0].previous_index == 0 &&
             parsed2.inputs[0].sequence == 0xfffffffd &&
             parsed2.inputs[0].value == 100000 &&
             parsed2.inputs[0].spend_type == BitcoinSpendType::NestedP2shP2wpkh;
    if (passed)
      g_bitcoin_stage = 105;
    passed = passed && parsed2.inputs[0].path_depth == 5 &&
             memcmp(parsed2.inputs[0].path, input_path, sizeof(input_path)) == 0;
    if (passed)
      g_bitcoin_stage = 106;
    passed = passed && parsed2.outputs[0].value == 90000;
    if (passed)
      g_bitcoin_stage = 107;
    passed = passed && parsed2.outputs[0].wallet_owned;
    if (passed)
      g_bitcoin_stage = 108;
    passed = passed && parsed2.outputs[0].change;
    if (passed)
      g_bitcoin_stage = 109;
    passed = passed && parsed2.fee == 10000;
    if (passed)
      g_bitcoin_stage = 110;
    passed = passed && parsed2.estimated_vbytes == v0_vbytes;
    if (passed)
      g_bitcoin_stage = 111;
    passed = passed &&
             bitcoin_sign_request(parsed2, master, signed_transaction2, &signed2_size) == TransactionError::Ok &&
             signed2_size == v0_signed_size &&
             crypto_constant_time_equal(signed_transaction, signed_transaction2, v0_signed_size);
    if (passed)
      g_bitcoin_stage = 112;
    clear_bitcoin_request(&parsed2);
    secure_zero(signed_transaction2, sizeof(signed_transaction2));
    if (passed)
      g_bitcoin_stage = 113;
    {
      uint8_t mixed[256];
      Writer mixed_writer = {mixed, sizeof(mixed), 0};
      bool wrote = write_bytes(&mixed_writer, kPsbtMagic, sizeof(kPsbtMagic));
      const uint8_t key_unsigned = kPsbtGlobalUnsignedTx;
      wrote = wrote && write_compact_size(&mixed_writer, 1) && write_bytes(&mixed_writer, &key_unsigned, 1) &&
              write_compact_size(&mixed_writer, unsigned_writer.position) &&
              write_bytes(&mixed_writer, unsigned_transaction, unsigned_writer.position);
      wrote = wrote && write_compact_size(&mixed_writer, 1) && write_bytes(&mixed_writer, &key_psbt_version, 1) &&
              write_compact_size(&mixed_writer, 4) && write_u32(&mixed_writer, 2);
      wrote = wrote && write_compact_size(&mixed_writer, 0);
      if (passed)
        g_bitcoin_stage = 114;
      BitcoinSigningRequest ignored;
      passed = passed && wrote &&
               bitcoin_parse_psbt(mixed, mixed_writer.position, master, request_chain, &ignored) ==
                   TransactionError::NonCanonical;
      clear_bitcoin_request(&ignored);

      if (passed)
        g_bitcoin_stage = 115;
      // A v0 blob carrying v2-only globals is not "almost v2", it is invalid.
      uint8_t v0_with_count[256];
      Writer v0_writer = {v0_with_count, sizeof(v0_with_count), 0};
      wrote = write_bytes(&v0_writer, kPsbtMagic, sizeof(kPsbtMagic));
      const uint8_t key_global_unsigned = kPsbtGlobalUnsignedTx;
      wrote = wrote && write_compact_size(&v0_writer, 1) && write_bytes(&v0_writer, &key_global_unsigned, 1) &&
              write_compact_size(&v0_writer, unsigned_writer.position) &&
              write_bytes(&v0_writer, unsigned_transaction, unsigned_writer.position);
      wrote = wrote && write_compact_size(&v0_writer, 1) && write_bytes(&v0_writer, &key_input_count, 1) &&
              write_compact_size(&v0_writer, 1) && write_compact_size(&v0_writer, 1);
      wrote = wrote && write_compact_size(&v0_writer, 0);
      passed = passed && wrote &&
               bitcoin_parse_psbt(v0_with_count, v0_writer.position, master, request_chain, &ignored) ==
                   TransactionError::NonCanonical;
      clear_bitcoin_request(&ignored);

      if (passed)
        g_bitcoin_stage = 116;
      uint8_t future[64];
      Writer future_writer = {future, sizeof(future), 0};
      wrote = write_bytes(&future_writer, kPsbtMagic, sizeof(kPsbtMagic));
      wrote = wrote && write_compact_size(&future_writer, 1) && write_bytes(&future_writer, &key_psbt_version, 1) &&
              write_compact_size(&future_writer, 4) && write_u32(&future_writer, 3);
      wrote = wrote && write_compact_size(&future_writer, 0);
      passed = passed && wrote &&
               bitcoin_parse_psbt(future, future_writer.position, master, request_chain, &ignored) ==
                   TransactionError::Unsupported;
      clear_bitcoin_request(&ignored);

      if (passed)
        g_bitcoin_stage = 117;
      uint8_t without_count[128];
      Writer no_count = {without_count, sizeof(without_count), 0};
      wrote = write_bytes(&no_count, kPsbtMagic, sizeof(kPsbtMagic));
      wrote = wrote && write_compact_size(&no_count, 1) && write_bytes(&no_count, &key_tx_version, 1) &&
              write_compact_size(&no_count, 4) && write_u32(&no_count, 2);
      wrote = wrote && write_compact_size(&no_count, 1) && write_bytes(&no_count, &key_output_count, 1) &&
              write_compact_size(&no_count, 1) && write_compact_size(&no_count, 1);
      wrote = wrote && write_compact_size(&no_count, 1) && write_bytes(&no_count, &key_psbt_version, 1) &&
              write_compact_size(&no_count, 4) && write_u32(&no_count, 2);
      wrote = wrote && write_compact_size(&no_count, 0);
      passed = passed && wrote &&
               bitcoin_parse_psbt(without_count, no_count.position, master, request_chain, &ignored) ==
                   TransactionError::MissingField;
      clear_bitcoin_request(&ignored);

      if (passed)
        g_bitcoin_stage = 118;
      uint8_t modifiable[128];
      Writer modify_writer = {modifiable, sizeof(modifiable), 0};
      wrote = write_bytes(&modify_writer, kPsbtMagic, sizeof(kPsbtMagic));
      const uint8_t key_modifiable = kPsbtGlobalTxModifiable;
      const uint8_t inputs_modifiable = 1;
      wrote = wrote && write_compact_size(&modify_writer, 1) && write_bytes(&modify_writer, &key_tx_version, 1) &&
              write_compact_size(&modify_writer, 4) && write_u32(&modify_writer, 2);
      wrote = wrote && write_compact_size(&modify_writer, 1) && write_bytes(&modify_writer, &key_input_count, 1) &&
              write_compact_size(&modify_writer, 1) && write_compact_size(&modify_writer, 1);
      wrote = wrote && write_compact_size(&modify_writer, 1) && write_bytes(&modify_writer, &key_output_count, 1) &&
              write_compact_size(&modify_writer, 1) && write_compact_size(&modify_writer, 1);
      wrote = wrote && write_compact_size(&modify_writer, 1) && write_bytes(&modify_writer, &key_modifiable, 1) &&
              write_compact_size(&modify_writer, 1) && write_bytes(&modify_writer, &inputs_modifiable, 1);
      wrote = wrote && write_compact_size(&modify_writer, 1) && write_bytes(&modify_writer, &key_psbt_version, 1) &&
              write_compact_size(&modify_writer, 4) && write_u32(&modify_writer, 2);
      wrote = wrote && write_compact_size(&modify_writer, 0);
      passed = passed && wrote &&
               bitcoin_parse_psbt(modifiable, modify_writer.position, master, request_chain, &ignored) ==
                   TransactionError::Unsupported;
      clear_bitcoin_request(&ignored);

      if (passed)
        g_bitcoin_stage = 119;
      uint8_t bad_locktime[128];
      Writer lock_writer = {bad_locktime, sizeof(bad_locktime), 0};
      wrote = write_bytes(&lock_writer, kPsbtMagic, sizeof(kPsbtMagic));
      const uint8_t key_time_lock = kPsbtInRequiredTimeLocktime;
      wrote = wrote && write_compact_size(&lock_writer, 1) && write_bytes(&lock_writer, &key_time_lock, 1) &&
              write_compact_size(&lock_writer, 4) && write_u32(&lock_writer, 1000);
      wrote = wrote && write_compact_size(&lock_writer, 0);
      Cursor lock_cursor = {bad_locktime, lock_writer.position, 5};
      BitcoinInput lock_input = {};
      PsbtInputLocktime lock_state = {};
      passed = passed && wrote &&
               parse_input_map_v2(&lock_cursor, master, request_chain, &lock_input, &lock_state) ==
                   TransactionError::NonCanonical &&
               lock_cursor.position == lock_writer.position - 1;
      secure_zero(&lock_input, sizeof(lock_input));
    }

    if (passed)
      g_bitcoin_stage = 120;
    {
      PsbtInputLocktime locks[3] = {};
      uint32_t chosen = 1;
      passed = passed && psbt_resolve_locktime(locks, 3, 77, &chosen) == TransactionError::Ok &&
               chosen == 77;
      locks[0].has_height = true;
      locks[0].height = 100;
      locks[1].has_height = true;
      locks[1].height = 200;
      locks[1].has_time = true;
      locks[1].time = 600000000UL;
      passed = passed && psbt_resolve_locktime(locks, 3, 77, &chosen) == TransactionError::Ok &&
               chosen == 200;
      PsbtInputLocktime conflict[2] = {};
      conflict[0].has_time = true;
      conflict[0].time = 600000000UL;
      conflict[1].has_height = true;
      conflict[1].height = 500;
      passed = passed && psbt_resolve_locktime(conflict, 2, 0, &chosen) ==
                             TransactionError::Unsupported;
      PsbtInputLocktime time_only[2] = {};
      time_only[0].has_time = true;
      time_only[0].time = 600000001UL;
      time_only[1].has_time = true;
      time_only[1].time = 600000002UL;
      passed = passed && psbt_resolve_locktime(time_only, 2, 0, &chosen) == TransactionError::Ok &&
               chosen == 600000002UL;
    }

    clear_bitcoin_request(&parsed);
    secure_zero(&master, sizeof(master));
    secure_zero(&input_node, sizeof(input_node));
    secure_zero(&output_node, sizeof(output_node));
    secure_zero(input_public, sizeof(input_public));
    secure_zero(output_public, sizeof(output_public));
    secure_zero(input_redeem, sizeof(input_redeem));
    secure_zero(output_redeem, sizeof(output_redeem));
    secure_zero(input_script, sizeof(input_script));
    secure_zero(output_script, sizeof(output_script));
    secure_zero(fingerprint, sizeof(fingerprint));
    secure_zero(unsigned_transaction, sizeof(unsigned_transaction));
    secure_zero(psbt, sizeof(psbt));
    secure_zero(signed_transaction, sizeof(signed_transaction));
    return passed;
  }

  int bitcoin_self_test_stage()
  {
    return g_bitcoin_stage;
  }

}
