#include "WalletCustomTokens.h"

#include <string.h>
#include <memory>
#include <new>

#include "CryptoPrimitives.h"

namespace hexwallet
{
  namespace
  {

    constexpr char kMagic[4] = {'H', 'X', 'C', 'T'};
    constexpr uint8_t kVersion = 2;
    constexpr uint8_t kLegacyVersion = 1;
    constexpr size_t kDigestSize = 8;

    constexpr size_t kRecordSize =
        kCustomTokenNetworkSize + 1 + kCustomTokenIdentifierSize + 1 +
        kCustomTokenIssuerSize + 1 + kCustomTokenCodeSize + kCustomTokenSymbolSize +
        kCustomTokenNameSize + 1;
    constexpr size_t kLegacyRecordSize = kCustomTokenNetworkSize +
                                         kCustomTokenContractSize +
                                         kCustomTokenSymbolSize +
                                         kCustomTokenNameSize + 1;
    constexpr size_t kHeaderSize = sizeof(kMagic) + 2;

    CustomTokenRecord g_records[kCustomTokenMax];
    size_t g_count = 0;
    CustomTokenStore g_store = {};
    bool g_bound = false;

    bool printable(const char *text, size_t capacity, size_t *out_length)
    {
      if (text == nullptr || out_length == nullptr)
        return false;
      size_t length = 0;
      while (length < capacity && text[length] != '\0')
      {
        const unsigned char character = static_cast<unsigned char>(text[length]);
        if (character < 0x20 || character > 0x7e)
          return false;
        ++length;
      }
      if (length == 0 || length >= capacity)
        return false;
      *out_length = length;
      return true;
    }

    bool text_fits(const char *text, size_t capacity)
    {
      if (text == nullptr)
        return false;
      size_t length = 0;
      while (length < capacity && text[length] != '\0')
        ++length;
      return length < capacity;
    }

    bool persist()
    {
      if (!g_bound || g_store.save == nullptr)
        return true; // RAM-only table
      return g_store.save(g_store.context, g_records, g_count);
    }

    void swap_out(size_t index)
    {
      for (size_t move = index; move + 1 < g_count; ++move)
      {
        g_records[move] = g_records[move + 1];
      }
      --g_count;
      memset(&g_records[g_count], 0, sizeof(g_records[0]));
    }

    void clear_table()
    {
      g_count = 0;
      memset(g_records, 0, sizeof(g_records));
    }

    // Every record that is stored must also satisfy the rules a fresh one does,
    // otherwise an old blob could reintroduce something this build refuses.
    bool zero_bytes(const uint8_t *data, size_t size);
    bool stellar_code_valid(const char *code)
    {
      size_t length = 0;
      if (!printable(code, kCustomTokenCodeSize, &length))
        return false;
      for (size_t index = 0; index < length; ++index)
      {
        const char c = code[index];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
          return false;
      }
      return true;
    }
    bool record_valid(const CustomTokenRecord &record)
    {
      size_t length = 0;
      if (!text_fits(record.network_id, kCustomTokenNetworkSize) ||
          !printable(record.symbol, kCustomTokenSymbolSize, &length) ||
          !printable(record.name, kCustomTokenNameSize, &length) ||
          !text_fits(record.code, kCustomTokenCodeSize) ||
          record.decimals > kCustomTokenMaxDecimals)
      {
        return false;
      }
      if (record.identifier_size == 0 ||
          record.identifier_size > kCustomTokenIdentifierSize ||
          (record.issuer_size != 0 && record.issuer_size != kCustomTokenIssuerSize))
      {
        return false;
      }
      const NetworkProfile *network = find_network_profile(record.network_id);
      if (network == nullptr || zero_bytes(record.identifier, record.identifier_size))
        return false;
      switch (record.standard)
      {
      case CustomTokenStandard::EvmErc721:
      case CustomTokenStandard::EvmErc1155:
        if (record.decimals != 0)
          return false;
        // NFT quantities and IDs are integers, never scaled by display decimals.
        return network->encoding == AddressEncoding::Evm && record.identifier_size == kCustomTokenContractSize &&
               record.issuer_size == 0 && record.code[0] == '\0';
      case CustomTokenStandard::EvmErc20:
        return network->encoding == AddressEncoding::Evm && record.identifier_size == kCustomTokenContractSize &&
               record.issuer_size == 0 && record.code[0] == '\0';
      case CustomTokenStandard::TronTrc20:
        return network->encoding == AddressEncoding::Tron && record.identifier_size == 21 &&
               record.identifier[0] == 0x41 && !zero_bytes(record.identifier + 1, 20) && record.issuer_size == 0 &&
               record.code[0] == '\0';
      case CustomTokenStandard::SolanaSpl:
        return strcmp(network->id, "sol") == 0 && record.identifier_size == kCustomTokenIdentifierSize &&
               record.issuer_size == 0 && record.code[0] == '\0';
      case CustomTokenStandard::StellarAsset:
        return network->encoding == AddressEncoding::StellarStrKey &&
               record.identifier_size == kCustomTokenIssuerSize && record.issuer_size == kCustomTokenIssuerSize &&
               !zero_bytes(record.issuer, kCustomTokenIssuerSize) &&
               memcmp(record.identifier, record.issuer, kCustomTokenIssuerSize) == 0 &&
               stellar_code_valid(record.code) && record.decimals == 7;
      case CustomTokenStandard::StarknetErc20:
        return network->encoding == AddressEncoding::StarknetKey && record.identifier_size == kCustomTokenIdentifierSize &&
               record.issuer_size == 0 && record.code[0] == '\0';
      }
      return false;
    }

    bool zero_bytes(const uint8_t *data, size_t size)
    {
      uint8_t accumulator = 0;
      for (size_t index = 0; index < size; ++index)
        accumulator |= data[index];
      return accumulator == 0;
    }

    bool table_valid(const CustomTokenRecord *records, size_t count)
    {
      if (count > kCustomTokenMax)
        return false;
      for (size_t index = 0; index < count; ++index)
      {
        const CustomTokenRecord &record = records[index];
        if (!record_valid(record))
          return false;
        for (size_t earlier = 0; earlier < index; ++earlier)
        {
          const CustomTokenRecord &other = records[earlier];
          if (strcmp(record.network_id, other.network_id) == 0 &&
              record.identifier_size == other.identifier_size &&
              memcmp(record.identifier, other.identifier, record.identifier_size) == 0 &&
              (record.standard != CustomTokenStandard::StellarAsset || strcmp(record.code, other.code) == 0))
            return false;
        }
      }
      return true;
    }

    // Default fungible standard and identifier width. NFT registration explicitly
    // overrides the standard only after checking the network uses EVM addresses.
    CustomTokenError standard_for_network(const NetworkProfile &network,
                                          CustomTokenStandard *standard,
                                          size_t *identifier_size)
    {
      switch (network.encoding)
      {
      case AddressEncoding::Evm:
        *standard = CustomTokenStandard::EvmErc20;
        *identifier_size = kCustomTokenContractSize;
        return CustomTokenError::Ok;
      case AddressEncoding::Tron:
        *standard = CustomTokenStandard::TronTrc20;
        *identifier_size = 21;
        return CustomTokenError::Ok;
      case AddressEncoding::Ed25519Base58:
        if (strcmp(network.id, "sol") == 0)
        {
          *standard = CustomTokenStandard::SolanaSpl;
          *identifier_size = kCustomTokenIdentifierSize;
          return CustomTokenError::Ok;
        }
        return CustomTokenError::UnsupportedNetwork;
      case AddressEncoding::StarknetKey:
        // Starknet token contracts are felt-sized addresses, so the key is the
        // full 32-byte value and not a truncated Ethereum-style address.
        *standard = CustomTokenStandard::StarknetErc20;
        *identifier_size = kCustomTokenIdentifierSize;
        return CustomTokenError::Ok;
      default:
        return CustomTokenError::UnsupportedNetwork;
      }
    }

    size_t find_by_identifier(const char *network_id, const uint8_t *identifier,
                              size_t identifier_size)
    {
      if (network_id == nullptr || identifier == nullptr || identifier_size == 0 ||
          identifier_size > kCustomTokenIdentifierSize)
      {
        return kCustomTokenMax;
      }
      for (size_t index = 0; index < g_count; ++index)
      {
        const CustomTokenRecord &record = g_records[index];
        if (strcmp(record.network_id, network_id) != 0)
          continue;
        if (record.identifier_size != identifier_size)
          continue;
        if (!crypto_constant_time_equal(record.identifier, identifier,
                                        identifier_size))
        {
          continue;
        }
        return index;
      }
      return kCustomTokenMax;
    }

    size_t find_stellar(const char *network_id, const uint8_t issuer[32],
                        const char *code)
    {
      if (network_id == nullptr || issuer == nullptr || code == nullptr)
      {
        return kCustomTokenMax;
      }
      for (size_t index = 0; index < g_count; ++index)
      {
        const CustomTokenRecord &record = g_records[index];
        if (record.standard != CustomTokenStandard::StellarAsset)
          continue;
        if (strcmp(record.network_id, network_id) != 0)
          continue;
        if (strcmp(record.code, code) != 0)
          continue;
        if (!crypto_constant_time_equal(record.issuer, issuer,
                                        kCustomTokenIssuerSize))
        {
          continue;
        }
        return index;
      }
      return kCustomTokenMax;
    }

    CustomTokenError upsert(size_t target, bool replacing,
                            const CustomTokenRecord &fresh)
    {
      CustomTokenRecord previous;
      memset(&previous, 0, sizeof(previous));
      if (replacing)
      {
        previous = g_records[target];
      }
      else
      {
        if (g_count >= kCustomTokenMax)
          return CustomTokenError::Full;
        target = g_count;
        ++g_count;
      }
      g_records[target] = fresh;
      if (!persist())
      {
        if (replacing)
        {
          g_records[target] = previous;
        }
        else
        {
          swap_out(target);
        }
        return CustomTokenError::StorageFailure;
      }
      return CustomTokenError::Ok;
    }

    // Builds the record for a non-Stellar token after the label and key checks.
    CustomTokenError build_and_store(const char *network_id,
                                     const uint8_t *identifier,
                                     size_t identifier_size, const char *symbol,
                                     const char *name, uint8_t decimals,
                                     const uint8_t *issuer,
                                     const char *code,
                                     CustomTokenStandard nft = CustomTokenStandard::EvmErc20)
    {
      if (network_id == nullptr || identifier == nullptr || symbol == nullptr ||
          name == nullptr)
      {
        return CustomTokenError::InvalidArgument;
      }
      if (strlen(network_id) >= kCustomTokenNetworkSize)
      {
        return CustomTokenError::InvalidArgument;
      }
      const NetworkProfile *network = find_network_profile(network_id);
      if (network == nullptr)
        return CustomTokenError::UnsupportedNetwork;
      CustomTokenStandard standard = CustomTokenStandard::EvmErc20;
      size_t expected_size = 0;
      if (issuer == nullptr)
      {
        const CustomTokenError supported =
            standard_for_network(*network, &standard, &expected_size);
        if (supported != CustomTokenError::Ok)
          return supported;
        if (identifier_size != expected_size)
        {
          return CustomTokenError::InvalidArgument;
        }
      }
      else
      {
        if (network == nullptr || network->encoding != AddressEncoding::StellarStrKey)
        {
          return CustomTokenError::UnsupportedNetwork;
        }
        standard = CustomTokenStandard::StellarAsset;
        expected_size = kCustomTokenIdentifierSize;
      }
      if (identifier_size != expected_size ||
          identifier_size > kCustomTokenIdentifierSize || zero_bytes(identifier, identifier_size))
      {
        return CustomTokenError::InvalidArgument;
      }
      size_t symbol_length = 0;
      size_t name_length = 0;
      if (!printable(symbol, kCustomTokenSymbolSize, &symbol_length) ||
          !printable(name, kCustomTokenNameSize, &name_length))
      {
        return CustomTokenError::InvalidArgument;
      }
      if (decimals > kCustomTokenMaxDecimals)
        return CustomTokenError::InvalidArgument;

      CustomTokenRecord fresh;
      memset(&fresh, 0, sizeof(fresh));
      memcpy(fresh.network_id, network_id, strlen(network_id));
      fresh.standard = standard;
      memcpy(fresh.identifier, identifier, identifier_size);
      fresh.identifier_size = static_cast<uint8_t>(identifier_size);
      memcpy(fresh.symbol, symbol, symbol_length);
      memcpy(fresh.name, name, name_length);
      fresh.decimals = decimals;
      if (issuer != nullptr)
      {
        if (zero_bytes(issuer, kCustomTokenIssuerSize))
        {
          return CustomTokenError::InvalidArgument;
        }
        size_t code_length = 0;
        if (!printable(code, kCustomTokenCodeSize, &code_length))
        {
          return CustomTokenError::InvalidArgument;
        }
        memcpy(fresh.issuer, issuer, kCustomTokenIssuerSize);
        fresh.issuer_size = kCustomTokenIssuerSize;
        memcpy(fresh.code, code, code_length);
      }
      if (nft != CustomTokenStandard::EvmErc20)
      {
        if (network->encoding != AddressEncoding::Evm || issuer != nullptr)
          return CustomTokenError::UnsupportedNetwork;
        fresh.standard = nft;
      }
      if (!record_valid(fresh))
        return CustomTokenError::InvalidArgument;

      const size_t target = issuer != nullptr
                                ? find_stellar(network_id, issuer, code)
                                : find_by_identifier(network_id, identifier,
                                                     identifier_size);
      return upsert(target, target < g_count, fresh);
    }

  } // namespace

  // The blob is written whole and carries its own digest, so a torn write is
  // detected instead of being half-loaded. Losing the table is annoying; acting on
  // a half-written one is not acceptable.
  bool custom_token_serialize(uint8_t *out, size_t capacity, size_t *out_size)
  {
    if (out == nullptr || out_size == nullptr || capacity < kCustomTokenBlobMax ||
        g_count > kCustomTokenMax)
    {
      return false;
    }
    memset(out, 0, kCustomTokenBlobMax);
    memcpy(out, kMagic, sizeof(kMagic));
    out[4] = kVersion;
    out[5] = static_cast<uint8_t>(g_count);
    size_t offset = kHeaderSize;
    for (size_t index = 0; index < g_count; ++index)
    {
      const CustomTokenRecord &record = g_records[index];
      memcpy(out + offset, record.network_id, kCustomTokenNetworkSize);
      offset += kCustomTokenNetworkSize;
      out[offset++] = static_cast<uint8_t>(record.standard);
      memcpy(out + offset, record.identifier, kCustomTokenIdentifierSize);
      offset += kCustomTokenIdentifierSize;
      out[offset++] = record.identifier_size;
      memcpy(out + offset, record.issuer, kCustomTokenIssuerSize);
      offset += kCustomTokenIssuerSize;
      out[offset++] = record.issuer_size;
      memcpy(out + offset, record.code, kCustomTokenCodeSize);
      offset += kCustomTokenCodeSize;
      memcpy(out + offset, record.symbol, kCustomTokenSymbolSize);
      offset += kCustomTokenSymbolSize;
      memcpy(out + offset, record.name, kCustomTokenNameSize);
      offset += kCustomTokenNameSize;
      out[offset++] = record.decimals;
    }
    uint8_t digest[kSha256Size];
    const bool ok = crypto_sha256(out, offset, digest);
    if (ok)
      memcpy(out + offset, digest, kDigestSize);
    secure_zero(digest, sizeof(digest));
    *out_size = offset + kDigestSize;
    return ok;
  }

  bool custom_token_deserialize(const uint8_t *blob, size_t size,
                                CustomTokenRecord *records, size_t capacity,
                                size_t *count)
  {
    if (blob == nullptr || records == nullptr || count == nullptr ||
        size < kHeaderSize + kDigestSize)
    {
      return false;
    }
    if (memcmp(blob, kMagic, sizeof(kMagic)) != 0)
      return false;
    const uint8_t version = blob[4];
    if (version != kVersion && version != kLegacyVersion)
      return false;
    const size_t stored = blob[5];
    if (stored > capacity || stored > kCustomTokenMax)
      return false;
    const size_t record_size =
        version == kVersion ? kRecordSize : kLegacyRecordSize;
    if (size != kHeaderSize + stored * record_size + kDigestSize)
      return false;
    uint8_t digest[kSha256Size];
    const bool hashed = crypto_sha256(blob, size - kDigestSize, digest);
    const bool matches =
        hashed && crypto_constant_time_equal(digest, blob + size - kDigestSize,
                                             kDigestSize);
    secure_zero(digest, sizeof(digest));
    if (!matches)
      return false;

    size_t offset = kHeaderSize;
    for (size_t index = 0; index < stored; ++index)
    {
      CustomTokenRecord &record = records[index];
      memset(&record, 0, sizeof(record));
      memcpy(record.network_id, blob + offset, kCustomTokenNetworkSize);
      offset += kCustomTokenNetworkSize;
      if (version == kVersion)
      {
        record.standard = static_cast<CustomTokenStandard>(blob[offset++]);
        memcpy(record.identifier, blob + offset, kCustomTokenIdentifierSize);
        offset += kCustomTokenIdentifierSize;
        record.identifier_size = blob[offset++];
        memcpy(record.issuer, blob + offset, kCustomTokenIssuerSize);
        offset += kCustomTokenIssuerSize;
        record.issuer_size = blob[offset++];
        memcpy(record.code, blob + offset, kCustomTokenCodeSize);
        offset += kCustomTokenCodeSize;
      }
      else
      {
        record.standard = CustomTokenStandard::EvmErc20;
        memcpy(record.identifier, blob + offset, kCustomTokenContractSize);
        offset += kCustomTokenContractSize;
        record.identifier_size = kCustomTokenContractSize;
      }
      memcpy(record.symbol, blob + offset, kCustomTokenSymbolSize);
      offset += kCustomTokenSymbolSize;
      memcpy(record.name, blob + offset, kCustomTokenNameSize);
      offset += kCustomTokenNameSize;
      record.decimals = blob[offset++];
      if (!record_valid(record))
        return false;
    }
    if (!table_valid(records, stored))
      return false;
    *count = stored;
    return true;
  }

  bool custom_tokens_bind_store(const CustomTokenStore &store)
  {
    g_store = store;
    g_bound = store.load != nullptr && store.save != nullptr;
    clear_table();
    if (!g_bound)
      return true;
    size_t count = 0;
    if (store.load(store.context, g_records, kCustomTokenMax, &count) &&
        table_valid(g_records, count))
    {
      g_count = count;
    }
    else
    {
      clear_table();
      return false;
    }
    return true;
  }

  size_t custom_token_count() { return g_count; }

  bool custom_token_at(size_t index, CustomTokenRecord *out)
  {
    if (out == nullptr || index >= g_count)
      return false;
    *out = g_records[index];
    return true;
  }

  const CustomTokenRecord *custom_token_find(const char *network_id,
                                             const uint8_t *identifier,
                                             size_t identifier_size)
  {
    const size_t index = find_by_identifier(network_id, identifier,
                                            identifier_size);
    return index < g_count ? &g_records[index] : nullptr;
  }

  size_t custom_token_index_of(const char *network_id, const uint8_t *identifier,
                               size_t identifier_size)
  {
    return find_by_identifier(network_id, identifier, identifier_size);
  }

  const CustomTokenRecord *custom_token_find_stellar(const char *network_id,
                                                     const uint8_t issuer[32],
                                                     const char *code)
  {
    const size_t index = find_stellar(network_id, issuer, code);
    return index < g_count ? &g_records[index] : nullptr;
  }

  size_t custom_token_index(const CustomTokenRecord *record)
  {
    if (record == nullptr)
      return kCustomTokenMax;
    for (size_t index = 0; index < g_count; ++index)
    {
      if (record == &g_records[index])
        return index;
    }
    if (record->standard == CustomTokenStandard::StellarAsset)
    {
      return find_stellar(record->network_id, record->issuer, record->code);
    }
    return find_by_identifier(record->network_id, record->identifier,
                              record->identifier_size);
  }

  CustomTokenError custom_token_add(const char *network_id,
                                    const uint8_t *identifier,
                                    size_t identifier_size, const char *symbol,
                                    const char *name, uint8_t decimals)
  {
    return build_and_store(network_id, identifier, identifier_size, symbol, name,
                           decimals, nullptr, nullptr);
  }

  CustomTokenError custom_token_add_stellar(const char *network_id,
                                            const uint8_t issuer[32],
                                            const char *code, const char *symbol,
                                            const char *name, uint8_t decimals)
  {
    if (issuer == nullptr || code == nullptr)
    {
      return CustomTokenError::InvalidArgument;
    }
    return build_and_store(network_id, issuer, kCustomTokenIssuerSize, symbol,
                           name, decimals, issuer, code);
  }

  CustomTokenError custom_token_add_nft(const char *network_id,
                                        const uint8_t contract[20],
                                        CustomTokenStandard standard,
                                        const char *symbol, const char *name)
  {
    if (standard != CustomTokenStandard::EvmErc721 &&
        standard != CustomTokenStandard::EvmErc1155)
      return CustomTokenError::InvalidArgument;
    return build_and_store(network_id, contract, 20, symbol, name, 0,
                           nullptr, nullptr, standard);
  }

  CustomTokenError custom_token_remove(const char *network_id,
                                       const uint8_t *identifier,
                                       size_t identifier_size)
  {
    const size_t target = find_by_identifier(network_id, identifier,
                                             identifier_size);
    if (target >= g_count)
    {
      return network_id == nullptr || identifier == nullptr
                 ? CustomTokenError::InvalidArgument
                 : CustomTokenError::NotFound;
    }
    const CustomTokenRecord removed = g_records[target];
    swap_out(target);
    if (!persist())
    {
      // Put it back rather than reporting a removal that did not survive a reboot.
      for (size_t move = g_count; move > target; --move)
      {
        g_records[move] = g_records[move - 1];
      }
      g_records[target] = removed;
      ++g_count;
      return CustomTokenError::StorageFailure;
    }
    return CustomTokenError::Ok;
  }

  CustomTokenError custom_token_remove_stellar(const char *network_id,
                                               const uint8_t issuer[32],
                                               const char *code)
  {
    const size_t target = find_stellar(network_id, issuer, code);
    if (target >= g_count)
    {
      return network_id == nullptr || issuer == nullptr || code == nullptr
                 ? CustomTokenError::InvalidArgument
                 : CustomTokenError::NotFound;
    }
    const CustomTokenRecord removed = g_records[target];
    swap_out(target);
    if (!persist())
    {
      for (size_t move = g_count; move > target; --move)
      {
        g_records[move] = g_records[move - 1];
      }
      g_records[target] = removed;
      ++g_count;
      return CustomTokenError::StorageFailure;
    }
    return CustomTokenError::Ok;
  }

  const char *custom_token_error_text(CustomTokenError error)
  {
    switch (error)
    {
    case CustomTokenError::Ok:
      return "ok";
    case CustomTokenError::InvalidArgument:
      return "invalid-argument";
    case CustomTokenError::UnsupportedNetwork:
      return "unsupported-network";
    case CustomTokenError::Duplicate:
      return "duplicate";
    case CustomTokenError::Full:
      return "table-full";
    case CustomTokenError::NotFound:
      return "not-found";
    case CustomTokenError::StorageFailure:
      return "storage-failure";
    }
    return "unknown";
  }

  bool run_custom_token_self_tests()
  {
    // The test backend stores the same blob the device writes, so the digest and
    // the "a corrupted table is ignored" behaviour are actually exercised.
    struct TestStore
    {
      uint8_t blob[kCustomTokenBlobMax];
      size_t size;
      bool present;
      bool fail;
    };
    std::unique_ptr<TestStore> allocation(new (std::nothrow) TestStore{});
    if (!allocation)
      return false;
    TestStore &store = *allocation;
    const CustomTokenStore persistence = {
        &store,
        [](void *context, CustomTokenRecord *records, size_t capacity, size_t *count)
        {
          auto *state = static_cast<TestStore *>(context);
          if (!state->present)
            return false;
          return custom_token_deserialize(state->blob, state->size, records, capacity,
                                          count);
        },
        [](void *context, const CustomTokenRecord *, size_t)
        {
          auto *state = static_cast<TestStore *>(context);
          if (state->fail)
            return false;
          const bool ok = custom_token_serialize(state->blob, sizeof(state->blob),
                                                 &state->size);
          if (ok)
            state->present = true;
          return ok;
        }};
    custom_tokens_bind_store(persistence);
    bool passed = custom_token_count() == 0;

    uint8_t contract[kCustomTokenContractSize];
    for (size_t index = 0; index < sizeof(contract); ++index)
    {
      contract[index] = static_cast<uint8_t>(0x10 + index);
    }
    passed = passed && custom_token_add("eth", contract, sizeof(contract), "TEST", "Test Token", 18) == CustomTokenError::Ok &&
             custom_token_count() == 1;
    const CustomTokenRecord *found =
        custom_token_find("eth", contract, sizeof(contract));
    passed = passed && found != nullptr && strcmp(found->symbol, "TEST") == 0 &&
             found->decimals == 18 &&
             found->standard == CustomTokenStandard::EvmErc20 && store.present;
    // The same contract on another network is a different token.
    passed = passed &&
             custom_token_find("matic", contract, sizeof(contract)) == nullptr;
    // Replacing keeps one row and updates the labels.
    passed = passed &&
             custom_token_add("eth", contract, sizeof(contract), "TEST2",
                              "Test Two", 6) == CustomTokenError::Ok &&
             custom_token_count() == 1 &&
             strcmp(custom_token_find("eth", contract, sizeof(contract))->symbol,
                    "TEST2") == 0;

    // TRON: the chain-native key is the 21-byte account address.
    uint8_t tron_contract[21];
    tron_contract[0] = 0x41;
    for (size_t index = 1; index < sizeof(tron_contract); ++index)
    {
      tron_contract[index] = static_cast<uint8_t>(0x20 + index);
    }
    passed = passed &&
             custom_token_add("trx", tron_contract, sizeof(tron_contract),
                              "TUSDT", "Tron Test", 6) == CustomTokenError::Ok;
    const CustomTokenRecord *tron_record =
        custom_token_find("trx", tron_contract, sizeof(tron_contract));
    passed = passed && tron_record != nullptr &&
             tron_record->standard == CustomTokenStandard::TronTrc20 &&
             tron_record->identifier_size == 21;
    // A 20-byte key never matches the 21-byte TRON record.
    passed = passed && custom_token_find("trx", tron_contract + 1, 20) == nullptr;

    // Solana: 32-byte mint.
    uint8_t mint[kCustomTokenIdentifierSize];
    for (size_t index = 0; index < sizeof(mint); ++index)
    {
      mint[index] = static_cast<uint8_t>(0x40 + index);
    }
    passed = passed && custom_token_add("sol", mint, sizeof(mint), "SPL",
                                        "Solana Test", 9) == CustomTokenError::Ok;
    const CustomTokenRecord *spl =
        custom_token_find("sol", mint, sizeof(mint));
    passed = passed && spl != nullptr &&
             spl->standard == CustomTokenStandard::SolanaSpl;

    // Stellar: issuer key + asset code.
    uint8_t issuer[kCustomTokenIssuerSize];
    for (size_t index = 0; index < sizeof(issuer); ++index)
    {
      issuer[index] = static_cast<uint8_t>(0x60 + index);
    }
    passed = passed &&
             custom_token_add_stellar("xlm", issuer, "USDC", "USDCx",
                                      "Stellar Test", 7) == CustomTokenError::Ok;
    const CustomTokenRecord *stellar =
        custom_token_find_stellar("xlm", issuer, "USDC");
    passed = passed && stellar != nullptr &&
             stellar->standard == CustomTokenStandard::StellarAsset &&
             strcmp(stellar->code, "USDC") == 0;
    passed = passed && custom_token_find_stellar("xlm", issuer, "USDT") == nullptr;
    passed = passed && custom_token_remove_stellar("xlm", issuer, "USDC") == CustomTokenError::Ok &&
             custom_token_find_stellar("xlm", issuer, "USDC") == nullptr &&
             custom_token_add_stellar("xlm", issuer, "USDC", "USDCx",
                                      "Stellar Test", 7) == CustomTokenError::Ok;

    // Starknet: the key is the 32-byte token contract address. A 20-byte
    // Ethereum-shaped key must not be accepted for it.
    uint8_t stark_token[kCustomTokenIdentifierSize];
    for (size_t index = 0; index < sizeof(stark_token); ++index)
    {
      stark_token[index] = static_cast<uint8_t>(0x80 + index);
    }
    passed = passed && custom_token_add("stark", stark_token,
                                        sizeof(stark_token), "dUSDC",
                                        "Stark USD", 6) == CustomTokenError::Ok;
    const CustomTokenRecord *starknet_record =
        custom_token_find("stark", stark_token, sizeof(stark_token));
    passed = passed && starknet_record != nullptr &&
             starknet_record->standard == CustomTokenStandard::StarknetErc20 &&
             starknet_record->identifier_size == kCustomTokenIdentifierSize &&
             starknet_record->decimals == 6;
    passed = passed && custom_token_add("stark", stark_token, 20, "dUSDC", "Stark USD", 6) == CustomTokenError::InvalidArgument &&
             custom_token_remove("stark", stark_token, sizeof(stark_token)) ==
                 CustomTokenError::Ok &&
             custom_token_find("stark", stark_token, sizeof(stark_token)) ==
                 nullptr;

    // Refusals.
    passed = passed && custom_token_add("btc", contract, sizeof(contract), "X",
                                        "X", 8) ==
                           CustomTokenError::UnsupportedNetwork;
    // Exactly five standards are wired; every other network must say so instead of
    // accepting a key it cannot resolve to a token.
    passed = passed && custom_token_add("dot", mint, sizeof(mint), "X", "X", 8) == CustomTokenError::UnsupportedNetwork &&
             custom_token_add("apt", mint, sizeof(mint), "X", "X", 8) ==
                 CustomTokenError::UnsupportedNetwork &&
             custom_token_add("qrl2", stark_token, sizeof(stark_token), "X", "X",
                              8) == CustomTokenError::UnsupportedNetwork &&
             custom_token_add("xmr", mint, sizeof(mint), "X", "X", 8) ==
                 CustomTokenError::UnsupportedNetwork;
    passed = passed && custom_token_add("eth", contract, 19, "X", "X", 8) ==
                           CustomTokenError::InvalidArgument;
    passed = passed && custom_token_add("eth", contract, sizeof(contract), "",
                                        "X", 8) ==
                           CustomTokenError::InvalidArgument;
    passed = passed && custom_token_add("eth", contract, sizeof(contract),
                                        "TOOLONGSYMBOL", "X", 8) ==
                           CustomTokenError::InvalidArgument;
    passed = passed && custom_token_add("eth", contract, sizeof(contract), "OK",
                                        "X", 37) ==
                           CustomTokenError::InvalidArgument;
    uint8_t zero_contract[kCustomTokenContractSize] = {};
    passed = passed && custom_token_add("eth", zero_contract,
                                        sizeof(zero_contract), "OK", "X", 18) ==
                           CustomTokenError::InvalidArgument;
    passed = passed && custom_token_add_stellar("xlm", issuer, "", "X", "X", 7) ==
                           CustomTokenError::InvalidArgument;
    passed = passed && custom_token_add_stellar("xlm", issuer, "BAD/CODE", "X", "X", 7) == CustomTokenError::InvalidArgument &&
             custom_token_add_stellar("xlm", issuer, "USDC", "X", "X", 6) ==
                 CustomTokenError::InvalidArgument;
    tron_contract[0] = 0x42;
    passed = passed && custom_token_add("trx", tron_contract, sizeof(tron_contract), "X", "X", 6) ==
                           CustomTokenError::InvalidArgument;
    tron_contract[0] = 0x41;

    // A failed write must not change what the device believes it has.
    store.fail = true;
    passed = passed && custom_token_add("eth", contract, sizeof(contract), "WONT", "Nope", 18) == CustomTokenError::StorageFailure &&
             strcmp(custom_token_find("eth", contract, sizeof(contract))->symbol,
                    "TEST2") == 0;
    passed = passed && custom_token_remove("eth", contract, sizeof(contract)) == CustomTokenError::StorageFailure &&
             custom_token_count() == 4;
    store.fail = false;

    // Fill the entire configured capacity, then refuse one more.
    uint8_t other[kCustomTokenContractSize];
    memcpy(other, contract, sizeof(other));
    for (size_t slot = custom_token_count(); slot < kCustomTokenMax; ++slot)
    {
      other[0] = static_cast<uint8_t>(slot + 0x80);
      passed = passed && custom_token_add("eth", other, sizeof(other), "T",
                                          "Token", 18) == CustomTokenError::Ok;
    }
    other[0] = 0xFF;
    passed = passed && custom_token_add("eth", other, sizeof(other), "T", "Token", 18) == CustomTokenError::Full &&
             custom_token_count() == kCustomTokenMax;

    // Removal frees a slot and persists.
    passed = passed && custom_token_remove("eth", contract, sizeof(contract)) == CustomTokenError::Ok &&
             custom_token_count() == kCustomTokenMax - 1 &&
             custom_token_find("eth", contract, sizeof(contract)) == nullptr;

    // A reload sees exactly what was stored, and a blob whose bytes were changed
    // is ignored rather than half-applied.
    const size_t stored_count = custom_token_count();
    custom_tokens_bind_store(persistence);
    passed = passed && custom_token_count() == stored_count;
    // A valid digest does not authorize records. Reject a rehashed cross-network
    // binding, and reject duplicate identities before exposing a loaded table.
    const auto rehash_store = [&store]()
    {
      uint8_t digest[kSha256Size];
      const bool ok = crypto_sha256(store.blob, store.size - kDigestSize, digest);
      if (ok)
        memcpy(store.blob + store.size - kDigestSize, digest, kDigestSize);
      secure_zero(digest, sizeof(digest));
      return ok;
    };
    uint8_t saved_network[kCustomTokenNetworkSize];
    memcpy(saved_network, store.blob + kHeaderSize, sizeof(saved_network));
    memset(store.blob + kHeaderSize, 0, sizeof(saved_network));
    memcpy(store.blob + kHeaderSize, "btc", 3);
    passed = passed && rehash_store() && !custom_tokens_bind_store(persistence) && custom_token_count() == 0;
    memcpy(store.blob + kHeaderSize, saved_network, sizeof(saved_network));
    passed = passed && rehash_store() && custom_tokens_bind_store(persistence) && custom_token_count() == stored_count;
    uint8_t saved_second[kRecordSize];
    memcpy(saved_second, store.blob + kHeaderSize + kRecordSize, sizeof(saved_second));
    memcpy(store.blob + kHeaderSize + kRecordSize, store.blob + kHeaderSize, kRecordSize);
    passed = passed && rehash_store() && !custom_tokens_bind_store(persistence) && custom_token_count() == 0;
    memcpy(store.blob + kHeaderSize + kRecordSize, saved_second, sizeof(saved_second));
    passed = passed && rehash_store() && custom_tokens_bind_store(persistence) && custom_token_count() == stored_count;
    store.blob[kHeaderSize + 3] ^= 0x01;
    custom_tokens_bind_store(persistence);
    passed = passed && custom_token_count() == 0;

    // A version-1 blob (EVM-only layout) is upgraded instead of discarded.
    uint8_t legacy[kHeaderSize + kLegacyRecordSize + kDigestSize] = {};
    memcpy(legacy, kMagic, sizeof(kMagic));
    legacy[4] = kLegacyVersion;
    legacy[5] = 1;
    memcpy(legacy + kHeaderSize, "eth", 3);
    memcpy(legacy + kHeaderSize + kCustomTokenNetworkSize, contract,
           sizeof(contract));
    memcpy(legacy + kHeaderSize + kCustomTokenNetworkSize + kCustomTokenContractSize,
           "LEGACY", 6);
    memcpy(legacy + kHeaderSize + kCustomTokenNetworkSize + kCustomTokenContractSize + kCustomTokenSymbolSize,
           "Legacy token", 12);
    legacy[kHeaderSize + kLegacyRecordSize - 1] = 18;
    uint8_t legacy_digest[kSha256Size];
    passed = passed && crypto_sha256(legacy, sizeof(legacy) - kDigestSize,
                                     legacy_digest);
    memcpy(legacy + sizeof(legacy) - kDigestSize, legacy_digest, kDigestSize);
    secure_zero(legacy_digest, sizeof(legacy_digest));
    CustomTokenRecord upgraded[1];
    size_t upgraded_count = 0;
    passed = passed &&
             custom_token_deserialize(legacy, sizeof(legacy), upgraded,
                                      1, &upgraded_count) &&
             upgraded_count == 1 &&
             upgraded[0].standard == CustomTokenStandard::EvmErc20 &&
             upgraded[0].identifier_size == kCustomTokenContractSize &&
             strcmp(upgraded[0].symbol, "LEGACY") == 0 &&
             crypto_constant_time_equal(upgraded[0].identifier, contract,
                                        sizeof(contract));

    custom_tokens_bind_store(CustomTokenStore{});
    secure_zero(contract, sizeof(contract));
    secure_zero(other, sizeof(other));
    secure_zero(tron_contract, sizeof(tron_contract));
    secure_zero(mint, sizeof(mint));
    secure_zero(issuer, sizeof(issuer));
    return passed;
  }

}
