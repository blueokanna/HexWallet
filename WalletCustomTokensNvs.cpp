#include "WalletCustomTokens.h"

#if defined(ARDUINO)

#include <nvs.h>
#include <memory>
#include <new>

#include "CryptoPrimitives.h"

namespace hexwallet
{
  namespace
  {

    constexpr const char *kNamespace = "hxctok";
    constexpr const char *kKey = "table";

    bool nvs_load(void *, CustomTokenRecord *records, size_t capacity, size_t *count)
    {
      if (records == nullptr || count == nullptr)
        return false;
      std::unique_ptr<uint8_t[]> blob(new (std::nothrow) uint8_t[kCustomTokenBlobMax]);
      if (!blob)
        return false;
      nvs_handle_t handle = 0;
      if (nvs_open(kNamespace, NVS_READONLY, &handle) != ESP_OK)
        return false;
      size_t length = kCustomTokenBlobMax;
      const esp_err_t status = nvs_get_blob(handle, kKey, blob.get(), &length);
      nvs_close(handle);
      if (status != ESP_OK)
      {
        secure_zero(blob.get(), kCustomTokenBlobMax);
        return false;
      }
      const bool ok = custom_token_deserialize(blob.get(), length, records, capacity, count);
      secure_zero(blob.get(), kCustomTokenBlobMax);
      return ok;
    }

    bool nvs_save(void *, const CustomTokenRecord *, size_t)
    {
      std::unique_ptr<uint8_t[]> blob(new (std::nothrow) uint8_t[kCustomTokenBlobMax]);
      if (!blob)
        return false;
      size_t size = 0;
      const bool serialized = custom_token_serialize(blob.get(), kCustomTokenBlobMax, &size);
      bool ok = false;
      if (serialized)
      {
        nvs_handle_t handle = 0;
        if (nvs_open(kNamespace, NVS_READWRITE, &handle) == ESP_OK)
        {
          ok = nvs_set_blob(handle, kKey, blob.get(), size) == ESP_OK &&
               nvs_commit(handle) == ESP_OK;
          nvs_close(handle);
        }
      }
      secure_zero(blob.get(), kCustomTokenBlobMax);
      return ok;
    }

  }

  bool custom_tokens_nvs_begin()
  {
    const CustomTokenStore store = {nullptr, nvs_load, nvs_save};
    return custom_tokens_bind_store(store);
  }

}

#endif
