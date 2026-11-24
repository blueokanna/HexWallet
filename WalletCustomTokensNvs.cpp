#include "WalletCustomTokens.h"
#include "WalletConfig.h"

#if defined(ARDUINO)

#include <nvs.h>
#include <memory>
#include <new>

#include "CryptoPrimitives.h"
#if HEXWALLET_BOARD == HEXWALLET_BOARD_ESP32P4_EINK
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <esp_flash.h>
#include <esp_littlefs.h>
#endif

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
      *count = 0;
      const esp_err_t opened = nvs_open(kNamespace, NVS_READONLY, &handle);
      if (opened != ESP_OK) return opened == ESP_ERR_NVS_NOT_FOUND;
      size_t length = kCustomTokenBlobMax;
      const esp_err_t status = nvs_get_blob(handle, kKey, blob.get(), &length);
      nvs_close(handle);
      if (status != ESP_OK)
      {
        secure_zero(blob.get(), kCustomTokenBlobMax);
        return status == ESP_ERR_NVS_NOT_FOUND;
      }
      const bool ok = custom_token_deserialize(blob.get(), length, records, capacity, count);
      secure_zero(blob.get(), kCustomTokenBlobMax);
      return ok;
    }

#if HEXWALLET_BOARD == HEXWALLET_BOARD_ESP32P4_EINK
    constexpr const char *kAssetTable = "/assets/tokens";
    constexpr const char *kTemporaryTable = "/assets/tokens.tmp";
    bool assets_writable = false;

    bool mount_assets()
    {
      const esp_partition_t *part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
          ESP_PARTITION_SUBTYPE_DATA_LITTLEFS, "assets");
      uint32_t physical_size = 0, addressable_size = 0;
      if (!part || esp_flash_get_physical_size(part->flash_chip, &physical_size) != ESP_OK)
        return false;
      const bool layout_8m = physical_size == 0x800000 && part->address == 0x7d0000 && part->size == 0x20000;
      const bool layout_32m = physical_size == 0x2000000 && part->address == 0x800000 && part->size == 0x1800000;
      if ((!layout_8m && !layout_32m) || esp_flash_get_size(part->flash_chip, &addressable_size) != ESP_OK ||
          addressable_size < part->address + part->size)
        return false;
      if (esp_littlefs_mounted("assets")) return true;
      esp_vfs_littlefs_conf_t config{};
      config.partition_label = "assets";
      config.base_path = "/assets";
      const esp_err_t status = esp_vfs_littlefs_register(&config);
      if (status == ESP_OK) return true;
      if (status != ESP_FAIL) return false;
      // Only a completely erased partition can be provisioned automatically.
      // An unreadable block or existing filesystem data must survive a mount failure.
      uint8_t block[4096];
      for (size_t offset = 0; offset < part->size; offset += sizeof(block))
      {
        if (esp_partition_read(part, offset, block, sizeof(block)) != ESP_OK) return false;
        for (uint8_t value : block) if (value != 0xff) return false;
      }
      config.format_if_mount_failed = true;
      return esp_vfs_littlefs_register(&config) == ESP_OK;
    }

    bool asset_load(void *, CustomTokenRecord *records, size_t capacity, size_t *count)
    {
      if (!mount_assets()) return false;
      FILE *file = fopen(kAssetTable, "rb");
      if (!file) return errno == ENOENT && nvs_load(nullptr, records, capacity, count);
      std::unique_ptr<uint8_t[]> blob(new (std::nothrow) uint8_t[kCustomTokenBlobMax]);
      const size_t length = blob ? fread(blob.get(), 1, kCustomTokenBlobMax, file) : 0;
      const bool complete = length && fgetc(file) == EOF && !ferror(file);
      return fclose(file) == 0 && complete && custom_token_deserialize(blob.get(), length, records, capacity, count);
    }

    bool asset_save(void *, const CustomTokenRecord *, size_t)
    {
      if (!assets_writable) return false;
      std::unique_ptr<uint8_t[]> blob(new (std::nothrow) uint8_t[kCustomTokenBlobMax]);
      size_t size = 0;
      if (!blob || !custom_token_serialize(blob.get(), kCustomTokenBlobMax, &size)) return false;
      const int file = open(kTemporaryTable, O_WRONLY | O_CREAT | O_TRUNC, 0600);
      if (file < 0) return false;
      const bool written = write(file, blob.get(), size) == static_cast<ssize_t>(size) && fsync(file) == 0;
      const bool closed = close(file) == 0;
      return written && closed && rename(kTemporaryTable, kAssetTable) == 0;
    }
#else
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
#endif

  }

  bool custom_tokens_nvs_begin()
  {
#if HEXWALLET_BOARD == HEXWALLET_BOARD_ESP32P4_EINK
    const CustomTokenStore store = {nullptr, asset_load, asset_save};
    assets_writable = custom_tokens_bind_store(store);
    return assets_writable;
#else
    const CustomTokenStore store = {nullptr, nvs_load, nvs_save};
    return custom_tokens_bind_store(store);
#endif
  }

}

#endif
