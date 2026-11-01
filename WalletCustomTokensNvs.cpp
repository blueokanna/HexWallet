#include "WalletCustomTokens.h"

#if defined(ARDUINO)

#include <nvs.h>

#include "CryptoPrimitives.h"

namespace hexwallet {
namespace {

// One blob, one namespace. The table is small and rewritten rarely, so a single
// keyspace entry with a whole-blob digest beats eight partial records.
constexpr const char *kNamespace = "hxctok";
constexpr const char *kKey = "table";

bool nvs_load(void *, CustomTokenRecord *records, size_t capacity, size_t *count) {
  if (records == nullptr || count == nullptr) return false;
  nvs_handle_t handle = 0;
  if (nvs_open(kNamespace, NVS_READONLY, &handle) != ESP_OK) return false;
  uint8_t blob[kCustomTokenBlobMax];
  size_t length = sizeof(blob);
  const esp_err_t status = nvs_get_blob(handle, kKey, blob, &length);
  nvs_close(handle);
  if (status != ESP_OK) {
    secure_zero(blob, sizeof(blob));
    return false;
  }
  const bool ok = custom_token_deserialize(blob, length, records, capacity, count);
  secure_zero(blob, sizeof(blob));
  return ok;
}

bool nvs_save(void *, const CustomTokenRecord *, size_t) {
  uint8_t blob[kCustomTokenBlobMax];
  size_t size = 0;
  const bool serialized = custom_token_serialize(blob, sizeof(blob), &size);
  bool ok = false;
  if (serialized) {
    nvs_handle_t handle = 0;
    if (nvs_open(kNamespace, NVS_READWRITE, &handle) == ESP_OK) {
      // nvs_set_blob() only reaches flash after nvs_commit(); reporting success
      // earlier would leave a token listed that a reboot forgets.
      ok = nvs_set_blob(handle, kKey, blob, size) == ESP_OK &&
           nvs_commit(handle) == ESP_OK;
      nvs_close(handle);
    }
  }
  secure_zero(blob, sizeof(blob));
  return ok;
}

}  // namespace

bool custom_tokens_nvs_begin() {
  const CustomTokenStore store = {nullptr, nvs_load, nvs_save};
  return custom_tokens_bind_store(store);
}

}  // namespace hexwallet

#endif  // ARDUINO
