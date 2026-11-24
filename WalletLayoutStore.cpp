#include "WalletLayoutStore.h"
#if defined(ARDUINO_ARCH_ESP32)
#include <nvs.h>
#include <esp_err.h>
#endif

namespace hexwallet {
const char *load_asset_layout(AssetLayout &layout) {
  layout = AssetLayout::List;
#if defined(ARDUINO_ARCH_ESP32)
  nvs_handle_t handle;
  esp_err_t result = nvs_open("hw-ui", NVS_READONLY, &handle);
  if (result == ESP_ERR_NVS_NOT_FOUND) return nullptr;
  if (result != ESP_OK) return esp_err_to_name(result);
  uint8_t value = 0;
  result = nvs_get_u8(handle, "layout", &value);
  nvs_close(handle);
  if (result == ESP_ERR_NVS_NOT_FOUND) return nullptr;
  if (result != ESP_OK) return esp_err_to_name(result);
  if (value > static_cast<uint8_t>(AssetLayout::Card)) return "INVALID_LAYOUT";
  layout = static_cast<AssetLayout>(value);
#endif
  return nullptr;
}

const char *save_asset_layout(AssetLayout layout) {
  if (layout > AssetLayout::Card) return "INVALID_LAYOUT";
#if defined(ARDUINO_ARCH_ESP32)
  nvs_handle_t handle;
  esp_err_t result = nvs_open("hw-ui", NVS_READWRITE, &handle);
  if (result != ESP_OK) return esp_err_to_name(result);
  result = nvs_set_u8(handle, "layout", static_cast<uint8_t>(layout));
  if (result == ESP_OK) result = nvs_commit(handle);
  nvs_close(handle);
  return result == ESP_OK ? nullptr : esp_err_to_name(result);
#else
  return "NO_NVS";
#endif
}
}
