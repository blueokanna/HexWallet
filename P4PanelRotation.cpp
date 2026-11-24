#include "WalletBoardPins.h"
#ifdef ARDUINO_ARCH_ESP32
#include <sdkconfig.h>
#endif
#if defined(ARDUINO_ARCH_ESP32) && defined(CONFIG_IDF_TARGET_ESP32P4) && defined(HEXWALLET_EPD_NATIVE_SSD1680)
#include "P4PanelRotation.h"
#include "WalletSecurity.h"
#include <Arduino.h>
#include <driver/ppa.h>
#include <esp_cache.h>
#include <esp_heap_caps.h>
#include <string.h>

namespace hexwallet {
namespace {
constexpr unsigned width = 296, height = 128, strip = 16;
constexpr size_t tile_bytes = width * strip * 2;
static_assert(tile_bytes % 128 == 0 && height % strip == 0);
ppa_client_handle_t client = nullptr;
uint8_t *tile = nullptr;

esp_err_t rotate_strip(const uint8_t *source, unsigned y) {
  ppa_srm_oper_config_t op{};
  op.in.buffer = source + width * y * 2;
  op.in.pic_w = op.in.block_w = width;
  op.in.pic_h = op.in.block_h = strip;
  op.in.srm_cm = PPA_SRM_COLOR_MODE_RGB565;
  op.out.buffer = tile;
  op.out.buffer_size = tile_bytes;
  op.out.pic_w = strip;
  op.out.pic_h = width;
  op.out.srm_cm = PPA_SRM_COLOR_MODE_RGB565;
  op.scale_x = op.scale_y = 1;
  op.rotation_angle = PPA_SRM_ROTATION_ANGLE_270;
  op.mode = PPA_TRANS_MODE_BLOCKING;
  esp_err_t err = esp_cache_msync(const_cast<void *>(op.in.buffer), tile_bytes, ESP_CACHE_MSYNC_FLAG_DIR_C2M);
  if (err == ESP_OK) err = ppa_do_scale_rotate_mirror(client, &op);
  if (err == ESP_OK) err = esp_cache_msync(tile, tile_bytes, ESP_CACHE_MSYNC_FLAG_DIR_M2C);
  return err;
}
}

void p4_panel_rotation_end() {
  if (client) ppa_unregister_client(client);
  client = nullptr;
  if (tile) {
    secure_zero(tile, tile_bytes);
    esp_cache_msync(tile, tile_bytes, ESP_CACHE_MSYNC_FLAG_DIR_C2M);
    heap_caps_free(tile);
    tile = nullptr;
  }
}

bool p4_panel_rotation_begin(uint8_t *unused_frame) {
  if (!unused_frame || (reinterpret_cast<uintptr_t>(unused_frame) & 127)) return false;
  tile = static_cast<uint8_t *>(heap_caps_aligned_alloc(128, tile_bytes, MALLOC_CAP_DMA | MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
  ppa_client_config_t config{};
  config.oper_type = PPA_OPERATION_SRM;
  esp_err_t result = tile ? ppa_register_client(&config, &client) : ESP_ERR_NO_MEM;
  if (result == ESP_OK) {
    // Verify rotation, stride, both colour bytes and DMA cache visibility on
    // the actual device before the first trusted screen is drawn.
    for (size_t i = 0; i < tile_bytes / 2; ++i) {
      unused_frame[2*i] = uint8_t(i);
      unused_frame[2*i+1] = uint8_t(i >> 8);
    }
    result = rotate_strip(unused_frame, 0);
    for (unsigned y = 0; result == ESP_OK && y < strip; ++y) {
      for (unsigned x = 0; x < width; ++x) {
        if (memcmp(tile + 2*(x*strip + strip-1-y), unused_frame + 2*(y*width+x), 2)) {
          result = ESP_ERR_INVALID_RESPONSE;
          break;
        }
      }
    }
    memset(unused_frame, 0, tile_bytes);
  }
  if (result == ESP_OK) return true;
  Serial.printf("Panel PPA self-check: %s; using CPU rotation\n", esp_err_to_name(result));
  p4_panel_rotation_end();
  return false;
}

bool p4_panel_rotate_mono(const uint8_t *frame, EinkRect dirty, uint8_t *out) {
  if (!client || !frame || !out || dirty.width < width/2 || dirty.height < strip ||
      unsigned(dirty.x) + dirty.width > width || unsigned(dirty.y) + dirty.height > height) return false;
  for (unsigned y = dirty.y / strip * strip; y < unsigned(dirty.y) + dirty.height; y += strip) {
    const auto result = rotate_strip(frame, y);
    if (result != ESP_OK) {
      Serial.printf("Panel PPA transfer: %s; using CPU rotation\n", esp_err_to_name(result));
      p4_panel_rotation_end();
      return false;
    }
    for (unsigned x = dirty.x; x < unsigned(dirty.x) + dirty.width; ++x) {
      // Preserve bits beyond partial damage on the first/last strip.
      const unsigned left = height-y-strip;
      uint8_t packed[2];
      eink_convert_rgb565(tile + 2*x*strip, strip, 1, 1, false, packed, sizeof(packed));
      for (unsigned b = 0; b < 2; ++b) {
        uint8_t mask = 0xff;
        const unsigned bottom = y + strip - 8*b;
        if (bottom <= dirty.y || bottom-8 >= unsigned(dirty.y)+dirty.height) continue;
        if (bottom > unsigned(dirty.y)+dirty.height) mask >>= bottom-(unsigned(dirty.y)+dirty.height);
        if (bottom-8 < dirty.y) mask &= uint8_t(0xffU << (dirty.y-(bottom-8)));
        auto &dest = out[x*(height/8) + left/8 + b];
        dest = uint8_t((dest & ~mask) | (packed[b] & mask));
      }
    }
  }
  secure_zero(tile, tile_bytes);
  // Flush the wipe before giving the scratch buffer to DMA again.
  esp_cache_msync(tile, tile_bytes, ESP_CACHE_MSYNC_FLAG_DIR_C2M);
  return true;
}
}
#endif
