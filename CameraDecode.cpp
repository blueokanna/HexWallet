#include "CameraDecode.h"
#include "WalletSecurity.h"
#include "src/quirc/quirc.h"
#include <cstdlib>
#include <cstring>

namespace hexwallet {
CameraRead camera_decode_backup(const uint8_t *image, size_t width, size_t height, char (&key)[65]) {
  secure_zero(key, sizeof(key));
  if (!image || width == 0 || height == 0 || width > 640 || height > 400) return CameraRead::Frame;
  quirc *decoder = quirc_new();
  if (!decoder) return CameraRead::Memory;
  struct Scratch { quirc_code code; quirc_data data; };
  auto *scratch = static_cast<Scratch *>(calloc(1, sizeof(Scratch)));
  CameraRead status = CameraRead::Memory;
  if (scratch && quirc_resize(decoder, int(width), int(height)) == 0) {
    uint8_t *pixels = quirc_begin(decoder, nullptr, nullptr);
    memcpy(pixels, image, width * height);
    quirc_end(decoder);
    status = CameraRead::Code;
    if (quirc_count(decoder) == 1) {
      quirc_extract(decoder, 0, &scratch->code);
      if (quirc_decode(&scratch->code, &scratch->data) == QUIRC_SUCCESS) {
        const auto &data = scratch->data;
        const int len = data.payload_len;
        const bool hex = len == 64;
        bool valid = hex || len == 51 || len == 52 || (len == 58 && !memcmp(data.payload, "6P", 2));
        const char *alphabet = hex ? "0123456789abcdefABCDEF" : "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for (int i = 0; valid && i < len; ++i) valid = data.payload[i] && strchr(alphabet, data.payload[i]);
        status = valid ? CameraRead::Ready : CameraRead::Format;
        if (valid) memcpy(key, data.payload, len);
      }
    }
    secure_zero(pixels, width * height);
  }
  if (scratch) { secure_zero(scratch, sizeof(*scratch)); free(scratch); }
  quirc_destroy(decoder);
  return status;
}
}
