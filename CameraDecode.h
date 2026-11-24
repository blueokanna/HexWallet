#pragma once
#include "CameraBackup.h"
#include <stddef.h>

namespace hexwallet {
CameraRead camera_decode_backup(const uint8_t *image, size_t width, size_t height, char (&key)[65]);
}
