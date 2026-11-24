#pragma once
#include <stdint.h>

namespace hexwallet {
enum class CameraRead : uint8_t { Pending, Busy, Unavailable, Memory, Frame, Code, Format, Ready, Cancelled };
CameraRead camera_backup_start();
void camera_backup_cancel();
bool camera_backup_take(CameraRead &status, char (&key)[65]);
}
