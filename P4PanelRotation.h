#pragma once
#include "EinkFrame.h"

namespace hexwallet {
// Board 7 only. The display task owns the DMA buffers and the blocking PPA
// client. The source is the aligned, full 296 x 128 RGB565 LVGL buffer.
bool p4_panel_rotation_begin(uint8_t *unused_frame);
void p4_panel_rotation_end();
bool p4_panel_rotate_mono(const uint8_t *frame, EinkRect dirty, uint8_t *out);
}
