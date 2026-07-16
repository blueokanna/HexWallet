#ifndef HEXWALLET_BOARD_PORT_H
#define HEXWALLET_BOARD_PORT_H

#include <stdint.h>

namespace hexwallet {

// Implement these functions for the selected board in WalletBoardPort.cpp.
// The port owns the SPI/I2C bus, panel driver, LVGL draw buffers, flush callback,
// input device, and power sequencing. It must call lv_init() before returning.
bool board_display_init();
void board_display_service();
uint16_t board_display_width();
uint16_t board_display_height();

}  // namespace hexwallet

#endif
