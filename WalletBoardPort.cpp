#include "WalletBoardPort.h"

namespace hexwallet {

// A panel driver is hardware-specific. Keeping this fail-closed default avoids
// silently running a wallet UI on an uninitialized or wrongly wired display.
// Replace these functions with the LVGL port for the selected controller.
bool board_display_init() {
  return false;
}

void board_display_service() {
}

uint16_t board_display_width() {
  return 0;
}

uint16_t board_display_height() {
  return 0;
}

}  // namespace hexwallet
