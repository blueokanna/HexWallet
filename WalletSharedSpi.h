#ifndef HEXWALLET_SHARED_SPI_H
#define HEXWALLET_SHARED_SPI_H

#include "WalletBoardPins.h"

#if defined(HEXWALLET_SHARED_SPI_PIN_SCK)
#include <Arduino.h>
#include <SPI.h>

namespace hexwallet {
// Called from the Arduino setup/loop task before either driver starts I/O.
// Later display or NFC retries must not reconfigure the other device's CS.
inline bool board_shared_spi_begin()
{
  static bool ready = false;
  if (!ready)
  {
    pinMode(HEXWALLET_EPD_PIN_CS, OUTPUT);
    digitalWrite(HEXWALLET_EPD_PIN_CS, HIGH);
    pinMode(HEXWALLET_NFC_PIN_CS, OUTPUT);
    digitalWrite(HEXWALLET_NFC_PIN_CS, HIGH);
    ready = SPI.begin(HEXWALLET_SHARED_SPI_PIN_SCK, HEXWALLET_SHARED_SPI_PIN_MISO,
                      HEXWALLET_SHARED_SPI_PIN_MOSI, -1);
  }
  return ready;
}
static_assert(HEXWALLET_EPD_PIN_CS != HEXWALLET_NFC_PIN_CS, "Shared SPI requires independent selects");
#if CONFIG_DISABLE_HAL_LOCKS
#error "Board 7 requires Arduino SPI transaction locks across tasks"
#endif
}
#endif
#endif
