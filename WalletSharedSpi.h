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

inline bool board_spi_check_cs(uint8_t pin, int expected)
{
  if (digitalRead(pin) == expected) return true;
  Serial.print(pin == HEXWALLET_EPD_PIN_CS ? "ERR: EINK_CS (GPIO16)" : "ERR: SPI_NSS (GPIO13)");
  Serial.println(expected == LOW ? " did not go low" : " did not go high");
  return false;
}

// Call only between beginTransaction and endTransaction, while holding the bus.
inline bool board_spi_select(uint8_t pin)
{
  const uint8_t peer = pin == HEXWALLET_EPD_PIN_CS ? HEXWALLET_NFC_PIN_CS : HEXWALLET_EPD_PIN_CS;
  if (!board_spi_check_cs(peer, HIGH) || !board_spi_check_cs(pin, HIGH)) return false;
  digitalWrite(pin, LOW);
  if (board_spi_check_cs(pin, LOW) && board_spi_check_cs(peer, HIGH)) return true;
  digitalWrite(pin, HIGH);
  return false;
}

inline bool board_spi_deselect(uint8_t pin)
{
  digitalWrite(pin, HIGH);
  return board_spi_check_cs(pin, HIGH);
}

static_assert(HEXWALLET_EPD_PIN_CS != HEXWALLET_NFC_PIN_CS, "Shared SPI requires independent selects");
#if CONFIG_DISABLE_HAL_LOCKS
#error "Board 7 requires Arduino SPI transaction locks across tasks"
#endif
}
#endif
#endif
