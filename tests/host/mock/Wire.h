// Minimal TwoWire mock for tests/host/board_port_compile_check.ps1.
#ifndef HEXWALLET_MOCK_WIRE_H
#define HEXWALLET_MOCK_WIRE_H

#include <stdint.h>
#include <stddef.h>

class TwoWire {
 public:
  bool begin(int sda, int scl, uint32_t frequency = 0) {
    (void)sda; (void)scl; (void)frequency; return true;
  }
  void beginTransmission(uint8_t addr) { (void)addr; }
  uint8_t endTransmission(bool stopBit = true) { (void)stopBit; return 0; }
  size_t write(uint8_t data) { (void)data; return 1; }
  int requestFrom(uint8_t addr, uint8_t len) { (void)addr; return len; }
  int available(void) { return 0; }
  int read(void) { return -1; }
};

extern TwoWire Wire;
// The ESP32 core exposes a second controller as Wire1; the board port uses it
// for the dedicated secure-element bus.
extern TwoWire Wire1;

#endif  // HEXWALLET_MOCK_WIRE_H
