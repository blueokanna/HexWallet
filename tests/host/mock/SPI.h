// Minimal SPI mock for tests/host/board_port_compile_check.ps1.
#ifndef HEXWALLET_MOCK_SPI_H
#define HEXWALLET_MOCK_SPI_H

#include <stdint.h>
#include <stddef.h>

#define SPI_MODE0 0
#define MSBFIRST 0

class SPISettings {
 public:
  SPISettings() : _clk(0), _order(0), _mode(0) {}
  SPISettings(uint32_t clk, uint8_t order, uint8_t mode)
      : _clk(clk), _order(order), _mode(mode) {}

 private:
  uint32_t _clk;
  uint8_t _order;
  uint8_t _mode;
};

class SPIClass {
 public:
  void begin(int8_t sck, int8_t miso, int8_t mosi, int8_t ss) {
    (void)sck; (void)miso; (void)mosi; (void)ss;
  }
  void setFrequency(uint32_t freq) { (void)freq; }
  void beginTransaction(SPISettings settings) { (void)settings; }
  void endTransaction(void) {}
  void write(uint8_t data) { (void)data; }
  void write16(uint16_t data) { (void)data; }
  void writeBytes(const uint8_t *data, size_t size) { (void)data; (void)size; }
  uint8_t transfer(uint8_t data) { return data; }
};

extern SPIClass SPI;

#endif  // HEXWALLET_MOCK_SPI_H
