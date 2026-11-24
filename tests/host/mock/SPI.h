// Minimal SPI mock for tests/host/board_port_compile_check.ps1.
#ifndef HEXWALLET_MOCK_SPI_H
#define HEXWALLET_MOCK_SPI_H

#include <stdint.h>
#include <stddef.h>

#define SPI_MODE0 0
#define MSBFIRST 0
#define FSPI 0
#define HSPI 1
#define VSPI 2

class SPISettings {
 public:
  SPISettings() : _clk(0), _order(0), _mode(0) {}
  SPISettings(uint32_t clk, uint8_t order, uint8_t mode)
      : _clk(clk), _order(order), _mode(mode) {}

  uint32_t clock() const { return _clk; }
  uint8_t mode() const { return _mode; }
 private:
  uint32_t _clk;
  uint8_t _order;
  uint8_t _mode;
};

class SPIClass {
 public:
  SPIClass() : _bus(0) {}
  explicit SPIClass(uint8_t bus) : _bus(bus) {}
  bool begin(int8_t sck, int8_t miso, int8_t mosi, int8_t ss) {
#ifdef HEXWALLET_SHARED_SPI_TEST
    extern bool board_test_spi_begin(SPIClass *, int, int, int, int);
    return board_test_spi_begin(this, sck, miso, mosi, ss);
#else
    (void)sck; (void)miso; (void)mosi; (void)ss;
    return true;
#endif
  }
  void setFrequency(uint32_t freq) { (void)freq; }
  void beginTransaction(SPISettings settings) {
    (void)settings;
#ifdef HEXWALLET_SHARED_SPI_TEST
    extern void board_test_spi_transaction(SPIClass *, bool, uint32_t, uint8_t);
    board_test_spi_transaction(this, true, settings.clock(), settings.mode());
#endif
  }
  void endTransaction(void) {
#ifdef HEXWALLET_SHARED_SPI_TEST
    extern void board_test_spi_transaction(SPIClass *, bool, uint32_t, uint8_t);
    board_test_spi_transaction(this, false, 0, 0);
#endif
  }
  void write(uint8_t data) {
#ifdef HEXWALLET_BOARD_RUNTIME_TEST
    extern void board_test_spi_write(uint8_t);
    board_test_spi_write(data);
#else
    (void)data;
#endif
  }
  void write16(uint16_t data) { (void)data; }
  void writeBytes(const uint8_t *data, size_t size) {
#ifdef HEXWALLET_BOARD_RUNTIME_TEST
    extern void board_test_spi_write_bytes(const uint8_t *, size_t);
    board_test_spi_write_bytes(data, size);
#else
    (void)data; (void)size;
#endif
  }
  uint8_t transfer(uint8_t data) {
#if defined(HEXWALLET_NFC_RUNTIME_TEST) || defined(HEXWALLET_SHARED_SPI_TEST)
    extern uint8_t nfc_test_transfer(uint8_t);
    return nfc_test_transfer(data);
#else
    return data;
#endif
  }

 private:
  uint8_t _bus;
};

extern SPIClass SPI;

#endif  // HEXWALLET_MOCK_SPI_H
