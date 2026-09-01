// Minimal Arduino core mock used ONLY by tests/host/board_port_compile_check.ps1.
// Provides the exact Arduino surface the board port / UI use, so the driver
// code type-checks without dragging in the whole ESP-IDF graph. The real
// device build (arduino-cli) compiles against the genuine core.
#ifndef HEXWALLET_MOCK_ARDUINO_H
#define HEXWALLET_MOCK_ARDUINO_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#define HIGH 0x1
#define LOW 0x0
#define INPUT 0x0
#define OUTPUT 0x2
#define INPUT_PULLUP 0x5
#define ANALOG 0x3

#define PI 3.1415926535897932384626433832795
#define HALF_PI 1.5707963267948966192313216916398
#define TWO_PI 6.283185307179586476925286766559

void pinMode(uint8_t pin, uint8_t mode);
void digitalWrite(uint8_t pin, uint8_t val);
int digitalRead(uint8_t pin);
void delay(uint32_t ms);
uint32_t millis(void);
int analogRead(uint8_t pin);
int analogReadMilliVolts(uint8_t pin);
void analogReadResolution(uint8_t bits);

void *ps_malloc(size_t size);
void *ps_calloc(size_t n, size_t size);

#define BOARD_HAS_PSRAM 1
#define ARDUINO 10607
#define ESP32 1
#define CONFIG_IDF_TARGET_ESP32S3 1

class String {
 public:
  String() {}
  String(const char *s) { (void)s; }
  const char *c_str() const { return ""; }
};

class Stream {
 public:
  virtual ~Stream() {}
};

class HardwareSerial : public Stream {
 public:
  void begin(uint32_t baud) { (void)baud; }
  size_t print(const char *s) { (void)s; return 0; }
  size_t print(int v) { (void)v; return 0; }
  size_t print(unsigned int v) { (void)v; return 0; }
  size_t print(long v) { (void)v; return 0; }
  size_t print(unsigned long v) { (void)v; return 0; }
  size_t println() { return 0; }
  size_t println(const char *s) { (void)s; return 0; }
  size_t println(int v) { (void)v; return 0; }
  size_t println(unsigned int v) { (void)v; return 0; }
  size_t println(long v) { (void)v; return 0; }
  size_t println(unsigned long v) { (void)v; return 0; }
  size_t println(double v) { (void)v; return 0; }
};

extern HardwareSerial Serial;

#endif  // HEXWALLET_MOCK_ARDUINO_H
