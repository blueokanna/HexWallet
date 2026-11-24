// Minimal Arduino compatibility shim for host-side self-tests. The firmware
// files include <Arduino.h> mostly for the convenience of the build system;
// nothing in the tested units depends on Arduino APIs.
#ifndef HXW_HOST_ARDUINO_H
#define HXW_HOST_ARDUINO_H

#include <stddef.h>
#include <stdint.h>

typedef unsigned char byte;

#define SET_LOOP_TASK_STACK_SIZE(n)
#define INPUT 0
#define OUTPUT 1
#define HEX 16

class HardwareSerial {
 public:
  int available() { return 0; }
  int read() { return -1; }
  int peek() { return -1; }
  size_t write(uint8_t) { return 1; }
  void print(unsigned long, int) {}
  void print(const char *) {}
  void print(char) {}
  void print(int) {}
  void print(unsigned int) {}
  void print(long) {}
  void print(unsigned long) {}
  void print(unsigned long long) {}
  void println() {}
  void println(const char *) {}
  void println(int) {}
  void println(unsigned int) {}
  void println(long) {}
  void println(unsigned long) {}
  void println(unsigned long long) {}
};

extern HardwareSerial Serial;
uint32_t millis();
void delay(uint32_t ms);

#endif
