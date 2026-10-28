#pragma once
#include <stddef.h>
#include <stdint.h>
struct TwoWire {
  size_t capacity = 260, queued = 0, written = 0, receive = 260;
  int reads = 0, fail_read_at = -1, ends = 0;
  uint8_t address = 0, status = 0;
  bool begins = true, short_write = false;
  size_t setBufferSize(size_t) { return capacity; }
  bool begin(int, int, uint32_t) { return begins; }
  void setTimeOut(uint16_t) {}
  void end() { ++ends; }
  void beginTransmission(uint8_t value) { address = value; queued = 0; }
  size_t write(const uint8_t *, size_t size) {
    queued = short_write ? size - 1 : size;
    return queued;
  }
  void flush() { queued = 0; }
  uint8_t endTransmission(bool) { written = queued; return status; }
  size_t requestFrom(uint8_t value, size_t, bool) { address = value; reads = 0; return receive; }
  int available() { return static_cast<int>(receive) - reads; }
  int read() { return reads++ == fail_read_at ? -1 : 0x5a; }
};
extern TwoWire Wire1;
