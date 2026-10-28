#include <stdio.h>
#include <string.h>
#include <Wire.h>
#include <i2c_a7.h>
#include "Se051ArduinoPort.h"
TwoWire Wire1;
static uintptr_t task = 1;
uintptr_t se051_test_task() { return task; }
#define CHECK(c) do { if (!(c)) { printf("FAIL %d: %s\n", __LINE__, #c); return 1; } } while (0)
static bool zero(const uint8_t *data, size_t size) {
  for (size_t i = 0; i < size; ++i) if (data[i]) return false;
  return true;
}
int main() {
  void *context = nullptr, *second = nullptr;
  uint8_t frame[260]{};
  CHECK(axI2CInit(nullptr, nullptr) == I2C_FAILED);
  Wire1.capacity = 128;
  CHECK(axI2CInit(&context, nullptr) == I2C_FAILED && context == nullptr);
  Wire1.capacity = 260;
  CHECK(axI2CInit(&context, "se051") == I2C_OK);
  CHECK(hexwallet::se051_transport_in_use());
  CHECK(axI2CInit(&second, nullptr) == I2C_FAILED && second == nullptr);
  CHECK(axI2CWrite(context, 0, 0x90, frame, 260) == I2C_OK);
  CHECK(Wire1.address == 0x48 && Wire1.written == 260);
  CHECK(axI2CWrite(context, 0, 0x48, frame, 260) == I2C_FAILED);
  CHECK(axI2CWrite(context, 1, 0x90, frame, 260) == I2C_FAILED);
  CHECK(axI2CWrite(context, 0, 0x90, frame, 261) == I2C_FAILED);
  task = 2;
  CHECK(axI2CWrite(context, 0, 0x90, frame, 260) == I2C_FAILED);
  axI2CTerm(context, 0);
  CHECK(hexwallet::se051_transport_in_use());
  task = 1;
  CHECK(axI2CRead(context, 0, 0x90, frame, 260) == I2C_OK && frame[259] == 0x5a);
  Wire1.receive = 259;
  CHECK(axI2CRead(context, 0, 0x90, frame, 260) == I2C_FAILED && zero(frame, 260));
  CHECK(axI2CWrite(context, 0, 0x90, frame, 1) == I2C_FAILED);
  axI2CTerm(context, 0);
  CHECK(!hexwallet::se051_transport_in_use());
  CHECK(axI2CInit(&context, nullptr) == I2C_OK);
  Wire1.short_write = true;
  CHECK(axI2CWrite(context, 0, 0x90, frame, 260) == I2C_FAILED);
  CHECK(Wire1.written == 0);
  axI2CTerm(context, 0);
  Wire1.short_write = false;
  CHECK(axI2CInit(&context, nullptr) == I2C_OK);
  Wire1.status = 2;
  CHECK(axI2CWrite(context, 0, 0x90, frame, 1) == I2C_NACK_ON_ADDRESS);
  Wire1.status = 0;
  CHECK(axI2CWrite(context, 0, 0x90, frame, 1) == I2C_OK);
  Wire1.status = 5;
  CHECK(axI2CWrite(context, 0, 0x90, frame, 1) == I2C_TIME_OUT);
  Wire1.status = 0;
  CHECK(axI2CWrite(context, 0, 0x90, frame, 1) == I2C_FAILED);
  axI2CTerm(context, 0);
  CHECK(axI2CInit(&context, nullptr) == I2C_OK);
  Wire1.receive = 260;
  Wire1.fail_read_at = 10;
  CHECK(axI2CRead(context, 0, 0x90, frame, 260) == I2C_FAILED && zero(frame, 260));
  axI2CTerm(context, 0);
  puts("se051-port=pass");
}
