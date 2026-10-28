#include "Se051ArduinoPort.h"
#if HEXWALLET_ENABLE_NXP_SE051
#include <Arduino.h>
#include <Wire.h>
#include <string.h>
#include "WalletConfig.h"
#include "WalletBoardPins.h"
#ifndef T1oI2C
#error "Build NXP SDK with T1oI2C"
#endif
#include <i2c_a7.h>
#include <sm_timer.h>
#if !defined(HEXWALLET_SE051_I2C_SDA) || !defined(HEXWALLET_SE051_PIN_RESET)
#error "Select a board with verified SE051 pins"
#endif
#if defined(HEXWALLET_SE051_PORT_TEST)
extern uintptr_t se051_test_task();
#else
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#endif

namespace {
constexpr size_t kFrameCapacity = 260; // NXP MAX_DATA_LEN for T1oI2C
constexpr uint8_t kAddress = HEXWALLET_SE051_I2C_ADDRESS;
static_assert(kAddress > 0 && kAddress < 0x78, "Expected 7-bit SE address");
struct PortState { bool opened; bool poisoned; uintptr_t owner; };
PortState port{};
uintptr_t current_task() {
#if defined(HEXWALLET_SE051_PORT_TEST)
  return se051_test_task();
#else
  return reinterpret_cast<uintptr_t>(xTaskGetCurrentTaskHandle());
#endif
}
bool valid(void *context, unsigned char bus, unsigned char address) {
  // NXP passes 0x90 (8-bit). Wire takes 0x48 (7-bit).
  return context == &port && port.opened && !port.poisoned &&
      port.owner == current_task() && bus == I2C_BUS_0 &&
      address == static_cast<unsigned char>(kAddress << 1);
}
void wipe(uint8_t *buffer, size_t length) {
  volatile uint8_t *p = buffer;
  while (length-- != 0) *p++ = 0;
}
}
namespace hexwallet {
bool se051_transport_in_use() { return port.opened; }
}
extern "C" i2c_error_t axI2CInit(void **context, const char *device) {
  if (context == nullptr) return I2C_FAILED;
  *context = nullptr;
  if (port.opened || (device != nullptr && strcmp(device, "se051") != 0))
    return I2C_FAILED;
  // Never split a T=1 frame into separate I2C transactions.
  if (Wire1.setBufferSize(kFrameCapacity) < kFrameCapacity) return I2C_FAILED;
  if (!Wire1.begin(HEXWALLET_SE051_I2C_SDA, HEXWALLET_SE051_I2C_SCL, 100000)) {
    Wire1.end();
    return I2C_FAILED;
  }
  Wire1.setTimeOut(100);
  pinMode(HEXWALLET_SE051_PIN_RESET, OUTPUT);
  digitalWrite(HEXWALLET_SE051_PIN_RESET, LOW);
  delay(10);
  digitalWrite(HEXWALLET_SE051_PIN_RESET, HIGH);
  delay(10);
  port = {true, false, current_task()};
  *context = &port;
  return I2C_OK;
}
extern "C" void axI2CTerm(void *context, int mode) {
  (void)mode;
  if (context != &port || !port.opened || port.owner != current_task()) return;
  digitalWrite(HEXWALLET_SE051_PIN_RESET, LOW);
  Wire1.end();
  port = {};
}
extern "C" i2c_error_t axI2CWrite(void *context, unsigned char bus,
    unsigned char address, unsigned char *data, unsigned short length) {
  if (!valid(context, bus, address) || data == nullptr || length == 0 ||
      length > kFrameCapacity) return I2C_FAILED;
  Wire1.beginTransmission(kAddress);
  if (Wire1.write(data, length) != length) {
    // ESP32 Wire::flush clears txLength. Release its transaction lock with an
    // empty probe; never send the truncated frame or retry a stateful command.
    Wire1.flush();
    Wire1.endTransmission(true);
    port.poisoned = true;
    return I2C_FAILED;
  }
  const uint8_t status = Wire1.endTransmission(true);
  if (status == 0) return I2C_OK;
  if (status == 2) return I2C_NACK_ON_ADDRESS;
  port.poisoned = true; // acceptance is uncertain after data NACK or timeout
  return status == 5 ? I2C_TIME_OUT : I2C_FAILED;
}
extern "C" i2c_error_t axI2CRead(void *context, unsigned char bus,
    unsigned char address, unsigned char *data, unsigned short length) {
  if (data == nullptr || length == 0 || length > kFrameCapacity) return I2C_FAILED;
  wipe(data, length);
  if (!valid(context, bus, address)) return I2C_FAILED;
  const size_t received = Wire1.requestFrom(kAddress, static_cast<size_t>(length), true);
  if (received == 0) return I2C_NO_DATA;
  if (received != length) {
    for (size_t i = 0; i < received && Wire1.available() > 0; ++i) Wire1.read();
    port.poisoned = true;
    return I2C_FAILED;
  }
  for (size_t i = 0; i < length; ++i) {
    const int value = Wire1.read();
    if (value < 0) {
      wipe(data, length);
      port.poisoned = true;
      return I2C_FAILED;
    }
    data[i] = static_cast<uint8_t>(value);
  }
  return I2C_OK;
}
extern "C" uint32_t sm_initSleep() { return 0; }
extern "C" void sm_sleep(uint32_t milliseconds) { delay(milliseconds); }
extern "C" void sm_usleep(uint32_t microseconds) {
  if (microseconds >= 1000) delay(microseconds / 1000);
  if (microseconds % 1000 != 0) delayMicroseconds(microseconds % 1000);
}
#else
namespace hexwallet {
bool se051_transport_in_use() { return false; }
}
#endif
