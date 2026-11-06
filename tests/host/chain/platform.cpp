// Only the platform entropy and Serial surface are substituted. All key
// derivation and signing code is the real firmware WalletSecurity.cpp.
#include <windows.h>
#include <bcrypt.h>
#include <Arduino.h>
#include <stdlib.h>
HardwareSerial Serial;
#if defined(HEXWALLET_TEST_BOOT_ENTROPY)
#include <bootloader_random.h>
namespace boot_entropy_test {
bool adc_enabled;
unsigned starts, reads, fail_on;
}
void bootloader_random_enable() {
  if (boot_entropy_test::adc_enabled) abort();
  boot_entropy_test::adc_enabled = true;
  ++boot_entropy_test::starts;
}
void bootloader_random_disable() {
  if (!boot_entropy_test::adc_enabled) abort();
  boot_entropy_test::adc_enabled = false;
}
void esp_fill_random(void *buffer, size_t size) {
  using namespace boot_entropy_test;
  if (!adc_enabled || size != 32) abort();
  ++reads;
  auto out = static_cast<uint8_t *>(buffer);
  for (size_t i = 0; i < size; ++i)
    out[i] = reads == fail_on ? 0 : static_cast<uint8_t>((reads - 1) * size + i);
}
#else
void esp_fill_random(void *buffer, size_t size) {
  if (size > ULONG_MAX || BCryptGenRandom(nullptr, static_cast<PUCHAR>(buffer),
      static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) abort();
}
#endif
