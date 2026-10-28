// Only the platform entropy and Serial surface are substituted. All key
// derivation and signing code is the real firmware WalletSecurity.cpp.
#include <windows.h>
#include <bcrypt.h>
#include <Arduino.h>
#include <stdlib.h>
HardwareSerial Serial;
void esp_fill_random(void *buffer, size_t size) {
  if (size > ULONG_MAX || BCryptGenRandom(nullptr, static_cast<PUCHAR>(buffer),
      static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) abort();
}
