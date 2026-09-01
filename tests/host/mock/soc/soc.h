// Minimal ESP-IDF register-access mock for board_port_compile_check.ps1.
// REG_WRITE is the same macro family the real soc/soc.h provides. Register
// addresses here are for the ESP32-S3 target and are never dereferenced in
// this host check; the authoritative names are validated by the arduino-cli
// device build in CI against the genuine headers.
#ifndef HEXWALLET_MOCK_SOC_H
#define HEXWALLET_MOCK_SOC_H

#include <stdint.h>

#define REG_WRITE(_reg, _val) (*(volatile uint32_t *)(_reg) = (uint32_t)(_val))
#define REG_READ(_reg) (*(volatile uint32_t *)(_reg))

#endif  // HEXWALLET_MOCK_SOC_H
