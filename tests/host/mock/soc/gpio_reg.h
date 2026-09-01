// Minimal GPIO register mock for board_port_compile_check.ps1 (ESP32-S3).
// Names match the real ESP32-S3 soc/gpio_reg.h; the arduino-cli device build
// in CI validates them against the genuine headers.
#ifndef HEXWALLET_MOCK_GPIO_REG_H
#define HEXWALLET_MOCK_GPIO_REG_H

#define GPIO_OUT_W1TS_REG   0x60004014
#define GPIO_OUT_W1TC_REG   0x60004018
#define GPIO_OUT1_W1TS_REG  0x60004024
#define GPIO_OUT1_W1TC_REG  0x60004028

#endif  // HEXWALLET_MOCK_GPIO_REG_H
