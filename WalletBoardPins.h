#ifndef HEXWALLET_BOARD_PINS_H
#define HEXWALLET_BOARD_PINS_H

// Verified pin assignments for every supported LilyGO board.
//
// Sources: official LilyGO example code (pins_config.h / pin_config.h in
// Xinyuan-LilyGO/T-Display-S3-AMOLED, T-Display-S3, T-Deck-Max) and the
// official pinout diagrams. Values are hardware constants - do not "fix"
// them to match a different board revision without checking the schematic.
//
// nRF52 (T-Echo Lite) pin numbers follow the Adafruit nRF52 mapping:
// P0.xx = xx (0..31), P1.xx = 32 + xx (32..47).

#include "WalletConfig.h"

// ---------------------------------------------------------------------------
// T-Display S3 AMOLED / AMOLED Plus  (ESP32-S3, RM67162, 240x536, SPI)
// ---------------------------------------------------------------------------
#if HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED || HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED_PLUS

#define HEXWALLET_HAS_DISPLAY 1
#define HEXWALLET_DISPLAY_KIND_COLOR 1

#define HEXWALLET_LCD_PIN_SCK 47
#define HEXWALLET_LCD_PIN_MOSI 18
#define HEXWALLET_LCD_PIN_MISO -1
#define HEXWALLET_LCD_PIN_CS 6
#define HEXWALLET_LCD_PIN_DC 7
#define HEXWALLET_LCD_PIN_RST 17
#define HEXWALLET_LCD_PIN_TE 9
#define HEXWALLET_LCD_WIDTH 240
#define HEXWALLET_LCD_HEIGHT 536
#define HEXWALLET_LCD_SPI_FREQ 80000000U

// Shared by both AMOLED variants: power LED / backlight rail and battery ADC.
#define HEXWALLET_PIN_LED 38
#define HEXWALLET_PIN_BAT_VOLT 4
#define HEXWALLET_PIN_BUTTON_1 0
#define HEXWALLET_PIN_BUTTON_2 21

// Capacitive touch (CST816S) on the touch variant; I2C bus is shared with RTC.
#define HEXWALLET_TOUCH_CST816S 1
#define HEXWALLET_PIN_TOUCH_SDA 3
#define HEXWALLET_PIN_TOUCH_SCL 2
#define HEXWALLET_PIN_TOUCH_INT 21
#define HEXWALLET_PIN_TOUCH_RST 38

#if HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED_PLUS
// PMU (AXP313A): I2C 0x36 on the shared bus, plus its own IRQ line.
#define HEXWALLET_PIN_PMU_IRQ 1
#define HEXWALLET_PIN_RTC_INT 15
// microSD on the dedicated SPI bus.
#define HEXWALLET_PIN_SD_MISO 13
#define HEXWALLET_PIN_SD_MOSI 12
#define HEXWALLET_PIN_SD_SCK 14
#define HEXWALLET_PIN_SD_CS 11
#define HEXWALLET_BOARD_NAME "T-Display S3 AMOLED Plus"
#else
#define HEXWALLET_BOARD_NAME "T-Display S3 AMOLED"
#endif

// ---------------------------------------------------------------------------
// T-Display S3  (ESP32-S3, ST7789, 170x320, 8-bit parallel)
// ---------------------------------------------------------------------------
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3

#define HEXWALLET_HAS_DISPLAY 1
#define HEXWALLET_DISPLAY_KIND_COLOR 1

#define HEXWALLET_LCD_WIDTH 170
#define HEXWALLET_LCD_HEIGHT 320
#define HEXWALLET_LCD_PIN_BL 38
#define HEXWALLET_LCD_PIN_RST 5
#define HEXWALLET_LCD_PIN_CS 6
#define HEXWALLET_LCD_PIN_DC 7
#define HEXWALLET_LCD_PIN_WR 8
#define HEXWALLET_LCD_PIN_RD 9
#define HEXWALLET_LCD_PIN_D0 39
#define HEXWALLET_LCD_PIN_D1 40
#define HEXWALLET_LCD_PIN_D2 41
#define HEXWALLET_LCD_PIN_D3 42
#define HEXWALLET_LCD_PIN_D4 45
#define HEXWALLET_LCD_PIN_D5 46
#define HEXWALLET_LCD_PIN_D6 47
#define HEXWALLET_LCD_PIN_D7 48

// LCD power gate must be driven high before the panel is usable.
#define HEXWALLET_PIN_POWER_ON 15
#define HEXWALLET_PIN_BAT_VOLT 4
#define HEXWALLET_PIN_BUTTON_1 0
#define HEXWALLET_PIN_BUTTON_2 14

// CST816S touch controller on I2C.
#define HEXWALLET_TOUCH_CST816S 1
#define HEXWALLET_PIN_TOUCH_SDA 17
#define HEXWALLET_PIN_TOUCH_SCL 18
#define HEXWALLET_PIN_TOUCH_INT 16
#define HEXWALLET_PIN_TOUCH_RST 21

#define HEXWALLET_BOARD_NAME "T-Display S3"

// ---------------------------------------------------------------------------
// T-Deck Max  (ESP32-S3, 3.1" E-paper, 240x320, SPI)
//
// Panel: Good Display GDEQ031T10, controller UC8253, B/W with partial
// refresh. Driven through the GxEPD2 library class GxEPD2_310_GDEQ031T10
// (see WalletBoardPort.cpp).
// ---------------------------------------------------------------------------
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_DECK_MAX

#define HEXWALLET_HAS_DISPLAY 1
#define HEXWALLET_DISPLAY_KIND_EINK 1

#define HEXWALLET_EPD_WIDTH 240
#define HEXWALLET_EPD_HEIGHT 320
#define HEXWALLET_EPD_PIN_SCK 36
#define HEXWALLET_EPD_PIN_MOSI 33
#define HEXWALLET_EPD_PIN_MISO -1
#define HEXWALLET_EPD_PIN_CS 34
#define HEXWALLET_EPD_PIN_DC 35
#define HEXWALLET_EPD_PIN_RST 9
#define HEXWALLET_EPD_PIN_BUSY 37
#define HEXWALLET_EPD_PIN_BL 41

#define HEXWALLET_PIN_TOUCH_SCL 14
#define HEXWALLET_PIN_TOUCH_SDA 13
#define HEXWALLET_PIN_TOUCH_INT 12
#define HEXWALLET_PIN_BAT_VOLT 4
#define HEXWALLET_BOARD_NAME "T-Deck Max"

// NOTE: the T-Deck Max touch controller is NOT a CST816S (it sits behind the
// XL9555 IO expander), so it is intentionally not wired into the CST816S
// driver; no HEXWALLET_TOUCH_CST816S is defined here.

// ---------------------------------------------------------------------------
// T-Echo Lite Kit  (nRF52840, 1.22" E-paper, 176x192, SPI)
//
// NOTE: this board runs the Adafruit nRF52 core, not the ESP32 core. The
// wallet core (crypto, CLI, session) is portable C++, but this port needs a
// separate build target (see README "Supported hardware"). Pins below use the
// Adafruit nRF52 numbering (P0.xx = xx, P1.xx = 32+xx).
// ---------------------------------------------------------------------------
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_ECHO_LITE

#define HEXWALLET_HAS_DISPLAY 1
#define HEXWALLET_DISPLAY_KIND_EINK 1

#define HEXWALLET_EPD_WIDTH 176
#define HEXWALLET_EPD_HEIGHT 192
#define HEXWALLET_EPD_PIN_SCK 19   // P0.19
#define HEXWALLET_EPD_PIN_MOSI 20  // P0.20
#define HEXWALLET_EPD_PIN_MISO -1
#define HEXWALLET_EPD_PIN_CS 22   // P0.22
#define HEXWALLET_EPD_PIN_DC 21   // P0.21
#define HEXWALLET_EPD_PIN_RST 28  // P0.28
#define HEXWALLET_EPD_PIN_BUSY 3  // P0.03

#define HEXWALLET_PIN_KEY_SDA 36  // P1.4  (TCA8418 keyboard)
#define HEXWALLET_PIN_KEY_SCL 34  // P1.2
#define HEXWALLET_BOARD_NAME "T-Echo Lite Kit"

// ---------------------------------------------------------------------------
// Headless - no display, no touch, no LVGL. Works on ANY supported MCU
// (ESP32, ESP32-S3, nRF52, ...): the authenticated Serial CLI is the only
// interface. Select with HEXWALLET_BOARD_HEADLESS (6), e.g. pass
// `-DHEXWALLET_BOARD=6` as a build flag, or drop a `build_opt.h` containing
// `-DHEXWALLET_BOARD=6` next to HexWallet.ino in the Arduino IDE.
// LVGL is auto-disabled and HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION defaults
// to 1 so transaction approval prints a confirm code over Serial.
// ---------------------------------------------------------------------------
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_HEADLESS

// Deliberately no HEXWALLET_HAS_DISPLAY / display pins / touch / battery.
#define HEXWALLET_BOARD_NAME "Headless CLI"

// ---------------------------------------------------------------------------
// Default: no display hardware selected.
// ---------------------------------------------------------------------------
#else
#define HEXWALLET_BOARD_NAME "None"
#endif

#endif  // HEXWALLET_BOARD_PINS_H
