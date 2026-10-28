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
// NFC (phone link) - NXP PN7161 over SPI.
//
// The pin map is board-specific and only the profiles that carry verified
// schematic nets define it (currently board 7). Anywhere else WalletNfcPort
// reports NotConfigured and only the USB link is available - guessing pins
// would silently drive an unrelated peripheral.
// ---------------------------------------------------------------------------

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
// BOOT button: long-press enables the USB data transport for one window.
#define HEXWALLET_PIN_USER_BUTTON HEXWALLET_PIN_BUTTON_1

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
#define HEXWALLET_PIN_USER_BUTTON HEXWALLET_PIN_BUTTON_1

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
// The BOOT strap button is the only physical key available without the
// XL9555 expander. Long-press gates the USB data transport.
#define HEXWALLET_PIN_USER_BUTTON 0
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
// No verified user button is exposed on this board (P0.00 is the reset strap),
// so board_has_user_button() stays false and USB data cannot be opened there.
#define HEXWALLET_BOARD_NAME "T-Echo Lite Kit"

// ---------------------------------------------------------------------------
// HexWallet ESP32-P4 + SE051C2HQ1 + 2.9" 128x296 e-paper (board rev A)
//
// Every assignment below is a net present in the EasyEDA Pro project
// `c26102103` (ProPrj_c26102103_2026-10-28.epro2). The pad number in each
// comment is the ESP32-P4 package pad the net lands on, so the GPIO column can
// be re-derived from the chip datasheet pin table before first power-on; the
// GPIO column itself is not stored anywhere inside the project file.
//
//   pad  7 SPI_CLK   pad 15 IRQ        pad 33 SW1  (user button)
//   pad  8 SPI_MOSI  pad 16 VEN        pad 32 SW2
//   pad 10 SPI_MISO  pad 17 EINK_CS    pad 31 SW3
//   pad 14 SPI_NSS   pad 18 EINK_RST   pad 30 SW4
//   pad 11 050_SDA   pad 19 EINK_BUSY  pad 35 BOOT strap
//   pad 12 050_SCL   pad 20 EINK_DC    pad 34 DWL_REQ
//   pad 13 050_RST   pad 22 BAT_ADC
//
// MIPI DSI (pads 35-40) carries no net on this revision: the 2.9" panel is the
// SPI SSD1680-class part, so there is no DSI display path and none is compiled.
// ---------------------------------------------------------------------------
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_ESP32P4_EINK

#define HEXWALLET_HAS_DISPLAY 1
#define HEXWALLET_DISPLAY_KIND_EINK 1
// Native SSD1680 driver (EinkPanel.cpp) instead of the GxEPD2 backend.
#define HEXWALLET_EPD_NATIVE_SSD1680 1

#define HEXWALLET_EPD_WIDTH 128
#define HEXWALLET_EPD_HEIGHT 296
#define HEXWALLET_EPD_PIN_SCK 7    // pad 7
#define HEXWALLET_EPD_PIN_MOSI 8   // pad 8
#define HEXWALLET_EPD_PIN_MISO -1  // panel is write-only on the shared bus
#define HEXWALLET_EPD_PIN_CS 16    // pad 17
#define HEXWALLET_EPD_PIN_DC 19    // pad 20
#define HEXWALLET_EPD_PIN_RST 17   // pad 18
#define HEXWALLET_EPD_PIN_BUSY 18  // pad 19
// SSD1680 write cycles are reliable well past this; 8 MHz keeps the 4.7 KiB
// frame upload under 5 ms without pushing the panel's setup times.
#define HEXWALLET_EPD_SPI_FREQ 8000000U

// SCK/MOSI/MISO/CS are shared between the panel and the PN7161, so the bus is
// initialised once here with the MISO line the panel itself never reads.
#define HEXWALLET_SHARED_SPI_PIN_SCK 7
#define HEXWALLET_SHARED_SPI_PIN_MOSI 8
#define HEXWALLET_SHARED_SPI_PIN_MISO 9

// NXP SE051C2HQ1 on its own I2C bus, plus a hardware reset line.
#define HEXWALLET_SE051_I2C_SDA 10    // pad 11
#define HEXWALLET_SE051_I2C_SCL 11    // pad 12
#define HEXWALLET_SE051_PIN_RESET 12  // pad 13
#define HEXWALLET_SE051_I2C_ADDRESS 0x48

// PN7161 NFC front end in SPI mode; NSS is its own chip select.
#define HEXWALLET_NFC_PN7161 1
#define HEXWALLET_NFC_PIN_SCK 7    // pad 7
#define HEXWALLET_NFC_PIN_MOSI 8   // pad 8
#define HEXWALLET_NFC_PIN_MISO 9   // pad 10
#define HEXWALLET_NFC_PIN_CS 13    // pad 14
#define HEXWALLET_NFC_PIN_IRQ 14   // pad 15
#define HEXWALLET_NFC_PIN_VEN 15   // pad 16

#define HEXWALLET_PIN_BUTTON_1 33  // pad 64, SW1
#define HEXWALLET_PIN_BUTTON_2 32  // pad 63, SW2
#define HEXWALLET_PIN_BUTTON_3 31  // pad 61, SW3
#define HEXWALLET_PIN_BUTTON_4 30  // pad 60, SW4
#define HEXWALLET_PIN_USER_BUTTON HEXWALLET_PIN_BUTTON_1

// R11/R12 on the BAT_ADC net are the same device id, i.e. an equal divider, so
// the shared 1:2 scaling in read_battery_mv() is correct for this board.
#define HEXWALLET_PIN_BAT_VOLT 20  // pad 22

// Gate-driver and boost rails of the bare 2.9" panel (GDR/RESE/PREVGH/PREVGL on
// the 26-pin FPC) are tied to passive networks only - there is no GPIO to drive
// and none is invented here.
#define HEXWALLET_BOARD_NAME "HexWallet P4 E-Paper 2.9"

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
// The BOOT strap button is the physical USB-enable control.
#define HEXWALLET_PIN_USER_BUTTON 0
#define HEXWALLET_BOARD_NAME "Headless CLI"

// ---------------------------------------------------------------------------
// Default: no display hardware selected.
// ---------------------------------------------------------------------------
#else
#define HEXWALLET_PIN_USER_BUTTON -1
#define HEXWALLET_BOARD_NAME "None"
#endif

#endif  // HEXWALLET_BOARD_PINS_H
