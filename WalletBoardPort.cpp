#include "WalletBoardPort.h"
#include "WalletBoardPins.h"

#include <Arduino.h>
#include <SPI.h>
#include <Wire.h>

#if HEXWALLET_ENABLE_LVGL
#include <lvgl.h>
#endif

namespace hexwallet {
namespace {

// ===========================================================================
//  Shared state and helpers
// ===========================================================================
bool g_display_ready = false;
bool g_touch_ready = false;
void *board_alloc(size_t bytes) {
#if defined(BOARD_HAS_PSRAM)
  if (void *p = ps_malloc(bytes)) return p;
#endif
  return malloc(bytes);
}

#if defined(HEXWALLET_PIN_BAT_VOLT)
uint16_t read_battery_mv() {
  // Battery sense line goes through a 1:2 divider on every supported board;
  // the ADC reports the divided voltage in mV, so double it.
  return static_cast<uint16_t>(analogReadMilliVolts(HEXWALLET_PIN_BAT_VOLT) * 2);
}
#endif

// ===========================================================================
//  RM67162 AMOLED driver (SPI) - T-Display S3 AMOLED / AMOLED Plus
//  Initialization sequence and window logic mirror the official LilyGO
//  rm67162.cpp SPI path; see Xinyuan-LilyGO/T-Display-S3-AMOLED.
// ===========================================================================
#if HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED || \
    HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED_PLUS

struct LcdCmd {
  uint8_t cmd;
  uint8_t data[4];
  uint8_t len;  // bit 0x80 = delay(120) after the command
};

static const LcdCmd kRm67162SpiInit[] = {
    {0xFE, {0x00}, 0x01},        // PAGE
    {0x36, {0x00}, 0x01},        // Scan direction control (MADCTL)
    {0x3A, {0x75}, 0x01},        // Interface pixel format: 16bpp
    {0x51, {0x00}, 0x01},        // Write display brightness
    {0x11, {0x00}, 0x81},        // Sleep out + delay(120)
    {0x29, {0x00}, 0x81},        // Display on + delay(120)
    {0x51, {0xD0}, 0x01},        // Brightness 0xD0
};

static void rm67162_write_command(uint8_t cmd) {
  digitalWrite(HEXWALLET_LCD_PIN_CS, LOW);
  SPI.beginTransaction(SPISettings(HEXWALLET_LCD_SPI_FREQ, MSBFIRST, SPI_MODE0));
  digitalWrite(HEXWALLET_LCD_PIN_DC, LOW);
  SPI.write(cmd);
  digitalWrite(HEXWALLET_LCD_PIN_DC, HIGH);
  SPI.endTransaction();
  digitalWrite(HEXWALLET_LCD_PIN_CS, HIGH);
}

static void rm67162_write_data(const uint8_t *data, size_t len) {
  digitalWrite(HEXWALLET_LCD_PIN_CS, LOW);
  SPI.beginTransaction(SPISettings(HEXWALLET_LCD_SPI_FREQ, MSBFIRST, SPI_MODE0));
  digitalWrite(HEXWALLET_LCD_PIN_DC, HIGH);
  SPI.writeBytes(data, len);
  SPI.endTransaction();
  digitalWrite(HEXWALLET_LCD_PIN_CS, HIGH);
}

static void rm67162_send_cmd(uint8_t cmd, const uint8_t *data, uint8_t len) {
  rm67162_write_command(cmd);
  if (len & 0x7F) rm67162_write_data(data, len & 0x7F);
  if (len & 0x80) delay(120);
}

static void rm67162_set_rotation(uint8_t rotation) {
  uint8_t madctl = 0x00;  // RGB order
  switch (rotation) {
    case 1:  madctl = 0x40 | 0x20; break;  // MV | MX  (landscape)
    case 2:  madctl = 0x40 | 0x80; break;  // MX | MY
    case 3:  madctl = 0x20 | 0x80; break;  // MV | MY
    default: break;
  }
  rm67162_send_cmd(0x36, &madctl, 1);
}

static void rm67162_set_window(uint16_t x1, uint16_t y1, uint16_t x2, uint16_t y2) {
  uint8_t caset[4] = {uint8_t(x1 >> 8), uint8_t(x1), uint8_t(x2 >> 8), uint8_t(x2)};
  uint8_t paset[4] = {uint8_t(y1 >> 8), uint8_t(y1), uint8_t(y2 >> 8), uint8_t(y2)};
  rm67162_send_cmd(0x2A, caset, 4);  // column address set
  rm67162_send_cmd(0x2B, paset, 4);  // page address set
  rm67162_send_cmd(0x2C, nullptr, 0);  // memory write
}

static void rm67162_push_pixels(uint16_t x, uint16_t y, uint16_t w, uint16_t h,
                                const uint8_t *pixels) {
  rm67162_set_window(x, y, uint16_t(x + w - 1), uint16_t(y + h - 1));
  digitalWrite(HEXWALLET_LCD_PIN_CS, LOW);
  SPI.beginTransaction(SPISettings(HEXWALLET_LCD_SPI_FREQ, MSBFIRST, SPI_MODE0));
  digitalWrite(HEXWALLET_LCD_PIN_DC, HIGH);
  SPI.writeBytes(pixels, size_t(w) * h * 2);
  SPI.endTransaction();
  digitalWrite(HEXWALLET_LCD_PIN_CS, HIGH);
}

static bool rm67162_init() {
  // IO38 is the panel power rail on the touch variant (onboard LED on the
  // basic one). The official driver enables it before touching the panel.
#if defined(HEXWALLET_PIN_LED)
  pinMode(HEXWALLET_PIN_LED, OUTPUT);
  digitalWrite(HEXWALLET_PIN_LED, HIGH);
#endif

  pinMode(HEXWALLET_LCD_PIN_CS, OUTPUT);
  pinMode(HEXWALLET_LCD_PIN_RST, OUTPUT);
  digitalWrite(HEXWALLET_LCD_PIN_RST, LOW);
  delay(300);
  digitalWrite(HEXWALLET_LCD_PIN_RST, HIGH);
  delay(200);

  SPI.begin(HEXWALLET_LCD_PIN_SCK, -1, HEXWALLET_LCD_PIN_MOSI, HEXWALLET_LCD_PIN_CS);
  SPI.setFrequency(HEXWALLET_LCD_SPI_FREQ);
  pinMode(HEXWALLET_LCD_PIN_DC, OUTPUT);

  // Run the init sequence three times, as the official driver does, to ride
  // out cold-start glitches on the panel's internal controller.
  for (int pass = 0; pass < 3; ++pass) {
    for (size_t i = 0; i < sizeof(kRm67162SpiInit) / sizeof(kRm67162SpiInit[0]); ++i) {
      rm67162_send_cmd(kRm67162SpiInit[i].cmd, kRm67162SpiInit[i].data,
                       kRm67162SpiInit[i].len);
    }
  }
  rm67162_set_rotation(1);  // landscape: 536 x 240 logical
  return true;
}

// ===========================================================================
//  ST7789 8-bit parallel driver - T-Display S3
//  Pins and init sequence match the official LilyGO T-Display-S3 factory
//  code (TFT_eSPI Setup206_LilyGo_T_Display_S3.h). The panel is driven in
//  its native portrait orientation; the 35-column CGRAM offset of the
//  170x320 visible area inside the 240x320 panel is applied in the window
//  math, which sidesteps all rotation/offset corner cases.
// ===========================================================================
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3

#include <soc/soc.h>
#include <soc/gpio_reg.h>

static inline void gpio_fast_set(uint8_t pin) {
  if (pin < 32) { REG_WRITE(GPIO_OUT_W1TS_REG, (1UL << pin)); }
  else { REG_WRITE(GPIO_OUT1_W1TS_REG, (1UL << (pin - 32))); }
}
static inline void gpio_fast_clr(uint8_t pin) {
  if (pin < 32) { REG_WRITE(GPIO_OUT_W1TC_REG, (1UL << pin)); }
  else { REG_WRITE(GPIO_OUT1_W1TC_REG, (1UL << (pin - 32))); }
}

static const uint8_t kStDataPins[8] = {
    HEXWALLET_LCD_PIN_D0, HEXWALLET_LCD_PIN_D1, HEXWALLET_LCD_PIN_D2,
    HEXWALLET_LCD_PIN_D3, HEXWALLET_LCD_PIN_D4, HEXWALLET_LCD_PIN_D5,
    HEXWALLET_LCD_PIN_D6, HEXWALLET_LCD_PIN_D7,
};

// Lookup tables: for every byte value the bit pattern to set/clear on the
// 8-bit data bus. All data pins live in GPIO 32..48 (OUT1), but the table is
// generic so the driver survives pin moves.
static uint64_t s_st_set_pat[256];
static uint64_t s_st_clr_pat[256];

static void st_write_byte(uint8_t b) {
  REG_WRITE(GPIO_OUT_W1TS_REG, uint32_t(s_st_set_pat[b]));
  REG_WRITE(GPIO_OUT1_W1TS_REG, uint32_t(s_st_set_pat[b] >> 32));
  REG_WRITE(GPIO_OUT_W1TC_REG, uint32_t(s_st_clr_pat[b]));
  REG_WRITE(GPIO_OUT1_W1TC_REG, uint32_t(s_st_clr_pat[b] >> 32));
  // 8080 WR strobe: falling edge latches nothing, data is latched on the
  // rising edge; keep the low phase a few cycles wide.
  gpio_fast_clr(HEXWALLET_LCD_PIN_WR);
  __asm__ __volatile__("nop");
  gpio_fast_set(HEXWALLET_LCD_PIN_WR);
}

static void st_write_cmd(uint8_t cmd) {
  gpio_fast_clr(HEXWALLET_LCD_PIN_CS);
  gpio_fast_clr(HEXWALLET_LCD_PIN_DC);  // command phase
  st_write_byte(cmd);
  gpio_fast_set(HEXWALLET_LCD_PIN_CS);
}

static void st_write_data(const uint8_t *data, size_t len) {
  gpio_fast_clr(HEXWALLET_LCD_PIN_CS);
  gpio_fast_set(HEXWALLET_LCD_PIN_DC);  // data phase
  for (size_t i = 0; i < len; ++i) st_write_byte(data[i]);
  gpio_fast_set(HEXWALLET_LCD_PIN_CS);
}

static void st_write_cmd_data(uint8_t cmd, const uint8_t *data, size_t len) {
  st_write_cmd(cmd);
  if (len) st_write_data(data, len);
}

struct StCmd {
  uint8_t cmd;
  uint8_t data[14];
  uint8_t len;  // 0x80 = delay(120) after
};

// Official LilyGO T-Display-S3 ST7789 init (lcd_st7789v in tft.ino).
static const StCmd kSt7789Init[] = {
    {0x11, {0}, 0x80},
    {0x3A, {0x05}, 1},
    {0xB2, {0x0B, 0x0B, 0x00, 0x33, 0x33}, 5},
    {0xB7, {0x75}, 1},
    {0xBB, {0x28}, 1},
    {0xC0, {0x2C}, 1},
    {0xC2, {0x01}, 1},
    {0xC3, {0x1F}, 1},
    {0xC6, {0x13}, 1},
    {0xD0, {0xA7}, 1},
    {0xD0, {0xA4, 0xA1}, 2},
    {0xD6, {0xA1}, 1},
    {0xE0, {0xF0, 0x05, 0x0A, 0x06, 0x06, 0x03, 0x2B, 0x32, 0x43, 0x36, 0x11, 0x10, 0x2B, 0x32}, 14},
    {0xE1, {0xF0, 0x08, 0x0C, 0x0B, 0x09, 0x24, 0x2B, 0x22, 0x43, 0x38, 0x15, 0x16, 0x2F, 0x37}, 14},
};

static void st_set_window(uint16_t x1, uint16_t y1, uint16_t x2, uint16_t y2) {
  // +35 CGRAM offset for the 170-column visible area of the 240-wide panel.
  const uint16_t ox = 35;
  uint8_t caset[4] = {uint8_t((ox + x1) >> 8), uint8_t(ox + x1),
                      uint8_t((ox + x2) >> 8), uint8_t(ox + x2)};
  uint8_t paset[4] = {uint8_t(y1 >> 8), uint8_t(y1), uint8_t(y2 >> 8), uint8_t(y2)};
  st_write_cmd_data(0x2A, caset, 4);
  st_write_cmd_data(0x2B, paset, 4);
  st_write_cmd(0x2C);
}

static void st_push_pixels(uint16_t x, uint16_t y, uint16_t w, uint16_t h,
                           const uint8_t *pixels) {
  st_set_window(x, y, uint16_t(x + w - 1), uint16_t(y + h - 1));
  gpio_fast_clr(HEXWALLET_LCD_PIN_CS);
  gpio_fast_set(HEXWALLET_LCD_PIN_DC);
  const size_t total = size_t(w) * h * 2;
  for (size_t i = 0; i < total; ++i) st_write_byte(pixels[i]);
  gpio_fast_set(HEXWALLET_LCD_PIN_CS);
}

static bool st7789_init() {
  // Power rail and reset.
  pinMode(HEXWALLET_LCD_PIN_RST, OUTPUT);
  pinMode(HEXWALLET_LCD_PIN_CS, OUTPUT);
  pinMode(HEXWALLET_LCD_PIN_DC, OUTPUT);
  pinMode(HEXWALLET_LCD_PIN_WR, OUTPUT);
  pinMode(HEXWALLET_LCD_PIN_RD, OUTPUT);
  pinMode(HEXWALLET_LCD_PIN_BL, OUTPUT);
  for (int i = 0; i < 8; ++i) pinMode(kStDataPins[i], OUTPUT);
  digitalWrite(HEXWALLET_LCD_PIN_RD, HIGH);  // read strobe idle
  digitalWrite(HEXWALLET_LCD_PIN_WR, HIGH);
  digitalWrite(HEXWALLET_LCD_PIN_CS, HIGH);
  digitalWrite(HEXWALLET_LCD_PIN_BL, HIGH);
#if defined(HEXWALLET_PIN_POWER_ON)
  pinMode(HEXWALLET_PIN_POWER_ON, OUTPUT);
  digitalWrite(HEXWALLET_PIN_POWER_ON, HIGH);
#endif

  // Precompute the byte->bus pattern lookup tables.
  for (int b = 0; b < 256; ++b) {
    uint64_t set = 0, clr = 0;
    for (int i = 0; i < 8; ++i) {
      if (b & (1 << i)) set |= (uint64_t(1) << kStDataPins[i]);
      else clr |= (uint64_t(1) << kStDataPins[i]);
    }
    s_st_set_pat[b] = set;
    s_st_clr_pat[b] = clr;
  }

  // Hardware reset.
  digitalWrite(HEXWALLET_LCD_PIN_RST, HIGH);
  delay(20);
  digitalWrite(HEXWALLET_LCD_PIN_RST, LOW);
  delay(20);
  digitalWrite(HEXWALLET_LCD_PIN_RST, HIGH);
  delay(120);

  for (size_t i = 0; i < sizeof(kSt7789Init) / sizeof(kSt7789Init[0]); ++i) {
    const StCmd &c = kSt7789Init[i];
    st_write_cmd_data(c.cmd, c.data, c.len & 0x7F);
    if (c.len & 0x80) delay(120);
  }
  // Portrait, RGB order, no mirror. (Inversion is enabled on this panel.)
  static const uint8_t kMadctl = 0x00;
  st_write_cmd_data(0x36, &kMadctl, 1);
  static const uint8_t kColmod = 0x05;  // 16bpp
  st_write_cmd_data(0x3A, &kColmod, 1);
  st_write_cmd(0x21);  // display inversion on
  st_write_cmd(0x29);  // display on
  delay(120);
  return true;
}

// ===========================================================================
//  Monochrome e-paper backend (GxEPD2) - T-Deck Max / T-Echo Lite
// ===========================================================================
#elif defined(HEXWALLET_HAS_DISPLAY) && defined(HEXWALLET_DISPLAY_KIND_EINK)

#if __has_include(<GxEPD2_BW.h>)
#define HEXWALLET_HAS_GXEPD2 1
#include <GxEPD2_BW.h>
#else
#define HEXWALLET_HAS_GXEPD2 0
#endif

#if HEXWALLET_BOARD == HEXWALLET_BOARD_T_DECK_MAX
#define HEXWALLET_EPD_DRIVER_CLASS GxEPD2_310_GDEQ031T10
#endif

#if HEXWALLET_HAS_GXEPD2
#if defined(HEXWALLET_EPD_DRIVER_CLASS)
static GxEPD2_BW<HEXWALLET_EPD_DRIVER_CLASS, HEXWALLET_EPD_DRIVER_CLASS::HEIGHT> s_epd(
    HEXWALLET_EPD_DRIVER_CLASS(HEXWALLET_EPD_PIN_CS, HEXWALLET_EPD_PIN_DC,
                               HEXWALLET_EPD_PIN_RST, HEXWALLET_EPD_PIN_BUSY));
#endif
#endif

// 4x4 Bayer ordered-dither threshold matrix for 16bpp -> 1bpp conversion.
static const uint8_t kBayer4[16] = {
    0,  8,  2, 10,
    12, 4, 14, 6,
    3, 11, 1,  9,
    15, 7, 13, 5,
};

#endif  // e-ink section

// ===========================================================================
//  CST816S capacitive touch (I2C 0x15) - AMOLED Touch / T-Display S3 Touch
// ===========================================================================
#if defined(HEXWALLET_TOUCH_CST816S)

static int16_t s_touch_x = 0;
static int16_t s_touch_y = 0;
static bool s_touch_pressed = false;

static bool cst816s_probe() {
  Wire.begin(HEXWALLET_PIN_TOUCH_SDA, HEXWALLET_PIN_TOUCH_SCL);
  Wire.beginTransmission(0x15);
  return Wire.endTransmission() == 0;
}

static void cst816s_read() {
  s_touch_pressed = false;
  Wire.beginTransmission(0x15);
  Wire.write(0x01);  // touch data starts at register 0x01
  if (Wire.endTransmission(false) != 0) return;
  uint8_t buf[6] = {0};
  if (Wire.requestFrom(static_cast<uint8_t>(0x15), static_cast<uint8_t>(6)) != 6) return;
  for (int i = 0; i < 6; ++i) buf[i] = Wire.read();
  const uint8_t fingers = buf[1];
  if (fingers == 0) return;
  s_touch_x = static_cast<int16_t>(((buf[2] & 0x0F) << 8) | buf[3]);
  s_touch_y = static_cast<int16_t>(((buf[4] & 0x0F) << 8) | buf[5]);
  s_touch_pressed = true;
}

#endif  // HEXWALLET_TOUCH_CST816S

// ===========================================================================
//  LVGL glue (LVGL 9.5 API: lv_display_t / lv_indev_t)
// ===========================================================================
#if HEXWALLET_ENABLE_LVGL
static uint8_t *g_draw_buf = nullptr;

#if defined(HEXWALLET_DISPLAY_KIND_COLOR)
static void color_flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map) {
#if HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED || \
    HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED_PLUS
  rm67162_push_pixels(area->x1, area->y1, uint16_t(area->x2 - area->x1 + 1),
                      uint16_t(area->y2 - area->y1 + 1), px_map);
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3
  st_push_pixels(area->x1, area->y1, uint16_t(area->x2 - area->x1 + 1),
                 uint16_t(area->y2 - area->y1 + 1), px_map);
#endif
  lv_display_flush_ready(disp);
}
#endif  // color

#if defined(HEXWALLET_DISPLAY_KIND_EINK)
// 1bpp frame buffer for the e-paper (w*h/8 bytes).
static uint8_t *s_eink_bw = nullptr;

static void eink_convert_to_bw(const uint8_t *frame16, uint16_t w, uint16_t h) {
  const uint16_t *frame = reinterpret_cast<const uint16_t *>(frame16);
  for (uint16_t y = 0; y < h; ++y) {
    for (uint16_t x = 0; x < w; ++x) {
      // LV_COLOR_16_SWAP is enabled (backward-compat swap in lv_refr.c before
      // flush_cb), so the in-memory bytes are swapped; undo to get RGB565.
      const uint16_t c16 = frame[size_t(y) * w + x];
      const uint16_t c = uint16_t((c16 << 8) | (c16 >> 8));
      const uint32_t r8 = ((c >> 11) & 0x1F) * 255 / 31;
      const uint32_t g8 = ((c >> 5) & 0x3F) * 255 / 63;
      const uint32_t b8 = (c & 0x1F) * 255 / 31;
      const uint32_t lum = (r8 * 299 + g8 * 587 + b8 * 114) / 1000;  // 0..255
      const uint8_t idx = uint8_t((y & 3) * 4 + (x & 3));
      const bool on = lum < uint32_t(255 - kBayer4[idx] * 17);
      const size_t bit = size_t(y) * w + x;
      if (on) s_eink_bw[bit >> 3] |= uint8_t(0x80 >> (x & 7));
      else s_eink_bw[bit >> 3] &= uint8_t(~(0x80 >> (x & 7)));
    }
  }
}

static void eink_flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map) {
  if (lv_display_flush_is_last(disp)) {
#if HEXWALLET_HAS_GXEPD2 && defined(HEXWALLET_EPD_DRIVER_CLASS)
    eink_convert_to_bw(g_draw_buf, HEXWALLET_EPD_WIDTH, HEXWALLET_EPD_HEIGHT);
    s_epd.writeScreenBuffer(s_eink_bw);
    s_epd.refresh(true);
    s_epd.powerOff();
#endif
  }
  lv_display_flush_ready(disp);
}
#endif  // eink

#if defined(HEXWALLET_TOUCH_CST816S)
static void touch_read_cb(lv_indev_t *indev, lv_indev_data_t *data) {
  (void)indev;
  cst816s_read();
  data->point.x = s_touch_x;
  data->point.y = s_touch_y;
  data->state = s_touch_pressed ? LV_INDEV_STATE_PRESSED : LV_INDEV_STATE_RELEASED;
}
#endif

static bool lvgl_register_display(
    uint16_t width, uint16_t height, bool full_frame,
    void (*flush_cb)(lv_display_t *, const lv_area_t *, uint8_t *)) {
  const size_t buf_px =
      full_frame ? size_t(width) * height
                 : size_t(width) * (size_t(height) / 10 < 16 ? 16 : size_t(height) / 10);
  // RGB565: 2 bytes per pixel.
  uint8_t *buf = static_cast<uint8_t *>(board_alloc(buf_px * 2));
  if (buf == nullptr) return false;
  g_draw_buf = buf;
  lv_display_t *disp = lv_display_create(width, height);
  if (disp == nullptr) return false;
  // buf_size is in bytes.
  lv_display_set_buffers(disp, buf, nullptr, buf_px * 2,
                         full_frame ? LV_DISPLAY_RENDER_MODE_DIRECT
                                    : LV_DISPLAY_RENDER_MODE_PARTIAL);
  lv_display_set_flush_cb(disp, flush_cb);
  lv_display_set_antialiasing(disp, false);
  return true;
}

#endif  // HEXWALLET_ENABLE_LVGL

}  // namespace

// ===========================================================================
//  Public board port API
// ===========================================================================
const char *board_name() { return HEXWALLET_BOARD_NAME; }

DisplayKind board_display_kind() {
#if defined(HEXWALLET_DISPLAY_KIND_COLOR)
  return DisplayKind::Color;
#elif defined(HEXWALLET_DISPLAY_KIND_EINK)
  return DisplayKind::MonoEink;
#else
  return DisplayKind::Color;
#endif
}

bool board_has_display() {
#if defined(HEXWALLET_HAS_DISPLAY)
  return true;
#else
  return false;
#endif
}

bool board_has_touch() {
#if defined(HEXWALLET_TOUCH_CST816S)
  return true;
#else
  return false;
#endif
}

bool board_is_color() { return board_display_kind() == DisplayKind::Color; }
bool board_is_eink() { return board_display_kind() == DisplayKind::MonoEink; }

uint16_t board_display_width() {
#if defined(HEXWALLET_DISPLAY_KIND_COLOR)
  return HEXWALLET_LCD_WIDTH;
#elif defined(HEXWALLET_DISPLAY_KIND_EINK)
  return HEXWALLET_EPD_WIDTH;
#else
  return 0;
#endif
}

uint16_t board_display_height() {
#if defined(HEXWALLET_DISPLAY_KIND_COLOR)
  return HEXWALLET_LCD_HEIGHT;
#elif defined(HEXWALLET_DISPLAY_KIND_EINK)
  return HEXWALLET_EPD_HEIGHT;
#else
  return 0;
#endif
}

void board_power(bool on) {
#if defined(HEXWALLET_PIN_POWER_ON)
  digitalWrite(HEXWALLET_PIN_POWER_ON, on ? HIGH : LOW);
#endif
#if defined(HEXWALLET_LCD_PIN_BL)
  digitalWrite(HEXWALLET_LCD_PIN_BL, on ? HIGH : LOW);
#endif
#if defined(HEXWALLET_LCD_PIN_TE)
  (void)on;
#endif
#if defined(HEXWALLET_PIN_LED)
  digitalWrite(HEXWALLET_PIN_LED, on ? HIGH : LOW);
#endif
}

uint16_t board_battery_millivolts() {
#if defined(HEXWALLET_PIN_BAT_VOLT)
  return read_battery_mv();
#else
  return 0;
#endif
}

bool board_display_init() {
#if !HEXWALLET_ENABLE_LVGL
  return false;
#elif defined(HEXWALLET_DISPLAY_KIND_COLOR)
#if HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED || \
    HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3_AMOLED_PLUS
  if (!rm67162_init()) return false;
#elif HEXWALLET_BOARD == HEXWALLET_BOARD_T_DISPLAY_S3
  if (!st7789_init()) return false;
#endif
  if (!lvgl_register_display(HEXWALLET_LCD_WIDTH, HEXWALLET_LCD_HEIGHT,
                             false, color_flush_cb)) {
    return false;
  }
  g_display_ready = true;

#elif defined(HEXWALLET_DISPLAY_KIND_EINK)
#if HEXWALLET_HAS_GXEPD2 && defined(HEXWALLET_EPD_DRIVER_CLASS)
  s_eink_bw = static_cast<uint8_t *>(
      board_alloc(size_t(HEXWALLET_EPD_WIDTH) * HEXWALLET_EPD_HEIGHT / 8));
  if (s_eink_bw == nullptr) return false;
  s_epd.init(0, true, 10, false);
  s_epd.setRotation(0);
  s_epd.setFullWindow();
  if (!lvgl_register_display(HEXWALLET_EPD_WIDTH, HEXWALLET_EPD_HEIGHT,
                             true, eink_flush_cb)) {
    return false;
  }
  g_display_ready = true;
#else
  // GxEPD2 (or the concrete panel class) is not available. Fail closed with
  // an explicit reason instead of pretending the e-paper is live.
  Serial.println("WARN: e-paper target needs the GxEPD2 library (and, for "
                 "T-Echo Lite, a HEXWALLET_EPD_DRIVER_CLASS definition)");
  g_display_ready = false;
  return false;
#endif
#else
  g_display_ready = false;
  return false;
#endif

#if defined(HEXWALLET_TOUCH_CST816S)
  if (cst816s_probe()) {
#if HEXWALLET_ENABLE_LVGL
    lv_indev_t *indev = lv_indev_create();
    if (indev != nullptr) {
      lv_indev_set_type(indev, LV_INDEV_TYPE_POINTER);
      lv_indev_set_read_cb(indev, touch_read_cb);
      g_touch_ready = true;
    }
#endif
  }
#endif

  return g_display_ready;
}

void board_display_service() {
#if HEXWALLET_ENABLE_LVGL
  if (g_display_ready) lv_timer_handler();
#endif
}

}  // namespace hexwallet
