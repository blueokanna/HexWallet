#include <stdio.h>
#include <string.h>
#include "../../../WalletBoardPort.cpp"
#ifdef HEXWALLET_SHARED_SPI_TEST
#include "../../../WalletNfcPort.cpp"
#endif

HardwareSerial Serial;
SPIClass SPI;
TwoWire Wire, Wire1;
static uint32_t test_now = 0;
static bool pin_low[64] = {};
static unsigned clicks = 0;
static uint8_t spi_command = 0, panel_orientation = 0xff;
static int touch_data[6] = {};
static size_t touch_index = 0;

#ifdef HEXWALLET_SHARED_SPI_TEST
static bool spi_available, in_transaction, invalid_spi;
static unsigned nfc_bytes, panel_bytes;
static unsigned bus_starts;
static uint32_t spi_clock;
bool board_test_spi_begin(SPIClass *bus, int clk, int miso, int mosi, int cs) {
  invalid_spi |= bus != &SPI || clk != 7 || miso != 9 || mosi != 8 || cs != -1 ||
                 pin_low[HEXWALLET_EPD_PIN_CS] || pin_low[HEXWALLET_NFC_PIN_CS];
  if (spi_available) ++bus_starts;
  return spi_available;
}
void board_test_spi_transaction(SPIClass *bus, bool begin, uint32_t clock, uint8_t mode) {
  spi_clock = clock;
  invalid_spi |= mode != SPI_MODE0;
  invalid_spi |= bus != &SPI || in_transaction == begin ||
                 pin_low[HEXWALLET_EPD_PIN_CS] || pin_low[HEXWALLET_NFC_PIN_CS];
  in_transaction = begin;
}
uint8_t nfc_test_transfer(uint8_t) {
  invalid_spi |= !in_transaction || pin_low[HEXWALLET_EPD_PIN_CS] == pin_low[HEXWALLET_NFC_PIN_CS];
  invalid_spi |= spi_clock != (pin_low[HEXWALLET_NFC_PIN_CS] ? 1000000U : HEXWALLET_EPD_SPI_FREQ);
  if (pin_low[HEXWALLET_NFC_PIN_CS]) ++nfc_bytes;
  else ++panel_bytes;
  return 0xff;
}
#endif

void board_test_spi_write(uint8_t value) { spi_command = value; }
void board_test_spi_write_bytes(const uint8_t *data, size_t size) {
#ifdef HEXWALLET_SHARED_SPI_TEST
  invalid_spi |= !in_transaction || !pin_low[HEXWALLET_EPD_PIN_CS] || pin_low[HEXWALLET_NFC_PIN_CS] || spi_clock != HEXWALLET_EPD_SPI_FREQ;
  panel_bytes += static_cast<unsigned>(size);
#endif
  if (spi_command == 0x36 && size == 1) panel_orientation = data[0];
}
int board_test_wire_read() { return touch_data[touch_index++ % 6]; }

uint32_t millis() { return test_now; }
void delay(uint32_t ms) { test_now += ms; }
void pinMode(uint8_t, uint8_t) {}
void digitalWrite(uint8_t pin, uint8_t value) {
#ifdef HEXWALLET_SHARED_SPI_TEST
  pin_low[pin] = value == LOW;
  if (pin == HEXWALLET_NFC_PIN_VEN && value == HIGH)
    invalid_spi |= !pin_low[HEXWALLET_NFC_PIN_DWL_REQ];
#else
  (void)pin; (void)value;
#endif
}
int digitalRead(uint8_t pin) { return pin < 64 && pin_low[pin] ? LOW : HIGH; }
int analogReadMilliVolts(uint8_t) { return 1900; }
void *ps_malloc(size_t size) { return malloc(size); }
namespace hexwallet {
bool se051_transport_in_use() { return false; }
void secure_zero(void *out, size_t size) { memset(out, 0, size); }
}

#define CHECK(condition) do { if (!(condition)) { \
  fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)

static void pump(uint32_t ms = 40) {
  test_now += ms;
  hexwallet::board_display_service();
}
static void clicked(lv_event_t *) { ++clicks; }

int main(int argc, char **argv) {
  using namespace hexwallet;
#if HEXWALLET_BOARD == HEXWALLET_BOARD_ESP32P4_EINK
  pin_low[HEXWALLET_EPD_PIN_BUSY] = true;
#endif
  CHECK(!lv_is_initialized());
#ifdef HEXWALLET_SHARED_SPI_TEST
  pin_low[HEXWALLET_NFC_PIN_IRQ] = true;
  auto no_apdu = [](const uint8_t *, size_t, uint8_t *, size_t) -> size_t { return 0; };
  CHECK(!nfc_port_begin(no_apdu, []{}) && nfc_port_state() == NfcPortState::InitFailed);
  CHECK(!board_display_init());
  spi_available = true;
  if (argc == 2 && !strcmp(argv[1], "nfc-first")) {
    CHECK(!nfc_port_begin(no_apdu, []{}) && nfc_bytes > 0 && bus_starts == 1 && !invalid_spi);
  }
#endif
  CHECK(board_display_init());
  CHECK(lv_is_initialized() && lv_tick_get_cb() != nullptr);
  const uint32_t before = lv_tick_get();
  test_now += 17;
  CHECK(lv_tick_get() - before == 17);
  lv_display_t *display = lv_display_get_default();
  CHECK(display != nullptr);
  CHECK(board_display_init() && lv_display_get_next(display) == nullptr);
  lv_obj_t *screen = lv_screen_active();
  lv_obj_set_style_bg_color(screen, lv_color_hex(0xff0000), 0);
  lv_obj_set_style_bg_opa(screen, LV_OPA_COVER, 0);
  pump();
  pump(160);
  CHECK(board_display_review_ready());

#if HEXWALLET_BOARD == HEXWALLET_BOARD_ESP32P4_EINK
  CHECK(lv_display_get_color_format(display) == LV_COLOR_FORMAT_RGB565);
  CHECK(g_draw_buf[0] == 0x00 && g_draw_buf[1] == 0xf8);
  lv_obj_t *patch = lv_obj_create(screen);
  lv_obj_set_pos(patch, 40, 100);
  lv_obj_set_size(patch, 10, 10);
  lv_obj_set_style_radius(patch, 0, 0);
  lv_obj_set_style_border_width(patch, 0, 0);
  lv_obj_set_style_bg_color(patch, lv_color_hex(0x0000ff), 0);
  pump();
  CHECK(!board_display_review_ready());
  pump(160);
  CHECK(board_display_review_ready());
  // DIRECT-mode redraw must not change retained pixels outside its rectangle.
  CHECK(g_draw_buf[0] == 0x00 && g_draw_buf[1] == 0xf8);
  CHECK(board_display_width() == 296 && board_display_height() == 128);
  const size_t pixel = (105 * 296 + 45) * 2;
  CHECK(g_draw_buf[pixel] == 0x1f && g_draw_buf[pixel + 1] == 0x00);

  // Red and blue both pack to black. Redrawing either consumes no waveform.
  CHECK(s_epd_native.stats().full_refreshes == 1 && s_epd_native.stats().partial_refreshes == 0);
  lv_obj_set_style_bg_color(patch, lv_color_white(), 0);
  for (int i = 0; i < 5; ++i) { lv_obj_invalidate(screen); pump(40); }
  CHECK(s_epd_native.stats().partial_refreshes == 1 && s_epd_native.stats().full_refreshes == 1);
  CHECK((s_eink_bw[45 * 16 + 2] & 0x02) == 0); // logical (45,105) = native (22,45)
  CHECK((s_eink_bw[45 * 16 + 2] & 0x80) != 0); // adjacent unchanged black pixel
  // A controller that fails to answer CORE_RESET must release the shared bus.
  CHECK(!nfc_port_begin(no_apdu, []{}) && nfc_bytes > 0 && !in_transaction && !invalid_spi);
  const unsigned previous_panel_bytes = panel_bytes;
  pump(160);
  pump(kPanelIdleSleepMs);
  CHECK(s_epd_native.sleeping() && board_display_review_ready());
  lv_obj_invalidate(screen); pump(); pump(160);
  CHECK(s_epd_native.sleeping() && board_display_review_ready());
  lv_obj_set_style_bg_color(patch, lv_color_black(), 0); pump();
  CHECK(!board_display_review_ready());
  pump(160);
  CHECK(!s_epd_native.sleeping() && s_epd_native.stats().full_refreshes == 2 && board_display_review_ready());
  CHECK(panel_bytes > previous_panel_bytes && !in_transaction && !invalid_spi);
  s_test_defer_refresh = true;
  lv_obj_set_style_bg_color(patch, lv_color_white(), 0); pump(); pump(160);
  CHECK(s_panel_job.load() == PanelJob::Running && !board_display_review_ready());
  const uint8_t reset_packet[] = {0x20,0,1,0};
  CHECK(spi_write_packet(reset_packet, sizeof(reset_packet)) && !in_transaction && !invalid_spi && bus_starts == 1);
  board_display_prepare_review();
  refresh_panel_frame(); pump();
  CHECK(!board_display_review_ready()); // The previous frame cannot approve the new page.
  s_test_defer_refresh = false;
  lv_obj_set_style_bg_color(patch, lv_color_black(), 0); pump(); pump(160);
  CHECK(board_display_review_ready());

  CHECK(g_keypad != nullptr && lv_indev_get_type(g_keypad) == LV_INDEV_TYPE_KEYPAD);
  CHECK(lv_indev_get_group(g_keypad) == lv_group_get_default());
  lv_obj_clean(screen);
  lv_obj_t *first = lv_button_create(screen);
  lv_obj_t *second = lv_button_create(screen);
  lv_obj_add_event_cb(second, clicked, LV_EVENT_CLICKED, nullptr);
  CHECK(lv_group_get_obj_count(lv_group_get_default()) == 2);
  lv_group_focus_obj(first);
  pin_low[HEXWALLET_PIN_BUTTON_2] = true; pump(); pump();
  pin_low[HEXWALLET_PIN_BUTTON_2] = false; pump(); pump();
  CHECK(lv_group_get_focused(lv_group_get_default()) == second);
  CHECK(button_key(1) == LV_KEY_ESC && button_key(4) == LV_KEY_PREV);
  pin_low[30] = true; pump(); pump();
  pin_low[30] = false; pump(); pump();
  CHECK(clicks == 1);
  pin_low[30] = true; pump(); pump();
  board_display_prepare_review();
  pin_low[30] = false; pump(); pump();
  CHECK(clicks == 1); // Holding ENTER across a review change cannot approve it.
  lv_group_focus_obj(first);
  pin_low[HEXWALLET_PIN_BUTTON_2] = true; pump(); pump();
  pin_low[30] = true; pump(); pump();
  pin_low[HEXWALLET_PIN_BUTTON_2] = false; pump(); pump();
  pin_low[30] = false; pump(); pump();
  CHECK(clicks == 1); // NEXT+ENTER followed by releasing NEXT is not a click.
  lv_group_focus_obj(second);
  pin_low[30] = true; pump(); pump();
  pin_low[30] = false; pump(); pump();
  CHECK(clicks == 2);

  release_display();
  pin_low[HEXWALLET_EPD_PIN_BUSY] = false;
  CHECK(!board_display_init() && !board_display_review_ready());
  CHECK(s_eink_bw == nullptr && g_draw_buf == nullptr && g_display == nullptr);
  pin_low[HEXWALLET_EPD_PIN_BUSY] = true;
  pin_low[30] = true;
  CHECK(board_display_init());
  CHECK(g_keypad != nullptr && lv_group_get_default() != nullptr);
  lv_obj_t *after_retry = lv_button_create(lv_screen_active());
  lv_obj_add_event_cb(after_retry, clicked, LV_EVENT_CLICKED, nullptr);
  pump(); pump();
  pin_low[30] = false; pump(); pump();
  CHECK(clicks == 2); // A held key during recovery must also be released first.
  puts("P4 display lifecycle, tick, partial frame, buttons, stale press and retry: PASS");
#else
  CHECK(panel_orientation == 0x00); // No axis exchange for 240 x 536 portrait.
  CHECK(lv_display_get_color_format(display) == LV_COLOR_FORMAT_RGB565_SWAPPED);
  CHECK(g_draw_buf[0] == 0xf8 && g_draw_buf[1] == 0x00);
  touch_data[1] = 1;
  touch_data[3] = 239;
  touch_data[4] = 2;
  touch_data[5] = 23; // Last valid point: (239, 535).
  touch_index = 0;
  cst816s_read();
  CHECK(s_touch_pressed && s_touch_x == 239 && s_touch_y == 535);
  touch_data[5] = 24;
  touch_index = 0;
  cst816s_read();
  CHECK(!s_touch_pressed);
  touch_data[5] = 23;
  touch_data[3] = 240;
  touch_index = 0;
  cst816s_read();
  CHECK(!s_touch_pressed);
  touch_data[3] = 239;
  touch_data[1] = 2;
  touch_index = 0;
  cst816s_read();
  CHECK(!s_touch_pressed);
  touch_data[1] = 1;
  touch_data[0] = -1;
  touch_index = 0;
  cst816s_read();
  CHECK(!s_touch_pressed);
  puts("S3 display lifecycle, tick, RGB565 wire order, orientation and touch bounds: PASS");
#endif
  release_display();
  CHECK(lv_display_get_default() == nullptr && lv_group_get_default() == nullptr);
  lv_deinit();
  return 0;
}
