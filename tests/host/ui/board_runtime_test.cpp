#include <stdio.h>
#include <string.h>
#include "../../../WalletBoardPort.cpp"
#ifdef HEXWALLET_SHARED_SPI_TEST
#include "../../../WalletNfcPort.cpp"
#include <vector>
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
#if HEXWALLET_EPD_PROFILE == 4
// Physical BUSY from the supplied HINK A/0, independent of the firmware macro.
static constexpr int simulated_busy_active = LOW;
#else
static constexpr int simulated_busy_active = HEXWALLET_EPD_BUSY_ACTIVE_LEVEL;
#endif
static bool spi_available, in_transaction, invalid_spi;
static bool reset_enabled_low;
static unsigned nfc_bytes, panel_bytes;
static unsigned bus_starts;
static uint32_t spi_clock;
static uint32_t activated_at;
static bool panel_activated, ignore_refresh;
static int reset_stuck = -1;
static int stuck_cs_pin = -1, stuck_cs_level = HIGH;
static bool fail_on_deselect = false;
static std::vector<uint8_t> panel_ram_write;
static uint8_t current_panel_command;
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
uint8_t nfc_test_transfer(uint8_t value) {
  invalid_spi |= !in_transaction || pin_low[HEXWALLET_EPD_PIN_CS] == pin_low[HEXWALLET_NFC_PIN_CS];
  invalid_spi |= spi_clock != (pin_low[HEXWALLET_NFC_PIN_CS] ? 1000000U : HEXWALLET_EPD_SPI_FREQ);
  if (pin_low[HEXWALLET_NFC_PIN_CS]) ++nfc_bytes;
  else {
    ++panel_bytes;
    invalid_spi |= !pin_low[HEXWALLET_EPD_PIN_DC];
    current_panel_command = value;
    if (value == 0x24) panel_ram_write.clear();
    if (value == 0x20 && pin_low[HEXWALLET_EPD_PIN_DC] && !ignore_refresh) {
      panel_activated = true;
      activated_at = test_now;
    }
  }
  return 0xff;
}
#endif

void board_test_spi_write(uint8_t value) { spi_command = value; }
void board_test_spi_write_bytes(const uint8_t *data, size_t size) {
#ifdef HEXWALLET_SHARED_SPI_TEST
  invalid_spi |= !in_transaction || !pin_low[HEXWALLET_EPD_PIN_CS] || pin_low[HEXWALLET_NFC_PIN_CS] || spi_clock != HEXWALLET_EPD_SPI_FREQ;
  invalid_spi |= pin_low[HEXWALLET_EPD_PIN_DC] || (reinterpret_cast<uintptr_t>(data) % alignof(uint32_t)) != 0;
  // Model the last complete word the P4 Arduino HAL reads, including the
  // unused tail. The wire still receives exactly 'size' bytes.
  for (size_t i = size; i % sizeof(uint32_t); ++i) invalid_spi |= data[i] != 0;
  if (current_panel_command == 0x24)
    panel_ram_write.insert(panel_ram_write.end(), data, data + size);
  panel_bytes += static_cast<unsigned>(size);
#endif
  if (spi_command == 0x36 && size == 1) panel_orientation = data[0];
}
int board_test_wire_read() { return touch_data[touch_index++ % 6]; }

uint32_t millis() { return test_now; }
void delay(uint32_t ms) { test_now += ms; }
void delayMicroseconds(uint32_t) {}
void pinMode(uint8_t pin, uint8_t mode) {
#ifdef HEXWALLET_SHARED_SPI_TEST
  if (pin == HEXWALLET_EPD_PIN_RST && mode == OUTPUT && pin_low[pin]) reset_enabled_low = true;
#else
  (void)pin; (void)mode;
#endif
}
void digitalWrite(uint8_t pin, uint8_t value) {
#ifdef HEXWALLET_SHARED_SPI_TEST
  if (fail_on_deselect && pin == HEXWALLET_EPD_PIN_CS && pin_low[pin] && value == HIGH) {
    stuck_cs_pin = pin;
    stuck_cs_level = LOW;
  }
  pin_low[pin] = value == LOW;
  if (pin == HEXWALLET_NFC_PIN_VEN && value == HIGH)
    invalid_spi |= !pin_low[HEXWALLET_NFC_PIN_DWL_REQ];
#else
  (void)pin; (void)value;
#endif
}
int digitalRead(uint8_t pin) {
#ifdef HEXWALLET_SHARED_SPI_TEST
  if (pin == stuck_cs_pin) return stuck_cs_level;
  if (pin == HEXWALLET_EPD_PIN_RST && reset_stuck >= 0) return reset_stuck;
  if (pin == HEXWALLET_EPD_PIN_BUSY && panel_activated) {
    const auto elapsed = test_now - activated_at;
    if (elapsed >= 35) panel_activated = false;
    else if (elapsed >= 3) return simulated_busy_active;
  }
#endif
  return pin < 64 && pin_low[pin] ? LOW : HIGH;
}
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
  CHECK(run_eink_panel_self_tests());
  CHECK(run_camera_port_self_tests());
  touch_data[0] = 0x92;
  touch_data[1] = 0x81;
  CHECK(board_camera_probe() == CameraProbeState::PresentUnverified);
  pin_low[HEXWALLET_EPD_PIN_BUSY] = simulated_busy_active == HIGH;
  pin_low[HEXWALLET_EPD_PIN_RST] = true; // Power-on value of the output latch.
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
#ifdef HEXWALLET_SHARED_SPI_TEST
  CHECK(!reset_enabled_low);
#endif
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
  CHECK(panel_ram_write.size() == 16 * 296);
  for (size_t i = 0; i < panel_ram_write.size(); ++i)
    CHECK(panel_ram_write[i] == static_cast<uint8_t>(~s_eink_bw[i]));
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
  const bool has_partial = HEXWALLET_EPD_PROFILE != 3;
  CHECK(board_partial_refresh_supported() == has_partial);
  lv_obj_set_style_bg_color(patch, lv_color_white(), 0);
  for (int i = 0; i < 5; ++i) { lv_obj_invalidate(screen); pump(40); }
  CHECK(s_epd_native.stats().partial_refreshes == (has_partial ? 1U : 0U) &&
        s_epd_native.stats().full_refreshes == (has_partial ? 1U : 2U));
  CHECK((s_eink_bw[45 * 16 + 2] & 0x02) == 0); // logical (45,105) = native (22,45)
  CHECK((s_eink_bw[45 * 16 + 2] & 0x80) != 0); // adjacent unchanged black pixel
  if (!has_partial) {
    // Check the actual 24h stream from the LVGL screen. The white patch
    // crosses a byte boundary; surrounding black pixels must stay black.
    CHECK(panel_ram_write.size() == 4736);
    CHECK((panel_ram_write[45 * 16 + 2] & 0x02) != 0);
    CHECK((panel_ram_write[45 * 16 + 2] & 0x80) == 0);
  }
#if HEXWALLET_EPD_PROFILE == 4
  // Toggle the same 10x10 logical patch without sleeping. Inspect the bytes
  // sent to the second RAM bank as well as the partial/full refresh counts.
  const auto white_patch = panel_ram_write;
  CHECK(white_patch.size() == 20 && (white_patch[10] & 0x82) == 0x02);
  lv_obj_set_style_bg_color(patch, lv_color_black(), 0); pump(); pump(160);
  CHECK(s_epd_native.stats().partial_refreshes == 2 && panel_ram_write.size() == white_patch.size());
  for (const auto value : panel_ram_write) CHECK(value == 0);
  lv_obj_set_style_bg_color(patch, lv_color_white(), 0); pump(); pump(160);
  CHECK(board_display_review_ready() && s_epd_native.stats().full_refreshes == 1 &&
        s_epd_native.stats().partial_refreshes == 3 && panel_ram_write == white_patch);
#endif
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
  CHECK(!s_epd_native.sleeping() && s_epd_native.stats().full_refreshes == (has_partial ? 2U : 3U) && board_display_review_ready());
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
  // Both failed reset levels must stop before SPI commands and block approval.
  const unsigned bytes_before_reset_fault = panel_bytes;
  for (int level = LOW; level <= HIGH; ++level) {
    reset_stuck = level;
    CHECK(!board_display_init() && !board_display_review_ready());
    CHECK(s_epd_native.last_error() == EinkRefreshResult::ResetFault);
    CHECK(panel_bytes == bytes_before_reset_fault);
    CHECK(s_eink_bw == nullptr && g_draw_buf == nullptr && g_display == nullptr);
  }
  reset_stuck = -1;
  stuck_cs_pin = HEXWALLET_EPD_PIN_CS;
  stuck_cs_level = HIGH;
  CHECK(!board_display_init() && !board_display_review_ready());
  CHECK(s_epd_native.last_error() == EinkRefreshResult::BusFault);
  CHECK(panel_bytes == bytes_before_reset_fault && !in_transaction);
  stuck_cs_pin = HEXWALLET_NFC_PIN_CS;
  stuck_cs_level = LOW;
  CHECK(!board_display_init() && panel_bytes == bytes_before_reset_fault && !in_transaction);
  const unsigned nfc_before_cs_fault = nfc_bytes;
  stuck_cs_level = HIGH;
  CHECK(!spi_write_packet(reset_packet, sizeof(reset_packet)) && !in_transaction);
  stuck_cs_pin = HEXWALLET_EPD_PIN_CS;
  stuck_cs_level = LOW;
  pin_low[HEXWALLET_NFC_PIN_IRQ] = false;
  uint8_t header[3];
  size_t length = sizeof(header);
  CHECK(!spi_read_packet(header, sizeof(header), &length, 0) && length == 0 && !in_transaction);
  CHECK(nfc_bytes == nfc_before_cs_fault);
  pin_low[HEXWALLET_NFC_PIN_IRQ] = true;
  stuck_cs_pin = -1;
  fail_on_deselect = true;
  const uint8_t parameter = 0x03;
  CHECK(!epd_write_command(nullptr, 0x11, &parameter, 1) && !in_transaction);
  CHECK(panel_bytes == bytes_before_reset_fault + 1); // No parameter clocks after failed release.
  fail_on_deselect = false;
  stuck_cs_pin = -1;
  pin_low[HEXWALLET_EPD_PIN_BUSY] = HEXWALLET_EPD_BUSY_ACTIVE_LEVEL == LOW;
  CHECK(!board_display_init() && !board_display_review_ready());
  CHECK(s_epd_native.last_error() == EinkRefreshResult::BusyTimeout);
  CHECK(s_eink_bw == nullptr && g_draw_buf == nullptr && g_display == nullptr);
  pin_low[HEXWALLET_EPD_PIN_BUSY] = HEXWALLET_EPD_BUSY_ACTIVE_LEVEL == HIGH;
  pin_low[30] = true;
  CHECK(board_display_init());
  CHECK(g_keypad != nullptr && lv_group_get_default() != nullptr);
  lv_obj_t *after_retry = lv_button_create(lv_screen_active());
  lv_obj_add_event_cb(after_retry, clicked, LV_EVENT_CLICKED, nullptr);
  pump(); pump();
  pin_low[30] = false; pump(); pump();
  CHECK(clicks == 2); // A held key during recovery must also be released first.
  ignore_refresh = true;
  lv_obj_set_style_bg_color(lv_screen_active(), lv_color_black(), 0);
  pump(); pump(160);
  CHECK(!board_display_operational() && !board_display_review_ready());
  puts("P4 display lifecycle, frame changes, reset/BUSY faults, buttons and retry: PASS");
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
#ifdef HEXWALLET_SHARED_SPI_TEST
  // Exercise a misaligned source spanning two FIFO blocks and a one-byte tail.
  alignas(4) uint8_t source[130];
  for (size_t i = 0; i < sizeof(source); ++i) source[i] = static_cast<uint8_t>(i * 37);
  CHECK(epd_write_command(nullptr, 0x24, source + 1, 129));
  CHECK(!invalid_spi && panel_ram_write.size() == 129 &&
        memcmp(panel_ram_write.data(), source + 1, 129) == 0);
#endif
  lv_deinit();
  return 0;
}
