// Executes the actual PN7161 driver with an instrumented SPI transport.
#define HEXWALLET_NFC_RUNTIME_TEST 1
#define HEXWALLET_NFC_PN7161 1
#define HEXWALLET_NFC_PIN_SCK 12
#define HEXWALLET_NFC_PIN_MOSI 13
#define HEXWALLET_NFC_PIN_MISO 14
#define HEXWALLET_NFC_PIN_CS 15
#define HEXWALLET_NFC_PIN_IRQ 16
#define HEXWALLET_NFC_PIN_VEN 17
#include <cassert>
#include <cstdio>
#include <vector>
#include <deque>
#include "../../WalletNfcPort.cpp"
static std::vector<uint8_t> sent;
static std::deque<uint8_t> incoming;
static uint32_t ticks = 0;
static int irq = 0, lost = 0, requests = 0;
static bool selected = false;
uint8_t nfc_test_transfer(uint8_t b) {
  assert(selected);
  sent.push_back(b);
  if (incoming.empty()) return 0xff;
  uint8_t v = incoming.front(); incoming.pop_front(); return v;
}
void pinMode(uint8_t, uint8_t) {}
void digitalWrite(uint8_t p, uint8_t v) {
  if (p == HEXWALLET_NFC_PIN_CS) selected = v == LOW;
}
int digitalRead(uint8_t) { return irq; }
void delay(uint32_t v) { ticks += v; }
uint32_t millis() { return ticks; }
namespace hexwallet { void secure_zero(void *p, size_t n) {
  volatile uint8_t *b = static_cast<volatile uint8_t *>(p);
  while (n--) *b++ = 0;
} }
static void on_lost() { ++lost; }
static size_t on_apdu(const uint8_t *, size_t, uint8_t *out, size_t cap) {
  ++requests; assert(cap >= 5);
  memset(out, 0x90, 5); return 5;
}
int main() {
  using namespace hexwallet;
  uint8_t read[258]; size_t n = 9;
  assert(!spi_read_packet(read, sizeof(read), &n, 0) && n == 0 && sent.empty());
  irq = HIGH; incoming = {0xff, 0x60, 0x06, 0x03, 0x01, 0x00, 0x01};
  assert(spi_read_packet(read, sizeof(read), &n, 0) && n == 6);
  assert(sent[0] == 0xff && read[2] == 3 && !selected);
  sent.clear();
  const uint8_t reset[] = {0x20,0,1,0};
  assert(!spi_write_packet(reset,sizeof(reset)) && sent.empty());
  irq = LOW;
  assert(spi_write_packet(reset,sizeof(reset)));
  assert((sent == std::vector<uint8_t>{0,0x20,0,1,0}));
  // A controller in standby is retried only after the wake-up delay.
  sent.clear(); incoming = {0,0xff}; ticks = 0;
  assert(spi_write_packet(reset,sizeof(reset)) && ticks == 5 && sent.size() == 6);
  // Maximum NCI packet: 255 payload bytes plus the three-byte header.
  uint8_t maximum[258] = {0x20,2,255};
  assert(spi_write_packet(maximum,sizeof(maximum)));
  session_lost = on_lost; apdu_handler = on_apdu;
  // Nonzero discovery ID; static RF connection remains 0. Max payload 2.
  const uint8_t activation[] = {0x61,5,11, 7,2,4,0x80,2,1,0,0x80,0,0,0};
  handle_notification(activation,sizeof(activation));
  assert(state == NfcPortState::Activated && connection_id == 0 && tx_limit == 2);
  const uint8_t first[] = {0x10,0,2,0,0xa4};
  const uint8_t last[] = {0,0,2,4,0};
  handle_data_packet(first,sizeof(first)); assert(requests == 0);
  handle_data_packet(last,sizeof(last)); assert(requests == 1);
  sent.clear(); flush_response();
  assert((sent == std::vector<uint8_t>{0,0x10,0,2,0x90,0x90}));
  sent.clear(); flush_response(); assert(sent.empty()); // no credits
  const uint8_t credit[] = {0x60,6,3,1,0,2};
  handle_notification(credit,sizeof(credit)); flush_response(); flush_response();
  assert(tx_size == 0 && tx_credits == 0);
  handle_data_packet(first,sizeof(first));
  const uint8_t deactivation[] = {0x61,6,2,3,0};
  int before = lost; handle_notification(deactivation,sizeof(deactivation));
  assert(lost > before && apdu_size == 0 && state == NfcPortState::Ready);
  handle_notification(activation,sizeof(activation));
  const uint8_t wrong_connection[] = {1,0,4,0,0xa4,4,0};
  handle_data_packet(wrong_connection,sizeof(wrong_connection));
  assert(state == NfcPortState::Error && requests == 1);
  handle_notification(activation,sizeof(activation));
  handle_data_packet(first,sizeof(first)); ticks += 2001;
  nfc_port_service(ticks); assert(state == NfcPortState::Error && apdu_size == 0);
  // Counter rollover must not defeat the fragment deadline.
  handle_notification(activation,sizeof(activation)); ticks = 0xffffff00;
  handle_data_packet(first,sizeof(first)); ticks += 2001;
  nfc_port_service(ticks); assert(state == NfcPortState::Error);
  puts("PN7161 SPI/NCI runtime tests: PASS");
}
