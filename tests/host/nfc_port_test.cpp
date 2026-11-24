// Executes the actual PN7161 driver with an instrumented SPI transport.
#undef NDEBUG
#include <algorithm>
#define HEXWALLET_NFC_RUNTIME_TEST 1
#undef HEXWALLET_BOARD
#define HEXWALLET_BOARD 7
#include "../../WalletNfcPort.cpp"
#include <cassert>
#include <cstdio>
#include <deque>
#include <vector>

SPIClass SPI;
HardwareSerial Serial;
static std::vector<uint8_t> sent;
static std::deque<uint8_t> incoming;
static uint32_t ticks = 0;
static int irq = 0, lost = 0, requests = 0;
static bool selected = false;
static bool controller = false;
static bool reject_listen = false;
static size_t spi_start = 0;
static std::deque<std::vector<uint8_t>> packets;
static std::vector<std::vector<uint8_t>> writes;
uint8_t nfc_test_transfer(uint8_t b) {
  assert(selected);
  sent.push_back(b);
  if (incoming.empty())
    return 0xff;
  uint8_t v = incoming.front();
  incoming.pop_front();
  return v;
}
void pinMode(uint8_t, uint8_t) {}
void digitalWrite(uint8_t p, uint8_t v) {
  if (p == HEXWALLET_NFC_PIN_VEN && v == LOW && controller) {
    incoming.clear(); packets.clear(); irq = LOW;
  }
  if (p != HEXWALLET_NFC_PIN_CS) return;
  selected = v == LOW;
  if (!controller) return;
  if (selected) {
    spi_start = sent.size();
    if (!packets.empty()) {
      incoming.push_back(0xff);
      for (auto c : packets.front()) incoming.push_back(c);
      packets.pop_front();
    }
  } else if (sent.size() >= spi_start + 4 && sent[spi_start] == 0) {
    std::vector<uint8_t> frame(sent.begin() + spi_start + 1, sent.end());
    writes.push_back(frame);
    if ((frame[0] & 0xe0) == 0x20) {
      const bool fail = reject_listen && frame == (std::vector<uint8_t>{0x21,3,3,1,0x80,1});
      packets.push_back({uint8_t(frame[0] + 0x20), frame[1], 1, uint8_t(fail)});
      if (frame[0] == 0x20 && frame[1] == 0) packets.push_back({0x60, 0, 1, 0});
    }
  }
  irq = !packets.empty();
}
int digitalRead(uint8_t pin) {
  if (pin == HEXWALLET_NFC_PIN_CS) return selected ? LOW : HIGH;
  if (pin == HEXWALLET_NFC_PIN_IRQ) return irq;
  return HIGH;
}
void delay(uint32_t v) { ticks += v; }
uint32_t millis() { return ticks; }
namespace hexwallet {
void secure_zero(void *p, size_t n) {
  volatile uint8_t *b = static_cast<volatile uint8_t *>(p);
  while (n--)
    *b++ = 0;
}
} // namespace hexwallet
static void on_lost() { ++lost; }
static size_t on_apdu(const uint8_t *, size_t, uint8_t *out, size_t cap) {
  ++requests;
  assert(cap >= 5);
  memset(out, 0x90, 5);
  return 5;
}
int main() {
  using namespace hexwallet;
  assert(&nfc_spi == &SPI);
  uint8_t read[258];
  size_t n = 9;
  assert(!spi_read_packet(read, sizeof(read), &n, 0) && n == 0 && sent.empty());
  irq = HIGH;
  incoming = {0xff, 0x60, 0x06, 0x03, 0x01, 0x00, 0x01};
  assert(spi_read_packet(read, sizeof(read), &n, 0) && n == 6);
  assert(sent[0] == 0xff && read[2] == 3 && !selected);
  sent.clear();
  const uint8_t reset[] = {0x20, 0, 1, 0};
  assert(!spi_write_packet(reset, sizeof(reset)) && sent.empty());
  irq = LOW;
  assert(spi_write_packet(reset, sizeof(reset)));
  assert((sent == std::vector<uint8_t>{0, 0x20, 0, 1, 0}));
  sent.clear();
  incoming = {0, 0xff};
  ticks = 0;
  assert(spi_write_packet(reset, sizeof(reset)) && ticks == 5 &&
         sent.size() == 6);
  uint8_t maximum[258] = {0x20, 2, 255};
  assert(spi_write_packet(maximum, sizeof(maximum)));
  session_lost = on_lost;
  apdu_handler = on_apdu;
  const uint8_t activation[] = {0x61, 5, 11, 7,    2, 4, 0x80,
                                2,    1, 0,  0x80, 0, 0, 0};
  handle_notification(activation, sizeof(activation));
  assert(state == NfcPortState::Activated && connection_id == 0 &&
         tx_limit == 2);
  const uint8_t first[] = {0x10, 0, 2, 0, 0xa4};
  const uint8_t last[] = {0, 0, 2, 4, 0};
  handle_data_packet(first, sizeof(first));
  assert(requests == 0);
  handle_data_packet(last, sizeof(last));
  assert(requests == 1);
  sent.clear();
  flush_response();
  assert((sent == std::vector<uint8_t>{0, 0x10, 0, 2, 0x90, 0x90}));
  sent.clear();
  flush_response();
  assert(sent.empty()); // no credits
  const uint8_t credit[] = {0x60, 6, 3, 1, 0, 2};
  handle_notification(credit, sizeof(credit));
  flush_response();
  flush_response();
  assert(tx_size == 0 && tx_credits == 0);
  handle_data_packet(first, sizeof(first));
  const uint8_t deactivation[] = {0x61, 6, 2, 3, 0};
  int before = lost;
  handle_notification(deactivation, sizeof(deactivation));
  assert(lost > before && apdu_size == 0 && state == NfcPortState::Ready);
  handle_notification(activation, sizeof(activation));
  const uint8_t wrong_connection[] = {1, 0, 4, 0, 0xa4, 4, 0};
  handle_data_packet(wrong_connection, sizeof(wrong_connection));
  assert(state == NfcPortState::Error && requests == 1 && nfc_port_error());
  handle_notification(activation, sizeof(activation));
  handle_data_packet(first, sizeof(first));
  ticks += 2001;
  nfc_port_service(ticks);
  assert(state == NfcPortState::Error && apdu_size == 0);
  assert(!strcmp(nfc_port_error(), "APDU transfer timed out"));
  handle_notification(activation, sizeof(activation));
  ticks = 0xffffff00;
  handle_data_packet(first, sizeof(first));
  ticks += 2001;
  nfc_port_service(ticks);
  assert(state == NfcPortState::Error);
  controller = true;
  assert(nfc_port_begin(on_apdu, on_lost));
  const int phone_requests = requests;
  assert(nfc_backup_start() == NfcBackupStatus::Pending);
  assert(writes.back() == (std::vector<uint8_t>{0x21,3,3,1,0,1}));
  auto service = [] { ticks += 3; nfc_port_service(ticks); };
  auto notify = [&](std::vector<uint8_t> frame) { packets.push_back(frame); irq = HIGH; service(); };
  auto reply = [&](std::vector<uint8_t> payload) {
    payload.push_back(0x90); payload.push_back(0);
    std::vector<uint8_t> data = {0,0,uint8_t(payload.size())};
    data.insert(data.end(), payload.begin(), payload.end());
    notify(data); service();
  };
  auto activate_tag = [&] { notify({0x61,5,11,1,2,4,0,64,0xff,0,0,0,0,0}); service(); };
  activate_tag();
  assert(writes.back() == (std::vector<uint8_t>{0,0,13,0,0xa4,4,0,7,0xd2,0x76,0,0,0x85,1,1,0}));
  reply({});
  assert(writes.back() == (std::vector<uint8_t>{0,0,7,0,0xa4,0,0x0c,2,0xe1,3}));
  reply({});
  assert(writes.back() == (std::vector<uint8_t>{0,0,5,0,0xb0,0,0,15}));
  reply({0,15,0x20,0,32,0,32,4,6,0xe1,4,0,128,0,0xff});
  assert(writes.back() == (std::vector<uint8_t>{0,0,7,0,0xa4,0,0x0c,2,0xe1,4}));
  reply({});
  assert(writes.back() == (std::vector<uint8_t>{0,0,5,0,0xb0,0,0,2}));
  const char fixture[] = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
  std::vector<uint8_t> record = {0xd1,1,61,'T',2,'e','n'};
  record.insert(record.end(), fixture, fixture+58);
  reply({0,uint8_t(record.size())});
  for (size_t at = 0; at < record.size();) {
    const size_t chunk = std::min<size_t>(32, record.size() - at);
    assert(writes.back() == (std::vector<uint8_t>{0,0,5,0,0xb0,0,uint8_t(at+2),uint8_t(chunk)}));
    reply({record.begin()+at, record.begin()+at+chunk});
    at += chunk;
  }
  char key[65]{};
  assert(nfc_backup_take(key) == NfcBackupStatus::Complete && !strcmp(key, fixture));
  assert(writes.back() == (std::vector<uint8_t>{0x21,3,3,1,0x80,1}));
  assert(requests == phone_requests && !reader.key[0] && !reader.record[0]);
  assert(nfc_backup_take(key) == NfcBackupStatus::Idle);
  assert(std::all_of(key, key + sizeof(key), [](char c) { return !c; }));
  assert(nfc_backup_start() == NfcBackupStatus::Pending);
  activate_tag();
  assert(nfc_backup_start() == NfcBackupStatus::Busy);
  notify({0,0,2,0x6a,0x82}); service();
  assert(nfc_backup_take(key) == NfcBackupStatus::MissingFile);
  assert(nfc_backup_start() == NfcBackupStatus::Pending);
  activate_tag(); notify({0,0,2,0x69,0x82}); service();
  assert(nfc_backup_take(key) == NfcBackupStatus::AccessDenied);
  assert(nfc_backup_start() == NfcBackupStatus::Pending);
  activate_tag(); notify({0,0,2,0x6d,0}); service();
  assert(nfc_backup_take(key) == NfcBackupStatus::CommandRejected);
  assert(nfc_backup_start() == NfcBackupStatus::Pending);
  nfc_backup_cancel(); service();
  assert(nfc_backup_take(key) == NfcBackupStatus::Idle && state == NfcPortState::Ready);
  assert(nfc_backup_start() == NfcBackupStatus::Pending);
  ticks += 30000; service();
  assert(nfc_backup_take(key) == NfcBackupStatus::Timeout && requests == phone_requests);
  assert(nfc_backup_start() == NfcBackupStatus::Pending);
  activate_tag();
  notify({0x10,0,2,0x70,1});
  notify({0x61,6,2,3,0}); service();
  assert(nfc_backup_take(key) == NfcBackupStatus::TagLost && apdu_size == 0 && !apdu_buffer[0]);
  assert(nfc_backup_start() == NfcBackupStatus::Pending);
  notify({0x61,3,5,1,4,0,0,2}); service();
  assert(nfc_backup_take(key) == NfcBackupStatus::UnsupportedTag);
  assert(nfc_backup_start() == NfcBackupStatus::Pending);
  activate_tag(); reply({}); reply({}); reply({0,15,0x20,0,32,0,32,4,6,0xe1,4,0,128,0,0xff}); reply({});
  reply({0,97});
  assert(nfc_backup_take(key) == NfcBackupStatus::InvalidRecord && state == NfcPortState::Ready);
  notify(std::vector<uint8_t>(activation, activation + sizeof(activation)));
  assert(nfc_backup_start() == NfcBackupStatus::Busy);
  notify({0,0,4,0,0xa4,4,0});
  assert(requests == phone_requests + 1);
  // Failed restoration must discard even a fully read backup.
  assert(nfc_port_begin(on_apdu, on_lost));
  assert(nfc_backup_start() == NfcBackupStatus::Pending);
  activate_tag(); reply({}); reply({});
  reply({0,15,0x20,0,96,0,32,4,6,0xe1,4,0,128,0,0xff}); reply({});
  reply({0,uint8_t(record.size())});
  reject_listen = true;
  reply(record);
  assert(state == NfcPortState::InitFailed && nfc_backup_take(key) == NfcBackupStatus::Controller);
  assert(std::all_of(key, key + sizeof(key), [](char c) { return c == 0; }));
  assert(std::all_of(reader.key, reader.key + sizeof(reader.key), [](char c) { return c == 0; }));
  assert(std::all_of(reader.record, reader.record + sizeof(reader.record), [](uint8_t c) { return c == 0; }));
  reject_listen = false;
  assert(nfc_port_begin(on_apdu, on_lost));
  notify(std::vector<uint8_t>(activation, activation + sizeof(activation)));
  notify({0,0,4,0,0xa4,4,0});
  assert(requests == phone_requests + 2);
  puts("PN7161 SPI/NCI runtime tests: PASS");
}
