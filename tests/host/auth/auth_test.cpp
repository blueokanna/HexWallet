#include "TotpAccounts.h"
#include "CtapHid.h"
#include "UsbApduFrame.h"
#include "EinkPanel.h"
#include <array>
#include <vector>
#include <cstdio>
#include <cstring>

namespace hexwallet
{
  void secure_zero(void *p, size_t n)
  {
    volatile uint8_t *v = static_cast<volatile uint8_t *>(p);
    while (n--)
      *v++ = 0;
  }
}
using namespace hexwallet;
static unsigned checks = 0;
#define CHECK(x)                                       \
  do                                                   \
  {                                                    \
    ++checks;                                          \
    if (!(x))                                          \
    {                                                  \
      std::printf("FAIL line=%d: %s\n", __LINE__, #x); \
      return false;                                    \
    }                                                  \
  } while (0)

static bool accounts()
{
  CHECK(run_totp_self_tests());
  uint8_t decoded[64];
  memset(decoded, 0xa5, sizeof(decoded));
  size_t size = 999;
  CHECK(totp_base32_decode("MZXW6!", decoded, sizeof(decoded), &size) == TotpError::InvalidBase32);
  CHECK(size == 0);
  for (uint8_t c : decoded)
    CHECK(c == 0xa5);
  CHECK(totp_base32_decode("MZXW6===", decoded, 2, &size) == TotpError::BufferTooSmall);
  for (uint8_t c : decoded)
    CHECK(c == 0xa5);
  const char *uri = "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&digits=8";
  TotpAccounts store;
  uint8_t slot = 255;
  CHECK(store.import_uri(uri, strlen(uri), &slot) == TotpError::Ok && slot == 0);
  TotpAccountInfo info;
  CHECK(store.info(0, &info) && strcmp(info.issuer, "Example") == 0 && strcmp(info.account, "alice") == 0);
  CHECK(store.import_uri(uri, strlen(uri), &slot) == TotpError::AccountExists && slot == 255);
  char code[9];
  uint32_t remaining;
  CHECK(store.generate(0, 0, code, &remaining) == TotpError::ClockNotSet);
  CHECK(totp_clock_set_unix(59, 1000));
  CHECK(store.generate(0, 1000, code, &remaining) == TotpError::Ok && strcmp(code, "94287082") == 0 && remaining == 1);
  CHECK(store.generate(0, 999, code, &remaining) == TotpError::ClockNotSet && code[0] == 0 && remaining == 0);
  const char *bad[] = {
      "otpauth://hotp/alice?secret=MY", "otpauth://totp/alice?secret=MZ",
      "otpauth://totp/alice?secret=MY&secret=MY", "otpauth://totp/A:alice?secret=MY&issuer=B",
      "otpauth://totp/alice%00bob?secret=MY", "otpauth://totp/alice?secret=MY&digits=7",
      "otpauth://totp/alice?secret=MY&period=4294967296", "otpauth://totp/alice?secret=MY&",
      "otpauth://totp/alice?secret=MY&algorithm=MD5", "otpauth://totp/alice?secret=MY&extra=1"};
  for (const char *s : bad)
    CHECK(store.import_uri(s, strlen(s), &slot) != TotpError::Ok);
  for (unsigned i = 1; i < 8; ++i)
  {
    char text[128];
    snprintf(text, sizeof(text), "otpauth://totp/account%u?secret=MY", i);
    CHECK(store.import_uri(text, strlen(text), &slot) == TotpError::Ok && slot == i);
  }
  const char *extra = "otpauth://totp/extra?secret=MY";
  CHECK(store.import_uri(extra, strlen(extra), &slot) == TotpError::StorageFull);
  CHECK(store.remove(0) && !store.remove(0));
  CHECK(store.import_uri(extra, strlen(extra), &slot) == TotpError::Ok && slot == 0);
  store.clear();
  for (uint8_t i = 0; i < 8; ++i)
    CHECK(!store.info(i, &info));
  return true;
}

static bool usb()
{
  UsbApduFrame frame;
  const uint8_t bytes[] = {0xa5, 0x5a, 4, 0, 0, 0xa4, 4, 0};
  for (size_t i = 0; i < sizeof(bytes); ++i)
    CHECK(frame.feed(bytes[i], 0) == (i + 1 == sizeof(bytes) ? UsbApduFrame::Result::Ready : UsbApduFrame::Result::Pending));
  CHECK(frame.size() == 4 && memcmp(frame.data(), bytes + 4, 4) == 0);
  frame.clear();
  CHECK(!frame.active());
  CHECK(frame.feed(0xa5, 0xfffffff0) == UsbApduFrame::Result::Pending);
  CHECK(!frame.expired(0x10) && frame.expired(0xfffffff0U + UsbApduFrame::kTimeoutMs));
  CHECK(frame.feed(0x5a, 0xfffffff0U + UsbApduFrame::kTimeoutMs) == UsbApduFrame::Result::Rejected);
  frame.clear();
  CHECK(frame.feed(0xa5, 0) == UsbApduFrame::Result::Pending);
  CHECK(frame.feed(0x00, 1) == UsbApduFrame::Result::Rejected);
  CHECK(frame.feed('\n', 2) == UsbApduFrame::Result::Rejected);
  frame.clear();
  const uint8_t oversized[] = {0xa5, 0x5a, 0xff, 0xff};
  for (size_t i = 0; i < 4; ++i)
    CHECK(frame.feed(oversized[i], 0) == (i == 3 ? UsbApduFrame::Result::Rejected : UsbApduFrame::Result::Pending));
  return true;
}

using Report = std::array<uint8_t, 64>;
struct Sink
{
  std::vector<Report> reports;
  bool fail = false;
};
static bool send(void *p, const uint8_t *data)
{
  auto &sink = *static_cast<Sink *>(p);
  if (sink.fail)
    return false;
  Report r;
  memcpy(r.data(), data, 64);
  sink.reports.push_back(r);
  return true;
}
static Report initial(uint32_t cid, uint8_t cmd, size_t length)
{
  Report r = {};
  r[0] = static_cast<uint8_t>(cid >> 24);
  r[1] = static_cast<uint8_t>(cid >> 16);
  r[2] = static_cast<uint8_t>(cid >> 8);
  r[3] = static_cast<uint8_t>(cid);
  r[4] = cmd | 0x80;
  r[5] = static_cast<uint8_t>(length >> 8);
  r[6] = static_cast<uint8_t>(length);
  return r;
}
static uint32_t assigned(const Report &r) { return uint32_t(r[15]) << 24 | uint32_t(r[16]) << 16 | uint32_t(r[17]) << 8 | r[18]; }
static bool hid()
{
  Sink sink;
  CtapHid h(send, &sink, true);
  auto init = initial(0xffffffff, 6, 8);
  for (unsigned i = 0; i < 8; ++i)
    init[7 + i] = static_cast<uint8_t>(i);
  CHECK(h.receive(init.data(), 64, 0));
  CHECK(sink.reports.size() == 1 && sink.reports[0][4] == 0x86 && sink.reports[0][23] == 0x0c);
  CHECK(memcmp(init.data() + 7, sink.reports[0].data() + 7, 8) == 0);
  const uint32_t cid = assigned(sink.reports.back());
  CHECK(cid == 1);
  auto cbor = initial(cid, 0x10, 60);
  cbor[7] = 4;
  CHECK(h.receive(cbor.data(), 64, 1));
  auto other = initial(0xffffffff, 6, 8);
  CHECK(h.receive(other.data(), 64, 2));
  CHECK(sink.reports.back()[4] == 0xbf && sink.reports.back()[7] == 6);
  Report cont = initial(cid, 0, 0);
  cont[4] = 1;
  CHECK(h.receive(cont.data(), 64, 3));
  CHECK(sink.reports.back()[7] == 4);
  CHECK(h.receive(cbor.data(), 64, 4));
  cont[4] = 0;
  cont[5] = 1;
  cont[6] = 2;
  cont[7] = 3;
  CHECK(h.receive(cont.data(), 64, 5));
  CtapHid::Request request;
  CHECK(h.request(&request) && request.size == 60 && request.data[57] == 1 && request.data[59] == 3);
  const uint64_t token = request.token;
  CHECK(h.poll(105));
  CHECK(sink.reports.back()[4] == 0xbb);
  auto cancel = initial(cid, 0x11, 0);
  CHECK(h.receive(cancel.data(), 64, 106));
  CHECK(sink.reports.back()[4] == 0x90 && sink.reports.back()[7] == 0x2d && !h.active(token));
  const uint8_t ok = 0;
  CHECK(!h.complete(token, &ok, 1));
  CHECK(h.receive(cbor.data(), 64, 107));
  CHECK(h.poll(3107));
  CHECK(sink.reports.back()[7] == 5);
  auto shortcbor = initial(cid, 0x10, 1);
  shortcbor[7] = 4;
  CHECK(h.receive(shortcbor.data(), 64, 3108));
  CHECK(h.request(&request) && request.token != token);
  CHECK(h.complete(request.token, &ok, 1));
  CHECK(sink.reports.back()[7] == 0);
  h.reset();
  CHECK(h.receive(shortcbor.data(), 64, 3109));
  CHECK(sink.reports.back()[7] == 0x0b);
  CHECK(h.receive(init.data(), 64, 3110));
  CHECK(assigned(sink.reports.back()) == 2);
  sink.fail = true;
  CHECK(!h.receive(init.data(), 64, 3111) && h.faulted());
  Sink no;
  CtapHid unavailable(send, &no);
  CHECK(unavailable.receive(init.data(), 64, 0));
  CHECK(no.reports.back()[23] == 8);
  shortcbor = initial(1, 0x10, 1);
  CHECK(unavailable.receive(shortcbor.data(), 64, 1));
  CHECK(no.reports.back()[7] == 1);
  CHECK(!unavailable.receive(nullptr, 64, 1) && !unavailable.receive(init.data(), 63, 1));
  // Maximum legal message: 57 + 128*59 bytes, ending with sequence 127.
  no.reports.clear();
  std::vector<uint8_t> payload(CtapHid::kMaxPayload);
  for (size_t i = 0; i < payload.size(); ++i)
    payload[i] = static_cast<uint8_t>(i * 31U);
  Report ping = initial(1, 1, payload.size());
  memcpy(ping.data() + 7, payload.data(), 57);
  CHECK(unavailable.receive(ping.data(), 64, 0xfffffff0U));
  size_t offset = 57;
  for (unsigned sequence = 0; sequence < 128; ++sequence)
  {
    Report part = initial(1, 0, 0);
    part[4] = static_cast<uint8_t>(sequence);
    memcpy(part.data() + 5, payload.data() + offset, 59);
    offset += 59;
    CHECK(unavailable.receive(part.data(), 64, 0xfffffff0U + sequence));
  }
  CHECK(no.reports.size() == 129 && no.reports[0][4] == 0x81);
  CHECK(memcmp(no.reports[0].data() + 7, payload.data(), 57) == 0);
  offset = 57;
  for (size_t i = 1; i < no.reports.size(); ++i)
  {
    CHECK(no.reports[i][4] == i - 1 && memcmp(no.reports[i].data() + 5, payload.data() + offset, 59) == 0);
    offset += 59;
  }
  ping = initial(1, 1, CtapHid::kMaxPayload + 1);
  CHECK(unavailable.receive(ping.data(), 64, 500));
  CHECK(no.reports.back()[7] == 3);
  return true;
}
bool run_totp_service_tests();
int main()
{
  if (!accounts() || !usb() || !hid())
    return 1;
  if (!run_totp_service_tests())
    return 1;
  if (!run_eink_panel_self_tests())
  {
    puts("FAIL eink-panel");
    return 1;
  }
  printf("auth-transport: %u checks + RFC TOTP + eink panel tests passed\n", checks);
  return 0;
}
