// Host harness for the phone <-> wallet link protocol.
//
// It runs the REAL device code (WalletLinkDevice) with an in-memory phone-key
// store and a stub application handler, and speaks a tiny line protocol on
// stdin/stdout so tools/phone_link_reference.py can drive a complete
// pairing + handshake + encrypted request round trip without hardware.
//
// This binary is a test harness only: it is never flashed and it uses
// deterministic randomness from host_security.cpp.
#include <stdio.h>
#include <string.h>

#include "../../WalletLink.h"
#include "../../WalletSecurity.h"

namespace {

using namespace hexwallet;

struct PairStore {
  uint8_t phone[32];
  bool present;
  uint32_t code;
};

PairStore store = { {}, false, 0 };
uint32_t clock_ms = 1000;

void print_hex(const uint8_t *data, size_t size) {
  static const char kHex[] = "0123456789abcdef";
  for (size_t index = 0; index < size; ++index) {
    putchar(kHex[data[index] >> 4]);
    putchar(kHex[data[index] & 0x0f]);
  }
}

bool decode_hex(const char *text, uint8_t *out, size_t capacity,
                size_t *out_size) {
  const size_t length = strlen(text);
  if (length == 0 || (length & 1U) != 0 || length / 2 > capacity) return false;
  for (size_t index = 0; index < length / 2; ++index) {
    int high = -1;
    int low = -1;
    for (int nibble = 0; nibble < 2; ++nibble) {
      const char value = text[index * 2 + nibble];
      int decoded = -1;
      if (value >= '0' && value <= '9') decoded = value - '0';
      else if (value >= 'a' && value <= 'f') decoded = value - 'a' + 10;
      else if (value >= 'A' && value <= 'F') decoded = value - 'A' + 10;
      if (decoded < 0) return false;
      if (nibble == 0) high = decoded;
      else low = decoded;
    }
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  *out_size = length / 2;
  return true;
}

bool load_phone_key(void *, uint8_t out[32]) {
  if (!store.present) return false;
  memcpy(out, store.phone, 32);
  return true;
}

bool store_phone_key(void *, const uint8_t phone[32]) {
  memcpy(store.phone, phone, 32);
  store.present = true;
  return true;
}

void show_pairing_code(void *, const uint8_t phone[32], uint32_t code) {
  store.code = code;
  store.present = false;
  memcpy(store.phone, phone, 32);
  printf("CODE %06u ", static_cast<unsigned>(code % 1000000UL));
  print_hex(phone, 4);
  printf("\n");
  fflush(stdout);
}

void clear_pairing_prompt(void *) {}

WalletLinkStatus handle_request(void *, const uint8_t *request,
                                size_t request_size, uint8_t *response,
                                size_t response_capacity, size_t *response_size) {
  if (request_size == 0 || response_capacity < request_size) {
    return WalletLinkStatus::RequestFailed;
  }
  // Echo with a fixed mask so the phone can prove the channel is intact.
  for (size_t index = 0; index < request_size; ++index) {
    response[index] = static_cast<uint8_t>(request[index] ^ 0xa5);
  }
  *response_size = request_size;
  return WalletLinkStatus::Ok;
}

const char *status_text(WalletLinkStatus status) {
  switch (status) {
    case WalletLinkStatus::Ok: return "ok";
    case WalletLinkStatus::Ignored: return "ignored";
    case WalletLinkStatus::PendingPairing: return "pending-pairing";
    case WalletLinkStatus::Rejected: return "rejected";
    case WalletLinkStatus::InvalidArgument: return "invalid-argument";
    case WalletLinkStatus::BufferTooSmall: return "buffer-too-small";
    case WalletLinkStatus::NoSession: return "no-session";
    case WalletLinkStatus::Expired: return "expired";
    case WalletLinkStatus::Replay: return "replay";
    case WalletLinkStatus::AuthenticationFailed: return "authentication-failed";
    case WalletLinkStatus::RequestFailed: return "request-failed";
  }
  return "unknown";
}

}  // namespace

int main() {
  static const uint8_t kDeviceSeed[32] = {
    0x5a, 0x11, 0x69, 0x22, 0x77, 0x33, 0x85, 0x44,
    0x93, 0x55, 0xa1, 0x66, 0xb7, 0x77, 0xc9, 0x88,
    0xdb, 0x99, 0xed, 0xaa, 0xf1, 0xbb, 0x03, 0xcc,
    0x15, 0xdd, 0x27, 0xee, 0x39, 0xff, 0x4b, 0x10,
  };
  WalletLinkCallbacks callbacks = { load_phone_key, store_phone_key,
                                    show_pairing_code, clear_pairing_prompt,
                                    handle_request };
  WalletLinkDevice device;
  if (!device.init(kDeviceSeed, callbacks, nullptr)) {
    printf("FATAL init\n");
    return 1;
  }
  printf("READY ");
  print_hex(device.device_public_key(), 32);
  printf("\n");
  fflush(stdout);

  char line[16384];
  uint8_t frame[8192];
  uint8_t response[8192];
  while (fgets(line, sizeof(line), stdin) != nullptr) {
    size_t length = strlen(line);
    while (length != 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
      line[--length] = '\0';
    }
    if (length == 0) continue;
    if (strcmp(line, "QUIT") == 0) break;
    if (strcmp(line, "APPROVE") == 0) {
      printf("PAIR %s\n", device.confirm_pairing() ? "ok" : "none");
      fflush(stdout);
      continue;
    }
    if (strcmp(line, "REJECT") == 0) {
      device.reset_pairing();
      printf("PAIR rejected\n");
      fflush(stdout);
      continue;
    }
    if (strncmp(line, "SESSION", 7) == 0) {
      printf("SESSION active=%d id=%08x\n", device.session_active() ? 1 : 0,
             device.session_id());
      fflush(stdout);
      continue;
    }
    if (strncmp(line, "FRAME ", 6) != 0) {
      printf("STATUS invalid-command\n");
      fflush(stdout);
      continue;
    }
    size_t frame_size = 0;
    if (!decode_hex(line + 6, frame, sizeof(frame), &frame_size)) {
      printf("STATUS invalid-hex\n");
      fflush(stdout);
      continue;
    }
    clock_ms += 1000;
    size_t response_size = 0;
    const WalletLinkStatus status = device.receive(
        frame, frame_size, clock_ms, response, sizeof(response), &response_size);
    if (status == WalletLinkStatus::Ok && response_size != 0) {
      printf("RESP ");
      print_hex(response, response_size);
      printf("\n");
    } else {
      printf("STATUS %s\n", status_text(status));
    }
    fflush(stdout);
  }
  return 0;
}
