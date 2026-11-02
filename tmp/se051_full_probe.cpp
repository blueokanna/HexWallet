#include <stdio.h>
#include <string.h>
#include "Se051Apdu.h"
using namespace hexwallet;

namespace
{
  struct FakeCard
  {
    uint16_t status;
    uint8_t response[256];
    size_t response_size;
    uint8_t frames[16][260];
    size_t sizes[16];
    size_t count;
    size_t fail_at;
  };

  bool send(void *context, const uint8_t *command, size_t command_size,
            uint8_t *response, size_t response_capacity, size_t *response_size)
  {
    FakeCard *card = static_cast<FakeCard *>(context);
    if (card->count < 16)
    {
      memcpy(card->frames[card->count], command, command_size);
      card->sizes[card->count] = command_size;
    }
    ++card->count;
    const bool failing = card->fail_at != 0 && card->count == card->fail_at;
    const uint16_t status = failing ? 0x6985 : card->status;
    if (card->response_size != 0)
      memcpy(response, card->response, card->response_size);
    response[card->response_size] = static_cast<uint8_t>(status >> 8);
    response[card->response_size + 1] = static_cast<uint8_t>(status);
    *response_size = card->response_size + 2;
    return true;
  }
}

int main()
{
  bool ok = true;
  FakeCard card = {};
  card.status = 0x9000;
  uint16_t status = 0;
  const bool installed = se051_install_curve(send, &card, kSe051CurveSecp256k1, &status);
  printf("install ok=%d status=%04x frames=%zu\n", (int)installed, status, card.count);
  for (size_t i = 0; i < card.count; ++i)
  {
    printf("  frame %zu size=%zu:", i, card.sizes[i]);
    for (size_t j = 0; j < card.sizes[i] && j < 20; ++j)
      printf(" %02x", card.frames[i][j]);
    printf("\n");
  }
  FakeCard partial = {};
  partial.status = 0x9000;
  partial.fail_at = 2;
  status = 0;
  const bool p = se051_install_curve(send, &partial, kSe051CurveNistP256, &status);
  printf("partial ok=%d status=%04x frames=%zu\n", (int)p, status, partial.count);

  FakeCard list = {};
  list.status = 0x9000;
  static const uint8_t kList[] = {0x41, 0x02, 0x03, 0x10, 0x90, 0x00};
  memcpy(list.response, kList, sizeof(kList));
  list.response_size = sizeof(kList);
  bool present = false;
  status = 0;
  const bool lp = se051_curve_present(send, &list, kSe051CurveSecp256k1, &present, &status);
  printf("list fn=%d present=%d status=%04x\n", (int)lp, (int)present, status);

  FakeCard pins = {};
  pins.status = 0x9000;
  static const uint8_t kPolicy[8] = {0x10, 0, 0, 0, 0, 0, 0, 0};
  Se051PinSession session;
  se051_pin_reset(&session);
  uint8_t user_id[16];
  memset(user_id, 0x11, sizeof(user_id));
  const bool began = se051_pin_begin(send, &pins, 0x7fff0207u, kPolicy, sizeof(kPolicy), &session);
  printf("pin begin=%d state=%d frames=%zu\n", (int)began, (int)session.state, pins.count);
  pins.status = 0x63c2;
  const bool v1 = se051_pin_verify(send, &pins, user_id, sizeof(user_id), &session);
  printf("pin verify(bad)=%d attempts=%u state=%d\n", (int)v1, session.attempts_left, (int)session.state);
  pins.status = 0x9000;
  const bool v2 = se051_pin_verify(send, &pins, user_id, sizeof(user_id), &session);
  printf("pin verify(good)=%d state=%d\n", (int)v2, (int)session.state);
  static const uint8_t kMac[] = {0x41, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x90, 0x00};
  memcpy(pins.response, kMac, sizeof(kMac));
  pins.response_size = sizeof(kMac);
  uint8_t mac[8] = {};
  size_t mac_size = 0;
  const bool h = se051_pin_hmac(send, &pins, &session, 3, 0x0a, user_id,
                                sizeof(user_id), mac, sizeof(mac), &mac_size);
  printf("pin hmac=%d size=%zu first=%02x\n", (int)h, mac_size, mac[0]);

  ok = installed && !p && lp && present && began && !v1 && v2 && h;
  return ok ? 0 : 1;
}
