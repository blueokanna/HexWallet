#include "BeamAddress.h"
#include "BeamPayment.h"
#include "base58.h"
#include "src/beam/WalletKeys.h"

namespace hexwallet {
namespace {
struct RegularToken {
  uint8_t header[11];
  uint8_t channel[8], bbs[32];
  uint8_t permanent[4], endpoint_header[3], endpoint[32];
};
constexpr uint8_t kHeader[] = {0x80, 0, 0x84, 1, 0, 0x82, 1, 0, 1, 7, 0xa8};
constexpr uint8_t kPermanent[] = {1, 8, 0x81, 1};
constexpr uint8_t kEndpoint[] = {1, 21, 0xa0};
static_assert(sizeof(RegularToken) == 90);

bool valid_peer(const uint8_t bytes[32]) {
  ECC::Point p;
  memcpy(p.m_X.m_pData, bytes, 32);
  p.m_Y = 0;
  ECC::Point::Native peer;
  return peer.ImportNnz(p);
}
} // namespace

bool beam_regular_recipient(const char *text, uint8_t endpoint[32]) {
  if (!endpoint)
    return false;
  memset(endpoint, 0, 32);
  RegularToken t{};
  size_t size = sizeof(t);
  if (!text || strlen(text) >= kBeamRegularAddressSize ||
      !b58dec(reinterpret_cast<uint8_t *>(&t), &size, text, strlen(text)) || size != sizeof(t) ||
      memcmp(t.header, kHeader, sizeof(kHeader)) || memcmp(t.permanent, kPermanent, 3) ||
      t.permanent[3] > 1 || memcmp(t.endpoint_header, kEndpoint, sizeof(kEndpoint)) ||
      memcmp(t.channel, "\0\0\0\0\0\0", 6) || t.channel[6] >= 4 || !valid_peer(t.bbs) ||
      !valid_peer(t.endpoint))
    return false;
  memcpy(endpoint, t.endpoint, 32);
  return true;
}

bool beam_regular_address(const uint8_t seed[64], uint64_t index, char (&out)[kBeamRegularAddressSize]) {
  out[0] = 0;
  if (!seed || !index)
    return false;
  try {
    RegularToken t{};
    if (!beam_endpoint(seed, index, t.endpoint))
      return false;
    ECC::HKdf master;
    beam_keys::master_key(seed, master);
    ECC::Hash::Value id;
    ECC::Key::ID(index, ECC::Key::Type::Bbs).get_Hash(id);
    ECC::Scalar::Native secret;
    master.DeriveKey(secret, id);
    ECC::Point pub = ECC::Point::Native(ECC::Context::get().G * secret);
    memcpy(t.bbs, pub.m_X.m_pData, sizeof(t.bbs));
    t.channel[6] = t.bbs[6] & 3;
    t.channel[7] = t.bbs[7];
    memcpy(t.header, kHeader, sizeof(kHeader));
    memcpy(t.permanent, kPermanent, sizeof(kPermanent));
    memcpy(t.endpoint_header, kEndpoint, sizeof(kEndpoint));
    size_t size = sizeof(out);
    return b58enc(out, &size, &t, sizeof(t));
  } catch (const std::exception &) {
    return false;
  }
}
} // namespace hexwallet
