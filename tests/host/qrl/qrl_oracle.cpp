#include <stdio.h>
#include <string.h>
#include "QrlXmss.h"
#include "CryptoPrimitives.h"
#include "xmss-alt/algsxmss.h"
#include "xmss-alt/xmss_common.h"

namespace hexwallet {
void secure_zero(void *data, size_t size) {
  volatile uint8_t *p = static_cast<volatile uint8_t *>(data);
  while (size--) *p++ = 0;
}
}
using namespace hexwallet;
#define CHECK(x) do { if (!(x)) { printf("FAIL line=%d: %s\n", __LINE__, #x); return 1; } } while (0)

// Deliberately a test-only store. Production must supply durable atomic state.
struct TestStore { uint8_t id[32]; uint32_t high; bool known; bool fail; unsigned writes; };
bool read(void *ctx, const uint8_t id[32], uint32_t *out) {
  auto &s = *static_cast<TestStore *>(ctx);
  if (!s.known || memcmp(id, s.id, 32)) return false;
  *out = s.high; return true;
}
bool reserve(void *ctx, const uint8_t id[32], uint32_t expected, uint32_t next) {
  auto &s = *static_cast<TestStore *>(ctx);
  ++s.writes;
  if (s.fail || !s.known || memcmp(id, s.id, 32) || s.high != expected || next <= expected)
    return false;
  s.high = next; return true;
}
bool zero(const uint8_t *p, size_t size) {
  while (size--) if (*p++) return false;
  return true;
}
int main() {
  CHECK(run_qrl_xmss_self_tests());
  const uint8_t heights[] = {4, 6, 10};
  for (uint8_t height : heights) {
    uint8_t seed[kQrlSeedSize], message[32];
    for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = uint8_t(i + height);
    for (size_t i = 0; i < sizeof(message); ++i) message[i] = uint8_t(i * 7 + 2);
    xmss_params params{};
    xmss_set_params(&params, 32, height, 16, 2);
    uint8_t oracle_pk[64], oracle_sk[132], public_key[kQrlPublicKeySize];
    CHECK(xmss_Genkeypair(SHAKE_256, &params, oracle_pk, oracle_sk, seed) == 0);
    CHECK(qrl_xmss_public_key(seed, height, public_key) == WalletError::Ok);
    CHECK(!memcmp(public_key + 3, oracle_pk, sizeof(oracle_pk)));
    const uint32_t indices[] = {0, 1, (1U << height) - 1};
    for (uint32_t index : indices) {
      TestStore state{};
      state.known = true; state.high = index;
      CHECK(crypto_sha256(public_key, sizeof(public_key), state.id));
      QrlOtsPort storage{&state, read, reserve};
      uint8_t signature[kQrlMaxSignatureSize], expected[kQrlMaxSignatureSize];
      size_t length = sizeof(signature);
      if (index > 1) CHECK(xmss_updateSK(oracle_sk, index) == 0);
      CHECK(xmss_Signmsg(SHAKE_256, &params, oracle_sk, expected, message, sizeof(message)) == 0);
      CHECK(qrl_xmss_sign_digest(seed, public_key, index, message, storage,
                                signature, &length) == QrlSignError::Ok);
      CHECK(state.high == index + 1 && state.writes == 1);
      CHECK(length == qrl_xmss_signature_size(height) && !memcmp(signature, expected, length));
      CHECK(xmss_Verifysig(SHAKE_256, &params.wots_par, message, sizeof(message),
                           signature, oracle_pk, height) == 0);
      CHECK(qrl_xmss_verify_digest(public_key, message, expected, length));
      signature[length - 1] ^= 1;
      CHECK(!qrl_xmss_verify_digest(public_key, message, signature, length));
      signature[length - 1] ^= 1;
      CHECK(!qrl_xmss_verify_digest(public_key, message, signature, length - 1));
      message[0] ^= 1;
      CHECK(!qrl_xmss_verify_digest(public_key, message, signature, length));
      message[0] ^= 1;
      length = sizeof(signature);
      CHECK(qrl_xmss_sign_digest(seed, public_key, index, message, storage,
                                signature, &length) == QrlSignError::OtsReuse);
      CHECK(length == 0 && zero(signature, sizeof(signature)) && state.writes == 1);
      if (height == 4 && index == 0) {
        state.high = 0; state.fail = true;
        length = sizeof(signature);
        CHECK(qrl_xmss_sign_digest(seed, public_key, index, message, storage,
                                  signature, &length) == QrlSignError::OtsCommitFailed);
        CHECK(length == 0 && zero(signature, sizeof(signature)));
        state.fail = false; state.known = false; length = sizeof(signature);
        CHECK(qrl_xmss_sign_digest(seed, public_key, index, message, storage,
                                  signature, &length) == QrlSignError::OtsUnavailable);
        CHECK(length == 0 && zero(signature, sizeof(signature)));
      }
      printf("xmss-shake256 height=%u index=%u oracle=pass\n", height, index);
      fflush(stdout);
    }
  }
  puts("qrl-xmss-oracle=pass");
  return 0;
}
