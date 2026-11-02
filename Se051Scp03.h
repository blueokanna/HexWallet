#ifndef HEXWALLET_SE051_SCP03_H
#define HEXWALLET_SE051_SCP03_H
#include <stddef.h>
#include <stdint.h>
namespace hexwallet {
// Original GP SCP03 S8/AES-128 codec. Short command APDUs, basic logical
// channel, fixed security level 0x33. Not an SE051 transport/backend. Owner
// must validate INITIALIZE UPDATE version/i/key-version and supply fresh host
// entropy, serialize operations, and reset on transport errors/disconnect.
struct Scp03StaticKeys { uint8_t enc[16]; uint8_t mac[16]; };
enum class Scp03Phase : uint8_t {
  Empty, KeysDerived, CardVerified, ExternalAuthenticatePending,
  Established, CommandPending
};
struct Scp03Session {
  uint8_t s_enc[16], s_mac[16], s_rmac[16];
  uint8_t context[16], command_chaining[16];
  uint32_t commands;
  Scp03Phase phase;
};
constexpr size_t kScp03MaxCommandData = 239;
constexpr size_t kScp03MaxResponseData = 256;
// Derivation is not authentication. S-RMAC derives from Key-MAC.
bool scp03_derive_session_keys(const Scp03StaticKeys &keys,
                              const uint8_t context[16], Scp03Session *session);
bool scp03_card_cryptogram(const Scp03Session &session,
                          const uint8_t context[16], uint8_t out[8]);
// Host proof is available only after verifying the received card proof.
bool scp03_host_cryptogram(const Scp03Session &session,
                          const uint8_t context[16], uint8_t out[8]);
bool scp03_verify_card(Scp03Session *session, const uint8_t cryptogram[8]);
bool scp03_external_authenticate(Scp03Session *session, uint8_t *out,
                                size_t capacity, size_t *out_size);
// GP EXTERNAL AUTHENTICATE returns bare 9000, not R-MAC. Only this handshake
// phase accepts it; a bare 9000 cannot authorize an application response.
bool scp03_finish_authentication(Scp03Session *session,
                                const uint8_t *response, size_t size);
bool scp03_authenticated(const Scp03Session &session);
// encrypt_data/encrypted must be true: no per-command policy downgrade.
// Empty data is not padded/encrypted. Exactly one response per command.
bool scp03_wrap_command(Scp03Session *session, uint8_t cla, uint8_t ins,
                       uint8_t p1, uint8_t p2, const uint8_t *data,
                       size_t data_size, bool encrypt_data, bool expect_response,
                       uint8_t *out, size_t capacity, size_t *out_size);
bool scp03_unwrap_response(Scp03Session *session, uint8_t *response,
                          size_t *response_size, bool encrypted, uint16_t *status);
void scp03_reset(Scp03Session *session);
bool run_scp03_self_tests();
}  // namespace hexwallet
#endif
