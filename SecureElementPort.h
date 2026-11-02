#ifndef HEXWALLET_SECURE_ELEMENT_PORT_H
#define HEXWALLET_SECURE_ELEMENT_PORT_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{
  uint16_t iso7816_crc16(const uint8_t *data, size_t size);
  bool iso7816_atr_valid(const uint8_t *atr, size_t size);

  struct Aes128Schedule
  {
    uint8_t round_keys[176];
  };

  void aes128_expand_key(const uint8_t key[16], Aes128Schedule *schedule);
  void aes128_encrypt_block(const Aes128Schedule &schedule, const uint8_t in[16],
                            uint8_t out[16]);
  void aes128_decrypt_block(const Aes128Schedule &schedule, const uint8_t in[16],
                            uint8_t out[16]);

  // AES-128-CMAC (RFC 4493). Returns false only for a null pointer.
  bool aes128_cmac(const uint8_t key[16], const uint8_t *data, size_t size,
                   uint8_t mac[16]);

  // ---------------------------------------------------------------------------
  // Backend contract
  // ---------------------------------------------------------------------------
  //
  // Every function pointer is mandatory. A backend that cannot sign and cannot
  // export a public key is not a custody backend, and registration is rejected
  // rather than producing a half-configured "secure" state.
  struct SecureElementBackend
  {
    const char *name;
    // Opens the transport, runs the SCP03 handshake and leaves the applet in the
    // authenticated state. Must fail if the card is absent, the applet is
    // missing, the provisioned keys differ, or any status word is not 0x9000.
    // `reason` receives a short ASCII diagnostic on failure.
    bool (*open)(char *reason, size_t reason_size);
    // True only while the card still holds an authenticated channel.
    bool (*session_authenticated)();
    // True only while the user credential (PIN) has been verified inside that
    // channel. An SCP03 session authenticates the host, not the person holding
    // the device, so custody needs both facts separately.
    bool (*user_authenticated)();
    // True only when the backend can keep the key material it signs with inside
    // the card. A backend that loads a key into RAM to sign must answer false:
    // reporting a handle is not the same as making the key non-exportable.
    bool (*keys_non_exportable)();
    // Signs a 32-byte digest with a non-exportable key handle held by the card.
    bool (*sign_digest)(uint32_t key_handle, const uint8_t digest[32],
                        uint8_t *signature, size_t *signature_size);
    // Returns the public key for a key handle, so the device never has to trust
    // a host-supplied key.
    bool (*public_key)(uint32_t key_handle, uint8_t *public_key,
                       size_t *public_key_size);
    void (*close)();
  };

  // Registers the single backend a build links. `nullptr` removes it. Returns
  // false for an incomplete or already-registered contract.
  bool secure_element_register_backend(const SecureElementBackend *backend);

  // Opens the registered backend. Returns false when nothing is registered, when
  // the backend refuses, or when it reports success while
  // `session_authenticated()` is still false - such a backend is unregistered
  // immediately, because claiming an open channel is exactly the failure mode a
  // custody gate must not tolerate.
  bool secure_element_open(char *reason, size_t reason_size);

  // True only for a registered backend with an authenticated session.
  bool secure_element_ready();

  // True only while a ready backend also reports a verified user credential.
  // PIN verification has to survive session churn inside the card, so this is
  // asked of the backend every time instead of being cached here.
  bool secure_element_user_authenticated();

  // True only while a ready backend reports that its keys cannot leave the card.
  bool secure_element_keys_non_exportable();

  // Name of the registered backend, or "" when none is registered.
  const char *secure_element_name();

  void secure_element_close();

  bool run_secure_element_self_tests();

} // namespace hexwallet

#endif
