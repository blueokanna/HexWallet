#ifndef HEXWALLET_SECURE_ELEMENT_PORT_H
#define HEXWALLET_SECURE_ELEMENT_PORT_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Authenticated backend lifecycle. Channel readiness is separate from wallet
// custody: the latter requires handle-based derivation and transaction signing.
// Se051ArduinoPort supplies the Arduino transport ABI for NXP Plug & Trust.
// No SCP03 backend or production key provisioning is registered by this file.
// See docs/se051-integration.md for the exact implementation boundary.

// Legacy API name: this is CRC-16/CCITT-FALSE, NOT CRC-A or a verified SE051
// T=1 EDC. poly 0x1021, init 0xFFFF, no reflection, no xorout; check 0x29B1.
uint16_t iso7816_crc16(const uint8_t *data, size_t size);

// Structural validation of an answer-to-reset: TS must be 0x3B or 0x3F, the
// TA/TB/TC/TD chain and the historical bytes must fit exactly, and when a TCK
// byte is present the XOR of every byte after TS must be zero (ISO 7816-3
// 8.2.5). Structural validity does not authenticate a device or an applet.
bool iso7816_atr_valid(const uint8_t *atr, size_t size);

// Reference AES-128/CMAC primitives, not the NXP secure-channel implementation.
// The table-based S-box has not undergone target side-channel validation.
struct Aes128Schedule {
  uint8_t round_keys[176];
};

void aes128_expand_key(const uint8_t key[16], Aes128Schedule *schedule);
void aes128_encrypt_block(const Aes128Schedule &schedule, const uint8_t in[16],
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
struct SecureElementBackend {
  const char *name;
  // Opens the transport, runs the SCP03 handshake and leaves the applet in the
  // authenticated state. Must fail if the card is absent, the applet is
  // missing, the provisioned keys differ, or any status word is not 0x9000.
  // `reason` receives a short ASCII diagnostic on failure.
  bool (*open)(char *reason, size_t reason_size);
  // True only while the card still holds an authenticated channel.
  bool (*session_authenticated)();
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

// Name of the registered backend, or "" when none is registered.
const char *secure_element_name();

void secure_element_close();

bool run_secure_element_self_tests();

}  // namespace hexwallet

#endif
