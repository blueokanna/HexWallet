#ifndef HEXWALLET_SECURE_ELEMENT_PORT_H
#define HEXWALLET_SECURE_ELEMENT_PORT_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Secure-element contract for the NXP SE051C2HQ1 (or any later part) plus the
// primitives any GlobalPlatform SCP03 backend must be built from.
//
// Why this file exists instead of a finished driver: a custody backend can only
// be claimed after it has been proven against a physical card (INITIALIZE
// UPDATE + EXTERNAL AUTHENTICATE returning 0x9000, then a key generated inside
// the card and a signature verified outside it). There is no card, no I2C
// wiring and no licensed applet in this repository, so no backend is
// registered and `secure_element_ready()` is false. That is deliberate: a
// compiled-but-unproven driver would let the wallet claim hardware custody it
// does not have.
//
// What is shipped and tested here:
//   * ISO/IEC 7816-3 CRC16/A          - published check value
//   * FIPS-197 AES-128                - published vector
//   * RFC 4493 AES-CMAC               - published vectors
//   * the backend contract and gate   - fail-closed behaviour under test
//
// What is NOT shipped: the SCP03 key-derivation/ICV layout and the T=1 over I2C
// framing. Both are specified in documents that are not reproduced here and
// neither can be validated without the part, so writing them now would be
// guesswork dressed as protocol support. docs/se051-plug-and-trust.md lists
// exactly what has to land, and in which order.

// ISO/IEC 7816-3 CRC16/A: poly 0x1021, init 0xFFFF, no reflection, no xorout.
// The published check value for "123456789" is 0x29B1.
uint16_t iso7816_crc16(const uint8_t *data, size_t size);

// Structural validation of an answer-to-reset: TS must be 0x3B or 0x3F, the
// TA/TB/TC/TD chain and the historical bytes must fit exactly, and when a TCK
// byte is present the XOR of every byte after TS must be zero (ISO 7816-3
// 8.2.5). An I2C ACK proves a device is at the address; a well-formed ATR is
// the first evidence that it is a smart card.
bool iso7816_atr_valid(const uint8_t *atr, size_t size);

// AES-128, encryption direction only (SCP03 uses the forward cipher for CMAC
// and CTR). The S-box is derived from the GF(2^8) inverse plus the affine
// transform instead of a transcribed table, so there is no constant to mistype.
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
