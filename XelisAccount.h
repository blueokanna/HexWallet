#pragma once
#include <stddef.h>
#include <stdint.h>

namespace hexwallet {
// Native 24-word key encoding with an optional 25th checksum word.
// Accepts the published English and Simplified Chinese lists.
bool xelis_recover_private_key(const char *mnemonic, uint8_t secret[32]);
bool xelis_account(const uint8_t secret[32], uint8_t public_key[32], char *address, size_t capacity);
bool xelis_public_key_from_address(const char *address, uint8_t public_key[32]);
// Native Schnorr primitive. Only a reviewed confidential transaction builder
// may expose spending through a transport.
bool xelis_sign_message(const uint8_t secret[32], const uint8_t *message, size_t size, uint8_t signature[64]);
bool xelis_verify_message(const uint8_t public_key[32], const uint8_t *message, size_t size,
                          const uint8_t signature[64]);
} // namespace hexwallet
