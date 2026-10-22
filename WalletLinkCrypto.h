#ifndef HEXWALLET_LINK_CRYPTO_H
#define HEXWALLET_LINK_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{
    constexpr size_t kLinkKeySize = 32;
    constexpr size_t kLinkNonceSize = 12;
    constexpr size_t kLinkTagSize = 32;

    // RFC 5869 HKDF-SHA256. out_size must be <= 96 bytes.
    bool link_hkdf_sha256(const uint8_t *ikm, size_t ikm_size,
                          const uint8_t *salt, size_t salt_size,
                          const uint8_t *info, size_t info_size,
                          uint8_t *out, size_t out_size);

    // RFC 8439 ChaCha20 keystream XOR. The 32-bit block counter starts at
    // `counter` and wraps; callers must not reuse (key, nonce, counter) pairs.
    bool link_chacha20_xor(const uint8_t key[kLinkKeySize],
                           const uint8_t nonce[kLinkNonceSize], uint32_t counter,
                           const uint8_t *input, size_t size, uint8_t *output);

    // Encrypt-then-MAC seal/open. ciphertext may alias plaintext; tag is always
    // 32 bytes. On authentication failure open() clears output and returns false.
    bool link_aead_seal(const uint8_t key[kLinkKeySize],
                        const uint8_t nonce[kLinkNonceSize],
                        const uint8_t *aad, size_t aad_size,
                        const uint8_t *plaintext, size_t plaintext_size,
                        uint8_t *ciphertext, uint8_t out_tag[kLinkTagSize]);
    bool link_aead_open(const uint8_t key[kLinkKeySize],
                        const uint8_t nonce[kLinkNonceSize],
                        const uint8_t *aad, size_t aad_size,
                        const uint8_t *ciphertext, size_t ciphertext_size,
                        const uint8_t tag[kLinkTagSize], uint8_t *plaintext);

    bool run_link_crypto_self_test();

} // namespace hexwallet

#endif
