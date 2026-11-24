#ifndef HEXWALLET_UNICODE_NORMALIZER_H
#define HEXWALLET_UNICODE_NORMALIZER_H

#include "WalletSecurity.h"

namespace hexwallet {
enum class UnicodeForm { Nfkd, Nfc };
// Byte lengths are explicit: BIP38 permits embedded U+0000 in a passphrase.
// Input is bounded to 128 UTF-8 bytes; output is never truncated. No trimming,
// case folding, removal of controls or replacement of malformed UTF-8 occurs.
WalletError normalize_passphrase(const uint8_t *input, size_t length,
                                UnicodeForm form, uint8_t *output,
                                size_t capacity, size_t *written);
}
#endif
