#include "UnicodeNormalizer.h"
#include <stdlib.h>
#include <string.h>
#define UTF8PROC_STATIC
#include "src/unicode/utf8proc.h"

namespace hexwallet {
WalletError normalize_passphrase(const uint8_t *input, size_t length,
                                UnicodeForm form, uint8_t *output,
                                size_t capacity, size_t *written) {
  if (written) *written = 0;
  if (!input || !output || !written || length > kBip39MaxPassphraseBytes ||
      (form != UnicodeForm::Nfkd && form != UnicodeForm::Nfc))
    return WalletError::InvalidArgument;
  const auto options = static_cast<utf8proc_option_t>(UTF8PROC_STABLE |
      (form == UnicodeForm::Nfkd ? UTF8PROC_DECOMPOSE | UTF8PROC_COMPAT : UTF8PROC_COMPOSE));
  const auto count = utf8proc_decompose(input, length, nullptr, 0, options);
  if (count < 0) return WalletError::UnsupportedUnicode;
  // Unicode's maximum compatibility expansion is 18 scalars. The hard cap
  // also bounds allocation and sorting work for adversarial combining marks.
  if (count > static_cast<utf8proc_ssize_t>(18 * kBip39MaxPassphraseBytes))
    return WalletError::BufferTooSmall;
  const size_t bytes = (static_cast<size_t>(count) + 1) * sizeof(utf8proc_int32_t);
  auto *work = static_cast<utf8proc_int32_t *>(malloc(bytes));
  if (!work) return WalletError::OutOfMemory;
  WalletError result = WalletError::CryptoFailure;
  if (utf8proc_decompose(input, length, work, count, options) == count) {
    const auto size = utf8proc_reencode(work, count, options);
    if (size >= 0) {
      if (static_cast<size_t>(size) > capacity) result = WalletError::BufferTooSmall;
      else {
        memcpy(output, work, static_cast<size_t>(size));
        *written = static_cast<size_t>(size);
        result = WalletError::Ok;
      }
    }
  }
  secure_zero(work, bytes);
  free(work);
  return result;
}
}
