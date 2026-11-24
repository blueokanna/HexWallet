#ifndef HEXWALLET_KEY_BACKUP_H
#define HEXWALLET_KEY_BACKUP_H
#include "WalletSecurity.h"

namespace hexwallet {
enum class BitcoinKeyNetwork : uint8_t { Mainnet, Testnet };
struct BitcoinPrivateKey {
  uint8_t bytes[32];
  bool compressed;
  BitcoinKeyNetwork network;
};
// Run on a serialized worker. Callback may yield and return false to cancel;
// it must not inspect scratch, retain secrets or re-enter this operation.
using KeyBackupProgress = bool (*)(void *context);
struct KeyBackupControl {
  KeyBackupProgress progress = nullptr;
  void *context = nullptr;
};
// Strict WIF or exactly 64 hex characters. Network is always explicit. A raw
// scalar has no compression/network metadata: the caller supplies both.
WalletError private_key_decode(const char *text, size_t length,
                               BitcoinKeyNetwork network, bool hex_compressed,
                               BitcoinPrivateKey *out);
WalletError private_key_encode_wif(const BitcoinPrivateKey &key, char *out, size_t capacity);
WalletError bitcoin_key_address(const BitcoinPrivateKey &key, char *out, size_t capacity);
// Non-EC encryption; recovery accepts both non-EC and EC-multiplied BIP38,
// including lot/sequence. BIP38 binds a legacy P2PKH address. Explicit lengths
// preserve embedded U+0000. A passphrase may occupy at most 128 UTF-8 bytes.
WalletError bip38_encrypt(const BitcoinPrivateKey &key, const uint8_t *passphrase,
                         size_t length, char *out, size_t capacity,
                         KeyBackupControl control = {});
WalletError bip38_decrypt(const char *encrypted, size_t encrypted_size,
                         const uint8_t *passphrase, size_t length,
                         BitcoinKeyNetwork network, BitcoinPrivateKey *out,
                         KeyBackupControl control = {});
}
#endif
