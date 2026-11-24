// Public test vectors only. This entry point is never built into the device.
#include "WalletKeyBackup.h"
#include "WalletBackupJob.h"
#include "WalletWorker.h"
#include "UnicodeNormalizer.h"
#include "ChainCommon.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace hexwallet;
namespace {
bool fail_allocation = false;
bool cancel_on_allocation = false;
unsigned allocations = 0, releases = 0;
}
namespace hexwallet {
void *backup_probe_alloc(size_t size) {
  ++allocations;
  if (fail_allocation) return nullptr;
  void *data = malloc(size);
  if (data) memset(data, 0xa5, size);
  if (cancel_on_allocation) bitcoin_backup_cancel();
  return data;
}
void backup_probe_free(void *data, size_t size) {
  const auto *bytes = static_cast<const uint8_t *>(data);
  for (size_t i = 0; i < size; ++i) if (bytes[i]) abort();
  ++releases;
  free(data);
}
}
static bool cancelled(void *) { return false; }
static void print_hex(const char *label, const uint8_t *data, size_t size) {
  printf("%s=", label);
  for (size_t i = 0; i < size; ++i) printf("%02x", data[i]);
  puts("");
}
int key_backup_probe(int argc, char **argv) {
  if (argc < 4) return 2;
  const auto network = argc > 5 && !strcmp(argv[5], "test") ? BitcoinKeyNetwork::Testnet : BitcoinKeyNetwork::Mainnet;
  BitcoinPrivateKey key{};
  uint8_t passphrase[256]{};
  size_t length = 0;
  if (argc > 4 && !chain_parse_hex(argv[4], passphrase, sizeof(passphrase), &length) && argv[4][0]) return 2;
  WalletError error;
  char encoded[59]{};
  if (!strcmp(argv[2], "mnemonic")) {
    const auto language = !strcmp(argv[3], "zh-hans") ? MnemonicLanguage::ChineseSimplified :
      !strcmp(argv[3], "zh-hant") ? MnemonicLanguage::ChineseTraditional : MnemonicLanguage::English;
    char words[256];
    error = bip39_from_entropy(passphrase, length, language, words, sizeof(words));
    if (error == WalletError::Ok) {
      uint8_t seed[64];
      error = bip39_seed(words, language, "TREZOR", seed);
      print_hex("words", reinterpret_cast<const uint8_t *>(words), strlen(words));
      print_hex("seed", seed, sizeof(seed));
      secure_zero(seed, sizeof(seed));
    }
    secure_zero(words, sizeof(words));
  } else if (!strcmp(argv[2], "worker-decrypt") || !strcmp(argv[2], "worker-encrypt")) {
    const auto operation = !strcmp(argv[2], "worker-decrypt") ? BackupOperation::Decrypt : BackupOperation::Encrypt;
    auto start = [&]() { return bitcoin_backup_begin(operation, network, true, argv[3], strlen(argv[3]), passphrase, length); };
    error = start();
    if (error != WalletError::Ok || start() != WalletError::WorkerUnavailable) return 3;
    const char *mode = argc > 6 ? argv[6] : "";
    fail_allocation = !strcmp(mode, "oom");
    cancel_on_allocation = !strcmp(mode, "cancel-running");
    if (!strcmp(mode, "cancel-finished") && !wallet_worker_wait(0)) return 3;
    if (!strcmp(mode, "cancel") || !strcmp(mode, "cancel-finished")) bitcoin_backup_cancel();
    BitcoinBackupResult result;
    memset(&result, 0x55, sizeof(result));
    if (!bitcoin_backup_poll(error, result) || bitcoin_backup_poll(error, result)) return 3;
    if (error != WalletError::Ok) {
      const uint8_t zeros[sizeof(result)]{};
      if (memcmp(&result, zeros, sizeof(result))) return 3;
    }
    printf("address=%s\n", result.address);
    memcpy(encoded, result.encrypted, sizeof(encoded));
    secure_zero(&result, sizeof(result));
    if (fail_allocation && (allocations != 1 || releases != 0)) return 3;
    if ((cancel_on_allocation || !strcmp(mode, "cancel-finished")) && (allocations != 1 || releases != 1)) return 3;
    if (error != WalletError::Ok) {
      // The same worker must immediately accept another request after cleanup.
      if (start() != WalletError::Ok) return 3;
      bitcoin_backup_cancel();
      WalletError retry_status;
      if (!bitcoin_backup_poll(retry_status, result) || retry_status != WalletError::Aborted) return 3;
    }
  } else if (!strcmp(argv[2], "parse")) {
    memset(key.bytes, 0xa5, sizeof(key.bytes));
    error = private_key_decode(argv[3], strlen(argv[3]), network, true, &key);
  } else if (!strcmp(argv[2], "decrypt")) {
    memset(key.bytes, 0xa5, sizeof(key.bytes));
    KeyBackupControl control;
    if (argc > 6 && !strcmp(argv[6], "cancel")) control.progress = cancelled;
    error = bip38_decrypt(argv[3], strlen(argv[3]), passphrase, length, network, &key, control);
  } else if (!strcmp(argv[2], "encrypt")) {
    error = private_key_decode(argv[3], strlen(argv[3]), network, true, &key);
    if (error == WalletError::Ok) error = bip38_encrypt(key, passphrase, length, encoded, sizeof(encoded));
  } else if (!strcmp(argv[2], "seed")) {
    uint8_t seed[64];
    error = bip39_seed(argv[3], MnemonicLanguage::English, passphrase, length, seed);
    print_hex("seed", seed, sizeof(seed));
    secure_zero(seed, sizeof(seed));
  } else if (!strcmp(argv[2], "normalize")) {
    uint8_t out[2304];
    size_t size = 0;
    error = normalize_passphrase(passphrase, length, !strcmp(argv[3], "nfc") ? UnicodeForm::Nfc : UnicodeForm::Nfkd, out, sizeof(out), &size);
    print_hex("normalized", out, size);
    secure_zero(out, sizeof(out));
  } else return 2;
  printf("error=%u\n", static_cast<unsigned>(error));
  print_hex("key", key.bytes, 32);
  printf("compressed=%u\n", key.compressed ? 1 : 0);
  if (encoded[0]) printf("encrypted=%s\n", encoded);
  if (error == WalletError::Ok && (!strcmp(argv[2], "parse") || !strcmp(argv[2], "decrypt"))) {
    char wif[53];
    if (private_key_encode_wif(key, wif, sizeof(wif)) != WalletError::Ok) return 3;
    printf("wif=%s\n", wif);
    secure_zero(wif, sizeof(wif));
  }
  secure_zero(passphrase, sizeof(passphrase));
  secure_zero(&key, sizeof(key));
  return 0;
}
