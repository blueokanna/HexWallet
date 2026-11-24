#include "WalletBackupJob.h"
#include "SensitiveValue.h"
#include "WalletWorker.h"
#include <atomic>
#include <string.h>
#ifdef ARDUINO_ARCH_ESP32
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#endif

namespace hexwallet {
namespace {
struct BackupInput {
  char text[65];
  uint8_t password[kBip39MaxPassphraseBytes];
  size_t text_size, password_size;
  BackupOperation operation;
  BitcoinKeyNetwork network;
  bool compressed;
};
BackupInput request{};
BitcoinBackupResult result{};
WalletError outcome = WalletError::Aborted;
std::atomic<bool> cancelled{false};
bool active = false;

bool keep_working(void *) {
#ifdef ARDUINO_ARCH_ESP32
  vTaskDelay(1);
#endif
  return !cancelled.load(std::memory_order_relaxed);
}

void run(void *) {
  SensitiveValue<BitcoinPrivateKey> key;
  const KeyBackupControl control{keep_working, nullptr};
  outcome = WalletError::Aborted;
  if (keep_working(nullptr)) {
    if (request.operation == BackupOperation::Decrypt) {
      outcome = bip38_decrypt(request.text, request.text_size, request.password, request.password_size,
                              request.network, &key.get(), control);
    } else {
      outcome = private_key_decode(request.text, request.text_size, request.network, request.compressed, &key.get());
      if (outcome == WalletError::Ok && request.operation == BackupOperation::Encrypt)
        outcome = bip38_encrypt(key.get(), request.password, request.password_size,
                                result.encrypted, sizeof(result.encrypted), control);
    }
    if (outcome == WalletError::Ok) {
      outcome = bitcoin_key_address(key.get(), result.address, sizeof(result.address));
      result.compressed = key.get().compressed;
    }
  }
  secure_zero(&request, sizeof(request));
  if (outcome != WalletError::Ok || cancelled.load(std::memory_order_relaxed)) secure_zero(&result, sizeof(result));
}
}

WalletError bitcoin_backup_begin(BackupOperation operation, BitcoinKeyNetwork network, bool compressed,
                                 const char *input, size_t input_size, const uint8_t *password, size_t password_size) {
  if (!input || !input_size || input_size >= sizeof(request.text) || password_size > sizeof(request.password) ||
      (password_size && !password)) return WalletError::InvalidArgument;
  if (active || (!wallet_worker_ready() && !wallet_worker_start())) return WalletError::WorkerUnavailable;
  cancelled.store(false, std::memory_order_relaxed);
  request.operation = operation;
  request.network = network;
  request.compressed = compressed;
  request.text_size = input_size;
  request.password_size = password_size;
  memcpy(request.text, input, input_size);
  if (password_size) memcpy(request.password, password, password_size);
  if (!wallet_worker_begin(run, nullptr)) {
    secure_zero(&request, sizeof(request));
    return WalletError::WorkerUnavailable;
  }
  active = true;
  return WalletError::Ok;
}

void bitcoin_backup_cancel() {
  if (active) cancelled.store(true, std::memory_order_relaxed);
}

bool bitcoin_backup_poll(WalletError &error, BitcoinBackupResult &out) {
  if (!active || !wallet_worker_wait(0)) return false;
  error = cancelled.load(std::memory_order_relaxed) ? WalletError::Aborted : outcome;
  if (error == WalletError::Ok) out = result;
  else secure_zero(&out, sizeof(out));
  secure_zero(&result, sizeof(result));
  active = false;
  return true;
}
}
