#ifndef HEXWALLET_BACKUP_JOB_H
#define HEXWALLET_BACKUP_JOB_H

#include "WalletKeyBackup.h"

namespace hexwallet {
enum class BackupOperation { Encrypt, Decrypt, ReadKey };
struct BitcoinBackupResult {
  char address[36];
  char encrypted[59];
  bool compressed;
};

// Single Arduino-loop owner. The worker copies input, derives the public
// address and erases the scalar. A cancelled result is never delivered.
WalletError bitcoin_backup_begin(BackupOperation operation, BitcoinKeyNetwork network,
                                 bool compressed, const char *input, size_t input_size,
                                 const uint8_t *password, size_t password_size);
void bitcoin_backup_cancel();
bool bitcoin_backup_poll(WalletError &error, BitcoinBackupResult &out);
}
#endif
