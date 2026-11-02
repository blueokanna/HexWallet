#ifndef HEXWALLET_TOTP_ACCOUNTS_H
#define HEXWALLET_TOTP_ACCOUNTS_H

#include "Totp.h"

namespace hexwallet {

constexpr size_t kTotpAccountLimit = 8;
constexpr size_t kTotpUriMaxBytes = 1024;
constexpr size_t kTotpCodeTextSize = 9;

struct TotpAccountInfo {
  char issuer[48];
  char account[64];
  uint32_t period;
  uint32_t digits;
  TotpAlgorithm algorithm;
};

class TotpAccounts {
 public:
  TotpAccounts();
  ~TotpAccounts();
  TotpAccounts(const TotpAccounts &) = delete;
  TotpAccounts &operator=(const TotpAccounts &) = delete;
  TotpError import_uri(const char *uri, size_t size, uint8_t *out_slot);
  bool info(uint8_t slot, TotpAccountInfo *out) const;
  bool remove(uint8_t slot);
  void clear();

  TotpError generate(uint8_t slot, uint64_t now_ms,
                     char out_code[kTotpCodeTextSize],
                     uint32_t *out_remaining) const;

 private:
  struct Entry {
    TotpAccountInfo info;
    uint8_t secret[kTotpSecretMaxBytes];
    size_t secret_size;
    bool occupied;
  } entries_[kTotpAccountLimit];
};

}

#endif
