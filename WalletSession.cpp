#include "WalletSession.h"

#include <string.h>
#include "WalletConfig.h"
#include "WalletCustody.h"

namespace hexwallet {
namespace {

constexpr size_t kMnemonicSize = 256;
char mnemonic[kMnemonicSize];
bool loaded = false;

}

bool wallet_session_is_loaded() {
  return loaded && wallet_session_custody_available();
}

bool wallet_session_custody_available() {
#if HEXWALLET_REQUIRE_SECURE_CUSTODY
  return secure_custody_backend_ready();
#else
  return true;
#endif
}

WalletError wallet_session_generate() {
  wallet_session_clear();
  if (!wallet_session_custody_available()) return WalletError::CustodyUnavailable;
  const WalletError result = bip39_generate_english_24(mnemonic, sizeof(mnemonic));
  loaded = result == WalletError::Ok;
  if (!loaded) wallet_session_clear();
  return result;
}

WalletError wallet_session_import(const char *words) {
  if (!wallet_session_custody_available()) {
    wallet_session_clear();
    return WalletError::CustodyUnavailable;
  }
  if (words == nullptr || strlen(words) >= sizeof(mnemonic)) return WalletError::InvalidArgument;
  const WalletError result = bip39_validate_english(words);
  if (result != WalletError::Ok) return result;
  wallet_session_clear();
  memcpy(mnemonic, words, strlen(words) + 1);
  loaded = true;
  return WalletError::Ok;
}

WalletError wallet_session_load_master(HdPrivateNode *master) {
  if (master == nullptr) return WalletError::InvalidArgument;
  secure_zero(master, sizeof(*master));
  if (!wallet_session_custody_available()) return WalletError::CustodyUnavailable;
  if (!loaded) return WalletError::InvalidArgument;
  uint8_t seed[kSeedSize] = {};
  WalletError result = bip39_seed_from_english(mnemonic, "", seed);
  if (result == WalletError::Ok) result = hd_private_from_seed(seed, sizeof(seed), master);
  secure_zero(seed, sizeof(seed));
  if (result != WalletError::Ok) secure_zero(master, sizeof(*master));
  return result;
}

WalletError wallet_session_load_seed(uint8_t out_seed[kSeedSize]) {
  if (out_seed == nullptr) return WalletError::InvalidArgument;
  secure_zero(out_seed, kSeedSize);
  if (!wallet_session_custody_available()) return WalletError::CustodyUnavailable;
  if (!loaded) return WalletError::InvalidArgument;
  const WalletError result = bip39_seed_from_english(mnemonic, "", out_seed);
  if (result != WalletError::Ok) secure_zero(out_seed, kSeedSize);
  return result;
}

const char *wallet_session_mnemonic_for_export() {
#if HEXWALLET_ENABLE_SECRET_EXPORT && !HEXWALLET_REQUIRE_SECURE_CUSTODY
  return loaded ? mnemonic : nullptr;
#else
  // Enforce at the secret's owner, not only at individual CLI call sites.
  return nullptr;
#endif
}

void wallet_session_clear() {
  secure_zero(mnemonic, sizeof(mnemonic));
  loaded = false;
}

}
