#include "WalletSession.h"

#include <string.h>

namespace hexwallet {
namespace {

constexpr size_t kMnemonicSize = 256;
char mnemonic[kMnemonicSize];
bool loaded = false;

}

bool wallet_session_is_loaded() {
  return loaded;
}

WalletError wallet_session_generate() {
  wallet_session_clear();
  const WalletError result = bip39_generate_english_24(mnemonic, sizeof(mnemonic));
  loaded = result == WalletError::Ok;
  return result;
}

WalletError wallet_session_import(const char *words) {
  if (words == nullptr || strlen(words) >= sizeof(mnemonic)) return WalletError::InvalidArgument;
  const WalletError result = bip39_validate_english(words);
  if (result != WalletError::Ok) return result;
  wallet_session_clear();
  memcpy(mnemonic, words, strlen(words) + 1);
  loaded = true;
  return WalletError::Ok;
}

WalletError wallet_session_load_master(HdPrivateNode *master) {
  if (!loaded || master == nullptr) return WalletError::InvalidArgument;
  uint8_t seed[kSeedSize];
  WalletError result = bip39_seed_from_english(mnemonic, "", seed);
  if (result == WalletError::Ok) result = hd_private_from_seed(seed, sizeof(seed), master);
  secure_zero(seed, sizeof(seed));
  return result;
}

const char *wallet_session_mnemonic_for_export() {
  return loaded ? mnemonic : nullptr;
}

void wallet_session_clear() {
  secure_zero(mnemonic, sizeof(mnemonic));
  loaded = false;
}

}
