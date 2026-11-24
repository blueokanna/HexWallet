#include "WalletSession.h"

#include <string.h>
#include "WalletConfig.h"
#include "WalletCustody.h"
#include "SensitiveValue.h"

#if defined(HEXWALLET_HOST_TEST) && !HEXWALLET_REQUIRE_SECURE_CUSTODY
namespace hexwallet
{
  namespace
  {

    constexpr size_t kMnemonicSize = 256;
    uint8_t session_seed[kSeedSize];
    bool loaded = false;

  }

  bool wallet_session_is_loaded()
  {
    return loaded && wallet_session_custody_available();
  }

  bool wallet_session_custody_available() { return true; }

  WalletError wallet_session_generate(const char *passphrase)
  {
    SensitiveValue<char[kMnemonicSize]> words;
    const WalletError result = bip39_generate_english_24(words.get(), sizeof(words.get()));
    return result == WalletError::Ok ? wallet_session_import(words.get(), passphrase) : result;
  }

  WalletError wallet_session_import(const char *words, const char *passphrase)
  {
    if (words == nullptr || strlen(words) >= kMnemonicSize)
      return WalletError::InvalidArgument;
    SensitiveValue<uint8_t[kSeedSize]> seed;
    const WalletError result = bip39_seed_from_english(words, passphrase, seed.get());
    if (result != WalletError::Ok)
      return result;
    wallet_session_clear();
    memcpy(session_seed, seed.get(), sizeof(session_seed));
    loaded = true;
    return WalletError::Ok;
  }

  WalletError wallet_session_load_master(HdPrivateNode *master)
  {
    if (master == nullptr)
      return WalletError::InvalidArgument;
    secure_zero(master, sizeof(*master));
    if (!wallet_session_custody_available())
      return WalletError::CustodyUnavailable;
    if (!loaded)
      return WalletError::InvalidArgument;
    WalletError result = hd_private_from_seed(session_seed, sizeof(session_seed), master);
    if (result != WalletError::Ok)
      secure_zero(master, sizeof(*master));
    return result;
  }

  WalletError wallet_session_load_seed(uint8_t out_seed[kSeedSize])
  {
    if (out_seed == nullptr)
      return WalletError::InvalidArgument;
    secure_zero(out_seed, kSeedSize);
    if (!wallet_session_custody_available())
      return WalletError::CustodyUnavailable;
    if (!loaded)
      return WalletError::InvalidArgument;
    memcpy(out_seed, session_seed, kSeedSize);
    return WalletError::Ok;
  }

  void wallet_session_clear()
  {
    secure_zero(session_seed, sizeof(session_seed));
    loaded = false;
  }

}

#else
namespace hexwallet
{
  bool wallet_session_is_loaded() { return false; }
  bool wallet_session_custody_available() { return false; }
  WalletError wallet_session_generate(const char *) { return WalletError::CustodyUnavailable; }
  WalletError wallet_session_import(const char *, const char *) { return WalletError::CustodyUnavailable; }
  WalletError wallet_session_load_master(HdPrivateNode *master)
  {
    if (master == nullptr)
      return WalletError::InvalidArgument;
    secure_zero(master, sizeof(*master));
    return WalletError::CustodyUnavailable;
  }
  WalletError wallet_session_load_seed(uint8_t out_seed[kSeedSize])
  {
    if (out_seed == nullptr)
      return WalletError::InvalidArgument;
    secure_zero(out_seed, kSeedSize);
    return WalletError::CustodyUnavailable;
  }
  void wallet_session_clear() {}
}
#endif
namespace hexwallet
{
  namespace
  {

    struct CustodyWalletLayerRegistration
    {
      CustodyWalletLayerRegistration()
      {
        custody_set_wallet_layer_query(&wallet_session_custody_available);
      }
    };

    const CustodyWalletLayerRegistration kCustodyWalletLayerRegistration;

  }
}
