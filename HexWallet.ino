#include <Arduino.h>

#ifndef HEXWALLET_LOOP_TASK_STACK_SIZE
#define HEXWALLET_LOOP_TASK_STACK_SIZE (32 * 1024)
#endif
SET_LOOP_TASK_STACK_SIZE(HEXWALLET_LOOP_TASK_STACK_SIZE);

#include "WalletBoardPort.h"
#include "BitcoinTransaction.h"
#include "KaspaTransaction.h"
#include "TokenCalldata.h"
#include "CosmosTransaction.h"
#include "StellarTransaction.h"
#include "TronTransaction.h"
#include "Totp.h"
#include "XrpTransaction.h"
#include "CryptoExtended.h"
#include "WalletCatalog.h"
#include "WalletCli.h"
#include "WalletConfig.h"
#include "CryptoPrimitives.h"
#include "CryptoNoteAddress.h"
#include "CryptoNoteRingCt.h"
#include "CryptoNoteSpend.h"
#include "CryptoNoteTransaction.h"
#include "CryptoNoteSigning.h"
#include "CryptoNoteMasari.h"
#include "EvmTransaction.h"
#include "ZcashTransaction.h"
#include "QrlXmss.h"
#include "WalletCustody.h"
#include "WalletEngine.h"
#include "WalletLinkCrypto.h"
#include "WalletLink.h"
#include "WalletLinkService.h"
#include "Mascot.h"
#include "WalletNfcApdu.h"
#include "WalletSecurity.h"
#include "WalletSigning.h"
#include "WalletTokens.h"
#include "WalletTransportPolicy.h"
#include "WalletUi.h"
#include "WalletWorker.h"

namespace
{

  bool display_available = false;
  bool security_ready = false;
  bool last_authenticated = false;
  enum SelfTestId : uint8_t
  {
    kCrypto = 0,
    kExtended,
    kCryptonote,
    kCryptonoteRingCt,
    kCryptonoteTransaction,
    kCryptonoteSpend,
    kCryptonoteSigning,
    kQrl,
    kCustody,
    kCatalog,
    kEvm,
    kBip39,
    kBip32,
    kBip84,
    kEvmDerivation,
    kBip340,
    kAddress,
    kNetworks,
    kSighash,
    kKaspa,
    kCalldata,
    kTokens,
    kTransport,
    kBitcoin,
    kZcashSighash,
    kZcash,
    kLinkCrypto,
    kWalletLink,
    kNfcApdu,
    kSigning,
    kTron,
    kCosmos,
    kStellar,
    kAlgorand,
    kNear,
    kTezos,
    kTotp,
    kXrp,
    kSelfTestCount
  };

  const char *const kSelfTestNames[kSelfTestCount] = {
      "crypto",
      "extended",
      "cryptonote",
      "cryptonote-ringct",
      "cryptonote-tx",
      "cryptonote-spend",
      "cryptonote-signing",
      "qrl",
      "custody",
      "catalog",
      "evm",
      "bip39",
      "bip32",
      "bip84",
      "evm-derive",
      "bip340",
      "address",
      "networks",
      "sighash",
      "kaspa",
      "calldata",
      "tokens",
      "transport",
      "bitcoin",
      "zcash-sighash",
      "zcash",
      "link-crypto",
      "wallet-link",
      "nfc-apdu",
      "signing",
      "tron",
      "cosmos",
      "stellar",
      "algorand",
      "near",
      "tezos",
      "totp",
      "xrp",
  };

  struct SelfTestReport
  {
    bool passed[kSelfTestCount];

    bool all_passed() const
    {
      for (uint8_t index = 0; index < kSelfTestCount; ++index)
      {
        if (!passed[index])
          return false;
      }
      return true;
    }
  };

  void run_self_tests(void *context)
  {
    SelfTestReport *report = static_cast<SelfTestReport *>(context);
    report->passed[kCrypto] = hexwallet::run_crypto_self_tests();
    report->passed[kExtended] = hexwallet::run_crypto_extended_self_tests();
    report->passed[kCryptonote] = hexwallet::run_cryptonote_self_tests();
    report->passed[kCryptonoteRingCt] = hexwallet::run_cryptonote_ringct_self_tests();
    report->passed[kCryptonoteTransaction] = hexwallet::run_cryptonote_transaction_self_tests();
    report->passed[kCryptonoteSpend] = hexwallet::run_cryptonote_spend_self_tests();
    report->passed[kCryptonoteSigning] = hexwallet::run_cryptonote_signing_self_tests();
    report->passed[kQrl] = hexwallet::run_qrl_xmss_self_tests();
    report->passed[kCustody] = hexwallet::run_custody_self_tests();
    report->passed[kCatalog] = hexwallet::run_catalog_self_tests();
    report->passed[kEvm] = hexwallet::run_evm_transaction_self_test();
    report->passed[kBip39] = hexwallet::run_bip39_self_test();
    report->passed[kBip32] = hexwallet::run_bip32_self_test();
    report->passed[kBip84] = hexwallet::run_bip84_self_test();
    report->passed[kEvmDerivation] = hexwallet::run_evm_derivation_self_test();
    report->passed[kBip340] = hexwallet::run_bip340_self_test();
    report->passed[kAddress] = hexwallet::run_address_self_tests();
    report->passed[kNetworks] = hexwallet::run_network_profile_self_tests();
    report->passed[kSighash] = hexwallet::run_bitcoin_sighash_self_tests();
    report->passed[kKaspa] = hexwallet::run_kaspa_self_tests();
    report->passed[kCalldata] = hexwallet::run_token_calldata_self_tests();
    report->passed[kTokens] = hexwallet::run_token_profile_self_tests();
    report->passed[kTransport] = hexwallet::run_transport_policy_self_test();
    report->passed[kBitcoin] = hexwallet::run_bitcoin_transaction_self_test();
    report->passed[kZcashSighash] = hexwallet::run_zcash_sighash_self_tests();
    report->passed[kZcash] = hexwallet::run_zcash_transaction_self_test();
    report->passed[kLinkCrypto] = hexwallet::run_link_crypto_self_test();
    report->passed[kWalletLink] = hexwallet::run_wallet_link_self_test();
    report->passed[kNfcApdu] = hexwallet::run_wallet_nfc_apdu_self_test();
    report->passed[kSigning] = hexwallet::run_wallet_signing_self_test();
    report->passed[kTron] = hexwallet::run_tron_self_tests();
    report->passed[kCosmos] = hexwallet::run_cosmos_self_tests();
    report->passed[kStellar] = hexwallet::run_stellar_self_tests();
    report->passed[kAlgorand] = hexwallet::run_algorand_self_tests();
    report->passed[kNear] = hexwallet::run_near_self_tests();
    report->passed[kTezos] = hexwallet::run_tezos_self_tests();
    report->passed[kTotp] = hexwallet::run_totp_self_tests();
    report->passed[kXrp] = hexwallet::run_xrp_self_tests();
  }

  void print_self_test_report(const SelfTestReport &report)
  {
    Serial.print("SELFTEST");
    for (uint8_t index = 0; index < kSelfTestCount; ++index)
    {
      Serial.print(' ');
      Serial.print(kSelfTestNames[index]);
      Serial.print('=');
      Serial.print(report.passed[index] ? "pass" : "FAIL");
    }
    Serial.println();
  }

  SelfTestReport self_test_report;

} // namespace

void setup()
{
  Serial.begin(115200);

  bool self_tests_queued = false;
#if HEXWALLET_RUN_SELF_TESTS && HEXWALLET_DEVICE_SELF_TESTS
  self_test_report = SelfTestReport{};
  self_tests_queued = hexwallet::wallet_worker_start() &&
                      hexwallet::wallet_worker_begin(run_self_tests,
                                                     &self_test_report);
#endif

  display_available = hexwallet::board_display_init();
  if (display_available)
  {
    if (!hexwallet::wallet_ui_init())
    {
      Serial.println("FATAL: LVGL UI initialization failed");
      display_available = false;
    }
    hexwallet::board_power(true);
    Serial.print("INFO: display ");
    Serial.print(hexwallet::board_display_width());
    Serial.print("x");
    Serial.print(hexwallet::board_display_height());
    Serial.print(" (");
    Serial.print(hexwallet::board_name());
    Serial.println(")");
  }
  else
  {
    Serial.print("WARN: no display on ");
    Serial.println(hexwallet::board_name());
  }

  // Companion counters (level, bond, signed/rejected) survive a reboot; a first
  // boot simply has nothing stored yet, which is not an error.
  if (!hexwallet::mascot_nvs_begin())
  {
    Serial.println("INFO: companion starts fresh (no stored state)");
  }

#if HEXWALLET_RUN_SELF_TESTS && HEXWALLET_DEVICE_SELF_TESTS
  if (self_tests_queued)
  {
    if (display_available) hexwallet::wallet_ui_show_busy("Running self-tests...");
    const uint32_t self_test_started = millis();
    while (!hexwallet::wallet_worker_wait(0))
    {
      if (display_available) hexwallet::wallet_ui_service();
      if (static_cast<uint32_t>(millis() - self_test_started) >= HEXWALLET_SELFTEST_TIMEOUT_MS)
      {
        Serial.println("FATAL: self-test did not finish; wallet services disabled");
        return;
      }
      delay(1);
    }
  }
  else
  {
    run_self_tests(&self_test_report);
  }
  print_self_test_report(self_test_report);
  if (!self_test_report.all_passed())
  {
    Serial.println("FATAL: cryptographic self-test failed; wallet services disabled");
    return;
  }
#endif

  security_ready = true;
  if (!hexwallet::wallet_cli_init(display_available))
  {
    Serial.println("FATAL: authenticated CLI initialization failed");
    security_ready = false;
  }
  if (!hexwallet::wallet_link_service_init())
  {
    Serial.println("WARN: phone link identity/pairing store unavailable; NFC/USB requests disabled");
  }
  else if (!hexwallet::wallet_link_service_nfc_begin())
  {
    Serial.print("INFO nfc=");
    Serial.print(hexwallet::wallet_link_service_nfc_state());
    Serial.println("; phone link available over USB only (define HEXWALLET_NFC_PN7161 pins to enable NFC)");
  }
  else
  {
    Serial.println("INFO nfc=ready (PN7161 ISO-DEP card emulation)");
  }
}

void loop()
{
  if (!security_ready)
  {
    delay(10);
    return;
  }
  hexwallet::wallet_cli_service();
  hexwallet::wallet_link_service_tick(millis());
  hexwallet::wallet_link_service_nfc_service(millis());
  if (display_available)
  {
    const bool authenticated = hexwallet::wallet_cli_is_authenticated();
    if (authenticated != last_authenticated)
    {
      hexwallet::wallet_ui_set_authenticated(authenticated);
      last_authenticated = authenticated;
    }
    hexwallet::wallet_ui_service();
  }
}
