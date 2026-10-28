#include "WalletCli.h"

#include <Arduino.h>
#include <esp_timer.h>
#include <Preferences.h>
#include <esp_system.h>
#include <stdlib.h>
#include <string.h>

#include "BitcoinTransaction.h"
#include "CryptoNoteAddress.h"
#include "CryptoNoteRingCt.h"
#include "CryptoPrimitives.h"
#include "EvmTransaction.h"
#include "KaspaTransaction.h"
#include "ZcashTransaction.h"
#include "Totp.h"
#include "WalletBoardPort.h"
#include "WalletCatalog.h"
#include "WalletConfig.h"
#include "WalletCustody.h"
#include "WalletEngine.h"
#include "WalletLinkService.h"
#include "WalletMiningCatalog.h"
#include "WalletSecurity.h"
#include "WalletSession.h"
#include "WalletTokens.h"
#include "WalletTransportPolicy.h"
#include "WalletUi.h"
#include "WalletSigning.h"

namespace hexwallet {
#if HEXWALLET_ENABLE_CLI
namespace {

constexpr char kPreferencesNamespace[] = "hexwallet";
constexpr char kProvisionedKey[] = "provisioned";
constexpr char kSaltKey[] = "auth_salt";
constexpr char kVerifierKey[] = "auth_verifier";
constexpr char kFailuresKey[] = "auth_failures";
constexpr size_t kSaltSize = 16;
constexpr size_t kVerifierSize = kSha256Size;
constexpr size_t kChallengeSize = kSha256Size;
constexpr size_t kLineSize = HEXWALLET_MAX_PSBT_BYTES * 2U + 128U;
constexpr size_t kMinimumPinSize = 8;
constexpr size_t kMaximumPinSize = 64;
constexpr uint32_t kMaximumBackoffMs = 10UL * 60UL * 1000UL;
constexpr uint32_t kTransactionApprovalMs = 2UL * 60UL * 1000UL;

Preferences preferences;
bool preferences_open = false;
bool display_is_available = false;
bool provisioned = false;
bool authenticated = false;
bool challenge_active = false;
uint32_t authenticated_at = 0;
uint32_t retry_after = 0;
uint8_t salt[kSaltSize];
uint8_t verifier[kVerifierSize];
uint8_t challenge[kChallengeSize];
char line_buffer[kLineSize];
size_t line_used = 0;
BitcoinSigningRequest pending_transaction;
EvmSigningRequest pending_evm_transaction;
KaspaTransaction pending_kaspa_transaction;
ZcashSigningRequest pending_zcash_transaction;
enum class PendingTransactionKind : uint8_t { None,
                                              Bitcoin,
                                              Evm,
                                              Kaspa,
                                              Zcash };
PendingTransactionKind pending_transaction_kind = PendingTransactionKind::None;
bool transaction_pending = false;
uint32_t transaction_approval = 0;
uint32_t transaction_expires_at = 0;
bool usb_data_enabled = HEXWALLET_USB_DATA_DEFAULT != 0;
uint32_t usb_data_enabled_at = 0;
bool usb_button_down = false;
bool usb_button_long_handled = false;
uint32_t usb_button_down_at = 0;
constexpr uint8_t kUsbApduMagic0 = 0xa5;
constexpr uint8_t kUsbApduMagic1 = 0x5a;
constexpr size_t kUsbApduMax = 5000;
uint8_t usb_apdu_frame[kUsbApduMax + 4];
size_t usb_apdu_used = 0;
size_t usb_apdu_expected = 0;
bool usb_apdu_mode = false;

bool deadline_reached(uint32_t now, uint32_t deadline) {
  return static_cast<int32_t>(now - deadline) >= 0;
}

void print_hex(const uint8_t *data, size_t size) {
  static constexpr char kHex[] = "0123456789abcdef";
  for (size_t index = 0; index < size; ++index) {
    Serial.write(kHex[data[index] >> 4]);
    Serial.write(kHex[data[index] & 0x0f]);
  }
}

void print_hex_reverse(const uint8_t *data, size_t size) {
  while (size != 0) {
    --size;
    print_hex(data + size, 1);
  }
}

bool hex_nibble(char value, uint8_t *out) {
  if (value >= '0' && value <= '9') *out = static_cast<uint8_t>(value - '0');
  else if (value >= 'a' && value <= 'f') *out = static_cast<uint8_t>(value - 'a' + 10);
  else if (value >= 'A' && value <= 'F') *out = static_cast<uint8_t>(value - 'A' + 10);
  else return false;
  return true;
}

bool decode_hex_exact(const char *text, uint8_t *out, size_t out_size) {
  if (text == nullptr || strlen(text) != out_size * 2) return false;
  for (size_t index = 0; index < out_size; ++index) {
    uint8_t high;
    uint8_t low;
    if (!hex_nibble(text[index * 2], &high) || !hex_nibble(text[index * 2 + 1], &low)) return false;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

bool decode_hex(const char *text, uint8_t *out, size_t capacity, size_t *out_size) {
  if (text == nullptr || out == nullptr || out_size == nullptr) return false;
  const size_t text_size = strlen(text);
  if (text_size == 0 || (text_size & 1U) != 0 || text_size / 2 > capacity) return false;
  *out_size = text_size / 2;
  return decode_hex_exact(text, out, *out_size);
}

const char *error_text(WalletError error) {
  switch (error) {
    case WalletError::Ok: return "ok";
    case WalletError::InvalidArgument: return "invalid-argument";
    case WalletError::InvalidMnemonic: return "invalid-mnemonic";
    case WalletError::UnsupportedUnicode: return "unsupported-unicode";
    case WalletError::BufferTooSmall: return "buffer-too-small";
    case WalletError::RandomFailure: return "random-failure";
    case WalletError::CryptoFailure: return "crypto-failure";
    case WalletError::InvalidKey: return "invalid-key";
    case WalletError::InvalidChild: return "invalid-child";
    case WalletError::InvalidPath: return "invalid-path";
    case WalletError::HardenedPublicDerivation: return "hardened-public-derivation";
    case WalletError::Aborted: return "aborted";
    case WalletError::CustodyUnavailable: return "secure-custody-unavailable";
  }
  return "unknown";
}

void clear_pending_transaction() {
  clear_bitcoin_request(&pending_transaction);
  clear_evm_request(&pending_evm_transaction);
  clear_kaspa_transaction(&pending_kaspa_transaction);
  clear_zcash_request(&pending_zcash_transaction);
  pending_transaction_kind = PendingTransactionKind::None;
  transaction_pending = false;
  transaction_approval = 0;
  transaction_expires_at = 0;
}

void clear_wallet() {
  clear_pending_transaction();
  wallet_session_clear();
}

void record_failure() {
  uint32_t failures = preferences.getUInt(kFailuresKey, 0);
  if (failures != UINT32_MAX) ++failures;
  preferences.putUInt(kFailuresKey, failures);
  const uint32_t exponent = failures > 10 ? 10 : failures;
  uint32_t delay_ms = 1000UL << exponent;
  if (delay_ms > kMaximumBackoffMs) delay_ms = kMaximumBackoffMs;
  retry_after = millis() + delay_ms;
  Serial.print("ERR authentication-failed retry-ms=");
  Serial.println(delay_ms);
}

bool require_authentication() {
  if (!authenticated) {
    Serial.println("ERR locked; run auth begin, calculate the HMAC proof, then auth unlock <proof-hex>");
    return false;
  }
  authenticated_at = millis();
  return true;
}

bool load_master(HdPrivateNode *master) {
  if (!wallet_session_is_loaded()) {
    Serial.println("ERR wallet-empty");
    return false;
  }
  const WalletError result = wallet_session_load_master(master);
  if (result != WalletError::Ok) {
    Serial.print("ERR wallet-derive ");
    Serial.println(error_text(result));
    return false;
  }
  return true;
}

uint32_t parse_index(const char *text, bool *ok) {
  if (text == nullptr || *text == '\0') {
    *ok = true;
    return 0;
  }
  uint32_t value = 0;
  for (; *text != '\0'; ++text) {
    if (*text < '0' || *text > '9' || value > 214748364UL) {
      *ok = false;
      return 0;
    }
    value = value * 10U + static_cast<uint32_t>(*text - '0');
    if (value >= kHardenedOffset) {
      *ok = false;
      return 0;
    }
  }
  *ok = true;
  return value;
}

void show_help() {
  Serial.println("OK public: help | status | coin list | coin search <text> | coin show <id> | mining stats | mining list [ASIC|GPU|CPU|HDD] [offset] | mining show <symbol> | token list [network] | token show <id>");
  Serial.println("OK auth: auth provision <pin> <pin> | auth begin | auth unlock <proof-hex> | lock");
  Serial.println("OK wallet: wallet generate | wallet import <mnemonic> | wallet address <id> [index] | wallet custody <id> | wallet token <id> [index] | wallet addresses [index]");
  Serial.println("OK totp: totp time | totp time <unix> | totp <base32> [digits] [period] [sha1|sha256|sha512] | totp clear");
  Serial.println("OK signing: tx inspect [<coin>] <psbt-v0-hex> | tx sign <code> | evm inspect <network> <index> <unsigned-rlp-hex> | evm sign <code> | kaspa inspect <payload-hex> | kaspa sign <code> | zec inspect <ZEC4-payload-hex> | zec sign <code> | tx reject");
  Serial.println("OK link: link status | link pair confirm | link pair reject");
#if HEXWALLET_ENABLE_SECRET_EXPORT
  Serial.println("OK sensitive: wallet secret [index] | selftest");
#else
  Serial.println("OK sensitive: secret export disabled | selftest");
#endif
}

void show_status() {
  Serial.print("OK provisioned=");
  Serial.print(provisioned ? "yes" : "no");
  Serial.print(" authenticated=");
  Serial.print(authenticated ? "yes" : "no");
  Serial.print(" display=");
  Serial.print(display_is_available ? "available" : "absent");
  Serial.print(" wallet=");
  Serial.print(wallet_session_is_loaded() ? "loaded" : "empty");
  Serial.print(" pending-tx=");
  Serial.println(transaction_pending ? "yes" : "no");
}

void provision_pin(char *arguments) {
  if (provisioned) {
    Serial.println("ERR already-provisioned");
    return;
  }
  char *separator = strchr(arguments, ' ');
  if (separator == nullptr) {
    Serial.println("ERR confirmation-required");
    return;
  }
  *separator++ = '\0';
  const size_t pin_size = strlen(arguments);
  if (pin_size < kMinimumPinSize || pin_size > kMaximumPinSize || strcmp(arguments, separator) != 0 || strchr(separator, ' ') != nullptr) {
    Serial.println("ERR pin-policy-or-confirmation");
    secure_zero(arguments, strlen(arguments));
    secure_zero(separator, strlen(separator));
    return;
  }
  esp_fill_random(salt, sizeof(salt));
  uint8_t new_verifier[kVerifierSize];
  const bool derived = crypto_pbkdf2_sha256(reinterpret_cast<const uint8_t *>(arguments), pin_size,
                                            salt, sizeof(salt), HEXWALLET_CLI_PBKDF2_ITERATIONS,
                                            new_verifier, sizeof(new_verifier));
  secure_zero(arguments, pin_size);
  secure_zero(separator, pin_size);
  if (!derived || preferences.putBytes(kSaltKey, salt, sizeof(salt)) != sizeof(salt) || preferences.putBytes(kVerifierKey, new_verifier, sizeof(new_verifier)) != sizeof(new_verifier) || preferences.putBool(kProvisionedKey, true) == 0) {
    secure_zero(new_verifier, sizeof(new_verifier));
    Serial.println("ERR provisioning-failed");
    return;
  }
  memcpy(verifier, new_verifier, sizeof(verifier));
  secure_zero(new_verifier, sizeof(new_verifier));
  preferences.putUInt(kFailuresKey, 0);
  provisioned = true;
  Serial.println("OK provisioned; run auth begin and auth unlock <proof-hex>");
}

void begin_challenge() {
  if (!provisioned) {
    Serial.println("ERR not-provisioned");
    return;
  }
  const uint32_t now = millis();
  if (!deadline_reached(now, retry_after)) {
    Serial.print("ERR backoff retry-ms=");
    Serial.println(retry_after - now);
    return;
  }
  esp_fill_random(challenge, sizeof(challenge));
  challenge_active = true;
  Serial.print("OK challenge salt=");
  print_hex(salt, sizeof(salt));
  Serial.print(" iterations=");
  Serial.print(HEXWALLET_CLI_PBKDF2_ITERATIONS);
  Serial.print(" nonce=");
  print_hex(challenge, sizeof(challenge));
  Serial.println();
}

void unlock(const char *proof_text) {
  if (!challenge_active) {
    Serial.println("ERR challenge-required");
    return;
  }
  uint8_t supplied[kVerifierSize];
  uint8_t expected[kVerifierSize];
  const bool decoded = decode_hex_exact(proof_text, supplied, sizeof(supplied));
  const bool calculated = crypto_hmac_sha256(verifier, sizeof(verifier), challenge,
                                             sizeof(challenge), expected);
  challenge_active = false;
  secure_zero(challenge, sizeof(challenge));
  if (!decoded || !calculated || !crypto_constant_time_equal(supplied, expected, sizeof(expected))) {
    secure_zero(supplied, sizeof(supplied));
    secure_zero(expected, sizeof(expected));
    record_failure();
    return;
  }
  secure_zero(supplied, sizeof(supplied));
  secure_zero(expected, sizeof(expected));
  preferences.putUInt(kFailuresKey, 0);
  authenticated = true;
  authenticated_at = millis();
  retry_after = 0;
  Serial.println("OK unlocked");
}

void print_capabilities(const WalletCatalogEntry &entry) {
  Serial.print(wallet_catalog_has(entry, WalletCapabilityAddress) ? "address" : "none");
  if (wallet_catalog_has(entry, WalletCapabilityTokenAccount)) Serial.print(",token-account");
  if (wallet_catalog_has(entry, WalletCapabilityTransactionReview)) Serial.print(",review");
  if (wallet_catalog_has(entry, WalletCapabilitySigning)) Serial.print(",sign");
}

void show_catalog(const char *query) {
  size_t matches = 0;
  for (size_t index = 0; index < wallet_catalog_count(); ++index) {
    WalletCatalogEntry entry;
    if (!wallet_catalog_at_sorted(index, &entry) || !wallet_catalog_matches(entry, query)) continue;
    Serial.print("coin=");
    Serial.print(entry.id);
    Serial.print(" symbol=");
    Serial.print(entry.symbol);
    Serial.print(" name=\"");
    Serial.print(entry.name);
    Serial.print("\"");
    Serial.print(" slip44=");
    Serial.print(entry.slip44_coin_type);
    Serial.print(" capabilities=");
    print_capabilities(entry);
    Serial.print(" status=\"");
    Serial.print(entry.status);
    Serial.println("\"");
    ++matches;
  }
  Serial.print("OK matches=");
  Serial.println(matches);
}

void show_coin(const char *id) {
  WalletCatalogEntry entry;
  if (!wallet_catalog_find(id, &entry)) {
    Serial.println("ERR unknown-coin");
    return;
  }
  Serial.print("OK id=");
  Serial.print(entry.id);
  Serial.print(" symbol=");
  Serial.print(entry.symbol);
  Serial.print(" name=\"");
  Serial.print(entry.name);
  Serial.print("\"");
  Serial.print(" slip44=");
  Serial.print(entry.slip44_coin_type);
  Serial.print(" capabilities=");
  print_capabilities(entry);
  Serial.print(" status=\"");
  Serial.print(entry.status);
  Serial.println("\"");
}

void handle_coin(char *command) {
  if (strcmp(command, "coin list") == 0) show_catalog("");
  else if (strncmp(command, "coin search ", 12) == 0 && command[12] != '\0') show_catalog(command + 12);
  else if (strncmp(command, "coin show ", 10) == 0 && command[10] != '\0') show_coin(command + 10);
  else Serial.println("ERR invalid-coin-command");
}

bool parse_mining_type(const char *text, MiningCoinType *out) {
  if (text == nullptr || out == nullptr) return false;
  if (strcmp(text, "ASIC") == 0) *out = MiningCoinType::Asic;
  else if (strcmp(text, "GPU") == 0) *out = MiningCoinType::Gpu;
  else if (strcmp(text, "CPU") == 0) *out = MiningCoinType::Cpu;
  else if (strcmp(text, "HDD") == 0) *out = MiningCoinType::Hdd;
  else return false;
  return true;
}

void print_mining_support(const MiningCoinEntry &coin) {
  WalletCatalogEntry entry;
  if (mining_coin_lookup(coin, &entry)) print_capabilities(entry);
}

void show_mining_coin(const char *symbol) {
  const MiningCoinEntry *coin = mining_coin_find(symbol);
  if (coin == nullptr) {
    Serial.println("ERR unknown-mining-coin");
    return;
  }
  Serial.print("OK symbol=");
  Serial.print(coin->symbol);
  Serial.print(" name=\"");
  Serial.print(coin->name);
  Serial.print("\" type=");
  Serial.print(mining_coin_type_name(coin->type));
  Serial.print(" algorithm=\"");
  Serial.print(coin->algorithm);
  Serial.print("\" catalog=");
  Serial.print(coin->catalog_id == nullptr ? "none" : coin->catalog_id);
  Serial.print(" capabilities=");
  print_mining_support(*coin);
  Serial.println();
}

void show_mining_list(bool has_type, MiningCoinType type, size_t offset) {
  size_t matches = 0;
  for (size_t index = 0; index < mining_coin_count(); ++index) {
    MiningCoinEntry coin;
    if (!mining_coin_at(index, &coin)) continue;
    if (has_type && coin.type != type) continue;
    ++matches;
  }
  const size_t end = offset + 25 > matches ? matches : offset + 25;
  Serial.print("BEGIN MINING total=");
  Serial.print(static_cast<unsigned long>(matches));
  Serial.print(" offset=");
  Serial.print(static_cast<unsigned long>(offset));
  Serial.print(" end=");
  Serial.println(static_cast<unsigned long>(end));
  size_t position = 0;
  for (size_t index = 0; index < mining_coin_count() && position < end; ++index) {
    MiningCoinEntry coin;
    if (!mining_coin_at(index, &coin)) continue;
    if (has_type && coin.type != type) continue;
    if (position++ < offset) continue;
    Serial.print(coin.symbol);
    Serial.print(' ');
    Serial.print(mining_coin_type_name(coin.type));
    Serial.print(' ');
    Serial.print(coin.algorithm);
    Serial.print(' ');
    print_mining_support(coin);
    Serial.print(' ');
    Serial.println(coin.catalog_id);
  }
  Serial.println("END MINING");
}

void show_mining_stats() {
  size_t signable = 0;
  for (size_t index = 0; index < mining_coin_count(); ++index) {
    MiningCoinEntry coin;
    if (!mining_coin_at(index, &coin)) continue;
    WalletCatalogEntry entry;
    if (mining_coin_lookup(coin, &entry) &&
        wallet_catalog_has(entry, WalletCapabilitySigning)) {
      ++signable;
    }
  }
  Serial.print("OK mining total=");
  Serial.print(static_cast<unsigned long>(mining_coin_count()));
  Serial.print(" signable=");
  Serial.println(static_cast<unsigned long>(signable));
}

void handle_mining(char *command) {
  if (strcmp(command, "mining stats") == 0) {
    show_mining_stats();
    return;
  }
  if (strncmp(command, "mining show ", 12) == 0 && command[12] != '\0') {
    show_mining_coin(command + 12);
    return;
  }
  if (strncmp(command, "mining list", 11) == 0) {
    char *arguments = command + 11;
    while (*arguments == ' ') ++arguments;
    bool has_type = false;
    MiningCoinType type = MiningCoinType::Asic;
    size_t offset = 0;
    if (*arguments != '\0') {
      char token[8] = {};
      size_t length = 0;
      while (arguments[length] != '\0' && arguments[length] != ' ' &&
             length + 1 < sizeof(token)) {
        token[length] = arguments[length];
        ++length;
      }
      token[length] = '\0';
      if (parse_mining_type(token, &type)) {
        has_type = true;
      } else {
        bool ok = false;
        offset = parse_index(token, &ok);
        if (!ok) {
          Serial.println("ERR invalid-mining-filter");
          return;
        }
      }
      arguments += length;
      while (*arguments == ' ') ++arguments;
      if (*arguments != '\0') {
        bool ok = false;
        offset = parse_index(arguments, &ok);
        if (!ok) {
          Serial.println("ERR invalid-mining-page");
          return;
        }
      }
    }
    show_mining_list(has_type, type, offset);
    return;
  }
  Serial.println("ERR invalid-mining-command");
}

void show_tokens(const char *network_filter) {
  size_t matches = 0;
  for (size_t index = 0; index < kTokenProfileCount; ++index) {
    const TokenProfile &token = kTokenProfiles[index];
    if (network_filter != nullptr && *network_filter != '\0' && strcmp(token.network_id, network_filter) != 0) continue;
    Serial.print("token=");
    Serial.print(token.id);
    Serial.print(" network=");
    Serial.print(token.network_id);
    Serial.print(" symbol=");
    Serial.print(token.symbol);
    Serial.print(" standard=");
    Serial.print(token_standard_text(token.standard));
    Serial.print(" decimals=");
    Serial.print(token.decimals);
    Serial.print(" asset=");
    Serial.print(token.contract_or_mint);
    Serial.print(" capabilities=");
    Serial.print(token_supports_account_address(token) ? "account-address" : "none");
    if (token_supports_transfer_signing(token)) Serial.print(",transfer-signing");
    Serial.print(" status=\"");
    Serial.print(token.status);
    Serial.println("\"");
    ++matches;
  }
  Serial.print("OK matches=");
  Serial.println(matches);
}

void show_token(const char *id) {
  const TokenProfile *token = find_token_profile(id);
  if (token == nullptr) {
    Serial.println("ERR unknown-token");
    return;
  }
  Serial.print("OK token=");
  Serial.print(token->id);
  Serial.print(" network=");
  Serial.print(token->network_id);
  Serial.print(" symbol=");
  Serial.print(token->symbol);
  Serial.print(" name=\"");
  Serial.print(token->name);
  Serial.println("\"");
  Serial.print(" standard=");
  Serial.print(token_standard_text(token->standard));
  Serial.print(" decimals=");
  Serial.print(token->decimals);
  Serial.print(" asset=");
  Serial.println(token->contract_or_mint);
  Serial.print(" capabilities=");
  Serial.print(token_supports_account_address(*token) ? "account-address" : "none");
  if (token_supports_transfer_signing(*token)) Serial.print(",transfer-signing");
  Serial.println();
  Serial.print(" status=\"");
  Serial.print(token->status);
  Serial.println("\"");
}

void handle_token(char *command) {
  if (strcmp(command, "token list") == 0) show_tokens("");
  else if (strncmp(command, "token list ", 11) == 0 && command[11] != '\0') show_tokens(command + 11);
  else if (strncmp(command, "token show ", 11) == 0 && command[11] != '\0') show_token(command + 11);
  else Serial.println("ERR invalid-token-command");
}

bool qrl_progress_hook(uint32_t completed, uint32_t total, void *context) {
  (void)context;
  if (completed == total || (completed % 64U) == 0) {
    Serial.print("INFO qrl-xmss-keygen=");
    Serial.print(completed);
    Serial.print("/");
    Serial.println(total);
  }
  delay(1);
  return true;
}

void print_derived(const NetworkProfile &network, const HdPrivateNode &master,
                   const uint8_t *seed, uint32_t address_index,
                   bool include_private, bool show_on_device = false) {
  DerivedAddress derived;
  const WalletError result =
    network.encoding == AddressEncoding::QrlXmss
      ? derive_address_ex(master, seed, network, 0, 0, address_index,
                          qrl_progress_hook, nullptr, &derived)
      : derive_address(master, seed, network, 0, 0, address_index, &derived);
  if (result != WalletError::Ok) {
    Serial.print("ERR network=");
    Serial.print(network.id);
    Serial.print(" error=");
    Serial.println(error_text(result));
    return;
  }
  if (show_on_device && !wallet_ui_show_address(network.id, derived.address, derived.path)) {
    clear_derived_address(&derived);
    Serial.println("ERR trusted-display-unavailable");
    return;
  }
  Serial.print("network=");
  Serial.print(network.id);
  Serial.print(" symbol=");
  Serial.print(network.symbol);
  Serial.print(" path=");
  Serial.print(derived.path);
  Serial.print(" address=");
  Serial.print(derived.address);
  if (include_private) {
    Serial.print(" private=");
    print_hex(derived.private_key, sizeof(derived.private_key));
  }
  Serial.println();
  clear_derived_address(&derived);
}

void show_addresses(uint32_t address_index, const NetworkProfile *only_network, bool include_secrets) {
  HdPrivateNode master;
  if (!load_master(&master)) return;
  uint8_t seed[kSeedSize];
  const bool have_seed = wallet_session_load_seed(seed) == WalletError::Ok;
  if (include_secrets) {
    const char *mnemonic = wallet_session_mnemonic_for_export();
    char extended[kExtendedKeyTextSize];
    size_t extended_size = sizeof(extended);
    Serial.println("BEGIN SENSITIVE");
    Serial.print("mnemonic=");
    Serial.println(mnemonic == nullptr ? "" : mnemonic);
    if (have_seed) {
      Serial.print("seed=");
      print_hex(seed, sizeof(seed));
      Serial.println();
    }
    Serial.print("master-private=");
    print_hex(master.private_key, sizeof(master.private_key));
    Serial.println();
    Serial.print("master-chain-code=");
    print_hex(master.chain_code, sizeof(master.chain_code));
    Serial.println();
    if (hd_serialize_private(&master, ExtendedKeyFormat::Xprv, extended, &extended_size) == WalletError::Ok) {
      Serial.print("master-xprv=");
      Serial.println(extended);
    }
    secure_zero(extended, sizeof(extended));
  }
  if (only_network != nullptr) {
    print_derived(*only_network, master, have_seed ? seed : nullptr,
                  address_index, include_secrets, !include_secrets);
  } else {
    for (size_t index = 0; index < kNetworkProfileCount; ++index) {
      const NetworkProfile &network = kNetworkProfiles[index];
      if (network.explicit_only_derivation) continue;
      WalletCatalogEntry entry{};
      if (!wallet_catalog_find(network.id, &entry) ||
          !wallet_catalog_has(entry, WalletCapabilityAddress)) continue;
      print_derived(network, master, have_seed ? seed : nullptr,
                    address_index, include_secrets);
    }
  }
  if (include_secrets) Serial.println("END SENSITIVE");
  secure_zero(seed, sizeof(seed));
  secure_zero(&master, sizeof(master));
}

void handle_wallet_address(char *arguments) {
  char *separator = strchr(arguments, ' ');
  const char *index_text = "";
  if (separator != nullptr) {
    *separator++ = '\0';
    index_text = separator;
  }
  WalletCatalogEntry entry;
  if (!wallet_catalog_find(arguments, &entry)) {
    Serial.println("ERR unknown-coin");
    return;
  }
  if (!wallet_catalog_has(entry, WalletCapabilityAddress) || entry.network == nullptr) {
    Serial.print("ERR address-unsupported status=\"");
    Serial.print(entry.status);
    Serial.println("\"");
    return;
  }
  bool valid_index;
  const uint32_t index = parse_index(index_text, &valid_index);
  if (!valid_index) {
    Serial.println("ERR invalid-index");
    return;
  }
  if (entry.network->encoding == AddressEncoding::QrlXmss) {
    Serial.println("INFO qrl-xmss height=10; key generation is CPU-heavy and may take minutes");
  }
  show_addresses(index, entry.network, false);
}

void handle_wallet_token(char *arguments) {
  char *separator = strchr(arguments, ' ');
  const char *index_text = "";
  if (separator != nullptr) {
    *separator++ = '\0';
    index_text = separator;
  }
  const TokenProfile *token = find_token_profile(arguments);
  if (token == nullptr) {
    Serial.println("ERR unknown-token");
    return;
  }
  if (!token_supports_account_address(*token)) {
    Serial.print("ERR token-account-unsupported status=\"");
    Serial.print(token->status);
    Serial.println("\"");
    return;
  }
  bool valid_index;
  const uint32_t index = parse_index(index_text, &valid_index);
  if (!valid_index) {
    Serial.println("ERR invalid-index");
    return;
  }
  const NetworkProfile *network = token_network(*token);
  if (network == nullptr) {
    Serial.println("ERR token-network-unsupported");
    return;
  }
  HdPrivateNode master;
  if (!load_master(&master)) return;
  uint8_t seed[kSeedSize];
  const bool have_seed = wallet_session_load_seed(seed) == WalletError::Ok;
  DerivedAddress derived;
  const WalletError result =
    derive_address(master, have_seed ? seed : nullptr, *network, 0, 0, index, &derived);
  secure_zero(&master, sizeof(master));
  secure_zero(seed, sizeof(seed));
  if (result != WalletError::Ok) {
    Serial.print("ERR token-account ");
    Serial.println(error_text(result));
    return;
  }
  if (!wallet_ui_show_address(network->id, derived.address, derived.path)) {
    clear_derived_address(&derived);
    Serial.println("ERR trusted-display-unavailable");
    return;
  }
  Serial.print("OK token=");
  Serial.print(token->id);
  Serial.print(" network=");
  Serial.print(network->id);
  Serial.print(" standard=");
  Serial.print(token_standard_text(token->standard));
  Serial.print(" asset=");
  Serial.print(token->contract_or_mint);
  Serial.print(" decimals=");
  Serial.print(token->decimals);
  Serial.print(" path=");
  Serial.print(derived.path);
  Serial.print(" account-address=");
  Serial.println(derived.address);
  Serial.println(token_supports_transfer_signing(*token) ? "INFO transfer-signing=evm-inspect-workflow" : "INFO transfer-signing-unavailable");
  clear_derived_address(&derived);
}

const char *key_scheme_text(KeyScheme scheme) {
  switch (scheme) {
    case KeyScheme::Secp256k1Ecdsa: return "secp256k1-ecdsa";
    case KeyScheme::KaspaSchnorr: return "secp256k1-schnorr";
    case KeyScheme::Ed25519Eddsa: return "ed25519-eddsa";
    case KeyScheme::CryptoNoteEdwards: return "cryptonote-edwards";
    case KeyScheme::Bls12381G1: return "bls12-381-g1";
    case KeyScheme::XmssShake256: return "xmss-shake256";
    case KeyScheme::CardanoEd25519Bip32: return "cardano-ed25519-bip32";
    case KeyScheme::ErgoSchnorr: return "ergo-sigma-schnorr";
    case KeyScheme::NemKeccakEd25519: return "nem-keccak-ed25519";
    case KeyScheme::Unsupported: return "unsupported";
  }
  return "unknown";
}

void handle_wallet_custody(char *arguments) {
  while (*arguments == ' ') ++arguments;
  WalletCatalogEntry entry;
  if (!wallet_catalog_find(arguments, &entry) || entry.network == nullptr) {
    Serial.println("ERR unknown-coin");
    return;
  }
  const CustodyPlan plan =
    plan_key_custody(*entry.network, active_secure_element_profile());
  const SecureElementProbeState probe = board_secure_element_probe();
  Serial.print("secure-element-probe=");
  Serial.print(probe == SecureElementProbeState::NotConfigured
                   ? "not-configured"
                   : (probe == SecureElementProbeState::NoResponse
                          ? "no-response"
                          : "present-unverified"));
  Serial.print(" secure-element=");
  Serial.print(active_secure_element_profile().name);
  Serial.print(" network=");
  Serial.print(entry.network->id);
  Serial.print(" scheme=");
  Serial.print(key_scheme_text(plan.scheme));
  Serial.print(" key-in-se=");
  Serial.print(plan.key_can_live_in_se ? "yes" : "no");
  Serial.print(" se-sign=");
  Serial.print(plan.se_can_sign ? "yes" : "no");
  Serial.print(" mcu-holds-key=");
  Serial.print(plan.mcu_must_hold_key ? "yes" : "no");
  Serial.print(" seed-in-mcu=");
  Serial.print(plan.requires_seed_in_mcu ? "yes" : "no");
  Serial.print(" reason=\"");
  Serial.print(plan.reason);
  Serial.println("\"");
}

void handle_wallet(char *command) {
  if (!require_authentication()) return;
  if (strcmp(command, "wallet generate") == 0) {
    const WalletError result = wallet_session_generate();
    Serial.println(result == WalletError::Ok ? "OK wallet-generated-in-volatile-memory" : "ERR wallet-generation-failed");
    return;
  }
  constexpr char kImportPrefix[] = "wallet import ";
  if (strncmp(command, kImportPrefix, sizeof(kImportPrefix) - 1) == 0) {
    const WalletError result = wallet_session_import(command + sizeof(kImportPrefix) - 1);
    Serial.print(result == WalletError::Ok ? "OK wallet-imported-in-volatile-memory" : "ERR import ");
    if (result != WalletError::Ok) Serial.print(error_text(result));
    Serial.println();
    return;
  }
  constexpr char kAddressPrefix[] = "wallet address ";
  if (strncmp(command, kAddressPrefix, sizeof(kAddressPrefix) - 1) == 0) {
    handle_wallet_address(command + sizeof(kAddressPrefix) - 1);
    return;
  }
  constexpr char kTokenPrefix[] = "wallet token ";
  if (strncmp(command, kTokenPrefix, sizeof(kTokenPrefix) - 1) == 0) {
    handle_wallet_token(command + sizeof(kTokenPrefix) - 1);
    return;
  }
  constexpr char kCustodyPrefix[] = "wallet custody ";
  if (strncmp(command, kCustodyPrefix, sizeof(kCustodyPrefix) - 1) == 0) {
    handle_wallet_custody(command + sizeof(kCustodyPrefix) - 1);
    return;
  }
  const bool secret = strncmp(command, "wallet secret", 13) == 0;
  const bool addresses = strncmp(command, "wallet addresses", 16) == 0;
  if (secret || addresses) {
#if !HEXWALLET_ENABLE_SECRET_EXPORT
    if (secret) {
      Serial.println("ERR secret-export-disabled-at-build-time");
      return;
    }
#endif
    const size_t prefix_size = secret ? 13 : 16;
    const char *argument = command + prefix_size;
    if (*argument == ' ') ++argument;
    else if (*argument != '\0') {
      Serial.println("ERR invalid-command");
      return;
    }
    bool valid_index;
    const uint32_t index = parse_index(argument, &valid_index);
    if (!valid_index) {
      Serial.println("ERR invalid-index");
      return;
    }
    show_addresses(index, nullptr, secret);
    return;
  }
  Serial.println("ERR invalid-wallet-command");
}

void print_transaction_review() {
  Serial.println("BEGIN TRANSACTION REVIEW");
  Serial.print("network=");
  Serial.print(pending_transaction.chain.network_id == nullptr ? "?" : pending_transaction.chain.network_id);
  Serial.print(" sighash=");
  Serial.println(pending_transaction.chain.sighash == SighashFamily::ForkId ? "ALL|FORKID" : "ALL");
  Serial.print("inputs=");
  Serial.print(pending_transaction.input_count);
  Serial.print(" input-sats=");
  Serial.println(static_cast<unsigned long long>(pending_transaction.input_total));
  for (size_t index = 0; index < pending_transaction.output_count; ++index) {
    const BitcoinOutput &output = pending_transaction.outputs[index];
    Serial.print("output=");
    Serial.print(index);
    Serial.print(" sats=");
    Serial.print(static_cast<unsigned long long>(output.value));
    Serial.print(" address=");
    Serial.print(output.address);
    Serial.print(" ownership=");
    Serial.println(output.change ? "change" : (output.wallet_owned ? "wallet" : "external"));
  }
  Serial.print("output-sats=");
  Serial.println(static_cast<unsigned long long>(pending_transaction.output_total));
  Serial.print("fee-sats=");
  Serial.print(static_cast<unsigned long long>(pending_transaction.fee));
  Serial.print(" estimated-vbytes=");
  Serial.print(pending_transaction.estimated_vbytes);
  Serial.print(" estimated-fee-rate=");
  Serial.println(pending_transaction.estimated_vbytes == 0 ? 0 : static_cast<unsigned long long>(pending_transaction.fee / pending_transaction.estimated_vbytes));
  Serial.print("review-id=");
  print_hex(pending_transaction.psbt_hash, 8);
  Serial.println();
  Serial.println("END TRANSACTION REVIEW");
}

void inspect_transaction(char *arguments) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = { true, false, display_is_available };
  if (!wallet_transport_allows(WalletTransport::SerialUsb,
                               WalletTransportOperation::SigningRequest, transport_state)) {
    Serial.println("ERR trusted-display-required-for-signing");
    return;
  }
  const NetworkProfile *network = find_network_profile("btc");
  char *separator = strchr(arguments, ' ');
  const char *psbt_hex = arguments;
  if (separator != nullptr) {
    *separator++ = '\0';
    psbt_hex = separator;
    WalletCatalogEntry entry;
    if (!wallet_catalog_find(arguments, &entry) || entry.network == nullptr) {
      Serial.println("ERR unknown-coin");
      return;
    }
    network = entry.network;
  }
  const NetworkSigningPolicy *policy = network == nullptr ? nullptr : find_network_signing_policy(network->id);
  WalletCatalogEntry signing_entry;
  if (network == nullptr || policy == nullptr ||
      (policy->family != SighashFamily::Bitcoin &&
       policy->family != SighashFamily::ForkId) ||
      !wallet_catalog_find(network->id, &signing_entry) ||
      !wallet_catalog_has(signing_entry, WalletCapabilitySigning) ||
      !wallet_catalog_has(signing_entry, WalletCapabilityTransactionReview)) {
    Serial.println("ERR tx-inspect network-signing-unsupported");
    return;
  }
  const BitcoinChainParams chain = {
      network->id,
      network->encoding == AddressEncoding::CashAddr ? network->alt_hrp : nullptr,
      network->utxo, policy->family, policy->fork_id};
  HdPrivateNode master;
  if (!load_master(&master)) return;
  static uint8_t psbt[HEXWALLET_MAX_PSBT_BYTES];
  size_t psbt_size;
  if (!decode_hex(psbt_hex, psbt, sizeof(psbt), &psbt_size)) {
    secure_zero(&master, sizeof(master));
    Serial.println("ERR invalid-psbt-hex");
    return;
  }
  clear_pending_transaction();
  const TransactionError result = bitcoin_parse_psbt(psbt, psbt_size, master, chain, &pending_transaction);
  secure_zero(psbt, sizeof(psbt));
  secure_zero(&master, sizeof(master));
  if (result != TransactionError::Ok) {
    clear_pending_transaction();
    Serial.print("ERR tx-inspect ");
    Serial.println(transaction_error_text(result));
    return;
  }
  uint32_t random_value;
  esp_fill_random(&random_value, sizeof(random_value));
  transaction_approval = random_value % 1000000U;
  transaction_expires_at = millis() + kTransactionApprovalMs;
  transaction_pending = true;
  pending_transaction_kind = PendingTransactionKind::Bitcoin;
  print_transaction_review();
  char approval[7];
  snprintf(approval, sizeof(approval), "%06lu", static_cast<unsigned long>(transaction_approval));
  if (display_is_available) {
    Serial.println("OK confirmation-shown-on-trusted-display expires-ms=120000");
  } else {
    Serial.print("OK confirm-code=");
    Serial.print(approval);
    Serial.println(" expires-ms=120000; compare every output before tx sign");
  }
  WalletUiTransactionReview review = {};
  review.network = network->name;
  review.output_count = pending_transaction.output_count;
  review.fee = pending_transaction.fee;
  review.fee_rate = pending_transaction.estimated_vbytes == 0 ? 0 : pending_transaction.fee / pending_transaction.estimated_vbytes;
  review.approval_code = approval;
  for (size_t index = 0; index < review.output_count; ++index) {
    const BitcoinOutput &output = pending_transaction.outputs[index];
    review.outputs[index] = { output.value, nullptr, output.address,
                              output.change ? "CHANGE" : (output.wallet_owned ? "WALLET" : "EXTERNAL") };
  }
  wallet_ui_show_transaction(review);
  secure_zero(approval, sizeof(approval));
}

void sign_transaction(const char *approval_text) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = { true, false, display_is_available };
  if (!wallet_transport_allows(WalletTransport::SerialUsb,
                               WalletTransportOperation::ApprovalResponse, transport_state)) {
    clear_pending_transaction();
    Serial.println("ERR trusted-display-required-for-approval; review-cleared");
    return;
  }
  if (!transaction_pending || pending_transaction_kind != PendingTransactionKind::Bitcoin) {
    Serial.println("ERR no-reviewed-transaction");
    return;
  }
  const uint32_t now = millis();
  if (deadline_reached(now, transaction_expires_at)) {
    clear_pending_transaction();
    Serial.println("ERR transaction-review-expired");
    return;
  }
  if (approval_text == nullptr || strlen(approval_text) != 6) {
    clear_pending_transaction();
    Serial.println("ERR invalid-confirmation; review-cleared");
    return;
  }
  uint32_t supplied = 0;
  for (size_t index = 0; index < 6; ++index) {
    if (approval_text[index] < '0' || approval_text[index] > '9') {
      clear_pending_transaction();
      Serial.println("ERR invalid-confirmation; review-cleared");
      return;
    }
    supplied = supplied * 10U + static_cast<uint32_t>(approval_text[index] - '0');
  }
  if (supplied != transaction_approval) {
    clear_pending_transaction();
    Serial.println("ERR confirmation-mismatch; review-cleared");
    return;
  }
  HdPrivateNode master;
  if (!load_master(&master)) {
    clear_pending_transaction();
    return;
  }
  uint8_t signed_transaction[HEXWALLET_MAX_PSBT_BYTES];
  size_t signed_size = sizeof(signed_transaction);
  const TransactionError result = bitcoin_sign_request(pending_transaction, master,
                                                       signed_transaction, &signed_size);
  secure_zero(&master, sizeof(master));
  clear_pending_transaction();
  if (result != TransactionError::Ok) {
    secure_zero(signed_transaction, sizeof(signed_transaction));
    Serial.print("ERR tx-sign ");
    Serial.println(transaction_error_text(result));
    return;
  }
  uint8_t wtxid[kSha256Size];
  const bool hashed = crypto_double_sha256(signed_transaction, signed_size, wtxid);
  Serial.print("OK signed-transaction=");
  print_hex(signed_transaction, signed_size);
  Serial.println();
  if (hashed) {
    Serial.print("wtxid=");
    print_hex_reverse(wtxid, sizeof(wtxid));
    Serial.println();
  }
  secure_zero(wtxid, sizeof(wtxid));
  secure_zero(signed_transaction, sizeof(signed_transaction));
  wallet_ui_show_catalog();
}

void inspect_evm_transaction(char *arguments) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = { true, false, display_is_available };
  if (!wallet_transport_allows(WalletTransport::SerialUsb,
                               WalletTransportOperation::SigningRequest, transport_state)) {
    Serial.println("ERR trusted-display-required-for-signing");
    return;
  }
  char *network_end = strchr(arguments, ' ');
  if (network_end == nullptr) {
    Serial.println("ERR invalid-evm-command");
    return;
  }
  *network_end++ = '\0';
  char *index_end = strchr(network_end, ' ');
  if (index_end == nullptr) {
    Serial.println("ERR invalid-evm-command");
    return;
  }
  *index_end++ = '\0';
  const NetworkProfile *network = find_network_profile(arguments);
  if (network == nullptr || network->encoding != AddressEncoding::Evm) {
    Serial.println("ERR unsupported-evm-network");
    return;
  }
  bool valid_index;
  const uint32_t address_index = parse_index(network_end, &valid_index);
  if (!valid_index) {
    Serial.println("ERR invalid-index");
    return;
  }
  uint8_t transaction[kEvmMaxUnsignedTransactionSize];
  size_t transaction_size = 0;
  if (!decode_hex(index_end, transaction, sizeof(transaction), &transaction_size)) {
    secure_zero(transaction, sizeof(transaction));
    Serial.println("ERR invalid-evm-transaction-hex");
    return;
  }
  HdPrivateNode master;
  if (!load_master(&master)) {
    secure_zero(transaction, sizeof(transaction));
    return;
  }
  clear_pending_transaction();
  const EvmTransactionError error = evm_parse_transaction(
    transaction, transaction_size, *network, master, address_index, &pending_evm_transaction);
  secure_zero(&master, sizeof(master));
  secure_zero(transaction, sizeof(transaction));
  if (error != EvmTransactionError::Ok) {
    clear_pending_transaction();
    Serial.print("ERR evm-inspect ");
    Serial.println(evm_transaction_error_text(error));
    return;
  }
  uint32_t random_value;
  esp_fill_random(&random_value, sizeof(random_value));
  transaction_approval = random_value % 1000000U;
  transaction_expires_at = millis() + kTransactionApprovalMs;
  transaction_pending = true;
  pending_transaction_kind = PendingTransactionKind::Evm;
  const bool contract_call = pending_evm_transaction.has_call;
  const char *asset = network->symbol;
  if (contract_call) {
    asset = pending_evm_transaction.token != nullptr
                ? pending_evm_transaction.token->symbol
                : evm_token_standard_name(pending_evm_transaction.call.standard);
  }
  Serial.println("BEGIN TRANSACTION REVIEW");
  Serial.print("network=");
  Serial.print(network->id);
  Serial.print(" type=");
  Serial.println(pending_evm_transaction.type == EvmTransactionType::Eip1559 ? "EIP-1559" : "EIP-155");
  Serial.print("from=");
  Serial.println(pending_evm_transaction.from_address);
  bool recipient_is_zero = true;
  for (size_t index = 0; index < kEvmAddressSize; ++index) {
    if (pending_evm_transaction.call.recipient[index] != 0) recipient_is_zero = false;
  }
  const bool layer_zero_peer =
      pending_evm_transaction.call.standard == EvmTokenStandard::LayerZeroOft ||
      pending_evm_transaction.call.standard == EvmTokenStandard::LayerZeroOnft;
  const char *review_recipient =
      layer_zero_peer && recipient_is_zero
          ? pending_evm_transaction.remote_address_text
          : pending_evm_transaction.recipient_address;
  Serial.print("asset=");
  Serial.print(asset);
  Serial.print(" recipient=");
  Serial.println(review_recipient);
  Serial.print("amount=");
  Serial.print(pending_evm_transaction.amount_text);
  Serial.print(" ");
  Serial.println(asset);
  if (contract_call) {
    Serial.print("call=");
    Serial.print(evm_token_standard_name(pending_evm_transaction.call.standard));
    Serial.print(".");
    Serial.println(token_function_name(pending_evm_transaction.call.function));
    Serial.print("contract=0x");
    print_hex(pending_evm_transaction.contract, kEvmAddressSize);
    Serial.println();
    if (pending_evm_transaction.call.has_token_id) {
      Serial.print("token-id=");
      Serial.println(pending_evm_transaction.token_id_text);
    }
    if (pending_evm_transaction.call.has_value) {
      Serial.print("call-value=");
      Serial.println(pending_evm_transaction.value_text);
    }
    if (pending_evm_transaction.call.has_min_amount) {
      Serial.print("min-amount=");
      Serial.println(pending_evm_transaction.min_amount_text);
    }
    if (pending_evm_transaction.call.standard == EvmTokenStandard::LayerZeroOft) {
      Serial.print("dst-eid=");
      Serial.println(static_cast<unsigned long>(pending_evm_transaction.call.remote_eid));
    }
    if (pending_evm_transaction.call.standard == EvmTokenStandard::LayerZeroOft ||
        pending_evm_transaction.call.standard == EvmTokenStandard::LayerZeroOnft) {
      if (pending_evm_transaction.call.remote_chain_id != 0) {
        Serial.print("remote-chain=");
        Serial.println(static_cast<unsigned long>(pending_evm_transaction.call.remote_chain_id));
      }
      Serial.print("remote=");
      Serial.println(pending_evm_transaction.remote_address_text);
    }
    if (pending_evm_transaction.call.has_nested_call) {
      Serial.print("nested-target=0x");
      print_hex(pending_evm_transaction.call.nested_target, kEvmAddressSize);
      Serial.println();
      Serial.print("nested-selector=0x");
      print_hex(pending_evm_transaction.call.nested_selector, kTokenSelectorSize);
      Serial.println();
      Serial.print("nested-data-bytes=");
      Serial.println(static_cast<unsigned long>(pending_evm_transaction.call.nested_data_size));
    }
    if (pending_evm_transaction.call.has_bytes_tail) {
      Serial.print("call-data-bytes=");
      Serial.println(static_cast<unsigned long>(pending_evm_transaction.call.bytes_tail_size));
    }
  }
  if (pending_evm_transaction.has_native_value) {
    Serial.print("native-value=");
    Serial.print(pending_evm_transaction.native_value_text);
    Serial.print(" ");
    Serial.println(network->symbol);
  }
  Serial.print("nonce=");
  Serial.print(static_cast<unsigned long long>(pending_evm_transaction.nonce));
  Serial.print(" gas-limit=");
  Serial.println(static_cast<unsigned long long>(pending_evm_transaction.gas_limit));
  Serial.print("maximum-fee=");
  Serial.print(pending_evm_transaction.maximum_fee_text);
  Serial.print(" ");
  Serial.println(network->symbol);
  Serial.print("review-id=");
  print_hex(pending_evm_transaction.request_hash, 8);
  Serial.println();
  Serial.println("END TRANSACTION REVIEW");
  char approval[7];
  snprintf(approval, sizeof(approval), "%06lu", static_cast<unsigned long>(transaction_approval));
  if (display_is_available) {
    Serial.println("OK confirmation-shown-on-trusted-display expires-ms=120000");
  } else {
    Serial.print("OK confirm-code=");
    Serial.print(approval);
    Serial.println(" expires-ms=120000");
  }
  char display_amount[256];
  char display_fee[112];
  char output_label[96];
  if (pending_evm_transaction.call.has_token_id) {
    snprintf(display_amount, sizeof(display_amount), "%s %s #%s",
             pending_evm_transaction.amount_text, asset,
             pending_evm_transaction.token_id_text);
  } else {
    snprintf(display_amount, sizeof(display_amount), "%s %s",
             pending_evm_transaction.amount_text, asset);
  }
  if (contract_call) {
    snprintf(output_label, sizeof(output_label), "%s %s",
             evm_token_standard_name(pending_evm_transaction.call.standard),
             token_function_name(pending_evm_transaction.call.function));
  } else {
    snprintf(output_label, sizeof(output_label), "NATIVE TRANSFER");
  }
  snprintf(display_fee, sizeof(display_fee), "%s %s", pending_evm_transaction.maximum_fee_text,
           network->symbol);
  WalletUiTransactionReview review = {};
  review.network = network->name;
  review.output_count = 1;
  review.outputs[0] = { 0, display_amount, review_recipient, output_label };
  review.fee_text = display_fee;
  review.approval_code = approval;
  wallet_ui_show_transaction(review);
  secure_zero(display_amount, sizeof(display_amount));
  secure_zero(display_fee, sizeof(display_fee));
  secure_zero(output_label, sizeof(output_label));
  secure_zero(approval, sizeof(approval));
}

void sign_evm_transaction(const char *approval_text) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = { true, false, display_is_available };
  if (!wallet_transport_allows(WalletTransport::SerialUsb,
                               WalletTransportOperation::ApprovalResponse, transport_state)) {
    clear_pending_transaction();
    Serial.println("ERR trusted-display-required-for-approval; review-cleared");
    return;
  }
  if (!transaction_pending || pending_transaction_kind != PendingTransactionKind::Evm) {
    Serial.println("ERR no-reviewed-evm-transaction");
    return;
  }
  if (deadline_reached(millis(), transaction_expires_at) || approval_text == nullptr || strlen(approval_text) != 6) {
    clear_pending_transaction();
    Serial.println("ERR invalid-or-expired-confirmation; review-cleared");
    return;
  }
  uint32_t supplied = 0;
  for (size_t index = 0; index < 6; ++index) {
    if (approval_text[index] < '0' || approval_text[index] > '9') {
      clear_pending_transaction();
      Serial.println("ERR invalid-confirmation; review-cleared");
      return;
    }
    supplied = supplied * 10U + static_cast<uint32_t>(approval_text[index] - '0');
  }
  if (supplied != transaction_approval) {
    clear_pending_transaction();
    Serial.println("ERR confirmation-mismatch; review-cleared");
    return;
  }
  HdPrivateNode master;
  if (!load_master(&master)) {
    clear_pending_transaction();
    return;
  }
  uint8_t signed_transaction[kEvmMaxSignedTransactionSize];
  size_t signed_size = sizeof(signed_transaction);
  const EvmTransactionError error = evm_sign_transaction(
    pending_evm_transaction, master, signed_transaction, &signed_size);
  secure_zero(&master, sizeof(master));
  clear_pending_transaction();
  if (error != EvmTransactionError::Ok) {
    secure_zero(signed_transaction, sizeof(signed_transaction));
    Serial.print("ERR evm-sign ");
    Serial.println(evm_transaction_error_text(error));
    return;
  }
  uint8_t transaction_hash[kKeccak256Size];
  const bool hashed = crypto_keccak256(signed_transaction, signed_size, transaction_hash);
  Serial.print("OK signed-transaction=");
  print_hex(signed_transaction, signed_size);
  Serial.println();
  if (hashed) {
    Serial.print("tx-hash=0x");
    print_hex(transaction_hash, sizeof(transaction_hash));
    Serial.println();
  }
  secure_zero(transaction_hash, sizeof(transaction_hash));
  secure_zero(signed_transaction, sizeof(signed_transaction));
  wallet_ui_show_catalog();
}

void format_sompi(uint64_t sompi, char *out, size_t out_size) {
  const uint64_t whole = sompi / kKaspaSompiPerKaspa;
  const uint32_t fraction = static_cast<uint32_t>(sompi % kKaspaSompiPerKaspa);
  snprintf(out, out_size, "%llu.%08lu", static_cast<unsigned long long>(whole),
           static_cast<unsigned long>(fraction));
}

void inspect_kaspa_transaction(char *arguments) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = { true, false, display_is_available };
  if (!wallet_transport_allows(WalletTransport::SerialUsb,
                               WalletTransportOperation::SigningRequest, transport_state)) {
    Serial.println("ERR trusted-display-required-for-signing");
    return;
  }
  uint8_t payload[4096];
  size_t payload_size = 0;
  if (!decode_hex(arguments, payload, sizeof(payload), &payload_size)) {
    secure_zero(payload, sizeof(payload));
    Serial.println("ERR invalid-kaspa-payload-hex");
    return;
  }
  clear_pending_transaction();
  const KaspaError error = kaspa_parse_review_payload(
      payload, payload_size, &pending_kaspa_transaction);
  secure_zero(payload, sizeof(payload));
  if (error != KaspaError::Ok) {
    clear_pending_transaction();
    Serial.print("ERR kaspa-inspect ");
    Serial.println(kaspa_error_text(error));
    return;
  }
  uint32_t random_value;
  esp_fill_random(&random_value, sizeof(random_value));
  transaction_approval = random_value % 1000000U;
  transaction_expires_at = millis() + kTransactionApprovalMs;
  transaction_pending = true;
  pending_transaction_kind = PendingTransactionKind::Kaspa;
  Serial.println("BEGIN TRANSACTION REVIEW");
  Serial.println("network=kas type=KASPA-V0");
  Serial.print("inputs=");
  Serial.print(static_cast<unsigned long>(pending_kaspa_transaction.input_count));
  Serial.print(" outputs=");
  Serial.println(static_cast<unsigned long>(pending_kaspa_transaction.output_count));
  Serial.print("input-total=");
  Serial.print(static_cast<unsigned long long>(pending_kaspa_transaction.input_total));
  Serial.println(" sompi");
  Serial.print("output-total=");
  Serial.print(static_cast<unsigned long long>(pending_kaspa_transaction.output_total));
  Serial.println(" sompi");
  char amount[32];
  format_sompi(pending_kaspa_transaction.fee, amount, sizeof(amount));
  Serial.print("fee=");
  Serial.print(static_cast<unsigned long long>(pending_kaspa_transaction.fee));
  Serial.print(" sompi (");
  Serial.print(amount);
  Serial.println(" KAS)");
  Serial.print("mass=");
  Serial.print(static_cast<unsigned long long>(
      pending_kaspa_transaction.compute_mass +
      pending_kaspa_transaction.storage_mass));
  Serial.println();
  for (size_t index = 0; index < pending_kaspa_transaction.output_count; ++index) {
    const KaspaOutput &output = pending_kaspa_transaction.outputs[index];
    Serial.print("output[");
    Serial.print(static_cast<unsigned long>(index));
    Serial.print("]=");
    Serial.print(static_cast<unsigned long long>(output.value));
    Serial.print(" sompi ");
    Serial.println(output.address);
  }
  Serial.print("review-id=");
  Serial.print(static_cast<unsigned long>(pending_kaspa_transaction.request_hash), HEX);
  Serial.println();
  Serial.println("END TRANSACTION REVIEW");
  char approval[7];
  snprintf(approval, sizeof(approval), "%06lu", static_cast<unsigned long>(transaction_approval));
  if (display_is_available) {
    Serial.println("OK confirmation-shown-on-trusted-display expires-ms=120000");
  } else {
    Serial.print("OK confirm-code=");
    Serial.print(approval);
    Serial.println(" expires-ms=120000");
  }
  char amount_texts[kWalletUiMaxTransactionOutputs][32];
  WalletUiTransactionReview review = {};
  review.network = "KASPA";
  review.fee = pending_kaspa_transaction.fee;
  review.fee_text = amount;
  review.approval_code = approval;
  review.output_count = pending_kaspa_transaction.output_count;
  for (size_t index = 0; index < pending_kaspa_transaction.output_count; ++index) {
    format_sompi(pending_kaspa_transaction.outputs[index].value,
                 amount_texts[index], sizeof(amount_texts[index]));
    review.outputs[index] = {
      0, amount_texts[index], pending_kaspa_transaction.outputs[index].address,
      pending_kaspa_transaction.outputs[index].script_size == 34 ? "KASPA P2PK" : "KASPA P2SH"
    };
  }
  wallet_ui_show_transaction(review);
  secure_zero(amount_texts, sizeof(amount_texts));
  secure_zero(amount, sizeof(amount));
  secure_zero(approval, sizeof(approval));
}

void sign_kaspa_transaction(const char *approval_text) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = { true, false, display_is_available };
  if (!wallet_transport_allows(WalletTransport::SerialUsb,
                               WalletTransportOperation::ApprovalResponse, transport_state)) {
    clear_pending_transaction();
    Serial.println("ERR trusted-display-required-for-approval; review-cleared");
    return;
  }
  if (!transaction_pending || pending_transaction_kind != PendingTransactionKind::Kaspa) {
    Serial.println("ERR no-reviewed-kaspa-transaction");
    return;
  }
  if (deadline_reached(millis(), transaction_expires_at) ||
      approval_text == nullptr || strlen(approval_text) != 6) {
    clear_pending_transaction();
    Serial.println("ERR invalid-or-expired-confirmation; review-cleared");
    return;
  }
  uint32_t supplied = 0;
  for (size_t index = 0; index < 6; ++index) {
    if (approval_text[index] < '0' || approval_text[index] > '9') {
      clear_pending_transaction();
      Serial.println("ERR invalid-confirmation; review-cleared");
      return;
    }
    supplied = supplied * 10U + static_cast<uint32_t>(approval_text[index] - '0');
  }
  if (supplied != transaction_approval) {
    clear_pending_transaction();
    Serial.println("ERR confirmation-mismatch; review-cleared");
    return;
  }
  HdPrivateNode master;
  if (!load_master(&master)) {
    clear_pending_transaction();
    return;
  }
  uint8_t signed_transaction[4096];
  size_t signed_size = sizeof(signed_transaction);
  const KaspaError error = kaspa_sign_transaction(
      pending_kaspa_transaction, master, signed_transaction, &signed_size);
  secure_zero(&master, sizeof(master));
  if (error != KaspaError::Ok) {
    clear_pending_transaction();
    secure_zero(signed_transaction, sizeof(signed_transaction));
    Serial.print("ERR kaspa-sign ");
    Serial.println(kaspa_error_text(error));
    return;
  }
  uint8_t transaction_id[32];
  const KaspaError id_error =
      kaspa_transaction_id(pending_kaspa_transaction, transaction_id);
  clear_pending_transaction();
  Serial.print("OK signed-transaction=");
  print_hex(signed_transaction, signed_size);
  Serial.println();
  if (id_error == KaspaError::Ok) {
    Serial.print("txid=");
    print_hex_reverse(transaction_id, sizeof(transaction_id));
    Serial.println();
    Serial.print("txid-raw=");
    print_hex(transaction_id, sizeof(transaction_id));
    Serial.println();
  }
  secure_zero(transaction_id, sizeof(transaction_id));
  secure_zero(signed_transaction, sizeof(signed_transaction));
  wallet_ui_show_catalog();
}

void format_zec(uint64_t zats, char *out, size_t out_size) {
  const uint64_t whole = zats / kZcashZatsPerZec;
  const uint32_t fraction = static_cast<uint32_t>(zats % kZcashZatsPerZec);
  snprintf(out, out_size, "%llu.%08lu", static_cast<unsigned long long>(whole),
           static_cast<unsigned long>(fraction));
}

void inspect_zcash_transaction(char *arguments) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = { true, false, display_is_available };
  if (!wallet_transport_allows(WalletTransport::SerialUsb,
                               WalletTransportOperation::SigningRequest, transport_state)) {
    Serial.println("ERR trusted-display-required-for-signing");
    return;
  }
  const NetworkProfile *network = find_network_profile("zec");
  const NetworkSigningPolicy *policy = find_network_signing_policy("zec");
  const ZcashNetworkPolicy *zcash_policy = find_zcash_network_policy("zec");
  WalletCatalogEntry entry;
  if (network == nullptr || policy == nullptr ||
      policy->family != SighashFamily::ZcashZip243 || zcash_policy == nullptr ||
      !wallet_catalog_find("zec", &entry) ||
      !wallet_catalog_has(entry, WalletCapabilityTransactionReview) ||
      !wallet_catalog_has(entry, WalletCapabilitySigning)) {
    Serial.println("ERR zcash-signing-unsupported");
    return;
  }
  static uint8_t payload[HEXWALLET_MAX_PSBT_BYTES];
  size_t payload_size = 0;
  if (!decode_hex(arguments, payload, sizeof(payload), &payload_size)) {
    secure_zero(payload, sizeof(payload));
    Serial.println("ERR invalid-zcash-payload-hex");
    return;
  }
  const ZcashChainParams chain = {
    network->id, network->alt_p2pkh_version, network->alt_p2sh_version,
    zcash_policy->branch_id, network->derivation_coin_type
  };
  clear_pending_transaction();
  const ZcashError error = zcash_parse_review_payload(
      payload, payload_size, chain, &pending_zcash_transaction);
  secure_zero(payload, sizeof(payload));
  if (error != ZcashError::Ok) {
    clear_pending_transaction();
    Serial.print("ERR zcash-inspect ");
    Serial.println(zcash_error_text(error));
    return;
  }
  uint32_t random_value;
  esp_fill_random(&random_value, sizeof(random_value));
  transaction_approval = random_value % 1000000U;
  transaction_expires_at = millis() + kTransactionApprovalMs;
  transaction_pending = true;
  pending_transaction_kind = PendingTransactionKind::Zcash;
  Serial.println("BEGIN TRANSACTION REVIEW");
  Serial.println("network=zec type=ZCASH-V4-TRANSPARENT");
  Serial.print("branch-id=0x");
  {
    char branch[9];
    snprintf(branch, sizeof(branch), "%08lx",
             static_cast<unsigned long>(pending_zcash_transaction.chain.branch_id));
    Serial.println(branch);
    secure_zero(branch, sizeof(branch));
  }
  Serial.print("inputs=");
  Serial.print(static_cast<unsigned long>(pending_zcash_transaction.input_count));
  Serial.print(" outputs=");
  Serial.println(static_cast<unsigned long>(pending_zcash_transaction.output_count));
  Serial.print("input-zats=");
  Serial.println(static_cast<unsigned long long>(pending_zcash_transaction.input_total));
  Serial.print("output-zats=");
  Serial.println(static_cast<unsigned long long>(pending_zcash_transaction.output_total));
  Serial.print("fee-zats=");
  Serial.print(static_cast<unsigned long long>(pending_zcash_transaction.fee));
  Serial.print(" estimated-vbytes=");
  Serial.println(static_cast<unsigned long>(pending_zcash_transaction.estimated_vbytes));
  Serial.print("expiry-height=");
  Serial.println(static_cast<unsigned long>(pending_zcash_transaction.expiry_height));
  Serial.print("lock-time=");
  Serial.println(static_cast<unsigned long>(pending_zcash_transaction.lock_time));
  for (size_t index = 0; index < pending_zcash_transaction.output_count; ++index) {
    const ZcashOutput &output = pending_zcash_transaction.outputs[index];
    Serial.print("output=");
    Serial.print(static_cast<unsigned long>(index));
    Serial.print(" zats=");
    Serial.print(static_cast<unsigned long long>(output.value));
    Serial.print(" address=");
    Serial.print(output.address);
    Serial.println(" ownership=external");
  }
  Serial.print("review-id=");
  print_hex(pending_zcash_transaction.request_hash, 8);
  Serial.println();
  Serial.println("END TRANSACTION REVIEW");
  char approval[7];
  snprintf(approval, sizeof(approval), "%06lu",
           static_cast<unsigned long>(transaction_approval));
  if (display_is_available) {
    Serial.println("OK confirmation-shown-on-trusted-display expires-ms=120000");
  } else {
    Serial.print("OK confirm-code=");
    Serial.print(approval);
    Serial.println(" expires-ms=120000");
  }
  char amount_texts[kWalletUiMaxTransactionOutputs][32];
  char display_fee[64];
  format_zec(pending_zcash_transaction.fee, display_fee, sizeof(display_fee));
  strncat(display_fee, " ZEC", sizeof(display_fee) - strlen(display_fee) - 1);
  WalletUiTransactionReview review = {};
  review.network = "ZCASH";
  review.fee = pending_zcash_transaction.fee;
  review.fee_text = display_fee;
  review.approval_code = approval;
  review.output_count = pending_zcash_transaction.output_count;
  for (size_t index = 0; index < pending_zcash_transaction.output_count; ++index) {
    format_zec(pending_zcash_transaction.outputs[index].value,
               amount_texts[index], sizeof(amount_texts[index]));
    strncat(amount_texts[index], " ZEC",
            sizeof(amount_texts[index]) - strlen(amount_texts[index]) - 1);
    review.outputs[index] = {
      pending_zcash_transaction.outputs[index].value, amount_texts[index],
      pending_zcash_transaction.outputs[index].address, "EXTERNAL"
    };
  }
  wallet_ui_show_transaction(review);
  secure_zero(amount_texts, sizeof(amount_texts));
  secure_zero(display_fee, sizeof(display_fee));
  secure_zero(approval, sizeof(approval));
}

void sign_zcash_transaction(const char *approval_text) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = { true, false, display_is_available };
  if (!wallet_transport_allows(WalletTransport::SerialUsb,
                               WalletTransportOperation::ApprovalResponse, transport_state)) {
    clear_pending_transaction();
    Serial.println("ERR trusted-display-required-for-approval; review-cleared");
    return;
  }
  if (!transaction_pending || pending_transaction_kind != PendingTransactionKind::Zcash) {
    Serial.println("ERR no-reviewed-zcash-transaction");
    return;
  }
  if (deadline_reached(millis(), transaction_expires_at) ||
      approval_text == nullptr || strlen(approval_text) != 6) {
    clear_pending_transaction();
    Serial.println("ERR invalid-or-expired-confirmation; review-cleared");
    return;
  }
  uint32_t supplied = 0;
  for (size_t index = 0; index < 6; ++index) {
    if (approval_text[index] < '0' || approval_text[index] > '9') {
      clear_pending_transaction();
      Serial.println("ERR invalid-confirmation; review-cleared");
      return;
    }
    supplied = supplied * 10U +
               static_cast<uint32_t>(approval_text[index] - '0');
  }
  if (supplied != transaction_approval) {
    clear_pending_transaction();
    Serial.println("ERR confirmation-mismatch; review-cleared");
    return;
  }
  HdPrivateNode master;
  if (!load_master(&master)) {
    clear_pending_transaction();
    return;
  }
  uint8_t signed_transaction[kZcashMaxTransactionSize];
  size_t signed_size = sizeof(signed_transaction);
  const ZcashError error = zcash_sign_request(
      pending_zcash_transaction, master, signed_transaction, &signed_size);
  secure_zero(&master, sizeof(master));
  clear_pending_transaction();
  if (error != ZcashError::Ok) {
    secure_zero(signed_transaction, sizeof(signed_transaction));
    Serial.print("ERR zcash-sign ");
    Serial.println(zcash_error_text(error));
    return;
  }
  uint8_t transaction_id[kSha256Size];
  const bool hashed =
      crypto_double_sha256(signed_transaction, signed_size, transaction_id);
  Serial.print("OK signed-transaction=");
  print_hex(signed_transaction, signed_size);
  Serial.println();
  if (hashed) {
    Serial.print("txid=");
    print_hex_reverse(transaction_id, sizeof(transaction_id));
    Serial.println();
  }
  secure_zero(transaction_id, sizeof(transaction_id));
  secure_zero(signed_transaction, sizeof(signed_transaction));
  wallet_ui_show_catalog();
}

void handle_zcash(char *command) {
  constexpr char kInspectPrefix[] = "zec inspect ";
  constexpr char kSignPrefix[] = "zec sign ";
  if (strncmp(command, kInspectPrefix, sizeof(kInspectPrefix) - 1) == 0) {
    inspect_zcash_transaction(command + sizeof(kInspectPrefix) - 1);
  } else if (strncmp(command, kSignPrefix, sizeof(kSignPrefix) - 1) == 0) {
    sign_zcash_transaction(command + sizeof(kSignPrefix) - 1);
  } else {
    Serial.println("ERR invalid-zcash-command");
  }
}

void handle_kaspa(char *command) {
  constexpr char kInspectPrefix[] = "kaspa inspect ";
  constexpr char kSignPrefix[] = "kaspa sign ";
  if (strncmp(command, kInspectPrefix, sizeof(kInspectPrefix) - 1) == 0) {
    inspect_kaspa_transaction(command + sizeof(kInspectPrefix) - 1);
  } else if (strncmp(command, kSignPrefix, sizeof(kSignPrefix) - 1) == 0) {
    sign_kaspa_transaction(command + sizeof(kSignPrefix) - 1);
  } else {
    Serial.println("ERR invalid-kaspa-command");
  }
}

void handle_evm(char *command) {
  constexpr char kInspectPrefix[] = "evm inspect ";
  constexpr char kSignPrefix[] = "evm sign ";
  if (strncmp(command, kInspectPrefix, sizeof(kInspectPrefix) - 1) == 0) {
    inspect_evm_transaction(command + sizeof(kInspectPrefix) - 1);
  } else if (strncmp(command, kSignPrefix, sizeof(kSignPrefix) - 1) == 0) {
    sign_evm_transaction(command + sizeof(kSignPrefix) - 1);
  } else {
    Serial.println("ERR invalid-evm-command");
  }
}

void handle_link(char *command) {
  if (!require_authentication()) return;
  if (strcmp(command, "link status") == 0) {
    Serial.print("OK link=");
    Serial.print(wallet_link_service_ready() ? "ready" : "unavailable");
    Serial.print(" nfc=");
    Serial.print(wallet_link_service_nfc_state());
    Serial.print(" pairing-pending=");
    Serial.print(wallet_link_service_pairing_pending() ? "yes" : "no");
    Serial.print(" usb-data=");
    Serial.println(usb_data_enabled ? "on" : "off");
    return;
  }
  if (strcmp(command, "link pair confirm") == 0) {
    Serial.println(wallet_link_service_confirm_pairing()
                       ? "OK phone-paired"
                       : "ERR no-pending-pairing");
    return;
  }
  if (strcmp(command, "link pair reject") == 0) {
    wallet_link_service_reject_pairing();
    Serial.println("OK pairing-rejected");
    return;
  }
  Serial.println("ERR invalid-link-command");
}

void handle_transaction(char *command) {
  constexpr char kInspectPrefix[] = "tx inspect ";
  constexpr char kSignPrefix[] = "tx sign ";
  if (strncmp(command, kInspectPrefix, sizeof(kInspectPrefix) - 1) == 0) {
    inspect_transaction(command + sizeof(kInspectPrefix) - 1);
  } else if (strncmp(command, kSignPrefix, sizeof(kSignPrefix) - 1) == 0) {
    sign_transaction(command + sizeof(kSignPrefix) - 1);
  } else if (strcmp(command, "tx reject") == 0) {
    clear_pending_transaction();
    wallet_ui_show_catalog();
    Serial.println("OK transaction-rejected-and-cleared");
  } else {
    Serial.println("ERR invalid-transaction-command");
  }
}

void run_self_tests() {
  if (!require_authentication()) return;
  const bool crypto = run_crypto_self_tests();
  const bool cryptonote = run_cryptonote_self_tests();
  const bool cryptonote_ringct = run_cryptonote_ringct_self_tests();
  const bool cryptonote_clsag = run_cryptonote_clsag_self_test();
  const bool bip39 = run_bip39_self_test();
  const bool bip32 = run_bip32_self_test();
  const bool evm_derive = run_evm_derivation_self_test();
  const bool address = run_address_self_tests();
  const bool networks = run_network_profile_self_tests();
  const bool tokens = run_token_profile_self_tests();
  const bool transaction = run_bitcoin_transaction_self_test();
  const bool evm = run_evm_transaction_self_test();
  const bool zcash_sighash = run_zcash_sighash_self_tests();
  const bool zcash = run_zcash_transaction_self_test();
  const bool transport = run_transport_policy_self_test();
  Serial.print("OK crypto=");
  Serial.print(crypto ? "pass" : "FAIL");
  Serial.print(" cryptonote=");
  Serial.print(cryptonote ? "pass" : "FAIL");
  Serial.print(" cryptonote-ringct=");
  Serial.print(cryptonote_ringct ? "pass" : "FAIL");
  Serial.print(" cryptonote-clsag=");
  Serial.print(cryptonote_clsag ? "pass" : "FAIL");
  Serial.print(" bip39=");
  Serial.print(bip39 ? "pass" : "FAIL");
  Serial.print(" bip32=");
  Serial.print(bip32 ? "pass" : "FAIL");
  Serial.print(" evm-derive=");
  Serial.print(evm_derive ? "pass" : "FAIL");
  Serial.print(" address=");
  Serial.print(address ? "pass" : "FAIL");
  Serial.print(" networks=");
  Serial.print(networks ? "pass" : "FAIL");
  Serial.print(" tokens=");
  Serial.print(tokens ? "pass" : "FAIL");
  Serial.print(" bip143=");
  Serial.print(transaction ? "pass" : "FAIL");
  Serial.print(" evm=");
  Serial.print(evm ? "pass" : "FAIL");
  Serial.print(" zcash-sighash=");
  Serial.print(zcash_sighash ? "pass" : "FAIL");
  Serial.print(" zcash=");
  Serial.print(zcash ? "pass" : "FAIL");
  Serial.print(" transport-policy=");
  Serial.println(transport ? "pass" : "FAIL");
}

void handle_totp(char *command) {
  if (!require_authentication()) return;
  if (strcmp(command, "totp time") == 0) {
    uint64_t now = 0;
    if (!totp_clock_unix(static_cast<uint64_t>(esp_timer_get_time()) / 1000U, &now)) {
      Serial.println("ERR totp-clock-not-set");
      return;
    }
    Serial.print("OK unix=");
    Serial.println(static_cast<unsigned long long>(now));
    return;
  }
  if (strncmp(command, "totp time ", 10) == 0) {
    char *end = nullptr;
    const unsigned long long unix_seconds = strtoull(command + 10, &end, 10);
    if (end == command + 10 || *end != '\0' || unix_seconds == 0) {
      Serial.println("ERR invalid-unix-time");
      return;
    }
    if (!totp_clock_set_unix(unix_seconds, static_cast<uint64_t>(esp_timer_get_time()) / 1000U)) {
      Serial.println("ERR invalid-unix-time");
      return;
    }
    Serial.println("OK totp-clock-set");
    return;
  }
  if (strcmp(command, "totp clear") == 0) {
    totp_clock_clear();
    Serial.println("OK totp-clock-cleared");
    return;
  }
  if (strncmp(command, "totp ", 5) != 0 || command[5] == '\0') {
    Serial.println("ERR invalid-totp-command");
    return;
  }
  char secret_text[128] = {};
  char *save = nullptr;
  char *token = strtok_r(command + 5, " ", &save);
  if (token == nullptr || strlen(token) >= sizeof(secret_text)) {
    Serial.println("ERR invalid-totp-secret");
    return;
  }
  memcpy(secret_text, token, strlen(token) + 1);
  uint32_t digits = kTotpDefaultDigits;
  uint32_t period = kTotpDefaultPeriod;
  TotpAlgorithm algorithm = TotpAlgorithm::Sha1;
  uint8_t fields = 0;
  while ((token = strtok_r(nullptr, " ", &save)) != nullptr) {
    if (fields == 0) {
      char *end = nullptr;
      const unsigned long value = strtoul(token, &end, 10);
      if (end == token || *end != '\0' || value < 6 || value > 8) {
        Serial.println("ERR invalid-totp-digits");
        secure_zero(secret_text, sizeof(secret_text));
        return;
      }
      digits = static_cast<uint32_t>(value);
    } else if (fields == 1) {
      char *end = nullptr;
      const unsigned long value = strtoul(token, &end, 10);
      if (end == token || *end != '\0' || value < 1 || value > 300) {
        Serial.println("ERR invalid-totp-period");
        secure_zero(secret_text, sizeof(secret_text));
        return;
      }
      period = static_cast<uint32_t>(value);
    } else if (fields == 2) {
      if (strcmp(token, "sha1") == 0) algorithm = TotpAlgorithm::Sha1;
      else if (strcmp(token, "sha256") == 0) algorithm = TotpAlgorithm::Sha256;
      else if (strcmp(token, "sha512") == 0) algorithm = TotpAlgorithm::Sha512;
      else {
        Serial.println("ERR invalid-totp-algorithm");
        secure_zero(secret_text, sizeof(secret_text));
        return;
      }
    } else {
      Serial.println("ERR invalid-totp-command");
      secure_zero(secret_text, sizeof(secret_text));
      return;
    }
    ++fields;
  }
  uint8_t secret[kTotpSecretMaxBytes] = {};
  size_t secret_size = 0;
  const TotpError decode = totp_base32_decode(secret_text, secret, sizeof(secret),
                                              &secret_size);
  secure_zero(secret_text, sizeof(secret_text));
  if (decode != TotpError::Ok) {
    Serial.println("ERR invalid-totp-secret");
    secure_zero(secret, sizeof(secret));
    return;
  }
  uint64_t now = 0;
  if (!totp_clock_unix(static_cast<uint64_t>(esp_timer_get_time()) / 1000U, &now)) {
    Serial.println("ERR totp-clock-not-set; use totp time <unix>");
    secure_zero(secret, sizeof(secret));
    return;
  }
  uint32_t code = 0;
  const TotpError generated = totp_generate_unix(
      secret, secret_size, now, period, digits, algorithm, &code);
  secure_zero(secret, sizeof(secret));
  if (generated != TotpError::Ok) {
    Serial.println("ERR totp-generation-failed");
    return;
  }
  char output[64];
  snprintf(output, sizeof(output), "OK code=%0*u remaining=%u",
           static_cast<int>(digits), code,
           static_cast<unsigned>(period - static_cast<uint32_t>(now % period)));
  Serial.println(output);
}

void handle_line(char *command) {
  while (*command == ' ') ++command;
  if (*command == '\0') return;
  // One trusted screen has one owner. A second transport/CLI command must not
  // replace an approval screen while the original request remains signable.
  const bool passive = strcmp(command, "help") == 0 || strcmp(command, "status") == 0 ||
      strcmp(command, "lock") == 0 || strcmp(command, "link status") == 0;
  if (!passive && (wallet_signing_active() || wallet_link_service_pairing_pending())) {
    Serial.println("ERR device-review-active");
    return;
  }
  const bool finish_cli = strcmp(command, "tx reject") == 0 ||
      strncmp(command, "tx sign ", 8) == 0 || strncmp(command, "evm sign ", 9) == 0 ||
      strncmp(command, "kaspa sign ", 11) == 0 || strncmp(command, "zec sign ", 9) == 0;
  if (transaction_pending && !passive && !finish_cli) {
    Serial.println("ERR transaction-review-active");
    return;
  }
  if (strcmp(command, "help") == 0) show_help();
  else if (strcmp(command, "status") == 0) show_status();
  else if (strncmp(command, "coin ", 5) == 0) handle_coin(command);
  else if (strncmp(command, "mining ", 7) == 0) handle_mining(command);
  else if (strncmp(command, "token ", 6) == 0) handle_token(command);
  else if (strcmp(command, "auth begin") == 0) begin_challenge();
  else if (strncmp(command, "auth unlock ", 12) == 0) unlock(command + 12);
  else if (strncmp(command, "auth provision ", 15) == 0) provision_pin(command + 15);
  else if (strcmp(command, "lock") == 0) {
    wallet_cli_lock();
    Serial.println("OK locked");
  } else if (strcmp(command, "selftest") == 0) run_self_tests();
  else if (strncmp(command, "wallet ", 7) == 0) handle_wallet(command);
  else if (strncmp(command, "evm ", 4) == 0) handle_evm(command);
  else if (strncmp(command, "kaspa ", 6) == 0) handle_kaspa(command);
  else if (strncmp(command, "zec ", 4) == 0) handle_zcash(command);
  else if (strncmp(command, "link ", 5) == 0) handle_link(command);
  else if (strncmp(command, "tx ", 3) == 0) handle_transaction(command);
  else if (strncmp(command, "totp", 4) == 0) handle_totp(command);
  else Serial.println("ERR unknown-command; use help");
}

}
#endif

bool wallet_cli_init(bool display_available) {
#if !HEXWALLET_ENABLE_CLI
  (void)display_available;
  return false;
#else
  display_is_available = display_available;
  preferences_open = preferences.begin(kPreferencesNamespace, false);
  if (!preferences_open) {
    Serial.println("FATAL CLI authentication storage unavailable");
    return false;
  }
  provisioned = preferences.getBool(kProvisionedKey, false) && preferences.getBytesLength(kSaltKey) == sizeof(salt) && preferences.getBytesLength(kVerifierKey) == sizeof(verifier) && preferences.getBytes(kSaltKey, salt, sizeof(salt)) == sizeof(salt) && preferences.getBytes(kVerifierKey, verifier, sizeof(verifier)) == sizeof(verifier);
  const uint32_t failures = preferences.getUInt(kFailuresKey, 0);
  if (failures != 0) {
    const uint32_t exponent = failures > 10 ? 10 : failures;
    uint32_t delay_ms = 1000UL << exponent;
    if (delay_ms > kMaximumBackoffMs) delay_ms = kMaximumBackoffMs;
    retry_after = millis() + delay_ms;
  }
  Serial.println("HexWallet authenticated CLI ready; use help");
  Serial.print("INFO usb-data=");
  Serial.print(usb_data_enabled ? "on" : "off");
  Serial.print(" hold-boot-ms=");
  Serial.println(HEXWALLET_USB_ENABLE_HOLD_MS);
  if (!board_has_user_button()) {
    Serial.println("WARN no verified user button; USB data cannot be enabled at runtime");
  }
  if (!display_available) Serial.println("INFO no display detected; authenticated CLI is the active interface");
  if (!provisioned) {
    Serial.println("INFO authentication is not provisioned; use auth provision <pin> <pin>");
  } else {
    Serial.println("INFO authentication required; use auth begin then auth unlock <proof-hex>");
  }
  return true;
#endif
}

bool wallet_usb_data_enabled() {
#if HEXWALLET_ENABLE_CLI
  return usb_data_enabled;
#else
  return false;
#endif
}

void wallet_usb_data_set(bool enabled) {
#if HEXWALLET_ENABLE_CLI
  usb_data_enabled = enabled;
  usb_data_enabled_at = millis();
  usb_apdu_used = 0;
  usb_apdu_expected = 0;
  usb_apdu_mode = false;
  if (enabled) {
    // Drop bytes that arrived while the transport was closed so they can
    // never be replayed into an authenticated session later.
    while (Serial.available() > 0) Serial.read();
    Serial.print("INFO usb-data-enabled window-ms=");
    Serial.println(HEXWALLET_USB_ENABLE_WINDOW_MS);
  } else {
    Serial.println("INFO usb-data-disabled");
  }
#else
  (void)enabled;
#endif
}

void wallet_usb_data_service() {
#if HEXWALLET_ENABLE_CLI
  if (!board_has_user_button()) {
    usb_button_down = false;
    return;
  }
  const bool down = board_user_button_pressed();
  const uint32_t now = millis();
  if (down && !usb_button_down) {
    usb_button_down = true;
    usb_button_long_handled = false;
    usb_button_down_at = now;
  } else if (!down) {
    usb_button_down = false;
  } else if (!usb_button_long_handled &&
             now - usb_button_down_at >= HEXWALLET_USB_ENABLE_HOLD_MS) {
    usb_button_long_handled = true;
    wallet_usb_data_set(!usb_data_enabled);
  }
  if (usb_data_enabled && usb_data_enabled_at != 0 &&
      now - usb_data_enabled_at >= HEXWALLET_USB_ENABLE_WINDOW_MS) {
    wallet_usb_data_set(false);
  }
#endif
}

bool service_usb_apdu() {
  if (!usb_apdu_mode && Serial.available() > 0 &&
      Serial.peek() == kUsbApduMagic0) {
    usb_apdu_mode = true;
    usb_apdu_used = 0;
    usb_apdu_expected = 0;
  }
  if (!usb_apdu_mode) return false;
  while (Serial.available() > 0 && usb_apdu_used < sizeof(usb_apdu_frame)) {
    usb_apdu_frame[usb_apdu_used++] = static_cast<uint8_t>(Serial.read());
  }
  if (usb_apdu_used >= 2 &&
      (usb_apdu_frame[0] != kUsbApduMagic0 ||
       usb_apdu_frame[1] != kUsbApduMagic1)) {
    usb_apdu_used = 0;
    usb_apdu_expected = 0;
    usb_apdu_mode = false;
    return true;
  }
  if (usb_apdu_expected == 0 && usb_apdu_used >= 4) {
    const size_t length = static_cast<size_t>(usb_apdu_frame[2]) |
                          (static_cast<size_t>(usb_apdu_frame[3]) << 8);
    if (length > kUsbApduMax) {
      usb_apdu_used = 0;
      usb_apdu_mode = false;
      return true;
    }
    usb_apdu_expected = 4 + length;
  }
  if (usb_apdu_expected != 0 && usb_apdu_used >= usb_apdu_expected) {
    uint8_t response[kUsbApduMax + 4];
    const size_t apdu_size = usb_apdu_expected - 4;
    const size_t response_size = wallet_link_service_apdu(
        usb_apdu_frame + 4, apdu_size, millis(), response + 4,
        sizeof(response) - 4);
    const size_t total = 4 + response_size;
    response[0] = kUsbApduMagic0;
    response[1] = kUsbApduMagic1;
    response[2] = static_cast<uint8_t>(response_size);
    response[3] = static_cast<uint8_t>(response_size >> 8);
    for (size_t index = 0; index < total; ++index) {
      Serial.write(response[index]);
    }
    secure_zero(response, sizeof(response));
    usb_apdu_used = 0;
    usb_apdu_expected = 0;
    usb_apdu_mode = false;
    return true;
  }
  return true;
}

void wallet_cli_service() {
#if HEXWALLET_ENABLE_CLI
  wallet_usb_data_service();
  if (authenticated && millis() - authenticated_at >= HEXWALLET_CLI_SESSION_TIMEOUT_MS) {
    wallet_cli_lock();
    Serial.println("INFO session-expired-and-wallet-cleared");
  }
  if (transaction_pending && deadline_reached(millis(), transaction_expires_at)) {
    clear_pending_transaction();
    Serial.println("INFO transaction-review-expired");
  }
  if (!usb_data_enabled) {
    while (Serial.available() > 0) Serial.read();
    return;
  }
  if (service_usb_apdu()) return;
  while (Serial.available() > 0) {
    const char value = static_cast<char>(Serial.read());
    if (value == '\r') continue;
    if (value == '\n') {
      line_buffer[line_used] = '\0';
      handle_line(line_buffer);
      secure_zero(line_buffer, sizeof(line_buffer));
      line_used = 0;
    } else if ((value == '\b' || value == 0x7f) && line_used != 0) {
      --line_used;
    } else if (value >= 0x20 && value <= 0x7e) {
      if (line_used + 1 < sizeof(line_buffer)) line_buffer[line_used++] = value;
      else {
        secure_zero(line_buffer, sizeof(line_buffer));
        line_used = 0;
        Serial.println("ERR line-too-long");
      }
    }
  }
#endif
}

bool wallet_cli_is_authenticated() {
#if HEXWALLET_ENABLE_CLI
  return authenticated;
#else
  return false;
#endif
}

bool wallet_cli_review_active() {
#if HEXWALLET_ENABLE_CLI
  return transaction_pending;
#else
  return false;
#endif
}

void wallet_cli_lock() {
#if HEXWALLET_ENABLE_CLI
  authenticated = false;
  challenge_active = false;
  authenticated_at = 0;
  secure_zero(challenge, sizeof(challenge));
  // Closing the USB gate on lock also drops anything that was typed but not
  // yet executed, so a half-typed signing command cannot survive a lock.
  usb_data_enabled = false;
  usb_apdu_used = 0;
  usb_apdu_expected = 0;
  usb_apdu_mode = false;
  clear_wallet();
#endif
}

}
