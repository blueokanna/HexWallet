#include "WalletCli.h"

#include <Arduino.h>
#include <Preferences.h>
#include <esp_system.h>
#include <string.h>

#include "BitcoinTransaction.h"
#include "CryptoNoteAddress.h"
#include "CryptoPrimitives.h"
#include "EvmTransaction.h"
#include "WalletCatalog.h"
#include "WalletConfig.h"
#include "WalletEngine.h"
#include "WalletSecurity.h"
#include "WalletSession.h"
#include "WalletTokens.h"
#include "WalletTransportPolicy.h"
#include "WalletUi.h"

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
enum class PendingTransactionKind : uint8_t { None, Bitcoin, Evm };
PendingTransactionKind pending_transaction_kind = PendingTransactionKind::None;
bool transaction_pending = false;
uint32_t transaction_approval = 0;
uint32_t transaction_expires_at = 0;

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
  }
  return "unknown";
}

void clear_pending_transaction() {
  clear_bitcoin_request(&pending_transaction);
  clear_evm_request(&pending_evm_transaction);
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
    Serial.println("ERR locked");
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
  Serial.println("OK public: help | status | coin list | coin search <text> | coin show <id> | token list [network] | token show <id>");
  Serial.println("OK auth: auth provision <pin> <pin> | auth begin | auth unlock <proof-hex> | lock");
  Serial.println("OK wallet: wallet generate | wallet import <mnemonic> | wallet address <id> [index] | wallet token <id> [index] | wallet addresses [index]");
  Serial.println("OK signing: tx inspect <psbt-v0-hex> | tx sign <code> | evm inspect <network> <index> <unsigned-rlp-hex> | evm sign <code> | tx reject");
#if HEXWALLET_ENABLE_SECRET_EXPORT
  Serial.println("OK sensitive: wallet secret [index] | selftest");
#else
  Serial.println("OK sensitive: secret export disabled | selftest");
#endif
}

void show_status() {
  Serial.print("OK provisioned="); Serial.print(provisioned ? "yes" : "no");
  Serial.print(" authenticated="); Serial.print(authenticated ? "yes" : "no");
  Serial.print(" display="); Serial.print(display_is_available ? "available" : "absent");
  Serial.print(" wallet="); Serial.print(wallet_session_is_loaded() ? "loaded" : "empty");
  Serial.print(" pending-tx="); Serial.println(transaction_pending ? "yes" : "no");
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
  if (pin_size < kMinimumPinSize || pin_size > kMaximumPinSize ||
      strcmp(arguments, separator) != 0 || strchr(separator, ' ') != nullptr) {
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
  if (!derived || preferences.putBytes(kSaltKey, salt, sizeof(salt)) != sizeof(salt) ||
      preferences.putBytes(kVerifierKey, new_verifier, sizeof(new_verifier)) != sizeof(new_verifier) ||
      preferences.putBool(kProvisionedKey, true) == 0) {
    secure_zero(new_verifier, sizeof(new_verifier));
    Serial.println("ERR provisioning-failed");
    return;
  }
  memcpy(verifier, new_verifier, sizeof(verifier));
  secure_zero(new_verifier, sizeof(new_verifier));
  preferences.putUInt(kFailuresKey, 0);
  provisioned = true;
  Serial.println("OK provisioned");
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
  Serial.print("OK challenge salt="); print_hex(salt, sizeof(salt));
  Serial.print(" iterations="); Serial.print(HEXWALLET_CLI_PBKDF2_ITERATIONS);
  Serial.print(" nonce="); print_hex(challenge, sizeof(challenge));
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
    if (!wallet_catalog_at(index, &entry) || !wallet_catalog_matches(entry, query)) continue;
    Serial.print("coin="); Serial.print(entry.id);
    Serial.print(" symbol="); Serial.print(entry.symbol);
    Serial.print(" name=\""); Serial.print(entry.name); Serial.print("\"");
    Serial.print(" slip44="); Serial.print(entry.slip44_coin_type);
    Serial.print(" capabilities="); print_capabilities(entry);
    Serial.print(" status=\""); Serial.print(entry.status); Serial.println("\"");
    ++matches;
  }
  Serial.print("OK matches="); Serial.println(matches);
}

void show_coin(const char *id) {
  WalletCatalogEntry entry;
  if (!wallet_catalog_find(id, &entry)) {
    Serial.println("ERR unknown-coin");
    return;
  }
  Serial.print("OK id="); Serial.print(entry.id);
  Serial.print(" symbol="); Serial.print(entry.symbol);
  Serial.print(" name=\""); Serial.print(entry.name); Serial.print("\"");
  Serial.print(" slip44="); Serial.print(entry.slip44_coin_type);
  Serial.print(" capabilities="); print_capabilities(entry);
  Serial.print(" status=\""); Serial.print(entry.status); Serial.println("\"");
}

void handle_coin(char *command) {
  if (strcmp(command, "coin list") == 0) show_catalog("");
  else if (strncmp(command, "coin search ", 12) == 0 && command[12] != '\0') show_catalog(command + 12);
  else if (strncmp(command, "coin show ", 10) == 0 && command[10] != '\0') show_coin(command + 10);
  else Serial.println("ERR invalid-coin-command");
}

void show_tokens(const char *network_filter) {
  size_t matches = 0;
  for (size_t index = 0; index < kTokenProfileCount; ++index) {
    const TokenProfile &token = kTokenProfiles[index];
    if (network_filter != nullptr && *network_filter != '\0' && strcmp(token.network_id, network_filter) != 0) continue;
    Serial.print("token="); Serial.print(token.id);
    Serial.print(" network="); Serial.print(token.network_id);
    Serial.print(" symbol="); Serial.print(token.symbol);
    Serial.print(" standard="); Serial.print(token_standard_text(token.standard));
    Serial.print(" decimals="); Serial.print(token.decimals);
    Serial.print(" asset="); Serial.print(token.contract_or_mint);
    Serial.print(" capabilities="); Serial.print(token_supports_account_address(token) ? "account-address" : "none");
    if (token_supports_transfer_signing(token)) Serial.print(",transfer-signing");
    Serial.print(" status=\""); Serial.print(token.status); Serial.println("\"");
    ++matches;
  }
  Serial.print("OK matches="); Serial.println(matches);
}

void show_token(const char *id) {
  const TokenProfile *token = find_token_profile(id);
  if (token == nullptr) {
    Serial.println("ERR unknown-token");
    return;
  }
  Serial.print("OK token="); Serial.print(token->id);
  Serial.print(" network="); Serial.print(token->network_id);
  Serial.print(" symbol="); Serial.print(token->symbol);
  Serial.print(" name=\""); Serial.print(token->name); Serial.println("\"");
  Serial.print(" standard="); Serial.print(token_standard_text(token->standard));
  Serial.print(" decimals="); Serial.print(token->decimals);
  Serial.print(" asset="); Serial.println(token->contract_or_mint);
  Serial.print(" capabilities="); Serial.print(token_supports_account_address(*token) ? "account-address" : "none");
  if (token_supports_transfer_signing(*token)) Serial.print(",transfer-signing");
  Serial.println();
  Serial.print(" status=\""); Serial.print(token->status); Serial.println("\"");
}

void handle_token(char *command) {
  if (strcmp(command, "token list") == 0) show_tokens("");
  else if (strncmp(command, "token list ", 11) == 0 && command[11] != '\0') show_tokens(command + 11);
  else if (strncmp(command, "token show ", 11) == 0 && command[11] != '\0') show_token(command + 11);
  else Serial.println("ERR invalid-token-command");
}

void print_derived(const NetworkProfile &network, const HdPrivateNode &master,
                   uint32_t address_index, bool include_private) {
  DerivedAddress derived;
  const WalletError result = derive_address(master, network, 0, 0, address_index, &derived);
  if (result != WalletError::Ok) {
    Serial.print("ERR network="); Serial.print(network.id);
    Serial.print(" error="); Serial.println(error_text(result));
    return;
  }
  Serial.print("network="); Serial.print(network.id);
  Serial.print(" symbol="); Serial.print(network.symbol);
  Serial.print(" path="); Serial.print(derived.path);
  Serial.print(" address="); Serial.print(derived.address);
  if (include_private) {
    Serial.print(" private="); print_hex(derived.private_key, sizeof(derived.private_key));
  }
  Serial.println();
  clear_derived_address(&derived);
}

void show_addresses(uint32_t address_index, const NetworkProfile *only_network, bool include_secrets) {
  HdPrivateNode master;
  if (!load_master(&master)) return;
  uint8_t seed[kSeedSize];
  if (include_secrets) {
    const char *mnemonic = wallet_session_mnemonic_for_export();
    WalletError seed_result = mnemonic == nullptr ? WalletError::InvalidArgument :
        bip39_seed_from_english(mnemonic, "", seed);
    char extended[kExtendedKeyTextSize];
    size_t extended_size = sizeof(extended);
    Serial.println("BEGIN SENSITIVE");
    Serial.print("mnemonic="); Serial.println(mnemonic == nullptr ? "" : mnemonic);
    if (seed_result == WalletError::Ok) {
      Serial.print("seed="); print_hex(seed, sizeof(seed)); Serial.println();
    }
    Serial.print("master-private="); print_hex(master.private_key, sizeof(master.private_key)); Serial.println();
    Serial.print("master-chain-code="); print_hex(master.chain_code, sizeof(master.chain_code)); Serial.println();
    if (hd_serialize_private(&master, ExtendedKeyFormat::Xprv, extended, &extended_size) == WalletError::Ok) {
      Serial.print("master-xprv="); Serial.println(extended);
    }
    secure_zero(extended, sizeof(extended));
  }
  if (only_network != nullptr) {
    print_derived(*only_network, master, address_index, include_secrets);
  } else {
    for (size_t index = 0; index < kNetworkProfileCount; ++index) {
      print_derived(kNetworkProfiles[index], master, address_index, include_secrets);
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
    Serial.print("ERR address-unsupported status=\""); Serial.print(entry.status); Serial.println("\"");
    return;
  }
  bool valid_index;
  const uint32_t index = parse_index(index_text, &valid_index);
  if (!valid_index) {
    Serial.println("ERR invalid-index");
    return;
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
    Serial.print("ERR token-account-unsupported status=\""); Serial.print(token->status); Serial.println("\"");
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
  DerivedAddress derived;
  const WalletError result = derive_address(master, *network, 0, 0, index, &derived);
  secure_zero(&master, sizeof(master));
  if (result != WalletError::Ok) {
    Serial.print("ERR token-account "); Serial.println(error_text(result));
    return;
  }
  Serial.print("OK token="); Serial.print(token->id);
  Serial.print(" network="); Serial.print(network->id);
  Serial.print(" standard="); Serial.print(token_standard_text(token->standard));
  Serial.print(" asset="); Serial.print(token->contract_or_mint);
  Serial.print(" decimals="); Serial.print(token->decimals);
  Serial.print(" path="); Serial.print(derived.path);
  Serial.print(" account-address="); Serial.println(derived.address);
  Serial.println(token_supports_transfer_signing(*token) ?
                 "INFO transfer-signing=evm-inspect-workflow" :
                 "INFO transfer-signing-unavailable");
  clear_derived_address(&derived);
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
  Serial.println("network=btc signing=P2WPKH,P2SH-P2WPKH sighash=ALL");
  Serial.print("inputs="); Serial.print(pending_transaction.input_count);
  Serial.print(" input-sats="); Serial.println(static_cast<unsigned long long>(pending_transaction.input_total));
  for (size_t index = 0; index < pending_transaction.output_count; ++index) {
    const BitcoinOutput &output = pending_transaction.outputs[index];
    Serial.print("output="); Serial.print(index);
    Serial.print(" sats="); Serial.print(static_cast<unsigned long long>(output.value));
    Serial.print(" address="); Serial.print(output.address);
    Serial.print(" ownership=");
    Serial.println(output.change ? "change" : (output.wallet_owned ? "wallet" : "external"));
  }
  Serial.print("output-sats="); Serial.println(static_cast<unsigned long long>(pending_transaction.output_total));
  Serial.print("fee-sats="); Serial.print(static_cast<unsigned long long>(pending_transaction.fee));
  Serial.print(" estimated-vbytes="); Serial.print(pending_transaction.estimated_vbytes);
  Serial.print(" estimated-fee-rate=");
  Serial.println(pending_transaction.estimated_vbytes == 0 ? 0 :
                 static_cast<unsigned long long>(pending_transaction.fee / pending_transaction.estimated_vbytes));
  Serial.print("review-id="); print_hex(pending_transaction.psbt_hash, 8); Serial.println();
  Serial.println("END TRANSACTION REVIEW");
}

void inspect_transaction(const char *psbt_hex) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = {true, false, display_is_available};
  if (!wallet_transport_allows(WalletTransport::SerialUsb,
                               WalletTransportOperation::SigningRequest, transport_state)) {
    Serial.println("ERR trusted-display-required-for-signing");
    return;
  }
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
  const TransactionError result = bitcoin_parse_psbt(psbt, psbt_size, master, &pending_transaction);
  secure_zero(psbt, sizeof(psbt));
  secure_zero(&master, sizeof(master));
  if (result != TransactionError::Ok) {
    clear_pending_transaction();
    Serial.print("ERR tx-inspect "); Serial.println(transaction_error_text(result));
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
    Serial.print("OK confirm-code="); Serial.print(approval);
    Serial.println(" expires-ms=120000; compare every output before tx sign");
  }
  WalletUiTransactionReview review = {};
  review.network = "BITCOIN";
  review.output_count = pending_transaction.output_count;
  review.fee = pending_transaction.fee;
  review.fee_rate = pending_transaction.estimated_vbytes == 0 ? 0 :
                    pending_transaction.fee / pending_transaction.estimated_vbytes;
  review.approval_code = approval;
  for (size_t index = 0; index < review.output_count; ++index) {
    const BitcoinOutput &output = pending_transaction.outputs[index];
    review.outputs[index] = {output.value, nullptr, output.address,
                             output.change ? "CHANGE" : (output.wallet_owned ? "WALLET" : "EXTERNAL")};
  }
  wallet_ui_show_transaction(review);
  secure_zero(approval, sizeof(approval));
}

void sign_transaction(const char *approval_text) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = {true, false, display_is_available};
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
    Serial.print("ERR tx-sign "); Serial.println(transaction_error_text(result));
    return;
  }
  uint8_t wtxid[kSha256Size];
  const bool hashed = crypto_double_sha256(signed_transaction, signed_size, wtxid);
  Serial.print("OK signed-transaction="); print_hex(signed_transaction, signed_size); Serial.println();
  if (hashed) {
    Serial.print("wtxid="); print_hex_reverse(wtxid, sizeof(wtxid)); Serial.println();
  }
  secure_zero(wtxid, sizeof(wtxid));
  secure_zero(signed_transaction, sizeof(signed_transaction));
  wallet_ui_show_catalog();
}

void inspect_evm_transaction(char *arguments) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = {true, false, display_is_available};
  if (!wallet_transport_allows(WalletTransport::SerialUsb,
                               WalletTransportOperation::SigningRequest, transport_state)) {
    Serial.println("ERR trusted-display-required-for-signing");
    return;
  }
  char *network_end = strchr(arguments, ' ');
  if (network_end == nullptr) { Serial.println("ERR invalid-evm-command"); return; }
  *network_end++ = '\0';
  char *index_end = strchr(network_end, ' ');
  if (index_end == nullptr) { Serial.println("ERR invalid-evm-command"); return; }
  *index_end++ = '\0';
  const NetworkProfile *network = find_network_profile(arguments);
  if (network == nullptr || network->encoding != AddressEncoding::Evm) {
    Serial.println("ERR unsupported-evm-network");
    return;
  }
  bool valid_index;
  const uint32_t address_index = parse_index(network_end, &valid_index);
  if (!valid_index) { Serial.println("ERR invalid-index"); return; }
  uint8_t transaction[kEvmMaxUnsignedTransactionSize];
  size_t transaction_size = 0;
  if (!decode_hex(index_end, transaction, sizeof(transaction), &transaction_size)) {
    secure_zero(transaction, sizeof(transaction));
    Serial.println("ERR invalid-evm-transaction-hex");
    return;
  }
  HdPrivateNode master;
  if (!load_master(&master)) { secure_zero(transaction, sizeof(transaction)); return; }
  clear_pending_transaction();
  const EvmTransactionError error = evm_parse_transaction(
      transaction, transaction_size, *network, master, address_index, &pending_evm_transaction);
  secure_zero(&master, sizeof(master));
  secure_zero(transaction, sizeof(transaction));
  if (error != EvmTransactionError::Ok) {
    clear_pending_transaction();
    Serial.print("ERR evm-inspect "); Serial.println(evm_transaction_error_text(error));
    return;
  }
  uint32_t random_value;
  esp_fill_random(&random_value, sizeof(random_value));
  transaction_approval = random_value % 1000000U;
  transaction_expires_at = millis() + kTransactionApprovalMs;
  transaction_pending = true;
  pending_transaction_kind = PendingTransactionKind::Evm;
  const char *asset = pending_evm_transaction.token == nullptr ? network->symbol :
                                                               pending_evm_transaction.token->symbol;
  Serial.println("BEGIN TRANSACTION REVIEW");
  Serial.print("network="); Serial.print(network->id);
  Serial.print(" type="); Serial.println(pending_evm_transaction.type == EvmTransactionType::Eip1559 ?
                                          "EIP-1559" : "EIP-155");
  Serial.print("from="); Serial.println(pending_evm_transaction.from_address);
  Serial.print("asset="); Serial.print(asset);
  Serial.print(" recipient="); Serial.println(pending_evm_transaction.recipient_address);
  Serial.print("amount="); Serial.print(pending_evm_transaction.amount_text);
  Serial.print(" "); Serial.println(asset);
  if (pending_evm_transaction.token != nullptr) {
    Serial.print("contract="); Serial.println(pending_evm_transaction.token->contract_or_mint);
  }
  Serial.print("nonce="); Serial.print(static_cast<unsigned long long>(pending_evm_transaction.nonce));
  Serial.print(" gas-limit="); Serial.println(static_cast<unsigned long long>(pending_evm_transaction.gas_limit));
  Serial.print("maximum-fee="); Serial.print(pending_evm_transaction.maximum_fee_text);
  Serial.print(" "); Serial.println(network->symbol);
  Serial.print("review-id="); print_hex(pending_evm_transaction.request_hash, 8); Serial.println();
  Serial.println("END TRANSACTION REVIEW");
  char approval[7];
  snprintf(approval, sizeof(approval), "%06lu", static_cast<unsigned long>(transaction_approval));
  if (display_is_available) {
    Serial.println("OK confirmation-shown-on-trusted-display expires-ms=120000");
  } else {
    Serial.print("OK confirm-code="); Serial.print(approval);
    Serial.println(" expires-ms=120000");
  }
  char display_amount[112];
  char display_fee[112];
  snprintf(display_amount, sizeof(display_amount), "%s %s", pending_evm_transaction.amount_text, asset);
  snprintf(display_fee, sizeof(display_fee), "%s %s", pending_evm_transaction.maximum_fee_text,
           network->symbol);
  WalletUiTransactionReview review = {};
  review.network = network->name;
  review.output_count = 1;
  review.outputs[0] = {0, display_amount, pending_evm_transaction.recipient_address,
                       pending_evm_transaction.token == nullptr ? "NATIVE TRANSFER" : "REGISTERED ERC-20"};
  review.fee_text = display_fee;
  review.approval_code = approval;
  wallet_ui_show_transaction(review);
  secure_zero(display_amount, sizeof(display_amount));
  secure_zero(display_fee, sizeof(display_fee));
  secure_zero(approval, sizeof(approval));
}

void sign_evm_transaction(const char *approval_text) {
  if (!require_authentication()) return;
  const WalletTransportState transport_state = {true, false, display_is_available};
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
  if (deadline_reached(millis(), transaction_expires_at) || approval_text == nullptr ||
      strlen(approval_text) != 6) {
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
  if (!load_master(&master)) { clear_pending_transaction(); return; }
  uint8_t signed_transaction[kEvmMaxSignedTransactionSize];
  size_t signed_size = sizeof(signed_transaction);
  const EvmTransactionError error = evm_sign_transaction(
      pending_evm_transaction, master, signed_transaction, &signed_size);
  secure_zero(&master, sizeof(master));
  clear_pending_transaction();
  if (error != EvmTransactionError::Ok) {
    secure_zero(signed_transaction, sizeof(signed_transaction));
    Serial.print("ERR evm-sign "); Serial.println(evm_transaction_error_text(error));
    return;
  }
  uint8_t transaction_hash[kKeccak256Size];
  const bool hashed = crypto_keccak256(signed_transaction, signed_size, transaction_hash);
  Serial.print("OK signed-transaction="); print_hex(signed_transaction, signed_size); Serial.println();
  if (hashed) { Serial.print("tx-hash=0x"); print_hex(transaction_hash, sizeof(transaction_hash)); Serial.println(); }
  secure_zero(transaction_hash, sizeof(transaction_hash));
  secure_zero(signed_transaction, sizeof(signed_transaction));
  wallet_ui_show_catalog();
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
  const bool bip39 = run_bip39_self_test();
  const bool bip32 = run_bip32_self_test();
  const bool address = run_address_self_tests();
  const bool networks = run_network_profile_self_tests();
  const bool tokens = run_token_profile_self_tests();
  const bool transaction = run_bitcoin_transaction_self_test();
  const bool evm = run_evm_transaction_self_test();
  const bool transport = run_transport_policy_self_test();
  Serial.print("OK crypto="); Serial.print(crypto ? "pass" : "FAIL");
  Serial.print(" cryptonote="); Serial.print(cryptonote ? "pass" : "FAIL");
  Serial.print(" bip39="); Serial.print(bip39 ? "pass" : "FAIL");
  Serial.print(" bip32="); Serial.print(bip32 ? "pass" : "FAIL");
  Serial.print(" address="); Serial.print(address ? "pass" : "FAIL");
  Serial.print(" networks="); Serial.print(networks ? "pass" : "FAIL");
  Serial.print(" tokens="); Serial.print(tokens ? "pass" : "FAIL");
  Serial.print(" bip143="); Serial.print(transaction ? "pass" : "FAIL");
  Serial.print(" evm="); Serial.print(evm ? "pass" : "FAIL");
  Serial.print(" transport-policy="); Serial.println(transport ? "pass" : "FAIL");
}

void handle_line(char *command) {
  while (*command == ' ') ++command;
  if (*command == '\0') return;
  if (strcmp(command, "help") == 0) show_help();
  else if (strcmp(command, "status") == 0) show_status();
  else if (strncmp(command, "coin ", 5) == 0) handle_coin(command);
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
  else if (strncmp(command, "tx ", 3) == 0) handle_transaction(command);
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
  provisioned = preferences.getBool(kProvisionedKey, false) &&
                preferences.getBytesLength(kSaltKey) == sizeof(salt) &&
                preferences.getBytesLength(kVerifierKey) == sizeof(verifier) &&
                preferences.getBytes(kSaltKey, salt, sizeof(salt)) == sizeof(salt) &&
                preferences.getBytes(kVerifierKey, verifier, sizeof(verifier)) == sizeof(verifier);
  const uint32_t failures = preferences.getUInt(kFailuresKey, 0);
  if (failures != 0) {
    const uint32_t exponent = failures > 10 ? 10 : failures;
    uint32_t delay_ms = 1000UL << exponent;
    if (delay_ms > kMaximumBackoffMs) delay_ms = kMaximumBackoffMs;
    retry_after = millis() + delay_ms;
  }
  Serial.println("HexWallet authenticated CLI ready; use help");
  if (!display_available) Serial.println("INFO no display detected; authenticated CLI is the active interface");
  if (!provisioned) Serial.println("INFO authentication is not provisioned");
  return true;
#endif
}

void wallet_cli_service() {
#if HEXWALLET_ENABLE_CLI
  if (authenticated && millis() - authenticated_at >= HEXWALLET_CLI_SESSION_TIMEOUT_MS) {
    wallet_cli_lock();
    Serial.println("INFO session-expired-and-wallet-cleared");
  }
  if (transaction_pending && deadline_reached(millis(), transaction_expires_at)) {
    clear_pending_transaction();
    Serial.println("INFO transaction-review-expired");
  }
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

void wallet_cli_lock() {
#if HEXWALLET_ENABLE_CLI
  authenticated = false;
  challenge_active = false;
  authenticated_at = 0;
  secure_zero(challenge, sizeof(challenge));
  clear_wallet();
#endif
}

}
