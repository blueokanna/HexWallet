#include "WalletLinkService.h"

#include <Arduino.h>
#include <Preferences.h>
#include "RandomSource.h"
#include <esp_system.h>
#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletBoardPort.h"
#include "WalletCatalog.h"
#include "WalletCli.h"
#include "WalletEngine.h"
#include "WalletLink.h"
#include "WalletNfcApdu.h"
#include "WalletNfcPort.h"
#include "WalletSecurity.h"
#include "WalletSession.h"
#include "WalletSigning.h"
#include "WalletTransportPolicy.h"
#include "WalletUi.h"

namespace hexwallet {
namespace {

constexpr char kLinkPreferencesNamespace[] = "hexwallet_link";
constexpr char kIdentitySeedKey[] = "id_seed";
constexpr char kPairedKey[] = "paired";
constexpr char kPhoneKey[] = "phone";
constexpr size_t kPhoneKeySize = 32;
constexpr size_t kMaxRequest = 16384;

constexpr uint8_t kOpPing = 0x01;
constexpr uint8_t kOpInfo = 0x02;
constexpr uint8_t kOpCatalog = 0x03;
constexpr uint8_t kOpAddress = 0x04;
constexpr uint8_t kOpBeginSign = 0x05;
constexpr uint8_t kOpResult = 0x06;
constexpr uint8_t kOpCancel = 0x07;

constexpr uint8_t kStatusOk = 0;
constexpr uint8_t kStatusPending = 1;
constexpr uint8_t kStatusRejected = 2;
constexpr uint8_t kStatusUnknownCoin = 3;
constexpr uint8_t kStatusInvalid = 4;
constexpr uint8_t kStatusExpired = 5;
constexpr uint8_t kStatusUnsupported = 6;
// 7 is reserved (was "no wallet"); "locked" is the precise state now.
constexpr uint8_t kStatusNotApproved = 8;
// The device is paired and reachable, but no wallet session is unlocked, so
// no key material exists in RAM. The phone must ask the user to unlock.
constexpr uint8_t kStatusLocked = 9;
// The transaction parsed but violates local spending policy (for example the
// Monero fee ceiling). Nothing was signed.
constexpr uint8_t kStatusFeePolicy = 10;

constexpr uint8_t kTxBitcoin = 1;
constexpr uint8_t kTxEvm = 2;
constexpr uint8_t kTxKaspa = 3;
constexpr uint8_t kTxZcash = 4;
constexpr uint8_t kTxCryptoNote = 5;
constexpr uint8_t kTxSolana = 6;
constexpr uint8_t kTxTron = 7;
constexpr uint8_t kTxCosmos = 8;
constexpr uint8_t kTxStellar = 9;
constexpr uint8_t kTxAlgorand = 10;
constexpr uint8_t kTxNear = 11;
constexpr uint8_t kTxTezos = 12;
constexpr uint8_t kTxXrp = 13;
// Shared envelope for the account-model adapters (VET, ICX, ...). The payload
// starts with the adapter's own magic and is never treated as opaque bytes.
constexpr uint8_t kTxChain = 14;

Preferences preferences;
WalletLinkDevice link;
WalletNfcApdu apdu;
bool service_ready = false;
bool preferences_ready = false;

struct Reader {
  const uint8_t *data;
  size_t size;
  size_t offset;

  bool u8(uint8_t *value) {
    if (offset + 1 > size) return false;
    *value = data[offset++];
    return true;
  }
  bool u16(uint16_t *value) {
    if (offset + 2 > size) return false;
    *value = static_cast<uint16_t>(data[offset]) |
             static_cast<uint16_t>(static_cast<uint16_t>(data[offset + 1]) << 8);
    offset += 2;
    return true;
  }
  bool u32(uint32_t *value) {
    if (offset + 4 > size) return false;
    *value = static_cast<uint32_t>(data[offset]) |
             (static_cast<uint32_t>(data[offset + 1]) << 8) |
             (static_cast<uint32_t>(data[offset + 2]) << 16) |
             (static_cast<uint32_t>(data[offset + 3]) << 24);
    offset += 4;
    return true;
  }
  bool bytes(const uint8_t **out, size_t count) {
    if (offset + count > size) return false;
    *out = data + offset;
    offset += count;
    return true;
  }
  bool skip(size_t count) {
    if (offset + count > size) return false;
    offset += count;
    return true;
  }
};

struct Writer {
  uint8_t *data;
  size_t capacity;
  size_t offset;

  bool u8(uint8_t value) {
    if (offset + 1 > capacity) return false;
    data[offset++] = value;
    return true;
  }
  bool u16(uint16_t value) {
    if (offset + 2 > capacity) return false;
    data[offset++] = static_cast<uint8_t>(value);
    data[offset++] = static_cast<uint8_t>(value >> 8);
    return true;
  }
  bool u32(uint32_t value) {
    if (offset + 4 > capacity) return false;
    data[offset++] = static_cast<uint8_t>(value);
    data[offset++] = static_cast<uint8_t>(value >> 8);
    data[offset++] = static_cast<uint8_t>(value >> 16);
    data[offset++] = static_cast<uint8_t>(value >> 24);
    return true;
  }
  bool bytes(const uint8_t *value, size_t count) {
    if (offset + count > capacity) return false;
    memcpy(data + offset, value, count);
    offset += count;
    return true;
  }
  bool text(const char *value) {
    const size_t size = value == nullptr ? 0 : strlen(value);
    if (size > 255) return false;
    if (!u8(static_cast<uint8_t>(size))) return false;
    return size == 0 ||
           bytes(reinterpret_cast<const uint8_t *>(value), size);
  }
};

bool load_phone_key(void *, uint8_t out[32]) {
  if (!preferences_ready || !preferences.getBool(kPairedKey, false) ||
      preferences.getBytesLength(kPhoneKey) != kPhoneKeySize) {
    return false;
  }
  return preferences.getBytes(kPhoneKey, out, kPhoneKeySize) == kPhoneKeySize;
}

bool store_phone_key(void *, const uint8_t phone[32]) {
  if (!preferences_ready) return false;
  if (preferences.putBytes(kPhoneKey, phone, kPhoneKeySize) != kPhoneKeySize) {
    return false;
  }
  return preferences.putBool(kPairedKey, true) != 0;
}

void pair_decision(bool approved);
volatile bool pair_decision_busy = false;

void pair_decision(bool approved) {
  if (pair_decision_busy) return;
  pair_decision_busy = true;
  if (approved) {
    link.confirm_pairing();
  } else {
    link.reset_pairing();
  }
  wallet_ui_set_decision_callback(nullptr);
  wallet_ui_show_catalog();
  wallet_ui_set_status(approved ? "Phone paired" : "Pairing rejected");
  pair_decision_busy = false;
}

void show_pairing_code(void *, const uint8_t phone[32], uint32_t code) {
  if (wallet_signing_active() || wallet_cli_review_active() ||
      !board_has_display() || !wallet_ui_ready()) {
    link.reset_pairing();
    return;
  }
  char fingerprint[17];
  snprintf(fingerprint, sizeof(fingerprint), "%02x%02x%02x%02x",
           phone[0], phone[1], phone[2], phone[3]);
  wallet_ui_set_decision_callback(pair_decision);
  wallet_ui_show_pairing(code, fingerprint);
  secure_zero(fingerprint, sizeof(fingerprint));
}

void clear_pairing_prompt(void *) {
  if (wallet_signing_active() || wallet_cli_review_active()) return;
  wallet_ui_set_decision_callback(nullptr);
  wallet_ui_show_catalog();
}

bool derive_public_address(const char *coin, uint32_t account,
                           uint32_t change, uint32_t index, char *address,
                           size_t address_size, char *path, size_t path_size,
                           const uint32_t *subaddress) {
  WalletCatalogEntry entry;
  if (coin == nullptr || !wallet_catalog_find(coin, &entry) ||
      !wallet_catalog_has(entry, WalletCapabilityAddress) ||
      entry.network == nullptr ||
      (subaddress != nullptr && entry.network->encoding != AddressEncoding::CryptoNote) ||
      entry.network->encoding == AddressEncoding::QrlXmss) {
    return false;
  }
  HdPrivateNode master;
  if (wallet_session_load_master(&master) != WalletError::Ok) return false;
  uint8_t seed[kSeedSize];
  const bool have_seed = wallet_session_load_seed(seed) == WalletError::Ok;
  DerivedAddress derived;
  // Subaddress indices are only meaningful for CryptoNote; every other
  // encoding keeps the plain BIP32 derivation.
  const WalletError result =
      (subaddress != nullptr && entry.network->encoding == AddressEncoding::CryptoNote)
          ? derive_cryptonote_subaddress(master, *entry.network, account, change,
                                         index, subaddress[0], subaddress[1],
                                         &derived)
          : derive_address(master, have_seed ? seed : nullptr, *entry.network,
                           account, change, index, &derived);
  secure_zero(&master, sizeof(master));
  secure_zero(seed, sizeof(seed));
  if (result != WalletError::Ok) {
    clear_derived_address(&derived);
    return false;
  }
  const size_t address_length = strlen(derived.address);
  const size_t path_length = strlen(derived.path);
  bool ok = address_length < address_size && path_length < path_size;
  if (ok) {
    memcpy(address, derived.address, address_length + 1);
    memcpy(path, derived.path, path_length + 1);
  }
  clear_derived_address(&derived);
  return ok;
}

uint8_t status_for_signing(WalletSigningError error) {
  switch (error) {
    case WalletSigningError::Ok: return kStatusOk;
    case WalletSigningError::NoWallet: return kStatusLocked;
    case WalletSigningError::Unsupported: return kStatusUnsupported;
    case WalletSigningError::NotApproved: return kStatusNotApproved;
    case WalletSigningError::Expired: return kStatusExpired;
    case WalletSigningError::FeePolicy: return kStatusFeePolicy;
    case WalletSigningError::InvalidArgument: return kStatusInvalid;
    default: return kStatusInvalid;
  }
}

// The phone link is a signing transport with the same fail-closed policy as
// the serial CLI: it needs an unlocked wallet and a working trusted display.
bool link_signing_allowed() {
  if (wallet_cli_review_active() || link.pairing_pending()) return false;
  const WalletTransportState transport_state = {
    wallet_session_is_loaded(), true, board_has_display()
  };
  return wallet_transport_allows(WalletTransport::Nfc,
                                 WalletTransportOperation::SigningRequest,
                                 transport_state);
}

bool handle_address(Reader &reader, Writer &writer) {
  const uint8_t *coin = nullptr;
  uint8_t coin_size = 0;
  uint32_t account = 0;
  uint32_t change = 0;
  uint32_t index = 0;
  if (!reader.u8(&coin_size) || coin_size == 0 || coin_size > 32 ||
      !reader.bytes(&coin, coin_size) || !reader.u32(&account) ||
      !reader.u32(&change) || !reader.u32(&index)) {
    return writer.u8(kStatusInvalid);
  }
  // Optional trailing CryptoNote subaddress indices (major, minor). Older
  // phone builds stop after `index`, which keeps deriving the standard
  // address.
  uint32_t subaddress[2] = {0, 0};
  bool has_subaddress = false;
  if (reader.offset != reader.size) {
    if (!reader.u32(&subaddress[0]) || !reader.u32(&subaddress[1]) ||
        reader.offset != reader.size) {
      return writer.u8(kStatusInvalid);
    }
    has_subaddress = true;
  }
  char coin_id[33];
  if (memchr(coin, 0, coin_size) != nullptr) return writer.u8(kStatusInvalid);
  memcpy(coin_id, coin, coin_size);
  coin_id[coin_size] = '\0';
  char address[kAddressTextSize];
  char path[kDerivationPathTextSize];
  if (!wallet_session_is_loaded()) return writer.u8(kStatusLocked);
  // Do not replace a transaction's trusted review with an address supplied in
  // a second host request. The caller must finish or cancel that review first.
  if (wallet_signing_active() || wallet_cli_review_active() || link.pairing_pending())
    return writer.u8(kStatusNotApproved);
  if (!board_has_display() || !wallet_ui_ready()) return writer.u8(kStatusUnsupported);
  if (!derive_public_address(coin_id, account, change, index, address,
                             sizeof(address), path, sizeof(path),
                             has_subaddress ? subaddress : nullptr)) {
    return writer.u8(kStatusUnknownCoin);
  }
  const bool shown = wallet_ui_show_address(coin_id, address, path);
  const bool ok = shown
      ? writer.u8(kStatusOk) && writer.text(address) && writer.text(path)
      : writer.u8(kStatusUnsupported);
  secure_zero(address, sizeof(address));
  secure_zero(path, sizeof(path));
  return ok;
}

bool handle_begin_sign(Reader &reader, Writer &writer, uint32_t now_ms) {
  const uint8_t *coin = nullptr;
  uint8_t coin_size = 0;
  uint8_t kind = 0;
  uint32_t address_index = 0;
  uint16_t payload_size = 0;
  const uint8_t *payload = nullptr;
  if (!reader.u8(&coin_size) || coin_size == 0 || coin_size > 32 ||
      !reader.bytes(&coin, coin_size) || !reader.u8(&kind) ||
      !reader.u32(&address_index) || !reader.u16(&payload_size) ||
      !reader.bytes(&payload, payload_size) || reader.offset != reader.size ||
      payload_size > kMaxRequest) {
    return writer.u8(kStatusInvalid);
  }
  char coin_id[33];
  if (memchr(coin, 0, coin_size) != nullptr) return writer.u8(kStatusInvalid);
  memcpy(coin_id, coin, coin_size);
  coin_id[coin_size] = '\0';

  if (!link_signing_allowed()) {
    return writer.u8(wallet_session_is_loaded() ? kStatusUnsupported
                                                : kStatusLocked);
  }

  WalletSigningError error = WalletSigningError::Unsupported;
  switch (kind) {
    case kTxBitcoin:
      error = wallet_signing_begin_bitcoin(coin_id, payload, payload_size, now_ms);
      break;
    case kTxEvm:
      error = wallet_signing_begin_evm(coin_id, address_index, payload,
                                       payload_size, now_ms);
      break;
    case kTxKaspa:
      error = wallet_signing_begin_kaspa(payload, payload_size, now_ms);
      break;
    case kTxZcash:
      error = wallet_signing_begin_zcash(coin_id, payload, payload_size,
                                        now_ms);
      break;
    case kTxCryptoNote:
      error = wallet_signing_begin_cryptonote(coin_id, address_index, payload,
                                              payload_size, now_ms);
      break;
    case kTxSolana:
      error = wallet_signing_begin_solana(coin_id, address_index, payload,
                                          payload_size, now_ms);
      break;
    case kTxTron:
      error = wallet_signing_begin_tron(coin_id, address_index, payload,
                                        payload_size, now_ms);
      break;
    case kTxCosmos:
      error = wallet_signing_begin_cosmos(coin_id, address_index, payload,
                                          payload_size, now_ms);
      break;
    case kTxStellar:
      error = wallet_signing_begin_stellar(coin_id, address_index, payload,
                                          payload_size, now_ms);
      break;
    case kTxAlgorand:
      error = wallet_signing_begin_algorand(coin_id, address_index, payload, payload_size, now_ms);
      break;
    case kTxNear:
      error = wallet_signing_begin_near(coin_id, address_index, payload, payload_size, now_ms);
      break;
    case kTxTezos:
      error = wallet_signing_begin_tezos(coin_id, address_index, payload, payload_size, now_ms);
      break;
    case kTxXrp:
      error = wallet_signing_begin_xrp(coin_id, address_index, payload, payload_size, now_ms);
      break;
    case kTxChain:
      error = wallet_signing_begin_chain(coin_id, address_index, payload, payload_size, now_ms);
      break;
    default:
      return writer.u8(kStatusUnsupported);
  }
  if (error != WalletSigningError::Ok) {
    return writer.u8(status_for_signing(error));
  }
  const WalletSigningSession *session = wallet_signing_session();
  if (session == nullptr) return writer.u8(kStatusInvalid);
  return writer.u8(kStatusPending) &&
         writer.bytes(session->review_id, kWalletSigningReviewIdSize);
}

bool handle_result(Reader &reader, Writer &writer, uint8_t *response,
                   size_t response_capacity) {
  const uint8_t *review_id = nullptr;
  if (!reader.bytes(&review_id, kWalletSigningReviewIdSize) ||
      reader.offset != reader.size) {
    return writer.u8(kStatusInvalid);
  }
  const WalletSigningSession *session = wallet_signing_session();
  if (session == nullptr) return writer.u8(kStatusExpired);
  if (!crypto_constant_time_equal(session->review_id, review_id,
                                  kWalletSigningReviewIdSize)) {
    return writer.u8(kStatusInvalid);
  }
  if (session->rejected) return writer.u8(kStatusRejected);
  if (!session->approved) return writer.u8(kStatusPending);
  if (writer.offset + 3 > response_capacity) return false;
  const size_t header_offset = writer.offset;
  if (!writer.u8(kStatusOk) || !writer.u16(0)) return false;
  size_t signed_size = response_capacity - writer.offset;
  uint8_t *signed_data = response + writer.offset;
  const WalletSigningError error = wallet_signing_sign(signed_data, &signed_size);
  if (error != WalletSigningError::Ok) {
    writer.offset = header_offset;
    return writer.u8(status_for_signing(error));
  }
  if (signed_size > 0xffff || writer.offset + signed_size > response_capacity) {
    writer.offset = header_offset;
    return writer.u8(kStatusInvalid);
  }
  response[header_offset + 1] = static_cast<uint8_t>(signed_size);
  response[header_offset + 2] = static_cast<uint8_t>(signed_size >> 8);
  writer.offset += signed_size;
  wallet_ui_show_catalog();
  return true;
}

bool handle_cancel(Reader &reader, Writer &writer) {
  const uint8_t *review_id = nullptr;
  if (!reader.bytes(&review_id, kWalletSigningReviewIdSize) ||
      reader.offset != reader.size) {
    return writer.u8(kStatusInvalid);
  }
  const WalletSigningSession *session = wallet_signing_session();
  if (session == nullptr) return writer.u8(kStatusExpired);
  if (!crypto_constant_time_equal(session->review_id, review_id,
                                  kWalletSigningReviewIdSize)) {
    return writer.u8(kStatusInvalid);
  }
  wallet_signing_reject();
  return writer.u8(kStatusRejected);
}

bool handle_catalog(Reader &reader, Writer &writer) {
  uint16_t offset = 0;
  uint8_t limit = 0;
  if (!reader.u16(&offset) || !reader.u8(&limit) || reader.offset != reader.size) {
    return writer.u8(kStatusInvalid);
  }
  if (limit > 20) limit = 20;
  size_t total = 0;
  for (size_t index = 0; index < wallet_catalog_count(); ++index) {
    WalletCatalogEntry entry;
    if (wallet_catalog_at_sorted(index, &entry)) ++total;
  }
  uint8_t entries[1024];
  Writer entry_writer = { entries, sizeof(entries), 0 };
  size_t position = 0;
  uint8_t count = 0;
  while (position < wallet_catalog_count() && count < limit) {
    WalletCatalogEntry entry;
    if (!wallet_catalog_at_sorted(position, &entry)) {
      ++position;
      continue;
    }
    if (position < offset) {
      ++position;
      continue;
    }
    const size_t before = entry_writer.offset;
    if (!entry_writer.text(entry.id) || !entry_writer.text(entry.symbol)) {
      entry_writer.offset = before;
      break;
    }
    uint8_t caps = 0;
    if (wallet_catalog_has(entry, WalletCapabilityAddress)) caps |= 0x01;
    if (wallet_catalog_has(entry, WalletCapabilityTokenAccount)) caps |= 0x02;
    if (wallet_catalog_has(entry, WalletCapabilityTransactionReview)) caps |= 0x04;
    if (wallet_catalog_has(entry, WalletCapabilitySigning)) caps |= 0x08;
    if (!entry_writer.u8(caps)) {
      entry_writer.offset = before;
      break;
    }
    ++count;
    ++position;
  }
  return writer.u8(kStatusOk) &&
         writer.u16(static_cast<uint16_t>(total)) &&
         writer.u16(offset) && writer.u8(count) &&
         writer.bytes(entries, entry_writer.offset);
}

WalletLinkStatus handle_request(void *, const uint8_t *request,
                                size_t request_size, uint8_t *response,
                                size_t response_capacity, size_t *response_size) {
  *response_size = 0;
  if (request == nullptr || response == nullptr || response_capacity < 6) {
    return WalletLinkStatus::RequestFailed;
  }
  Reader reader = { request, request_size, 0 };
  uint8_t opcode = 0;
  uint32_t request_id = 0;
  if (!reader.u8(&opcode) || !reader.u32(&request_id)) {
    return WalletLinkStatus::RequestFailed;
  }
  Writer writer = { response, response_capacity, 0 };
  if (!writer.u32(request_id)) return WalletLinkStatus::RequestFailed;

  bool ok = false;
  switch (opcode) {
    case kOpPing:
      ok = reader.offset == reader.size && writer.u8(kStatusOk);
      break;
    case kOpInfo: {
      uint8_t flags = 0;
      if (wallet_session_is_loaded()) flags |= 0x01;
      if (wallet_signing_active()) flags |= 0x02;
      if (link.session_active()) flags |= 0x04;
      if (link.pairing_pending()) flags |= 0x08;
      ok = reader.offset == reader.size && writer.u8(kStatusOk) &&
           writer.u8(static_cast<uint8_t>(kLinkProtocolVersion)) &&
           writer.u8(flags);
      break;
    }
    case kOpCatalog:
      ok = handle_catalog(reader, writer);
      break;
    case kOpAddress:
      ok = handle_address(reader, writer);
      break;
    case kOpBeginSign:
      ok = handle_begin_sign(reader, writer, millis());
      break;
    case kOpResult:
      ok = handle_result(reader, writer, response, response_capacity);
      break;
    case kOpCancel:
      ok = handle_cancel(reader, writer);
      break;
    default:
      ok = writer.u8(kStatusInvalid);
      break;
  }
  if (!ok) return WalletLinkStatus::RequestFailed;
  *response_size = writer.offset;
  return WalletLinkStatus::Ok;
}

uint8_t identity_seed[32];
WalletLinkCallbacks callbacks = { load_phone_key, store_phone_key,
                                  show_pairing_code, clear_pairing_prompt,
                                  handle_request };

size_t nfc_apdu_handler(const uint8_t *apdu_bytes, size_t apdu_size,
                        uint8_t *response, size_t response_capacity) {
  return wallet_link_service_apdu(apdu_bytes, apdu_size, millis(), response,
                                  response_capacity);
}

}  // namespace

bool wallet_link_service_init() {
  if (service_ready) return true;
  preferences_ready = preferences.begin(kLinkPreferencesNamespace, false);
  if (!preferences_ready) return false;
  if (preferences.getBytesLength(kIdentitySeedKey) == sizeof(identity_seed)) {
    preferences.getBytes(kIdentitySeedKey, identity_seed, sizeof(identity_seed));
  } else {
    random_fill(identity_seed, sizeof(identity_seed));
    identity_seed[0] |= 1;
    if (preferences.putBytes(kIdentitySeedKey, identity_seed,
                             sizeof(identity_seed)) != sizeof(identity_seed)) {
      return false;
    }
  }
  if (!link.init(identity_seed, callbacks, nullptr)) return false;
  if (!apdu.init(&link)) return false;
  service_ready = true;
  return true;
}

void wallet_link_service_tick(uint32_t now_ms) {
  if (!service_ready) return;
  link.tick(now_ms);
  wallet_signing_tick(now_ms);
}

size_t wallet_link_service_apdu(const uint8_t *apdu_bytes, size_t apdu_size,
                                uint32_t now_ms, uint8_t *response,
                                size_t response_capacity) {
  if (!service_ready) return 0;
  return apdu.process(apdu_bytes, apdu_size, now_ms, response,
                      response_capacity);
}

void wallet_link_service_field_lost() {
  if (!service_ready) return;
  apdu.field_lost();
  wallet_signing_clear();
}

bool wallet_link_service_ready() {
  return service_ready;
}

bool wallet_link_service_pairing_pending() {
  return service_ready && link.pairing_pending();
}

bool wallet_link_service_confirm_pairing() {
#if !HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION
  // Production pairing is confirmed only by pair_decision on the local UI.
  return false;
#else
  if (!service_ready || !link.pairing_pending()) return false;
  const bool confirmed = link.confirm_pairing();
  if (confirmed) {
    wallet_ui_set_decision_callback(nullptr);
    wallet_ui_show_catalog();
  }
  return confirmed;
#endif
}

void wallet_link_service_reject_pairing() {
  if (!service_ready) return;
  link.reset_pairing();
  if (wallet_signing_active() || wallet_cli_review_active()) return;
  wallet_ui_set_decision_callback(nullptr);
  wallet_ui_show_catalog();
}

bool wallet_link_service_nfc_begin() {
  if (!service_ready) return false;
  return nfc_port_begin(nfc_apdu_handler, wallet_link_service_field_lost);
}

void wallet_link_service_nfc_service(uint32_t now_ms) {
  if (!service_ready) return;
  nfc_port_service(now_ms);
}

const char *wallet_link_service_nfc_state() {
  return nfc_port_state_text(nfc_port_state());
}

}  // namespace hexwallet
