// Exercise the application callback registered with WalletLinkDevice. The UI
// boundary models page replacement and a single committed decision. The LVGL
// and transport suites drive the actual buttons and encrypted frames separately.
#include <array>
#include <string>
#include <vector>
#include "ChainCommon.h"
#include "../../../WalletLinkService.cpp"

namespace {
uint32_t clock_ms = 1000;
bool review_visible = false, low_battery = false;
hexwallet::WalletUiDecisionCallback decision = nullptr;
std::string review_text;
int pair_status = ESP_OK, marker_status, phone_status, seed_status, commit_status;
nvs_type_t pair_type = NVS_TYPE_U8, seed_type = NVS_TYPE_BLOB;
size_t seed_length = 32;
bool invalid_page;
unsigned handles, writes;
}

int nvs_open(const char *, int, nvs_handle_t *handle) { *handle = ++handles; return ESP_OK; }
void nvs_close(nvs_handle_t) { if (handles-- != 1) abort(); }
int nvs_commit(nvs_handle_t) { return commit_status; }
int nvs_get_stats(const char *, nvs_stats_t *) { return invalid_page ? -1 : ESP_OK; }
int nvs_set_blob(nvs_handle_t, const char *, const void *, size_t) { ++writes; return ESP_OK; }
int nvs_find_key(nvs_handle_t, const char *key, nvs_type_t *type) {
  if (invalid_page) return ESP_ERR_NVS_NOT_FOUND;
  const bool paired = !strcmp(key, "paired"), seed = !strcmp(key, "id_seed");
  if (type) *type = paired ? pair_type : (seed ? seed_type : NVS_TYPE_BLOB);
  return paired ? pair_status : (seed ? seed_status : phone_status);
}
int nvs_get_u8(nvs_handle_t, const char *, uint8_t *out) {
  if (marker_status == ESP_OK) *out = 1;
  return marker_status;
}
int nvs_get_blob(nvs_handle_t, const char *key, void *out, size_t *size) {
  const bool seed = strcmp(key, "id_seed") == 0;
  if ((!strcmp(key, "paired") && pair_type != NVS_TYPE_BLOB) || (seed && seed_type != NVS_TYPE_BLOB))
    return ESP_ERR_NVS_NOT_FOUND;
  const int result = seed ? seed_status : (strcmp(key, "paired") == 0 ? pair_status : phone_status);
  if (result == ESP_OK) {
    if (seed) *size = seed_length;
    if (out) memset(out, 0x31, *size);
  }
  return result;
}

int phone_storage_test() {
  using namespace hexwallet;
  auto fails = [] { return !wallet_link_service_init() && !service_ready && handles == 0 && writes == 0; };
  invalid_page = true;
  if (!fails()) return 1;
  invalid_page = false;
  pair_type = NVS_TYPE_U32;
  if (!fails()) return 1;
  pair_type = NVS_TYPE_U8;
  marker_status = -1;
  if (!fails()) return 1;
  marker_status = ESP_OK;
  phone_status = ESP_ERR_NVS_NOT_FOUND;
  if (!fails()) return 1;
  phone_status = ESP_OK;
  seed_status = ESP_ERR_NVS_NOT_FOUND;
  if (!fails()) return 1;
  pair_status = ESP_ERR_NVS_NOT_FOUND;
  if (!fails()) return 1; // Orphaned legacy phone record.
  phone_status = ESP_ERR_NVS_NOT_FOUND;
  seed_status = -1;
  if (!fails()) return 1;
  seed_status = ESP_OK;
  seed_type = NVS_TYPE_U8;
  if (!fails()) return 1;
  seed_type = NVS_TYPE_BLOB;
  seed_length = 31;
  if (!fails()) return 1;
  seed_status = ESP_ERR_NVS_NOT_FOUND;
  commit_status = -1;
  if (wallet_link_service_init() || service_ready || handles || writes != 1) return 1;
  seed_length = 32;
  seed_status = ESP_OK;
  pair_status = ESP_OK;
  pair_type = NVS_TYPE_U8;
  phone_status = ESP_OK;
  commit_status = ESP_OK;
  if (!wallet_link_service_init() || !wallet_link_service_init() || handles || writes != 1) return 1;
  service_ready = false;
  pair_type = NVS_TYPE_BLOB;
  phone_status = -1;
  if (!wallet_link_service_init() || handles || writes != 1) return 1;
  puts("phone-identity-storage=pass");
  return 0;
}

uint32_t millis() { return clock_ms; }
void delay(uint32_t ms) { clock_ms += ms; }

namespace hexwallet {
bool board_has_display() { return true; }
bool wallet_cli_review_active() { return false; }
bool wallet_totp_pending() { return false; }
bool battery_monitor_blocks_signing() { return low_battery; }
bool wallet_usb_data_enabled() { return false; }
bool wallet_ui_ready() { return true; }
void wallet_ui_service() {}
void wallet_ui_set_status(const char *) {}
void wallet_ui_show_catalog() { review_visible = false; }
void wallet_ui_show_refusal(const char *reason) { review_visible = false; decision = nullptr; review_text = reason; }
void wallet_ui_show_busy(const char *) { review_visible = false; }
void wallet_ui_set_decision_callback(WalletUiDecisionCallback cb) { decision = cb; }
bool wallet_ui_review_digest(uint8_t out[kReviewSealSize]) {
  return review_visible && crypto_sha256(reinterpret_cast<const uint8_t *>(review_text.data()), review_text.size(), out);
}
bool wallet_ui_review_authorize(const uint8_t expected[kReviewSealSize]) {
  uint8_t digest[kReviewSealSize];
  const bool committed = wallet_ui_review_digest(digest) && !memcmp(digest, expected, sizeof(digest));
  review_visible = false;
  return committed;
}
void wallet_ui_show_transaction(const WalletUiTransactionReview &review) {
  review_visible = review.show_decision_buttons && review.output_count != 0;
  review_text.clear();
  for (auto text : {review.network, review.fee_label, review.fee_text, review.total_text, review.note})
    if (text) review_text += std::string(text) + "\n";
  if (!review.fee_text) review_text += "fee=" + std::to_string(review.fee) + " sat\n";
  for (size_t i = 0; i < review.output_count; ++i) {
    const auto &output = review.outputs[i];
    if (!output.amount_text) review_text += "amount=" + std::to_string(output.value) + " sat\n";
    for (auto text : {output.amount_text, output.address, output.ownership, output.details})
      if (text) review_text += std::string(text) + "\n";
  }
}
bool wallet_ui_show_address(const char *, const char *address, const char *path) {
  printf("address=%s\npath=%s\n", address, path);
  return true;
}
void wallet_ui_show_pairing(uint32_t, const char *) { abort(); }
bool nfc_port_begin(NfcApduHandler, NfcSessionLostHandler) { abort(); }
void nfc_port_service(uint32_t) { abort(); }
NfcPortState nfc_port_state() { abort(); }
const char *nfc_port_state_text(NfcPortState) { abort(); }
}

// Test transport for DApp clients. Only the local harness can simulate a panel decision.
int phone_app_pipe() {
  using namespace hexwallet;
  if (!wallet_link_service_init() || wallet_session_import("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about") != WalletError::Ok)
    return 1;
  static char line[2 * kLinkMaxPayload + 3];
  static uint8_t request[kLinkMaxPayload], response[kLinkMaxPayload];
  while (fgets(line, sizeof(line), stdin)) {
    line[strcspn(line, "\r\n")] = '\0';
    if (!strcmp(line, "field-lost")) {
      transport_owner = WalletLinkTransport::Nfc;
      wallet_link_service_field_lost();
      if (wallet_signing_active() || decision || review_visible) return 1;
      puts("review-cleared");
    } else if (!strcmp(line, "expire")) {
      clock_ms += kWalletSigningReviewMs;
      puts("deadline-reached");
    } else if (!strcmp(line, "tick")) {
      wallet_signing_tick(clock_ms);
      puts("tick-serviced");
    } else if (!strcmp(line, "review")) {
      if (!review_visible) return 1;
      fputs(review_text.c_str(), stdout);
      puts("review-end");
    } else if (!strcmp(line, "approve") || !strcmp(line, "reject")) {
      if (!decision || !review_visible) return 1;
      decision(!strcmp(line, "approve"));
      puts("panel-decided");
    } else {
      size_t length, size;
      if (!chain_parse_hex(line, request, sizeof(request), &length) ||
          handle_request(nullptr, request, length, response, sizeof(response), &size) != WalletLinkStatus::Ok)
        return 1;
      printf("response=");
      for (size_t i = 0; i < size; ++i) printf("%02x", response[i]);
      putchar('\n');
    }
    fflush(stdout);
  }
  return 0;
}

int phone_review(int argc, char **argv) {
  using namespace hexwallet;
  if (argc != 5) return 2;
  // Public BIP39 fixture used by the SDK oracle. No secret is accepted as input.
  if (wallet_session_import("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about") != WalletError::Ok)
    return 1;
  const std::string network(argv[2]);
  uint8_t kind;
  const auto *profile = find_network_profile(network.c_str());
  if (profile && profile->encoding == AddressEncoding::Evm) kind = kTxEvm;
  else if (network == "sol") kind = 6;
  else if (network == "zec" || network == "zer") kind = kTxZcash;
  else if (cosmos_chain_params(network.c_str())) kind = kTxCosmos;
  else if (find_network_signing_policy(network.c_str())) kind = kTxBitcoin;
  else if (network == "apt") kind = kTxChain;
  else return 2;
  uint8_t payload[kEvmMaxUnsignedTransactionSize];
  size_t length;
  if (!chain_parse_hex(argv[3], payload, sizeof(payload), &length)) return 2;
  using Bytes = std::vector<uint8_t>;
  const Bytes header{4, 1, 0, 0, 0, static_cast<uint8_t>(network.size())};
  Bytes address = header;
  address.insert(address.end(), network.begin(), network.end());
  Bytes begin = address;
  address.insert(address.end(), {0,0,0,0, 0,0,0,0, 3,0,0,0});
  begin[0] = 5;
  begin.insert(begin.end(), {kind, 3,0,0,0,
                            static_cast<uint8_t>(length), static_cast<uint8_t>(length >> 8)});
  begin.insert(begin.end(), payload, payload + length);
  std::array<uint8_t, 2048> response{};
  size_t size;
  auto send = [&](const Bytes &request, uint8_t expected) {
    return handle_request(nullptr, request.data(), request.size(), response.data(), response.size(), &size) == WalletLinkStatus::Ok &&
           size >= 5 && !memcmp(response.data(), request.data() + 1, 4) && response[4] == expected;
  };
  if (network == "eth") {
    auto kaspa_request = address;
    kaspa_request.resize(header.size() + network.size());
    kaspa_request[0] = 5;
    kaspa_request.insert(kaspa_request.end(), {kTxKaspa, 0,0,0,0, 0,0});
    if (!send(kaspa_request, kStatusUnsupported) || decision || wallet_signing_active()) return 1;
  }
  const std::string mode(argv[4]);
  if (!send(address, 0)) return 1;
  if (mode == "refusal") {
    review_text.clear();
    if (handle_request(nullptr, begin.data(), begin.size(), response.data(), response.size(), &size) != WalletLinkStatus::Ok ||
        size != 5 || response[4] <= kStatusPending || review_text.empty() || decision || review_visible || wallet_signing_active()) return 1;
    printf("refusal=%s\n", review_text.c_str());
    return 0;
  }
  if (!send(begin, 1) || size != 13 || !decision || !review_visible) return 1;
  puts(review_text.c_str());
  Bytes result{6, 2, 0, 0, 0};
  result.insert(result.end(), response.begin() + 5, response.begin() + 13);
  const auto original_review = review_text;
  Bytes competing = begin;
  competing[1] = 7;
  competing[header.size() + network.size() + 1] = 4; // Different address index.
  if (!send(competing, kStatusNotApproved) || !send(address, kStatusNotApproved) ||
      !review_visible || review_text != original_review || !decision) return 1;
  if (!send(result, 1) || size != 5) return 1;
  if (mode == "field-lost") {
    service_ready = true;
    transport_owner = WalletLinkTransport::Nfc;
    decision(true);
    wallet_link_service_field_lost();
    return !wallet_signing_active() && send(result, 5) && size == 5 ? 0 : 1;
  }
  Bytes other = result;
  other.back() ^= 1;
  if (!send(other, 4) || size != 5) return 1;
  if (mode == "cancel") {
    Bytes cancel = result;
    cancel.front() = 7;
    return send(cancel, 2) && !decision && send(result, 2) && size == 5 ? 0 : 1;
  }
  if (mode == "stale-page") review_text = "A different review";
  decision(mode != "reject");
  if (decision || review_visible) return 1;
  if (mode == "reject" || mode == "stale-page") return send(result, 2) && size == 5 ? 0 : 1;
  if (!send(competing, kStatusNotApproved) || !send(address, kStatusNotApproved) || decision || review_visible) return 1;
  if (mode == "expire") {
    clock_ms += kWalletSigningReviewMs;
    return send(result, 5) && size == 5 ? 0 : 1;
  }
  if (mode == "low-battery") {
    low_battery = true;
    return send(result, 6) && size == 5 && !wallet_signing_active() ? 0 : 1;
  }
  if (mode != "approve" || !send(result, 0) || size <= 7 || size - 7 != (response[5] | response[6] << 8)) return 1;
  printf("signed=");
  for (size_t i = 7; i < size; ++i) printf("%02x", response[i]);
  puts("");
  return send(result, 5) && size == 5 ? 0 : 1;
}
