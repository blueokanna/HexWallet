// Fault-injected NVS and board boundaries around the firmware CLI handlers.
#include <cstdio>
#include <map>
#include <string>
#include <vector>
#include <mbedtls/platform_util.h>
// This executable drives the authentication handlers directly. Give the unused
// device service entry points inline linkage so the host build can omit them.
namespace hexwallet {
inline void wallet_cli_service();
inline void wallet_usb_data_service();
inline bool service_usb_apdu();
}
#include "../../../WalletCli.cpp"

namespace {
using Bytes = std::vector<uint8_t>;
enum class Kind { Blob, U8, U32 };
struct Record { Kind kind; Bytes bytes; };
using Records = std::map<std::string, Record>;
Records committed;
std::string read_fault;
bool write_fault, commit_fault, open_fault, handle_open, protected_storage = true;
bool invalid_page;
bool page_visible, battery_low;
uint8_t page_id;
uint32_t now_ms = 100;
unsigned writes;

void check(bool ok, const char *expression, int line) {
  if (!ok) {
    fprintf(stderr, "CLI auth storage line %d: %s\n", line, expression);
    exit(1);
  }
}
#define CHECK(expr) check((expr), #expr, __LINE__)

int get(nvs_handle_t handle, const char *key, Kind kind, void *out, size_t *size) {
  CHECK(handle_open && handle == 1);
  if (read_fault == key) return -1;
  const auto it = committed.find(key);
  if (it == committed.end()) return ESP_ERR_NVS_NOT_FOUND;
  if (it->second.kind != kind) return ESP_ERR_NVS_NOT_FOUND;
  const auto &bytes = it->second.bytes;
  if (out && *size < bytes.size()) return -1;
  if (out) memcpy(out, bytes.data(), bytes.size());
  *size = bytes.size();
  return ESP_OK;
}
int set(nvs_handle_t handle, const char *key, Kind kind, const void *data, size_t size) {
  CHECK(handle_open && handle == 1);
  ++writes;
  if (write_fault) return -1;
  const auto *bytes = static_cast<const uint8_t *>(data);
  // NVSHandleSimple writes in the setter. Closing after a commit error
  // cannot be relied upon to roll that write back.
  committed[key] = {kind, Bytes(bytes, bytes + size)};
  return ESP_OK;
}
}

int nvs_open(const char *name, int mode, nvs_handle_t *handle) {
  CHECK(!handle_open && !strcmp(name, "hexwallet") && mode == NVS_READWRITE);
  if (open_fault) return -1;
  handle_open = true;
  *handle = 1;
  return ESP_OK;
}
void nvs_close(nvs_handle_t handle) {
  CHECK(handle == 1 && handle_open);
  handle_open = false;
}
int nvs_commit(nvs_handle_t handle) {
  CHECK(handle_open && handle == 1);
  if (commit_fault) return -1;
  return ESP_OK;
}
int nvs_get_stats(const char *, nvs_stats_t *) { return invalid_page ? -1 : ESP_OK; }
int nvs_find_key(nvs_handle_t handle, const char *key, nvs_type_t *type) {
  CHECK(handle_open && handle == 1);
  if (invalid_page) return ESP_ERR_NVS_NOT_FOUND;
  if (read_fault == key) return -1;
  const auto it = committed.find(key);
  if (it == committed.end()) return ESP_ERR_NVS_NOT_FOUND;
  if (type) {
    switch (it->second.kind) {
      case Kind::Blob: *type = NVS_TYPE_BLOB; break;
      case Kind::U8: *type = NVS_TYPE_U8; break;
      case Kind::U32: *type = NVS_TYPE_U32; break;
    }
  }
  return ESP_OK;
}
int nvs_get_blob(nvs_handle_t h, const char *k, void *v, size_t *n) { return get(h, k, Kind::Blob, v, n); }
int nvs_set_blob(nvs_handle_t h, const char *k, const void *v, size_t n) { return set(h, k, Kind::Blob, v, n); }
int nvs_get_u8(nvs_handle_t h, const char *k, uint8_t *v) { size_t n = 1; return get(h, k, Kind::U8, v, &n); }
int nvs_get_u32(nvs_handle_t h, const char *k, uint32_t *v) { size_t n = 4; return get(h, k, Kind::U32, v, &n); }
int nvs_set_u32(nvs_handle_t h, const char *k, uint32_t v) { return set(h, k, Kind::U32, &v, sizeof(v)); }
uint32_t millis() { return now_ms; }

namespace hexwallet {
void secure_zero(void *p, size_t n) { mbedtls_platform_zeroize(p, n); }
bool board_has_user_button() { return true; }
bool board_credential_storage_ready() { return protected_storage; }
void battery_monitor_init() {}
bool battery_monitor_blocks_signing() { return battery_low; }
TrustState trust_state() { return {}; }
bool trust_signing_allowed(const TrustState &) { return protected_storage; }
bool wallet_ui_review_digest(uint8_t out[kReviewSealSize]) {
  memset(out, page_id, kReviewSealSize);
  return page_visible;
}
bool wallet_ui_review_authorize(const uint8_t expected[kReviewSealSize]) {
  uint8_t current[kReviewSealSize];
  if (!wallet_ui_review_digest(current) || memcmp(current, expected, sizeof(current))) return false;
  page_visible = false;
  return true;
}
void wallet_session_clear() {}
void wallet_totp_clear() {}
void wallet_link_service_reset() {}
void wallet_ui_set_authenticated(bool value) { CHECK(!value); }
void beam_cli_reset() {}
void clear_bitcoin_request(BitcoinSigningRequest *) {}
void clear_evm_request(EvmSigningRequest *) {}
void clear_kaspa_transaction(KaspaTransaction *) {}
void clear_zcash_request(ZcashSigningRequest *) {}
}

namespace {
using namespace hexwallet;
void check_closed() {
  CHECK(!wallet_cli_is_authenticated() && !handle_open && !preferences_open && !provisioned && !challenge_active);
  CHECK(!wallet_cli_review_active() && !wallet_usb_data_enabled());
  for (uint8_t byte : verifier) CHECK(byte == 0);
  for (uint8_t byte : salt) CHECK(byte == 0);
  for (uint8_t byte : challenge) CHECK(byte == 0);
}
void provision() {
  char args[] = "test-pin-123 test-pin-123";
  provision_pin(args);
}
void submit_proof(const Bytes &expected_verifier) {
  CHECK(challenge_active);
  uint8_t proof[32];
  CHECK(crypto_hmac_sha256(expected_verifier.data(), expected_verifier.size(), challenge, sizeof(challenge), proof));
  char text[65];
  for (size_t i = 0; i < sizeof(proof); ++i) snprintf(text + 2 * i, 3, "%02x", proof[i]);
  unlock(text);
}
}

int main() {
  using namespace hexwallet;
  CHECK(wallet_cli_init(true));
  provision();
  const Bytes blob = committed.at(kProvisionedKey).bytes;
  CHECK(blob.size() == 48 && committed.size() == 1 && provisioned);
  const Bytes stored_verifier(blob.begin() + 16, blob.end());
  CHECK(wallet_cli_init(true));
  begin_challenge();
  submit_proof(stored_verifier);
  CHECK(wallet_cli_is_authenticated());
  auto review = [] {
    CHECK(begin_transaction_review());
    pending_transaction_kind = PendingTransactionKind::Zcash;
    report_transaction_review("123456");
  };
  review();
  CHECK(!transaction_pending);
  page_visible = true;
  review();
  ++page_id;
  CHECK(!authorize_transaction_review() && !transaction_pending);
  review();
  battery_low = true;
  CHECK(!authorize_transaction_review() && !transaction_pending);
  battery_low = false;
  review();
  now_ms += kTransactionApprovalMs;
  CHECK(!authorize_transaction_review() && !transaction_pending);
  review();
  CHECK(authorize_transaction_review() && !authorize_transaction_review() && !transaction_pending);
  puts("cli-display-approval=pass");
  protected_storage = false;
  CHECK(wallet_cli_init(true));
  check_closed();
  protected_storage = true;

  const Records legacy{{kProvisionedKey, {Kind::U8, {1}}}, {kSaltKey, {Kind::Blob, Bytes(blob.begin(), blob.begin() + 16)}},
                       {kVerifierKey, {Kind::Blob, stored_verifier}}};
  committed = legacy;
  CHECK(wallet_cli_init(true));
  begin_challenge();
  submit_proof(stored_verifier);
  CHECK(wallet_cli_is_authenticated());
  CHECK(!memcmp(salt, blob.data(), sizeof(salt)));
  CHECK(wallet_cli_init(true) && !wallet_cli_is_authenticated());
  begin_challenge();
  unlock("incorrect");
  CHECK(failure_count == 1 && !challenge_active && !wallet_cli_is_authenticated());
  now_ms += 300;
  CHECK(wallet_cli_init(true) && failure_count == 1);
  begin_challenge();
  CHECK(!challenge_active);
  now_ms += 2000;
  begin_challenge();
  submit_proof(stored_verifier);
  CHECK(wallet_cli_is_authenticated() && failure_count == 0);
  CHECK(wallet_cli_init(true) && failure_count == 0);

  for (bool fail_commit : {false, true}) {
    committed.clear();
    CHECK(wallet_cli_init(true));
    write_fault = !fail_commit;
    commit_fault = fail_commit;
    provision();
    check_closed();
    write_fault = commit_fault = false;
    committed = legacy;
    CHECK(wallet_cli_init(true));
    begin_challenge();
    submit_proof(stored_verifier);
    begin_challenge();
    write_fault = !fail_commit;
    commit_fault = fail_commit;
    unlock("incorrect");
    check_closed();
    write_fault = commit_fault = false;
    committed[kFailuresKey] = {Kind::U32, {7, 0, 0, 0}};
    CHECK(wallet_cli_init(true) && failure_count == 7);
    now_ms += 128000;
    begin_challenge();
    write_fault = !fail_commit;
    commit_fault = fail_commit;
    submit_proof(stored_verifier);
    check_closed();
    write_fault = commit_fault = false;
  }

  const auto before = writes;
  committed = legacy;
  invalid_page = true;
  CHECK(!wallet_cli_init(true));
  check_closed();
  invalid_page = false;
  for (auto key : {kProvisionedKey, kSaltKey, kVerifierKey, kFailuresKey}) {
    committed = legacy;
    read_fault = key;
    CHECK(!wallet_cli_init(true));
    check_closed();
  }
  read_fault.clear();
  for (auto key : {kProvisionedKey, kSaltKey, kVerifierKey}) {
    committed = legacy;
    committed.erase(key);
    CHECK(!wallet_cli_init(true));
    check_closed();
  }
  for (size_t n : {47, 49}) {
    committed = {{kProvisionedKey, {Kind::Blob, Bytes(n)}}};
    CHECK(!wallet_cli_init(true));
    check_closed();
  }
  committed = {{kFailuresKey, {Kind::U32, {0, 0, 0, 0}}}};
  CHECK(!wallet_cli_init(true));
  check_closed();
  committed = legacy;
  committed[kFailuresKey] = {Kind::U8, {0}};
  CHECK(!wallet_cli_init(true));
  check_closed();
  open_fault = true;
  CHECK(!wallet_cli_init(true));
  check_closed();
  CHECK(writes == before);
  puts("cli-auth-storage=pass");
}
