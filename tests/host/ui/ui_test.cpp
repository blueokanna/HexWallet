// Runs the production UI against real LVGL objects. Only board I/O, catalog and
// seal hashing are replaced: TrustAnchor's cryptographic tests run separately.
#include <stdio.h>
#include <string>
#include <vector>
#include "../../../WalletUi.cpp"

static uint32_t test_now = 0;
static bool test_partial = true, test_entropy = true, test_committed = true;
static std::vector<std::string> sealed_lines;
uint32_t millis() { return test_now; }
void delay(uint32_t ms) { test_now += ms; }

namespace hexwallet {
bool board_is_eink() { return true; }
uint8_t board_display_colors() { return 2; }
uint16_t board_display_width() { return 128; }
uint16_t board_display_height() { return 296; }
uint16_t board_battery_millivolts() { return 3800; }
bool board_has_display() { return true; }
bool board_partial_refresh_supported() { return test_partial; }
bool board_display_review_ready() { return test_committed; }
void board_display_prepare_review() {}
void board_display_service() {}
size_t wallet_catalog_count() { return 0; }
bool wallet_catalog_at_sorted(size_t, WalletCatalogEntry *) { return false; }
bool wallet_catalog_matches(const WalletCatalogEntry &, const char *) { return false; }
bool wallet_catalog_has(const WalletCatalogEntry &, WalletCapability) { return false; }
void random_fill(void *out, size_t size) { memset(out, 0x37, size); }
bool random_healthy() { return test_entropy; }
bool review_seal_build(ReviewSeal *seal, const uint8_t *, const char *const *lines,
                       size_t count, uint32_t now, uint32_t window) {
  sealed_lines.clear();
  for (size_t index = 0; index < count; ++index) sealed_lines.emplace_back(lines[index]);
  *seal = {};
  seal->built = true;
  seal->expires_ms = now + window;
  return true;
}
void review_seal_code(const ReviewSeal &, char out[9]) { memcpy(out, "1234ABCD", 9); }
void review_seal_mark_displayed(ReviewSeal *seal) { seal->displayed = seal->built; }
bool review_seal_authorize_rendered(ReviewSeal *seal, uint32_t now) {
  if (!seal->built || !seal->displayed || seal->consumed ||
      static_cast<int32_t>(now - seal->expires_ms) >= 0) return false;
  seal->consumed = true;
  return true;
}
}

#define CHECK(condition) do { if (!(condition)) { \
  fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); return 1; } } while (0)

int main() {
  using namespace hexwallet;
  CHECK(run_mascot_self_tests());
  CHECK(run_maid_sprite_self_tests());
  lv_init();
  lv_display_t *display = lv_display_create(128, 296);
  CHECK(display != nullptr);
  CHECK(wallet_ui_init());
  CHECK(companion_canvas != nullptr);
  lv_obj_t *original_canvas = companion_canvas;
  uint8_t original_pixels[sizeof(companion_pixels)];
  memcpy(original_pixels, companion_pixels, sizeof(original_pixels));
  test_now = 3 * kMascotAnimationMs;
  wallet_ui_service();
  CHECK(original_canvas == companion_canvas);
  CHECK(lv_obj_get_child_count(companion_stage) == 1);
  CHECK(memcmp(original_pixels, companion_pixels, sizeof(original_pixels)) != 0);
  // Unsupported partial refresh leaves the current pixels untouched.
  memcpy(original_pixels, companion_pixels, sizeof(original_pixels));
  test_partial = false;
  test_now += kMascotAnimationMs;
  wallet_ui_service();
  CHECK(memcmp(original_pixels, companion_pixels, sizeof(original_pixels)) == 0);
  test_partial = true;

  WalletUiTransactionReview review = {};
  review.network = "ETH";
  review.fee_label = "MAXIMUM NETWORK FEE";
  review.fee_text = "0.002 ETH";
  review.total_text = "1.002 ETH";
  review.note = "Check complete calldata metadata.";
  review.approval_code = "654321";
  review.show_decision_buttons = true;
  review.output_count = kWalletUiMaxTransactionOutputs;
  std::string details[16];
  for (size_t index = 0; index < review.output_count; ++index) {
    details[index] = std::string(300, 'A' + static_cast<char>(index));
    review.outputs[index].amount_text = "1 ETH";
    review.outputs[index].address = "0x1111111111111111111111111111111111111111";
    review.outputs[index].ownership = "EXTERNAL";
    review.outputs[index].details = details[index].c_str();
  }
  wallet_ui_show_transaction(review);
  CHECK(companion_stage == nullptr && companion_canvas == nullptr);
  CHECK(review_seal_valid && sealed_lines.size() == 71);
  CHECK(sealed_lines[64] == details[15]);
  CHECK(sealed_lines[65] == "MAXIMUM NETWORK FEE  0.002 ETH");
  CHECK(sealed_lines[67] == review.note);
  CHECK(sealed_lines[68] == "CONFIRM 654321");
  const size_t review_children = lv_obj_get_child_count(screen_content);
  test_now += kMascotAnimationMs;
  wallet_ui_service();
  CHECK(lv_obj_get_child_count(screen_content) == review_children);
  CHECK(wallet_ui_review_authorize() && !wallet_ui_review_authorize());

  wallet_ui_show_transaction(review);
  wallet_ui_show_catalog();
  CHECK(!wallet_ui_review_authorize());
  CHECK(companion_canvas != nullptr);
  // Direct ancestor deletion fires LVGL's deletion callback too.
  lv_obj_clean(screen_content);
  CHECK(companion_stage == nullptr && companion_canvas == nullptr);
  wallet_ui_show_transaction(review);
  CHECK(wallet_ui_show_address("ETH", review.outputs[0].address, "m/44'/60'/0'/0/0"));
  CHECK(!wallet_ui_review_authorize());
  wallet_ui_show_transaction(review);
  wallet_ui_show_pairing(123456, "paired fingerprint");
  CHECK(!wallet_ui_review_authorize());

  review.output_count = kWalletUiMaxTransactionOutputs + 1;
  wallet_ui_show_transaction(review);
  CHECK(!wallet_ui_review_authorize());
  review.output_count = 1;
  std::string overlong(256, '9');
  review.outputs[0].amount_text = overlong.c_str();
  wallet_ui_show_transaction(review);
  CHECK(!wallet_ui_review_authorize());
  review.outputs[0].amount_text = "1 ETH";
  test_entropy = false;
  wallet_ui_show_transaction(review);
  CHECK(!wallet_ui_review_authorize());
  test_entropy = true;
  wallet_ui_show_transaction(review);
  test_committed = false;
  CHECK(!wallet_ui_review_authorize());
  test_committed = true;
  CHECK(wallet_ui_review_authorize());
  wallet_ui_show_port_error();
  CHECK(!wallet_ui_ready() && !wallet_ui_review_authorize());
  wallet_ui_service();
  lv_display_delete(display);
  lv_deinit();
  puts("mascot, sprite bounds, real LVGL lifetime and complete review labels: PASS");
  return 0;
}
