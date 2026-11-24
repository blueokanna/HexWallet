#include <stdio.h>
#include <string>
#include <vector>
#include "EinkFrame.h"
#include "../../../WalletUi.cpp"

static uint32_t test_now = 0;
static bool test_partial = true, test_entropy = true, test_committed = true;
static std::vector<std::string> sealed_lines;
static lv_key_t input_key = LV_KEY_ENTER;
static lv_indev_state_t input_state = LV_INDEV_STATE_RELEASED;
static unsigned decisions = 0;
static bool last_approval = false;
static uint8_t display_pixels[128 * 296 * 2];
static size_t catalog_size = 10;
uint32_t millis() { return test_now; }
void delay(uint32_t ms) { test_now += ms; }
static void read_key(lv_indev_t *, lv_indev_data_t *data) {
  data->key = input_key;
  data->state = input_state;
}
static void press_key(lv_indev_t *indev, lv_key_t key, bool hold = false) {
  input_key = key;
  input_state = LV_INDEV_STATE_PRESSED;
  test_now += 40;
  lv_indev_read(indev);
  if (hold) {
    test_now += 800;
    lv_indev_read(indev);
  }
  input_state = LV_INDEV_STATE_RELEASED;
  test_now += 40;
  lv_indev_read(indev);
}
static void decided(bool approved) { ++decisions; last_approval = approved; }
static void flush(lv_display_t *display, const lv_area_t *, uint8_t *) {
  lv_display_flush_ready(display);
}

namespace hexwallet
{
  bool board_is_eink() { return true; }
  uint8_t board_display_colors() { return 2; }
  uint16_t board_display_width() { return 296; }
  uint16_t board_display_height() { return 128; }
  bool wallet_link_service_connected() { return false; }
  uint16_t board_battery_millivolts() { return 3800; }
  bool board_has_display() { return true; }
  bool board_partial_refresh_supported() { return test_partial; }
  bool board_display_review_ready() { return test_committed; }
  void board_display_prepare_review() {}
  void board_display_service() { lv_timer_handler(); }
  size_t wallet_catalog_count() { return catalog_size; }
  bool wallet_catalog_at_sorted(size_t index, WalletCatalogEntry *out) {
    static const char *symbols[] = {"BTC", "ETH", "SOL", "ATOM", "OSMO", "XMR", "ZEC", "RYO", "ZANO", "TEST"};
    static const char *names[] = {"Bitcoin", "Ethereum", "Solana", "Cosmos Hub", "Osmosis", "Monero", "Zcash", "Ryo", "Zano", "Long asset name for wrapping and focus audit"};
    if (!out || index >= catalog_size || index >= 10) return false;
    // Match the release gates for Ryo/Zano: host-only payment candidates must
    // not appear as available signing capabilities in the screenshot fixtures.
    const uint8_t capabilities = WalletCapabilityAddress |
        ((index == 7 || index == 8) ? 0 : WalletCapabilitySigning);
    *out = {symbols[index], symbols[index], names[index], 0,
            capabilities, nullptr, "Registered code; hardware validation pending"};
    return true;
  }
  bool wallet_catalog_matches(const WalletCatalogEntry &, const char *) { return false; }
  bool wallet_catalog_has(const WalletCatalogEntry &entry, WalletCapability cap) { return (entry.capabilities & cap) != 0; }
  bool random_fill_checked(void *out, size_t size) { memset(out, test_entropy ? 0x37 : 0, size); return test_entropy; }
  bool review_seal_build(ReviewSeal *seal, const uint8_t *, const char *const *lines,
                         size_t count, uint32_t now, uint32_t window)
  {
    sealed_lines.clear();
    for (size_t index = 0; index < count; ++index)
      sealed_lines.emplace_back(lines[index]);
    *seal = {};
    seal->built = true;
    seal->expires_ms = now + window;
    return true;
  }
  void review_seal_code(const ReviewSeal &, char out[9]) { memcpy(out, "1234ABCD", 9); }
  void review_seal_mark_displayed(ReviewSeal *seal) { seal->displayed = seal->built; }
  bool review_seal_authorize_rendered(ReviewSeal *seal, uint32_t now)
  {
    if (!seal->built || !seal->displayed || seal->consumed ||
        static_cast<int32_t>(now - seal->expires_ms) >= 0)
      return false;
    seal->consumed = true;
    return true;
  }
}

#define CHECK(condition)                                           \
  do                                                               \
  {                                                                \
    if (!(condition))                                              \
    {                                                              \
      fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
      return 1;                                                    \
    }                                                              \
  } while (0)

static bool capture(lv_display_t *display, const char *directory, const char *name)
{
  lv_refr_now(display);
  uint8_t pixels[128 * 296 / 8] = {};
  if (!hexwallet::eink_pack_landscape(display_pixels, 296, 128, {0, 0, 296, 128}, 1, pixels, sizeof(pixels))) return false;
  const std::string path = std::string(directory) + "/" + name + ".pbm";
  FILE *file = fopen(path.c_str(), "wb");
  if (!file) return false;
  const bool written = fprintf(file, "P4\n128 296\n") > 0 && fwrite(pixels, 1, sizeof(pixels), file) == sizeof(pixels);
  return fclose(file) == 0 && written;
}

static bool audit_labels(lv_obj_t *object) {
  if (lv_obj_has_flag(object, LV_OBJ_FLAG_HIDDEN)) return true;
  if (lv_obj_check_type(object, &lv_label_class)) {
    const char *text = lv_label_get_text(object);
    const lv_font_t *font = lv_obj_get_style_text_font(object, LV_PART_MAIN);
    // Strict UTF-8/font coverage check on every rendered label, including those
    // below the viewport. No missing-glyph rectangle may pass a screenshot test.
    const auto *s = reinterpret_cast<const unsigned char *>(text);
    while (*s) {
      uint32_t c = *s++;
      if (c >= 0xc0) {
        const unsigned n = c < 0xe0 ? 1 : c < 0xf0 ? 2 : 3;
        c &= (1U << (6 - n)) - 1;
        for (unsigned i = 0; i < n; ++i) {
          if ((*s & 0xc0) != 0x80) return false;
          c = (c << 6) | (*s++ & 0x3f);
        }
      }
      if (c == '\n' || c == '\r' || c == '\t') continue;
      lv_font_glyph_dsc_t glyph{};
      if (!lv_font_get_glyph_dsc(font, &glyph, c, 0) || glyph.is_placeholder) {
        fprintf(stderr, "Missing glyph U+%04X in %s\n", c, text);
        return false;
      }
    }
    lv_obj_t *parent = lv_obj_get_parent(object);
    if (parent && lv_obj_get_width(object) > lv_obj_get_content_width(parent)) {
      fprintf(stderr, "Label wider than parent: %s (%d > %d)\n", text, (int)lv_obj_get_width(object), (int)lv_obj_get_content_width(parent));
      return false;
    }
    if (parent && lv_obj_check_type(parent, &lv_button_class) &&
        lv_obj_get_height(object) > lv_obj_get_content_height(parent)) {
      fprintf(stderr, "Label taller than button: %s (%d > %d; button %d; font %d)\n", text, (int)lv_obj_get_height(object), (int)lv_obj_get_content_height(parent), (int)lv_obj_get_height(parent), font->line_height);
      return false;
    }
  }
  for (uint32_t i = 0; i < lv_obj_get_child_count(object); ++i)
    if (!audit_labels(lv_obj_get_child(object, i))) return false;
  return true;
}

static bool audited_capture(lv_display_t *display, const char *directory, const char *name) {
  lv_obj_update_layout(lv_screen_active());
  if (!audit_labels(lv_screen_active())) return false;
  using namespace hexwallet;
  if (screen_content && (lv_obj_get_height(screen_content) < 48 || lv_obj_get_scroll_right(screen_content) > 0)) {
    fprintf(stderr, "Invalid body geometry on %s\n", name);
    return false;
  }
  return capture(display, directory, name);
}

static int render_pages(lv_display_t *display, lv_indev_t *keypad, lv_group_t *group, const char *directory) {
  using namespace hexwallet;
  const char *address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
  auto shot = [&](const char *name) { return audited_capture(display, directory, name); };
  auto bottom = [&]() {
    for (unsigned i = 0; i < 64; ++i) {
      lv_obj_update_layout(screen_content);
      if (lv_obj_get_scroll_bottom(screen_content) <= 0) return true;
      press_key(keypad, LV_KEY_NEXT);
    }
    return false;
  };
  CHECK(shot("home"));
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Create && shot("create"));
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::CreateWords && shot("create-words"));
  press_key(keypad, LV_KEY_ESC);
  CHECK(current_page == Page::Create);
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::CreateKey && shot("create-key"));
  press_key(keypad, LV_KEY_ESC);
  press_key(keypad, LV_KEY_ESC);
  CHECK(current_page == Page::Home);
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Recover && shot("recover"));
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::RecoverWords && shot("recover-words"));
  press_key(keypad, LV_KEY_ESC);
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::RecoverKey && shot("recover-key"));
  open_page(Page::Scan);
  CHECK(shot("scan"));
  press_key(keypad, LV_KEY_ESC);
  CHECK(current_page == Page::Home);
  open_page(Page::Controls);
  CHECK(shot("controls"));
  press_key(keypad, LV_KEY_NEXT);
  CHECK(shot("controls-scroll"));
  open_page(Page::Home);
  for (unsigned i = 0; i < 5; ++i) press_key(keypad, LV_KEY_NEXT);
  lv_obj_scroll_to_view_recursive(lv_group_get_focused(group), LV_ANIM_OFF);
  CHECK(shot("home-language"));
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Language);
  CHECK(shot("language"));
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Language);
  press_key(keypad, LV_KEY_ESC);
  open_page(Page::Catalog);
  CHECK(shot("catalog"));
  // Traverse all eight entries and choose Next assets through the real keypad.
  for (int i = 0; i < 8; ++i) press_key(keypad, LV_KEY_NEXT);
  lv_obj_scroll_to_view_recursive(lv_group_get_focused(group), LV_ANIM_OFF);
  CHECK(shot("catalog-next"));
  press_key(keypad, LV_KEY_ENTER);
  CHECK(catalog_offset == 8 && shot("catalog-last"));
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Asset && shot("asset"));
  CHECK(strcmp(lv_label_get_text(lv_obj_get_child(screen_content, 4)), tr("Signing code: unavailable", "签名代码：不可用")) == 0);
  press_key(keypad, LV_KEY_NEXT);
  CHECK(shot("asset-scroll"));
  press_key(keypad, LV_KEY_ESC);
  CHECK(current_page == Page::Catalog);
  catalog_size = 0;
  open_page(Page::Catalog);
  CHECK(catalog_offset == 0 && lv_group_get_focused(group) == screen_content && shot("catalog-empty"));
  catalog_size = 10;
  wallet_ui_set_authenticated(true);
  CHECK(wallet_ui_show_address("ETH", address, "m/44'/60'/0'/0/1") && shot("receive"));
  press_key(keypad, LV_KEY_NEXT);
  CHECK(shot("receive-scroll"));
  CHECK(bottom() && shot("receive-bottom"));
  press_key(keypad, LV_KEY_ESC);
  CHECK(current_page == Page::Home);
  std::string long_address(220, 'X');
  CHECK(wallet_ui_show_address("TEST", long_address.c_str(), "m/44'/0'/0'/0/0") && shot("receive-long"));
  CHECK(bottom() && shot("receive-long-bottom"));
  wallet_ui_show_catalog();
  WalletUiTransactionReview payment{};
  payment.network = "ETH";
  payment.outputs[0].address = address;
  payment.outputs[0].amount_text = "0.05 ETH";
  payment.outputs[0].ownership = "EXTERNAL";
  payment.outputs[0].ownership_is_label = true;
  payment.output_count = 1;
  payment.fee_text = "0.00042 ETH";
  payment.total_text = "0.05042 ETH";
  payment.show_decision_buttons = true;
  wallet_ui_set_decision_callback(decided);
  wallet_ui_show_transaction(payment);
  CHECK(shot("review"));
  press_key(keypad, LV_KEY_NEXT);
  CHECK(shot("scroll"));
  press_key(keypad, LV_KEY_ENTER);
  lv_obj_scroll_to_view_recursive(lv_group_get_focused(group), LV_ANIM_OFF);
  CHECK(shot("decision"));
  press_key(keypad, LV_KEY_NEXT);
  lv_obj_scroll_to_view_recursive(lv_group_get_focused(group), LV_ANIM_OFF);
  CHECK(shot("approval"));
  press_key(keypad, LV_KEY_ENTER);
  wallet_ui_service();
  CHECK(decisions == 0);
  press_key(keypad, LV_KEY_ENTER, true);
  wallet_ui_service();
  CHECK(decisions == 1 && last_approval);
  wallet_ui_show_catalog();
  wallet_ui_set_status("Approved. Keep the phone connected to collect the signature.");
  CHECK(shot("approved"));
  payment.show_decision_buttons = false;
  payment.approval_code = "654321";
  wallet_ui_show_transaction(payment);
  CHECK(lv_group_get_focused(group) == screen_content && shot("review-code"));
  press_key(keypad, LV_KEY_NEXT);
  CHECK(lv_obj_get_scroll_y(screen_content) > 0 && shot("review-code-scroll"));
  CHECK(bottom() && shot("review-code-bottom"));
  press_key(keypad, LV_KEY_ESC);
  CHECK(!review_seal_valid);
  test_entropy = false;
  payment.show_decision_buttons = true;
  wallet_ui_show_transaction(payment);
  CHECK(!review_seal_valid && shot("review-error"));
  test_entropy = true;
  wallet_ui_show_refusal("Fee is outside the device limits.");
  CHECK(!wallet_ui_review_authorize() && shot("refused"));
  wallet_ui_show_refusal("Chain ID differs from the selected network.");
  CHECK(shot("wrong-network"));
  wallet_ui_set_decision_callback(decided);
  wallet_ui_show_pairing(123456, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  CHECK(lv_group_get_focused(group) == screen_content && shot("pairing"));
  press_key(keypad, LV_KEY_NEXT);
  CHECK(shot("pairing-scroll"));
  press_key(keypad, LV_KEY_ENTER);
  lv_obj_scroll_to_view_recursive(lv_group_get_focused(group), LV_ANIM_OFF);
  CHECK(shot("pairing-reject"));
  press_key(keypad, LV_KEY_NEXT);
  lv_obj_scroll_to_view_recursive(lv_group_get_focused(group), LV_ANIM_OFF);
  CHECK(shot("pairing-approve"));
  press_key(keypad, LV_KEY_ESC);
  wallet_ui_service();
  CHECK(decisions == 2 && !last_approval);
  wallet_ui_show_catalog();
  CHECK(wallet_ui_show_otp("Example", "alice@example.com", "012345", 2000000030) && shot("otp"));
  press_key(keypad, LV_KEY_NEXT);
  CHECK(shot("otp-scroll"));
  CHECK(bottom() && shot("otp-bottom"));
  press_key(keypad, LV_KEY_ESC);
  CHECK(!otp_visible && otp_text[0] == 0);
  wallet_ui_show_busy("Preparing transaction review...");
  CHECK(shot("busy"));
  wallet_ui_set_status("UNDECODED CODE. The amount is native call value only. Code may move other assets or grant permissions. Approve only after independently verifying the target and every data byte.");
  CHECK(shot("status-long"));
  wallet_ui_show_port_error();
  CHECK(!wallet_ui_ready() && shot("port-error"));
  return 0;
}

int main(int argc, char **argv)
{
  using namespace hexwallet;
  const bool render = argc == 4 && !strcmp(argv[1], "--render");
  CHECK(argc == 1 || render || (argc == 3 && !strcmp(argv[1], "--language")));
  if (argc > 1) CHECK(wallet_ui_set_language(!strcmp(argv[render ? 3 : 2], "zh") ? WalletUiLanguage::Chinese : WalletUiLanguage::English));
  CHECK(run_qr_code_self_tests());
  CHECK(run_mascot_self_tests());
  CHECK(run_maid_sprite_self_tests());
  lv_init();
  lv_tick_set_cb(millis);
  lv_display_t *display = lv_display_create(296, 128);
  CHECK(display != nullptr);
  lv_display_set_color_format(display, LV_COLOR_FORMAT_RGB565);
  lv_display_set_buffers(display, display_pixels, nullptr, sizeof(display_pixels), LV_DISPLAY_RENDER_MODE_DIRECT);
  lv_display_set_flush_cb(display, flush);
  lv_group_t *group = lv_group_create();
  lv_indev_t *keypad = lv_indev_create();
  CHECK(group != nullptr && keypad != nullptr);
  lv_group_set_default(group);
  lv_indev_set_type(keypad, LV_INDEV_TYPE_KEYPAD);
  lv_indev_set_read_cb(keypad, read_key);
  lv_indev_set_group(keypad, group);
  CHECK(wallet_ui_init());
  if (render) {
    const int result = render_pages(display, keypad, group, argv[2]);
    lv_indev_delete(keypad);
    lv_group_set_default(nullptr);
    lv_group_delete(group);
    lv_display_delete(display);
    lv_deinit();
    return result;
  }
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
  test_now += 31000;
  wallet_ui_service();
  CHECK(memcmp(original_pixels, companion_pixels, sizeof(original_pixels)) == 0);

  const WalletUiLanguage startup_language = wallet_ui_language();
  open_page(Page::Language);
  press_key(keypad, startup_language == WalletUiLanguage::English ? LV_KEY_NEXT : LV_KEY_PREV);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(wallet_ui_language() != startup_language);
  press_key(keypad, startup_language == WalletUiLanguage::English ? LV_KEY_PREV : LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(wallet_ui_language() == startup_language);
  press_key(keypad, LV_KEY_ESC);
  CHECK(current_page == Page::Home);

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
  for (size_t index = 0; index < review.output_count; ++index)
  {
    details[index] = std::string(300, 'A' + static_cast<char>(index));
    review.outputs[index].amount_text = "1 ETH";
    review.outputs[index].address = "0x1111111111111111111111111111111111111111";
    review.outputs[index].ownership = "EXTERNAL";
    review.outputs[index].details = details[index].c_str();
  }
  wallet_ui_show_transaction(review);
  const WalletUiLanguage original_language = wallet_ui_language();
  CHECK(!wallet_ui_set_language(original_language == WalletUiLanguage::English ? WalletUiLanguage::Chinese : WalletUiLanguage::English));
  CHECK(wallet_ui_language() == original_language);
  CHECK(companion_stage == nullptr && companion_canvas == nullptr);
  CHECK(review_seal_valid && sealed_lines.size() == 71);
  CHECK(sealed_lines[64] == details[15]);
  CHECK(sealed_lines[65] == std::string(localize("MAXIMUM NETWORK FEE")) + "  0.002 ETH");
  CHECK(sealed_lines[67] == review.note);
  CHECK(sealed_lines[68] == tr("CONFIRM  654321", "确认码 654321"));
  CHECK(lv_group_get_focused(group) == screen_content);
  CHECK(review_key_remap(keypad, LV_KEY_NEXT) == LV_KEY_DOWN);
  lv_obj_update_layout(lv_screen_active());
  CHECK(lv_obj_get_scroll_y(screen_content) == 0);
  CHECK(lv_group_send_data(group, LV_KEY_DOWN) == LV_RESULT_OK);
  CHECK(lv_obj_get_scroll_y(screen_content) > 0);
  CHECK(lv_group_send_data(group, LV_KEY_UP) == LV_RESULT_OK);
  CHECK(lv_obj_get_scroll_y(screen_content) == 0);
  lv_obj_send_event(screen_content, LV_EVENT_CLICKED, nullptr);
  lv_obj_t *action = lv_group_get_focused(group);
  CHECK(action != screen_content && lv_obj_check_type(action, &lv_button_class));
  CHECK(strcmp(lv_label_get_text(lv_obj_get_child(action, 0)), tr("REJECT", "拒绝")) == 0);
  lv_group_focus_next(group);
  CHECK(strcmp(lv_label_get_text(lv_obj_get_child(lv_group_get_focused(group), 0)), tr("HOLD TO APPROVE", "长按批准")) == 0);
  CHECK(review_key_remap(keypad, LV_KEY_NEXT) == LV_KEY_NEXT);
  lv_group_focus_obj(screen_content);
  wallet_ui_set_decision_callback(decided);
  press_key(keypad, LV_KEY_ENTER);
  wallet_ui_service();
  CHECK(decisions == 0);
  CHECK(strcmp(lv_label_get_text(lv_obj_get_child(lv_group_get_focused(group), 0)), tr("REJECT", "拒绝")) == 0);
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  wallet_ui_service();
  CHECK(decisions == 0);
  press_key(keypad, LV_KEY_ENTER, true);
  // Button-release redraw may be in flight after the committed approve click.
  test_committed = false;
  wallet_ui_service();
  CHECK(decisions == 0);
  test_committed = true;
  wallet_ui_service();
  CHECK(decisions == 1 && last_approval);
  press_key(keypad, LV_KEY_ENTER, true);
  wallet_ui_service();
  CHECK(decisions == 1); // Decision delivery is one-shot even if the callback leaves the page up.
  wallet_ui_set_decision_callback(nullptr);
  const size_t review_children = lv_obj_get_child_count(screen_content);
  test_now += kMascotAnimationMs;
  wallet_ui_service();
  CHECK(lv_obj_get_child_count(screen_content) == review_children);
  uint8_t digest[kReviewSealSize];
  CHECK(wallet_ui_review_digest(digest));
  digest[0] ^= 1;
  CHECK(!wallet_ui_review_authorize(digest));
  digest[0] ^= 1;
  CHECK(wallet_ui_review_authorize(digest) && !wallet_ui_review_authorize(digest));

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
  CHECK(!wallet_ui_set_language(WalletUiLanguage::Chinese));
  wallet_ui_set_decision_callback(decided);
  CHECK(lv_group_get_focused(group) == screen_content);
  press_key(keypad, LV_KEY_ENTER);
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  wallet_ui_service();
  CHECK(decisions == 1);
  test_committed = false;
  press_key(keypad, LV_KEY_ENTER, true);
  wallet_ui_service();
  CHECK(decisions == 1);
  test_committed = true;
  press_key(keypad, LV_KEY_ESC);
  wallet_ui_service();
  CHECK(decisions == 2 && !last_approval);

  wallet_ui_set_decision_callback(decided);
  wallet_ui_show_pairing(123456, "0123456789abcdef");
  press_key(keypad, LV_KEY_ENTER);
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER, true);
  wallet_ui_service();
  CHECK(decisions == 3 && last_approval);
  press_key(keypad, LV_KEY_ENTER, true);
  wallet_ui_service();
  CHECK(decisions == 3);
  wallet_ui_set_decision_callback(decided);
  wallet_ui_show_pairing(1000000, "0123456789abcdef");
  CHECK(!pairing_page && !decision_callback);
  wallet_ui_set_decision_callback(decided);
  wallet_ui_show_pairing(123456, "abc\xE2\x80\xAE" "def");
  CHECK(!pairing_page && !decision_callback);

  const std::string long_fingerprint(220, 'f');
  wallet_ui_show_pairing(123456, long_fingerprint.c_str());
  CHECK(strcmp(lv_label_get_text(lv_obj_get_child(screen_content, 3)), long_fingerprint.c_str()) == 0);
  wallet_ui_show_catalog();

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
  const char *bad_text[] = {"abc\xE2\x80\xAE" "def", "abc\rdef", "abc\tdef", "\xc0\xaf", "\xf0\x9f\x92\xb0", "\xe4"};
  for (const char *text : bad_text) {
    review.outputs[0].details = text;
    wallet_ui_show_transaction(review);
    CHECK(!review_seal_valid && !wallet_ui_review_authorize());
  }
  review.outputs[0].details = details[0].c_str();
  wallet_ui_show_transaction(review);
  test_committed = false;
  CHECK(!wallet_ui_review_authorize());
  test_committed = true;
  CHECK(wallet_ui_review_authorize());
  wallet_ui_show_transaction(review);
  wallet_ui_service();
  CHECK(review_seal.displayed);
  test_committed = false;
  CHECK(!wallet_ui_review_authorize()); // A previously displayed frame can fail later.
  test_committed = true;
  CHECK(wallet_ui_review_authorize());
  wallet_ui_show_transaction(review);
  test_now += kReviewSealWindowMs;
  CHECK(!wallet_ui_review_authorize());
  // A host-supplied account named EXTERNAL must never turn into an ownership claim.
  review.outputs[0].ownership = "EXTERNAL";
  review.outputs[0].ownership_is_label = false;
  wallet_ui_show_transaction(review);
  CHECK(sealed_lines[3] == "EXTERNAL");
  review.outputs[0].ownership_is_label = true;
  wallet_ui_show_transaction(review);
  CHECK(sealed_lines[3] == localize("EXTERNAL"));
  CHECK(wallet_ui_show_otp("Example", "alice@example.com", "012345", 2000000030));
  CHECK(otp_visible && strcmp(otp_text, "012345") == 0 && !wallet_ui_review_authorize());
  CHECK(!wallet_ui_set_language(WalletUiLanguage::Chinese));
  wallet_ui_hide_otp();
  CHECK(!otp_visible && otp_text[0] == 0);
  CHECK(!wallet_ui_show_otp("Example", "alice", "12345x", 2000000030));
  CHECK(wallet_ui_show_otp("Example", "alice", "12345678", 2000000030));
  wallet_ui_show_transaction(review);
  CHECK(!otp_visible && otp_text[0] == 0);
  // Expiry of an earlier code must not erase a later transaction review.
  wallet_ui_hide_otp();
  CHECK(wallet_ui_review_authorize());
  wallet_ui_show_port_error();
  CHECK(!wallet_ui_ready() && !wallet_ui_review_authorize());
  wallet_ui_service();
  lv_indev_delete(keypad);
  lv_group_set_default(nullptr);
  lv_group_delete(group);
  lv_display_delete(display);
  lv_deinit();
  puts("real LVGL: lifetime, scrolling, language lock, full labels, one-shot hold/reject, seal and OTP: PASS");
  return 0;
}
