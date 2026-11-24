#include <stdio.h>
#include <string>
#include <vector>
#include "EinkFrame.h"
#include "WalletWorker.h"
#include "../../../WalletUi.cpp"

static uint32_t test_now = 0;
static bool test_partial = true, test_entropy = true, test_committed = true;
static std::vector<std::string> sealed_lines;
static lv_key_t input_key = LV_KEY_ENTER;
static lv_indev_state_t input_state = LV_INDEV_STATE_RELEASED;
static unsigned decisions = 0;
static bool last_approval = false;
static uint16_t panel_width = 296, panel_height = 128;
static uint8_t display_pixels[240 * 320 * 2];
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
  CameraProbeState board_camera_probe() { return CameraProbeState::NotConfigured; }
  bool nfc_port_configured() { return true; }
  const char *nfc_port_error() { return nullptr; }
  static NfcBackupStatus tag_status = NfcBackupStatus::Idle;
  NfcBackupStatus nfc_backup_start() { return tag_status = NfcBackupStatus::Pending; }
  void nfc_backup_cancel() { tag_status = NfcBackupStatus::Idle; }
  NfcBackupStatus nfc_backup_take(char (&key)[65]) {
    if (tag_status == NfcBackupStatus::Complete) {
      memcpy(key, "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg", 59);
      tag_status = NfcBackupStatus::Idle;
      return NfcBackupStatus::Complete;
    }
    return tag_status;
  }
  static CustodyBlocker test_blocker = CustodyBlocker::BackendMissing;
  CustodyGateState custody_gate_state() { return {}; }
  CustodyBlocker custody_gate_blocker(const CustodyGateState &) { return test_blocker; }
  bool wallet_session_is_loaded() { return false; }
  static bool test_display_operational = true;
  bool board_display_operational() { return test_display_operational; }
  static const char public_encrypted[] = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
  static unsigned backup_reads = 0;
  WalletError bip38_decrypt(const char *input, size_t size, const uint8_t *password, size_t length,
                            BitcoinKeyNetwork net, BitcoinPrivateKey *out, KeyBackupControl control) {
    ++backup_reads;
    if (!control.progress(control.context)) return WalletError::Aborted;
    if (size != 58 || memcmp(input, public_encrypted, 58)) return WalletError::InvalidChecksum;
    if (length != 1 || *password != 'p' || net != BitcoinKeyNetwork::Mainnet) return WalletError::IncorrectPassphrase;
    out->network = net;
    return WalletError::Ok;
  }
  WalletError private_key_decode(const char *text, size_t size, BitcoinKeyNetwork net, bool compressed, BitcoinPrivateKey *out) {
    if (size != 64 || text[63] != '1') return WalletError::InvalidKey;
    out->network = net;
    out->compressed = compressed;
    return WalletError::Ok;
  }
  WalletError bip38_encrypt(const BitcoinPrivateKey &, const uint8_t *, size_t, char *out, size_t capacity, KeyBackupControl) {
    if (capacity < sizeof(public_encrypted)) return WalletError::BufferTooSmall;
    memcpy(out, public_encrypted, sizeof(public_encrypted));
    return WalletError::Ok;
  }
  WalletError bitcoin_key_address(const BitcoinPrivateKey &, char *out, size_t capacity) {
    const char address[] = "1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB";
    if (capacity < sizeof(address)) return WalletError::BufferTooSmall;
    memcpy(out, address, sizeof(address));
    return WalletError::Ok;
  }
  static const char fixture_words[] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  // English BIP39 phrases for zero-filled entropy, cross-checked with ethers.
  static std::string fixture_phrase(unsigned count) {
    static const char *const endings[] = {"about", "address", "agent", "admit", "art"};
    if (count < 12 || count > 24 || count % 3) return {};
    std::string words;
    for (unsigned i = 1; i < count; ++i) words += "abandon ";
    return words + endings[(count - 12) / 3];
  }
  WalletError bip39_generate(MnemonicLanguage language, unsigned count, char *out, size_t size) {
    const auto words = fixture_phrase(count);
    if (language != MnemonicLanguage::English || words.empty()) return WalletError::InvalidArgument;
    if (size <= words.size()) return WalletError::BufferTooSmall;
    memcpy(out, words.c_str(), words.size() + 1);
    return WalletError::Ok;
  }
  WalletError bip39_validate(const char *words, MnemonicLanguage language) {
    if (language == MnemonicLanguage::English) {
      for (unsigned count = 12; count <= 24; count += 3)
        if (fixture_phrase(count) == words) return WalletError::Ok;
    }
    return WalletError::InvalidMnemonic;
  }
  static unsigned imports = 0;
  WalletError wallet_session_import_language(const char *words, MnemonicLanguage language, const char *) {
    if (bip39_validate(words, language) != WalletError::Ok) return WalletError::InvalidMnemonic;
    ++imports;
    return WalletError::Ok;
  }
  void secure_zero(void *p, size_t size) { memset(p, 0, size); }
  static AssetLayout saved_layout = AssetLayout::List;
  static bool layout_write_failure = false;
  const char *load_asset_layout(AssetLayout &layout) { layout = saved_layout; return nullptr; }
  const char *save_asset_layout(AssetLayout layout) {
    if (layout_write_failure) return "ESP_ERR_NVS_NOT_ENOUGH_SPACE";
    saved_layout = layout;
    return nullptr;
  }
  bool board_is_eink() { return true; }
  uint8_t board_display_colors() { return 2; }
  uint16_t board_display_width() { return panel_width; }
  uint16_t board_display_height() { return panel_height; }
  bool wallet_link_service_connected() { return false; }
  uint16_t board_battery_millivolts() { return 3800; }
  bool board_has_display() { return true; }
  bool board_has_touch() { return panel_width < panel_height; }
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
        ((index == 7 || index == 8) ? 0 : WalletCapabilitySigning | WalletCapabilityTransactionReview);
    *out = {symbols[index], symbols[index], names[index], 0,
            capabilities, nullptr, "Registered code; hardware validation pending"};
    return true;
  }
  bool wallet_catalog_matches(const WalletCatalogEntry &entry, const char *query) {
    std::string needle(query);
    for (auto &c : needle) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    for (std::string value : {entry.id, entry.name, entry.symbol}) {
      for (auto &c : value) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
      if (value.find(needle) != std::string::npos) return true;
    }
    return false;
  }
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

static bool type_key(lv_indev_t *keypad, const char *caption) {
  using namespace hexwallet;
  for (unsigned i = 0; input_matrix && i < 52; ++i) {
    const char *selected = lv_buttonmatrix_get_button_text(input_matrix, lv_buttonmatrix_get_selected_button(input_matrix));
    if (selected && !strcmp(selected, caption)) {
      press_key(keypad, LV_KEY_ENTER);
      return true;
    }
    press_key(keypad, LV_KEY_NEXT);
  }
  fprintf(stderr, "Keyboard button missing: %s\n", caption);
  return false;
}

static bool type_secret(lv_indev_t *keypad, const char *text) {
  const char *mode = "abc";
  for (; *text; ++text) {
    char key[2] = {*text, 0};
    if (*text == ' ') {
      if (!type_key(keypad, hexwallet::tr("Spc", "空格"))) return false;
      continue;
    }
    const char *next = *text >= '0' && *text <= '9' ? "123" : *text >= 'A' && *text <= 'Z' ? "ABC" : "abc";
    if (strcmp(mode, next) && !type_key(keypad, next)) return false;
    if (!type_key(keypad, key)) return false;
    mode = next;
  }
  return type_key(keypad, hexwallet::tr("Done", "完成"));
}

static int render_pages(lv_display_t *display, lv_indev_t *keypad, lv_group_t *group, const char *directory) {
  using namespace hexwallet;
  const char *address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
  auto shot = [&](const char *name) { return audited_capture(display, directory, name); };
  auto bottom = [&]() {
    auto target = reader_target ? reader_target : screen_content;
    for (unsigned i = 0; i < 64; ++i) {
      lv_obj_update_layout(target);
      if (lv_obj_get_scroll_bottom(target) <= 0) return true;
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
  wallet_ui_set_authenticated(true);
  open_page(Page::RecoverKey);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::KeyNetwork && shot("backup-network"));
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::KeyEntry && type_secret(keypad, public_encrypted));
  CHECK(current_page == Page::KeyPass && shot("backup-password") && type_secret(keypad, "p"));
  CHECK(current_page == Page::KeyWorking && shot("backup-working"));
  wallet_ui_service();
  CHECK(current_page == Page::KeyResult && shot("backup-address"));
  open_page(Page::NfcImport);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::TagWait && shot("backup-tag"));
  press_key(keypad, LV_KEY_ESC);
  test_blocker = CustodyBlocker::None;
  open_page(Page::CreateWords);
  CHECK(shot("mnemonic-language"));
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::WordsCount && shot("mnemonic-count"));
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::WordsBackup && shot("mnemonic-backup") && bottom());
  press_key(keypad, LV_KEY_ENTER);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::WordsConfirm && shot("mnemonic-retype") && type_secret(keypad, fixture_words));
  CHECK(current_page == Page::PassChoice && shot("mnemonic-passphrase"));
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Enroll && shot("mnemonic-create-confirm"));
  press_key(keypad, LV_KEY_ENTER);
  open_page(Page::RecoverWords);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::WordsInput && shot("mnemonic-recover") && type_secret(keypad, fixture_words));
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Enroll && shot("mnemonic-recover-confirm"));
  test_blocker = CustodyBlocker::BackendMissing;
  wallet_ui_set_authenticated(false);
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
  open_page(Page::Companion);
  CHECK(companion_canvas && shot("companion"));
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Companion && companion_canvas && shot("companion-feed"));
  test_now += kMascotActionCooldownMs;
  for (unsigned i = 0; i < 3; ++i) press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(companion_rendered.mood == MascotMood::Bubbles && shot("companion-bubbles"));
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
  open_page(Page::Settings);
  CHECK(shot("settings"));
  for (unsigned i = 0; i < 3; ++i) press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Search && shot("keyboard"));
  CHECK(type_key(keypad, tr("Pin", "拼音")) && type_key(keypad, "s") && type_key(keypad, "h") && type_key(keypad, "i"));
  CHECK(type_key(keypad, tr("Han", "选字")) && input_candidates && shot("keyboard-candidates"));
  press_key(keypad, LV_KEY_ESC);
  CHECK(!input_matrix && !text_input.composition()[0] && !asset_query[0]);
  open_page(Page::Settings);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Layout && shot("layout"));
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(asset_layout == AssetLayout::Grid && shot("catalog-grid"));
  open_page(Page::Layout);
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(asset_layout == AssetLayout::Card && shot("catalog-card"));
  CHECK(saved_layout == AssetLayout::Card);
  CHECK(lv_obj_get_style_radius(lv_obj_get_child(screen_content, 0), LV_PART_MAIN) == (12 * lv_display_get_dpi(display) + 80) / 160);
  open_page(Page::Layout);
  layout_write_failure = true;
  press_key(keypad, LV_KEY_PREV);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(asset_layout == AssetLayout::Card && current_page == Page::Layout && layout_error);
  layout_write_failure = false;
  press_key(keypad, LV_KEY_ENTER);
  CHECK(!layout_error);
  asset_layout = AssetLayout::List;
  wallet_ui_set_authenticated(true);
  CHECK(wallet_ui_show_address("ETH", address, "m/44'/60'/0'/0/1") && shot("receive"));
  auto qr = lv_obj_get_child(lv_obj_get_child(lv_obj_get_child(screen_content, 0), 0), 0);
  lv_area_t qr_before, qr_after;
  lv_obj_get_coords(qr, &qr_before);
  press_key(keypad, LV_KEY_NEXT);
  CHECK(shot("receive-scroll"));
  CHECK(bottom() && shot("receive-bottom"));
  lv_obj_get_coords(qr, &qr_after);
  CHECK(!memcmp(&qr_before, &qr_after, sizeof(qr_before)) && lv_obj_get_scroll_y(screen_content) == 0);
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
  test_display_operational = false;
  wallet_ui_service();
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
  CHECK(current_page == Page::Settings);

  for (unsigned i = 0; i < 3; ++i) press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Search && input_matrix);
  CHECK(type_key(keypad, "ABC") && type_key(keypad, "B") && type_key(keypad, "abc") && type_key(keypad, "t"));
  CHECK(type_key(keypad, "123") && type_key(keypad, "8") && type_key(keypad, "#%") && type_key(keypad, "!"));
  CHECK(!strcmp(text_input.text(), "Bt8!"));
  CHECK(type_key(keypad, tr("Del", "删除")) && type_key(keypad, tr("Del", "删除")));
  CHECK(type_key(keypad, "abc") && type_key(keypad, "c") && type_key(keypad, tr("Done", "完成")));
  CHECK(current_page == Page::Catalog && catalog_matches == 1 && !strcmp(asset_query, "Btc") && !text_input.size());
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Search);
  const char *pinyin = tr("Pin", "拼音"), *han = tr("Han", "选字");
  CHECK(type_key(keypad, pinyin) && type_key(keypad, "s") && type_key(keypad, "h") && type_key(keypad, "i") && type_key(keypad, han));
  CHECK(input_candidates && text_input.candidate_count() > 16);
  CHECK(type_key(keypad, tr("Next", "下页")) && input_candidate_offset == 8);
  CHECK(type_key(keypad, tr("Prev", "上页")) && input_candidate_offset == 0);
  CHECK(type_key(keypad, tr("Next", "下页")));
  char han_char[4];
  CHECK(text_input.candidate(8, han_char) && type_key(keypad, han_char));
  CHECK(!strcmp(text_input.text() + 3, han_char));
  CHECK(type_key(keypad, tr("Done", "完成")) && !catalog_matches);
  for (unsigned i = 0; i < 16; ++i) {
    press_key(keypad, LV_KEY_ENTER);
    CHECK(current_page == Page::Search && text_input.size() == 6);
    CHECK(type_key(keypad, tr("Del", "删除")) && !strcmp(text_input.text(), "Btc"));
    press_key(keypad, LV_KEY_ESC);
    CHECK(current_page == Page::Catalog && !input_matrix && !text_input.size() && strlen(asset_query) == 6);
  }
  press_key(keypad, LV_KEY_ENTER);
  for (unsigned i = 0; i < 4; ++i) CHECK(type_key(keypad, tr("Del", "删除")));
  CHECK(type_key(keypad, tr("Done", "完成")) && catalog_matches == catalog_size && !asset_query[0]);

  // Public words and a simulated custody gate exercise only the display flow.
  wallet_ui_set_authenticated(true);
  test_blocker = CustodyBlocker::None;
  open_page(Page::Home);
  for (unsigned i = 0; i < 3; ++i) press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::WordsCount);
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::WordsBackup && setup_words.count == 12);
  lv_obj_update_layout(screen_content);
  for (unsigned i = 0; i < 32 && lv_obj_get_scroll_bottom(screen_content) > 0; ++i) press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::WordsConfirm && input_matrix);
  CHECK(type_key(keypad, tr("Done", "完成")) && current_page == Page::WordsConfirm);
  for (const char c : std::string(fixture_words)) {
    const char key[] = {c, 0};
    CHECK(type_key(keypad, c == ' ' ? tr("Spc", "空格") : key));
  }
  CHECK(type_key(keypad, tr("Done", "完成")) && current_page == Page::PassChoice);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(type_key(keypad, "p") && !strcmp(lv_label_get_text(input_preview), "*") && type_key(keypad, tr("Done", "完成")));
  CHECK(current_page == Page::PassConfirm && type_key(keypad, "q") && type_key(keypad, tr("Done", "完成")));
  CHECK(current_page == Page::PassConfirm && type_key(keypad, tr("Del", "删除")) && type_key(keypad, "p"));
  CHECK(type_key(keypad, tr("Done", "完成")) && current_page == Page::Enroll);
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(imports == 0);
  press_key(keypad, LV_KEY_ENTER, true);
  CHECK(imports == 1 && current_page == Page::Home && !setup_words.words[0] && !setup_words.passphrase[0]);
  // Restore with explicit empty passphrase and cancel at the default choice.
  open_page(Page::Recover);
  press_key(keypad, LV_KEY_ENTER);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::WordsInput && type_secret(keypad, fixture_words));
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::Enroll && !setup_words.passphrase[0]);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(imports == 1 && current_page == Page::Home && !setup_words.words[0]);

  for (unsigned action = 0; action < 4; ++action) {
    wallet_ui_set_authenticated(true);
    open_page(Page::Recover);
    press_key(keypad, LV_KEY_NEXT);
    press_key(keypad, LV_KEY_ENTER);
    press_key(keypad, LV_KEY_ENTER);
    CHECK(current_page == Page::KeyNetwork);
    press_key(keypad, LV_KEY_ENTER);
    CHECK(type_secret(keypad, public_encrypted) && type_secret(keypad, "p"));
    CHECK(current_page == Page::KeyWorking && !setup_key.input[0] && !setup_key.password[0] && !text_input.size());
    if (action == 0) press_key(keypad, LV_KEY_ESC);
    if (action == 1) wallet_ui_set_authenticated(false);
    if (action == 3) {
      CHECK(wallet_worker_wait(0)); // Result ready, UI has not collected it yet.
      wallet_ui_set_authenticated(false);
    }
    wallet_ui_service();
    if (action == 2) {
      CHECK(current_page == Page::KeyResult && setup_key.result.address[0]);
      press_key(keypad, LV_KEY_ESC);
    }
    CHECK(!setup_key.result.address[0] && backup_reads == (action < 2 ? 0U : action - 1));
  }
  wallet_ui_set_authenticated(true);
  open_page(Page::CreateKey);
  press_key(keypad, LV_KEY_ENTER);
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::KeyEntry && setup_key.network == BitcoinKeyNetwork::Testnet);
  CHECK(type_secret(keypad, (std::string(63, '0') + '1').c_str()) && current_page == Page::KeyCompression);
  press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(!setup_key.compressed && type_secret(keypad, "p") && type_secret(keypad, "x"));
  CHECK(current_page == Page::KeyRepeat && type_key(keypad, tr("Del", "删除")) && type_secret(keypad, "p"));
  wallet_ui_service();
  CHECK(current_page == Page::KeyResult && !strcmp(setup_key.result.encrypted, public_encrypted));
  lv_obj_update_layout(screen_content);
  for (unsigned i = 0; i < 32 && lv_obj_get_scroll_bottom(screen_content) > 0; ++i) press_key(keypad, LV_KEY_NEXT);
  press_key(keypad, LV_KEY_ENTER);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::KeyVerify && type_secret(keypad, public_encrypted));
  CHECK(current_page == Page::Home && !setup_key.result.encrypted[0] && imports == 1);
  open_page(Page::NfcImport);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::TagWait && tag_status == NfcBackupStatus::Pending);
  wallet_ui_set_authenticated(false);
  CHECK(tag_status == NfcBackupStatus::Idle && current_page == Page::Home);
  wallet_ui_set_authenticated(true);
  open_page(Page::NfcImport);
  press_key(keypad, LV_KEY_ENTER);
  tag_status = NfcBackupStatus::Complete;
  wallet_ui_service();
  CHECK(current_page == Page::KeyNetwork && setup_key.operation == BackupOperation::Decrypt);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(current_page == Page::KeyPass && type_secret(keypad, "p"));
  wallet_ui_service();
  CHECK(current_page == Page::KeyResult && setup_key.result.address[0]);
  for (unsigned count = 15; count <= 24; count += 3) {
    open_page(Page::CreateWords);
    press_key(keypad, LV_KEY_ENTER);
    if (count < 24) for (unsigned i = 0; i <= (count - 12) / 3; ++i) press_key(keypad, LV_KEY_NEXT);
    press_key(keypad, LV_KEY_ENTER);
    auto phrase = fixture_phrase(count);
    CHECK(current_page == Page::WordsBackup && setup_words.count == count && phrase == setup_words.words);
    lv_obj_update_layout(screen_content);
    for (unsigned i = 0; i < 32 && lv_obj_get_scroll_bottom(screen_content) > 0; ++i) press_key(keypad, LV_KEY_NEXT);
    press_key(keypad, LV_KEY_ENTER);
    press_key(keypad, LV_KEY_ENTER);
    CHECK(current_page == Page::WordsConfirm && type_secret(keypad, phrase.c_str()));
    press_key(keypad, LV_KEY_NEXT);
    press_key(keypad, LV_KEY_ENTER);
    press_key(keypad, LV_KEY_NEXT);
    const unsigned before = imports;
    test_committed = false;
    press_key(keypad, LV_KEY_ENTER, true);
    CHECK(imports == before && current_page == Page::Enroll);
    test_committed = true;
    press_key(keypad, LV_KEY_ENTER, true);
    CHECK(imports == before + 1 && current_page == Page::Home && !setup_words.words[0]);
  }
  for (unsigned count = 12; count <= 24; count += 3) {
    open_page(Page::RecoverWords);
    press_key(keypad, LV_KEY_ENTER);
    CHECK(type_secret(keypad, fixture_phrase(count).c_str()));
    press_key(keypad, LV_KEY_NEXT);
    press_key(keypad, LV_KEY_ENTER);
    press_key(keypad, LV_KEY_NEXT);
    const auto before_restore = imports;
    press_key(keypad, LV_KEY_ENTER, true);
    CHECK(imports == before_restore + 1 && !setup_words.words[0] && current_page == Page::Home);
  }
  test_blocker = CustodyBlocker::BackendMissing;
  wallet_ui_set_authenticated(false);

  // Multiple visible icons must own different buffers and retain their pixels
  // after the following rows are created and a page is repeatedly rebuilt.
  for (unsigned iteration = 0; iteration < 16; ++iteration) {
    open_page(Page::Catalog);
    auto *btc = lv_obj_get_child(lv_obj_get_child(screen_content, 0), 0);
    auto *eth = lv_obj_get_child(lv_obj_get_child(screen_content, 1), 0);
    CHECK(lv_obj_check_type(btc, &lv_canvas_class) && lv_obj_check_type(eth, &lv_canvas_class));
    auto *btc_buf = lv_canvas_get_draw_buf(btc);
    auto *eth_buf = lv_canvas_get_draw_buf(eth);
    CHECK(btc_buf != eth_buf && btc_buf->data != eth_buf->data);
    CHECK(!memcmp(btc_buf->data + 8, coin_icon_find("BTC")->pixels, kCoinIconBytes));
    CHECK(!memcmp(eth_buf->data + 8, coin_icon_find("ETH")->pixels, kCoinIconBytes));
  }
  open_page(Page::Home);

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
  open_page(Page::Companion);
  lv_obj_update_layout(screen_content);
  CHECK(companion_canvas && companion_stage);
  lv_area_t stage, center, right, left;
  lv_obj_get_coords(companion_stage, &stage);
  lv_obj_get_coords(companion_canvas, &center);
  MascotSnapshot roaming{};
  roaming.mood = MascotMood::Calm;
  test_now += 2 * kMascotAnimationMs;
  render_companion(roaming);
  lv_obj_update_layout(screen_content);
  lv_obj_get_coords(companion_canvas, &right);
  test_now += 4 * kMascotAnimationMs;
  render_companion(roaming);
  lv_obj_update_layout(screen_content);
  lv_obj_get_coords(companion_canvas, &left);
  CHECK(left.x1 >= stage.x1 && right.x2 <= stage.x2 && left.x1 < center.x1 && center.x1 < right.x1);
  roaming.mood = MascotMood::Sleep;
  render_companion(roaming);
  lv_obj_update_layout(screen_content);
  lv_area_t resting;
  lv_obj_get_coords(companion_canvas, &resting);
  CHECK(resting.x1 == center.x1);
  for (const uint16_t width : {176, 170, 240}) {
    panel_width = width;
    panel_height = width == 176 ? 192 : 320;
    lv_display_set_resolution(display, panel_width, panel_height);
    CHECK(wallet_ui_init());
    CHECK(wallet_ui_show_address("ETH", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "m/44'/60'/0'/0/1"));
    lv_obj_update_layout(screen_content);
    auto row = lv_obj_get_child(screen_content, 0);
    auto canvas = lv_obj_get_child(lv_obj_get_child(row, 0), 0);
    CHECK(canvas && lv_obj_check_type(canvas, &lv_canvas_class));
    lv_area_t before, after, details;
    lv_obj_get_coords(canvas, &before);
    lv_obj_get_coords(reader_target, &details);
    CHECK(before.y1 >= 0 && before.y2 < details.y1 && before.x1 >= 0 && before.x2 < panel_width);
    CHECK(details.y2 < panel_height && details.y2 - details.y1 >= 50);
    lv_obj_scroll_to_y(reader_target, LV_COORD_MAX, LV_ANIM_OFF);
    lv_obj_update_layout(screen_content);
    lv_obj_get_coords(canvas, &after);
    CHECK(!memcmp(&before, &after, sizeof(before)) && lv_obj_get_scroll_y(screen_content) == 0);
    CHECK(!wallet_ui_show_address("ETH", "", "m/44'/60'/0'/0/1"));
    open_page(Page::Search);
    CHECK(input_matrix && lv_obj_get_child_count(screen_content) > 0);
    auto toolbar = lv_obj_get_child(screen_content, 0);
    auto cancel = lv_obj_get_child(toolbar, -1);
    CHECK(cancel && lv_obj_check_type(cancel, &lv_button_class));
    lv_obj_send_event(cancel, LV_EVENT_CLICKED, nullptr);
    CHECK(current_page == Page::Catalog && !input_matrix);
    open_page(Page::Companion);
    lv_obj_update_layout(screen_content);
    auto actions = lv_obj_get_child(screen_content, -1);
    auto back = lv_obj_get_child(actions, -1);
    lv_area_t controls;
    lv_obj_get_coords(actions, &controls);
    CHECK(controls.x1 >= 64 && controls.x2 < panel_width && lv_obj_check_type(back, &lv_button_class));
    lv_obj_send_event(back, LV_EVENT_CLICKED, nullptr);
    CHECK(current_page == Page::Home);
  }
  panel_width = 296;
  panel_height = 128;
  lv_display_set_resolution(display, panel_width, panel_height);
  CHECK(wallet_ui_init());
  wallet_ui_set_authenticated(true);
  open_page(Page::RecoverKey);
  press_key(keypad, LV_KEY_ENTER);
  press_key(keypad, LV_KEY_ENTER);
  CHECK(type_secret(keypad, public_encrypted) && type_secret(keypad, "p"));
  CHECK(current_page == Page::KeyWorking && wallet_worker_wait(0));
  test_display_operational = false;
  wallet_ui_service();
  const BitcoinBackupResult empty_result{};
  CHECK(!memcmp(&setup_key.result, &empty_result, sizeof(empty_result)) && !text_input.size());
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
