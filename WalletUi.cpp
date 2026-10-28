#include "WalletUi.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "WalletBoardPort.h"
#include "WalletCatalog.h"

#if HEXWALLET_ENABLE_LVGL
#include <lvgl.h>
#endif

namespace hexwallet {
namespace {
#if HEXWALLET_ENABLE_LVGL

bool initialized = false;
bool session_authenticated = false;
bool eink_panel = false;
uint8_t eink_colors = 1;
unsigned long last_service_ms = 0;
WalletUiDecisionCallback decision_callback = nullptr;
bool decision_pending = false;
bool decision_value = false;

void approve_event(lv_event_t *) {
  if (decision_callback != nullptr && board_display_review_ready()) {
    decision_value = true;
    decision_pending = true;
  }
}

void reject_event(lv_event_t *) {
  if (decision_callback != nullptr) {
    decision_value = false;
    decision_pending = true;
  }
}

// Resolution-adaptive scale factor. The UI is laid out against a 240px-wide
// reference; every fixed dimension goes through sc() so a 170px or 176px
// panel shrinks widgets proportionally instead of clipping them.
static float ui_scale() {
  const uint16_t w = board_display_width();
  const uint16_t h = board_display_height();
  const uint16_t min_side = (w < h) ? w : h;
  if (min_side == 0) return 1.0f;
  float s = static_cast<float>(min_side) / 240.0f;
  // A 128 px-wide EPD is a real target; do not clamp it back up to 0.55 or
  // fixed paddings will push the address/keyboard columns off-screen.
  if (s < 0.45f) s = 0.45f;
  if (s > 1.25f) s = 1.25f;
  return s;
}

static const lv_font_t *ui_font() {
  const uint16_t w = board_display_width();
  const uint16_t h = board_display_height();
  const uint16_t min_side = (w < h) ? w : h;
  return min_side > 0 && min_side <= 160 ? &lv_font_montserrat_12
                                         : &lv_font_montserrat_14;
}

static int sc(int value) {
  const int scaled = static_cast<int>(static_cast<float>(value) * ui_scale());
  return scaled < 1 ? 1 : scaled;
}

static lv_color_t theme_fg() { return lv_color_hex(eink_panel ? 0x000000 : 0x161916); }
static lv_color_t theme_bg() { return lv_color_hex(eink_panel ? 0xffffff : 0xf4f5f2); }
static lv_color_t theme_accent() {
  if (!eink_panel) return lv_color_hex(0x155b2a);
  if (eink_colors >= 3) return lv_color_hex(0xa00000);  // red is in every colour panel
  return lv_color_hex(0x000000);
}
static lv_color_t theme_warn() {
  if (!eink_panel) return lv_color_hex(0x8a241e);
  if (eink_colors >= 4) return lv_color_hex(0x8a6d00);  // yellow, not a dithered red
  if (eink_colors == 3) return lv_color_hex(0x000000);
  return lv_color_hex(0x000000);
}
static lv_color_t theme_badge_on() { return lv_color_hex(eink_panel ? 0xffffff : 0xd9eadb); }
static lv_color_t theme_badge_off() { return lv_color_hex(eink_panel ? 0xffffff : 0xf0d8d5); }
lv_obj_t *screen_content = nullptr;
lv_obj_t *state_label = nullptr;
lv_obj_t *status_label = nullptr;
lv_obj_t *search_field = nullptr;
lv_obj_t *coin_list = nullptr;
lv_obj_t *keyboard = nullptr;

void set_clean_container(lv_obj_t *object) {
  lv_obj_set_style_bg_opa(object, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(object, 0, 0);
  lv_obj_set_style_pad_all(object, 0, 0);
}

void coin_clicked(lv_event_t *event) {
  const size_t index = reinterpret_cast<size_t>(lv_event_get_user_data(event));
  WalletCatalogEntry entry;
  if (!wallet_catalog_at_sorted(index, &entry) || status_label == nullptr) return;
  // Never truncate the limitations at the end of a capability description.
  lv_label_set_text_fmt(status_label, "%s\n%s", entry.name, entry.status);
}

void populate_catalog(const char *query) {
  if (coin_list == nullptr) return;
  lv_obj_clean(coin_list);
  size_t matches = 0;
  for (size_t index = 0; index < wallet_catalog_count(); ++index) {
    WalletCatalogEntry entry;
    if (!wallet_catalog_at_sorted(index, &entry) || !wallet_catalog_matches(entry, query)) continue;
    char row[128];
    const bool signs = wallet_catalog_has(entry, WalletCapabilitySigning);
    const bool addresses = wallet_catalog_has(entry, WalletCapabilityAddress);
    const bool tokens = wallet_catalog_has(entry, WalletCapabilityTokenAccount);
    snprintf(row, sizeof(row), "%s  %s\n%s", entry.symbol, entry.name,
             signs ? (addresses ? "ADDRESS + SIGN" : "ACCOUNT SIGNING") : (tokens ? "ADDRESS + TOKENS" :
             (addresses ? "ADDRESS" : "UNSUPPORTED")));
    lv_obj_t *button = lv_list_add_button(coin_list, nullptr, row);
    lv_obj_set_height(button, LV_SIZE_CONTENT);
    lv_obj_set_style_pad_ver(button, sc(10), 0);
    lv_obj_set_style_radius(button, sc(8), 0);
    lv_obj_t *label = lv_obj_get_child(button, 0);
    if (label != nullptr) {
      lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(label, LV_PCT(100));
    }
    lv_obj_set_style_text_color(button, theme_fg(), 0);
    lv_obj_add_event_cb(button, coin_clicked, LV_EVENT_CLICKED, reinterpret_cast<void *>(index));
    ++matches;
    if (*query == '\0' && matches >= 40) {
      lv_list_add_text(coin_list, "TYPE TO NARROW");
      break;
    }
  }
  if (matches == 0) lv_list_add_text(coin_list, "NO MATCHES");
}

void search_event(lv_event_t *event) {
  const lv_event_code_t code = lv_event_get_code(event);
  if (code == LV_EVENT_VALUE_CHANGED) {
    populate_catalog(lv_textarea_get_text(search_field));
  } else if (code == LV_EVENT_FOCUSED && keyboard != nullptr) {
    lv_keyboard_set_textarea(keyboard, search_field);
    lv_obj_remove_flag(keyboard, LV_OBJ_FLAG_HIDDEN);
  } else if (code == LV_EVENT_DEFOCUSED && keyboard != nullptr) {
    lv_obj_add_flag(keyboard, LV_OBJ_FLAG_HIDDEN);
  }
}

void create_catalog_view() {
  if (screen_content == nullptr) return;
  lv_obj_clean(screen_content);
  lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(screen_content, 8, 0);

  search_field = lv_textarea_create(screen_content);
  lv_obj_set_width(search_field, LV_PCT(100));
  lv_obj_set_height(search_field, sc(44));
  lv_textarea_set_one_line(search_field, true);
  lv_textarea_set_max_length(search_field, 32);
  lv_textarea_set_placeholder_text(search_field, "Search symbol or network");
  lv_obj_set_style_radius(search_field, 4, 0);
  lv_obj_add_event_cb(search_field, search_event, LV_EVENT_ALL, nullptr);

  coin_list = lv_list_create(screen_content);
  lv_obj_set_width(coin_list, LV_PCT(100));
  lv_obj_set_flex_grow(coin_list, 1);
  lv_obj_set_style_radius(coin_list, 4, 0);
  lv_obj_set_scrollbar_mode(coin_list, LV_SCROLLBAR_MODE_AUTO);

  keyboard = lv_keyboard_create(screen_content);
  lv_obj_set_width(keyboard, LV_PCT(100));
  lv_obj_set_height(keyboard, sc(150));
  lv_obj_add_flag(keyboard, LV_OBJ_FLAG_HIDDEN);
  populate_catalog("");
}

#endif
}

bool wallet_ui_init() {
#if !HEXWALLET_ENABLE_LVGL
  return false;
#else
  eink_panel = board_is_eink();
  eink_colors = board_display_colors();
  const lv_color_t fg = theme_fg();
  const lv_color_t bg = theme_bg();
  lv_obj_t *screen = lv_screen_active();
  if (screen == nullptr) return false;
  lv_obj_clean(screen);
  lv_obj_set_style_bg_color(screen, bg, 0);
  lv_obj_set_style_text_color(screen, fg, 0);
  lv_obj_set_style_text_font(screen, ui_font(), 0);
  lv_obj_set_style_pad_all(screen, sc(12), 0);
  lv_obj_set_style_pad_row(screen, sc(10), 0);
  lv_obj_set_flex_flow(screen, LV_FLEX_FLOW_COLUMN);

  lv_obj_t *header = lv_obj_create(screen);
  lv_obj_set_size(header, LV_PCT(100), LV_SIZE_CONTENT);
  set_clean_container(header);
  lv_obj_set_flex_flow(header, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(header, LV_FLEX_ALIGN_SPACE_BETWEEN,
                       LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  lv_obj_t *title = lv_label_create(header);
  lv_label_set_text(title, "HEX WALLET");
  lv_obj_set_style_text_color(title, fg, 0);

  state_label = lv_label_create(header);
  lv_obj_set_style_pad_hor(state_label, sc(8), 0);
  lv_obj_set_style_pad_ver(state_label, sc(4), 0);
  lv_obj_set_style_radius(state_label, 4, 0);

  screen_content = lv_obj_create(screen);
  lv_obj_set_width(screen_content, LV_PCT(100));
  lv_obj_set_flex_grow(screen_content, 1);
  set_clean_container(screen_content);

  status_label = lv_label_create(screen);
  lv_label_set_long_mode(status_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(status_label, LV_PCT(100));
  lv_obj_set_style_text_color(status_label, theme_warn(), 0);

  initialized = true;
  last_service_ms = 0;
  wallet_ui_show_catalog();
  wallet_ui_set_authenticated(false);
  return true;
#endif
}

bool wallet_ui_ready() {
#if HEXWALLET_ENABLE_LVGL
  return initialized;
#else
  return false;
#endif
}

void wallet_ui_show_port_error() {
#if HEXWALLET_ENABLE_LVGL
  lv_obj_t *screen = lv_screen_active();
  if (screen == nullptr) return;
  lv_obj_clean(screen);
  lv_obj_set_style_bg_color(screen, lv_color_white(), 0);
  lv_obj_t *message = lv_label_create(screen);
  lv_label_set_text(message, "DISPLAY PORT ERROR");
  lv_obj_center(message);
#endif
}

void wallet_ui_set_authenticated(bool authenticated) {
#if HEXWALLET_ENABLE_LVGL
  session_authenticated = authenticated;
  if (!initialized || state_label == nullptr) return;
  lv_label_set_text(state_label, authenticated ? "UNLOCKED" : "LOCKED");
  lv_obj_set_style_bg_color(state_label, authenticated ? theme_badge_on() : theme_badge_off(), 0);
  lv_obj_set_style_text_color(state_label, authenticated ? theme_accent() : theme_warn(), 0);
  wallet_ui_set_status(authenticated ? "Authenticated session active" : "Authentication required");
#else
  (void)authenticated;
#endif
}

void wallet_ui_set_status(const char *status) {
#if HEXWALLET_ENABLE_LVGL
  if (initialized && status_label != nullptr && status != nullptr) lv_label_set_text(status_label, status);
#else
  (void)status;
#endif
}

// Long field-arithmetic steps (Bulletproofs+ verification takes seconds on the
// MCU) run on the same task as the UI, so the panel would otherwise keep the
// previous screen until they finish. Flush the status line first.
void wallet_ui_show_busy(const char *status) {
#if HEXWALLET_ENABLE_LVGL
  if (!initialized) return;
  wallet_ui_set_status(status);
  for (int pass = 0; pass < 4; ++pass) {
    lv_timer_handler();
    delay(4);
  }
#else
  (void)status;
#endif
}

void wallet_ui_set_decision_callback(WalletUiDecisionCallback callback) {
#if HEXWALLET_ENABLE_LVGL
  decision_callback = callback;
  decision_pending = false;
#else
  (void)callback;
#endif
}

void wallet_ui_show_catalog() {
#if HEXWALLET_ENABLE_LVGL
  if (!initialized) return;
  create_catalog_view();
  wallet_ui_set_status(session_authenticated ? "Authenticated session active" : "Authentication required");
#endif
}

bool wallet_ui_show_address(const char *network, const char *address,
                            const char *path) {
#if HEXWALLET_ENABLE_LVGL
  if (!initialized || screen_content == nullptr || !board_has_display() ||
      network == nullptr || address == nullptr || path == nullptr) return false;
  decision_callback = nullptr;
  decision_pending = false;
  board_display_prepare_review();
  lv_obj_clean(screen_content);
  search_field = nullptr;
  coin_list = nullptr;
  keyboard = nullptr;
  lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(screen_content, sc(10), 0);
  lv_obj_set_scrollbar_mode(screen_content, LV_SCROLLBAR_MODE_AUTO);
  const char *fields[] = {"RECEIVE ADDRESS", network, address, path,
      "Compare the entire address with your sending wallet before receiving funds."};
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    lv_obj_t *label = lv_label_create(screen_content);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, LV_PCT(100));
    lv_label_set_text(label, fields[i]);
    if (i == 0 || i == 1) lv_obj_set_style_text_color(label, theme_accent(), 0);
    if (i == 2) {
      // A distinct, full-width address block: no ellipsis or horizontal scroll.
      lv_obj_set_style_border_width(label, 1, 0);
      lv_obj_set_style_border_color(label, theme_accent(), 0);
      lv_obj_set_style_radius(label, sc(8), 0);
      lv_obj_set_style_pad_all(label, sc(10), 0);
    }
  }
  wallet_ui_set_status("Verify receive address on this device");
  return true;
#else
  (void)network; (void)address; (void)path;
  return false;
#endif
}

void wallet_ui_show_transaction(const WalletUiTransactionReview &review) {
#if HEXWALLET_ENABLE_LVGL
  if (!initialized || screen_content == nullptr ||
      (review.approval_code == nullptr && !review.show_decision_buttons)) {
    return;
  }
  if (!review.show_decision_buttons) decision_callback = nullptr;
  decision_pending = false;
  board_display_prepare_review();
  lv_obj_clean(screen_content);
  search_field = nullptr;
  coin_list = nullptr;
  keyboard = nullptr;
  lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(screen_content, 6, 0);
  lv_obj_set_scrollbar_mode(screen_content, LV_SCROLLBAR_MODE_AUTO);

  lv_obj_t *title = lv_label_create(screen_content);
  char line[192];
  snprintf(line, sizeof(line), "%s TRANSACTION", review.network == nullptr ? "" : review.network);
  lv_label_set_text(title, line);
  lv_obj_set_style_text_color(title, theme_accent(), 0);

  for (size_t index = 0; index < review.output_count; ++index) {
    const WalletUiTransactionOutput &output = review.outputs[index];
    if (output.amount_text != nullptr) {
      snprintf(line, sizeof(line), "%u  %s", static_cast<unsigned>(index + 1),
               output.amount_text);
    } else {
      snprintf(line, sizeof(line), "%u  %llu sat", static_cast<unsigned>(index + 1),
               static_cast<unsigned long long>(output.value));
    }
    lv_obj_t *label = lv_label_create(screen_content);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, LV_PCT(100));
    lv_label_set_text(label, line);
    // Addresses must never share a bounded summary buffer with amounts or
    // ownership text: a long amount could otherwise truncate the destination.
    const char *fields[] = {output.address, output.ownership};
    for (const char *text : fields) {
      if (text == nullptr) continue;
      lv_obj_t *field = lv_label_create(screen_content);
      lv_label_set_long_mode(field, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(field, LV_PCT(100));
      lv_label_set_text(field, text);
    }
    if (output.details != nullptr) {
      lv_obj_t *details = lv_label_create(screen_content);
      lv_label_set_long_mode(details, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(details, LV_PCT(100));
      lv_label_set_text(details, output.details);
    }
  }
  if (review.fee_text != nullptr) {
    snprintf(line, sizeof(line), "%s  %s", review.fee_label == nullptr ? "MAX FEE" : review.fee_label, review.fee_text);
  } else {
    snprintf(line, sizeof(line), "FEE  %llu sat  |  %llu sat/vB",
             static_cast<unsigned long long>(review.fee),
             static_cast<unsigned long long>(review.fee_rate));
  }
  lv_obj_t *fee = lv_label_create(screen_content);
  lv_label_set_long_mode(fee, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(fee, LV_PCT(100));
  lv_label_set_text(fee, line);
  lv_obj_set_style_text_color(fee, theme_warn(), 0);

  if (review.total_text != nullptr) {
    snprintf(line, sizeof(line), "TOTAL  %s", review.total_text);
    lv_obj_t *total = lv_label_create(screen_content);
    lv_label_set_long_mode(total, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(total, LV_PCT(100));
    lv_label_set_text(total, line);
  }
  if (review.note != nullptr) {
    lv_obj_t *note = lv_label_create(screen_content);
    lv_label_set_long_mode(note, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(note, LV_PCT(100));
    lv_label_set_text(note, review.note);
    lv_obj_set_style_text_color(note, theme_warn(), 0);
  }

  if (review.approval_code != nullptr) {
    snprintf(line, sizeof(line), "CONFIRM  %s", review.approval_code);
    lv_obj_t *confirmation = lv_label_create(screen_content);
    lv_label_set_text(confirmation, line);
    lv_obj_set_style_text_color(confirmation, theme_fg(), 0);
  }
  if (review.show_decision_buttons) {
    lv_obj_t *actions = lv_obj_create(screen_content);
    lv_obj_set_width(actions, LV_PCT(100));
    lv_obj_set_height(actions, sc(52));
    set_clean_container(actions);
    lv_obj_set_flex_flow(actions, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(actions, LV_FLEX_ALIGN_SPACE_EVENLY,
                         LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(actions, sc(8), 0);

    lv_obj_t *reject = lv_button_create(actions);
    lv_obj_set_height(reject, sc(44));
    lv_obj_set_flex_grow(reject, 1);
    lv_obj_set_style_bg_color(reject, theme_warn(), 0);
    lv_obj_add_event_cb(reject, reject_event, LV_EVENT_CLICKED, nullptr);
    lv_obj_t *reject_label = lv_label_create(reject);
    lv_label_set_text(reject_label, "REJECT");
    lv_obj_center(reject_label);

    lv_obj_t *approve = lv_button_create(actions);
    lv_obj_set_height(approve, sc(44));
    lv_obj_set_flex_grow(approve, 1);
    lv_obj_set_style_bg_color(approve, theme_accent(), 0);
    lv_obj_add_event_cb(approve, approve_event, LV_EVENT_CLICKED, nullptr);
    lv_obj_t *approve_label = lv_label_create(approve);
    lv_label_set_text(approve_label, "APPROVE");
    lv_obj_center(approve_label);
  }
  wallet_ui_set_status("Transaction review active");
#else
  (void)review;
#endif
}

void wallet_ui_show_pairing(uint32_t code, const char *fingerprint) {
#if HEXWALLET_ENABLE_LVGL
  if (!initialized || screen_content == nullptr) return;
  decision_pending = false;
  board_display_prepare_review();
  lv_obj_clean(screen_content);
  search_field = nullptr;
  coin_list = nullptr;
  keyboard = nullptr;
  lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(screen_content, sc(10), 0);

  lv_obj_t *title = lv_label_create(screen_content);
  lv_label_set_text(title, "PAIR PHONE");
  lv_obj_set_style_text_color(title, theme_accent(), 0);

  char line[128];
  snprintf(line, sizeof(line), "CODE  %06lu",
           static_cast<unsigned long>(code % 1000000UL));
  lv_obj_t *code_label = lv_label_create(screen_content);
  lv_label_set_text(code_label, line);
  lv_obj_set_style_text_color(code_label, theme_fg(), 0);

  snprintf(line, sizeof(line), "PHONE %s", fingerprint == nullptr ? "?" : fingerprint);
  lv_obj_t *fingerprint_label = lv_label_create(screen_content);
  lv_label_set_long_mode(fingerprint_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(fingerprint_label, LV_PCT(100));
  lv_label_set_text(fingerprint_label, line);

  lv_obj_t *actions = lv_obj_create(screen_content);
  lv_obj_set_width(actions, LV_PCT(100));
  lv_obj_set_height(actions, sc(52));
  set_clean_container(actions);
  lv_obj_set_flex_flow(actions, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(actions, LV_FLEX_ALIGN_SPACE_EVENLY,
                       LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(actions, sc(8), 0);

  lv_obj_t *reject = lv_button_create(actions);
  lv_obj_set_height(reject, sc(44));
  lv_obj_set_flex_grow(reject, 1);
  lv_obj_set_style_bg_color(reject, theme_warn(), 0);
  lv_obj_add_event_cb(reject, reject_event, LV_EVENT_CLICKED, nullptr);
  lv_obj_t *reject_label = lv_label_create(reject);
  lv_label_set_text(reject_label, "REJECT");
  lv_obj_center(reject_label);

  lv_obj_t *approve = lv_button_create(actions);
  lv_obj_set_height(approve, sc(44));
  lv_obj_set_flex_grow(approve, 1);
  lv_obj_set_style_bg_color(approve, theme_accent(), 0);
  lv_obj_add_event_cb(approve, approve_event, LV_EVENT_CLICKED, nullptr);
  lv_obj_t *approve_label = lv_label_create(approve);
  lv_label_set_text(approve_label, "APPROVE");
  lv_obj_center(approve_label);
  wallet_ui_set_status("Confirm this phone on the trusted display");
#else
  (void)code;
  (void)fingerprint;
#endif
}

void wallet_ui_service() {
#if HEXWALLET_ENABLE_LVGL
  if (!initialized) return;
  if (decision_pending) {
    decision_pending = false;
    WalletUiDecisionCallback callback = decision_callback;
    const bool value = decision_value;
    if (callback != nullptr && (!value || board_display_review_ready())) callback(value);
  }
  const unsigned long now = millis();
  // Input/timer service stays responsive; the board owns slow EPD coalescing.
  if (last_service_ms != 0 && (now - last_service_ms) < 16UL) return;
  last_service_ms = now;
  board_display_service();
#endif
}

}
