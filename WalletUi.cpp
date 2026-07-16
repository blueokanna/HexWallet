#include "WalletUi.h"

#include <stdio.h>
#include <string.h>

#include "WalletCatalog.h"

#if HEXWALLET_ENABLE_LVGL
#include <lvgl.h>
#endif

namespace hexwallet {
namespace {
#if HEXWALLET_ENABLE_LVGL

bool initialized = false;
bool session_authenticated = false;
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
  if (!wallet_catalog_at(index, &entry) || status_label == nullptr) return;
  char status[160];
  snprintf(status, sizeof(status), "%s | SLIP-0044 %lu | %s", entry.name,
           static_cast<unsigned long>(entry.slip44_coin_type), entry.status);
  lv_label_set_text(status_label, status);
}

void populate_catalog(const char *query) {
  if (coin_list == nullptr) return;
  lv_obj_clean(coin_list);
  size_t matches = 0;
  for (size_t index = 0; index < wallet_catalog_count(); ++index) {
    WalletCatalogEntry entry;
    if (!wallet_catalog_at(index, &entry) || !wallet_catalog_matches(entry, query)) continue;
    char row[128];
    const bool signs = wallet_catalog_has(entry, WalletCapabilitySigning);
    const bool addresses = wallet_catalog_has(entry, WalletCapabilityAddress);
    snprintf(row, sizeof(row), "%s  %s  %s", entry.symbol, entry.name,
             signs ? "ADDRESS + SIGN" : (addresses ? "ADDRESS" : "UNSUPPORTED"));
    lv_obj_t *button = lv_list_add_button(coin_list, nullptr, row);
    lv_obj_set_height(button, 42);
    lv_obj_set_style_radius(button, 4, 0);
    lv_obj_add_event_cb(button, coin_clicked, LV_EVENT_CLICKED, reinterpret_cast<void *>(index));
    ++matches;
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
  lv_obj_set_height(search_field, 44);
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
  lv_obj_set_height(keyboard, 150);
  lv_obj_add_flag(keyboard, LV_OBJ_FLAG_HIDDEN);
  populate_catalog("");
}

#endif
}

bool wallet_ui_init() {
#if !HEXWALLET_ENABLE_LVGL
  return false;
#else
  lv_obj_t *screen = lv_screen_active();
  if (screen == nullptr) return false;
  lv_obj_clean(screen);
  lv_obj_set_style_bg_color(screen, lv_color_hex(0xf4f5f2), 0);
  lv_obj_set_style_text_color(screen, lv_color_hex(0x161916), 0);
  lv_obj_set_style_pad_all(screen, 12, 0);
  lv_obj_set_style_pad_row(screen, 10, 0);
  lv_obj_set_flex_flow(screen, LV_FLEX_FLOW_COLUMN);

  lv_obj_t *header = lv_obj_create(screen);
  lv_obj_set_size(header, LV_PCT(100), LV_SIZE_CONTENT);
  set_clean_container(header);
  lv_obj_set_flex_flow(header, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(header, LV_FLEX_ALIGN_SPACE_BETWEEN,
                       LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  lv_obj_t *title = lv_label_create(header);
  lv_label_set_text(title, "HEX WALLET");

  state_label = lv_label_create(header);
  lv_obj_set_style_pad_hor(state_label, 8, 0);
  lv_obj_set_style_pad_ver(state_label, 4, 0);
  lv_obj_set_style_radius(state_label, 4, 0);

  screen_content = lv_obj_create(screen);
  lv_obj_set_width(screen_content, LV_PCT(100));
  lv_obj_set_flex_grow(screen_content, 1);
  set_clean_container(screen_content);

  status_label = lv_label_create(screen);
  lv_label_set_long_mode(status_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(status_label, LV_PCT(100));
  lv_obj_set_style_text_color(status_label, lv_color_hex(0x48514a), 0);

  initialized = true;
  wallet_ui_show_catalog();
  wallet_ui_set_authenticated(false);
  return true;
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
  lv_obj_set_style_bg_color(state_label,
                            lv_color_hex(authenticated ? 0xd9eadb : 0xf0d8d5), 0);
  lv_obj_set_style_text_color(state_label,
                              lv_color_hex(authenticated ? 0x155b2a : 0x8a241e), 0);
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

void wallet_ui_show_catalog() {
#if HEXWALLET_ENABLE_LVGL
  if (!initialized) return;
  create_catalog_view();
  wallet_ui_set_status(session_authenticated ? "Authenticated session active" : "Authentication required");
#endif
}

void wallet_ui_show_transaction(const WalletUiTransactionReview &review) {
#if HEXWALLET_ENABLE_LVGL
  if (!initialized || screen_content == nullptr || review.approval_code == nullptr) return;
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
  lv_obj_set_style_text_color(title, lv_color_hex(0x155b2a), 0);

  for (size_t index = 0; index < review.output_count; ++index) {
    const WalletUiTransactionOutput &output = review.outputs[index];
    snprintf(line, sizeof(line), "%u  %llu sat\n%s\n%s", static_cast<unsigned>(index + 1),
             static_cast<unsigned long long>(output.value), output.address, output.ownership);
    lv_obj_t *label = lv_label_create(screen_content);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, LV_PCT(100));
    lv_label_set_text(label, line);
  }
  snprintf(line, sizeof(line), "FEE  %llu sat  |  %llu sat/vB",
           static_cast<unsigned long long>(review.fee),
           static_cast<unsigned long long>(review.fee_rate));
  lv_obj_t *fee = lv_label_create(screen_content);
  lv_label_set_text(fee, line);
  lv_obj_set_style_text_color(fee, lv_color_hex(0x8a241e), 0);

  snprintf(line, sizeof(line), "CONFIRM  %s", review.approval_code);
  lv_obj_t *confirmation = lv_label_create(screen_content);
  lv_label_set_text(confirmation, line);
  lv_obj_set_style_text_color(confirmation, lv_color_hex(0x161916), 0);
  wallet_ui_set_status("Transaction review active");
#else
  (void)review;
#endif
}

void wallet_ui_service() {
#if HEXWALLET_ENABLE_LVGL
  if (initialized) lv_timer_handler();
#endif
}

}
