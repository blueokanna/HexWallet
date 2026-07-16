#include "WalletUi.h"

#if HEXWALLET_ENABLE_LVGL
#include <lvgl.h>
#endif

namespace hexwallet {

#if HEXWALLET_ENABLE_LVGL
namespace {

lv_obj_t *status_label = nullptr;

void set_status(const char *text) {
  if (status_label != nullptr) {
    lv_label_set_text(status_label, text);
  }
}

void on_receive(lv_event_t *event) {
  if (lv_event_get_code(event) == LV_EVENT_CLICKED) {
    set_status("Connect a reviewed companion request");
  }
}

void on_settings(lv_event_t *event) {
  if (lv_event_get_code(event) == LV_EVENT_CLICKED) {
    set_status("Device is locked. Unlock before settings.");
  }
}

lv_obj_t *make_action(lv_obj_t *parent, const char *label, lv_event_cb_t callback) {
  lv_obj_t *button = lv_button_create(parent);
  lv_obj_set_width(button, LV_PCT(100));
  lv_obj_set_height(button, LV_SIZE_CONTENT);
  lv_obj_set_style_radius(button, 4, 0);
  lv_obj_set_style_pad_ver(button, 12, 0);
  lv_obj_add_event_cb(button, callback, LV_EVENT_CLICKED, nullptr);
  lv_obj_t *text = lv_label_create(button);
  lv_label_set_text(text, label);
  lv_obj_center(text);
  return button;
}

}  // namespace
#endif

bool wallet_ui_init() {
#if !HEXWALLET_ENABLE_LVGL
  return false;
#else
  lv_obj_t *screen = lv_scr_act();
  lv_obj_clean(screen);
  lv_obj_set_style_bg_color(screen, lv_color_white(), 0);
  lv_obj_set_style_text_color(screen, lv_color_black(), 0);
  lv_obj_set_style_pad_all(screen, 14, 0);

  lv_obj_t *content = lv_obj_create(screen);
  lv_obj_set_size(content, LV_PCT(100), LV_PCT(100));
  lv_obj_center(content);
  lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(content, 0, 0);
  lv_obj_set_style_pad_all(content, 0, 0);
  lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  lv_obj_t *title = lv_label_create(content);
  lv_label_set_text(title, "HEX WALLET");

  lv_obj_t *state = lv_label_create(content);
  lv_label_set_text(state, "LOCKED");

  status_label = lv_label_create(content);
  lv_label_set_long_mode(status_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(status_label, LV_PCT(100));
  lv_obj_set_style_text_align(status_label, LV_TEXT_ALIGN_CENTER, 0);
  set_status("Keys remain offline");

  lv_obj_t *actions = lv_obj_create(content);
  lv_obj_set_width(actions, LV_PCT(100));
  lv_obj_set_height(actions, LV_SIZE_CONTENT);
  lv_obj_set_style_bg_opa(actions, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(actions, 0, 0);
  lv_obj_set_style_pad_all(actions, 0, 0);
  lv_obj_set_style_pad_row(actions, 8, 0);
  lv_obj_set_flex_flow(actions, LV_FLEX_FLOW_COLUMN);
  make_action(actions, "Receive", on_receive);
  make_action(actions, "Settings", on_settings);
  return true;
#endif
}

void wallet_ui_show_port_error() {
#if HEXWALLET_ENABLE_LVGL
  lv_obj_t *screen = lv_scr_act();
  lv_obj_clean(screen);
  lv_obj_set_style_bg_color(screen, lv_color_white(), 0);
  lv_obj_t *message = lv_label_create(screen);
  lv_label_set_text(message, "Display port unavailable");
  lv_obj_center(message);
#endif
}

void wallet_ui_service() {
#if HEXWALLET_ENABLE_LVGL
  lv_timer_handler();
#endif
}

}  // namespace hexwallet
