// Minimal LVGL 9.5 API mock used ONLY as a fallback by the host-side
// board-port compile check (tests/host/board_port_compile_check.ps1) when the
// real LVGL tree is unavailable. The check PREFERS the real LVGL checkout
// (tests/host/lvgl_real or $env:HEXWALLET_LVGL_DIR); this file exists so the
// fallback surface matches the real 9.5 API (lv_display_t / lv_indev_t) and
// never drifts back to the removed lv_disp_drv_t / lv_indev_drv_t API.
#ifndef HEXWALLET_MOCK_LVGL_H
#define HEXWALLET_MOCK_LVGL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LV_COLOR_DEPTH 16
#define LV_COLOR_16_SWAP 1

typedef int16_t lv_coord_t;

typedef struct {
  uint8_t blue;
  uint8_t green;
  uint8_t red;
} lv_color_t;

typedef struct {
  lv_coord_t x1, y1, x2, y2;
} lv_area_t;

typedef struct {
  lv_coord_t x, y;
} lv_point_t;

typedef struct _lv_display_t {
  void *reserved;
} lv_display_t;

typedef struct _lv_indev_t {
  void *reserved;
} lv_indev_t;

// --- input device data (matches lv_indev.h) --------------------------------
typedef enum {
  LV_INDEV_STATE_RELEASED = 0,
  LV_INDEV_STATE_PRESSED,
} lv_indev_state_t;

typedef enum {
  LV_INDEV_TYPE_NONE,
  LV_INDEV_TYPE_POINTER,
  LV_INDEV_TYPE_KEYPAD,
  LV_INDEV_TYPE_BUTTON,
  LV_INDEV_TYPE_ENCODER,
} lv_indev_type_t;

typedef struct {
  lv_indev_state_t state;
  lv_point_t point;
  uint32_t key;
  uint32_t btn_id;
  int16_t enc_diff;
} lv_indev_data_t;

typedef void (*lv_display_flush_cb_t)(lv_display_t *disp, const lv_area_t *area,
                                      uint8_t *px_map);
typedef void (*lv_indev_read_cb_t)(lv_indev_t *indev, lv_indev_data_t *data);

// --- render modes (matches lv_display.h) -----------------------------------
typedef enum {
  LV_DISPLAY_RENDER_MODE_PARTIAL,
  LV_DISPLAY_RENDER_MODE_DIRECT,
  LV_DISPLAY_RENDER_MODE_FULL,
} lv_display_render_mode_t;

// --- widgets ---------------------------------------------------------------
typedef struct _lv_obj_t lv_obj_t;
typedef struct _lv_event_t lv_event_t;
typedef void (*lv_event_cb_t)(lv_event_t *e);

typedef enum {
  LV_EVENT_ALL = 0,
  LV_EVENT_CLICKED = 1,
  LV_EVENT_VALUE_CHANGED = 2,
  LV_EVENT_FOCUSED = 3,
  LV_EVENT_DEFOCUSED = 4,
} lv_event_code_t;

#define LV_SIZE_CONTENT 0
#define LV_PCT(x) (x)
#define LV_OPA_TRANSP 0

#define LV_FLEX_FLOW_COLUMN 0
#define LV_FLEX_FLOW_ROW 1
#define LV_FLEX_ALIGN_START 0
#define LV_FLEX_ALIGN_END 1
#define LV_FLEX_ALIGN_CENTER 2
#define LV_FLEX_ALIGN_SPACE_EVENLY 3
#define LV_FLEX_ALIGN_SPACE_AROUND 4
#define LV_FLEX_ALIGN_SPACE_BETWEEN 5

#define LV_OBJ_FLAG_HIDDEN (1UL << 6)
#define LV_SCROLLBAR_MODE_AUTO 1
#define LV_LABEL_LONG_WRAP 2

// --- API (declared only; the check is compile-only) ------------------------
lv_display_t *lv_display_create(int32_t hor_res, int32_t ver_res);
void lv_display_set_buffers(lv_display_t *disp, void *buf1, void *buf2,
                            uint32_t buf_size, lv_display_render_mode_t render_mode);
void lv_display_set_flush_cb(lv_display_t *disp, lv_display_flush_cb_t flush_cb);
void lv_display_set_antialiasing(lv_display_t *disp, bool en);
void lv_display_flush_ready(lv_display_t *disp);
bool lv_display_flush_is_last(lv_display_t *disp);

lv_indev_t *lv_indev_create(void);
void lv_indev_set_type(lv_indev_t *indev, lv_indev_type_t indev_type);
void lv_indev_set_read_cb(lv_indev_t *indev, lv_indev_read_cb_t read_cb);

void lv_timer_handler(void);

lv_obj_t *lv_screen_active(void);
lv_obj_t *lv_obj_create(lv_obj_t *parent);
void lv_obj_clean(lv_obj_t *obj);
void lv_obj_center(lv_obj_t *obj);
void lv_obj_set_size(lv_obj_t *obj, lv_coord_t w, lv_coord_t h);
void lv_obj_set_width(lv_obj_t *obj, lv_coord_t w);
void lv_obj_set_height(lv_obj_t *obj, lv_coord_t h);
void lv_obj_set_flex_grow(lv_obj_t *obj, uint8_t grow);
void lv_obj_set_flex_flow(lv_obj_t *obj, uint8_t flow);
void lv_obj_set_flex_align(lv_obj_t *obj, uint8_t main_place, uint8_t cross_place,
                           uint8_t track_cross_place);
void lv_obj_add_flag(lv_obj_t *obj, uint64_t flag);
void lv_obj_remove_flag(lv_obj_t *obj, uint64_t flag);
void lv_obj_add_event_cb(lv_obj_t *obj, lv_event_cb_t cb, lv_event_code_t filter,
                         void *user_data);
void lv_obj_set_style_radius(lv_obj_t *obj, lv_coord_t value, uint32_t selector);
void lv_obj_set_style_pad_all(lv_obj_t *obj, lv_coord_t value, uint32_t selector);
void lv_obj_set_style_pad_row(lv_obj_t *obj, lv_coord_t value, uint32_t selector);
void lv_obj_set_style_pad_hor(lv_obj_t *obj, lv_coord_t value, uint32_t selector);
void lv_obj_set_style_pad_ver(lv_obj_t *obj, lv_coord_t value, uint32_t selector);
void lv_obj_set_style_border_width(lv_obj_t *obj, lv_coord_t value, uint32_t selector);
void lv_obj_set_style_bg_opa(lv_obj_t *obj, uint8_t value, uint32_t selector);
void lv_obj_set_style_bg_color(lv_obj_t *obj, lv_color_t value, uint32_t selector);
void lv_obj_set_style_text_color(lv_obj_t *obj, lv_color_t value, uint32_t selector);
void lv_obj_set_scrollbar_mode(lv_obj_t *obj, uint8_t mode);

lv_obj_t *lv_label_create(lv_obj_t *parent);
void lv_label_set_text(lv_obj_t *obj, const char *text);
void lv_label_set_long_mode(lv_obj_t *obj, uint8_t mode);

lv_obj_t *lv_list_create(lv_obj_t *parent);
lv_obj_t *lv_list_add_button(lv_obj_t *list, const void *icon, const char *txt);
void lv_list_add_text(lv_obj_t *list, const char *txt);

lv_obj_t *lv_textarea_create(lv_obj_t *parent);
void lv_textarea_set_one_line(lv_obj_t *obj, bool one_line);
void lv_textarea_set_max_length(lv_obj_t *obj, uint32_t len);
void lv_textarea_set_placeholder_text(lv_obj_t *obj, const char *txt);
const char *lv_textarea_get_text(const lv_obj_t *obj);

lv_obj_t *lv_keyboard_create(lv_obj_t *parent);
void lv_keyboard_set_textarea(lv_obj_t *obj, lv_obj_t *ta);

lv_event_code_t lv_event_get_code(lv_event_t *e);
void *lv_event_get_user_data(lv_event_t *e);

lv_color_t lv_color_hex(uint32_t c);
lv_color_t lv_color_white(void);

#endif  // HEXWALLET_MOCK_LVGL_H
