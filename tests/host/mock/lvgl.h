// Minimal LVGL 9 API mock used ONLY by the host-side board-port compile
// check (tests/host/board_port_compile_check.ps1). It exists so the
// hardware driver code can be syntax- and type-checked with the real ESP32
// headers but without pulling in the full LVGL tree. It is NOT shipped to
// the device and is never used by the firmware build.
#ifndef HEXWALLET_MOCK_LVGL_H
#define HEXWALLET_MOCK_LVGL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LV_COLOR_DEPTH 16
#define LV_COLOR_16_SWAP 1

typedef int16_t lv_coord_t;

typedef struct {
  uint16_t full;
} lv_color_t;

typedef struct {
  lv_coord_t x1, y1, x2, y2;
} lv_area_t;

typedef struct {
  lv_coord_t x, y;
} lv_point_t;

// --- display driver -------------------------------------------------------
typedef struct _lv_disp_draw_buf_t {
  void *buf1;
  void *buf2;
  uint32_t size;
} lv_disp_draw_buf_t;

typedef struct _lv_disp_drv_t lv_disp_drv_t;
typedef void (*lv_disp_flush_cb_t)(lv_disp_drv_t *, const lv_area_t *, lv_color_t *);
typedef void (*lv_disp_render_start_cb_t)(lv_disp_drv_t *);

struct _lv_disp_drv_t {
  lv_coord_t hor_res;
  lv_coord_t ver_res;
  lv_disp_flush_cb_t flush_cb;
  lv_disp_render_start_cb_t render_start_cb;
  bool antialiasing;
  lv_disp_draw_buf_t *draw_buf;
  void *user_data;
};

typedef struct _lv_disp_t {
  void *reserved;
} lv_disp_t;

// --- input device ---------------------------------------------------------
typedef struct {
  lv_point_t point;
  uint8_t state;
} lv_indev_data_t;

typedef struct _lv_indev_drv_t {
  uint8_t type;
  void (*read_cb)(struct _lv_indev_drv_t *, lv_indev_data_t *);
  void *user_data;
} lv_indev_drv_t;

typedef struct _lv_indev_t {
  void *reserved;
} lv_indev_t;

#define LV_INDEV_TYPE_POINTER 0
#define LV_INDEV_STATE_RELEASED 0
#define LV_INDEV_STATE_PRESSED 1

// --- widgets --------------------------------------------------------------
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

// --- API (declared only; the check is compile-only) -----------------------
void lv_disp_draw_buf_init(lv_disp_draw_buf_t *draw_buf, void *buf1, void *buf2,
                           uint32_t size_in_px);
void lv_disp_drv_init(lv_disp_drv_t *drv);
lv_disp_t *lv_disp_drv_register(lv_disp_drv_t *drv);
void lv_disp_flush_ready(lv_disp_drv_t *drv);
bool lv_disp_flush_is_last(lv_disp_drv_t *drv);

void lv_indev_drv_init(lv_indev_drv_t *drv);
lv_indev_t *lv_indev_drv_register(lv_indev_drv_t *drv);

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
