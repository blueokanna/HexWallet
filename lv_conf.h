#ifndef LV_CONF_H
#define LV_CONF_H

/*====================
   COLOR SETTINGS
 *====================*/
#define LV_COLOR_DEPTH 16

/* The board port selects RGB565_SWAPPED for color-panel wire buffers and
 * native RGB565 for persistent e-paper frames. Global flush-time swapping
 * corrupts DIRECT-mode frames when only a subrectangle is redrawn. */
#define LV_COLOR_16_SWAP 0
#define LV_COLOR_SCREEN_TRANSP 0
#define LV_COLOR_MIX_ROUND_OFS 0
#define LV_COLOR_CHROMA_KEY lv_color_hex(0x00ff00)

/*====================
   MEMORY SETTINGS
 *====================*/
/* LVGL 9 allocates through a stdlib backend, not a fixed pool. The v8-era
 * LV_MEM_SIZE knob below is kept only so older configs still parse; the pool it
 * used to reserve lived in .dram0.bss and cost 96 KiB of a 320 KiB DRAM segment.
 * malloc/free comes from the platform heap, which is where a PSRAM-equipped board
 * wants it, and nothing is reserved up front. */
#define LV_USE_STDLIB_MALLOC LV_STDLIB_CLIB
#define LV_MEM_CUSTOM 0
#define LV_MEM_SIZE (32U * 1024U)
#define LV_MEM_ADR 0
/* LV_MEM_POOL_INCLUDE / LV_MEM_POOL_ALLOC must stay UNDEFINED when
 * LV_MEM_ADR == 0: lv_mem_core_builtin.c does `#include LV_MEM_POOL_INCLUDE`
 * under `#ifdef`, so an empty definition breaks the build with a bare
 * `#include` directive. */
#if LV_MEM_ADR == 0
#undef LV_MEM_POOL_INCLUDE
#undef LV_MEM_POOL_ALLOC
#endif
#define LV_MEM_BUF_MAX_NUM 16

/*====================
   HAL SETTINGS
 *====================*/
#define LV_DISP_DEF_REFR_PERIOD 16
#define LV_INDEV_DEF_READ_PERIOD 30

/* LVGL 9: WalletBoardPort installs millis() with lv_tick_set_cb(). */

#define LV_DPI_DEF 130

/*====================
   FONT SETTINGS
 *====================*/
#define LV_FONT_MONTSERRAT_12 1
#define LV_FONT_MONTSERRAT_14 1
#define LV_FONT_MONTSERRAT_16 1
#define LV_FONT_DEFAULT &lv_font_montserrat_14

/*====================
   THEME
 *====================*/
#define LV_USE_THEME_DEFAULT 1

/*====================
   WIDGETS USED BY THE UI
 *====================*/
#define LV_USE_BUTTON 1
#define LV_USE_LABEL 1
#define LV_USE_LIST 1
#define LV_USE_TEXTAREA 1
#define LV_USE_KEYBOARD 1
#define LV_USE_STYLE 1

/*====================
   RENDERING
 *====================*/
#define LV_USE_OS LV_OS_NONE
#define LV_USE_LOG 0
#define LV_USE_ASSERT_NULL 1
#define LV_USE_ASSERT_MALLOC 1
#define LV_USE_ASSERT_STYLE 1
#define LV_USE_ASSERT_MEM_INTEGRITY 0
#define LV_USE_ASSERT_OBJ 0

#define LV_USE_PERF_MONITOR 0
#define LV_USE_MEM_MONITOR 0
#define LV_USE_REFR_DEBUG 0

#define LV_SPRINTF_CUSTOM 0
#define LV_USE_USER_DATA 1
#define LV_BIG_ENDIAN_SYSTEM 0

#define LV_ATTRIBUTE_FAST_MEM
#define LV_ATTRIBUTE_MEM_ALIGN

/* clang-format on */

#endif /*LV_CONF_H*/
