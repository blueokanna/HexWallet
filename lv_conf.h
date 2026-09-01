/**
 * @file lv_conf.h
 * LVGL configuration for HexWallet (LVGL 9.x).
 *
 * Keep the widget set to exactly what WalletUi.cpp instantiates; every
 * enabled widget costs flash and every disabled one avoids surprises.
 */

#ifndef LV_CONF_H
#define LV_CONF_H

/* clang-format off */

/*====================
   COLOR SETTINGS
 *====================*/
#define LV_COLOR_DEPTH 16

/* All panels (SPI RM67162, 8-bit parallel ST7789, e-paper conversion) expect
 * the high byte of RGB565 first, so store the two bytes swapped in memory and
 * stream the buffer straight to the panel without a per-pixel copy. */
#define LV_COLOR_16_SWAP 1

#define LV_COLOR_SCREEN_TRANSP 0
#define LV_COLOR_MIX_ROUND_OFS 0
#define LV_COLOR_CHROMA_KEY lv_color_hex(0x00ff00)

/*====================
   MEMORY SETTINGS
 *====================*/
#define LV_MEM_CUSTOM 0
#define LV_MEM_SIZE (96U * 1024U)
#define LV_MEM_ADR 0
#define LV_MEM_POOL_INCLUDE
#define LV_MEM_POOL_ALLOC
#define LV_MEM_BUF_MAX_NUM 16

/*====================
   HAL SETTINGS
 *====================*/
#define LV_DISP_DEF_REFR_PERIOD 16
#define LV_INDEV_DEF_READ_PERIOD 30

/* Tick from millis(); the board port drives lv_timer_handler() from loop(). */
#define LV_TICK_CUSTOM 1
#if LV_TICK_CUSTOM
#define LV_TICK_CUSTOM_INCLUDE "Arduino.h"
#define LV_TICK_CUSTOM_SYS_TIME_EXPR (millis())
#endif

#define LV_DPI_DEF 130

/*====================
   FONT SETTINGS
 *====================*/
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
