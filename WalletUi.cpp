#include "WalletUi.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "Mascot.h"
#include "MaidSprite.h"
#include "QrCode.h"
#include "WalletBoardPort.h"
#include "RandomSource.h"
#include "TrustAnchor.h"
#include "WalletCatalog.h"
#include "WalletLinkService.h"
#include "CoinIcons.h"

#if HEXWALLET_ENABLE_LVGL
#include <lvgl.h>
LV_FONT_DECLARE(hexwallet_ui_chinese);
#endif

namespace hexwallet
{
  namespace
  {
    constexpr uint32_t kReviewSealWindowMs = 120UL * 1000UL;

    ReviewSeal review_seal = {};
    bool review_seal_valid = false;
    WalletUiLanguage language = WalletUiLanguage::English;
    const char *tr(const char *en, const char *zh) {
      return language == WalletUiLanguage::Chinese ? zh : en;
    }

#if HEXWALLET_ENABLE_LVGL

    bool initialized = false;
    bool session_authenticated = false;
    bool otp_visible = false;
    char otp_text[9] = {};
    bool eink_panel = false;
    uint8_t eink_colors = 1;
    unsigned long last_service_ms = 0;
    WalletUiDecisionCallback decision_callback = nullptr;
    bool decision_pending = false;
    bool decision_value = false;
    bool reading_page = false;
    bool pairing_page = false;

    const char *localize(const char *text) {
      if (!text || language != WalletUiLanguage::Chinese) return text;
      static const struct { const char *en; const char *zh; } messages[] = {
#include "src/UiText.inc"
      };
      for (const auto &message : messages)
        if (strcmp(message.en, text) == 0) return message.zh;
      return text;
    }

    bool landscape_panel() { return eink_panel && board_display_height() == 128 && board_display_width() == 296; }

    void approve_event(lv_event_t *event)
    {
      if (decision_callback != nullptr && !decision_pending &&
          (review_seal_valid || pairing_page) && board_display_review_ready())
      {
        if (lv_event_get_code(event) == LV_EVENT_LONG_PRESSED) {
          if (auto indev = lv_indev_active()) lv_indev_wait_release(indev);
        }
        mascot_note_approval(millis());
        decision_value = true;
        decision_pending = true;
      }
    }

    void reject_event(lv_event_t *)
    {
      if (decision_callback != nullptr)
      {
        mascot_note_rejection(millis());
        decision_value = false;
        decision_pending = true;
      }
    }

    static float ui_scale()
    {
      const uint16_t w = board_display_width();
      const uint16_t h = board_display_height();
      const uint16_t min_side = (w < h) ? w : h;
      if (min_side == 0)
        return 1.0f;
      float s = static_cast<float>(min_side) / 240.0f;
      if (s < 0.45f)
        s = 0.45f;
      if (s > 1.25f)
        s = 1.25f;
      return s;
    }

    static const lv_font_t *ui_font()
    {
      if (language == WalletUiLanguage::Chinese) return &hexwallet_ui_chinese;
      const uint16_t w = board_display_width();
      const uint16_t h = board_display_height();
      const uint16_t min_side = (w < h) ? w : h;
      return min_side > 0 && min_side <= 160 ? &lv_font_montserrat_12
                                             : &lv_font_montserrat_14;
    }

    static int sc(int value)
    {
      const int scaled = static_cast<int>(static_cast<float>(value) * ui_scale());
      return scaled < 1 ? 1 : scaled;
    }

    static lv_color_t theme_fg() { return lv_color_hex(eink_panel ? 0x000000 : 0x171717); }
    static lv_color_t theme_bg() { return lv_color_hex(eink_panel ? 0xffffff : 0xf7f7f5); }
    static lv_color_t theme_accent()
    {
      if (!eink_panel)
        return lv_color_hex(0xb52424);
      if (eink_colors >= 3)
        return lv_color_hex(0xa00000); // red is in every colour panel
      return lv_color_hex(0x000000);
    }
    static lv_color_t theme_warn()
    {
      if (!eink_panel)
        return lv_color_hex(0x8a241e);
      if (eink_colors >= 4)
        return lv_color_hex(0x8a6d00); // yellow, not a dithered red
      if (eink_colors == 3)
        return lv_color_hex(0x000000);
      return lv_color_hex(0x000000);
    }
    static lv_color_t theme_badge_on() { return lv_color_hex(eink_panel ? 0xffffff : 0xe5e5e5); }
    static lv_color_t theme_badge_off() { return lv_color_hex(eink_panel ? 0xffffff : 0xf0d8d5); }
    static lv_color32_t to_color32(lv_color_t color)
    {
      const lv_color32_t converted = {color.blue, color.green, color.red, 0xFF};
      return converted;
    }
    lv_obj_t *screen_content = nullptr;
    lv_obj_t *state_label = nullptr;
    lv_obj_t *status_label = nullptr;
    lv_obj_t *search_field = nullptr;
    lv_obj_t *coin_list = nullptr;
    lv_obj_t *keyboard = nullptr;
    lv_obj_t *companion_stage = nullptr;
    lv_obj_t *companion_canvas = nullptr;
    lv_obj_t *companion_mood_label = nullptr;
    lv_obj_t *companion_hint_label = nullptr;
    MascotSnapshot companion_rendered = {};
    bool companion_has_frame = false;
    static LV_ATTRIBUTE_MEM_ALIGN uint8_t companion_pixels[8 + 64 * 16];

    lv_key_t review_key_remap(lv_indev_t *indev, lv_key_t key)
    {
      lv_group_t *group = lv_indev_get_group(indev);
      if ((reading_page || review_seal_valid) && group != nullptr &&
          lv_group_get_focused(group) == screen_content)
      {
        if (key == LV_KEY_NEXT) return LV_KEY_DOWN;
        if (key == LV_KEY_PREV) return LV_KEY_UP;
      }
      return key;
    }

    void review_body_event(lv_event_t *event)
    {
      if (!review_seal_valid && !pairing_page) return;
      if (lv_event_get_code(event) == LV_EVENT_CANCEL)
      {
        reject_event(event);
      }
      else if (lv_event_get_code(event) == LV_EVENT_CLICKED)
      {
        // ENTER leaves the scrollable text and selects REJECT first. A separate
        // press is required for either decision; NEXT/PREV then select actions.
        lv_group_t *group = lv_obj_get_group(screen_content);
        if (group != nullptr) lv_group_focus_next(group);
      }
    }

    void forget_companion()
    {
      companion_stage = nullptr;
      companion_canvas = nullptr;
      companion_mood_label = nullptr;
      companion_hint_label = nullptr;
      companion_has_frame = false;
    }

    void companion_deleted(lv_event_t *) { forget_companion(); }

    void clear_content()
    {
      reading_page = false;
      pairing_page = false;
      otp_visible = false;
      volatile char *code = otp_text;
      for (size_t i = 0; i < sizeof(otp_text); ++i)
        code[i] = 0;
      forget_companion();
      review_seal_valid = false;
      decision_pending = false;
      search_field = nullptr;
      coin_list = nullptr;
      keyboard = nullptr;
      if (screen_content != nullptr)
      {
        lv_group_remove_obj(screen_content);
        lv_obj_clean(screen_content);
        lv_obj_scroll_to_y(screen_content, 0, LV_ANIM_OFF);
        lv_obj_set_scrollbar_mode(screen_content, LV_SCROLLBAR_MODE_AUTO);
      }
    }

    bool renderable_text(const char *text, const lv_font_t *font) {
      if (!text || !font) return false;
      const auto *cursor = reinterpret_cast<const uint8_t *>(text);
      while (*cursor) {
        uint32_t code = *cursor++;
        if (code >= 0x80) {
          unsigned extra;
          uint32_t minimum;
          if (code >= 0xc2 && code <= 0xdf) { extra = 1; minimum = 0x80; code &= 0x1f; }
          else if (code >= 0xe0 && code <= 0xef) { extra = 2; minimum = 0x800; code &= 0x0f; }
          else if (code >= 0xf0 && code <= 0xf4) { extra = 3; minimum = 0x10000; code &= 7; }
          else return false;
          for (unsigned i = 0; i < extra; ++i) {
            if ((*cursor & 0xc0) != 0x80) return false;
            code = (code << 6) | (*cursor++ & 0x3f);
          }
          if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return false;
        }
        if (code == '\n') continue;
        if (code < 0x20 || (code >= 0x7f && code <= 0x9f) ||
            (code >= 0x200b && code <= 0x200f) || (code >= 0x202a && code <= 0x202e) ||
            (code >= 0x2060 && code <= 0x206f) || code == 0xfeff) return false;
        lv_font_glyph_dsc_t glyph{};
        if (!lv_font_get_glyph_dsc(font, &glyph, code, 0) || glyph.is_placeholder) return false;
      }
      return true;
    }

    struct RenderedReviewLines
    {
      const char *text[kReviewSealMaxLines] = {};
      size_t count = 0;
      bool valid = true;
      void add(lv_obj_t *label)
      {
        if (label == nullptr || count == sizeof(text) / sizeof(text[0]))
        {
          valid = false;
          return;
        }
        text[count++] = lv_label_get_text(label);
        valid = valid && renderable_text(text[count - 1], lv_obj_get_style_text_font(label, LV_PART_MAIN));
      }
    };

    void finish_review_seal(const RenderedReviewLines &lines)
    {
      uint8_t nonce[kReviewSealNonceSize] = {};
      review_seal_valid = random_fill_checked(nonce, sizeof(nonce)) && lines.valid && lines.count != 0 &&
                          review_seal_build(&review_seal, nonce, lines.text, lines.count, millis(),
                                            kReviewSealWindowMs);
      if (!review_seal_valid || screen_content == nullptr)
        return;
      char code[9] = {};
      review_seal_code(review_seal, code);
      char text[24] = {};
      snprintf(text, sizeof(text), tr("SEAL %s", "校验码 %s"), code);
      lv_obj_t *seal = lv_label_create(screen_content);
      lv_label_set_text(seal, text);
      lv_obj_set_style_text_color(seal, theme_accent(), 0);
      lv_obj_set_style_text_letter_space(seal, sc(2), 0);
    }

    void nothing_companion(lv_obj_t *parent, const MascotSnapshot &snapshot);

    void create_catalog_view();

    // All labels on a button inherit its foreground in both focus states.
    void focus_ink(lv_obj_t *button)
    {
      lv_obj_remove_style_all(button);
      lv_obj_set_style_radius(button, 2, 0);
      lv_obj_set_style_pad_all(button, 2, 0);
      lv_obj_set_style_border_width(button, 1, 0);
      lv_obj_set_style_border_color(button, theme_fg(), 0);
      lv_obj_set_style_bg_opa(button, LV_OPA_COVER, 0);
      lv_obj_set_style_bg_color(button, theme_bg(), 0);
      lv_obj_set_style_text_color(button, theme_fg(), 0);
      lv_obj_set_style_bg_color(button, theme_fg(), LV_STATE_FOCUSED);
      lv_obj_set_style_text_color(button, theme_bg(), LV_STATE_FOCUSED);
      lv_obj_set_style_outline_width(button, 0, LV_STATE_FOCUS_KEY);
      lv_obj_set_style_shadow_width(button, 0, 0);
      lv_obj_set_style_text_font(button, ui_font(), 0);
    }

    void set_clean_container(lv_obj_t *object)
    {
      lv_obj_set_style_bg_opa(object, LV_OPA_TRANSP, 0);
      lv_obj_set_style_border_width(object, 0, 0);
      lv_obj_set_style_pad_all(object, 0, 0);
      lv_obj_set_style_radius(object, 0, 0);
    }

    void landscape_scrollbar(lv_obj_t *object)
    {
      lv_obj_set_scroll_dir(object, LV_DIR_VER);
      lv_obj_set_scrollbar_mode(object, LV_SCROLLBAR_MODE_AUTO);
      lv_obj_set_style_pad_right(object, 4, 0);
      lv_obj_set_style_pad_right(object, 0, LV_PART_SCROLLBAR);
      lv_obj_set_style_width(object, 2, LV_PART_SCROLLBAR);
      lv_obj_set_style_bg_color(object, theme_fg(), LV_PART_SCROLLBAR);
      lv_obj_set_style_bg_opa(object, LV_OPA_COVER, LV_PART_SCROLLBAR);
    }

    // ---------------------------------------------------------------------------
    // Nothing-style design language
    //
    // Three primitives carry the whole look on a 1bpp panel: a dot band (the dot
    // matrix glyph), a 1 px rule, and micro labels with wide letter spacing. There
    // is no grey to hide behind, so hierarchy comes from spacing and from these
    // three marks only.
    // ---------------------------------------------------------------------------
    void nothing_dot_band(lv_obj_t *parent, uint8_t dots)
    {
      lv_obj_t *band = lv_obj_create(parent);
      set_clean_container(band);
      lv_obj_clear_flag(band, LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_size(band, LV_PCT(100), sc(4));
      lv_obj_set_flex_flow(band, LV_FLEX_FLOW_ROW);
      lv_obj_set_style_pad_column(band, sc(3), 0);
      for (uint8_t index = 0; index < dots; ++index)
      {
        lv_obj_t *dot = lv_obj_create(band);
        set_clean_container(dot);
        lv_obj_clear_flag(dot, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_size(dot, sc(4), sc(4));
        lv_obj_set_style_radius(dot, LV_RADIUS_CIRCLE, 0);
        lv_obj_set_style_bg_opa(dot, LV_OPA_COVER, 0);
        lv_obj_set_style_bg_color(dot, theme_fg(), 0);
      }
    }

    void nothing_rule(lv_obj_t *parent)
    {
      lv_obj_t *rule = lv_obj_create(parent);
      set_clean_container(rule);
      lv_obj_clear_flag(rule, LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_size(rule, LV_PCT(100), 1);
      lv_obj_set_style_bg_opa(rule, LV_OPA_COVER, 0);
      lv_obj_set_style_bg_color(rule, theme_fg(), 0);
    }

    lv_obj_t *nothing_micro_label(lv_obj_t *parent, const char *text, bool accent)
    {
      lv_obj_t *label = lv_label_create(parent);
      lv_label_set_text(label, text);
      lv_obj_set_style_text_color(label, accent ? theme_accent() : theme_fg(), 0);
      // Wide tracking is what makes an uppercase micro label read as a label
      // instead of as content.
      lv_obj_set_style_text_letter_space(label, sc(2), 0);
      lv_obj_set_width(label, LV_PCT(100));
      lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
      return label;
    }

    bool nothing_group_address(char *out, size_t capacity, const char *address)
    {
      if (out == nullptr || capacity < 2)
        return false;
      size_t written = 0;
      size_t count = 0;
      for (const char *cursor = address; cursor != nullptr && *cursor != '\0'; ++cursor)
      {
        if (written + 1 >= capacity) return false;
        out[written++] = *cursor;
        ++count;
        if ((count % 4) == 0 && cursor[1] != '\0') {
          if (written + 1 >= capacity) return false;
          out[written++] = ' ';
        }
      }
      out[written] = '\0';
      return true;
    }

    // QR code as an LVGL canvas in 1bpp (I1) format. The canvas stores exactly the
    // panel-side bit order LVGL expects (MSB first), so no conversion is needed on
    // either the colour or the e-paper flush path.
    //
    // The encoder output and the pixel scratch are static: a screen shows one QR
    // code, and 3.3 KiB of stack is not something this firmware hands out per view.
    lv_obj_t *nothing_qr(lv_obj_t *parent, const char *text, const char **level_name)
    {
      if (parent == nullptr || text == nullptr)
        return nullptr;
      if (level_name != nullptr)
        *level_name = "M";
      const size_t length = strlen(text);
      if (length == 0)
        return nullptr;

      static QrCode code;
      QrEcc chosen = QrEcc::Medium;
      if (!qr_encode_best(reinterpret_cast<const uint8_t *>(text), length, &code,
                          &chosen))
      {
        return nullptr;
      }
      if (level_name != nullptr)
        *level_name = qr_ecc_name(chosen);
      // Rasterize integer modules at their final size. The indexed image and
      // its quiet zone then occupy exactly the space LVGL assigns to the canvas.
      constexpr uint16_t max_side = 192;
      lv_obj_update_layout(parent);
      const lv_coord_t available = lv_obj_get_content_width(parent);
      const uint16_t modules = code.size + 2U * kQrQuietZone;
      const int scale = (available < max_side ? available : max_side) / modules;
      if (scale < 1) return nullptr;
      const uint16_t side = modules * scale;
      const uint32_t stride = lv_draw_buf_width_to_stride(side, LV_COLOR_FORMAT_I1);
      const size_t bytes = static_cast<size_t>(stride) * side;
      static LV_ATTRIBUTE_MEM_ALIGN uint8_t pixels[8 + max_side * (max_side / 8)];
      if (bytes + 8 > sizeof(pixels))
        return nullptr;
      memset(pixels, 0, bytes + 8);
      if (!qr_render(code, pixels + 8, bytes, stride * 8, side, 0, 0, scale)) return nullptr;

      lv_obj_t *canvas = lv_canvas_create(parent);
      if (canvas == nullptr)
        return nullptr;
      static lv_draw_buf_t draw_buffer;
      if (lv_draw_buf_init(&draw_buffer, side, side, LV_COLOR_FORMAT_I1, stride,
                           pixels, static_cast<uint32_t>(bytes + 8)) != LV_RESULT_OK)
      {
        lv_obj_delete(canvas);
        return nullptr;
      }
      lv_canvas_set_draw_buf(canvas, &draw_buffer);
      lv_canvas_set_palette(canvas, 0, to_color32(theme_bg()));
      lv_canvas_set_palette(canvas, 1, to_color32(theme_fg()));

      return canvas;
    }

    lv_obj_t *coin_icon_view(lv_obj_t *parent, const char *key)
    {
      const CoinIcon *icon = coin_icon_find(key);
      if (icon == nullptr)
        return nullptr;
      const lv_coord_t side = static_cast<lv_coord_t>(kCoinIconSize);
      const uint32_t stride = lv_draw_buf_width_to_stride(side, LV_COLOR_FORMAT_I1);
      const size_t bytes = static_cast<size_t>(stride) * side;
      static LV_ATTRIBUTE_MEM_ALIGN uint8_t pixels[8 + kCoinIconBytes];
      if (bytes + 8 > sizeof(pixels) || icon->size != bytes)
        return nullptr;
      memset(pixels, 0, bytes + 8);
      memcpy(pixels + 8, icon->pixels, icon->size);
      lv_obj_t *canvas = lv_canvas_create(parent);
      if (canvas == nullptr)
        return nullptr;
      static lv_draw_buf_t draw_buffer;
      if (lv_draw_buf_init(&draw_buffer, side, side, LV_COLOR_FORMAT_I1, stride,
                           pixels, static_cast<uint32_t>(bytes + 8)) != LV_RESULT_OK)
      {
        lv_obj_delete(canvas);
        return nullptr;
      }
      lv_canvas_set_draw_buf(canvas, &draw_buffer);
      lv_canvas_set_palette(canvas, 0, to_color32(theme_bg()));
      lv_canvas_set_palette(canvas, 1, to_color32(theme_fg()));
      return canvas;
    }

    void show_asset(size_t index);

    void coin_clicked(lv_event_t *event)
    {
      const size_t index = reinterpret_cast<size_t>(lv_event_get_user_data(event));
      if (landscape_panel()) { show_asset(index); return; }
      WalletCatalogEntry entry;
      if (!wallet_catalog_at_sorted(index, &entry) || status_label == nullptr)
        return;
      lv_label_set_text_fmt(status_label, "%s\n%s", entry.name, entry.status);
    }

    void populate_catalog(const char *query)
    {
      if (coin_list == nullptr)
        return;
      lv_obj_clean(coin_list);
      size_t matches = 0;
      for (size_t index = 0; index < wallet_catalog_count(); ++index)
      {
        WalletCatalogEntry entry;
        if (!wallet_catalog_at_sorted(index, &entry) || !wallet_catalog_matches(entry, query))
          continue;
        char row[128];
        const bool signs = wallet_catalog_has(entry, WalletCapabilitySigning);
        const bool addresses = wallet_catalog_has(entry, WalletCapabilityAddress);
        const bool tokens = wallet_catalog_has(entry, WalletCapabilityTokenAccount);
        snprintf(row, sizeof(row), "%s  %s\n%s", entry.symbol, entry.name,
                 signs ? (addresses ? "ADDRESS + SIGN" : "ACCOUNT SIGNING") : (tokens ? "ADDRESS + TOKENS" : (addresses ? "ADDRESS" : "UNSUPPORTED")));
        lv_obj_t *button = lv_list_add_button(coin_list, nullptr, row);
        lv_obj_set_height(button, LV_SIZE_CONTENT);
        lv_obj_set_style_pad_ver(button, sc(10), 0);
        lv_obj_set_style_radius(button, sc(8), 0);
        lv_obj_t *label = lv_obj_get_child(button, 0);
        if (label != nullptr)
        {
          lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
          lv_obj_set_width(label, LV_PCT(100));
        }
        lv_obj_set_style_text_color(button, theme_fg(), 0);
        lv_obj_add_event_cb(button, coin_clicked, LV_EVENT_CLICKED, reinterpret_cast<void *>(index));
        ++matches;
        if (*query == '\0' && matches >= 40)
        {
          lv_list_add_text(coin_list, "TYPE TO NARROW");
          break;
        }
      }
      if (matches == 0)
        lv_list_add_text(coin_list, "NO MATCHES");
    }

    void search_event(lv_event_t *event)
    {
      const lv_event_code_t code = lv_event_get_code(event);
      if (code == LV_EVENT_VALUE_CHANGED)
      {
        populate_catalog(lv_textarea_get_text(search_field));
      }
      else if (code == LV_EVENT_FOCUSED && keyboard != nullptr)
      {
        lv_keyboard_set_textarea(keyboard, search_field);
        lv_obj_remove_flag(keyboard, LV_OBJ_FLAG_HIDDEN);
      }
      else if (code == LV_EVENT_DEFOCUSED && keyboard != nullptr)
      {
        lv_obj_add_flag(keyboard, LV_OBJ_FLAG_HIDDEN);
      }
    }

    void create_catalog_view()
    {
      if (screen_content == nullptr)
        return;
      clear_content();
      lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
      lv_obj_set_style_pad_row(screen_content, 8, 0);
      MascotInputs companion_inputs = {};
      companion_inputs.phone_linked = wallet_link_service_connected();
      companion_inputs.battery_mv = board_battery_millivolts();
      nothing_companion(screen_content, mascot_snapshot(companion_inputs, millis()));
      nothing_rule(screen_content);

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

    void create_catalog_view();

    // FEED / PET / PLAY. Plain widgets, so they work with a touch panel and, through
    // the keypad input device, with four physical buttons.
    void companion_action_event(lv_event_t *event)
    {
      const intptr_t action = reinterpret_cast<intptr_t>(lv_event_get_user_data(event));
      const uint32_t now = millis();
      if (action == 0)
        mascot_feed(now);
      else if (action == 1)
        mascot_pet(now);
      else
        mascot_play(now);
      mascot_note_activity(now);
      create_catalog_view();
    }

    void companion_parts(lv_obj_t *stage, const MascotSnapshot &snapshot)
    {
      const uint32_t stride = lv_draw_buf_width_to_stride(64, LV_COLOR_FORMAT_I1);
      if (stride < 8 || stride > 16)
        return;
      memset(companion_pixels, 0, sizeof(companion_pixels));
      if (!maid_sprite_render(snapshot.mood, snapshot.frame, companion_pixels + 8,
                              sizeof(companion_pixels) - 8, stride))
        return;
      lv_obj_t *canvas = lv_canvas_create(stage);
      if (canvas == nullptr)
        return;
      static lv_draw_buf_t draw_buffer;
      if (lv_draw_buf_init(&draw_buffer, 64, 64, LV_COLOR_FORMAT_I1, stride,
                           companion_pixels, 8 + 64 * stride) != LV_RESULT_OK)
      {
        lv_obj_delete(canvas);
        return;
      }
      lv_canvas_set_draw_buf(canvas, &draw_buffer);
      lv_canvas_set_palette(canvas, 0, to_color32(theme_bg()));
      lv_canvas_set_palette(canvas, 1, to_color32(theme_fg()));
      lv_obj_center(canvas);
      companion_canvas = canvas;
      companion_rendered = snapshot;
      companion_has_frame = true;
    }
    void render_companion(const MascotSnapshot &snapshot)
    {
      if (companion_stage == nullptr || companion_canvas == nullptr || review_seal_valid)
        return;
      const bool changed = !companion_has_frame || snapshot.mood != companion_rendered.mood ||
                           (snapshot.animating && snapshot.frame != companion_rendered.frame);
      if (changed)
      {
        const size_t stride = lv_draw_buf_width_to_stride(64, LV_COLOR_FORMAT_I1);
        if (stride > 16 || !maid_sprite_render(snapshot.mood, snapshot.frame,
                                               companion_pixels + 8, sizeof(companion_pixels) - 8, stride))
          return;
        lv_obj_invalidate(companion_canvas);
      }
      if (companion_mood_label != nullptr && snapshot.mood != companion_rendered.mood)
        lv_label_set_text(companion_mood_label, mascot_mood_name(snapshot.mood));
      if (companion_hint_label != nullptr && snapshot.reminder != companion_rendered.reminder)
        lv_label_set_text(companion_hint_label, mascot_reminder_text(snapshot.reminder));
      companion_rendered = snapshot;
      companion_has_frame = true;
    }

    enum class Page { Home, Create, Recover, CreateWords, RecoverWords, CreateKey, RecoverKey, Scan, Controls, Catalog, Language, Asset };
    Page current_page = Page::Home;
    void open_page(Page page);
    size_t catalog_offset = 0;

    void catalog_page_event(lv_event_t *event)
    {
      if (lv_event_get_user_data(event)) {
        if (catalog_offset + 8 < wallet_catalog_count()) catalog_offset += 8;
      } else if (catalog_offset >= 8) catalog_offset -= 8;
      open_page(Page::Catalog);
    }

    void open_page_event(lv_event_t *event)
    {
      open_page(static_cast<Page>(reinterpret_cast<uintptr_t>(lv_event_get_user_data(event))));
    }

    void back_event(lv_event_t *)
    {
      switch (current_page) {
        case Page::CreateWords: case Page::CreateKey: open_page(Page::Create); break;
        case Page::RecoverWords: case Page::RecoverKey: open_page(Page::Recover); break;
        case Page::Asset: open_page(Page::Catalog); break;
        default: open_page(Page::Home); break;
      }
    }

    lv_obj_t *menu_item(lv_obj_t *parent, const char *caption, Page target)
    {
      auto button = lv_button_create(parent);
      focus_ink(button);
      lv_obj_set_size(button, LV_PCT(100), 22);
      lv_obj_add_event_cb(button, open_page_event, LV_EVENT_CLICKED,
                          reinterpret_cast<void *>(static_cast<uintptr_t>(target)));
      lv_obj_add_event_cb(button, back_event, LV_EVENT_CANCEL, nullptr);
      auto label = lv_label_create(button);
      lv_label_set_text(label, caption);
      lv_obj_set_width(label, lv_pct(100));
      lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
      lv_obj_align(label, LV_ALIGN_LEFT_MID, 0, 0);
      return button;
    }

    void focus_reader()
    {
      reading_page = true;
      lv_obj_add_flag(screen_content, LV_OBJ_FLAG_SCROLL_WITH_ARROW);
      if (auto group = lv_group_get_default()) {
        lv_group_add_obj(group, screen_content);
        lv_group_focus_obj(screen_content);
      }
    }

    void page_text(const char *text)
    {
      auto label = lv_label_create(screen_content);
      lv_obj_set_width(label, LV_PCT(100));
      lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
      lv_label_set_text(label, text);
    }

    void language_event(lv_event_t *event) {
      wallet_ui_set_language(static_cast<WalletUiLanguage>(reinterpret_cast<uintptr_t>(lv_event_get_user_data(event))));
    }

    void open_page(Page page)
    {
      clear_content();
      decision_callback = nullptr;
      current_page = page;
      lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
      lv_obj_set_style_pad_row(screen_content, 2, 0);
      wallet_ui_set_status(tr("OK select   Prev / Next   Back", "确定选择  上一个 / 下一个  返回"));
      if (page == Page::Home) {
        catalog_offset = 0;
        lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_ROW);
        companion_stage = lv_obj_create(screen_content);
        set_clean_container(companion_stage);
        lv_obj_set_size(companion_stage, 74, LV_PCT(100));
        lv_obj_clear_flag(companion_stage, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_add_event_cb(companion_stage, companion_deleted, LV_EVENT_DELETE, nullptr);
        MascotInputs inputs{};
        inputs.battery_mv = board_battery_millivolts();
        inputs.phone_linked = wallet_link_service_connected();
        companion_parts(companion_stage, mascot_snapshot(inputs, millis()));
        auto menu = lv_obj_create(screen_content);
        set_clean_container(menu);
        lv_obj_set_flex_grow(menu, 1);
        lv_obj_set_height(menu, 68); // Three complete 22px rows, no clipped fourth row.
        lv_obj_set_flex_flow(menu, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_style_pad_row(menu, 1, 0);
        landscape_scrollbar(menu);
        auto first = menu_item(menu, tr("Create wallet", "创建钱包"), Page::Create);
        menu_item(menu, tr("Recover wallet", "恢复钱包"), Page::Recover);
        menu_item(menu, tr("Scan QR", "扫描二维码"), Page::Scan);
        menu_item(menu, tr("Button guide", "按键说明"), Page::Controls);
        menu_item(menu, tr("Asset directory", "资产目录"), Page::Catalog);
        auto locale = menu_item(menu, "Language / 语言", Page::Language);
        lv_obj_set_style_text_font(locale, &hexwallet_ui_chinese, 0);
        lv_group_focus_obj(first);
        return;
      }
      if (page == Page::Create || page == Page::Recover) {
        bool create = page == Page::Create;
        page_text(create ? tr("Create wallet  /  Choose a backup", "创建钱包 / 选择备份方式") : tr("Recover wallet  /  Choose your backup", "恢复钱包 / 选择已有备份"));
        auto first = menu_item(screen_content, tr("BIP39  /  Recovery words", "BIP39 / 助记词"), create ? Page::CreateWords : Page::RecoverWords);
        menu_item(screen_content, tr("BIP38  /  Encrypted Bitcoin key", "BIP38 / 加密比特币私钥"), create ? Page::CreateKey : Page::RecoverKey);
        lv_group_focus_obj(first);
        return;
      }
      if (page == Page::Language) {
        page_text(tr("Language / applies until power-off", "语言 / 本次开机有效"));
        for (uintptr_t i = 0; i < 2; ++i) {
          auto button = lv_button_create(screen_content);
          focus_ink(button);
          lv_obj_set_style_text_font(button, &hexwallet_ui_chinese, 0);
          lv_obj_set_size(button, LV_PCT(100), 22);
          lv_label_set_text(lv_label_create(button), i ? "简体中文" : "English");
          lv_obj_add_event_cb(button, language_event, LV_EVENT_CLICKED, reinterpret_cast<void *>(i));
          lv_obj_add_event_cb(button, back_event, LV_EVENT_CANCEL, nullptr);
          if (i == static_cast<uintptr_t>(language)) lv_group_focus_obj(button);
        }
        return;
      }
      if (page == Page::Catalog) {
        if (catalog_offset >= wallet_catalog_count())
          catalog_offset = wallet_catalog_count() ? ((wallet_catalog_count() - 1) / 8) * 8 : 0;
        const size_t end = catalog_offset + 8;
        for (size_t i = catalog_offset; i < end && i < wallet_catalog_count(); ++i) {
          WalletCatalogEntry entry;
          if (!wallet_catalog_at_sorted(i, &entry)) continue;
          auto button = lv_button_create(screen_content);
          focus_ink(button);
           lv_obj_set_width(button, LV_PCT(100));
           lv_obj_set_height(button, LV_SIZE_CONTENT);
          auto label = lv_label_create(button);
           lv_label_set_text_fmt(label, "%s   %s", entry.symbol, entry.name);
           lv_obj_set_width(label, LV_PCT(100));
           lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
          lv_obj_add_event_cb(button, coin_clicked, LV_EVENT_CLICKED, reinterpret_cast<void *>(i));
          lv_obj_add_event_cb(button, back_event, LV_EVENT_CANCEL, nullptr);
        }
        for (int next = 0; next <= 1; ++next) {
          if (next ? end >= wallet_catalog_count() : catalog_offset == 0) continue;
          auto button = lv_button_create(screen_content);
          focus_ink(button);
           lv_obj_set_size(button, LV_PCT(100), 22);
           lv_label_set_text(lv_label_create(button), next ? tr("Next assets", "下一页资产") : tr("Previous assets", "上一页资产"));
          lv_obj_add_event_cb(button, catalog_page_event, LV_EVENT_CLICKED, reinterpret_cast<void *>(uintptr_t(next)));
          lv_obj_add_event_cb(button, back_event, LV_EVENT_CANCEL, nullptr);
        }
        if (!lv_obj_get_child_count(screen_content)) {
          page_text(tr("No assets available", "暂无资产"));
          focus_reader();
        } else lv_group_focus_obj(lv_obj_get_child(screen_content, 0));
        return;
      }
      switch (page) {
        case Page::CreateWords: page_text(tr("Create / BIP39", "创建 / BIP39")); page_text(tr("24 recovery words + optional passphrase. Secure creation is not available yet.", "24 个助记词与可选密码共同确定钱包。安全创建功能尚未开放。")); break;
        case Page::RecoverWords: page_text(tr("Recover / BIP39", "恢复 / BIP39")); page_text(tr("Use the original words and exact passphrase. Secure recovery is not available yet.", "需要原始助记词和完全一致的密码。安全恢复功能尚未开放。")); break;
        case Page::CreateKey: page_text(tr("Create / BIP38", "创建 / BIP38")); page_text(tr("Encrypt one Bitcoin private key with a passphrase. Protected export is not available yet.", "使用密码加密一个比特币私钥。受保护的私钥导出尚未开放。")); break;
        case Page::RecoverKey: page_text(tr("Recover / BIP38", "恢复 / BIP38")); page_text(tr("Use the encrypted Bitcoin key and its passphrase. Protected import is not available yet.", "需要加密的比特币私钥及其密码。受保护的私钥导入尚未开放。")); break;
        case Page::Scan: page_text(tr("Scan QR", "扫描二维码")); page_text(tr("Camera capture is not available yet on this board.", "此板卡的摄像头采集尚未开放。")); break;
        case Page::Controls: page_text(tr("Keys: OK / Prev / Next / Back", "左起：确定 / 上一个 / 下一个 / 返回")); page_text(tr("Prev / Next move or scroll. Back cancels. Review: OK selects Reject first; select Approve, then hold OK for 0.75s.", "上一个、下一个用于选择或滚动；返回用于取消。审阅时，确定先选中拒绝；切换至批准后，另行长按确定 0.75 秒。")); break;
        default: break;
      }
      focus_reader();
      wallet_ui_set_status(tr("Prev / Next scroll   Back to menu", "上 / 下滚动  返回菜单"));
    }

    void reader_back_event(lv_event_t *event)
    {
      if (reading_page && !decision_callback) back_event(event);
    }

    void show_asset(size_t index) {
      WalletCatalogEntry entry;
      if (!wallet_catalog_at_sorted(index, &entry)) return;
      clear_content();
      decision_callback = nullptr;
      current_page = Page::Asset;
      lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
      page_text(entry.name);
      page_text(entry.symbol);
      nothing_rule(screen_content);
      page_text(wallet_catalog_has(entry, WalletCapabilityAddress) ?
                tr("Address derivation: registered", "地址派生：已登记") : tr("Address derivation: unavailable", "地址派生：不可用"));
      page_text(wallet_catalog_has(entry, WalletCapabilitySigning) ?
                tr("Signing code: registered", "签名代码：已登记") : tr("Signing code: unavailable", "签名代码：不可用"));
      page_text(tr("Registry entries do not prove secure-card signing or on-chain acceptance.", "目录登记不代表实卡签名或链上验收完成。"));
      focus_reader();
      wallet_ui_set_status(tr("Prev / Next scroll   Back to assets", "上 / 下滚动  返回资产目录"));
    }

    void nothing_companion(lv_obj_t *parent, const MascotSnapshot &snapshot)
    {
      const bool narrow = board_display_width() <= 160;
      lv_obj_t *row = lv_obj_create(parent);
      set_clean_container(row);
      lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_size(row, LV_PCT(100), LV_SIZE_CONTENT);
      lv_obj_set_flex_flow(row, narrow ? LV_FLEX_FLOW_COLUMN : LV_FLEX_FLOW_ROW);
      lv_obj_set_style_pad_column(row, sc(6), 0);

      companion_stage = lv_obj_create(row);
      lv_obj_add_event_cb(companion_stage, companion_deleted, LV_EVENT_DELETE, nullptr);
      set_clean_container(companion_stage);
      lv_obj_clear_flag(companion_stage, LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_size(companion_stage, 68, 68);
      companion_parts(companion_stage, snapshot);

      lv_obj_t *info = lv_obj_create(row);
      set_clean_container(info);
      lv_obj_clear_flag(info, LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_height(info, LV_SIZE_CONTENT);
      if (narrow)
        lv_obj_set_width(info, LV_PCT(100));
      else
        lv_obj_set_flex_grow(info, 1);
      lv_obj_set_flex_flow(info, LV_FLEX_FLOW_COLUMN);
      lv_obj_set_style_pad_row(info, sc(3), 0);

      char line[64];
      snprintf(line, sizeof(line), "%s  LV%d", kMascotDisplayName, snapshot.level);
      lv_obj_t *headline = lv_label_create(info);
      lv_label_set_text(headline, line);
      lv_obj_set_style_text_color(headline, theme_accent(), 0);
      lv_obj_set_style_text_letter_space(headline, sc(1), 0);

      lv_obj_t *mood = lv_label_create(info);
      companion_mood_label = mood;
      lv_label_set_text(mood, mascot_mood_name(snapshot.mood));
      lv_obj_set_style_text_color(mood, theme_fg(), 0);

      // Bond as a segmented meter: filled blocks are progress inside this level.
      lv_obj_t *meter = lv_obj_create(info);
      if (narrow)
        lv_obj_add_flag(meter, LV_OBJ_FLAG_HIDDEN);
      set_clean_container(meter);
      lv_obj_clear_flag(meter, LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_size(meter, LV_PCT(100), sc(4));
      lv_obj_set_flex_flow(meter, LV_FLEX_FLOW_ROW);
      lv_obj_set_style_pad_column(meter, sc(2), 0);
      const uint8_t segments = 8;
      const uint8_t filled = static_cast<uint8_t>(
          (static_cast<uint32_t>(snapshot.bond) * segments) / snapshot.bond_max);
      for (uint8_t index = 0; index < segments; ++index)
      {
        lv_obj_t *segment = lv_obj_create(meter);
        set_clean_container(segment);
        lv_obj_clear_flag(segment, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_size(segment, sc(4), sc(4));
        lv_obj_set_style_bg_color(segment, theme_fg(), 0);
        if (index < filled)
        {
          lv_obj_set_style_bg_opa(segment, LV_OPA_COVER, 0);
        }
        else
        {
          lv_obj_set_style_bg_opa(segment, LV_OPA_TRANSP, 0);
          lv_obj_set_style_border_width(segment, 1, 0);
          lv_obj_set_style_border_color(segment, theme_fg(), 0);
        }
      }

      // FEED / PET / PLAY. Plain widgets, so they work with a touch panel and,
      // through the keypad input device, with four physical buttons.
      lv_obj_t *actions = lv_obj_create(info);
      set_clean_container(actions);
      lv_obj_clear_flag(actions, LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_size(actions, LV_PCT(100), LV_SIZE_CONTENT);
      lv_obj_set_flex_flow(actions, LV_FLEX_FLOW_ROW);
      lv_obj_set_style_pad_column(actions, sc(3), 0);
      static const char *const kActionLabels[3] = {"FEED", "PET", "PLAY"};
      for (intptr_t index = 0; index < 3; ++index)
      {
        lv_obj_t *button = lv_button_create(actions);
        lv_obj_set_height(button, 28);
        lv_obj_set_style_pad_all(button, 1, 0);
        lv_obj_set_flex_grow(button, 1);
        lv_obj_set_style_radius(button, sc(4), 0);
        lv_obj_set_style_border_width(button, 1, 0);
        lv_obj_set_style_border_color(button, theme_fg(), 0);
        lv_obj_set_style_bg_opa(button, LV_OPA_TRANSP, 0);
        lv_obj_add_event_cb(button, companion_action_event, LV_EVENT_CLICKED,
                            reinterpret_cast<void *>(index));
        lv_obj_t *text = lv_label_create(button);
        lv_label_set_text(text, kActionLabels[index]);
        lv_obj_set_style_text_color(text, theme_fg(), 0);
        lv_obj_set_style_text_font(text, ui_font(), 0);
        lv_obj_set_style_text_letter_space(text, 0, 0);
        lv_obj_center(text);
      }

      snprintf(line, sizeof(line), "approved %u\nrejected %u",
               static_cast<unsigned>(snapshot.stats.approvals),
               static_cast<unsigned>(snapshot.stats.rejections));
      lv_obj_t *stats = lv_label_create(info);
      if (narrow)
        lv_obj_add_flag(stats, LV_OBJ_FLAG_HIDDEN);
      lv_label_set_text(stats, line);
      lv_obj_set_style_text_color(stats, theme_fg(), 0);

      const char *reminder = mascot_reminder_text(snapshot.reminder);
      if (reminder != nullptr)
      {
        lv_obj_t *hint = lv_label_create(info);
        companion_hint_label = hint;
        lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(hint, LV_PCT(100));
        lv_label_set_text(hint, reminder);
        lv_obj_set_style_text_color(hint, theme_accent(), 0);
      }
    }
#endif
  }

  bool wallet_ui_init()
  {
#if !HEXWALLET_ENABLE_LVGL
    return false;
#else
    eink_panel = board_is_eink();
    eink_colors = board_display_colors();
    const lv_color_t fg = theme_fg();
    const lv_color_t bg = theme_bg();
    lv_obj_t *screen = lv_screen_active();
    if (screen == nullptr)
      return false;
    forget_companion();
    review_seal_valid = false;
    lv_obj_clean(screen);
    lv_obj_set_style_bg_color(screen, bg, 0);
    lv_obj_set_style_text_color(screen, fg, 0);
    lv_obj_set_style_text_font(screen, ui_font(), 0);
    lv_obj_set_style_pad_all(screen, landscape_panel() ? 3 : sc(12), 0);
    lv_obj_set_style_pad_row(screen, landscape_panel() ? 2 : sc(10), 0);
    lv_obj_set_flex_flow(screen, LV_FLEX_FLOW_COLUMN);

    lv_obj_t *header = lv_obj_create(screen);
    lv_obj_set_size(header, LV_PCT(100), LV_SIZE_CONTENT);
    set_clean_container(header);
    lv_obj_set_flex_flow(header, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(header, LV_FLEX_ALIGN_SPACE_BETWEEN,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *title = lv_label_create(header);
    lv_label_set_text(title, board_display_width() <= 160 ? "HEX" : "HEX WALLET");
    lv_obj_set_style_text_color(title, fg, 0);

    state_label = lv_label_create(header);
    lv_obj_set_style_pad_hor(state_label, sc(8), 0);
    lv_obj_set_style_pad_ver(state_label, sc(4), 0);
    lv_obj_set_style_radius(state_label, 4, 0);

    screen_content = lv_obj_create(screen);
    lv_obj_set_width(screen_content, LV_PCT(100));
    lv_obj_set_flex_grow(screen_content, 1);
    set_clean_container(screen_content);
    if (landscape_panel()) landscape_scrollbar(screen_content);
    lv_obj_add_event_cb(screen_content, review_body_event, LV_EVENT_CLICKED, nullptr);
    lv_obj_add_event_cb(screen_content, review_body_event, LV_EVENT_CANCEL, nullptr);
    lv_obj_add_event_cb(screen_content, reader_back_event, LV_EVENT_CANCEL, nullptr);
    for (lv_indev_t *indev = lv_indev_get_next(nullptr); indev != nullptr;
         indev = lv_indev_get_next(indev))
    {
      if (lv_indev_get_type(indev) == LV_INDEV_TYPE_KEYPAD) {
        lv_indev_set_key_remap_cb(indev, review_key_remap);
        if (landscape_panel()) lv_indev_set_long_press_time(indev, 750);
      }
    }

    status_label = lv_label_create(screen);
    lv_label_set_long_mode(status_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(status_label, LV_PCT(100));
    lv_obj_set_style_text_color(status_label, theme_warn(), 0);

    initialized = true;
    last_service_ms = 0;
    wallet_ui_set_authenticated(false);
    wallet_ui_show_catalog();
    return true;
#endif
  }

  bool wallet_ui_ready()
  {
#if HEXWALLET_ENABLE_LVGL
    return initialized;
#else
    return false;
#endif
  }

  WalletUiLanguage wallet_ui_language() { return language; }

  bool wallet_ui_set_language(WalletUiLanguage value) {
    if (value != WalletUiLanguage::English && value != WalletUiLanguage::Chinese) return false;
#if HEXWALLET_ENABLE_LVGL
    if (review_seal_valid || pairing_page || decision_callback || decision_pending || otp_visible) return false;
    language = value;
    if (initialized) {
      lv_obj_set_style_text_font(lv_screen_active(), ui_font(), 0);
      wallet_ui_set_authenticated(session_authenticated);
      open_page(Page::Language);
    }
#else
    language = value;
#endif
    return true;
  }

  void wallet_ui_show_port_error()
  {
#if HEXWALLET_ENABLE_LVGL
    lv_obj_t *screen = lv_screen_active();
    if (screen == nullptr)
      return;
    forget_companion();
    review_seal_valid = false;
    decision_pending = false;
    decision_callback = nullptr;
    initialized = false;
    volatile char *code = otp_text;
    for (size_t i = 0; i < sizeof(otp_text); ++i) code[i] = 0;
    otp_visible = false;
    pairing_page = false;
    screen_content = state_label = status_label = nullptr;
    search_field = coin_list = keyboard = nullptr;
    lv_obj_clean(screen);
    lv_obj_set_style_bg_color(screen, lv_color_white(), 0);
    lv_obj_t *message = lv_label_create(screen);
    lv_obj_set_width(message, LV_PCT(100));
    lv_label_set_text(message, tr("DISPLAY PORT ERROR", "显示接口错误"));
    lv_obj_center(message);
#endif
  }

  void wallet_ui_set_authenticated(bool authenticated)
  {
#if HEXWALLET_ENABLE_LVGL
    session_authenticated = authenticated;
    if (!initialized || state_label == nullptr)
      return;
    lv_label_set_text(state_label, authenticated ? tr("UNLOCKED", "已解锁") : tr("LOCKED", "已锁定"));
    lv_obj_set_style_bg_color(state_label, authenticated ? theme_badge_on() : theme_badge_off(), 0);
    lv_obj_set_style_text_color(state_label, authenticated ? theme_accent() : theme_warn(), 0);
    if (!landscape_panel()) wallet_ui_set_status(authenticated ? "Authenticated session active" : "Authentication required");
#else
    (void)authenticated;
#endif
  }

  void wallet_ui_set_status(const char *status)
  {
#if HEXWALLET_ENABLE_LVGL
    if (initialized && status_label != nullptr && status != nullptr) {
      const char *text = localize(status);
      lv_point_t size;
      lv_text_get_size(&size, text, ui_font(), 0, 0, board_display_width() - 6, LV_TEXT_FLAG_NONE);
      if (landscape_panel() && size.y > ui_font()->line_height * 2 && !review_seal_valid && !pairing_page) {
        // Long notices belong in a scrollable body, never in a footer that can
        // consume the whole display. Clear the old authorization with the page.
        clear_content();
        decision_callback = nullptr;
        current_page = Page::Home;
        lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
        page_text(tr("Device status", "设备状态"));
        nothing_rule(screen_content);
        page_text(text);
        focus_reader();
        text = tr("Prev / Next scroll   Back to home", "上 / 下滚动  返回主页");
      }
      lv_label_set_text(status_label, text);
    }
#else
    (void)status;
#endif
  }

  void wallet_ui_show_busy(const char *status)
  {
#if HEXWALLET_ENABLE_LVGL
    if (!initialized)
      return;
    if (status && !review_seal_valid && !pairing_page) {
      clear_content();
      decision_callback = nullptr;
      current_page = Page::Home;
      lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
      page_text(tr("Please wait", "请稍候"));
      nothing_rule(screen_content);
      page_text(localize(status));
      focus_reader();
      wallet_ui_set_status(tr("Processing on device", "设备正在处理"));
    } else wallet_ui_set_status(status);
    for (int pass = 0; pass < 4; ++pass)
    {
      lv_timer_handler();
      delay(4);
    }
#else
    (void)status;
#endif
  }

  void wallet_ui_set_decision_callback(WalletUiDecisionCallback callback)
  {
#if HEXWALLET_ENABLE_LVGL
    decision_callback = callback;
    decision_pending = false;
#else
    (void)callback;
#endif
  }

  void wallet_ui_show_catalog()
  {
    review_seal_valid = false;
#if HEXWALLET_ENABLE_LVGL
    if (!initialized)
      return;
    if (landscape_panel()) {
      open_page(Page::Home);
      return;
    }
    create_catalog_view();
    wallet_ui_set_status(session_authenticated ? "Authenticated session active" : "Authentication required");
#endif
  }

  bool wallet_ui_show_address(const char *network, const char *address,
                              const char *path)
  {
    review_seal_valid = false;
#if HEXWALLET_ENABLE_LVGL
    if (!initialized || screen_content == nullptr || !board_has_display() ||
        network == nullptr || address == nullptr || path == nullptr)
      return false;
    decision_callback = nullptr;
    decision_pending = false;
    board_display_prepare_review();
    clear_content();
    search_field = nullptr;
    coin_list = nullptr;
    keyboard = nullptr;
    lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(screen_content, sc(8), 0);
    lv_obj_set_scrollbar_mode(screen_content, LV_SCROLLBAR_MODE_AUTO);

    const bool wide = landscape_panel();
    if (!wide) {
      nothing_dot_band(screen_content, 10);
      nothing_micro_label(screen_content, tr("RECEIVE", "收款"), true);
      nothing_rule(screen_content);
    }

    lv_obj_t *details = screen_content;
    lv_obj_t *row = screen_content;
    if (wide) {
      row = lv_obj_create(screen_content);
      set_clean_container(row);
      lv_obj_set_size(row, LV_PCT(100), LV_SIZE_CONTENT);
      lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    }

    // The QR code is the fast path; the text below it is the path that works when
    // a camera does not. Neither is optional on a wallet.
    lv_obj_t *qr_row = lv_obj_create(row);
    lv_obj_update_layout(screen_content);
    set_clean_container(qr_row);
    lv_obj_clear_flag(qr_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_size(qr_row, wide ? lv_obj_get_content_height(screen_content) : LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(qr_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(qr_row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    const char *qr_level = nullptr;
    lv_obj_t *qr = nothing_qr(qr_row, address, &qr_level);
    if (wide) {
      details = lv_obj_create(row);
      set_clean_container(details);
      lv_obj_set_flex_grow(details, 1);
      lv_obj_set_height(details, LV_SIZE_CONTENT);
      lv_obj_set_flex_flow(details, LV_FLEX_FLOW_COLUMN);
      lv_obj_set_style_pad_row(details, 1, 0);
      focus_reader();
    }
    lv_obj_t *network_label = lv_label_create(details);
    lv_obj_set_width(network_label, LV_PCT(100));
    lv_label_set_text_fmt(network_label, tr("Receive / %s", "收款 / %s"), network);
    if (qr == nullptr)
    {
      lv_obj_add_flag(qr_row, LV_OBJ_FLAG_HIDDEN);
      nothing_micro_label(details, tr("QR unavailable; use full address", "二维码不可用；请核对完整地址"), true);
    }
    else if (!wide && qr_level != nullptr)
    {
      char caption[16];
      snprintf(caption, sizeof(caption), "QR %s", qr_level);
      nothing_micro_label(screen_content, caption, false);
    }

    char grouped[192];
    const bool grouped_fits = nothing_group_address(grouped, sizeof(grouped), address);
    lv_obj_t *address_label = lv_label_create(details);
    lv_label_set_long_mode(address_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(address_label, LV_PCT(100));
    // Long addresses still have to be readable in full when the QR cannot fit.
    lv_label_set_text(address_label, grouped_fits ? grouped : address);
    lv_obj_set_style_text_color(address_label, theme_fg(), 0);
    lv_obj_set_style_border_width(address_label, 1, 0);
    lv_obj_set_style_border_color(address_label, theme_accent(), 0);
    lv_obj_set_style_radius(address_label, sc(8), 0);
    lv_obj_set_style_pad_all(address_label, sc(8), 0);
    lv_obj_set_style_text_letter_space(address_label, 1, 0);

    nothing_micro_label(details, path, false);
    lv_obj_t *warning = lv_label_create(screen_content);
    lv_label_set_long_mode(warning, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(warning, LV_PCT(100));
    lv_label_set_text(warning,
                      tr("Compare every character with the sending wallet before receiving.", "收款前，请与付款钱包逐字核对完整地址。"));
    lv_obj_set_style_text_color(warning, theme_fg(), 0);

    current_page = Page::Home;
    wallet_ui_set_status(tr("Verify address   Prev / Next scroll", "核对地址  上 / 下滚动  返回"));
    return true;
#else
    (void)network;
    (void)address;
    (void)path;
    return false;
#endif
  }

  bool wallet_ui_show_otp(const char *issuer, const char *account, const char *code,
                          uint64_t expires_unix)
  {
#if HEXWALLET_ENABLE_LVGL
    if (!initialized || screen_content == nullptr || !board_has_display() ||
        issuer == nullptr || account == nullptr || code == nullptr)
      return false;
    const size_t length = strlen(code);
    if (length != 6 && length != 8)
      return false;
    for (size_t i = 0; i < length; ++i)
      if (code[i] < '0' || code[i] > '9')
        return false;
    clear_content();
    decision_callback = nullptr;
    board_display_prepare_review();
    lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
    current_page = Page::Home;
    nothing_micro_label(screen_content, tr("AUTHENTICATOR", "动态验证码"), true);
    nothing_rule(screen_content);
    const char *labels[] = {issuer, account};
    for (const char *text : labels)
    {
      lv_obj_t *label = lv_label_create(screen_content);
      lv_obj_set_width(label, LV_PCT(100));
      lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
      lv_label_set_text(label, text);
    }
    memcpy(otp_text, code, length + 1);
    lv_obj_t *label = lv_label_create(screen_content);
    lv_label_set_text_static(label, otp_text);
    lv_obj_set_style_text_letter_space(label, 2, 0);
    char expiry[64];
    snprintf(expiry, sizeof(expiry), tr("Valid before Unix %llu", "到期 Unix 时间 %llu"), static_cast<unsigned long long>(expires_unix));
    nothing_micro_label(screen_content, expiry, false);
    nothing_micro_label(screen_content, tr("Session account", "本次会话账户"), false);
    if (landscape_panel()) focus_reader();
    otp_visible = true;
    wallet_ui_set_status(tr("Device-only code   Back to hide", "验证码仅在本机显示  返回隐藏"));
    return true;
#else
    (void)issuer;
    (void)account;
    (void)code;
    (void)expires_unix;
    return false;
#endif
  }

  void wallet_ui_hide_otp()
  {
#if HEXWALLET_ENABLE_LVGL
    if (otp_visible)
      wallet_ui_show_catalog();
#endif
  }

  void wallet_ui_show_transaction(const WalletUiTransactionReview &review)
  {
    review_seal_valid = false;
#if HEXWALLET_ENABLE_LVGL
    decision_pending = false;
    if (!initialized || screen_content == nullptr ||
        review.output_count > kWalletUiMaxTransactionOutputs ||
        (review.approval_code == nullptr && !review.show_decision_buttons))
    {
      decision_callback = nullptr;
      if (initialized && screen_content) wallet_ui_show_refusal(tr("Invalid transaction review.", "交易审阅数据无效。"));
      return;
    }
    if (!review.show_decision_buttons)
      decision_callback = nullptr;
    decision_pending = false;
    board_display_prepare_review();
    clear_content();
    search_field = nullptr;
    coin_list = nullptr;
    keyboard = nullptr;
    lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(screen_content, landscape_panel() ? 2 : 6, 0);
    lv_obj_set_scrollbar_mode(screen_content, LV_SCROLLBAR_MODE_AUTO);

    if (!landscape_panel()) nothing_dot_band(screen_content, 6);
    lv_obj_t *title_row = lv_obj_create(screen_content);
    set_clean_container(title_row);
    lv_obj_clear_flag(title_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_size(title_row, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(title_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(title_row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(title_row, sc(8), 0);
    if (!landscape_panel()) coin_icon_view(title_row, review.network == nullptr ? "" : review.network);
    RenderedReviewLines lines;
    lv_obj_t *title = lv_label_create(title_row);
    lv_obj_set_flex_grow(title, 1);
    lv_label_set_long_mode(title, LV_LABEL_LONG_WRAP);
    char line[192];
    int formatted = snprintf(line, sizeof(line), tr("%s TRANSACTION", "%s 交易审阅"), review.network == nullptr ? "" : review.network);
    lines.valid = formatted >= 0 && static_cast<size_t>(formatted) < sizeof(line);
    lv_label_set_text(title, line);
    lines.add(title);
    lv_obj_set_style_text_color(title, theme_accent(), 0);
    lv_obj_set_style_text_letter_space(title, sc(2), 0);
    nothing_rule(screen_content);

    for (size_t index = 0; index < review.output_count; ++index)
    {
      const WalletUiTransactionOutput &output = review.outputs[index];
      if (output.amount_text != nullptr)
      {
        formatted = snprintf(line, sizeof(line), "%u  %s", static_cast<unsigned>(index + 1),
                             output.amount_text);
      }
      else
      {
        formatted = snprintf(line, sizeof(line), "%u  %llu sat", static_cast<unsigned>(index + 1),
                             static_cast<unsigned long long>(output.value));
      }
      lines.valid = lines.valid && formatted >= 0 && static_cast<size_t>(formatted) < sizeof(line);
      lv_obj_t *label = lv_label_create(screen_content);
      lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(label, LV_PCT(100));
      lv_label_set_text(label, line);
      lines.add(label);
      const char *fields[] = {output.address, output.ownership_is_label ? localize(output.ownership) : output.ownership};
      for (const char *text : fields)
      {
        if (text == nullptr)
          continue;
        lv_obj_t *field = lv_label_create(screen_content);
        lv_label_set_long_mode(field, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(field, LV_PCT(100));
        lv_label_set_text(field, text);
        lines.add(field);
      }
      if (output.details != nullptr)
      {
        lv_obj_t *details = lv_label_create(screen_content);
        lv_label_set_long_mode(details, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(details, LV_PCT(100));
        lv_label_set_text(details, output.details);
        lines.add(details);
      }
    }
    if (review.fee_text != nullptr)
    {
      formatted = snprintf(line, sizeof(line), "%s  %s", review.fee_label == nullptr ? tr("MAX FEE", "最高费用") : localize(review.fee_label), review.fee_text);
    }
    else
    {
      formatted = snprintf(line, sizeof(line), tr("FEE  %llu sat  |  %llu sat/vB", "费用 %llu sat | %llu sat/vB"),
                           static_cast<unsigned long long>(review.fee),
                           static_cast<unsigned long long>(review.fee_rate));
    }
    lv_obj_t *fee = lv_label_create(screen_content);
    lines.valid = lines.valid && formatted >= 0 && static_cast<size_t>(formatted) < sizeof(line);
    lv_label_set_long_mode(fee, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(fee, LV_PCT(100));
    lv_label_set_text(fee, line);
    lines.add(fee);
    lv_obj_set_style_text_color(fee, theme_warn(), 0);

    if (review.total_text != nullptr)
    {
      formatted = snprintf(line, sizeof(line), tr("TOTAL  %s", "合计 %s"), review.total_text);
      lines.valid = lines.valid && formatted >= 0 && static_cast<size_t>(formatted) < sizeof(line);
      lv_obj_t *total = lv_label_create(screen_content);
      lv_label_set_long_mode(total, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(total, LV_PCT(100));
      lv_label_set_text(total, line);
      lines.add(total);
    }
    if (review.note != nullptr)
    {
      lv_obj_t *note = lv_label_create(screen_content);
      lv_label_set_long_mode(note, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(note, LV_PCT(100));
      lv_label_set_text(note, localize(review.note));
      lines.add(note);
      lv_obj_set_style_text_color(note, theme_warn(), 0);
    }

    if (review.approval_code != nullptr)
    {
      formatted = snprintf(line, sizeof(line), tr("CONFIRM  %s", "确认码 %s"), review.approval_code);
      lines.valid = lines.valid && formatted >= 0 && static_cast<size_t>(formatted) < sizeof(line);
      lv_obj_t *confirmation = lv_label_create(screen_content);
      lv_obj_set_width(confirmation, LV_PCT(100));
      lv_label_set_text(confirmation, line);
      lines.add(confirmation);
      lv_obj_set_style_text_color(confirmation, theme_fg(), 0);
    }
    if (review.show_decision_buttons)
    {
      // A keypad must be able to scroll every line, including labels taller
      // than the viewport, before moving to the decision buttons.
      if (lv_group_t *group = lv_group_get_default())
      {
        lv_group_add_obj(group, screen_content);
        lv_group_focus_obj(screen_content);
        lv_obj_add_flag(screen_content, LV_OBJ_FLAG_SCROLL_WITH_ARROW);
      }
      lv_obj_t *actions = lv_obj_create(screen_content);
      lv_obj_set_width(actions, LV_PCT(100));
      lv_obj_set_height(actions, sc(52));
      set_clean_container(actions);
      lv_obj_set_flex_flow(actions, LV_FLEX_FLOW_ROW);
      lv_obj_set_flex_align(actions, LV_FLEX_ALIGN_SPACE_EVENLY,
                            LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
      lv_obj_set_style_pad_column(actions, sc(8), 0);

      lv_obj_t *reject = lv_button_create(actions);
      focus_ink(reject);
      lv_obj_set_height(reject, sc(44));
      lv_obj_set_flex_grow(reject, 1);
      lv_obj_add_event_cb(reject, reject_event, LV_EVENT_CLICKED, nullptr);
      lv_obj_add_event_cb(reject, reject_event, LV_EVENT_CANCEL, nullptr);
      lv_obj_t *reject_label = lv_label_create(reject);
      lv_obj_set_style_text_font(reject_label, ui_font(), 0);
      lv_label_set_text(reject_label, tr("REJECT", "拒绝"));
      lines.add(reject_label);
      lv_obj_center(reject_label);

      lv_obj_t *approve = lv_button_create(actions);
      focus_ink(approve);
      lv_obj_set_height(approve, sc(44));
      lv_obj_set_flex_grow(approve, 1);
      lv_obj_add_event_cb(approve, approve_event, landscape_panel() ? LV_EVENT_LONG_PRESSED : LV_EVENT_CLICKED, nullptr);
      lv_obj_add_event_cb(approve, reject_event, LV_EVENT_CANCEL, nullptr);
      lv_obj_t *approve_label = lv_label_create(approve);
      lv_obj_set_style_text_font(approve_label, ui_font(), 0);
      lv_label_set_text(approve_label, landscape_panel() ? tr("HOLD TO APPROVE", "长按批准") : tr("APPROVE", "批准"));
      lines.add(approve_label);
      lv_obj_center(approve_label);
    }
    focus_reader();
    finish_review_seal(lines);
    if (!review_seal_valid)
      decision_callback = nullptr;
    wallet_ui_set_status(!review_seal_valid ? tr("REVIEW ERROR - cannot authorize", "审阅错误，无法批准") :
                         review.show_decision_buttons ? tr("Prev / Next scroll   OK actions   Back reject", "上 / 下滚动  确定选择  返回拒绝") : tr("Prev / Next scroll   Back to close", "上 / 下滚动  返回关闭"));
#else
    (void)review;
#endif
  }

  void wallet_ui_show_refusal(const char *reason)
  {
#if HEXWALLET_ENABLE_LVGL
    if (!initialized || !reason) return;
    clear_content();
    current_page = Page::Home;
    decision_callback = nullptr;
    board_display_prepare_review();
    lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
    page_text(tr("Request rejected", "请求已拒绝"));
    nothing_rule(screen_content);
    page_text(localize(reason));
    focus_reader();
    wallet_ui_set_status(tr("No signature   Back to home", "未签名  返回主页"));
#else
    (void)reason;
#endif
  }

  void wallet_ui_show_pairing(uint32_t code, const char *fingerprint)
  {
    review_seal_valid = false;
#if HEXWALLET_ENABLE_LVGL
    if (!initialized || screen_content == nullptr)
      return;
    if (code > 999999 || !fingerprint || !*fingerprint ||
        !renderable_text(fingerprint, ui_font())) {
      wallet_ui_show_refusal(tr("Invalid phone pairing data.", "手机配对数据无效。"));
      return;
    }
    decision_pending = false;
    board_display_prepare_review();
    clear_content();
    search_field = nullptr;
    coin_list = nullptr;
    keyboard = nullptr;
    lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(screen_content, sc(10), 0);

    lv_obj_t *title = lv_label_create(screen_content);
    lv_label_set_text(title, tr("PAIR PHONE", "配对手机"));
    lv_obj_set_style_text_color(title, theme_accent(), 0);

    char line[128];
    snprintf(line, sizeof(line), tr("CODE  %06lu", "配对码 %06lu"),
             static_cast<unsigned long>(code % 1000000UL));
    lv_obj_t *code_label = lv_label_create(screen_content);
    lv_label_set_text(code_label, line);
    lv_obj_set_style_text_color(code_label, theme_fg(), 0);

    page_text(tr("Phone fingerprint", "手机指纹"));
    lv_obj_t *fingerprint_label = lv_label_create(screen_content);
    lv_label_set_long_mode(fingerprint_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(fingerprint_label, LV_PCT(100));
    lv_label_set_text(fingerprint_label, fingerprint == nullptr ? "?" : fingerprint);
    page_text(tr("Compare the code and complete fingerprint with your phone.", "请与手机核对配对码和完整指纹。"));

    lv_obj_t *actions = lv_obj_create(screen_content);
    lv_obj_set_width(actions, LV_PCT(100));
    lv_obj_set_height(actions, sc(52));
    set_clean_container(actions);
    lv_obj_set_flex_flow(actions, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(actions, LV_FLEX_ALIGN_SPACE_EVENLY,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(actions, sc(8), 0);

    lv_obj_t *reject = lv_button_create(actions);
    focus_ink(reject);
    lv_obj_set_height(reject, sc(44));
    lv_obj_set_flex_grow(reject, 1);
    lv_obj_add_event_cb(reject, reject_event, LV_EVENT_CLICKED, nullptr);
    lv_obj_add_event_cb(reject, reject_event, LV_EVENT_CANCEL, nullptr);
    lv_obj_t *reject_label = lv_label_create(reject);
    lv_obj_set_style_text_font(reject_label, ui_font(), 0);
    lv_label_set_text(reject_label, tr("REJECT", "拒绝"));
    lv_obj_center(reject_label);

    lv_obj_t *approve = lv_button_create(actions);
    focus_ink(approve);
    lv_obj_set_height(approve, sc(44));
    lv_obj_set_flex_grow(approve, 1);
    lv_obj_add_event_cb(approve, approve_event, landscape_panel() ? LV_EVENT_LONG_PRESSED : LV_EVENT_CLICKED, nullptr);
    lv_obj_add_event_cb(approve, reject_event, LV_EVENT_CANCEL, nullptr);
    lv_obj_t *approve_label = lv_label_create(approve);
    lv_obj_set_style_text_font(approve_label, ui_font(), 0);
    lv_label_set_text(approve_label, landscape_panel() ? tr("HOLD TO PAIR", "长按配对") : tr("APPROVE", "批准"));
    lv_obj_center(approve_label);
    pairing_page = true;
    focus_reader();
    wallet_ui_set_status(tr("Verify phone   OK actions   Back reject", "核对手机  确定选择  返回拒绝"));
#else
    (void)code;
    (void)fingerprint;
#endif
  }

  void wallet_ui_service()
  {
#if HEXWALLET_ENABLE_LVGL
    if (!initialized)
      return;
    if (decision_pending && (!decision_value || board_display_review_ready()))
    {
      decision_pending = false;
      WalletUiDecisionCallback callback = decision_callback;
      decision_callback = nullptr;
      const bool value = decision_value;
      if (callback != nullptr)
        callback(value);
    }
    if (review_seal_valid && !review_seal.displayed && board_display_review_ready())
      review_seal_mark_displayed(&review_seal);

    if (companion_canvas != nullptr && !review_seal_valid &&
        (!eink_panel || (board_partial_refresh_supported() &&
                         lv_display_get_inactive_time(nullptr) < 30000U)) &&
        board_display_review_ready() && mascot_take_animation_tick(millis(), companion_rendered.mood))
    {
      MascotInputs animation_inputs = {};
      animation_inputs.phone_linked = wallet_link_service_connected();
      animation_inputs.battery_mv = board_battery_millivolts();
      render_companion(mascot_snapshot(animation_inputs, millis()));
    }

    const unsigned long now = millis();
    if (last_service_ms != 0 && (now - last_service_ms) < 16UL)
      return;
    last_service_ms = now;
    board_display_service();
#endif
  }

  bool wallet_ui_review_seal_code(char out[9])
  {
    if (out == nullptr || !review_seal_valid)
      return false;
    review_seal_code(review_seal, out);
    return true;
  }

  bool wallet_ui_review_digest(uint8_t out[kReviewSealSize])
  {
    if (!out || !review_seal_valid) return false;
    memcpy(out, review_seal.digest, kReviewSealSize);
    return true;
  }

  bool wallet_ui_review_authorize(const uint8_t expected[kReviewSealSize])
  {
    return expected && review_seal_valid && memcmp(expected, review_seal.digest, kReviewSealSize) == 0 &&
           wallet_ui_review_authorize();
  }

  bool wallet_ui_review_authorize()
  {
    if (!review_seal_valid || !board_display_review_ready())
      return false;
    if (!review_seal.displayed)
    {
      review_seal_mark_displayed(&review_seal);
    }
    return review_seal_authorize_rendered(&review_seal, millis());
  }

}
