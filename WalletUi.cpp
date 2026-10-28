#include "WalletUi.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "Mascot.h"
#include "MascotArt.h"
#include "QrCode.h"
#include "WalletBoardPort.h"
#include "WalletCatalog.h"

#if HEXWALLET_ENABLE_LVGL
#include <lvgl.h>
#endif

namespace hexwallet
{
  namespace
  {
#if HEXWALLET_ENABLE_LVGL

    bool initialized = false;
    bool session_authenticated = false;
    bool eink_panel = false;
    uint8_t eink_colors = 1;
    unsigned long last_service_ms = 0;
    WalletUiDecisionCallback decision_callback = nullptr;
    bool decision_pending = false;
    bool decision_value = false;

    void approve_event(lv_event_t *)
    {
      if (decision_callback != nullptr && board_display_review_ready())
      {
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

    static lv_color_t theme_fg() { return lv_color_hex(eink_panel ? 0x000000 : 0x161916); }
    static lv_color_t theme_bg() { return lv_color_hex(eink_panel ? 0xffffff : 0xf4f5f2); }
    static lv_color_t theme_accent()
    {
      if (!eink_panel)
        return lv_color_hex(0x155b2a);
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
    static lv_color_t theme_badge_on() { return lv_color_hex(eink_panel ? 0xffffff : 0xd9eadb); }
    static lv_color_t theme_badge_off() { return lv_color_hex(eink_panel ? 0xffffff : 0xf0d8d5); }

    // lv_color32_t stores its channels BGR(A); the theme works in RGB, so convert
    // explicitly rather than relying on initialiser order.
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

    // Defined below the catalog view, which is the first screen to draw it.
    void nothing_companion(lv_obj_t *parent, const MascotSnapshot &snapshot);

    void create_catalog_view();
    void nothing_companion(lv_obj_t *parent, const MascotSnapshot &snapshot);

    void set_clean_container(lv_obj_t *object)
    {
      lv_obj_set_style_bg_opa(object, LV_OPA_TRANSP, 0);
      lv_obj_set_style_border_width(object, 0, 0);
      lv_obj_set_style_pad_all(object, 0, 0);
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
      return label;
    }

    // Inserts a space every four characters so a human can verify an address in
    // groups. The address itself is unchanged; this is display-only.
    void nothing_group_address(char *out, size_t capacity, const char *address)
    {
      if (out == nullptr || capacity < 2)
        return;
      size_t written = 0;
      size_t count = 0;
      for (const char *cursor = address; cursor != nullptr && *cursor != '\0'; ++cursor)
      {
        if (written + 3 > capacity)
          break;
        out[written++] = *cursor;
        ++count;
        if ((count % 4) == 0 && cursor[1] != '\0')
          out[written++] = ' ';
      }
      out[written] = '\0';
    }

    // QR code as an LVGL canvas in 1bpp (I1) format. The canvas stores exactly the
    // panel-side bit order LVGL expects (MSB first), so no conversion is needed on
    // either the colour or the e-paper flush path.
    //
    // The encoder output and the pixel scratch are static: a screen shows one QR
    // code, and 3.3 KiB of stack is not something this firmware hands out per view.
    lv_obj_t *nothing_qr(lv_obj_t *parent, const char *text)
    {
      if (parent == nullptr || text == nullptr)
        return nullptr;
      const size_t length = strlen(text);
      const size_t capacity = qr_capacity(kQrMaxVersion, QrEcc::Low);
      if (length == 0 || length > capacity)
        return nullptr;

      static QrCode code;
      if (!qr_encode(reinterpret_cast<const uint8_t *>(text), length, QrEcc::Low,
                     &code))
      {
        return nullptr;
      }
      const lv_coord_t side = static_cast<lv_coord_t>(code.size);
      const uint32_t stride = lv_draw_buf_width_to_stride(side, LV_COLOR_FORMAT_I1);
      const size_t bytes = static_cast<size_t>(stride) * code.size;
      static LV_ATTRIBUTE_MEM_ALIGN uint8_t pixels[64 * 8];
      if (bytes > sizeof(pixels))
        return nullptr;
      memset(pixels, 0, bytes);
      for (uint8_t row = 0; row < code.size; ++row)
      {
        for (uint8_t column = 0; column < code.size; ++column)
        {
          if (code.modules[static_cast<size_t>(row) * code.size + column] == 0)
          {
            continue;
          }
          pixels[row * stride + (column / 8)] |= static_cast<uint8_t>(0x80U >> (column % 8));
        }
      }

      lv_obj_t *canvas = lv_canvas_create(parent);
      if (canvas == nullptr)
        return nullptr;
      lv_canvas_set_buffer(canvas, pixels, side, side, LV_COLOR_FORMAT_I1);
      // I1 palette: index 0 is the paper, index 1 is the ink. There is no grey on
      // this panel, and a dither pattern here would destroy module edges.
      lv_canvas_set_palette(canvas, 0, to_color32(theme_bg()));
      lv_canvas_set_palette(canvas, 1, to_color32(theme_fg()));
      // Integer zoom only: a module that lands on a half pixel turns a scannable
      // code into a grey smear on e-paper.
      const lv_coord_t available = static_cast<lv_coord_t>(board_display_width() - sc(16));
      lv_coord_t zoom = available / side;
      if (zoom < 1)
        zoom = 1;
      if (zoom > 1)
        lv_image_set_scale(canvas, static_cast<uint32_t>(zoom) * 256U);
      return canvas;
    }

    void coin_clicked(lv_event_t *event)
    {
      const size_t index = reinterpret_cast<size_t>(lv_event_get_user_data(event));
      WalletCatalogEntry entry;
      if (!wallet_catalog_at_sorted(index, &entry) || status_label == nullptr)
        return;
      // Never truncate the limitations at the end of a capability description.
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
      lv_obj_clean(screen_content);
      lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
      lv_obj_set_style_pad_row(screen_content, 8, 0);

      // The companion greets the user on the home screen, the way a Flipper shows
      // its dolphin - but event-driven: its mood only changes when something
      // happened (approve, reject, long idle), so it never forces an extra refresh.
      MascotInputs companion_inputs = {};
      companion_inputs.phone_linked = true;
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

    // ---------------------------------------------------------------------------
    // Companion: a chibi whale, drawn as 1bpp art
    //
    // Frames live in MascotArt.cpp as character maps so the drawing is edited as
    // art, not as hex. This function only packs the current frame into an I1
    // canvas and lays out mood, level, bond meter, reminder and counters.
    // ---------------------------------------------------------------------------
    // FEED / PET / PLAY. The buttons are plain widgets, so they work with a
    // touch panel and, through the keypad input device, with the four physical
    // buttons on a board that has no touch at all.
    void companion_action_event(lv_event_t *event)
    {
      const intptr_t action = reinterpret_cast<intptr_t>(lv_event_get_user_data(event));
      const uint32_t now = millis();
      if (action == 0) mascot_feed(now);
      else if (action == 1) mascot_pet(now);
      else mascot_play(now);
      create_catalog_view();
    }

    void nothing_companion(lv_obj_t *parent, const MascotSnapshot &snapshot)
    {
      lv_obj_t *row = lv_obj_create(parent);
      set_clean_container(row);
      lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_size(row, LV_PCT(100), LV_SIZE_CONTENT);
      lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
      lv_obj_set_style_pad_column(row, sc(8), 0);

      static LV_ATTRIBUTE_MEM_ALIGN uint8_t pixels[kMascotArtBytes];
      const uint8_t frame = mascot_frame_index(millis());
      if (mascot_art_pack(snapshot.mood, frame, pixels, sizeof(pixels)))
      {
        lv_obj_t *portrait = lv_canvas_create(row);
        if (portrait != nullptr)
        {
          lv_canvas_set_buffer(portrait, pixels, kMascotArtSize, kMascotArtSize,
                               LV_COLOR_FORMAT_I1);
          lv_canvas_set_palette(portrait, 0, to_color32(theme_bg()));
          lv_canvas_set_palette(portrait, 1, to_color32(theme_fg()));
          // Integer zoom only: a 1bpp sprite scaled by a fraction turns into
          // grey mush on e-paper.
          const lv_coord_t target = static_cast<lv_coord_t>(sc(52));
          lv_coord_t zoom = target / static_cast<lv_coord_t>(kMascotArtSize);
          if (zoom < 1) zoom = 1;
          if (zoom > 3) zoom = 3;
          if (zoom > 1) lv_image_set_scale(portrait, static_cast<uint32_t>(zoom) * 256U);
        }
      }

      lv_obj_t *info = lv_obj_create(row);
      set_clean_container(info);
      lv_obj_clear_flag(info, LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_flex_grow(info, 1);
      lv_obj_set_flex_flow(info, LV_FLEX_FLOW_COLUMN);
      lv_obj_set_style_pad_row(info, sc(3), 0);

      char line[64];
      snprintf(line, sizeof(line), "%s  LV%d", mascot_mood_name(snapshot.mood), snapshot.level);
      lv_obj_t *headline = lv_label_create(info);
      lv_label_set_text(headline, line);
      lv_obj_set_style_text_color(headline, theme_accent(), 0);
      lv_obj_set_style_text_letter_space(headline, sc(1), 0);

      // Bond as a segmented meter: filled blocks are progress inside the level,
      // empty ones are outline-only. On 1bpp blocks read better than a bar.
      lv_obj_t *meter = lv_obj_create(info);
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
        lv_obj_set_size(segment, sc(5), sc(4));
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

      snprintf(line, sizeof(line), "signed %u  rejected %u",
               static_cast<unsigned>(snapshot.stats.approvals),
               static_cast<unsigned>(snapshot.stats.rejections));
      lv_obj_t *actions = lv_obj_create(info);
      set_clean_container(actions);
      lv_obj_clear_flag(actions, LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_size(actions, LV_PCT(100), LV_SIZE_CONTENT);
      lv_obj_set_flex_flow(actions, LV_FLEX_FLOW_ROW);
      lv_obj_set_style_pad_column(actions, sc(4), 0);
      static const char *const kActionLabels[3] = {"FEED", "PET", "PLAY"};
      for (intptr_t index = 0; index < 3; ++index)
      {
        lv_obj_t *button = lv_button_create(actions);
        lv_obj_set_height(button, static_cast<lv_coord_t>(sc(22)));
        lv_obj_set_flex_grow(button, 1);
        lv_obj_set_style_radius(button, sc(4), 0);
        lv_obj_set_style_border_width(button, 1, 0);
        lv_obj_set_style_border_color(button, theme_fg(), 0);
        lv_obj_set_style_bg_opa(button, LV_OPA_TRANSP, 0);
        lv_obj_add_event_cb(button, companion_action_event, LV_EVENT_CLICKED,
                            reinterpret_cast<void *>(index));
        lv_obj_t *text = lv_label_create(button);
        lv_label_set_text(text, kActionLabels[index]);
        lv_obj_set_style_text_letter_space(text, sc(1), 0);
        lv_obj_center(text);
      }

            lv_obj_t *stats = lv_label_create(info);
      lv_label_set_text(stats, line);
      lv_obj_set_style_text_color(stats, theme_fg(), 0);

      const char *reminder = mascot_reminder_text(snapshot.reminder);
      if (reminder != nullptr && reminder[0] != '\0')
      {
        lv_obj_t *hint = lv_label_create(info);
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

  bool wallet_ui_ready()
  {
#if HEXWALLET_ENABLE_LVGL
    return initialized;
#else
    return false;
#endif
  }

  void wallet_ui_show_port_error()
  {
#if HEXWALLET_ENABLE_LVGL
    lv_obj_t *screen = lv_screen_active();
    if (screen == nullptr)
      return;
    lv_obj_clean(screen);
    lv_obj_set_style_bg_color(screen, lv_color_white(), 0);
    lv_obj_t *message = lv_label_create(screen);
    lv_label_set_text(message, "DISPLAY PORT ERROR");
    lv_obj_center(message);
#endif
  }

  void wallet_ui_set_authenticated(bool authenticated)
  {
#if HEXWALLET_ENABLE_LVGL
    session_authenticated = authenticated;
    if (!initialized || state_label == nullptr)
      return;
    lv_label_set_text(state_label, authenticated ? "UNLOCKED" : "LOCKED");
    lv_obj_set_style_bg_color(state_label, authenticated ? theme_badge_on() : theme_badge_off(), 0);
    lv_obj_set_style_text_color(state_label, authenticated ? theme_accent() : theme_warn(), 0);
    wallet_ui_set_status(authenticated ? "Authenticated session active" : "Authentication required");
#else
    (void)authenticated;
#endif
  }

  void wallet_ui_set_status(const char *status)
  {
#if HEXWALLET_ENABLE_LVGL
    if (initialized && status_label != nullptr && status != nullptr)
      lv_label_set_text(status_label, status);
#else
    (void)status;
#endif
  }

  // Long field-arithmetic steps (Bulletproofs+ verification takes seconds on the
  // MCU) run on the same task as the UI, so the panel would otherwise keep the
  // previous screen until they finish. Flush the status line first.
  void wallet_ui_show_busy(const char *status)
  {
#if HEXWALLET_ENABLE_LVGL
    if (!initialized)
      return;
    wallet_ui_set_status(status);
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
#if HEXWALLET_ENABLE_LVGL
    if (!initialized)
      return;
    create_catalog_view();
    wallet_ui_set_status(session_authenticated ? "Authenticated session active" : "Authentication required");
#endif
  }

  bool wallet_ui_show_address(const char *network, const char *address,
                              const char *path)
  {
#if HEXWALLET_ENABLE_LVGL
    if (!initialized || screen_content == nullptr || !board_has_display() ||
        network == nullptr || address == nullptr || path == nullptr)
      return false;
    decision_callback = nullptr;
    decision_pending = false;
    board_display_prepare_review();
    lv_obj_clean(screen_content);
    search_field = nullptr;
    coin_list = nullptr;
    keyboard = nullptr;
    lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(screen_content, sc(8), 0);
    lv_obj_set_scrollbar_mode(screen_content, LV_SCROLLBAR_MODE_AUTO);

    nothing_dot_band(screen_content, 10);
    nothing_micro_label(screen_content, "RECEIVE", true);
    nothing_rule(screen_content);

    lv_obj_t *network_label = lv_label_create(screen_content);
    lv_label_set_text(network_label, network);
    lv_obj_set_style_text_color(network_label, theme_fg(), 0);

    // The QR code is the fast path; the text below it is the path that works when
    // a camera does not. Neither is optional on a wallet.
    lv_obj_t *qr_row = lv_obj_create(screen_content);
    set_clean_container(qr_row);
    lv_obj_clear_flag(qr_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_size(qr_row, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(qr_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(qr_row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    lv_obj_t *qr = nothing_qr(qr_row, address);
    if (qr == nullptr)
    {
      // Refusing is better than drawing a QR that encodes something else or a
      // version the panel cannot carry.
      nothing_micro_label(screen_content, "QR UNAVAILABLE - USE ADDRESS", true);
    }

    char grouped[192];
    nothing_group_address(grouped, sizeof(grouped), address);
    lv_obj_t *address_label = lv_label_create(screen_content);
    lv_label_set_long_mode(address_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(address_label, LV_PCT(100));
    lv_label_set_text(address_label, grouped);
    lv_obj_set_style_text_color(address_label, theme_fg(), 0);
    lv_obj_set_style_border_width(address_label, 1, 0);
    lv_obj_set_style_border_color(address_label, theme_accent(), 0);
    lv_obj_set_style_radius(address_label, sc(8), 0);
    lv_obj_set_style_pad_all(address_label, sc(8), 0);
    // Addresses are compared character by character, so the tracking has to be
    // loose enough to read and tight enough to fit 128 px.
    lv_obj_set_style_text_letter_space(address_label, 1, 0);

    nothing_micro_label(screen_content, path, false);
    lv_obj_t *warning = lv_label_create(screen_content);
    lv_label_set_long_mode(warning, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(warning, LV_PCT(100));
    lv_label_set_text(warning,
                      "Compare every character with the sending wallet before receiving.");
    lv_obj_set_style_text_color(warning, theme_fg(), 0);

    wallet_ui_set_status("Verify receive address on this device");
    return true;
#else
    (void)network;
    (void)address;
    (void)path;
    return false;
#endif
  }

  void wallet_ui_show_transaction(const WalletUiTransactionReview &review)
  {
#if HEXWALLET_ENABLE_LVGL
    if (!initialized || screen_content == nullptr ||
        (review.approval_code == nullptr && !review.show_decision_buttons))
    {
      return;
    }
    if (!review.show_decision_buttons)
      decision_callback = nullptr;
    decision_pending = false;
    board_display_prepare_review();
    lv_obj_clean(screen_content);
    search_field = nullptr;
    coin_list = nullptr;
    keyboard = nullptr;
    lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(screen_content, 6, 0);
    lv_obj_set_scrollbar_mode(screen_content, LV_SCROLLBAR_MODE_AUTO);

    nothing_dot_band(screen_content, 6);
    lv_obj_t *title = lv_label_create(screen_content);
    char line[192];
    snprintf(line, sizeof(line), "%s TRANSACTION", review.network == nullptr ? "" : review.network);
    lv_label_set_text(title, line);
    lv_obj_set_style_text_color(title, theme_accent(), 0);
    lv_obj_set_style_text_letter_space(title, sc(2), 0);
    nothing_rule(screen_content);

    for (size_t index = 0; index < review.output_count; ++index)
    {
      const WalletUiTransactionOutput &output = review.outputs[index];
      if (output.amount_text != nullptr)
      {
        snprintf(line, sizeof(line), "%u  %s", static_cast<unsigned>(index + 1),
                 output.amount_text);
      }
      else
      {
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
      for (const char *text : fields)
      {
        if (text == nullptr)
          continue;
        lv_obj_t *field = lv_label_create(screen_content);
        lv_label_set_long_mode(field, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(field, LV_PCT(100));
        lv_label_set_text(field, text);
      }
      if (output.details != nullptr)
      {
        lv_obj_t *details = lv_label_create(screen_content);
        lv_label_set_long_mode(details, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(details, LV_PCT(100));
        lv_label_set_text(details, output.details);
      }
    }
    if (review.fee_text != nullptr)
    {
      snprintf(line, sizeof(line), "%s  %s", review.fee_label == nullptr ? "MAX FEE" : review.fee_label, review.fee_text);
    }
    else
    {
      snprintf(line, sizeof(line), "FEE  %llu sat  |  %llu sat/vB",
               static_cast<unsigned long long>(review.fee),
               static_cast<unsigned long long>(review.fee_rate));
    }
    lv_obj_t *fee = lv_label_create(screen_content);
    lv_label_set_long_mode(fee, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(fee, LV_PCT(100));
    lv_label_set_text(fee, line);
    lv_obj_set_style_text_color(fee, theme_warn(), 0);

    if (review.total_text != nullptr)
    {
      snprintf(line, sizeof(line), "TOTAL  %s", review.total_text);
      lv_obj_t *total = lv_label_create(screen_content);
      lv_label_set_long_mode(total, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(total, LV_PCT(100));
      lv_label_set_text(total, line);
    }
    if (review.note != nullptr)
    {
      lv_obj_t *note = lv_label_create(screen_content);
      lv_label_set_long_mode(note, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(note, LV_PCT(100));
      lv_label_set_text(note, review.note);
      lv_obj_set_style_text_color(note, theme_warn(), 0);
    }

    if (review.approval_code != nullptr)
    {
      snprintf(line, sizeof(line), "CONFIRM  %s", review.approval_code);
      lv_obj_t *confirmation = lv_label_create(screen_content);
      lv_label_set_text(confirmation, line);
      lv_obj_set_style_text_color(confirmation, theme_fg(), 0);
    }
    if (review.show_decision_buttons)
    {
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

  void wallet_ui_show_pairing(uint32_t code, const char *fingerprint)
  {
#if HEXWALLET_ENABLE_LVGL
    if (!initialized || screen_content == nullptr)
      return;
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

  void wallet_ui_service()
  {
#if HEXWALLET_ENABLE_LVGL
    if (!initialized)
      return;
    if (decision_pending)
    {
      decision_pending = false;
      WalletUiDecisionCallback callback = decision_callback;
      const bool value = decision_value;
      if (callback != nullptr && (!value || board_display_review_ready()))
        callback(value);
    }
    const unsigned long now = millis();
    if (last_service_ms != 0 && (now - last_service_ms) < 16UL)
      return;
    last_service_ms = now;
    board_display_service();
#endif
  }

}
