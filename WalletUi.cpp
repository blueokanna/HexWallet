#include "WalletUi.h"

#include <Arduino.h>
#include <algorithm>
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
#include "WalletTextInput.h"
#include "WalletLayoutStore.h"
#include "WalletSession.h"
#include "WalletCustody.h"
#include "WalletNfcPort.h"
#include "WalletBackupJob.h"

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
    lv_obj_t *screen_header = nullptr;
    lv_obj_t *state_label = nullptr;
    lv_obj_t *status_label = nullptr;
    lv_obj_t *reader_target = nullptr;
    WalletTextInput text_input;
    lv_obj_t *input_matrix = nullptr, *input_preview = nullptr, *input_hint = nullptr;
    bool input_pinyin = false, input_candidates = false;
    size_t input_candidate_offset = 0;
    char input_keys[40][4] = {};
    char input_status[80] = {};
    const char *input_map[56] = {};
    char asset_query[65] = {};
    lv_obj_t *companion_stage = nullptr;
    lv_obj_t *companion_canvas = nullptr;
    lv_obj_t *companion_mood_label = nullptr;
    lv_obj_t *companion_hint_label = nullptr;
    MascotSnapshot companion_rendered = {};
    bool companion_has_frame = false;
    uint32_t companion_entered_ms = 0;
    // The LVGL I1 palette uses the eight bytes immediately before the pixels.
    struct alignas(16) CompanionStorage { uint8_t padding[8]; uint8_t canvas[8 + 64 * 16]; };
    CompanionStorage companion_storage{};
    auto &companion_pixels = companion_storage.canvas;
    enum class Page { Home, Create, Recover, CreateWords, RecoverWords, CreateKey, RecoverKey, RawKey, Scan, NfcImport, Controls, Catalog, Language, Asset, Companion, Settings, Layout, Search, WordsCount, WordsInput, WordsBackup, WordsConfirm, PassChoice, PassInput, PassConfirm, Enroll, KeyNetwork, KeyEntry, KeyCompression, KeyPass, KeyRepeat, KeyWorking, KeyResult, KeyVerify, TagWait };
    struct MnemonicSetup {
      char words[256];
      char passphrase[kBip39MaxPassphraseBytes + 1];
      MnemonicLanguage language;
      bool creating;
      unsigned count;
    };
    MnemonicSetup setup_words{};
    struct KeySetup {
      BackupOperation operation;
      BitcoinKeyNetwork network;
      bool compressed;
      char input[65];
      char password[kBip39MaxPassphraseBytes + 1];
      BitcoinBackupResult result;
    };
    KeySetup setup_key{};
    bool setup_transition = false;
    size_t keyboard_limit = 64;
    AssetLayout asset_layout = AssetLayout::List;
    const char *layout_error = nullptr;
    Page current_page = Page::Home;
    void open_page(Page page);

    lv_key_t review_key_remap(lv_indev_t *indev, lv_key_t key)
    {
      lv_group_t *group = lv_indev_get_group(indev);
      if (input_matrix && group && lv_group_get_focused(group) == input_matrix) {
        if (key == LV_KEY_NEXT) return LV_KEY_RIGHT;
        if (key == LV_KEY_PREV) return LV_KEY_LEFT;
      }
      if ((reading_page || review_seal_valid) && group != nullptr &&
          lv_group_get_focused(group) == (reader_target ? reader_target : screen_content))
      {
        if (key == LV_KEY_NEXT) return LV_KEY_DOWN;
        if (key == LV_KEY_PREV) return LV_KEY_UP;
      }
      return key;
    }

    void review_body_event(lv_event_t *event)
    {
      if ((current_page == Page::WordsBackup || (current_page == Page::KeyResult && setup_key.result.encrypted[0])) && reading_page && lv_event_get_code(event) == LV_EVENT_CLICKED &&
          lv_obj_get_scroll_bottom(screen_content) <= 0) {
        lv_group_focus_obj(lv_obj_get_child(screen_content, -1));
        return;
      }
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
      if (!setup_transition) {
        nfc_backup_cancel();
        bitcoin_backup_cancel();
        secure_zero(&setup_key, sizeof(setup_key));
        secure_zero(&setup_words, sizeof(setup_words));
        current_page = Page::Home;
      }
      secure_zero(input_status, sizeof(input_status));
      setup_transition = false;
      reading_page = false;
      pairing_page = false;
      otp_visible = false;
      volatile char *code = otp_text;
      for (size_t i = 0; i < sizeof(otp_text); ++i)
        code[i] = 0;
      forget_companion();
      review_seal_valid = false;
      decision_pending = false;
      reader_target = nullptr;
      // The label preview references editor-owned memory; erase it before the
      // objects disappear. Keys/candidates contain only public dictionary text.
      text_input.clear();
      input_matrix = input_preview = input_hint = nullptr;
      if (screen_content != nullptr)
      {
        if (screen_header) lv_obj_remove_flag(screen_header, LV_OBJ_FLAG_HIDDEN);
        if (status_label) lv_obj_remove_flag(status_label, LV_OBJ_FLAG_HIDDEN);
        lv_obj_set_style_pad_all(lv_screen_active(), landscape_panel() ? 3 : sc(12), 0);
        lv_group_remove_obj(screen_content);
        lv_obj_clean(screen_content);
        lv_obj_add_flag(screen_content, LV_OBJ_FLAG_SCROLLABLE);
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
      // Rasterize integer modules at their final size. The indexed image and
      // its quiet zone then occupy exactly the space LVGL assigns to the canvas.
      constexpr uint16_t max_side = 192;
      lv_obj_update_layout(parent);
      const lv_coord_t available = lv_obj_get_content_width(parent);
      const int budget = available < max_side ? available : max_side;
      // At this panel size a larger module is more useful than a denser H
      // symbol. Choose the largest integer module, then the strongest ECC.
      // Never emit a one-pixel module or reduce ECC below M.
      QrEcc chosen = QrEcc::Medium;
      int best_scale = 1;
      for (QrEcc ecc : {QrEcc::High, QrEcc::Quartile, QrEcc::Medium}) {
        for (uint8_t version = 1; version <= kQrMaxVersion; ++version) {
          if (qr_capacity(version, ecc) < length) continue;
          const int candidate = budget / (17 + 4 * version + 2 * kQrQuietZone);
          if (candidate > best_scale) { best_scale = candidate; chosen = ecc; }
          break;
        }
      }
      if (best_scale < 2 || !qr_encode(reinterpret_cast<const uint8_t *>(text), length, chosen, &code))
        return nullptr;
      if (level_name) *level_name = qr_ecc_name(chosen);
      const uint16_t modules = code.size + 2U * kQrQuietZone;
      const int scale = budget / modules;
      if (scale < 2) return nullptr;
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
      if (icon->size != bytes)
        return nullptr;
      auto *draw_buffer = lv_draw_buf_create(side, side, LV_COLOR_FORMAT_I1, stride);
      if (!draw_buffer) return nullptr;
      memset(draw_buffer->data, 0, bytes + 8);
      memcpy(draw_buffer->data + 8, icon->pixels, icon->size);
      lv_obj_t *canvas = lv_canvas_create(parent);
      if (!canvas) { lv_draw_buf_destroy(draw_buffer); return nullptr; }
      lv_canvas_set_draw_buf(canvas, draw_buffer);
      lv_obj_add_event_cb(canvas, [](lv_event_t *event) {
        lv_draw_buf_destroy(static_cast<lv_draw_buf_t *>(lv_event_get_user_data(event)));
      }, LV_EVENT_DELETE, draw_buffer);
      lv_canvas_set_palette(canvas, 0, to_color32(theme_bg()));
      lv_canvas_set_palette(canvas, 1, to_color32(theme_fg()));
      return canvas;
    }

    void show_asset(size_t index);
    void render_companion(const MascotSnapshot &snapshot);

    void coin_clicked(lv_event_t *event)
    {
      show_asset(reinterpret_cast<size_t>(lv_event_get_user_data(event)));
    }

    // FEED / PET / PLAY. Plain widgets, so they work with a touch panel and, through
    // the keypad input device, with four physical buttons.
    void companion_action_event(lv_event_t *event)
    {
      const intptr_t action = reinterpret_cast<intptr_t>(lv_event_get_user_data(event));
      const uint32_t now = millis();
      bool accepted;
      if (action == 0) accepted = mascot_feed(now);
      else if (action == 1) accepted = mascot_pet(now);
      else if (action == 3) accepted = mascot_blow_bubbles(now);
      else accepted = mascot_play(now);
      MascotInputs inputs{};
      inputs.battery_mv = board_battery_millivolts();
      inputs.phone_linked = wallet_link_service_connected();
      const MascotSnapshot snapshot = mascot_snapshot(inputs, now);
      if (current_page != Page::Companion) open_page(Page::Companion);
      else render_companion(snapshot);
      if (!accepted) {
        wallet_ui_set_status(action >= 2 && snapshot.hunger >= 80
            ? tr("Feed before playing", "先喂食再玩耍")
            : tr("Try again in two seconds", "请在两秒后重试"));
      } else {
        wallet_ui_set_status("");
      }
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
      if (current_page == Page::Companion) {
        const uint32_t elapsed = millis() - companion_entered_ms;
        const int room = lv_obj_get_content_width(companion_stage) - 64;
        const int range = room > 0 ? room / 2 : 0;
        const int phase = (elapsed / kMascotAnimationMs) % 8;
        // Travel from the center to each edge, once per idle frame. Reactions
        // stay centered so that resting, feeding and play have distinct poses.
        const int step = phase <= 2 ? phase : (phase <= 6 ? 4 - phase : phase - 8);
        const int x = snapshot.mood == MascotMood::Calm ? step * range / 2 : 0;
        const int lift = lv_obj_get_content_height(companion_stage) - 64;
        const int y = snapshot.mood == MascotMood::Excited && (snapshot.frame & 1) && lift >= 6 ? -3 : 0;
        lv_obj_align(companion_canvas, LV_ALIGN_CENTER, x, y);
      }
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

    size_t catalog_offset = 0;
    size_t catalog_matches = 0;

    void catalog_page_event(lv_event_t *event)
    {
      if (lv_event_get_user_data(event)) {
        if (catalog_offset + 8 < catalog_matches) catalog_offset += 8;
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
        case Page::TagWait: open_page(Page::NfcImport); break;
        case Page::KeyNetwork: case Page::KeyEntry: case Page::KeyCompression: case Page::KeyPass: case Page::KeyRepeat:
        case Page::KeyWorking: case Page::KeyResult: case Page::KeyVerify:
          open_page(setup_key.operation == BackupOperation::Encrypt ? Page::Create : Page::Recover); break;
        case Page::CreateWords: case Page::CreateKey: open_page(Page::Create); break;
        case Page::RecoverWords: case Page::RecoverKey: case Page::RawKey: case Page::NfcImport: open_page(Page::Recover); break;
        case Page::WordsCount: case Page::WordsInput: case Page::WordsBackup: case Page::WordsConfirm: case Page::PassChoice:
        case Page::PassInput: case Page::PassConfirm: case Page::Enroll:
          open_page(setup_words.creating ? Page::Create : Page::Recover); break;
        case Page::Asset: open_page(Page::Catalog); break;
        case Page::Search: open_page(Page::Catalog); break;
        case Page::Layout: case Page::Language: open_page(Page::Settings); break;
        default: open_page(Page::Home); break;
      }
    }

    lv_obj_t *menu_item(lv_obj_t *parent, const char *caption, Page target)
    {
      auto button = lv_button_create(parent);
      focus_ink(button);
      lv_obj_set_size(button, LV_PCT(100), board_has_touch() ? 44 : 22);
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
      reader_target = screen_content;
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

    void setup_page(Page page) {
      setup_transition = true;
      open_page(page);
    }

    const char *custody_reason() {
      switch (custody_gate_blocker(custody_gate_state())) {
        case CustodyBlocker::BackendMissing: return tr("E210 SE051 backend missing in this firmware", "E210 固件缺少 SE051 托管后端");
        case CustodyBlocker::ChannelNotAuthenticated: return tr("E211 Open the authenticated card channel", "E211 安全卡通道未认证");
        case CustodyBlocker::UserNotAuthenticated: return tr("E212 Verify the card PIN first", "E212 请先验证安全卡 PIN");
        case CustodyBlocker::KeysExportable: return tr("E213 Card key policy allows export", "E213 卡内密钥策略允许导出");
        case CustodyBlocker::WalletLayerNotConverted: return tr("E214 Firmware lacks card-backed wallet sessions", "E214 固件缺少卡内钱包会话");
        default: return nullptr;
      }
    }

    void start_words(lv_event_t *event) {
      if (custody_reason() || !session_authenticated || wallet_session_is_loaded()) {
        open_page(current_page);
        return;
      }
      setup_words.language = static_cast<MnemonicLanguage>(reinterpret_cast<uintptr_t>(lv_event_get_user_data(event)));
      setup_words.creating = current_page == Page::CreateWords;
      setup_page(setup_words.creating ? Page::WordsCount : Page::WordsInput);
    }

    void generate_words(lv_event_t *event) {
      if (custody_reason() || !session_authenticated || wallet_session_is_loaded()) {
        open_page(Page::CreateWords);
        return;
      }
      setup_words.count = static_cast<unsigned>(reinterpret_cast<uintptr_t>(lv_event_get_user_data(event)));
      const auto result = bip39_generate(setup_words.language, setup_words.count, setup_words.words, sizeof(setup_words.words));
      if (result != WalletError::Ok) {
        wallet_ui_set_status(result == WalletError::RandomFailure ? tr("E215 Entropy source failed", "E215 随机数源失败") : tr("E216 Mnemonic encoding failed", "E216 助记词编码失败"));
        return;
      }
      setup_page(Page::WordsBackup);
    }

    lv_obj_t *setup_button(const char *caption, lv_event_cb_t callback, uintptr_t value = 0) {
      auto button = lv_button_create(screen_content);
      focus_ink(button);
      lv_obj_set_size(button, LV_PCT(100), 22);
      lv_label_set_text(lv_label_create(button), caption);
      lv_obj_add_event_cb(button, callback, LV_EVENT_CLICKED, reinterpret_cast<void *>(value));
      lv_obj_add_event_cb(button, back_event, LV_EVENT_CANCEL, nullptr);
      return button;
    }

    void next_setup_page(lv_event_t *event) {
      setup_page(static_cast<Page>(reinterpret_cast<uintptr_t>(lv_event_get_user_data(event))));
    }

    const char *backup_error(WalletError error) {
      switch (error) {
        case WalletError::InvalidChecksum: return tr("E230 Backup checksum mismatch", "E230 备份校验和不符");
        case WalletError::WrongNetwork: return tr("E231 WIF belongs to another Bitcoin network", "E231 WIF 属于另一比特币网络");
        case WalletError::IncorrectPassphrase: return tr("E232 Check the password and Bitcoin network", "E232 请核对密码和比特币网络");
        case WalletError::OutOfMemory: return tr("E233 Insufficient scrypt memory", "E233 scrypt 内存不足");
        case WalletError::WorkerUnavailable: return tr("E234 Crypto worker busy or unavailable", "E234 加密任务忙或无法启动");
        case WalletError::UnsupportedFormat: return tr("E235 Invalid key format or length", "E235 私钥格式或长度无效");
        case WalletError::InvalidKey: return tr("E236 Invalid secp256k1 private key", "E236 secp256k1 私钥无效");
        case WalletError::Aborted: return tr("Backup cancelled", "已取消备份操作");
        case WalletError::UnsupportedUnicode: return tr("E237 Invalid passphrase encoding", "E237 密码编码无效");
        default: return tr("E238 Backup cryptography failed", "E238 备份加密运算失败");
      }
    }

    void start_backup(lv_event_t *) {
      if (!session_authenticated) { open_page(Page::Home); return; }
      setup_key.operation = current_page == Page::CreateKey ? BackupOperation::Encrypt :
                            current_page == Page::RawKey ? BackupOperation::ReadKey : BackupOperation::Decrypt;
      setup_page(Page::KeyNetwork);
    }

    void run_backup() {
      if (!session_authenticated) { open_page(Page::Home); return; }
      const auto error = bitcoin_backup_begin(setup_key.operation, setup_key.network, setup_key.compressed,
          setup_key.input, strlen(setup_key.input), reinterpret_cast<const uint8_t *>(setup_key.password), strlen(setup_key.password));
      secure_zero(setup_key.password, sizeof(setup_key.password));
      secure_zero(setup_key.input, sizeof(setup_key.input));
      if (error != WalletError::Ok) {
        open_page(Page::Home);
        wallet_ui_set_status(backup_error(error));
        return;
      }
      setup_page(Page::KeyWorking);
    }

    void after_key_entry() {
      if (setup_key.operation == BackupOperation::ReadKey) run_backup();
      else setup_page(Page::KeyPass);
    }

    void start_key_entry(lv_event_t *event) {
      setup_key.network = static_cast<BitcoinKeyNetwork>(reinterpret_cast<uintptr_t>(lv_event_get_user_data(event)));
      setup_key.compressed = true;
      if (!setup_key.input[0]) setup_page(Page::KeyEntry);
      else if (strlen(setup_key.input) == 64) setup_page(Page::KeyCompression);
      else after_key_entry();
    }

    const char *tag_error(NfcBackupStatus status) {
      switch (status) {
        case NfcBackupStatus::Busy: return tr("E250 NFC session busy", "E250 NFC 会话忙");
        case NfcBackupStatus::Timeout: return tr("E251 NFC read timed out", "E251 NFC 读取超时");
        case NfcBackupStatus::TagLost: return tr("E252 Tag removed during read", "E252 读取期间标签已移开");
        case NfcBackupStatus::UnsupportedTag: return tr("E253 Present one NFC-A Type 4 tag", "E253 请放置一张 NFC-A Type 4 标签");
        case NfcBackupStatus::AccessDenied: return tr("E254 Tag refused NDEF access", "E254 标签拒绝读取 NDEF");
          case NfcBackupStatus::InvalidRecord: return tr("E255 Expected one NDEF Text key record", "E255 需要单条 NDEF 文本私钥记录");
          case NfcBackupStatus::MissingFile: return tr("E257 NDEF app or file missing", "E257 缺少 NDEF 应用或文件");
          case NfcBackupStatus::CommandRejected: return tr("E258 Tag rejected read command", "E258 标签拒绝读取命令");
        default: return tr("E256 NFC controller unavailable", "E256 NFC 控制器不可用");
      }
    }

    void start_tag_read(lv_event_t *) {
      if (!session_authenticated) { open_page(Page::Home); return; }
      auto status = nfc_backup_start();
      if (status == NfcBackupStatus::Pending) setup_page(Page::TagWait);
      else wallet_ui_set_status(tag_error(status));
    }

    void choose_compression(lv_event_t *event) {
      setup_key.compressed = lv_event_get_user_data(event) != nullptr;
      after_key_entry();
    }

    void commit_setup(lv_event_t *) {
      if (!board_display_review_ready()) {
        wallet_ui_set_status(tr("Wait for the display, then hold again", "请等屏幕刷新完毕后再次长按"));
        return;
      }
      if (auto indev = lv_indev_active()) lv_indev_wait_release(indev);
      const char *error = custody_reason();
      if (!error && (!session_authenticated || wallet_session_is_loaded()))
        error = tr("E217 Unlock an empty wallet slot first", "E217 请先解锁空钱包槽位");
      if (!error) {
        const auto result = wallet_session_import_language(setup_words.words, setup_words.language, setup_words.passphrase);
        if (result != WalletError::Ok) {
          open_page(Page::Home);
          const char *message;
          switch (result) {
            case WalletError::InvalidMnemonic: message = tr("E240 Check word order, language and checksum", "E240 请核对词序、语言和校验和"); break;
            case WalletError::UnsupportedUnicode: message = tr("E241 Invalid passphrase encoding", "E241 附加密码编码无效"); break;
            case WalletError::OutOfMemory: message = tr("E242 Insufficient memory to process the passphrase", "E242 处理附加密码的内存不足"); break;
            case WalletError::BufferTooSmall: message = tr("E243 Normalized text exceeds the buffer", "E243 规范化文本超出缓冲区"); break;
            case WalletError::InvalidArgument: message = tr("E244 Check the passphrase length", "E244 请核对附加密码长度"); break;
            case WalletError::CustodyUnavailable: message = tr("E214 Card-backed wallet session unavailable", "E214 卡内钱包会话不可用"); break;
            default: message = tr("E245 Wallet seed derivation failed", "E245 钱包种子派生失败"); break;
          }
          wallet_ui_set_status(message);
          return;
        }
      }
      open_page(Page::Home);
      wallet_ui_set_status(error ? error : tr("Wallet ready", "钱包已就绪"));
    }

    void language_event(lv_event_t *event) {
      wallet_ui_set_language(static_cast<WalletUiLanguage>(reinterpret_cast<uintptr_t>(lv_event_get_user_data(event))));
    }

    void layout_event(lv_event_t *event) {
      const auto selected = static_cast<AssetLayout>(reinterpret_cast<uintptr_t>(lv_event_get_user_data(event)));
      if (selected != asset_layout || layout_error) {
        layout_error = save_asset_layout(selected);
        if (layout_error) { open_page(Page::Layout); return; }
        asset_layout = selected;
      }
      catalog_offset = 0;
      open_page(Page::Catalog);
    }

    void keyboard_map(const char *alphabet) {
      size_t map = 0, key = 0;
      memset(input_keys, 0, sizeof(input_keys));
      if (input_candidates) {
        for (size_t i = 0; i < 8; ++i) {
          if (!text_input.candidate(input_candidate_offset + i, input_keys[key])) break;
          input_map[map++] = input_keys[key++];
          if (i == 3 && input_candidate_offset + 4 < text_input.candidate_count()) input_map[map++] = "\n";
        }
        input_map[map++] = "\n";
        input_map[map++] = tr("Prev", "上页"); input_map[map++] = tr("Next", "下页"); input_map[map++] = "abc";
      } else {
        for (size_t i = 0; alphabet[i] && key < 40; ++i) {
          input_keys[key][0] = alphabet[i];
          input_map[map++] = input_keys[key++];
          if (i == 9 || i == 19) input_map[map++] = "\n";
        }
        input_map[map++] = tr("Del", "删除");
        input_map[map++] = "\n";
        for (const char *action : {"abc", "ABC", "123", "#%", tr("Pin", "拼音"), tr("Spc", "空格"), tr("Han", "选字"), tr("Done", "完成")})
          input_map[map++] = action;
      }
      input_map[map] = "";
      lv_buttonmatrix_set_map(input_matrix, input_map);
      lv_buttonmatrix_set_button_ctrl_all(input_matrix, static_cast<lv_buttonmatrix_ctrl_t>(LV_BUTTONMATRIX_CTRL_CLICK_TRIG | LV_BUTTONMATRIX_CTRL_NO_REPEAT));
      lv_buttonmatrix_set_selected_button(input_matrix, 0);
    }

    void input_refresh(TextInputError error = TextInputError::Ok) {
      lv_label_set_text_static(input_preview, text_input.preview());
      const char *message = nullptr;
      switch (error) {
        case TextInputError::Full: message = tr("E201 Input is full", "E201 输入已满"); break;
        case TextInputError::InvalidUtf8: message = tr("E202 Invalid UTF-8", "E202 字符编码无效"); break;
        case TextInputError::UnsupportedCharacter: message = tr("E203 Character not allowed", "E203 字符不可用"); break;
        case TextInputError::CompositionPending: message = tr("E204 Select a Chinese character first", "E204 请先选择汉字"); break;
        case TextInputError::NoCandidates: message = tr("E205 No match; edit pinyin", "E205 无候选字；请修改拼音"); break;
        default: break;
      }
      if (message) {
        lv_label_set_text_static(input_hint, message);
        return;
      }
      snprintf(input_status, sizeof(input_status), "%s  %s  %u / %u", input_pinyin ? tr("Pinyin", "拼音") : "ABC", text_input.composition(), static_cast<unsigned>(text_input.size()), static_cast<unsigned>(keyboard_limit));
      lv_label_set_text_static(input_hint, input_status);
    }

    void input_key_event(lv_event_t *) {
      const uint32_t selected = lv_buttonmatrix_get_selected_button(input_matrix);
      const char *key = lv_buttonmatrix_get_button_text(input_matrix, selected);
      if (!key) return;
      TextInputError error = TextInputError::Ok;
      if (input_candidates && strlen(key) == 3 && static_cast<uint8_t>(key[0]) >= 0xe0) {
        error = text_input.choose(input_candidate_offset + selected);
        input_candidates = false;
        keyboard_map("abcdefghijklmnopqrstuvwxyz");
      } else if (!strcmp(key, tr("Prev", "上页")) || !strcmp(key, tr("Next", "下页"))) {
        if (!strcmp(key, tr("Prev", "上页"))) { if (input_candidate_offset >= 8) input_candidate_offset -= 8; }
        else if (input_candidate_offset + 8 < text_input.candidate_count()) input_candidate_offset += 8;
        keyboard_map("");
      } else if (!strcmp(key, tr("Han", "选字"))) {
        if (!text_input.candidate_count()) error = TextInputError::NoCandidates;
        else { input_candidates = true; input_candidate_offset = 0; keyboard_map(""); }
      } else if (!strcmp(key, tr("Done", "完成"))) {
        if (text_input.composition()[0]) error = TextInputError::CompositionPending;
        else if (current_page == Page::KeyEntry) {
          const auto size = text_input.size();
          const bool encrypted = setup_key.operation == BackupOperation::Decrypt;
          if (encrypted ? size != 58 : (size != 51 && size != 52 && size != 64)) {
            lv_label_set_text_static(input_hint, backup_error(WalletError::UnsupportedFormat));
            return;
          }
          memcpy(setup_key.input, text_input.text(), size + 1);
          if (size == 64) setup_page(Page::KeyCompression);
          else after_key_entry();
          return;
        } else if (current_page == Page::KeyPass) {
          if (!text_input.size() && setup_key.operation == BackupOperation::Encrypt) {
            lv_label_set_text_static(input_hint, tr("Enter a backup password", "请输入备份密码")); return;
          }
          memcpy(setup_key.password, text_input.text(), text_input.size() + 1);
          if (setup_key.operation == BackupOperation::Encrypt) setup_page(Page::KeyRepeat);
          else run_backup();
          return;
        } else if (current_page == Page::KeyRepeat || current_page == Page::KeyVerify) {
          const bool verify = current_page == Page::KeyVerify;
          const char *expected = verify ? setup_key.result.encrypted : setup_key.password;
          if (strcmp(text_input.text(), expected)) {
            lv_label_set_text_static(input_hint, tr("Entries differ", "两次输入不一致")); return;
          }
          if (verify) { open_page(Page::Home); wallet_ui_set_status(tr("Encrypted backup verified", "已核对加密备份")); }
          else run_backup();
          return;
        } else if (current_page == Page::WordsInput || current_page == Page::WordsConfirm) {
          if (bip39_validate(text_input.text(), setup_words.language) != WalletError::Ok) {
            lv_label_set_text(input_hint, tr("Check words, spaces and checksum", "请核对词语、空格及校验和"));
            return;
          }
          if (current_page == Page::WordsConfirm && strcmp(text_input.text(), setup_words.words)) {
            lv_label_set_text_static(input_hint, tr("Words differ from backup", "与备份的助记词不一致"));
            return;
          }
          if (current_page == Page::WordsInput) memcpy(setup_words.words, text_input.text(), text_input.size() + 1);
          setup_page(Page::PassChoice);
          return;
        } else if (current_page == Page::PassInput || current_page == Page::PassConfirm) {
          if (!text_input.size()) { lv_label_set_text(input_hint, tr("Enter the passphrase", "请输入附加密码")); return; }
          if (current_page == Page::PassInput) {
            memcpy(setup_words.passphrase, text_input.text(), text_input.size() + 1);
            setup_page(Page::PassConfirm);
          } else if (!strcmp(setup_words.passphrase, text_input.text())) setup_page(Page::Enroll);
          else lv_label_set_text(input_hint, tr("Passphrases differ", "两次输入的密码不一致"));
          return;
        } else if (current_page == Page::Search && text_input.size() < sizeof(asset_query)) {
          memcpy(asset_query, text_input.text(), text_input.size() + 1);
          catalog_offset = 0;
          open_page(Page::Catalog);
          return;
        }
      } else if (!strcmp(key, tr("Del", "删除"))) text_input.backspace();
      else if (!strcmp(key, tr("Spc", "空格"))) {
        error = text_input.composition()[0] ? TextInputError::CompositionPending : text_input.insert(" ", 1);
      } else if (strlen(key) > 1) {
        if (text_input.composition()[0] && strcmp(key, "abc")) error = TextInputError::CompositionPending;
        else {
          input_candidates = false;
          input_pinyin = !strcmp(key, tr("Pin", "拼音")) || (text_input.composition()[0] != 0);
          keyboard_map(!strcmp(key, "ABC") ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" :
                       !strcmp(key, "123") ? "0123456789.,+-*/=()" :
                       !strcmp(key, "#%") ? "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" : "abcdefghijklmnopqrstuvwxyz");
        }
      } else error = input_pinyin ? text_input.compose(key[0]) : text_input.insert(key, 1);
      input_refresh(error);
    }

    void open_keyboard(const char *title, size_t limit, bool secret) {
      keyboard_limit = limit;
      text_input.begin(limit, secret);
      if (current_page == Page::Search) text_input.insert(asset_query, strlen(asset_query));
      input_pinyin = input_candidates = false;
      input_candidate_offset = 0;
      lv_obj_add_flag(screen_header, LV_OBJ_FLAG_HIDDEN);
      lv_obj_add_flag(status_label, LV_OBJ_FLAG_HIDDEN);
      lv_obj_set_style_pad_all(lv_screen_active(), 2, 0);
      lv_obj_remove_flag(screen_content, LV_OBJ_FLAG_SCROLLABLE);
      if (board_has_touch()) {
        auto bar = lv_obj_create(screen_content);
        set_clean_container(bar);
        lv_obj_set_size(bar, LV_PCT(100), LV_SIZE_CONTENT);
        lv_obj_set_flex_flow(bar, LV_FLEX_FLOW_ROW);
        auto label = lv_label_create(bar);
        lv_label_set_text(label, title);
        lv_obj_set_width(label, 0);
        lv_obj_set_flex_grow(label, 1);
        auto cancel = lv_button_create(bar);
        focus_ink(cancel);
        lv_label_set_text(lv_label_create(cancel), tr("Cancel", "取消"));
        lv_obj_add_event_cb(cancel, back_event, LV_EVENT_CLICKED, nullptr);
      } else page_text(title);
      input_preview = lv_label_create(screen_content);
      lv_obj_set_size(input_preview, LV_PCT(100), 16);
      lv_label_set_long_mode(input_preview, LV_LABEL_LONG_MODE_CLIP);
      lv_obj_set_style_text_font(input_preview, &hexwallet_ui_chinese, 0);
      input_hint = lv_label_create(screen_content);
      lv_obj_set_size(input_hint, LV_PCT(100), 16);
      lv_obj_set_style_text_font(input_hint, &hexwallet_ui_chinese, 0);
      input_matrix = lv_buttonmatrix_create(screen_content);
      lv_obj_set_size(input_matrix, LV_PCT(100), 0);
      lv_obj_set_flex_grow(input_matrix, 1);
      lv_obj_set_style_text_font(input_matrix, &hexwallet_ui_chinese, 0);
      lv_obj_set_style_pad_all(input_matrix, 0, 0);
      lv_obj_set_style_pad_row(input_matrix, 1, 0);
      lv_obj_set_style_pad_column(input_matrix, 1, 0);
      lv_obj_set_style_border_width(input_matrix, 0, 0);
      lv_obj_set_style_radius(input_matrix, 0, 0);
      lv_obj_set_style_bg_color(input_matrix, theme_bg(), LV_PART_ITEMS);
      lv_obj_set_style_text_color(input_matrix, theme_fg(), LV_PART_ITEMS);
      lv_obj_set_style_bg_color(input_matrix, theme_fg(), LV_PART_ITEMS | LV_STATE_FOCUSED);
      lv_obj_set_style_text_color(input_matrix, theme_bg(), LV_PART_ITEMS | LV_STATE_FOCUSED);
      lv_obj_set_style_bg_color(input_matrix, theme_fg(), LV_PART_ITEMS | LV_STATE_PRESSED);
      lv_obj_set_style_text_color(input_matrix, theme_bg(), LV_PART_ITEMS | LV_STATE_PRESSED);
      lv_obj_set_style_shadow_width(input_matrix, 0, LV_PART_ITEMS);
      keyboard_map("abcdefghijklmnopqrstuvwxyz");
      input_refresh();
      lv_obj_add_event_cb(input_matrix, input_key_event, LV_EVENT_VALUE_CHANGED, nullptr);
      lv_obj_add_event_cb(input_matrix, back_event, LV_EVENT_CANCEL, nullptr);
      lv_group_focus_obj(input_matrix);
    }

    void open_page(Page page)
    {
      clear_content();
      decision_callback = nullptr;
      current_page = page;
      lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
      lv_obj_set_style_pad_row(screen_content, 2, 0);
      wallet_ui_set_status(tr("OK select   Prev / Next   Back", "确定选择  上一个 / 下一个  返回"));
      if (page == Page::Search) { open_keyboard(tr("Search assets  /  Back cancels", "搜索资产 / 返回取消"), sizeof(asset_query) - 1, false); return; }
      if (page == Page::KeyNetwork) {
        page_text(tr("Bitcoin backup network", "比特币备份网络"));
        auto main = setup_button(tr("Bitcoin mainnet", "比特币主网"), start_key_entry);
        setup_button(tr("Bitcoin testnet", "比特币测试网"), start_key_entry, 1);
        lv_group_focus_obj(main);
        return;
      }
      if (page == Page::TagWait) {
        page_text(tr("Present one Type 4 NDEF text backup", "请放置一张 Type 4 NDEF 文本备份标签"));
        auto cancel = menu_item(screen_content, tr("Cancel", "取消"), Page::NfcImport);
        lv_group_focus_obj(cancel);
        return;
      }
      if (page == Page::KeyEntry || page == Page::KeyVerify) {
        const bool encrypted = setup_key.operation == BackupOperation::Decrypt || page == Page::KeyVerify;
        open_keyboard(page == Page::KeyVerify ? tr("Retype the encrypted backup", "重新输入加密备份") :
                      encrypted ? tr("Enter encrypted BIP38 key", "输入 BIP38 加密私钥") : tr("Enter WIF or 64 hex digits", "输入 WIF 或 64 位十六进制私钥"), encrypted ? 58 : 64, true);
        return;
      }
      if (page == Page::KeyCompression) {
        page_text(tr("Public key for the P2PKH address", "P2PKH 地址的公钥格式"));
        auto first = setup_button(tr("Compressed", "压缩"), choose_compression, 1);
        setup_button(tr("Uncompressed", "未压缩"), choose_compression);
        lv_group_focus_obj(first);
        return;
      }
      if (page == Page::KeyPass || page == Page::KeyRepeat) {
        open_keyboard(page == Page::KeyPass ? tr("BIP38 backup password", "BIP38 备份密码") : tr("Repeat backup password", "再次输入备份密码"), kBip39MaxPassphraseBytes, true);
        return;
      }
      if (page == Page::KeyWorking) {
        page_text(tr("Processing Bitcoin key", "正在处理比特币私钥"));
        auto cancel = menu_item(screen_content, tr("Cancel", "取消"), Page::Home);
        lv_group_focus_obj(cancel);
        return;
      }
      if (page == Page::KeyResult) {
        page_text(setup_key.network == BitcoinKeyNetwork::Mainnet ? tr("Backup address / mainnet", "备份地址 / 主网") : tr("Backup address / testnet", "备份地址 / 测试网"));
        page_text(setup_key.result.address);
        page_text(setup_key.result.compressed ? tr("Compressed P2PKH", "压缩公钥 P2PKH") : tr("Uncompressed P2PKH", "未压缩公钥 P2PKH"));
        if (setup_key.result.encrypted[0]) {
          page_text(tr("Write down the encrypted key", "抄下加密私钥"));
          auto label = lv_label_create(screen_content);
          lv_obj_set_width(label, LV_PCT(100));
          lv_label_set_text_static(label, setup_key.result.encrypted);
          setup_button(tr("Verify backup", "核对备份"), next_setup_page, static_cast<uintptr_t>(Page::KeyVerify));
        } else page_text(tr("Address check only. Wallet import unavailable.", "仅供核对地址。钱包导入尚不可用。"));
        focus_reader();
        return;
      }
      if (page == Page::WordsInput || page == Page::WordsConfirm) {
        open_keyboard(page == Page::WordsInput ? tr("Recovery words / separate with spaces", "输入助记词 / 用空格分隔") : tr("Verify words from your backup", "重新输入备份的助记词"), sizeof(setup_words.words) - 1, true);
        return;
      }
      if (page == Page::PassInput || page == Page::PassConfirm) {
        open_keyboard(page == Page::PassInput ? tr("Enter BIP39 passphrase", "输入 BIP39 附加密码") : tr("Repeat the same passphrase", "再次输入相同的附加密码"), sizeof(setup_words.passphrase) - 1, true);
        return;
      }
      if (page == Page::PassChoice) {
        page_text(tr("BIP39 passphrase / each choice opens a different wallet", "BIP39 附加密码 / 不同密码对应不同钱包"));
        auto add = setup_button(tr("Use a passphrase", "使用附加密码"), next_setup_page, static_cast<uintptr_t>(Page::PassInput));
        setup_button(tr("Use empty passphrase", "明确使用空密码"), next_setup_page, static_cast<uintptr_t>(Page::Enroll));
        lv_group_focus_obj(add);
        return;
      }
      if (page == Page::WordsBackup) {
        char heading[80];
        snprintf(heading, sizeof(heading), tr("Write all %u words in order", "按顺序抄下全部 %u 个词"), setup_words.count);
        page_text(heading);
        auto label = lv_label_create(screen_content);
        lv_obj_set_width(label, LV_PCT(100));
        lv_obj_set_style_text_font(label, &hexwallet_ui_chinese, 0);
        lv_label_set_text_static(label, setup_words.words);
        setup_button(tr("Verify backup", "核对备份"), next_setup_page, static_cast<uintptr_t>(Page::WordsConfirm));
        focus_reader();
        return;
      }
      if (page == Page::Enroll) {
        board_display_prepare_review();
        page_text(setup_words.creating ? tr("Create this wallet?", "确认创建该钱包？") : tr("Recover this wallet?", "确认恢复该钱包？"));
        auto cancel = menu_item(screen_content, tr("Cancel", "取消"), Page::Home);
        auto approve = setup_button(tr("Hold OK to confirm", "长按确定以确认"), [](lv_event_t *) {});
        lv_obj_add_event_cb(approve, commit_setup, LV_EVENT_LONG_PRESSED, nullptr);
        lv_group_focus_obj(cancel);
        return;
      }
      if (page == Page::WordsCount) {
        page_text(tr("Number of recovery words", "助记词数量"));
        for (unsigned count = 12; count <= 24; count += 3) {
          char caption[16];
          snprintf(caption, sizeof(caption), tr("%u words", "%u 个词"), count);
          auto choice = setup_button(caption, generate_words, count);
          if (count == 24) lv_group_focus_obj(choice);
        }
        return;
      }
      if (board_has_touch() && page != Page::Home && page != Page::Companion) {
        auto back = lv_button_create(screen_content);
        focus_ink(back);
        lv_obj_set_size(back, LV_PCT(100), 32);
        lv_label_set_text(lv_label_create(back), tr("Back", "返回"));
        lv_obj_add_event_cb(back, back_event, LV_EVENT_CLICKED, nullptr);
      }
      if (page == Page::Home) {
        catalog_offset = 0;
        const bool horizontal = board_display_width() > board_display_height();
        MascotInputs inputs{};
        inputs.battery_mv = board_battery_millivolts();
        inputs.phone_linked = wallet_link_service_connected();
        const auto snapshot = mascot_snapshot(inputs, millis());
        if (horizontal) {
          lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_ROW);
          companion_stage = lv_obj_create(screen_content);
          set_clean_container(companion_stage);
          lv_obj_set_size(companion_stage, 74, LV_PCT(100));
          lv_obj_remove_flag(companion_stage, LV_OBJ_FLAG_SCROLLABLE);
          lv_obj_add_event_cb(companion_stage, companion_deleted, LV_EVENT_DELETE, nullptr);
          companion_parts(companion_stage, snapshot);
        } else if (board_display_height() >= 320) {
          nothing_companion(screen_content, snapshot);
        }
        auto menu = lv_obj_create(screen_content);
        set_clean_container(menu);
        lv_obj_set_width(menu, horizontal ? 0 : LV_PCT(100));
        lv_obj_set_height(menu, horizontal ? 68 : LV_SIZE_CONTENT);
        if (horizontal) lv_obj_set_flex_grow(menu, 1);
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
          menu_item(menu, tr("DeepSeek companion", "DeepSeek 伙伴"), Page::Companion);
        menu_item(menu, tr("Settings", "设置"), Page::Settings);
        lv_group_focus_obj(first);
        return;
      }
      if (page == Page::Create || page == Page::Recover) {
        bool create = page == Page::Create;
        page_text(create ? tr("Create wallet  /  Choose a backup", "创建钱包 / 选择备份方式") : tr("Recover wallet  /  Choose your backup", "恢复钱包 / 选择已有备份"));
        auto first = menu_item(screen_content, tr("BIP39  /  Recovery words", "BIP39 / 助记词"), create ? Page::CreateWords : Page::RecoverWords);
        menu_item(screen_content, tr("BIP38  /  Encrypted Bitcoin key", "BIP38 / 加密比特币私钥"), create ? Page::CreateKey : Page::RecoverKey);
        if (!create) {
          menu_item(screen_content, tr("Bitcoin private key / WIF or hex", "比特币私钥 / WIF 或十六进制"), Page::RawKey);
          menu_item(screen_content, tr("Read NFC backup", "读取 NFC 备份"), Page::NfcImport);
        }
        lv_group_focus_obj(first);
        return;
      }
      if (page == Page::Companion) {
        companion_entered_ms = millis();
        lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_ROW);
        companion_stage = lv_obj_create(screen_content);
        set_clean_container(companion_stage);
        lv_obj_set_size(companion_stage, LV_PCT(48), LV_PCT(100));
        lv_obj_set_style_min_width(companion_stage, 64, 0);
        lv_obj_remove_flag(companion_stage, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_add_event_cb(companion_stage, companion_deleted, LV_EVENT_DELETE, nullptr);
        MascotInputs inputs{};
        inputs.battery_mv = board_battery_millivolts();
        inputs.phone_linked = wallet_link_service_connected();
        companion_parts(companion_stage, mascot_snapshot(inputs, millis()));
        auto menu = lv_obj_create(screen_content);
        set_clean_container(menu);
        lv_obj_set_flex_grow(menu, 1);
        lv_obj_set_height(menu, LV_PCT(100));
        lv_obj_set_flex_flow(menu, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_style_pad_row(menu, 1, 0);
        const char *actions[] = {tr("Feed", "喂食"), tr("Pet", "抚摸"), tr("Play", "玩耍"), tr("Blow bubbles", "吹泡泡")};
        for (intptr_t i = 0; i < 4; ++i) {
          auto button = lv_button_create(menu);
          focus_ink(button);
          lv_obj_set_size(button, LV_PCT(100), board_has_touch() ? 44 : 22);
          lv_label_set_text(lv_label_create(button), actions[i]);
          lv_obj_add_event_cb(button, companion_action_event, LV_EVENT_CLICKED, reinterpret_cast<void *>(i));
          lv_obj_add_event_cb(button, back_event, LV_EVENT_CANCEL, nullptr);
          if (!i) lv_group_focus_obj(button);
        }
        if (board_has_touch()) menu_item(menu, tr("Back", "返回"), Page::Home);
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
      if (page == Page::Settings) {
        page_text(tr("Settings", "设置"));
        auto first = menu_item(screen_content, tr("Asset layout", "资产布局"), Page::Layout);
        auto locale = menu_item(screen_content, "Language / 语言", Page::Language);
        lv_obj_set_style_text_font(locale, &hexwallet_ui_chinese, 0);
        menu_item(screen_content, tr("Button guide", "按键说明"), Page::Controls);
        menu_item(screen_content, tr("Search assets", "搜索资产"), Page::Search);
        lv_group_focus_obj(first);
        return;
      }
      if (page == Page::Layout) {
        page_text(tr("Asset layout", "资产布局"));
        if (layout_error) {
          auto error_label = lv_label_create(screen_content);
          lv_obj_set_width(error_label, LV_PCT(100));
          lv_label_set_text_fmt(error_label, tr("Layout storage error (%s)", "布局存储错误 (%s)"), layout_error);
        }
        for (uintptr_t i = 0; i < 3; ++i) {
          auto button = lv_button_create(screen_content);
          focus_ink(button);
          lv_obj_set_size(button, LV_PCT(100), 22);
          lv_label_set_text(lv_label_create(button), i == 0 ? tr("ListView", "列表视图") : i == 1 ? tr("GridView", "网格视图") : tr("CardView", "卡片视图"));
          lv_obj_add_event_cb(button, layout_event, LV_EVENT_CLICKED, reinterpret_cast<void *>(i));
          lv_obj_add_event_cb(button, back_event, LV_EVENT_CANCEL, nullptr);
          if (i == static_cast<uintptr_t>(asset_layout)) lv_group_focus_obj(button);
        }
        return;
      }
      if (page == Page::Catalog) {
        catalog_matches = 0;
        for (size_t i = 0; i < wallet_catalog_count(); ++i) {
          WalletCatalogEntry entry;
          if (wallet_catalog_at_sorted(i, &entry) && (!asset_query[0] || wallet_catalog_matches(entry, asset_query))) ++catalog_matches;
        }
        const bool grid = asset_layout == AssetLayout::Grid;
        const bool card = asset_layout == AssetLayout::Card;
        lv_obj_set_flex_flow(screen_content, grid ? LV_FLEX_FLOW_ROW_WRAP : LV_FLEX_FLOW_COLUMN);
        lv_obj_set_style_pad_column(screen_content, 4, 0);
        lv_obj_set_style_pad_row(screen_content, card ? 6 : 4, 0);
        if (catalog_offset >= catalog_matches)
          catalog_offset = catalog_matches ? ((catalog_matches - 1) / 8) * 8 : 0;
        const size_t end = catalog_offset + 8;
        size_t shown = 0, skipped = 0;
        for (size_t i = 0; i < wallet_catalog_count() && shown < 8; ++i) {
          WalletCatalogEntry entry;
          if (!wallet_catalog_at_sorted(i, &entry)) continue;
          if (asset_query[0] && !wallet_catalog_matches(entry, asset_query)) continue;
          if (skipped++ < catalog_offset) continue;
          ++shown;
          auto button = lv_button_create(screen_content);
          focus_ink(button);
            lv_obj_set_width(button, LV_PCT(grid ? 48 : 100));
            lv_obj_set_height(button, LV_SIZE_CONTENT);
          const auto dpi = lv_display_get_dpi(lv_obj_get_display(button));
          lv_obj_set_style_radius(button, card ? (12 * dpi + 80) / 160 : grid ? 6 : 2, 0);
          lv_obj_set_style_pad_all(button, card ? 8 : 3, 0);
          lv_obj_set_flex_flow(button, LV_FLEX_FLOW_ROW);
          lv_obj_set_style_pad_column(button, 6, 0);
          lv_obj_set_flex_align(button, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
          coin_icon_view(button, entry.symbol);
          auto label = lv_label_create(button);
            lv_label_set_text_fmt(label, "%s\n%s", entry.symbol, entry.name);
           lv_obj_set_width(label, 0);
           lv_obj_set_flex_grow(label, 1);
           lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
          lv_obj_add_event_cb(button, coin_clicked, LV_EVENT_CLICKED, reinterpret_cast<void *>(i));
          lv_obj_add_event_cb(button, back_event, LV_EVENT_CANCEL, nullptr);
        }
        for (int next = 0; next <= 1; ++next) {
          if (next ? end >= catalog_matches : catalog_offset == 0) continue;
          auto button = lv_button_create(screen_content);
          focus_ink(button);
           lv_obj_set_size(button, LV_PCT(100), 22);
           lv_label_set_text(lv_label_create(button), next ? tr("Next assets", "下一页资产") : tr("Previous assets", "上一页资产"));
          lv_obj_add_event_cb(button, catalog_page_event, LV_EVENT_CLICKED, reinterpret_cast<void *>(uintptr_t(next)));
          lv_obj_add_event_cb(button, back_event, LV_EVENT_CANCEL, nullptr);
        }
        if (!shown) {
          page_text(asset_query[0] ? tr("No matching assets; edit search", "无匹配资产；请修改搜索") : tr("No assets available", "暂无资产"));
          if (!wallet_catalog_count()) focus_reader();
        } else lv_group_focus_obj(lv_obj_get_child(screen_content, 0));
        if (wallet_catalog_count()) {
          auto search = menu_item(screen_content, tr("Search assets", "搜索资产"), Page::Search);
          if (!shown) lv_group_focus_obj(search);
        }
        return;
      }
      if (page == Page::CreateWords || page == Page::RecoverWords) {
        page_text(page == Page::CreateWords ? tr("Create / BIP39", "创建 / BIP39") : tr("Recover / BIP39", "恢复 / BIP39"));
        const char *error = custody_reason();
        if (error) page_text(error);
        else if (!session_authenticated || wallet_session_is_loaded()) page_text(tr("E217 Unlock an empty wallet slot first", "E217 请先解锁空钱包槽位"));
        else {
          auto first = setup_button("English", start_words);
          auto simplified = setup_button("简体中文", start_words, 1);
          auto traditional = setup_button("繁體中文", start_words, 2);
          lv_obj_set_style_text_font(simplified, &hexwallet_ui_chinese, 0);
          lv_obj_set_style_text_font(traditional, &hexwallet_ui_chinese, 0);
          lv_group_focus_obj(first);
          return;
        }
        focus_reader();
        return;
      }
      switch (page) {
        case Page::CreateKey:
          page_text(tr("Create / BIP38", "创建 / BIP38"));
          page_text(tr("E225 This firmware lacks protected Bitcoin key creation and BIP38 backup on the card.",
                       "E225 固件缺少比特币私钥的卡内创建和 BIP38 备份功能。"));
          break;
        case Page::RecoverKey:
          page_text(tr("Recover / BIP38", "恢复 / BIP38"));
          page_text(tr("E218 This firmware lacks protected Bitcoin key import and signing on the card.",
                       "E218 固件缺少比特币私钥的卡内导入与签名功能。"));
          break;
        case Page::RawKey: page_text(tr("Bitcoin / WIF or hex", "比特币 / WIF 或十六进制")); page_text(tr("E218 Firmware lacks secure single-key import and signing", "E218 固件缺少单私钥卡内导入与签名")); break;
        case Page::NfcImport:
          page_text(tr("Check Bitcoin backup on NFC tag", "核对 NFC 标签上的比特币备份"));
          if (!nfc_port_configured()) page_text(tr("E220 No NFC controller configured", "E220 未配置 NFC 控制器"));
          else if (!session_authenticated) page_text(tr("Unlock to read a backup", "请先解锁以读取备份"));
          else {
            if (const char *error = nfc_port_error()) page_text(error);
            page_text(tr("WIF, hex or BIP38 / address check only", "WIF、十六进制或 BIP38 / 仅核对地址"));
            lv_group_focus_obj(setup_button(tr("Read Type 4 tag", "读取 Type 4 标签"), start_tag_read));
            return;
          }
          break;
        case Page::Scan: {
          page_text(tr("Scan QR", "扫描二维码"));
          switch (board_camera_probe()) {
            case CameraProbeState::NotConfigured: page_text(tr("E221 Camera control bus (SCCB) is not wired in this board profile", "E221 板卡配置无摄像头控制总线 SCCB")); break;
            case CameraProbeState::NoResponse: page_text(tr("E222 Camera did not acknowledge SCCB", "E222 摄像头未响应 SCCB")); break;
            case CameraProbeState::WrongSensor: page_text(tr("E223 Sensor ID differs from OV9281", "E223 传感器型号与 OV9281 不符")); break;
            case CameraProbeState::PresentUnverified: page_text(tr("E224 OV9281 detected; CSI capture unavailable", "E224 已检测到 OV9281，CSI 采集尚不可用")); break;
          }
          break;
        }
        case Page::Controls: page_text(tr("Keys: OK / Prev / Next / Back", "左起：确定 / 上一个 / 下一个 / 返回")); page_text(tr("Prev / Next move or scroll. Back cancels. Review: OK selects Reject first; select Approve, then hold OK for 0.75s.", "上一个、下一个用于选择或滚动；返回用于取消。审阅时，确定先选中拒绝；切换至批准后，另行长按确定 0.75 秒。")); break;
        default: break;
      }
      if (page == Page::RecoverKey || page == Page::RawKey || page == Page::CreateKey) {
        if (session_authenticated) {
          auto action = setup_button(page == Page::CreateKey ? tr("Encrypt an existing key", "加密已有私钥") : tr("Check backup address", "核对备份地址"), start_backup);
          lv_group_focus_obj(action);
          return;
        }
        page_text(tr("Unlock to check or encrypt a backup", "请解锁以核对或加密备份"));
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
      if (!wallet_catalog_can_receive(entry))
        page_text(tr("Receiving disabled: review and signing are required.", "收款已禁用：必须支持交易审阅和签名。"));
      if (board_has_touch()) menu_item(screen_content, tr("Back to assets", "返回资产目录"), Page::Catalog);
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
    screen_header = header;
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

    layout_error = load_asset_layout(asset_layout);
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
    bitcoin_backup_cancel();
    nfc_backup_cancel();
    secure_zero(&setup_key, sizeof(setup_key));
    forget_companion();
    review_seal_valid = false;
    decision_pending = false;
    decision_callback = nullptr;
    initialized = false;
    volatile char *code = otp_text;
    for (size_t i = 0; i < sizeof(otp_text); ++i) code[i] = 0;
    otp_visible = false;
    pairing_page = false;
    screen_content = screen_header = state_label = status_label = nullptr;
    reader_target = nullptr;
    input_matrix = input_preview = input_hint = nullptr;
    text_input.clear();
    secure_zero(&setup_words, sizeof(setup_words));
    secure_zero(input_status, sizeof(input_status));
    setup_transition = false;
    if (!screen) return;
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
    if (!authenticated && initialized && current_page >= Page::WordsCount) open_page(Page::Home);
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
    open_page(Page::Home);
#endif
  }

  bool wallet_ui_show_address(const char *network, const char *address,
                              const char *path)
  {
    review_seal_valid = false;
#if HEXWALLET_ENABLE_LVGL
    if (!initialized || screen_content == nullptr || !board_has_display() ||
        network == nullptr || !*network || address == nullptr || !*address || path == nullptr) {
      if (initialized && screen_content)
        wallet_ui_show_refusal(tr("E300 Missing receive network or address", "E300 缺少收款网络或地址"));
      return false;
    }
    decision_callback = nullptr;
    decision_pending = false;
    board_display_prepare_review();
    clear_content();
    lv_obj_set_flex_flow(screen_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(screen_content, sc(8), 0);
    lv_obj_set_scrollbar_mode(screen_content, LV_SCROLLBAR_MODE_AUTO);

    const bool wide = board_display_width() >= board_display_height();
    lv_obj_add_flag(screen_header, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(status_label, LV_OBJ_FLAG_HIDDEN);
    lv_obj_set_style_pad_all(lv_screen_active(), 0, 0);
    lv_obj_remove_flag(screen_content, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *row = lv_obj_create(screen_content);
    set_clean_container(row);
    lv_obj_remove_flag(row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_size(row, LV_PCT(100), LV_PCT(100));
    lv_obj_set_flex_flow(row, wide ? LV_FLEX_FLOW_ROW : LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_gap(row, 4, 0);
    lv_obj_update_layout(row);
    const int width = lv_obj_get_content_width(row);
    const int height = lv_obj_get_content_height(row);
    // Keep space for the network and at least two lines of the full address.
    const int room = wide ? std::min(height, width / 2) : std::min(width, height - 64);
    const int side = std::max(1, std::min(room, 192));
    lv_obj_t *qr_row = lv_obj_create(row);
    set_clean_container(qr_row);
    lv_obj_remove_flag(qr_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_size(qr_row, side, side);
    lv_obj_set_flex_flow(qr_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(qr_row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_t *qr = nothing_qr(qr_row, address, nullptr);
    if (!qr) lv_obj_add_flag(qr_row, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *details = lv_obj_create(row);
    set_clean_container(details);
    lv_obj_set_size(details, wide ? 0 : LV_PCT(100), wide ? LV_PCT(100) : 0);
    lv_obj_set_flex_grow(details, 1);
    lv_obj_set_flex_flow(details, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(details, 4, 0);
    landscape_scrollbar(details);
    reading_page = true;
    reader_target = details;
    lv_obj_add_flag(details, LV_OBJ_FLAG_SCROLL_WITH_ARROW);
    lv_obj_add_event_cb(details, reader_back_event, LV_EVENT_CANCEL, nullptr);
    if (auto group = lv_group_get_default()) {
      lv_group_add_obj(group, details);
      lv_group_focus_obj(details);
    }
    lv_obj_t *network_label = lv_label_create(details);
    lv_obj_set_width(network_label, LV_PCT(100));
    lv_label_set_text_fmt(network_label, tr("Receive / %s", "收款 / %s"), network);
    if (!qr) {
      const bool too_long = strlen(address) > qr_capacity(kQrMaxVersion, QrEcc::Medium);
      nothing_micro_label(details, too_long
          ? tr("E301 Address exceeds QR capacity", "E301 地址超出二维码容量")
          : tr("E302 QR cannot be drawn at a readable size", "E302 无法绘制清晰的二维码"), true);
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
    lv_obj_set_style_pad_all(address_label, wide ? 1 : sc(8), 0);
    lv_obj_set_style_text_letter_space(address_label, wide ? 0 : 1, 0);

    nothing_micro_label(details, path, false);
    if (wide) nothing_micro_label(details, tr("Prev / Next scroll; Back", "上 / 下滚动；返回"), false);
    lv_obj_t *warning = lv_label_create(details);
    lv_label_set_long_mode(warning, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(warning, LV_PCT(100));
    lv_label_set_text(warning,
                      tr("Compare every character with the sending wallet before receiving.", "收款前，请与付款钱包逐字核对完整地址。"));
    lv_obj_set_style_text_color(warning, theme_fg(), 0);

    if (board_has_touch()) menu_item(details, tr("Back", "返回"), Page::Home);
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
    WalletError backup_status;
    if (initialized && !board_display_operational()) wallet_ui_show_port_error();
    if (initialized && session_authenticated && current_page == Page::TagWait) {
      const auto status = nfc_backup_take(setup_key.input);
      if (status == NfcBackupStatus::Complete) {
        setup_key.operation = strlen(setup_key.input) == 58 ? BackupOperation::Decrypt : BackupOperation::ReadKey;
        setup_page(Page::KeyNetwork);
      } else if (status != NfcBackupStatus::Pending) {
        open_page(Page::NfcImport);
        wallet_ui_set_status(tag_error(status));
      }
    }
    if (bitcoin_backup_poll(backup_status, setup_key.result) && initialized && session_authenticated && current_page == Page::KeyWorking) {
      if (backup_status == WalletError::Ok) {
        setup_page(Page::KeyResult);
      } else {
        open_page(Page::Home);
        wallet_ui_set_status(backup_error(backup_status));
      }
    }
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
