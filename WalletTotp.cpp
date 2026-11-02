#include "WalletTotp.h"
#include "WalletCli.h"
#include "WalletLinkService.h"
#include "WalletSigning.h"
#include "WalletUi.h"
#include "WalletSecurity.h"
#include <Arduino.h>
#include <esp_timer.h>
#include <stdio.h>
#include <string.h>

namespace hexwallet
{
  namespace
  {
    TotpAccounts accounts;
    enum class Action : uint8_t
    {
      None,
      Import,
      Remove,
      Show,
      Time
    };
    Action action = Action::None;
    char pending_uri[kTotpUriMaxBytes + 1] = {};
    size_t pending_uri_size = 0;
    uint8_t pending_slot = 0;
    uint64_t pending_time = 0;
    uint64_t pending_started = 0;
    uint64_t code_expires = 0;
    uint64_t now_ms() { return static_cast<uint64_t>(esp_timer_get_time()) / 1000U; }
    void clear_pending()
    {
      secure_zero(pending_uri, sizeof(pending_uri));
      pending_uri_size = 0;
      pending_slot = 0;
      pending_time = pending_started = 0;
      action = Action::None;
    }
    bool available()
    {
      return wallet_cli_is_authenticated() && wallet_ui_ready() &&
             !wallet_cli_review_active() && !wallet_signing_active() &&
             !wallet_link_service_pairing_pending() && action == Action::None;
    }
    void decision(bool approved)
    {
      if (action == Action::None)
        return;
      const bool authorized = approved && wallet_cli_is_authenticated() &&
                              now_ms() - pending_started < 120000 && wallet_ui_review_authorize();
      bool ok = false;
      bool shown = false;
      if (authorized)
      {
        switch (action)
        {
        case Action::Import:
        {
          uint8_t slot;
          ok = accounts.import_uri(pending_uri, pending_uri_size, &slot) == TotpError::Ok;
          break;
        }
        case Action::Remove:
          ok = accounts.remove(pending_slot);
          break;
        case Action::Time:
          ok = totp_clock_set_unix(pending_time, now_ms());
          break;
        case Action::Show:
        {
          char code[9] = {};
          uint32_t remaining = 0;
          TotpAccountInfo info = {};
          uint64_t unix_time = 0;
          const uint64_t stamp = now_ms();
          ok = accounts.info(pending_slot, &info) &&
               accounts.generate(pending_slot, stamp, code, &remaining) == TotpError::Ok &&
               totp_clock_unix(stamp, &unix_time) && unix_time <= UINT64_MAX - remaining;
          if (ok)
          {
            shown = wallet_ui_show_otp(info.issuer, info.account, code, unix_time + remaining);
            ok = shown;
            code_expires = stamp + (remaining - 1U) * 1000U;
          }
          secure_zero(code, sizeof(code));
          break;
        }
        default:
          break;
        }
      }
      clear_pending();
      wallet_ui_set_decision_callback(nullptr);
      if (!shown)
      {
        wallet_ui_show_catalog();
        wallet_ui_set_status(ok ? "TOTP change applied" : "TOTP request rejected or expired");
      }
    }
    bool review(Action requested, const char *name, const char *issuer, const char *detail)
    {
      WalletUiTransactionReview r = {};
      r.network = "TOTP AUTHENTICATOR";
      r.output_count = 1;
      r.outputs[0].amount_text = name;
      r.outputs[0].address = detail;
      r.outputs[0].ownership = issuer;
      r.fee_text = "NONE";
      r.fee_label = "NETWORK";
      r.note = requested == Action::Import ? "Session only. Lock or power loss erases this account. Keep your recovery method." : requested == Action::Time ? "Verify this Unix time with a trusted clock before approving."
                                                                                                                                                            : "Approve on this device. Codes are displayed here only.";
      r.show_decision_buttons = true;
      action = requested;
      pending_started = now_ms();
      wallet_ui_set_decision_callback(decision);
      wallet_ui_show_transaction(r);
      char seal[9];
      if (!wallet_ui_review_seal_code(seal))
      {
        clear_pending();
        wallet_ui_set_decision_callback(nullptr);
        return false;
      }
      return true;
    }
  }
  bool wallet_totp_import(const char *uri, size_t size)
  {
    if (!available())
      return false;
    TotpAccounts candidate;
    uint8_t slot;
    if (candidate.import_uri(uri, size, &slot) != TotpError::Ok)
      return false;
    TotpAccountInfo info;
    if (!candidate.info(slot, &info))
      return false;
    char detail[160];
    const char *algorithm = info.algorithm == TotpAlgorithm::Sha1 ? "SHA1" : info.algorithm == TotpAlgorithm::Sha256 ? "SHA256"
                                                                                                                     : "SHA512";
    snprintf(detail, sizeof(detail), "%s\n%s, %u digits, %u seconds", info.account,
             algorithm, static_cast<unsigned>(info.digits), static_cast<unsigned>(info.period));
    memcpy(pending_uri, uri, size);
    pending_uri[size] = 0;
    pending_uri_size = size;
    return review(Action::Import, "ADD ACCOUNT", info.issuer, detail);
  }
  bool wallet_totp_info(uint8_t slot, TotpAccountInfo *out)
  {
    return wallet_cli_is_authenticated() && accounts.info(slot, out);
  }
  bool wallet_totp_remove(uint8_t slot)
  {
    TotpAccountInfo info;
    if (!available() || !accounts.info(slot, &info))
      return false;
    pending_slot = slot;
    return review(Action::Remove, "REMOVE ACCOUNT", info.issuer, info.account);
  }
  bool wallet_totp_show(uint8_t slot)
  {
    TotpAccountInfo info;
    if (!available() || !accounts.info(slot, &info) || !totp_clock_valid())
      return false;
    pending_slot = slot;
    return review(Action::Show, "SHOW CODE", info.issuer, info.account);
  }
  bool wallet_totp_set_time(uint64_t unix_seconds)
  {
    if (!available() || unix_seconds == 0)
      return false;
    pending_time = unix_seconds;
    char time_text[40];
    snprintf(time_text, sizeof(time_text), "Unix seconds: %llu", static_cast<unsigned long long>(unix_seconds));
    return review(Action::Time, "SET CLOCK", "HOST PROVIDED TIME", time_text);
  }
  bool wallet_totp_pending() { return action != Action::None; }
  void wallet_totp_tick()
  {
    const uint64_t stamp = now_ms();
    if (action != Action::None && (stamp < pending_started || stamp - pending_started >= 120000))
      decision(false);
    if (code_expires != 0 && stamp >= code_expires)
    {
      code_expires = 0;
      wallet_ui_hide_otp();
    }
  }
  void wallet_totp_clear()
  {
    const bool pending = wallet_totp_pending();
    clear_pending();
    accounts.clear();
    totp_clock_clear();
    code_expires = 0;
    wallet_ui_hide_otp();
    if (pending)
    {
      wallet_ui_set_decision_callback(nullptr);
      wallet_ui_show_catalog();
    }
  }
}
