#ifndef HEXWALLET_UI_H
#define HEXWALLET_UI_H

#include <stddef.h>
#include <stdint.h>

#include "WalletConfig.h"
#include "TrustAnchor.h"

namespace hexwallet {

constexpr size_t kWalletUiMaxTransactionOutputs = 16;

struct WalletUiTransactionOutput {
  uint64_t value;
  const char *amount_text;
  const char *address;
  const char *ownership;
  // Rendered separately, without the summary line's fixed-size buffer.
  // SPL uses this for the full mint, source account and integer precision.
  const char *details;
  // Only firmware-authored role labels may be translated. Account names and
  // token symbols can be request data and must remain verbatim.
  bool ownership_is_label;
};

struct WalletUiTransactionReview {
  const char *network;
  WalletUiTransactionOutput outputs[kWalletUiMaxTransactionOutputs];
  size_t output_count;
  uint64_t fee;
  uint64_t fee_rate;
  const char *fee_text;
  const char *fee_label; // nullptr preserves MAX FEE; SOL uses EST. FEE
  // Optional total spent (sum of outputs plus fee). Null hides the line.
  const char *total_text;
  // Optional honest caveat shown in warning colour (for example that ring
  // decoys are host-supplied and cannot be chain-verified offline).
  const char *note;
  const char *approval_code;
  // Link-originated requests use on-device APPROVE/REJECT buttons instead of
  // the six-digit code that the serial host must echo back.
  bool show_decision_buttons;
};

using WalletUiDecisionCallback = void (*)(bool approved);
void wallet_ui_set_decision_callback(WalletUiDecisionCallback callback);

enum class WalletUiLanguage : uint8_t { English, Chinese };
WalletUiLanguage wallet_ui_language();
// Changes the menu language. An active review, pairing or OTP must be closed first.
// The preference is held in RAM and defaults to English after power-on.
bool wallet_ui_set_language(WalletUiLanguage language);

bool wallet_ui_init();
bool wallet_ui_ready();
void wallet_ui_show_port_error();
void wallet_ui_set_authenticated(bool authenticated);
void wallet_ui_set_status(const char *status);
// Renders `status` immediately; call before a multi-second MCU computation so
// the trusted display is not frozen on the previous screen.
void wallet_ui_show_busy(const char *status);
void wallet_ui_show_catalog();
// Copies the complete public address/path into wrapping display labels. False
// means there is no working trusted display; callers must not claim verification.
bool wallet_ui_show_address(const char *network, const char *address,
                            const char *path);
bool wallet_ui_show_otp(const char *issuer, const char *account, const char *code,
                        uint64_t expires_unix);
void wallet_ui_hide_otp();
void wallet_ui_show_transaction(const WalletUiTransactionReview &review);
void wallet_ui_show_refusal(const char *reason);

// Trusted-verification tie between the panel and the signer.
//
// wallet_ui_show_transaction() hashes the exact strings it renders into a review
// seal and shows its 8-character code under the review. The seal is armed only
// after the panel reports the frame committed, and wallet_ui_review_authorize()
// consumes it exactly once: displayed, fresh, unused. An approval that outlives
// its own screen therefore cannot sign anything.
bool wallet_ui_review_seal_code(char out[9]);
bool wallet_ui_review_digest(uint8_t out[kReviewSealSize]);
bool wallet_ui_review_authorize(const uint8_t expected[kReviewSealSize]);
bool wallet_ui_review_authorize();
void wallet_ui_show_pairing(uint32_t code, const char *fingerprint);
void wallet_ui_service();

}  // namespace hexwallet

#endif
