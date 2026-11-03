#ifndef HEXWALLET_BITCOIN_REVIEW_H
#define HEXWALLET_BITCOIN_REVIEW_H

#include "BitcoinTransaction.h"
#include "ChainCommon.h"
#include "WalletUi.h"
#include <stdio.h>
#include <string.h>

namespace hexwallet {

// Public display text only. Keep alive until wallet_ui_show_transaction returns.
struct BitcoinReviewText {
  char amounts[kWalletUiMaxTransactionOutputs][48];
  char fee[96];
};

// Shared by serial USB and the link signing session. Rendering failure must
// prevent approval; no output may disappear because a UI array is smaller.
inline bool bitcoin_prepare_review(const BitcoinSigningRequest &request,
                                   BitcoinReviewText *text,
                                   WalletUiTransactionReview *out) {
  static_assert(kBitcoinMaxOutputs <= kWalletUiMaxTransactionOutputs,
                "Bitcoin review must display every output");
  if (text == nullptr || out == nullptr || request.output_count == 0 ||
      request.output_count > kBitcoinMaxOutputs || request.estimated_vbytes == 0)
    return false;
  const NetworkProfile *network = find_network_profile(request.chain.network_id);
  if (network == nullptr) return false;
  const bool pearl = !strcmp(network->id, "prl");
  WalletUiTransactionReview review = {};
  review.network = network->id;
  review.output_count = request.output_count;
  review.fee = request.fee;
  review.fee_rate = request.fee / request.estimated_vbytes;
  for (size_t i = 0; i < request.output_count; ++i) {
    const BitcoinOutput &output = request.outputs[i];
    if (pearl && !chain_format_units(output.value, 8, "PRL", text->amounts[i], sizeof(text->amounts[i])))
      return false;
    review.outputs[i] = {output.value, pearl ? text->amounts[i] : nullptr,
                        output.address, output.change ? "CHANGE" : (output.wallet_owned ? "WALLET" : "EXTERNAL")};
  }
  if (pearl) {
    char fee[48];
    if (!chain_format_units(request.fee, 8, "PRL", fee, sizeof(fee))) return false;
    const int size = snprintf(text->fee, sizeof(text->fee), "%s | %llu grain/vB (floor)",
                              fee, static_cast<unsigned long long>(review.fee_rate));
    if (size < 0 || static_cast<size_t>(size) >= sizeof(text->fee)) return false;
    review.fee_text = text->fee;
    review.fee_label = "FEE";
  }
  *out = review;
  return true;
}

} // namespace hexwallet
#endif
