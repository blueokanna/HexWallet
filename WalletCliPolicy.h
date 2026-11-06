#ifndef HEXWALLET_WALLET_CLI_POLICY_H
#define HEXWALLET_WALLET_CLI_POLICY_H

#include <stdint.h>

namespace hexwallet {

enum class PendingReview : uint8_t {
  None = 0,
  Transaction,  // inspected and waiting for <family> sign / reject
  Signing,      // on-screen confirmation, resolved by the buttons only
  Totp,         // on-screen confirmation, resolved by the buttons only
  Pairing,      // phone pairing, resolved by `link pair confirm|reject`
};

// `help`, `status`, `lock` and `link status` change nothing, so they stay
// available in every phase. Exact matches only: "statusx" is a typo, not a query.
bool wallet_cli_command_is_passive(const char *command);

// True when `command` can finish `review`. Handlers still validate the approval
// code and the pending kind; this only decides whether the command may run.
bool wallet_cli_command_resolves(PendingReview review, const char *command);

// The single error line a blocked command prints, so the phone-side client and
// the docs quote the same strings.
const char *wallet_cli_review_error(PendingReview review);

// Pins the table above: every documented finish command must be allowed, and the
// commands that start a *new* request must not be.
bool run_wallet_cli_policy_self_test();

}  // namespace hexwallet

#endif
