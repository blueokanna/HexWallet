#include "WalletCliPolicy.h"

#include <stdio.h>
#include <string.h>

namespace hexwallet {
namespace {

struct CommandPattern {
  const char *prefix;
  bool exact;
};

constexpr CommandPattern kTransactionCommands[] = {
  {"tx sign ", false},
  {"tx reject", true},
  {"evm sign ", false},
  {"kaspa sign ", false},
  {"zec sign ", false},
  {"chain sign ", false},
  {"chain reject", true},
  {"beam finalize ", false},
  {"beam approve ", false},
  {"beam reject", true},
};

constexpr CommandPattern kPairingCommands[] = {
  {"link pair confirm", true},
  {"link pair reject", true},
};

constexpr CommandPattern kPassiveCommands[] = {
  {"help", true},
  {"status", true},
  {"lock", true},
  {"link status", true},
};

bool matches(const CommandPattern &pattern, const char *command) {
  if (command == nullptr) {
    return false;
  }
  if (pattern.exact) {
    return strcmp(command, pattern.prefix) == 0;
  }
  const size_t length = strlen(pattern.prefix);
  return strncmp(command, pattern.prefix, length) == 0 && command[length] != '\0';
}

template <size_t N>
bool matches_any(const CommandPattern (&patterns)[N], const char *command) {
  for (const CommandPattern &pattern : patterns) {
    if (matches(pattern, command)) {
      return true;
    }
  }
  return false;
}

}  // namespace

bool wallet_cli_command_is_passive(const char *command) {
  return matches_any(kPassiveCommands, command);
}

bool wallet_cli_command_resolves(PendingReview review, const char *command) {
  switch (review) {
    case PendingReview::Transaction:
      return matches_any(kTransactionCommands, command);
    case PendingReview::Pairing:
      return matches_any(kPairingCommands, command);
    case PendingReview::Signing:
    case PendingReview::Totp:
    case PendingReview::None:
      break;
  }
  return false;
}

const char *wallet_cli_review_error(PendingReview review) {
  switch (review) {
    case PendingReview::Transaction:
      return "ERR transaction-review-active";
    case PendingReview::Signing:
    case PendingReview::Totp:
    case PendingReview::Pairing:
      return "ERR device-review-active";
    case PendingReview::None:
      break;
  }
  return "ERR unknown-review-state";
}

bool run_wallet_cli_policy_self_test() {
  bool passed = true;

  for (const CommandPattern &pattern : kPassiveCommands) {
    passed = passed && wallet_cli_command_is_passive(pattern.prefix);
  }
  passed = passed && !wallet_cli_command_is_passive(nullptr);
  passed = passed && !wallet_cli_command_is_passive("");
  passed = passed && !wallet_cli_command_is_passive("statusx");
  passed = passed && !wallet_cli_command_is_passive("link statuses");
  passed = passed && !wallet_cli_command_is_passive(" lock");
  passed = passed && !wallet_cli_command_is_passive("lock ");

  for (const CommandPattern &pattern : kTransactionCommands) {
    if (pattern.exact) {
      passed = passed && wallet_cli_command_resolves(PendingReview::Transaction, pattern.prefix);
      continue;
    }
    char probe[64];
    const int written = snprintf(probe, sizeof(probe), "%s000000", pattern.prefix);
    passed = passed && written > 0 && static_cast<size_t>(written) < sizeof(probe) &&
             wallet_cli_command_resolves(PendingReview::Transaction, probe);
  }
  passed = passed &&
           wallet_cli_command_resolves(PendingReview::Transaction, "tx sign 123456");
  passed = passed &&
           wallet_cli_command_resolves(PendingReview::Transaction, "chain sign 123456");
  passed = passed &&
           wallet_cli_command_resolves(PendingReview::Transaction, "chain reject");
  passed = passed && !wallet_cli_command_resolves(PendingReview::Transaction, nullptr);
  passed = passed && !wallet_cli_command_resolves(PendingReview::Transaction, "chain sign");
  passed = passed && !wallet_cli_command_resolves(PendingReview::Transaction, "chain signer 1");
  passed = passed && !wallet_cli_command_resolves(PendingReview::Transaction, "chain begin ton 0 00");
  passed = passed && !wallet_cli_command_resolves(PendingReview::Transaction, "tx inspect 00");
  passed = passed && !wallet_cli_command_resolves(PendingReview::Transaction, "status");
  passed = passed && !wallet_cli_command_resolves(PendingReview::Transaction, "link pair confirm");

  for (const CommandPattern &pattern : kPairingCommands) {
    passed = passed && wallet_cli_command_resolves(PendingReview::Pairing, pattern.prefix);
  }
  passed = passed && !wallet_cli_command_resolves(PendingReview::Pairing, "link pair");
  passed = passed && !wallet_cli_command_resolves(PendingReview::Pairing, "link status");
  passed = passed && !wallet_cli_command_resolves(PendingReview::Pairing, "chain reject");

  const char *const probes[] = {"tx sign 123456", "chain reject", "link pair confirm", "status"};
  for (const char *probe : probes) {
    passed = passed && !wallet_cli_command_resolves(PendingReview::Signing, probe);
    passed = passed && !wallet_cli_command_resolves(PendingReview::Totp, probe);
    passed = passed && !wallet_cli_command_resolves(PendingReview::None, probe);
  }

  passed = passed && strcmp(wallet_cli_review_error(PendingReview::Transaction),
                            "ERR transaction-review-active") == 0;
  passed = passed && strcmp(wallet_cli_review_error(PendingReview::Signing),
                            "ERR device-review-active") == 0;
  passed = passed && strcmp(wallet_cli_review_error(PendingReview::Pairing),
                            "ERR device-review-active") == 0;
  return passed;
}

}
