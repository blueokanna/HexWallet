#include "BeamCli.h"
#include "WalletConfig.h"

#if HEXWALLET_ENABLE_CLI
#include <Arduino.h>
#include <cstring>
#include <memory>
#include "BeamPayment.h"
#include "BeamAddress.h"
#include "BatteryMonitor.h"
#include "ChainCommon.h"
#include "RandomSource.h"
#include "SensitiveValue.h"
#include "WalletSession.h"
#include "WalletTransportPolicy.h"
#include "WalletUi.h"
#include "WalletWorker.h"

namespace hexwallet {
namespace {
constexpr uint32_t kExchangeTimeout = 120000;
bool display_is_available;

bool expired(uint32_t deadline) {
  return static_cast<int32_t>(millis() - deadline) >= 0;
}

bool decode_hex_exact(const char *text, uint8_t *out, size_t size) {
  size_t written;
  return strlen(text) == size * 2 && chain_parse_hex(text, out, size, &written) && written == size;
}

void print_hex(const uint8_t *data, size_t size) {
  char buffer[65];
  while (size) {
    const size_t n = size < 32 ? size : 32;
    chain_hex(data, n, buffer, sizeof(buffer));
    Serial.print(buffer);
    data += n;
    size -= n;
  }
}

enum class BeamPhase { Offer, ReviewSend, ReviewReceive };
struct BeamExchange {
  BeamPhase phase = BeamPhase::Offer;
  BeamSender sender;
  BeamOffer offer{};
  BeamReceiverReply reply{};
  uint64_t endpoint_index = 0;
  uint64_t change = 0;
  char recipient_address[kBeamRegularAddressSize]{};
  uint32_t approval = 0, expires_at = 0;
};
std::unique_ptr<BeamExchange> beam_exchange;
enum class BeamOperation { Prove, Verify, Recover };
struct BeamJob {
  BeamOperation operation;
  BeamCoin coin;
  BeamOutput output;
  uint8_t seed[kSeedSize];
  bool ok;
};

void run_beam_job(void *context) {
  auto &job = *static_cast<BeamJob *>(context);
  switch (job.operation) {
    case BeamOperation::Prove:
      job.ok = beam_create_output(job.seed, job.coin, job.output);
      break;
    case BeamOperation::Verify:
      job.ok = beam_verify_output(job.output);
      break;
    case BeamOperation::Recover:
      job.ok = beam_recover_output(job.seed, job.output, job.coin);
      break;
  }
}

bool beam_number(const char *&cursor, uint64_t limit, uint64_t &value, char delimiter) {
  if (*cursor < '0' || *cursor > '9') return false;
  value = 0;
  while (*cursor >= '0' && *cursor <= '9') {
    const unsigned digit = *cursor++ - '0';
    if (value > (limit - digit) / 10) return false;
    value = value * 10 + digit;
  }
  if (*cursor != delimiter) return false;
  if (delimiter) ++cursor;
  return true;
}

template<typename F>
bool beam_work(F &&function) {
  struct Work { F &fn; bool ok; } work{function, false};
  auto run = [](void *ctx) {
    auto &w = *static_cast<Work *>(ctx);
    w.ok = w.fn();
  };
  return wallet_worker_execute(run, &work, HEXWALLET_WORKER_JOB_TIMEOUT_MS, millis,
      [] { delay(1); }) == WalletWorkerResult::Completed && work.ok;
}

bool beam_transfer_allowed() {
  return display_is_available && wallet_session_is_loaded() &&
      wallet_transport_allows(WalletTransport::SerialUsb, WalletTransportOperation::ApprovalResponse,
                              WalletTransportState{true, false, display_is_available, battery_monitor_blocks_signing()});
}

void beam_drop(const char *message) {
  beam_cli_reset();
  wallet_ui_show_catalog();
  Serial.println(message);
}

void review_beam(BeamExchange &session) {
  uint32_t code;
  if (!random_fill_checked(&code, sizeof(code))) {
    beam_drop("ERR entropy-unavailable");
    return;
  }
  const bool sending = session.phase == BeamPhase::ReviewSend;
  char amount[48], fee[48], peer[65], details[144], approval[7];
  chain_format_units(session.offer.amount, 8, "BEAM", amount, sizeof(amount));
  chain_format_units(session.offer.fee, 8, "BEAM", fee, sizeof(fee));
  chain_hex(sending ? session.offer.receiver : session.offer.sender, 32, peer, sizeof(peer));
  snprintf(details, sizeof(details), "Heights %llu to %llu\nOwn endpoint %llu\nChange %llu groth",
      (unsigned long long)session.offer.min_height, (unsigned long long)session.offer.max_height,
      (unsigned long long)session.endpoint_index, (unsigned long long)session.change);
  session.approval = code % 1000000;
  snprintf(approval, sizeof(approval), "%06lu", (unsigned long)session.approval);
  WalletUiTransactionReview review{};
  review.network = sending ? "BEAM mainnet send" : "BEAM mainnet receive";
  review.output_count = 1;
  review.outputs[0].address = session.recipient_address[0] ? session.recipient_address : peer;
  review.outputs[0].amount_text = amount;
  review.outputs[0].ownership = sending ? (session.recipient_address[0] ? "Receiver address" : "Receiver endpoint") : "Declared sender endpoint";
  review.outputs[0].details = details;
  review.fee_label = sending ? "FEE" : "SENDER PAYS";
  review.fee_text = fee;
  review.note = sending ? "Input availability is checked by the node." : "Await node confirmation before crediting this payment.";
  review.approval_code = approval;
  beam_exchange->expires_at = millis() + kExchangeTimeout;
  wallet_ui_show_transaction(review);
  secure_zero(approval, sizeof(approval));
  Serial.println("OK review-on-device");
}

void start_beam_exchange(char *args, bool sending) {
  if (!beam_transfer_allowed() || beam_exchange) {
    Serial.println("ERR beam-transfer-needs-wallet-and-trusted-display");
    return;
  }
  const char *cursor = args;
  uint64_t index;
  if (!beam_number(cursor, UINT64_MAX, index, ' ') || !index) {
    Serial.println("ERR invalid-beam-endpoint-index");
    return;
  }
  std::unique_ptr<BeamExchange> state(new (std::nothrow) BeamExchange);
  SensitiveValue<uint8_t[kSeedSize]> seed;
  if (!state || wallet_session_load_seed(seed.get()) != WalletError::Ok) {
    Serial.println("ERR wallet-unavailable");
    return;
  }
  state->endpoint_index = index;
  uint8_t encoded[kBeamOfferSize];
  if (!sending) {
    uint8_t me[32];
    if (!decode_hex_exact(cursor, encoded, sizeof(encoded)) || !beam_decode_offer(encoded, state->offer) ||
        !beam_work([&] { return beam_endpoint(seed.get(), index, me); }) ||
        memcmp(me, state->offer.receiver, sizeof(me))) {
      Serial.println("ERR beam-offer-not-for-this-endpoint");
      return;
    }
    state->phase = BeamPhase::ReviewReceive;
    beam_exchange = std::move(state);
    review_beam(*beam_exchange);
    return;
  }
  char *sep = strchr(args + (cursor - args), ' ');
  uint8_t receiver[32];
  if (!sep) { Serial.println("ERR invalid-beam-offer"); return; }
  *sep = 0;
  if (beam_regular_recipient(cursor, receiver)) {
    memcpy(state->recipient_address, cursor, strlen(cursor) + 1);
  } else if (!decode_hex_exact(cursor, receiver, sizeof(receiver))) {
    Serial.println("ERR invalid-beam-receiver");
    return;
  }
  cursor = sep + 1;
  BeamOutput input;
  uint64_t amount, fee, low, high;
  if (!beam_number(cursor, UINT64_MAX, amount, ' ') || !beam_number(cursor, UINT64_MAX, fee, ' ') ||
      !beam_number(cursor, UINT64_MAX, low, ' ') || !beam_number(cursor, UINT64_MAX, high, ' ') ||
      !decode_hex_exact(cursor, reinterpret_cast<uint8_t *>(&input), sizeof(input)) ||
      !beam_work([&] {
        return state->sender.begin(seed.get(), index, receiver, input, amount, fee, low, high, state->offer);
      })) {
    Serial.println("ERR invalid-beam-funding-or-terms");
    return;
  }
  state->change = state->sender.change_amount();
  beam_encode_offer(state->offer, encoded);
  beam_exchange = std::move(state);
  beam_exchange->expires_at = millis() + kExchangeTimeout;
  Serial.print("OK beam-offer=");
  print_hex(encoded, sizeof(encoded));
  Serial.println();
}

void advance_beam_exchange(const char *args, bool confirm) {
  if (!beam_exchange) {
    Serial.println("ERR no-beam-exchange");
    return;
  }
  auto &s = *beam_exchange;
  if (!beam_transfer_allowed() || expired(s.expires_at)) {
    beam_drop("ERR beam-exchange-closed");
    return;
  }
  if (!confirm) {
    if (s.phase != BeamPhase::Offer ||
        !decode_hex_exact(args, reinterpret_cast<uint8_t *>(&s.reply), sizeof(s.reply)) ||
        !beam_work([&] { return beam_verify_receiver(s.offer, s.reply); }) ||
        expired(s.expires_at)) {
      beam_drop("ERR invalid-or-expired-beam-reply");
      return;
    }
    s.phase = BeamPhase::ReviewSend;
    review_beam(s);
    return;
  }
  uint64_t supplied;
  if (s.phase == BeamPhase::Offer || strlen(args) != 6 ||
      !beam_number(args, 999999, supplied, '\0') || supplied != s.approval ||
      !wallet_ui_review_authorize()) {
    beam_drop("ERR invalid-beam-approval");
    return;
  }
  SensitiveValue<uint8_t[kSeedSize]> seed;
  if (wallet_session_load_seed(seed.get()) != WalletError::Ok) { beam_drop("ERR wallet-unavailable"); return; }
  BeamSignedTransfer tx{};
  const bool sending = s.phase == BeamPhase::ReviewSend;
  const bool ok = beam_work([&] {
    if (!sending) return beam_receive(seed.get(), s.endpoint_index, s.offer, s.reply);
    uint8_t me[32];
    return beam_endpoint(seed.get(), s.endpoint_index, me) && !memcmp(me, s.offer.sender, 32) &&
           s.sender.finish(s.reply, tx);
  });
  if (ok && !expired(s.expires_at) && beam_transfer_allowed()) {
    Serial.print(sending ? "OK beam-transaction=" : "OK beam-receiver-reply=");
    if (sending) print_hex(tx.bytes, tx.size);
    else print_hex(reinterpret_cast<const uint8_t *>(&s.reply), sizeof(s.reply));
    Serial.println();
  } else Serial.println("ERR beam-signing-failed");
  beam_cli_reset();
  wallet_ui_show_catalog();
}

void handle_beam(char *args) {
  // Authentication and exclusive ownership of the review screen are checked by WalletCli.
  if (!strncmp(args, "offer ", 6)) { start_beam_exchange(args + 6, true); return; }
  if (!strncmp(args, "receive ", 8)) { start_beam_exchange(args + 8, false); return; }
  if (!strncmp(args, "finalize ", 9)) { advance_beam_exchange(args + 9, false); return; }
  if (!strncmp(args, "approve ", 8)) { advance_beam_exchange(args + 8, true); return; }
  if (!strcmp(args, "reject")) {
    if (beam_exchange) beam_drop("OK beam-exchange-cleared");
    else Serial.println("ERR no-beam-exchange");
    return;
  }
  const bool show_address = !strncmp(args, "address ", 8);
  if (show_address || !strncmp(args, "endpoint ", 9)) {
    SensitiveValue<uint8_t[kSeedSize]> seed;
    const char *number = args + (show_address ? 8 : 9);
    uint64_t index;
    uint8_t endpoint[32];
    char address[kBeamRegularAddressSize]{};
    if (!beam_number(number, UINT64_MAX, index, '\0') || !index ||
        wallet_session_load_seed(seed.get()) != WalletError::Ok ||
        !beam_work([&] { return show_address ? beam_regular_address(seed.get(), index, address) :
                                              beam_endpoint(seed.get(), index, endpoint); })) {
      Serial.println("ERR beam-endpoint-unavailable");
      return;
    }
    if (show_address) {
      char path[44];
      snprintf(path, sizeof(path), "Beam address %llu", (unsigned long long)index);
      if (!display_is_available || !wallet_ui_show_address("beam", address, path)) {
        Serial.println("ERR trusted-display-unavailable");
        return;
      }
      Serial.print("OK beam-address=");
      Serial.println(address);
      return;
    }
    Serial.print("OK beam-endpoint=");
    print_hex(endpoint, sizeof(endpoint));
    Serial.println();
    return;
  }
  if (strncmp(args, "check-peer ", 11) == 0) {
    struct PeerCheck {
      uint8_t offer[kBeamOfferSize];
      BeamReceiverReply reply;
      bool valid;
    } check{};
    args += 11;

    char *split = strchr(args, ' ');
    if (!split || size_t(split - args) != 2 * kBeamOfferSize ||
        !decode_hex_exact(split + 1, reinterpret_cast<uint8_t *>(&check.reply), sizeof(check.reply))) {
      Serial.println("ERR invalid-beam-peer-frame");
      return;
    }
    *split = 0;
    if (!decode_hex_exact(args, check.offer, sizeof(check.offer))) {
      Serial.println("ERR invalid-beam-peer-frame");
      return;
    }
    const auto verify = [](void *ctx) {
      auto &job = *static_cast<PeerCheck *>(ctx);
      BeamOffer offer{};
      job.valid = beam_decode_offer(job.offer, offer) && beam_verify_receiver(offer, job.reply);
    };
    const auto result = wallet_worker_execute(verify, &check, HEXWALLET_WORKER_JOB_TIMEOUT_MS,
        millis, [] { wallet_ui_service(); delay(1); });
    Serial.println(result == WalletWorkerResult::Completed && check.valid ?
        "OK beam-receiver-contribution-valid" : "ERR invalid-beam-receiver-contribution");
    return;
  }
  SensitiveValue<BeamJob> storage;
  auto &job = storage.get();
  if (strncmp(args, "prove ", 6) == 0) {
    job.operation = BeamOperation::Prove;
    args += 6;
    if (strncmp(args, "regular ", 8) == 0) {
      job.coin.type = BeamCoinType::Regular;
      args += 8;
    } else if (strncmp(args, "change ", 7) == 0) {
      job.coin.type = BeamCoinType::Change;
      args += 7;
    } else {
      Serial.println("ERR beam-coin-type");
      return;
    }
    uint64_t subkey;
    const char *numbers = args;
    if (!beam_number(numbers, UINT64_MAX, job.coin.index, ' ') ||
        !beam_number(numbers, 0xffffff, subkey, ' ') ||
        !beam_number(numbers, UINT64_MAX, job.coin.groth, '\0') || !job.coin.groth) {
      Serial.println("ERR invalid-beam-coin");
      return;
    }
    job.coin.subkey = static_cast<uint32_t>(subkey);
  } else {
    if (strncmp(args, "verify ", 7) == 0) {
      job.operation = BeamOperation::Verify;
      args += 7;
    } else if (strncmp(args, "recover ", 8) == 0) {
      job.operation = BeamOperation::Recover;
      args += 8;
    } else {
      Serial.println("ERR invalid-beam-command");
      return;
    }
    if (!decode_hex_exact(args, reinterpret_cast<uint8_t *>(&job.output), sizeof(job.output))) {
      Serial.println("ERR invalid-beam-output");
      return;
    }
  }
  if (job.operation != BeamOperation::Verify && wallet_session_load_seed(job.seed) != WalletError::Ok) {
    Serial.println("ERR wallet-seed-unavailable");
    return;
  }
  const auto result = wallet_worker_execute(run_beam_job, &job, HEXWALLET_WORKER_JOB_TIMEOUT_MS,
      millis, [] { wallet_ui_service(); delay(1); });
  if (result != WalletWorkerResult::Completed || !job.ok) {
    Serial.println("ERR beam-output-operation-failed");
  } else if (job.operation == BeamOperation::Verify) {
    Serial.println("OK beam-output-proof-valid");
  } else if (job.operation == BeamOperation::Recover) {
    Serial.printf("OK beam-owned-output type=%s index=%llu subkey=%lu groth=%llu\n",
        job.coin.type == BeamCoinType::Change ? "change" : "regular",
        (unsigned long long)job.coin.index, (unsigned long)job.coin.subkey,
        (unsigned long long)job.coin.groth);
  } else {
    Serial.print("OK beam-output=");
    print_hex(reinterpret_cast<const uint8_t *>(&job.output), sizeof(job.output));
    Serial.println();
  }
}

}
void beam_cli_reset() { beam_exchange.reset(); }
BeamCliState beam_cli_command(char *args, bool display_available) {
  display_is_available = display_available;
  handle_beam(args);
  return {bool(beam_exchange), beam_exchange ? beam_exchange->expires_at : 0};
}
}
#endif
