#include "WalletSigning.h"

#include <Arduino.h>
#include <esp_random.h>
#include <esp_system.h>
#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "WalletBoardPort.h"
#include "WalletCatalog.h"
#include "WalletConfig.h"
#include "WalletNetworks.h"
#include "WalletSession.h"

namespace hexwallet {
namespace {

WalletSigningSession active;

bool deadline_reached(uint32_t now, uint32_t deadline) {
  return static_cast<int32_t>(now - deadline) >= 0;
}

WalletSigningError map_bitcoin_error(TransactionError error) {
  switch (error) {
    case TransactionError::Ok: return WalletSigningError::Ok;
    case TransactionError::WrongWallet: return WalletSigningError::WrongWallet;
    case TransactionError::FeePolicy: return WalletSigningError::FeePolicy;
    case TransactionError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case TransactionError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case TransactionError::InvalidArgument: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}

WalletSigningError map_evm_error(EvmTransactionError error) {
  switch (error) {
    case EvmTransactionError::Ok: return WalletSigningError::Ok;
    case EvmTransactionError::WrongWallet: return WalletSigningError::WrongWallet;
    case EvmTransactionError::FeePolicy: return WalletSigningError::FeePolicy;
    case EvmTransactionError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case EvmTransactionError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case EvmTransactionError::InvalidArgument: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}

WalletSigningError map_kaspa_error(KaspaError error) {
  switch (error) {
    case KaspaError::Ok: return WalletSigningError::Ok;
    case KaspaError::WrongWallet: return WalletSigningError::WrongWallet;
    case KaspaError::FeePolicy: return WalletSigningError::FeePolicy;
    case KaspaError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case KaspaError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case KaspaError::InvalidArgument: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}

WalletSigningError map_zcash_error(ZcashError error) {
  switch (error) {
    case ZcashError::Ok: return WalletSigningError::Ok;
    case ZcashError::WrongWallet: return WalletSigningError::WrongWallet;
    case ZcashError::FeePolicy: return WalletSigningError::FeePolicy;
    case ZcashError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case ZcashError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case ZcashError::InvalidArgument: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}

bool catalog_can_sign(const char *network_id) {
  if (network_id == nullptr) return false;
  WalletCatalogEntry entry;
  return wallet_catalog_find(network_id, &entry) &&
         wallet_catalog_has(entry, WalletCapabilitySigning) &&
         wallet_catalog_has(entry, WalletCapabilityTransactionReview);
}

bool load_master(HdPrivateNode *master) {
  if (master == nullptr || !wallet_session_is_loaded()) {
    return false;
  }
  return wallet_session_load_master(master) == WalletError::Ok;
}

void decision_callback(bool approved) {
  if (active.kind == WalletSigningKind::None || active.consumed) return;
  if (approved) {
    active.approved = true;
    active.rejected = false;
  } else {
    active.approved = false;
    active.rejected = true;
  }
  wallet_ui_set_decision_callback(nullptr);
  wallet_ui_show_catalog();
  wallet_ui_set_status(approved
                           ? "Approved. Tap the phone again to collect the signature."
                           : "Rejected. Nothing was signed.");
}

void show_review(const char *network_name, uint64_t fee, uint64_t fee_rate,
                 const char *fee_text, const WalletUiTransactionOutput *outputs,
                 size_t output_count) {
  WalletUiTransactionReview review = {};
  review.network = network_name;
  review.output_count = output_count > kWalletUiMaxTransactionOutputs
                            ? kWalletUiMaxTransactionOutputs
                            : output_count;
  for (size_t index = 0; index < review.output_count; ++index) {
    review.outputs[index] = outputs[index];
  }
  review.fee = fee;
  review.fee_rate = fee_rate;
  review.fee_text = fee_text;
  review.approval_code = nullptr;
  review.show_decision_buttons = true;
  wallet_ui_set_decision_callback(decision_callback);
  wallet_ui_show_transaction(review);
}

void show_bitcoin_review(const BitcoinSigningRequest &request) {
  WalletUiTransactionOutput outputs[kWalletUiMaxTransactionOutputs] = {};
  const size_t count = request.output_count > kWalletUiMaxTransactionOutputs
                           ? kWalletUiMaxTransactionOutputs
                           : request.output_count;
  for (size_t index = 0; index < count; ++index) {
    const BitcoinOutput &output = request.outputs[index];
    outputs[index] = { output.value, nullptr, output.address,
                       output.change ? "CHANGE" : (output.wallet_owned ? "WALLET" : "EXTERNAL") };
  }
  show_review(request.chain.network_id, request.fee,
              request.estimated_vbytes == 0 ? 0 : request.fee / request.estimated_vbytes,
              nullptr, outputs, count);
}

void show_evm_review(const EvmSigningRequest &request) {
  WalletUiTransactionOutput output = {};
  char amount[256];
  const char *asset = request.network == nullptr ? "?" : request.network->symbol;
  if (request.has_call) {
    asset = request.token != nullptr
                ? request.token->symbol
                : evm_token_standard_name(request.call.standard);
  }
  if (request.call.has_token_id) {
    snprintf(amount, sizeof(amount), "%s %s #%s", request.amount_text, asset,
             request.token_id_text);
  } else {
    snprintf(amount, sizeof(amount), "%s %s", request.amount_text, asset);
  }
  bool recipient_zero = true;
  for (size_t index = 0; index < kEvmAddressSize; ++index) {
    if (request.call.recipient[index] != 0) recipient_zero = false;
  }
  const bool layer_zero_peer =
      request.call.standard == EvmTokenStandard::LayerZeroOft ||
      request.call.standard == EvmTokenStandard::LayerZeroOnft;
  const char *recipient = layer_zero_peer && recipient_zero
                              ? request.remote_address_text
                              : request.recipient_address;
  output = { 0, amount, recipient,
             request.has_call ? evm_token_standard_name(request.call.standard) : "NATIVE" };
  char fee[128];
  snprintf(fee, sizeof(fee), "%s %s", request.maximum_fee_text,
           request.network == nullptr ? "?" : request.network->symbol);
  show_review(request.network == nullptr ? "EVM" : request.network->symbol,
              request.maximum_fee, 0, fee, &output, 1);
}

void show_kaspa_review(const KaspaTransaction &request) {
  WalletUiTransactionOutput outputs[kWalletUiMaxTransactionOutputs] = {};
  char amounts[kWalletUiMaxTransactionOutputs][32] = {};
  const size_t count = request.output_count > kWalletUiMaxTransactionOutputs
                           ? kWalletUiMaxTransactionOutputs
                           : request.output_count;
  for (size_t index = 0; index < count; ++index) {
    snprintf(amounts[index], sizeof(amounts[index]), "%llu.%08lu KAS",
             static_cast<unsigned long long>(request.outputs[index].value / kKaspaSompiPerKaspa),
             static_cast<unsigned long>(request.outputs[index].value % kKaspaSompiPerKaspa));
    outputs[index] = { request.outputs[index].value, amounts[index],
                       request.outputs[index].address, "KASPA" };
  }
  char fee[64];
  snprintf(fee, sizeof(fee), "%llu.%08lu KAS",
           static_cast<unsigned long long>(request.fee / kKaspaSompiPerKaspa),
           static_cast<unsigned long>(request.fee % kKaspaSompiPerKaspa));
  show_review("KASPA", request.fee, 0, fee, outputs, count);
}

void show_zcash_review(const ZcashSigningRequest &request) {
  WalletUiTransactionOutput outputs[kWalletUiMaxTransactionOutputs] = {};
  char amounts[kWalletUiMaxTransactionOutputs][32] = {};
  const size_t count = request.output_count > kWalletUiMaxTransactionOutputs
                           ? kWalletUiMaxTransactionOutputs
                           : request.output_count;
  for (size_t index = 0; index < count; ++index) {
    snprintf(amounts[index], sizeof(amounts[index]), "%llu.%08lu ZEC",
             static_cast<unsigned long long>(request.outputs[index].value / kZcashZatsPerZec),
             static_cast<unsigned long>(request.outputs[index].value % kZcashZatsPerZec));
    outputs[index] = { request.outputs[index].value, amounts[index],
                       request.outputs[index].address, "EXTERNAL" };
  }
  char fee[64];
  snprintf(fee, sizeof(fee), "%llu.%08lu ZEC",
           static_cast<unsigned long long>(request.fee / kZcashZatsPerZec),
           static_cast<unsigned long>(request.fee % kZcashZatsPerZec));
  show_review("ZCASH", request.fee, 0, fee, outputs, count);
}

WalletSigningError finish_review(uint32_t now_ms) {
  if (!board_has_display() || !wallet_ui_ready()) {
    wallet_signing_clear();
    return WalletSigningError::Unsupported;
  }
  active.created_ms = now_ms;
  active.expires_ms = now_ms + kWalletSigningReviewMs;
  active.approved = false;
  active.rejected = false;
  active.consumed = false;
  esp_fill_random(active.review_id, sizeof(active.review_id));
  bool nonzero = false;
  for (size_t index = 0; index < sizeof(active.review_id); ++index) {
    if (active.review_id[index] != 0) nonzero = true;
  }
  if (!nonzero) active.review_id[0] = 1;
  switch (active.kind) {
    case WalletSigningKind::Bitcoin: show_bitcoin_review(active.request.bitcoin); break;
    case WalletSigningKind::Evm: show_evm_review(active.request.evm); break;
    case WalletSigningKind::Kaspa: show_kaspa_review(active.request.kaspa); break;
    case WalletSigningKind::Zcash: show_zcash_review(active.request.zcash); break;
    case WalletSigningKind::None: return WalletSigningError::InvalidArgument;
  }
  return WalletSigningError::Ok;
}

}  // namespace

void wallet_signing_clear() {
  wallet_ui_set_decision_callback(nullptr);
  secure_zero(&active, sizeof(active));
}

bool wallet_signing_active() {
  return active.kind != WalletSigningKind::None && !active.consumed;
}

const WalletSigningSession *wallet_signing_session() {
  return wallet_signing_active() ? &active : nullptr;
}

WalletSigningKind wallet_signing_kind() {
  return active.kind;
}

WalletSigningError wallet_signing_begin_bitcoin(const char *network_id,
                                                const uint8_t *psbt,
                                                size_t psbt_size,
                                                uint32_t now_ms) {
  if (network_id == nullptr || psbt == nullptr || psbt_size == 0) {
    return WalletSigningError::InvalidArgument;
  }
  const NetworkProfile *network = find_network_profile(network_id);
  const NetworkSigningPolicy *policy = network == nullptr
                                           ? nullptr
                                           : find_network_signing_policy(network->id);
  if (network == nullptr || policy == nullptr ||
      (policy->family != SighashFamily::Bitcoin &&
       policy->family != SighashFamily::ForkId) ||
      !catalog_can_sign(network->id)) {
    return WalletSigningError::Unsupported;
  }
  HdPrivateNode master;
  if (!load_master(&master)) return WalletSigningError::NoWallet;
  const BitcoinChainParams chain = {
      network->id,
      network->encoding == AddressEncoding::CashAddr ? network->alt_hrp : nullptr,
      network->utxo, policy->family, policy->fork_id };
  wallet_signing_clear();
  const TransactionError error = bitcoin_parse_psbt(
      psbt, psbt_size, master, chain, &active.request.bitcoin);
  secure_zero(&master, sizeof(master));
  if (error != TransactionError::Ok) {
    wallet_signing_clear();
    return map_bitcoin_error(error);
  }
  active.kind = WalletSigningKind::Bitcoin;
  return finish_review(now_ms);
}

WalletSigningError wallet_signing_begin_evm(const char *network_id,
                                            uint32_t address_index,
                                            const uint8_t *transaction,
                                            size_t transaction_size,
                                            uint32_t now_ms) {
  if (network_id == nullptr || transaction == nullptr || transaction_size == 0) {
    return WalletSigningError::InvalidArgument;
  }
  const NetworkProfile *network = find_network_profile(network_id);
  if (network == nullptr || network->encoding != AddressEncoding::Evm ||
      !catalog_can_sign(network->id)) {
    return WalletSigningError::Unsupported;
  }
  HdPrivateNode master;
  if (!load_master(&master)) return WalletSigningError::NoWallet;
  wallet_signing_clear();
  const EvmTransactionError error = evm_parse_transaction(
      transaction, transaction_size, *network, master, address_index,
      &active.request.evm);
  secure_zero(&master, sizeof(master));
  if (error != EvmTransactionError::Ok) {
    wallet_signing_clear();
    return map_evm_error(error);
  }
  active.kind = WalletSigningKind::Evm;
  return finish_review(now_ms);
}

WalletSigningError wallet_signing_begin_kaspa(const uint8_t *payload,
                                              size_t payload_size,
                                              uint32_t now_ms) {
  if (payload == nullptr || payload_size == 0) {
    return WalletSigningError::InvalidArgument;
  }
  if (!catalog_can_sign("kas")) return WalletSigningError::Unsupported;
  wallet_signing_clear();
  const KaspaError error =
      kaspa_parse_review_payload(payload, payload_size, &active.request.kaspa);
  if (error != KaspaError::Ok) {
    wallet_signing_clear();
    return map_kaspa_error(error);
  }
  active.kind = WalletSigningKind::Kaspa;
  return finish_review(now_ms);
}

WalletSigningError wallet_signing_begin_zcash(const uint8_t *payload,
                                              size_t payload_size,
                                              uint32_t now_ms) {
  if (payload == nullptr || payload_size == 0) {
    return WalletSigningError::InvalidArgument;
  }
  const NetworkProfile *network = find_network_profile("zec");
  const NetworkSigningPolicy *policy = find_network_signing_policy("zec");
  const ZcashNetworkPolicy *zcash_policy = find_zcash_network_policy("zec");
  if (network == nullptr || policy == nullptr ||
      policy->family != SighashFamily::ZcashZip243 || zcash_policy == nullptr ||
      !catalog_can_sign("zec")) {
    return WalletSigningError::Unsupported;
  }
  const ZcashChainParams chain = {
      network->id, network->alt_p2pkh_version, network->alt_p2sh_version,
      zcash_policy->branch_id, network->derivation_coin_type };
  wallet_signing_clear();
  const ZcashError error = zcash_parse_review_payload(
      payload, payload_size, chain, &active.request.zcash);
  if (error != ZcashError::Ok) {
    wallet_signing_clear();
    return map_zcash_error(error);
  }
  active.kind = WalletSigningKind::Zcash;
  return finish_review(now_ms);
}

void wallet_signing_reject() {
  if (active.kind == WalletSigningKind::None) return;
  active.approved = false;
  active.rejected = true;
  // Detach the buttons so a late tap cannot flip a rejected review back to
  // approved; the phone must start over.
  wallet_ui_set_decision_callback(nullptr);
  wallet_ui_set_status("Rejected. Nothing was signed.");
}

WalletSigningError wallet_signing_sign(uint8_t *out, size_t *in_out_size) {
  if (out == nullptr || in_out_size == nullptr || !wallet_signing_active() ||
      !active.approved || active.rejected || active.consumed) {
    return WalletSigningError::NotApproved;
  }
  if (deadline_reached(millis(), active.expires_ms)) {
    wallet_signing_clear();
    return WalletSigningError::Expired;
  }
  HdPrivateNode master;
  if (!load_master(&master)) {
    wallet_signing_clear();
    return WalletSigningError::NoWallet;
  }
  WalletSigningError result = WalletSigningError::CryptoFailure;
  switch (active.kind) {
    case WalletSigningKind::Bitcoin:
      result = map_bitcoin_error(bitcoin_sign_request(active.request.bitcoin,
                                                      master, out,
                                                      in_out_size));
      break;
    case WalletSigningKind::Evm:
      result = map_evm_error(evm_sign_transaction(active.request.evm, master,
                                                  out, in_out_size));
      break;
    case WalletSigningKind::Kaspa:
      result = map_kaspa_error(kaspa_sign_transaction(active.request.kaspa,
                                                      master, out,
                                                      in_out_size));
      break;
    case WalletSigningKind::Zcash:
      result = map_zcash_error(zcash_sign_request(active.request.zcash, master,
                                                  out, in_out_size));
      break;
    case WalletSigningKind::None:
      result = WalletSigningError::InvalidArgument;
      break;
  }
  secure_zero(&master, sizeof(master));
  active.consumed = true;
  wallet_signing_clear();
  return result;
}

bool wallet_signing_tick(uint32_t now_ms) {
  if (active.kind == WalletSigningKind::None) return false;
  if (deadline_reached(now_ms, active.expires_ms)) {
    wallet_signing_clear();
    wallet_ui_show_catalog();
    return true;
  }
  return false;
}

const char *wallet_signing_error_text(WalletSigningError error) {
  switch (error) {
    case WalletSigningError::Ok: return "ok";
    case WalletSigningError::InvalidArgument: return "invalid-argument";
    case WalletSigningError::NoWallet: return "wallet-empty";
    case WalletSigningError::Unsupported: return "unsupported";
    case WalletSigningError::WrongWallet: return "wrong-wallet";
    case WalletSigningError::FeePolicy: return "fee-policy";
    case WalletSigningError::ParseFailed: return "parse-failed";
    case WalletSigningError::CryptoFailure: return "crypto-failure";
    case WalletSigningError::NotApproved: return "not-approved";
    case WalletSigningError::Expired: return "expired";
    case WalletSigningError::AlreadyConsumed: return "already-consumed";
    case WalletSigningError::BufferTooSmall: return "buffer-too-small";
  }
  return "unknown";
}

bool run_wallet_signing_self_test() {
  // The full path needs a loaded mnemonic and a trusted display; those are
  // exercised on-device. This checks the fail-closed state machine and error
  // mapping that must hold before any transaction is parsed.
  wallet_signing_clear();
  bool ok = !wallet_signing_active();
  uint8_t output[64];
  size_t output_size = sizeof(output);
  ok = ok && wallet_signing_sign(output, &output_size) ==
                 WalletSigningError::NotApproved;
  const uint8_t empty = 0;
  ok = ok && wallet_signing_begin_bitcoin("btc", &empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  ok = ok && wallet_signing_begin_evm("eth", 0, &empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  ok = ok && wallet_signing_begin_kaspa(&empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  ok = ok && wallet_signing_begin_zcash(&empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  return ok;
}

}  // namespace hexwallet
