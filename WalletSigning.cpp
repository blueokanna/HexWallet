#include "WalletSigning.h"

#include <Arduino.h>
#include "RandomSource.h"
#include <esp_system.h>
#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "CryptoNoteAddress.h"
#include "CryptoNoteReview.h"
#include "TrustAnchor.h"
#include "WalletBoardPort.h"
#include "WalletCatalog.h"
#include "WalletConfig.h"
#include "WalletEngine.h"
#include "WalletNetworks.h"
#include "WalletSession.h"
#include "SensitiveValue.h"
#include "WalletWorker.h"
#include "WalletAltAddresses.h"
#include "CryptoExtended.h"
#include "base58.h"

namespace hexwallet {
namespace {

WalletSigningSession active;

bool deadline_reached(uint32_t now, uint32_t deadline) {
  return static_cast<int32_t>(now - deadline) >= 0;
}

// Bulletproofs+ verification needs roughly 7 KiB of stack, which is close to
// the whole 8 KiB Arduino loop task. The reviewed request is built on the
// crypto worker (24 KiB) while the loop task waits; the display update stays
// on the calling task because LVGL is not thread safe.
struct CryptoNotePrepareJob {
  const char *network_id = nullptr;
  const uint8_t *payload = nullptr;
  size_t payload_size = 0;
  uint8_t spend_secret[kCryptoNoteKeySize] = {};
  uint8_t view_secret[kCryptoNoteKeySize] = {};
  CryptoNoteSigningState *state = nullptr;
  CryptoNoteTxError error = CryptoNoteTxError::CryptoFailure;
};

void run_cryptonote_prepare_job(void *context) {
  CryptoNotePrepareJob *job = static_cast<CryptoNotePrepareJob *>(context);
  job->error = cryptonote_signing_prepare_with_keys(
      job->network_id, job->payload, job->payload_size, job->view_secret,
      job->spend_secret, job->state);
  secure_zero(job->spend_secret, sizeof(job->spend_secret));
  secure_zero(job->view_secret, sizeof(job->view_secret));
}

void service_crypto_wait() {
  wallet_ui_service();
  delay(1);
}

// Common worker/key lifecycle; chain codecs and their error policies stay typed.
template <typename Transaction, typename Error>
struct SeedSignJob {
  const Transaction *request;
  const uint8_t *seed;
  uint8_t *out;
  size_t *size;
  Error (*sign)(const Transaction &, const uint8_t *, uint8_t *, size_t *);
  Error error;
  static void run(void *context) {
    auto *job = static_cast<SeedSignJob *>(context);
    job->error = job->sign(*job->request, job->seed, job->out, job->size);
  }
};

template <typename Transaction, typename Error>
WalletSigningError sign_seed_transaction(const Transaction &request, const char *busy,
    Error (*sign)(const Transaction &, const uint8_t *, uint8_t *, size_t *),
    WalletSigningError (*map_error)(Error), uint8_t *out, size_t *size) {
  SensitiveValue<uint8_t[kSeedSize]> seed;
  if (wallet_session_load_seed(seed.get()) != WalletError::Ok) {
    wallet_signing_clear();
    return WalletSigningError::NoWallet;
  }
  wallet_ui_show_busy(busy);
  SeedSignJob<Transaction, Error> job{&request, seed.get(), out, size, sign, Error::CryptoFailure};
  // execute drains a timed-out worker before releasing its borrowed seed.
  const WalletWorkerResult result = wallet_worker_execute(
      SeedSignJob<Transaction, Error>::run, &job, HEXWALLET_WORKER_JOB_TIMEOUT_MS,
      millis, service_crypto_wait);
  const Error error = job.error;
  secure_zero(&job, sizeof(job));
  wallet_signing_clear();
  if (result == WalletWorkerResult::TimedOut) return WalletSigningError::Expired;
  if (result != WalletWorkerResult::Completed) return WalletSigningError::Unsupported;
  return map_error(error);
}
struct ChainPrepareJob {
  ChainFamily family;
  const uint8_t *payload;
  size_t size;
  const HdPrivateNode *master;
  const uint8_t *seed;
  uint32_t index;
  ChainTransaction *request;
  ChainError error;
};
struct DashPrepareJob {
  const uint8_t *payload;
  size_t size;
  DashChainParams chain;
  const HdPrivateNode *master;
  DashTransaction *request;
  DashError error;
};
struct DashSignJob {
  const DashTransaction *request;
  const HdPrivateNode *master;
  uint8_t *out;
  size_t *size;
  DashError error;
};
void run_dash_prepare_job(void *context) {
  auto *job = static_cast<DashPrepareJob *>(context);
  job->error = dash_parse_review_payload(job->payload, job->size,
                                         job->chain, job->request);
  if (job->error == DashError::Ok)
    job->error = dash_validate_inputs(*job->request, *job->master);
}
void run_dash_sign_job(void *context) {
  auto *job = static_cast<DashSignJob *>(context);
  job->error = dash_sign_transaction(*job->request, *job->master,
                                     job->out, job->size);
}
struct ChainSignJob {
  const ChainTransaction *request;
  const HdPrivateNode *master;
  const uint8_t *seed;
  uint8_t *out;
  size_t *size;
  ChainError error;
};
void run_chain_prepare_job(void *context) {
  auto *job = static_cast<ChainPrepareJob *>(context);
  job->error = chain_review_transaction(job->family, job->payload, job->size,
      *job->master, job->seed, job->index, job->request);
}
void run_chain_sign_job(void *context) {
  auto *job = static_cast<ChainSignJob *>(context);
  job->error = chain_sign_transaction(*job->request, *job->master, job->seed,
      job->out, job->size);
}

WalletSigningError map_algorand_error(AlgorandError error) {
  switch (error) {
    case AlgorandError::Ok: return WalletSigningError::Ok;
    case AlgorandError::Unsupported:
    case AlgorandError::WrongNetwork: return WalletSigningError::Unsupported;
    case AlgorandError::WrongWallet: return WalletSigningError::WrongWallet;
    case AlgorandError::FeePolicy: return WalletSigningError::FeePolicy;
    case AlgorandError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case AlgorandError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case AlgorandError::InvalidArgument:
    case AlgorandError::InvalidAmount: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}
WalletSigningError map_near_error(NearError error) {
  switch (error) {
    case NearError::Ok: return WalletSigningError::Ok;
    case NearError::Unsupported: return WalletSigningError::Unsupported;
    case NearError::WrongWallet: return WalletSigningError::WrongWallet;
    case NearError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case NearError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case NearError::InvalidArgument:
    case NearError::InvalidAmount: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}
WalletSigningError map_tezos_error(TezosError error) {
  switch (error) {
    case TezosError::Ok: return WalletSigningError::Ok;
    case TezosError::Unsupported: return WalletSigningError::Unsupported;
    case TezosError::FeePolicy: return WalletSigningError::FeePolicy;
    case TezosError::WrongWallet: return WalletSigningError::WrongWallet;
    case TezosError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case TezosError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case TezosError::InvalidArgument:
    case TezosError::InvalidAmount: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}
struct XrpSignJob {
  const XrpTransaction *request;
  const uint8_t *private_key;
  uint8_t *out;
  size_t *size;
  XrpError error;
};
void run_xrp_sign_job(void *context) {
  auto *job = static_cast<XrpSignJob *>(context);
  job->error = xrp_sign_transaction(*job->request, job->private_key, job->out, job->size);
}
WalletSigningError map_xrp_error(XrpError error) {
  switch (error) {
    case XrpError::Ok: return WalletSigningError::Ok;
    case XrpError::Unsupported: return WalletSigningError::Unsupported;
    case XrpError::FeePolicy: return WalletSigningError::FeePolicy;
    case XrpError::WrongWallet: return WalletSigningError::WrongWallet;
    case XrpError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case XrpError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case XrpError::InvalidArgument:
    case XrpError::InvalidAmount: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}
WalletSigningError map_chain_error(ChainError error) {
  switch (error) {
    case ChainError::Ok: return WalletSigningError::Ok;
    case ChainError::Unsupported:
    case ChainError::WrongNetwork: return WalletSigningError::Unsupported;
    case ChainError::WrongWallet: return WalletSigningError::WrongWallet;
    case ChainError::FeePolicy: return WalletSigningError::FeePolicy;
    case ChainError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case ChainError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case ChainError::InvalidArgument:
    case ChainError::InvalidAmount: return WalletSigningError::InvalidArgument;
    case ChainError::Malformed: return WalletSigningError::ParseFailed;
  }
  return WalletSigningError::ParseFailed;
}
WalletSigningError map_stellar_error(StellarError error) {
  switch (error) {
    case StellarError::Ok: return WalletSigningError::Ok;
    case StellarError::Unsupported:
    case StellarError::WrongNetwork: return WalletSigningError::Unsupported;
    case StellarError::WrongWallet: return WalletSigningError::WrongWallet;
    case StellarError::FeePolicy: return WalletSigningError::FeePolicy;
    case StellarError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case StellarError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case StellarError::InvalidArgument:
    case StellarError::InvalidAmount: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}
WalletSigningError map_solana_error(SolanaError error) {
  switch (error) {
    case SolanaError::Ok: return WalletSigningError::Ok;
    case SolanaError::Unsupported: return WalletSigningError::Unsupported;
    case SolanaError::WrongWallet: return WalletSigningError::WrongWallet;
    case SolanaError::FeePolicy: return WalletSigningError::FeePolicy;
    case SolanaError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case SolanaError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case SolanaError::InvalidArgument: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}

WalletSigningError map_cosmos_error(CosmosError error) {
  switch (error) {
    case CosmosError::Ok: return WalletSigningError::Ok;
    case CosmosError::Unsupported: return WalletSigningError::Unsupported;
    case CosmosError::WrongWallet: return WalletSigningError::WrongWallet;
    case CosmosError::FeePolicy: return WalletSigningError::FeePolicy;
    case CosmosError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case CosmosError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case CosmosError::InvalidArgument:
    case CosmosError::InvalidAmount: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}

WalletSigningError map_tron_error(TronError error) {
  switch (error) {
    case TronError::Ok: return WalletSigningError::Ok;
    case TronError::Unsupported: return WalletSigningError::Unsupported;
    case TronError::WrongWallet: return WalletSigningError::WrongWallet;
    case TronError::FeePolicy: return WalletSigningError::FeePolicy;
    case TronError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case TronError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case TronError::InvalidArgument:
    case TronError::InvalidAmount: return WalletSigningError::InvalidArgument;
    case TronError::UnknownToken: return WalletSigningError::Unsupported;
    default: return WalletSigningError::ParseFailed;
  }
}

struct CryptoNoteSignJob {
  CryptoNoteSigningState *state;
  const uint8_t *view_secret;
  const uint8_t *spend_secret;
  const uint8_t *nonce_seed;
  uint8_t *out;
  size_t *in_out_size;
  CryptoNoteTxError error;
};

void run_cryptonote_sign_job(void *context) {
  CryptoNoteSignJob *job = static_cast<CryptoNoteSignJob *>(context);
  job->error = cryptonote_signing_sign_with_keys(job->state, job->view_secret,
      job->spend_secret, job->nonce_seed, job->out, job->in_out_size);
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

WalletSigningError map_dash_error(DashError error) {
  switch (error) {
    case DashError::Ok: return WalletSigningError::Ok;
    case DashError::WrongWallet: return WalletSigningError::WrongWallet;
    case DashError::FeePolicy: return WalletSigningError::FeePolicy;
    case DashError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case DashError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    // A special transaction type is a form this firmware does not implement,
    // not a parse failure: the phone should stop offering it.
    case DashError::Unsupported: return WalletSigningError::Unsupported;
    case DashError::InvalidArgument:
    case DashError::InvalidAmount: return WalletSigningError::InvalidArgument;
    default: return WalletSigningError::ParseFailed;
  }
}

WalletSigningError map_cryptonote_error(CryptoNoteTxError error) {  switch (error) {
    case CryptoNoteTxError::Ok: return WalletSigningError::Ok;
    case CryptoNoteTxError::Unsupported: return WalletSigningError::Unsupported;
    case CryptoNoteTxError::FeePolicy: return WalletSigningError::FeePolicy;
    case CryptoNoteTxError::CryptoFailure: return WalletSigningError::CryptoFailure;
    case CryptoNoteTxError::BufferTooSmall: return WalletSigningError::BufferTooSmall;
    case CryptoNoteTxError::TooLarge:
    case CryptoNoteTxError::TooManyItems: return WalletSigningError::Unsupported;
    case CryptoNoteTxError::InvalidArgument:
    case CryptoNoteTxError::InvalidAmount: return WalletSigningError::InvalidArgument;
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
    secure_zero(&active.request, sizeof(active.request));
  }
  wallet_ui_set_decision_callback(nullptr);
  wallet_ui_show_catalog();
  wallet_ui_set_status(approved
                           ? "Approved. Tap the phone again to collect the signature."
                           : "Rejected. Nothing was signed.");
}

void show_review(const char *network_name, uint64_t fee, uint64_t fee_rate,
                 const char *fee_text, const WalletUiTransactionOutput *outputs,
                 size_t output_count, const char *total_text = nullptr,
                 const char *note = nullptr, const char *fee_label = nullptr) {
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
  review.fee_label = fee_label;
  review.total_text = total_text;
  review.note = note;
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

bool show_evm_review(const EvmSigningRequest &request) {
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
  char details[kEvmReviewTextSize];
  if (!evm_review_details(request, details, sizeof(details))) return false;
  output.details = details;
  char fee[128];
  snprintf(fee, sizeof(fee), "%s %s", request.maximum_fee_text,
           request.network == nullptr ? "?" : request.network->symbol);
  show_review(request.network == nullptr ? "EVM" : request.network->symbol,
              request.maximum_fee, 0, fee, &output, 1);
  return true;
}

bool show_tron_review(const TronTransaction &request) {
  WalletUiTransactionOutput output = {};
  char details[448];
  const TronTransferReview &review = request.review;
  const TronKind kind = review.kind;
  const bool native = kind == TronKind::Native;
  const bool token = !native;
  const bool trc10 = kind == TronKind::Trc10;
  const bool nft = kind == TronKind::Trc721 || kind == TronKind::Trc1155;
  // fee_limit only exists for the contract-call shapes reviewed here.
  const bool charges_fee_limit = kind == TronKind::Trc20 || nft;
  char memo[kTronMemoTextSize + 8] = {};
  if (review.has_memo) {
    const int memo_written =
        snprintf(memo, sizeof(memo), "\nMEMO\n%s", review.memo_text);
    if (memo_written < 0 || static_cast<size_t>(memo_written) >= sizeof(memo)) {
      return false;
    }
  }
  char precision[24] = {};
  if (trc10) {
    const int precision_written =
        review.asset_registered
            ? snprintf(precision, sizeof(precision), "%u",
                       static_cast<unsigned>(review.token_decimals))
            : snprintf(precision, sizeof(precision), "issuer-defined");
    if (precision_written < 0 ||
        static_cast<size_t>(precision_written) >= sizeof(precision)) {
      return false;
    }
  }
  const char *method = review.method_text[0] == '\0' ? "-" : review.method_text;
  int written = 0;
  if (nft) {
    written = snprintf(
        details, sizeof(details),
        "CONTRACT\n%s\nMETHOD\n%s\nSTANDARD\n%s\nTOKEN ID\n%s\n"
        "UNREGISTERED: verify the contract address with the issuer\n"
        "FEE LIMIT\n%llu.%06llu TRX\nEXPIRES (ms)\n%lld\nTXID\n%02x%02x%02x%02x%02x%02x%02x%02x%s",
        review.token_contract_text, method, review.token_symbol,
        review.token_id_text,
        static_cast<unsigned long long>(review.fee_limit_sun / kTronSunPerTrx),
        static_cast<unsigned long long>(review.fee_limit_sun % kTronSunPerTrx),
        static_cast<long long>(review.expiration_ms),
        review.tx_id[0], review.tx_id[1], review.tx_id[2], review.tx_id[3],
        review.tx_id[4], review.tx_id[5], review.tx_id[6], review.tx_id[7], memo);
  } else if (trc10) {
    // The identifier is printed byte for byte: the node resolves the transfer
    // by these bytes, not by a symbol.
    written = snprintf(
        details, sizeof(details),
        "TRC-10 ASSET ID\n%s\nPRECISION\n%s\nEXPIRES (ms)\n%lld\nTXID\n%02x%02x%02x%02x%02x%02x%02x%02x%s%s",
        review.asset_id_text, precision,
        static_cast<long long>(review.expiration_ms),
        review.tx_id[0], review.tx_id[1], review.tx_id[2], review.tx_id[3],
        review.tx_id[4], review.tx_id[5], review.tx_id[6], review.tx_id[7],
        review.asset_registered ? "" : "\nASSET NOT REGISTERED", memo);
  } else if (token) {
    written = snprintf(
        details, sizeof(details),
        "CONTRACT\n%s\nMETHOD\n%s\nFEE LIMIT\n%llu.%06llu TRX\nEXPIRES (ms)\n%lld\nTXID\n%02x%02x%02x%02x%02x%02x%02x%02x%s",
        review.token_contract_text, method,
        static_cast<unsigned long long>(review.fee_limit_sun / kTronSunPerTrx),
        static_cast<unsigned long long>(review.fee_limit_sun % kTronSunPerTrx),
        static_cast<long long>(review.expiration_ms),
        review.tx_id[0], review.tx_id[1], review.tx_id[2], review.tx_id[3],
        review.tx_id[4], review.tx_id[5], review.tx_id[6], review.tx_id[7], memo);
  } else {
    written = snprintf(
        details, sizeof(details),
        "EXPIRES (ms)\n%lld\nTXID\n%02x%02x%02x%02x%02x%02x%02x%02x%s",
        static_cast<long long>(review.expiration_ms),
        review.tx_id[0], review.tx_id[1], review.tx_id[2], review.tx_id[3],
        review.tx_id[4], review.tx_id[5], review.tx_id[6], review.tx_id[7], memo);
  }
  if (written < 0 || static_cast<size_t>(written) >= sizeof(details)) return false;
  const char *ownership =
      native ? "NATIVE"
      : trc10 ? (review.asset_registered ? review.token_symbol : "UNREGISTERED")
               : review.token_symbol;
  output = { 0, review.amount_text, review.recipient_text, ownership, details };
  char fee[64] = {};
  if (charges_fee_limit) {
    snprintf(fee, sizeof(fee), "%llu.%06llu TRX",
             static_cast<unsigned long long>(review.fee_limit_sun / kTronSunPerTrx),
             static_cast<unsigned long long>(review.fee_limit_sun % kTronSunPerTrx));
  }
  const char *note =
      nft ? "Offline NFT review. Only the canonical safeTransferFrom with an empty data tail is accepted. The contract is not registered: verify its address independently; metadata and ownership are not verified."
      : trc10 ? (review.asset_registered
                     ? "Offline review. The TRC-10 id and precision are pinned to the on-chain issuance record in firmware; recipient and amount are re-derived from the signed bytes."
                     : "Unregistered TRC-10 asset. The issuer chose this identifier and defines its precision, so the amount is the exact base-unit count the chain will move. Verify the asset id before approving.")
              : "Offline review. Expiration, ref block and energy/bandwidth state are checked by the phone. Token identity and decimals come from the registered contract.";
  show_review("TRON", charges_fee_limit ? review.fee_limit_sun : 0, 0,
              charges_fee_limit ? fee : nullptr, &output, 1, nullptr, note,
              charges_fee_limit ? "FEE LIMIT" : nullptr);
  return true;
}

bool show_cosmos_review(const CosmosTransaction &request) {
  const CosmosReview &review = request.review;
  WalletUiTransactionOutput output = {};
  char details[384];
  char memo[kCosmosMaxMemo + 16] = {};
  if (review.has_memo) {
    const int memo_written = snprintf(memo, sizeof(memo), "\nMEMO\n%s", review.memo);
    if (memo_written < 0 || static_cast<size_t>(memo_written) >= sizeof(memo)) {
      return false;
    }
  }
  int written = 0;
  if (review.denom_registered) {
    written = snprintf(
        details, sizeof(details),
        "CHAIN ID\n%s\nACCOUNT / SEQUENCE\n%llu / %llu\nGAS\n%llu%s",
        review.chain_id, static_cast<unsigned long long>(review.account_number),
        static_cast<unsigned long long>(review.sequence),
        static_cast<unsigned long long>(review.gas_limit), memo);
  } else {
    // A denom with no pinned precision is displayed verbatim next to an exact
    // base-unit amount; inventing decimals there would misstate the transfer.
    written = snprintf(
        details, sizeof(details),
        "CHAIN ID\n%s\nACCOUNT / SEQUENCE\n%llu / %llu\nGAS\n%llu\nDENOM\n%s\n"
        "NO PINNED PRECISION: amount above is the exact base-unit count%s",
        review.chain_id, static_cast<unsigned long long>(review.account_number),
        static_cast<unsigned long long>(review.sequence),
        static_cast<unsigned long long>(review.gas_limit), review.denom, memo);
  }
  if (written < 0 || static_cast<size_t>(written) >= sizeof(details)) return false;
  if (review.message_count == 0 || review.message_count > kCosmosMaxMessages) {
    return false;
  }
  // One display row per MsgSend: every recipient and its own amount. The
  // chain/account/memo detail block hangs off the first row.
  WalletUiTransactionOutput outputs[kCosmosMaxMessages] = {};
  static_assert(kCosmosMaxMessages <= kWalletUiMaxTransactionOutputs,
                "Every Cosmos message must fit the trusted review");
  for (uint8_t index = 0; index < review.message_count; ++index) {
    outputs[index] = { review.amounts[index], review.amount_texts[index],
                       review.to[index],
                       review.denom_registered ? review.symbol : "DENOM",
                       index == 0 ? details : nullptr };
  }
  output = outputs[0];
  char total[192];
  const int total_written = snprintf(total, sizeof(total), "%s + %s",
                                     review.amount_text, review.fee_text);
  if (total_written < 0 || static_cast<size_t>(total_written) >= sizeof(total)) {
    return false;
  }
  show_review(review.chain == nullptr ? "COSMOS" : review.chain->symbol,
              review.fee, 0, review.fee_text, outputs, review.message_count,
              total,
              review.denom_registered
                  ? "Offline review. Chain id, account number and sequence are supplied by the phone and shown here; verify them before approving. Every MsgSend is listed with its own recipient and amount; the memo is committed in TxBody. IBC and authz messages are refused."
                  : "Offline review of a denom without pinned metadata: each amount is the exact base-unit integer the chain will move. Verify the denom string before approving. IBC and authz messages are refused.",
              "FEE");
  return true;
}

bool show_stellar_review(const StellarTransaction &request) {
  static_assert(kStellarMaxOperations <= kWalletUiMaxTransactionOutputs, "XLM review must show all operations");
  const StellarReview &v = request.review;
  WalletUiTransactionOutput outputs[kStellarMaxOperations] = {};
  char details[kStellarMaxOperations][96] = {};
  for (size_t i = 0; i < v.operation_count; ++i) {
    const StellarOperation &op = v.operations[i];
    const int n = snprintf(details[i], sizeof(details[i]), "%s%s",
        op.issuer[0] ? "ISSUED ASSET / ISSUER\n" : "NATIVE XLM", op.issuer);
    if (n < 0 || static_cast<size_t>(n) >= sizeof(details[i])) return false;
    outputs[i] = {op.amount, op.amount_text, op.destination,
                  op.type == 0 ? "CREATE ACCOUNT" : "PAYMENT", details[i]};
  }
  constexpr const char *memo_names[] = {"NONE", "TEXT", "ID", "HASH", "RETURN HASH"};
  if (v.memo_type > 4) return false;
  char note[640], fee[48];
  const int n = snprintf(note, sizeof(note),
      "STELLAR PUBLIC NETWORK\nFROM\n%s\nPATH\nm/44'/148'/%lu'\nSEQUENCE\n%llu\n"
      "VALIDITY (UNIX SECONDS)\n%llu - %llu\nMEMO %s\n%s\n"
      "Offline: balances, reserves, trustlines and recipient memo requirements are not verified. "
      "Issued asset identity is its code AND issuer; a familiar code does not authenticate an issuer.",
      v.source, static_cast<unsigned long>(request.address_index),
      static_cast<unsigned long long>(v.sequence), static_cast<unsigned long long>(v.min_time),
      static_cast<unsigned long long>(v.max_time), memo_names[v.memo_type], v.memo);
  if (n < 0 || static_cast<size_t>(n) >= sizeof(note)) return false;
  snprintf(fee, sizeof(fee), "%lu.%07lu XLM", static_cast<unsigned long>(v.fee / kStellarStroops),
           static_cast<unsigned long>(v.fee % kStellarStroops));
  show_review("STELLAR", v.fee, 0, fee, outputs, v.operation_count,
              "Amounts and asset identities shown per operation", note, "MAXIMUM FEE");
  return true;
}

bool show_algorand_review(const AlgorandTransaction &request) {
  const AlgorandReview &v = request.review;
  struct Scratch {
    WalletUiTransactionOutput output;
    char details[160];
    char fee[56];
    char note[2 * kAlgorandMaxNote + 480];
  };
  static Scratch scratch;
  secure_zero(&scratch, sizeof(scratch));
  struct ClearScratch { Scratch &value; ~ClearScratch() { secure_zero(&value, sizeof(value)); } } clear{scratch};
  const char *kind = v.kind == AlgorandKind::Payment ? "NATIVE ALGO PAYMENT"
      : v.kind == AlgorandKind::AssetOptIn ? "ASA OPT-IN (ZERO AMOUNT)" : "ASA TRANSFER";
  if (v.kind == AlgorandKind::Payment) {
    const int n = snprintf(scratch.details, sizeof(scratch.details), "%s", kind);
    if (n < 0 || static_cast<size_t>(n) >= sizeof(scratch.details)) return false;
  } else {
    const int n = snprintf(scratch.details, sizeof(scratch.details),
        "%s\nASA ID\n%llu", kind, static_cast<unsigned long long>(v.asset_id));
    if (n < 0 || static_cast<size_t>(n) >= sizeof(scratch.details)) return false;
  }
  const int fee_written = snprintf(scratch.fee, sizeof(scratch.fee), "%llu.%06llu ALGO",
      static_cast<unsigned long long>(v.fee / 1000000ULL),
      static_cast<unsigned long long>(v.fee % 1000000ULL));
  if (fee_written < 0 || static_cast<size_t>(fee_written) >= sizeof(scratch.fee)) return false;
  const int note_written = snprintf(scratch.note, sizeof(scratch.note),
      "ALGORAND MAINNET\nFROM\n%s\nPATH\nm/44'/283'/0'/0'/%lu'\n"
      "VALID ROUNDS\n%llu - %llu\nLEASE\n%s\nNOTE (HEX)\n%s\n"
      "Offline review: ASA identity, opt-in state and balances are not verified; "
      "verify the ASA id and the note independently. Current round is checked by the network.",
      v.sender, static_cast<unsigned long>(request.address_index),
      static_cast<unsigned long long>(v.first_valid),
      static_cast<unsigned long long>(v.last_valid),
      v.lease_hex[0] ? v.lease_hex : "NONE", v.note_hex[0] ? v.note_hex : "NONE");
  if (note_written < 0 || static_cast<size_t>(note_written) >= sizeof(scratch.note)) return false;
  scratch.output = {v.amount, v.amount_text, v.recipient, "EXTERNAL", scratch.details};
  show_review("ALGORAND", v.fee, 0, scratch.fee, &scratch.output, 1,
              v.amount_text, scratch.note, "FEE");
  return true;
}

bool show_near_review(const NearTransaction &request) {
  static_assert(kNearMaxActions <= kWalletUiMaxTransactionOutputs,
                "Every NEAR transfer must be displayed");
  const NearReview &v = request.review;
  if (v.action_count == 0 || v.action_count > kNearMaxActions) return false;
  struct Scratch {
    WalletUiTransactionOutput outputs[kNearMaxActions];
    char amounts[kNearMaxActions][72];
    char details[kNearMaxActions][48];
    char note[640];
  };
  static Scratch scratch;
  secure_zero(&scratch, sizeof(scratch));
  struct ClearScratch { Scratch &value; ~ClearScratch() { secure_zero(&value, sizeof(value)); } } clear{scratch};
  for (size_t i = 0; i < v.action_count; ++i) {
    if (!near_format_amount(v.amounts[i], scratch.amounts[i], sizeof(scratch.amounts[i]))) {
      return false;
    }
    const int n = snprintf(scratch.details[i], sizeof(scratch.details[i]),
        "TRANSFER %u/%u", static_cast<unsigned>(i + 1),
        static_cast<unsigned>(v.action_count));
    if (n < 0 || static_cast<size_t>(n) >= sizeof(scratch.details[i])) return false;
    scratch.outputs[i] = {0, scratch.amounts[i], v.receiver, "EXTERNAL", scratch.details[i]};
  }
  const int note_written = snprintf(scratch.note, sizeof(scratch.note),
      "NEAR PROTOCOL\nSIGNER\n%s\nPUBLIC KEY\n%s\nBLOCK HASH\n%s\nNONCE\n%llu\n"
      "PATH\nm/44'/397'/%lu'\nOffline review: block-hash freshness, named-account ownership "
      "and access keys are not verified. Gas is charged to the signer and is not part of "
      "this transaction; verify the block hash with the sender.",
      v.signer, v.public_key, v.block_hash,
      static_cast<unsigned long long>(v.nonce),
      static_cast<unsigned long>(request.address_index));
  if (note_written < 0 || static_cast<size_t>(note_written) >= sizeof(scratch.note)) return false;
  show_review("NEAR", 0, 0, "NOT IN TRANSACTION", scratch.outputs, v.action_count,
              v.total_text, scratch.note, "NETWORK FEE");
  return true;
}

bool show_tezos_review(const TezosTransaction &request) {
  static_assert(kTezosMaxOperations <= kWalletUiMaxTransactionOutputs, "Every XTZ operation must be shown");
  const auto &v = request.review;
  if (!v.operation_count || v.operation_count > kTezosMaxOperations) return false;
  struct Scratch {
    WalletUiTransactionOutput outputs[kTezosMaxOperations];
    char amounts[kTezosMaxOperations][40], details[kTezosMaxOperations][200];
    char fee[40], total[40], note[600];
  };
  static Scratch scratch;
  memset(&scratch, 0, sizeof(scratch));
  struct ClearScratch { ~ClearScratch() { secure_zero(&scratch, sizeof(scratch)); } } clear;
  for (size_t i = 0; i < v.operation_count; ++i) {
    const auto &op = v.operations[i];
    if (!tezos_format_amount(op.amount, scratch.amounts[i], sizeof(scratch.amounts[i]))) return false;
    const int n = snprintf(scratch.details[i], sizeof(scratch.details[i]),
        "%s\nCOUNTER %llu\nFEE %llu mutez\nGAS LIMIT %llu\nSTORAGE LIMIT %llu bytes",
        op.reveal ? "REVEAL PUBLIC KEY" : "NATIVE TRANSFER",
        static_cast<unsigned long long>(op.counter), static_cast<unsigned long long>(op.fee),
        static_cast<unsigned long long>(op.gas_limit), static_cast<unsigned long long>(op.storage_limit));
    if (n < 0 || static_cast<size_t>(n) >= sizeof(scratch.details[i])) return false;
    scratch.outputs[i] = {op.amount, scratch.amounts[i], op.recipient,
                          op.reveal ? "OWN ACCOUNT" : "EXTERNAL", scratch.details[i]};
  }
  if (!tezos_format_amount(v.total_fee, scratch.fee, sizeof(scratch.fee)) ||
      !tezos_format_amount(v.total, scratch.total, sizeof(scratch.total))) return false;
  const int n = snprintf(scratch.note, sizeof(scratch.note),
      "FROM\n%s\nPUBLIC KEY\n%s\nBRANCH\n%s\nPATH\nm/44'/1729'/0'/0'/%lu'\n"
      "Branch network/freshness and account state are not authenticated offline. "
      "Storage allocation may burn additional XTZ up to the reviewed storage limits; "
      "the operation fee does not include this burn.",
      v.source, v.public_key, v.branch, static_cast<unsigned long>(request.address_index));
  if (n < 0 || static_cast<size_t>(n) >= sizeof(scratch.note)) return false;
  show_review("TEZOS", v.total_fee, 0, scratch.fee, scratch.outputs, v.operation_count,
              scratch.total, scratch.note, "OPERATION FEES");
  return true;
}

bool show_xrp_review(const XrpTransaction &request) {
  const XrpReview &v = request.review;
  WalletUiTransactionOutput output = {};
  char details[320];
  int written = snprintf(details, sizeof(details),
      "FROM\n%s\nSEQUENCE\n%lu\nLAST LEDGER\n%lu\nHASH\n%s\nPATH\nm/44'/144'/0'/0/%lu",
      v.source_text, static_cast<unsigned long>(v.sequence),
      static_cast<unsigned long>(v.last_ledger_sequence), v.hash_text,
      static_cast<unsigned long>(request.address_index));
  if (written < 0 || static_cast<size_t>(written) >= sizeof(details)) return false;
  if (v.has_destination_tag) {
    char tag[80];
    const int n = snprintf(tag, sizeof(tag), "\nDESTINATION TAG\n%lu",
                           static_cast<unsigned long>(v.destination_tag));
    if (n < 0 || static_cast<size_t>(n) >= sizeof(tag)) return false;
    const size_t used = strlen(details);
    if (used + static_cast<size_t>(n) + 1 >= sizeof(details)) return false;
    memcpy(details + used, tag, static_cast<size_t>(n) + 1);
  }
  output = {v.amount_drops, v.amount_text, v.destination_text, "EXTERNAL", details};
  show_review("XRP", v.fee_drops, 0, v.fee_text, &output, 1, v.amount_text,
              "Offline review. Sequence and last ledger are supplied by the phone; "
              "the ledger must be current at submission. A destination tag is required "
              "by some exchanges: verify it independently. No memo, invoice id, paths, "
              "partial payment or issued currency is supported.",
              "FEE");
  return true;
}

bool show_chain_review(const ChainTransaction &request) {
  char note[512] = {};
  snprintf(note, sizeof(note),
           "FROM %s\nADDRESS INDEX %lu\nOffline review. Verify the destination, "
           "amount and fees. Node state and network selection must be checked "
           "before broadcast. Some protocols do not bind a chain ID in their "
           "signed bytes; see the transaction details.",
           request.review.sender, static_cast<unsigned long>(request.address_index));
  WalletUiTransactionOutput output = {};
  output = {0, request.review.amount, request.review.recipient, "NATIVE",
            request.review.extra};
  show_review(request.review.symbol, 0, 0, request.review.fee, &output, 1,
              nullptr,
              note,
              "FEE");
  return true;
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

bool show_zcash_review(const ZcashSigningRequest &request) {
  WalletUiTransactionOutput outputs[kWalletUiMaxTransactionOutputs] = {};
  char amounts[kWalletUiMaxTransactionOutputs][32] = {};
  char input_addresses[kZcashMaxInputs][kAddressTextSize] = {};
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
  // t3 spends must name the P2SH address whose redeem script is being spent.
  // Silently hiding one would let a review show only destinations.
  size_t shown = count;
  bool has_p2sh_input = false;
  for (size_t index = 0; index < request.input_count; ++index) {
    const ZcashInput &input = request.inputs[index];
    if (input.redeem_size == 0) continue;
    if (shown >= kWalletUiMaxTransactionOutputs) return false;
    if (address_zcash_transparent_from_script(
            request.chain.p2pkh_version, request.chain.p2sh_version, input.script,
            input.script_size, input_addresses[index],
            sizeof(input_addresses[index])) != WalletError::Ok) {
      return false;
    }
    has_p2sh_input = true;
    outputs[shown++] = { input.value, nullptr, input_addresses[index],
                         "P2SH INPUT" };
  }
  char fee[64];
  snprintf(fee, sizeof(fee), "%llu.%08lu ZEC",
           static_cast<unsigned long long>(request.fee / kZcashZatsPerZec),
           static_cast<unsigned long>(request.fee % kZcashZatsPerZec));
  show_review("ZCASH", request.fee, 0, fee, outputs, shown, nullptr,
              has_p2sh_input
                  ? "P2SH inputs list the t3 address whose redeem script is spent. The firmware re-hashes that script against the address before signing."
                  : nullptr);
  return true;
}

// Dash review. Every row comes from bytes the device will actually sign: the
// destination scripts are decoded back into addresses, and the input rows show
// the prevout scripts whose key hashes the signer re-derives and compares.
bool show_dash_review(const DashTransaction &request) {
  static_assert(kDashMaxInputs + kDashMaxOutputs <= kWalletUiMaxTransactionOutputs,
                "Every Dash row must fit the trusted review");
  WalletUiTransactionOutput outputs[kWalletUiMaxTransactionOutputs] = {};
  char amounts[kWalletUiMaxTransactionOutputs][40] = {};
  char input_details[kDashMaxInputs][128] = {};
  if (request.output_count == 0 || request.output_count > kDashMaxOutputs ||
      request.input_count == 0 || request.input_count > kDashMaxInputs) return false;
  size_t shown = 0;
  for (size_t index = 0; index < request.output_count; ++index) {
    const DashOutput &output = request.outputs[index];
    snprintf(amounts[shown], sizeof(amounts[shown]), "%llu.%08lu DASH",
             static_cast<unsigned long long>(output.value / kDashDuffsPerDash),
             static_cast<unsigned long>(output.value % kDashDuffsPerDash));
    outputs[shown] = { output.value, amounts[shown], output.address, "TO" };
    ++shown;
  }
  for (size_t index = 0; index < request.input_count; ++index) {
    const DashInput &input = request.inputs[index];
    snprintf(amounts[shown], sizeof(amounts[shown]), "%llu.%08lu DASH",
             static_cast<unsigned long long>(input.value / kDashDuffsPerDash),
             static_cast<unsigned long>(input.value % kDashDuffsPerDash));
    snprintf(input_details[index], sizeof(input_details[index]),
             "m/44'/5'/%lu'/%u/%lu\nSequence: %lu",
             static_cast<unsigned long>(input.account), static_cast<unsigned>(input.change),
             static_cast<unsigned long>(input.address_index),
             static_cast<unsigned long>(input.sequence));
    outputs[shown] = { input.value, amounts[shown], input.address, "VERIFIED INPUT",
                       input_details[index] };
    ++shown;
  }
  char fee[64];
  snprintf(fee, sizeof(fee), "%llu.%08lu DASH",
           static_cast<unsigned long long>(request.fee / kDashDuffsPerDash),
           static_cast<unsigned long>(request.fee % kDashDuffsPerDash));
  char note[256];
  snprintf(note, sizeof(note),
           "Version %lu / type 0. Lock time: %lu. Input amounts verified against funding transactions. Confirmations, unspent status and InstantSend locks require a node.",
           static_cast<unsigned long>(request.version),
           static_cast<unsigned long>(request.lock_time));
  show_review("DASH", request.fee, 0, fee, outputs, shown, nullptr, note, "FEE");
  return true;
}

bool show_cryptonote_review(const CryptoNoteSigningState &request) {  static_assert(kCryptoNoteMaxSignOutputs <= kWalletUiMaxTransactionOutputs,
                "Every signed output must fit the trusted review");
  const char *network_id =
      request.network == CryptoNoteReviewNetwork::MasariMainnet ? "msr" : "xmr";
  const NetworkProfile *profile = find_network_profile(network_id);
  if (profile == nullptr || request.output_count == 0 ||
      request.output_count > kWalletUiMaxTransactionOutputs) return false;
  const char *symbol = profile->symbol;
  WalletUiTransactionOutput outputs[kWalletUiMaxTransactionOutputs] = {};
  char amounts[kWalletUiMaxTransactionOutputs][32] = {};
  char addresses[kWalletUiMaxTransactionOutputs][kCryptoNoteMaxAddressSize] = {};
  const size_t count = request.output_count > kWalletUiMaxTransactionOutputs
                           ? kWalletUiMaxTransactionOutputs
                           : request.output_count;
  uint64_t external_total = 0;
  for (size_t index = 0; index < count; ++index) {
    const CryptoNoteSigningOutput &output = request.outputs[index];
    snprintf(amounts[index], sizeof(amounts[index]), "%llu.%012llu %s",
             static_cast<unsigned long long>(output.amount / 1000000000000ULL),
             static_cast<unsigned long long>(output.amount % 1000000000000ULL),
             symbol);
    uint64_t prefix = 0;
    if (profile != nullptr) {
      prefix = output.address_type == 1 && profile->cryptonote_subaddress_prefix != 0
                   ? profile->cryptonote_subaddress_prefix
                   : profile->account_version;
    }
    if (prefix == 0 ||
        cryptonote_address_from_public_keys(prefix, output.spend_public,
                                            output.view_public, addresses[index],
                                            sizeof(addresses[index])) != WalletError::Ok) {
      return false;
    }
    outputs[index] = { output.amount, amounts[index], addresses[index],
                       output.change ? "CHANGE" : "EXTERNAL" };
    if (!output.change) external_total += output.amount;
  }
  char fee[64];
  snprintf(fee, sizeof(fee), "%llu.%012llu %s",
           static_cast<unsigned long long>(request.summary.fee / 1000000000000ULL),
           static_cast<unsigned long long>(request.summary.fee % 1000000000000ULL),
           symbol);
  char total[64];
  const uint64_t spent = external_total + request.summary.fee;
  snprintf(total, sizeof(total), "%llu.%012llu %s",
           static_cast<unsigned long long>(spent / 1000000000000ULL),
           static_cast<unsigned long long>(spent % 1000000000000ULL), symbol);
  char note[128];
  snprintf(note, sizeof(note),
           "Ring %u decoys supplied by phone; chain membership cannot be "
           "verified offline.",
           static_cast<unsigned>(request.ring_size));
  show_review(symbol, request.summary.fee, 0, fee, outputs, count, total, note);
  return true;
}

bool show_solana_review(const SolanaTransaction &request) {
  static_assert(kSolanaMaxTransfers <= kWalletUiMaxTransactionOutputs,
                "Every SOL transfer must be displayed");
  if (request.transfer_count == 0 || request.transfer_count > kSolanaMaxTransfers) return false;
  // Main-loop-only scratch: LVGL copies the strings synchronously. Keeping the
  // bounded public review data out of the 8 KiB loop stack leaves headroom for
  // LVGL rendering. Clear it on every return, including formatting failures.
  struct Scratch {
    WalletUiTransactionOutput outputs[kSolanaMaxTransfers];
    char addresses[kSolanaMaxTransfers][45];
    char amounts[kSolanaMaxTransfers][64];
    char details[kSolanaMaxTransfers][176];
  };
  static Scratch scratch;
  secure_zero(&scratch, sizeof(scratch));
  struct ClearScratch { Scratch &value; ~ClearScratch() { secure_zero(&value, sizeof(value)); } } clear{scratch};
  auto &outputs = scratch.outputs;
  auto &addresses = scratch.addresses;
  auto &amounts = scratch.amounts;
  auto &details = scratch.details;
  bool has_tokens = false;
  bool has_token_2022 = false;
  const auto amount_text = [](uint64_t value, char *out, size_t size) {
    snprintf(out, size, "%llu.%09llu SOL",
        static_cast<unsigned long long>(value / 1000000000ULL),
        static_cast<unsigned long long>(value % 1000000000ULL));
  };
  for (size_t i = 0; i < request.transfer_count; ++i) {
    size_t capacity = sizeof(addresses[i]);
    if (address_solana(request.transfers[i].recipient, addresses[i], &capacity) != WalletError::Ok)
      return false;
    const SolanaTransfer &transfer = request.transfers[i];
    if (!solana_format_amount(transfer, amounts[i], sizeof(amounts[i]))) return false;
    outputs[i] = {transfer.amount, amounts[i], addresses[i], "EXTERNAL", nullptr};
    if (transfer.kind != SolanaTransferKind::Native) {
      has_tokens = true;
      const bool token_2022 = transfer.kind == SolanaTransferKind::SplToken2022;
      has_token_2022 = has_token_2022 || token_2022;
      char mint[45], source[45];
      size_t mint_size = sizeof(mint), source_size = sizeof(source);
      if (address_solana(transfer.mint, mint, &mint_size) != WalletError::Ok ||
          address_solana(transfer.source, source, &source_size) != WalletError::Ok) return false;
      const int length = snprintf(details[i], sizeof(details[i]),
          "%s MINT\n%s\nFROM TOKEN ACCOUNT\n%s\nRAW UNITS: %llu\nDECIMALS: %u",
          token_2022 ? "TOKEN-2022" : "SPL TOKEN", mint, source,
          static_cast<unsigned long long>(transfer.amount), unsigned(transfer.decimals));
      if (length < 0 || static_cast<size_t>(length) >= sizeof(details[i])) return false;
      outputs[i].ownership = token_2022 ? "TO TOKEN-2022 ACCOUNT (not wallet address)"
                                        : "TO TOKEN ACCOUNT (not wallet address)";
      outputs[i].details = details[i];
    }
  }
  char fee[32], total[80], sol_total[32];
  amount_text(request.estimated_fee, fee, sizeof(fee));
  amount_text(request.total_lamports + request.estimated_fee, sol_total, sizeof(sol_total));
  snprintf(total, sizeof(total), "%s%s", sol_total, has_tokens ? " (SOL only; tokens listed above)" : "");
  show_review("SOLANA", request.estimated_fee, 0, fee, outputs, request.transfer_count,
      total, has_token_2022
          ? "TOKEN-2022 mint extensions (transfer fee, hook) cannot be verified offline: the recipient may receive less than shown. Verify the mint with the issuer. Instructions requiring extra hook accounts are rejected. Token names/owners are not authenticated; decimals are checked on-chain."
          : has_tokens
          ? "Verify the full mint and destination TOKEN ACCOUNT. Token names and account owners are not authenticated offline. Decimals are checked on-chain. SOL fee is estimated; phone checks blockhash and cluster."
          : "Offline fee estimate. Blockhash freshness and cluster require phone-side verification.", "EST. FEE");
  return true;
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
  random_fill(active.review_id, sizeof(active.review_id));
  bool nonzero = false;
  for (size_t index = 0; index < sizeof(active.review_id); ++index) {
    if (active.review_id[index] != 0) nonzero = true;
  }
  if (!nonzero) active.review_id[0] = 1;
  switch (active.kind) {
    case WalletSigningKind::Bitcoin: show_bitcoin_review(active.request.bitcoin); break;
      case WalletSigningKind::Evm:
        if (!show_evm_review(active.request.evm)) {
          wallet_signing_clear();
          wallet_ui_set_status("Cannot display the complete access list. Review rejected.");
          return WalletSigningError::InvalidArgument;
        }
        break;
    case WalletSigningKind::Kaspa: show_kaspa_review(active.request.kaspa); break;
    case WalletSigningKind::Zcash:
      if (!show_zcash_review(active.request.zcash)) {
        wallet_signing_clear();
        wallet_ui_set_status("Cannot display the complete transaction. Review rejected.");
        return WalletSigningError::InvalidArgument;
      }
      break;
    case WalletSigningKind::Dash:
      if (!show_dash_review(active.request.dash)) {
        wallet_signing_clear();
        wallet_ui_set_status("Cannot display the complete transaction. Review rejected.");
        return WalletSigningError::InvalidArgument;
      }
      break;
    case WalletSigningKind::CryptoNote:
      if (!show_cryptonote_review(active.request.cryptonote)) {
        wallet_signing_clear();
        wallet_ui_set_status("Cannot display the complete transaction. Review rejected.");
        return WalletSigningError::InvalidArgument;
      }
      break;
    case WalletSigningKind::Solana:
      if (!show_solana_review(active.request.solana)) {
        wallet_signing_clear();
        return WalletSigningError::InvalidArgument;
      }
      break;
    case WalletSigningKind::Tron:
      if (!show_tron_review(active.request.tron)) {
        wallet_signing_clear();
        return WalletSigningError::InvalidArgument;
      }
      break;
    case WalletSigningKind::Cosmos:
      if (!show_cosmos_review(active.request.cosmos)) {
        wallet_signing_clear();
        return WalletSigningError::InvalidArgument;
      }
      break;
    case WalletSigningKind::Stellar:
      if (!show_stellar_review(active.request.stellar)) {
        wallet_signing_clear();
        return WalletSigningError::InvalidArgument;
      }
      break;
    case WalletSigningKind::Algorand:
      if (!show_algorand_review(active.request.algorand)) {
        wallet_signing_clear();
        return WalletSigningError::InvalidArgument;
      }
      break;
    case WalletSigningKind::Near:
      if (!show_near_review(active.request.near)) {
        wallet_signing_clear();
        return WalletSigningError::InvalidArgument;
      }
      break;
    case WalletSigningKind::Tezos:
      if (!show_tezos_review(active.request.tezos)) {
        wallet_signing_clear();
        return WalletSigningError::InvalidArgument;
      }
      break;
    case WalletSigningKind::Xrp:
      if (!show_xrp_review(active.request.xrp)) {
        wallet_signing_clear();
        return WalletSigningError::InvalidArgument;
      }
      break;
    case WalletSigningKind::Chain:
      if (!show_chain_review(active.request.chain)) {
        wallet_signing_clear();
        return WalletSigningError::InvalidArgument;
      }
      break;
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
  wallet_signing_clear();
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
  wallet_signing_clear();
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
  wallet_signing_clear();
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

WalletSigningError wallet_signing_begin_zcash(const char *network_id,
                                              const uint8_t *payload,
                                              size_t payload_size,
                                              uint32_t now_ms) {
  wallet_signing_clear();
  if (payload == nullptr || payload_size == 0) {
    return WalletSigningError::InvalidArgument;
  }
  if (network_id == nullptr || network_id[0] == '\0') network_id = "zec";
  const NetworkProfile *network = find_network_profile(network_id);
  const NetworkSigningPolicy *policy =
      find_network_signing_policy(network_id);
  const ZcashNetworkPolicy *zcash_policy =
      find_zcash_network_policy(network_id);
  if (network == nullptr || policy == nullptr ||
      policy->family != SighashFamily::ZcashZip243 || zcash_policy == nullptr ||
      !catalog_can_sign(network_id)) {
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

WalletSigningError wallet_signing_begin_dash(const char *network_id,
                                             const uint8_t *payload,
                                             size_t payload_size,
                                             uint32_t now_ms) {
  wallet_signing_clear();
  if (payload == nullptr || payload_size < 4 ||
      payload_size > HEXWALLET_MAX_PSBT_BYTES) {
    return WalletSigningError::InvalidArgument;
  }
  // The old DASH payload trusts host-supplied input amounts. Never approve it.
  if (memcmp(payload, "DAS2", 4) != 0) return WalletSigningError::Unsupported;
  if (network_id == nullptr || network_id[0] == '\0') network_id = "dash";
  const NetworkProfile *network = find_network_profile(network_id);
  // Dash is only offered through this payload shape: a PSBT would carry
  // witness fields Dash has no meaning for, and the Bitcoin adapter would then
  // be reviewing a transaction it cannot describe.
  if (network == nullptr || strcmp(network->id, "dash") != 0 ||
      network->encoding != AddressEncoding::P2pkh ||
      network->derivation_coin_type != kDashCoinType ||
      !catalog_can_sign(network_id)) {
    return WalletSigningError::Unsupported;
  }
  const DashChainParams chain = {network->id, network->utxo.p2pkh_version,
                                 network->utxo.p2sh_version};
  SensitiveValue<HdPrivateNode> master;
  if (!load_master(&master.get())) return WalletSigningError::NoWallet;
  wallet_ui_show_busy("Verifying DASH inputs...");
  DashPrepareJob job{payload, payload_size, chain, &master.get(),
                     &active.request.dash, DashError::CryptoFailure};
  const WalletWorkerResult result = wallet_worker_execute(run_dash_prepare_job, &job,
      HEXWALLET_WORKER_JOB_TIMEOUT_MS, millis, service_crypto_wait);
  const DashError error = job.error;
  secure_zero(&job, sizeof(job));
  if (result != WalletWorkerResult::Completed || error != DashError::Ok) {
    wallet_signing_clear();
    if (result == WalletWorkerResult::TimedOut) return WalletSigningError::Expired;
    if (result != WalletWorkerResult::Completed) return WalletSigningError::Unsupported;
    return map_dash_error(error);
  }
  active.kind = WalletSigningKind::Dash;
  (void)now_ms;
  return finish_review(millis());
}

WalletSigningError wallet_signing_begin_cryptonote(const char *network_id,
                                                   uint32_t address_index,
                                                   const uint8_t *payload,
                                                   size_t payload_size,
                                                   uint32_t now_ms) {
  wallet_signing_clear();
  if (network_id == nullptr || payload == nullptr || payload_size == 0) {
    return WalletSigningError::InvalidArgument;
  }
  const NetworkProfile *network = find_network_profile(network_id);
  if (!catalog_can_sign(network_id) || network == nullptr ||
      network->encoding != AddressEncoding::CryptoNote ||
      cryptonote_review_policy(network_id) == nullptr) {
    return WalletSigningError::Unsupported;
  }
  HdPrivateNode master;
  if (!load_master(&master)) return WalletSigningError::NoWallet;
  uint8_t spend_secret[kCryptoNoteKeySize];
  uint8_t view_secret[kCryptoNoteKeySize];
  if (derive_cryptonote_keys(master, *network, 0, 0, address_index,
                             spend_secret, view_secret) != WalletError::Ok) {
    secure_zero(&master, sizeof(master));
    secure_zero(spend_secret, sizeof(spend_secret));
    secure_zero(view_secret, sizeof(view_secret));
    return WalletSigningError::NoWallet;
  }
  secure_zero(&master, sizeof(master));
  wallet_signing_clear();
  wallet_ui_show_busy(strcmp(network_id, "msr") == 0
                          ? "Verifying MSR transaction..."
                          : "Verifying XMR transaction...");
  CryptoNotePrepareJob job;
  job.network_id = network_id;
  job.payload = payload;
  job.payload_size = payload_size;
  memcpy(job.spend_secret, spend_secret, kCryptoNoteKeySize);
  memcpy(job.view_secret, view_secret, kCryptoNoteKeySize);
  job.state = &active.request.cryptonote;
  secure_zero(spend_secret, sizeof(spend_secret));
  secure_zero(view_secret, sizeof(view_secret));
  const WalletWorkerResult completion = wallet_worker_execute(
      run_cryptonote_prepare_job, &job, HEXWALLET_WORKER_JOB_TIMEOUT_MS,
      millis, service_crypto_wait);
  const CryptoNoteTxError error = completion == WalletWorkerResult::Completed
      ? job.error : CryptoNoteTxError::Unsupported;
  secure_zero(&job, sizeof(job));
  if (error != CryptoNoteTxError::Ok) {
    wallet_signing_clear();
    wallet_ui_set_status("Review failed. Nothing was signed.");
    return map_cryptonote_error(error);
  }
  active.request.cryptonote.address_index = address_index;
  active.kind = WalletSigningKind::CryptoNote;
  // The review lifetime starts when verification finishes, not when the
  // potentially expensive verification began.
  (void)now_ms;
  return finish_review(millis());
}

WalletSigningError wallet_signing_begin_solana(const char *network_id,
    uint32_t address_index, const uint8_t *message, size_t size, uint32_t now_ms) {
  wallet_signing_clear();
  if (network_id == nullptr || strcmp(network_id, "sol") != 0 || !catalog_can_sign("sol"))
    return WalletSigningError::Unsupported;
  uint8_t seed[kSeedSize] = {}, child[32] = {}, payer[32] = {};
  if (wallet_session_load_seed(seed) != WalletError::Ok) {
    secure_zero(seed, sizeof(seed)); return WalletSigningError::NoWallet;
  }
  const bool derived = solana_derive_key(seed, address_index, child) && ed25519_public_key(child, payer);
  secure_zero(seed, sizeof(seed)); secure_zero(child, sizeof(child));
  const SolanaError error = derived
      ? solana_review_message(message, size, payer, &active.request.solana)
      : SolanaError::CryptoFailure;
  secure_zero(payer, sizeof(payer));
  if (error != SolanaError::Ok) { wallet_signing_clear(); return map_solana_error(error); }
  active.request.solana.address_index = address_index;
  active.kind = WalletSigningKind::Solana;
  (void)now_ms;
  return finish_review(millis());
}

WalletSigningError wallet_signing_begin_stellar(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size, uint32_t now_ms) {
  wallet_signing_clear();
  if (!network_id || strcmp(network_id, "xlm") || !catalog_can_sign("xlm"))
    return WalletSigningError::Unsupported;
  if (!payload || size == 0) return WalletSigningError::InvalidArgument;
  uint8_t seed[kSeedSize] = {}, child[32] = {}, owner[32] = {};
  if (wallet_session_load_seed(seed) != WalletError::Ok) {
    secure_zero(seed, sizeof(seed)); return WalletSigningError::NoWallet;
  }
  const bool derived = stellar_derive_key(seed, address_index, child) && ed25519_public_key(child, owner);
  secure_zero(seed, sizeof(seed)); secure_zero(child, sizeof(child));
  const StellarError error = derived
      ? stellar_review_request(payload, size, owner, &active.request.stellar)
      : StellarError::CryptoFailure;
  secure_zero(owner, sizeof(owner));
  if (error != StellarError::Ok) { wallet_signing_clear(); return map_stellar_error(error); }
  active.request.stellar.address_index = address_index;
  active.kind = WalletSigningKind::Stellar;
  (void)now_ms;
  return finish_review(millis());
}

WalletSigningError wallet_signing_begin_algorand(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size, uint32_t now_ms) {
  wallet_signing_clear();
  if (!network_id || strcmp(network_id, "algo") || !catalog_can_sign("algo"))
    return WalletSigningError::Unsupported;
  if (!payload || size == 0) return WalletSigningError::InvalidArgument;
  uint8_t seed[kSeedSize] = {}, child[32] = {}, owner[32] = {};
  if (wallet_session_load_seed(seed) != WalletError::Ok) {
    secure_zero(seed, sizeof(seed)); return WalletSigningError::NoWallet;
  }
  const bool derived = algorand_derive_key(seed, address_index, child) &&
      ed25519_public_key(child, owner);
  secure_zero(seed, sizeof(seed)); secure_zero(child, sizeof(child));
  const AlgorandError error = derived
      ? algorand_review_transaction(payload, size, owner, &active.request.algorand)
      : AlgorandError::CryptoFailure;
  secure_zero(owner, sizeof(owner));
  if (error != AlgorandError::Ok) { wallet_signing_clear(); return map_algorand_error(error); }
  active.request.algorand.address_index = address_index;
  active.kind = WalletSigningKind::Algorand;
  (void)now_ms;
  return finish_review(millis());
}

WalletSigningError wallet_signing_begin_near(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size, uint32_t now_ms) {
  wallet_signing_clear();
  if (!network_id || strcmp(network_id, "near") || !catalog_can_sign("near"))
    return WalletSigningError::Unsupported;
  if (!payload || size == 0) return WalletSigningError::InvalidArgument;
  uint8_t seed[kSeedSize] = {}, child[32] = {}, owner[32] = {};
  if (wallet_session_load_seed(seed) != WalletError::Ok) {
    secure_zero(seed, sizeof(seed)); return WalletSigningError::NoWallet;
  }
  const bool derived = near_derive_key(seed, address_index, child) &&
      ed25519_public_key(child, owner);
  secure_zero(seed, sizeof(seed)); secure_zero(child, sizeof(child));
  const NearError error = derived
      ? near_review_transaction(payload, size, owner, &active.request.near)
      : NearError::CryptoFailure;
  secure_zero(owner, sizeof(owner));
  if (error != NearError::Ok) { wallet_signing_clear(); return map_near_error(error); }
  active.request.near.address_index = address_index;
  active.kind = WalletSigningKind::Near;
  (void)now_ms;
  return finish_review(millis());
}

WalletSigningError wallet_signing_begin_tezos(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size, uint32_t now_ms) {
  wallet_signing_clear();
  if (!network_id || strcmp(network_id, "xtz") || !catalog_can_sign("xtz"))
    return WalletSigningError::Unsupported;
  if (!payload || size == 0) return WalletSigningError::InvalidArgument;
  uint8_t seed[kSeedSize] = {}, child[32] = {}, owner[32] = {};
  if (wallet_session_load_seed(seed) != WalletError::Ok) {
    secure_zero(seed, sizeof(seed)); return WalletSigningError::NoWallet;
  }
  const bool derived = tezos_derive_key(seed, address_index, child) &&
      ed25519_public_key(child, owner);
  secure_zero(seed, sizeof(seed)); secure_zero(child, sizeof(child));
  const TezosError error = derived
      ? tezos_review_transaction(payload, size, owner, &active.request.tezos)
      : TezosError::CryptoFailure;
  secure_zero(owner, sizeof(owner));
  if (error != TezosError::Ok) { wallet_signing_clear(); return map_tezos_error(error); }
  active.request.tezos.address_index = address_index;
  active.kind = WalletSigningKind::Tezos;
  (void)now_ms;
  return finish_review(millis());
}

WalletSigningError wallet_signing_begin_xrp(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size, uint32_t now_ms) {
  wallet_signing_clear();
  if (!network_id || strcmp(network_id, "xrp") || !catalog_can_sign("xrp"))
    return WalletSigningError::Unsupported;
  if (!payload || size != 50) return WalletSigningError::InvalidArgument;
  const NetworkProfile *network = find_network_profile("xrp");
  HdPrivateNode master;
  if (network == nullptr || !load_master(&master)) return WalletSigningError::NoWallet;
  DerivedAddress derived;
  const WalletError derived_error =
      derive_address(master, nullptr, *network, 0, 0, address_index, &derived);
  secure_zero(&master, sizeof(master));
  uint8_t public_key[kXrpPublicKeySize] = {};
  const bool keys_ok = derived_error == WalletError::Ok &&
      public_key_from_private(derived.private_key, public_key) == WalletError::Ok;
  XrpError error = XrpError::CryptoFailure;
  if (keys_ok) {
    error = xrp_review_payload(payload, size, public_key, &active.request.xrp);
  }
  clear_derived_address(&derived);
  secure_zero(public_key, sizeof(public_key));
  if (error != XrpError::Ok) { wallet_signing_clear(); return map_xrp_error(error); }
  active.request.xrp.address_index = address_index;
  active.kind = WalletSigningKind::Xrp;
  (void)now_ms;
  return finish_review(millis());
}

WalletSigningError wallet_signing_begin_chain(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size,
    uint32_t now_ms) {
  wallet_signing_clear();
  if (network_id == nullptr || payload == nullptr || size == 0) {
    return WalletSigningError::InvalidArgument;
  }
  const NetworkProfile *network = find_network_profile(network_id);
  ChainFamily family = ChainFamily::None;
  if (network == nullptr ||
      !chain_family_for_network(network_id, &family) ||
      !catalog_can_sign(network_id)) {
    return WalletSigningError::Unsupported;
  }
  HdPrivateNode master;
  uint8_t seed[kSeedSize] = {};
  if (!load_master(&master) || wallet_session_load_seed(seed) != WalletError::Ok) {
    secure_zero(&master, sizeof(master));
    secure_zero(seed, sizeof(seed));
    return WalletSigningError::NoWallet;
  }
  wallet_ui_show_busy("Preparing transaction review...");
  ChainPrepareJob job = {family, payload, size, &master, seed, address_index,
                        &active.request.chain, ChainError::CryptoFailure};
  const WalletWorkerResult result = wallet_worker_execute(run_chain_prepare_job,
      &job, HEXWALLET_WORKER_JOB_TIMEOUT_MS, millis, service_crypto_wait);
  const ChainError error = job.error;
  secure_zero(&job, sizeof(job));
  secure_zero(&master, sizeof(master));
  secure_zero(seed, sizeof(seed));
  if (result != WalletWorkerResult::Completed || error != ChainError::Ok) {
    wallet_signing_clear();
    if (result == WalletWorkerResult::TimedOut) return WalletSigningError::Expired;
    if (result == WalletWorkerResult::Unavailable) return WalletSigningError::Unsupported;
    return map_chain_error(error);
  }
  active.kind = WalletSigningKind::Chain;
  (void)now_ms;
  return finish_review(millis());
}

WalletSigningError wallet_signing_begin_cosmos(const char *network_id,
                                               uint32_t address_index,
                                               const uint8_t *payload,
                                               size_t payload_size,
                                               uint32_t now_ms) {
  wallet_signing_clear();
  if (network_id == nullptr || payload == nullptr || payload_size == 0) {
    return WalletSigningError::InvalidArgument;
  }
  const CosmosChainParams *chain = cosmos_chain_params(network_id);
  if (chain == nullptr || !catalog_can_sign(network_id)) {
    return WalletSigningError::Unsupported;
  }
  const NetworkProfile *network = find_network_profile(network_id);
  if (network == nullptr || network->encoding != AddressEncoding::Bech32Cosmos ||
      network->alt_hrp == nullptr || strcmp(network->alt_hrp, chain->hrp) != 0) {
    return WalletSigningError::Unsupported;
  }
  HdPrivateNode master;
  if (!load_master(&master)) return WalletSigningError::NoWallet;
  DerivedAddress derived;
  const WalletError derived_error =
      derive_address(master, nullptr, *network, 0, 0, address_index, &derived);
  secure_zero(&master, sizeof(master));
  uint8_t public_key[kCompressedPublicKeySize];
  const bool keys_ok =
      derived_error == WalletError::Ok &&
      public_key_from_private(derived.private_key, public_key) == WalletError::Ok;
  CosmosError error = CosmosError::CryptoFailure;
  if (keys_ok) {
    error = cosmos_review_payload(payload, payload_size, *chain, derived.address,
                                  public_key, &active.request.cosmos);
  }
  secure_zero(public_key, sizeof(public_key));
  clear_derived_address(&derived);
  if (error != CosmosError::Ok) {
    wallet_signing_clear();
    return map_cosmos_error(error);
  }
  active.request.cosmos.address_index = address_index;
  active.kind = WalletSigningKind::Cosmos;
  (void)now_ms;
  return finish_review(millis());
}

WalletSigningError wallet_signing_begin_tron(const char *network_id,
                                             uint32_t address_index,
                                             const uint8_t *payload,
                                             size_t payload_size,
                                             uint32_t now_ms) {
  wallet_signing_clear();
  if (network_id == nullptr || payload == nullptr || payload_size == 0) {
    return WalletSigningError::InvalidArgument;
  }
  if (strcmp(network_id, "trx") != 0 || !catalog_can_sign("trx")) {
    return WalletSigningError::Unsupported;
  }
  const NetworkProfile *network = find_network_profile("trx");
  if (network == nullptr || network->encoding != AddressEncoding::Tron) {
    return WalletSigningError::Unsupported;
  }
  HdPrivateNode master;
  if (!load_master(&master)) return WalletSigningError::NoWallet;
  DerivedAddress derived;
  const WalletError derived_error =
      derive_address(master, nullptr, *network, 0, 0, address_index, &derived);
  secure_zero(&master, sizeof(master));
  uint8_t owner[kTronAddressSize] = {};
  size_t owner_size = sizeof(owner);
  const bool decoded = derived_error == WalletError::Ok &&
                       b58check_dec(owner, &owner_size, derived.address) &&
                       owner_size == kTronAddressSize;
  clear_derived_address(&derived);
  if (!decoded) {
    secure_zero(owner, sizeof(owner));
    wallet_signing_clear();
    return WalletSigningError::NoWallet;
  }
  const TronError error =
      tron_review_raw_data(payload, payload_size, owner, &active.request.tron);
  secure_zero(owner, sizeof(owner));
  if (error != TronError::Ok) {
    wallet_signing_clear();
    return map_tron_error(error);
  }
  active.request.tron.address_index = address_index;
  active.kind = WalletSigningKind::Tron;
  (void)now_ms;
  return finish_review(millis());
}

void wallet_signing_reject() {
  if (active.kind == WalletSigningKind::None) return;
  active.approved = false;
  active.rejected = true;
  secure_zero(&active.request, sizeof(active.request));
  // Detach the buttons so a late tap cannot flip a rejected review back to
  // approved; the phone must start over.
  wallet_ui_set_decision_callback(nullptr);
  wallet_ui_set_status("Rejected. Nothing was signed.");
}

static WalletSigningError sign_approved_transaction(uint8_t *out, size_t *in_out_size) {
  if (!wallet_signing_active() || !active.approved || active.rejected || active.consumed) {
    wallet_signing_clear();
    return WalletSigningError::NotApproved;
  }
  // The panel must have finished committing this review before anything is
  // signed, and the review seal must still be armed and unused. APPROVE is only
  // produced by a button on a rendered frame, so this also catches a stale
  // approval that outlived its own screen.
  if (board_has_display()) {
    if (!board_display_review_ready() || !wallet_ui_review_authorize()) {
      wallet_signing_clear();
      return WalletSigningError::NotApproved;
    }
  }
  // A build that demands verified boot refuses to hand out signatures from an
  // unprotected device (secure boot and flash encryption both off).
  if (!trust_signing_allowed(trust_state())) {
    wallet_signing_clear();
    wallet_ui_set_status("Trusted boot required. Signing refused.");
    return WalletSigningError::Unsupported;
  }
  // Consume before key access. An invalid output buffer, failed unseal, or
  // failed signing operation must never leave a reusable approval behind.
  active.consumed = true;
  if (out == nullptr || in_out_size == nullptr) {
    wallet_signing_clear();
    return WalletSigningError::InvalidArgument;
  }
  if (deadline_reached(millis(), active.expires_ms)) {
    wallet_signing_clear();
    return WalletSigningError::Expired;
  }
  if (active.kind == WalletSigningKind::Dash) {
    SensitiveValue<HdPrivateNode> master;
    if (!load_master(&master.get())) {
      wallet_signing_clear();
      return WalletSigningError::NoWallet;
    }
    wallet_ui_show_busy("Signing DASH transaction...");
    DashSignJob job{&active.request.dash, &master.get(), out, in_out_size,
                    DashError::CryptoFailure};
    const WalletWorkerResult result = wallet_worker_execute(run_dash_sign_job, &job,
        HEXWALLET_WORKER_JOB_TIMEOUT_MS, millis, service_crypto_wait);
    const DashError error = job.error;
    secure_zero(&job, sizeof(job));
    wallet_signing_clear();
    if (result == WalletWorkerResult::TimedOut) return WalletSigningError::Expired;
    if (result != WalletWorkerResult::Completed) return WalletSigningError::Unsupported;
    return map_dash_error(error);
  }
  if (active.kind == WalletSigningKind::Stellar) {
    return sign_seed_transaction(active.request.stellar, "Signing XLM transaction...",
        stellar_sign_transaction, map_stellar_error, out, in_out_size);
  }
  if (active.kind == WalletSigningKind::Algorand) {
    return sign_seed_transaction(active.request.algorand, "Signing ALGO transaction...",
        algorand_sign_transaction, map_algorand_error, out, in_out_size);
  }
  if (active.kind == WalletSigningKind::Near) {
    return sign_seed_transaction(active.request.near, "Signing NEAR transaction...",
        near_sign_transaction, map_near_error, out, in_out_size);
  }
  if (active.kind == WalletSigningKind::Tezos) {
    return sign_seed_transaction(active.request.tezos, "Signing XTZ transaction...",
        tezos_sign_transaction, map_tezos_error, out, in_out_size);
  }
  if (active.kind == WalletSigningKind::Xrp) {
    const NetworkProfile *network = find_network_profile("xrp");
    HdPrivateNode master;
    if (network == nullptr || !load_master(&master)) {
      wallet_signing_clear();
      return WalletSigningError::NoWallet;
    }
    DerivedAddress derived;
    const WalletError derived_error = derive_address(
        master, nullptr, *network, 0, 0, active.request.xrp.address_index, &derived);
    secure_zero(&master, sizeof(master));
    if (derived_error != WalletError::Ok) {
      clear_derived_address(&derived);
      wallet_signing_clear();
      return WalletSigningError::NoWallet;
    }
    const size_t capacity = *in_out_size;
    wallet_ui_show_busy("Signing XRP transaction...");
    XrpSignJob job = {&active.request.xrp, derived.private_key, out, in_out_size,
                      XrpError::CryptoFailure};
    const WalletWorkerResult result = wallet_worker_execute(run_xrp_sign_job, &job,
        HEXWALLET_WORKER_JOB_TIMEOUT_MS, millis, service_crypto_wait);
    const XrpError error = job.error;
    clear_derived_address(&derived);
    secure_zero(&job, sizeof(job));
    wallet_signing_clear();
    if (result != WalletWorkerResult::Completed || error != XrpError::Ok) {
      secure_zero(out, capacity); *in_out_size = 0;
    }
    if (result == WalletWorkerResult::TimedOut) return WalletSigningError::Expired;
    if (result == WalletWorkerResult::Unavailable) return WalletSigningError::Unsupported;
    return map_xrp_error(error);
  }
  if (active.kind == WalletSigningKind::Chain) {
    HdPrivateNode master;
    uint8_t seed[kSeedSize] = {};
    if (!load_master(&master) ||
        wallet_session_load_seed(seed) != WalletError::Ok) {
      secure_zero(&master, sizeof(master));
      secure_zero(seed, sizeof(seed));
      wallet_signing_clear();
      return WalletSigningError::NoWallet;
    }
    const size_t capacity = *in_out_size;
    wallet_ui_show_busy("Signing transaction...");
    ChainSignJob job = {&active.request.chain, &master, seed, out, in_out_size,
                        ChainError::CryptoFailure};
    const WalletWorkerResult result = wallet_worker_execute(run_chain_sign_job,
        &job, HEXWALLET_WORKER_JOB_TIMEOUT_MS, millis, service_crypto_wait);
    const ChainError error = job.error;
    secure_zero(&job, sizeof(job));
    secure_zero(&master, sizeof(master));
    secure_zero(seed, sizeof(seed));
    wallet_signing_clear();
    if (result != WalletWorkerResult::Completed || error != ChainError::Ok) {
      secure_zero(out, capacity);
      *in_out_size = 0;
    }
    if (result == WalletWorkerResult::TimedOut) return WalletSigningError::Expired;
    if (result == WalletWorkerResult::Unavailable) return WalletSigningError::Unsupported;
    return map_chain_error(error);
  }
  if (active.kind == WalletSigningKind::Solana) {
    return sign_seed_transaction(active.request.solana, "Signing SOL transaction...",
        solana_sign_transaction, map_solana_error, out, in_out_size);
  }
  if (active.kind == WalletSigningKind::Tron) {
    const NetworkProfile *network = find_network_profile("trx");
    HdPrivateNode master;
    if (network == nullptr || !load_master(&master)) {
      wallet_signing_clear();
      return WalletSigningError::NoWallet;
    }
    DerivedAddress derived;
    const WalletError derived_error = derive_address(
        master, nullptr, *network, 0, 0, active.request.tron.address_index, &derived);
    secure_zero(&master, sizeof(master));
    if (derived_error != WalletError::Ok) {
      clear_derived_address(&derived);
      wallet_signing_clear();
      return WalletSigningError::NoWallet;
    }
    const size_t capacity = *in_out_size;
    wallet_ui_show_busy("Signing TRX transaction...");
    const TronError error =
        tron_sign_transaction(active.request.tron, derived.private_key, out, in_out_size);
    clear_derived_address(&derived);
    wallet_signing_clear();
    if (error != TronError::Ok) {
      secure_zero(out, capacity);
      *in_out_size = 0;
    }
    return map_tron_error(error);
  }
  if (active.kind == WalletSigningKind::Cosmos) {
    const CosmosReview &review = active.request.cosmos.review;
    const NetworkProfile *network =
        review.chain == nullptr ? nullptr
                                : find_network_profile(review.chain->network_id);
    HdPrivateNode master;
    if (network == nullptr || !load_master(&master)) {
      wallet_signing_clear();
      return WalletSigningError::NoWallet;
    }
    DerivedAddress derived;
    const WalletError derived_error = derive_address(
        master, nullptr, *network, 0, 0, active.request.cosmos.address_index,
        &derived);
    secure_zero(&master, sizeof(master));
    if (derived_error != WalletError::Ok) {
      clear_derived_address(&derived);
      wallet_signing_clear();
      return WalletSigningError::NoWallet;
    }
    const size_t capacity = *in_out_size;
    char busy[48];
    snprintf(busy, sizeof(busy), "Signing %s transaction...",
             review.chain->symbol);
    wallet_ui_show_busy(busy);
    const CosmosError error = cosmos_sign_transaction(
        active.request.cosmos, derived.private_key, out, in_out_size);
    clear_derived_address(&derived);
    wallet_signing_clear();
    if (error != CosmosError::Ok) {
      secure_zero(out, capacity);
      *in_out_size = 0;
    }
    return map_cosmos_error(error);
  }
  if (active.kind == WalletSigningKind::CryptoNote) {
    const char *network_id =
        active.request.cryptonote.network == CryptoNoteReviewNetwork::MasariMainnet
            ? "msr"
            : "xmr";
    const NetworkProfile *network = find_network_profile(network_id);
    HdPrivateNode master;
    if (network == nullptr || !load_master(&master)) {
      wallet_signing_clear();
      return WalletSigningError::NoWallet;
    }
    uint8_t spend_secret[kCryptoNoteKeySize];
    uint8_t view_secret[kCryptoNoteKeySize];
    const WalletError derived = derive_cryptonote_keys(
        master, *network, 0, 0, active.request.cryptonote.address_index,
        spend_secret, view_secret);
    secure_zero(&master, sizeof(master));
    if (derived != WalletError::Ok) {
      secure_zero(spend_secret, sizeof(spend_secret));
      secure_zero(view_secret, sizeof(view_secret));
      wallet_signing_clear();
      return WalletSigningError::NoWallet;
    }
    uint8_t nonce_seed[kCryptoNoteKeySize];
    random_fill(nonce_seed, sizeof(nonce_seed));
    wallet_ui_show_busy(strcmp(network_id, "msr") == 0
                            ? "Signing MSR transaction..."
                            : "Signing XMR transaction...");
    const size_t output_capacity = *in_out_size;
    CryptoNoteSignJob job = {&active.request.cryptonote, view_secret,
        spend_secret, nonce_seed, out, in_out_size, CryptoNoteTxError::CryptoFailure};
    const WalletWorkerResult completion = wallet_worker_execute(
        run_cryptonote_sign_job, &job, HEXWALLET_WORKER_JOB_TIMEOUT_MS,
        millis, service_crypto_wait);
    const CryptoNoteTxError error = job.error;
    secure_zero(&job, sizeof(job));
    secure_zero(view_secret, sizeof(view_secret));
    secure_zero(spend_secret, sizeof(spend_secret));
    secure_zero(nonce_seed, sizeof(nonce_seed));
    wallet_signing_clear();
    if (completion != WalletWorkerResult::Completed || error != CryptoNoteTxError::Ok) {
      secure_zero(out, output_capacity);
      *in_out_size = 0;
    }
    if (completion == WalletWorkerResult::TimedOut) return WalletSigningError::Expired;
    if (completion == WalletWorkerResult::Unavailable) return WalletSigningError::Unsupported;
    return map_cryptonote_error(error);
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
    case WalletSigningKind::Dash:
    case WalletSigningKind::CryptoNote:
    case WalletSigningKind::Solana:
    case WalletSigningKind::Tron:
    case WalletSigningKind::Cosmos:
    case WalletSigningKind::Stellar:
    case WalletSigningKind::Algorand:
    case WalletSigningKind::Tezos:
    case WalletSigningKind::Xrp:
    case WalletSigningKind::Near:
    case WalletSigningKind::Chain:
      result = WalletSigningError::InvalidArgument;
      break;
  }
  secure_zero(&master, sizeof(master));
  active.consumed = true;
  wallet_signing_clear();
  return result;
}

WalletSigningError wallet_signing_sign(uint8_t *out, size_t *in_out_size) {
  SigningOutputGuard output(out, in_out_size);
  if (!output.valid()) {
    wallet_signing_clear();
    return WalletSigningError::InvalidArgument;
  }
  const WalletSigningError result = sign_approved_transaction(out, in_out_size);
  if (result != WalletSigningError::Ok) return result;
  return output.commit() ? WalletSigningError::Ok : WalletSigningError::CryptoFailure;
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
  ok = ok && wallet_signing_begin_zcash("zec", &empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  ok = ok && wallet_signing_begin_dash("dash", &empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  ok = ok && wallet_signing_begin_cryptonote("xmr", 0, &empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  ok = ok && wallet_signing_begin_tron("trx", 0, &empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  ok = ok && wallet_signing_begin_cosmos("atom", 0, &empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  ok = ok && wallet_signing_begin_algorand("algo", 0, &empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  ok = ok && wallet_signing_begin_near("near", 0, &empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  ok = ok && wallet_signing_begin_xrp("xrp", 0, &empty, 0, 0) ==
                 WalletSigningError::InvalidArgument;
  // CryptoNote review is dispatched to the crypto worker because the
  // Bulletproofs+ verifier needs more stack than the loop task has. Verify that
  // the job API actually runs work on this build (the host runs jobs inline).
  static bool worker_job_ran = false;
  worker_job_ran = false;
  if (wallet_worker_ready() || wallet_worker_start()) {
    const bool queued = wallet_worker_begin(
        [](void *context) { *static_cast<bool *>(context) = true; },
        &worker_job_ran);
    if (queued) {
      ok = ok && wallet_worker_wait(HEXWALLET_WORKER_JOB_TIMEOUT_MS) && worker_job_ran;
    }
  }
  active.kind = WalletSigningKind::Bitcoin;
  active.approved = true;
  ok = ok && wallet_signing_sign(nullptr, &output_size) ==
                 WalletSigningError::InvalidArgument && !wallet_signing_active();
  output_size = sizeof(output);
  memset(output, 0xa5, sizeof(output));
  ok = ok && wallet_signing_sign(output, &output_size) == WalletSigningError::NotApproved;
  ok = ok && output_size == 0;
  for (uint8_t byte : output) ok = ok && byte == 0;
  return ok;
}

}  // namespace hexwallet
