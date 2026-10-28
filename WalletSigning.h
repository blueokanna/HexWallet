#ifndef HEXWALLET_SIGNING_H
#define HEXWALLET_SIGNING_H

#include <stddef.h>
#include <stdint.h>

#include "BitcoinTransaction.h"
#include "CryptoNoteSigning.h"
#include "EvmTransaction.h"
#include "CosmosTransaction.h"
#include "KaspaTransaction.h"
#include "TronTransaction.h"
#include "WalletUi.h"
#include "ZcashTransaction.h"
#include "SolanaTransaction.h"
#include "StellarTransaction.h"
#include "AlgorandTransaction.h"
#include "ChainTransaction.h"
#include "NearTransaction.h"
#include "TezosTransaction.h"
#include "XrpTransaction.h"

namespace hexwallet {

enum class WalletSigningKind : uint8_t {
  None = 0,
  Bitcoin,
  Evm,
  Kaspa,
  Zcash,
  CryptoNote,
  Solana,
  Tron,
  Cosmos,
  Stellar,
  Algorand,
  Near,
  Tezos,
  Xrp,
  Chain,
};

enum class WalletSigningError : uint8_t {
  Ok = 0,
  InvalidArgument,
  NoWallet,
  Unsupported,
  WrongWallet,
  FeePolicy,
  ParseFailed,
  CryptoFailure,
  NotApproved,
  Expired,
  AlreadyConsumed,
  BufferTooSmall,
};

constexpr uint32_t kWalletSigningReviewMs = 2UL * 60UL * 1000UL;
constexpr size_t kWalletSigningReviewIdSize = 8;

// Shared on-device signing session used by the serial CLI and the phone link.
// It holds only reviewed, bounded request structures; private keys are loaded
// from WalletSession for the single signing call and zeroized immediately.
struct WalletSigningSession {
  WalletSigningKind kind;
  uint8_t review_id[kWalletSigningReviewIdSize];
  uint32_t created_ms;
  uint32_t expires_ms;
  bool approved;
  bool rejected;
  bool consumed;
  union {
    BitcoinSigningRequest bitcoin;
    EvmSigningRequest evm;
    KaspaTransaction kaspa;
    ZcashSigningRequest zcash;
    CryptoNoteSigningState cryptonote;
    SolanaTransaction solana;
    TronTransaction tron;
    CosmosTransaction cosmos;
    StellarTransaction stellar;
    AlgorandTransaction algorand;
    NearTransaction near;
    TezosTransaction tezos;
    XrpTransaction xrp;
    ChainTransaction chain;
  } request;
};

// Begin a reviewed request. Each function parses the host payload, verifies
// wallet ownership and fee policy, creates a fresh review id and shows the
// trusted-display review with APPROVE/REJECT buttons. They do not sign.
WalletSigningError wallet_signing_begin_bitcoin(const char *network_id,
                                                const uint8_t *psbt,
                                                size_t psbt_size,
                                                uint32_t now_ms);
WalletSigningError wallet_signing_begin_evm(const char *network_id,
                                            uint32_t address_index,
                                            const uint8_t *transaction,
                                            size_t transaction_size,
                                            uint32_t now_ms);
WalletSigningError wallet_signing_begin_kaspa(const uint8_t *payload,
                                              size_t payload_size,
                                              uint32_t now_ms);
WalletSigningError wallet_signing_begin_zcash(const char *network_id,
                                              const uint8_t *payload,
                                              size_t payload_size,
                                              uint32_t now_ms);
// CryptoNote (Monero type-6 RingCT). The payload carries the serialized
// transaction plus the host's ring data; every amount, fee, destination and
// key image is re-derived and verified on device before the review is shown.
WalletSigningError wallet_signing_begin_cryptonote(const char *network_id,
                                                   uint32_t address_index,
                                                   const uint8_t *payload,
                                                   size_t payload_size,
                                                   uint32_t now_ms);

WalletSigningError wallet_signing_begin_solana(const char *network_id,
    uint32_t address_index, const uint8_t *message, size_t size, uint32_t now_ms);

WalletSigningError wallet_signing_begin_stellar(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size, uint32_t now_ms);

WalletSigningError wallet_signing_begin_algorand(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size, uint32_t now_ms);
WalletSigningError wallet_signing_begin_near(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size, uint32_t now_ms);
WalletSigningError wallet_signing_begin_tezos(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size, uint32_t now_ms);
WalletSigningError wallet_signing_begin_xrp(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size, uint32_t now_ms);

// Account-model adapters that share the ChainTransaction envelope (currently
// VET and ICX). The payload carries its own chain magic and is parsed by the
// adapter, never signed blindly.
WalletSigningError wallet_signing_begin_chain(const char *network_id,
    uint32_t address_index, const uint8_t *payload, size_t size,
    uint32_t now_ms);

// Native TRX and registered TRC-20 transfers. The payload is the raw
// `raw_data` protobuf bytes; the phone attaches the returned 65-byte
// r||s||v signature.
WalletSigningError wallet_signing_begin_tron(const char *network_id,
                                             uint32_t address_index,
                                             const uint8_t *payload,
                                             size_t payload_size,
                                             uint32_t now_ms);

// Cosmos SDK native MsgSend for atom/osmo/tia. The payload is the compact
// review structure documented in docs/chain-protocols.md; the returned bytes are
// the complete TxRaw protobuf.
WalletSigningError wallet_signing_begin_cosmos(const char *network_id,
                                               uint32_t address_index,
                                               const uint8_t *payload,
                                               size_t payload_size,
                                               uint32_t now_ms);

// User decision from the trusted display. Approval is only ever produced by
// the on-screen buttons; there is deliberately no API to approve in code.
void wallet_signing_reject();

// Signs the active approved request. The caller supplies the output buffer;
// the session is consumed whether signing succeeds or fails.
WalletSigningError wallet_signing_sign(uint8_t *out, size_t *in_out_size);

// Periodic housekeeping. Returns true when the active review was expired and
// cleared.
bool wallet_signing_tick(uint32_t now_ms);
void wallet_signing_clear();
bool wallet_signing_active();
const WalletSigningSession *wallet_signing_session();
WalletSigningKind wallet_signing_kind();
const char *wallet_signing_error_text(WalletSigningError error);

bool run_wallet_signing_self_test();

}  // namespace hexwallet

#endif
