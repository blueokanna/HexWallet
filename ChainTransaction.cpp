#include "ChainTransaction.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoExtended.h"
#include "CardanoTransaction.h"
#include "BlsG2.h"
#include "Clvm.h"
#include "ChiaTransaction.h"
#include "ErgoTransaction.h"
#include "HiveTransaction.h"
#include "HederaTransaction.h"
#include "SiaTransaction.h"
#include "NemTransaction.h"
#include "IcpTransaction.h"
#include "CkbTransaction.h"
#include "DecredTransaction.h"
#include "IconTransaction.h"
#include "PolkadotTransaction.h"
#include "TonTransaction.h"
#include "VeChainTransaction.h"
#include "SuiTransaction.h"
#include "FilecoinTransaction.h"
#include "WalletEngine.h"
#include "WalletNetworks.h"

namespace hexwallet {
namespace {

struct FamilyMap {
  ChainFamily family;
  const char *network_id;
};

constexpr FamilyMap kFamilyMap[] = {
    {ChainFamily::Cardano, "ada"},
    {ChainFamily::Hedera, "hbar"},
    {ChainFamily::Siacoin, "sc"},
    {ChainFamily::Nem, "xem"},
    {ChainFamily::InternetComputer, "icp"},
    {ChainFamily::VeChain, "vet"},
    {ChainFamily::Icon, "icx"},
#if defined(HEXWALLET_HOST_TEST) && defined(HEXWALLET_LEGACY_SUBSTRATE_TEST_ONLY)
    // Historical codec vectors only; current runtime metadata is not authenticated.
    {ChainFamily::Polkadot, "dot"},
    {ChainFamily::Kusama, "ksm"},
#endif
    {ChainFamily::Sui, "sui"},
    {ChainFamily::Filecoin, "fil"},
    {ChainFamily::Ton, "ton"},
    {ChainFamily::Decred, "dcr"},
    {ChainFamily::Ckb, "ckb"},
    {ChainFamily::Hive, "hive"},
    {ChainFamily::Ergo, "erg"},
    {ChainFamily::Chia, "xch"},
};

bool review_equals(const ChainReview &left, const ChainReview &right) {
  return !memcmp(&left, &right, sizeof(ChainReview));
}

}  // namespace

bool chain_family_for_network(const char *network_id, ChainFamily *out) {
  if (network_id == nullptr || out == nullptr) return false;
  for (size_t index = 0; index < sizeof(kFamilyMap) / sizeof(kFamilyMap[0]);
       ++index) {
    if (strcmp(kFamilyMap[index].network_id, network_id) == 0) {
      *out = kFamilyMap[index].family;
      return true;
    }
  }
  *out = ChainFamily::None;
  return false;
}

const char *chain_family_network_id(ChainFamily family) {
  for (size_t index = 0; index < sizeof(kFamilyMap) / sizeof(kFamilyMap[0]);
       ++index) {
    if (kFamilyMap[index].family == family) return kFamilyMap[index].network_id;
  }
  return nullptr;
}

const char *chain_family_name(ChainFamily family) {
  switch (family) {
    case ChainFamily::VeChain: return "VET";
    case ChainFamily::Icon: return "ICX";
    case ChainFamily::Nem: return "XEM";
    case ChainFamily::Hive: return "HIVE";
    case ChainFamily::Lisk: return "LSK";
    case ChainFamily::Sui: return "SUI";
    case ChainFamily::Flow: return "FLOW";
    case ChainFamily::Filecoin: return "FIL";
    case ChainFamily::Siacoin: return "SC";
    case ChainFamily::Ckb: return "CKB";
    case ChainFamily::Ton: return "TON";
    case ChainFamily::Decred: return "DCR";
    case ChainFamily::Cardano: return "ADA";
    case ChainFamily::Polkadot: return "DOT";
    case ChainFamily::Kusama: return "KSM";
    case ChainFamily::Ergo: return "ERG";
    case ChainFamily::Hedera: return "HBAR";
    case ChainFamily::Chia: return "XCH";
    case ChainFamily::InternetComputer: return "ICP";
    default: return "?";
  }
}

const char *chain_error_text(ChainError error) {
  switch (error) {
    case ChainError::Ok: return "ok";
    case ChainError::InvalidArgument: return "invalid argument";
    case ChainError::Malformed: return "malformed payload";
    case ChainError::Unsupported: return "unsupported transaction";
    case ChainError::WrongNetwork: return "wrong network";
    case ChainError::WrongWallet: return "wrong wallet";
    case ChainError::InvalidAmount: return "invalid amount";
    case ChainError::FeePolicy: return "fee policy";
    case ChainError::CryptoFailure: return "crypto failure";
    case ChainError::BufferTooSmall: return "buffer too small";
  }
  return "unknown";
}

ChainError chain_review_transaction(ChainFamily family, const uint8_t *payload,
                                    size_t size, const HdPrivateNode &master,
                                    const uint8_t *seed, uint32_t address_index,
                                    ChainTransaction *out) {
  if (out == nullptr || payload == nullptr || size == 0 ||
      size > kChainMaxPayload) {
    return ChainError::InvalidArgument;
  }
  memset(out, 0, sizeof(*out));
  out->family = family;
  out->address_index = address_index;
  out->payload_size = static_cast<uint16_t>(size);
  memcpy(out->payload, payload, size);

  const char *network_id = chain_family_network_id(family);
  const NetworkProfile *network =
      network_id == nullptr ? nullptr : find_network_profile(network_id);
  if (network == nullptr) return ChainError::Unsupported;

  DerivedAddress derived;
  const WalletError derived_error =
      derive_address(master, seed, *network, 0, 0, address_index, &derived);
  if (derived_error != WalletError::Ok) {
    clear_derived_address(&derived);
    return ChainError::CryptoFailure;
  }

  ChainError error = ChainError::Unsupported;
  switch (family) {
    case ChainFamily::InternetComputer: {
      uint8_t public_key[32];
      error = ed25519_public_key(derived.private_key, public_key)
          ? icp_review_payload(payload, size, public_key, &out->review, out->digest)
          : ChainError::CryptoFailure;
      break;
    }
    case ChainFamily::Siacoin:
      error = sia_review_payload(payload, size, derived.address, &out->review, out->digest);
      break;
    case ChainFamily::Nem:
      error = nem_review_payload(payload, size, derived.address, &out->review, out->digest);
      break;
    case ChainFamily::Hedera:
      error = hedera_review_payload(payload, size, derived.address,
                                    &out->review, out->digest);
      break;
    case ChainFamily::Cardano:
      error = cardano_review_payload(payload, size, derived.address,
                                     &out->review, out->digest);
      break;
    case ChainFamily::Sui:
      error = sui_review_payload(payload, size, derived.address, &out->review, out->digest);
      break;
    case ChainFamily::Filecoin:
      error = filecoin_review_payload(payload, size, derived.address, &out->review, out->digest);
      break;
    case ChainFamily::VeChain:
      error = vechain_review_payload(payload, size, derived.address,
                                     &out->review, out->digest);
      break;
    case ChainFamily::Icon:
      error = icon_review_payload(payload, size, derived.address, &out->review,
                                  out->digest);
      break;
    case ChainFamily::Polkadot:
    case ChainFamily::Kusama:
      error = polkadot_review_payload(family, payload, size, derived.address,
                                      &out->review, out->digest);
      break;
    case ChainFamily::Ergo:
      error = ergo_review_payload(payload, size, derived.address, &out->review,
                                  out->digest);
      break;
    case ChainFamily::Chia:
      error = chia_review_payload(payload, size, derived.address, &out->review,
                                  out->digest);
      break;
    case ChainFamily::Ton:
      error = ton_review_payload(payload, size, derived.address, &out->review,
                                 out->digest);
      break;
    case ChainFamily::Decred: {
      uint8_t public_key[33] = {};
      if (public_key_from_private(derived.private_key, public_key) !=
          WalletError::Ok) {
        error = ChainError::CryptoFailure;
      } else {
        error = dcr_review_payload(payload, size, public_key, derived.address,
                                   &out->review, out->digest);
      }
      secure_zero(public_key, sizeof(public_key));
      break;
    }
    case ChainFamily::Ckb: {
      uint8_t public_key[33] = {};
      if (public_key_from_private(derived.private_key, public_key) !=
          WalletError::Ok) {
        error = ChainError::CryptoFailure;
      } else {
        error = ckb_review_payload(payload, size, public_key, derived.address,
                                   &out->review, out->digest);
      }
      secure_zero(public_key, sizeof(public_key));
      break;
    }
    case ChainFamily::Hive:
      error = hive_review_payload(payload, size, derived.address,
                                  &out->review, out->digest);
      break;
    default:
      error = ChainError::Unsupported;
      break;
  }
  clear_derived_address(&derived);
  if (error != ChainError::Ok) {
    secure_zero(out, sizeof(*out));
  }
  return error;
}

ChainError chain_sign_transaction(const ChainTransaction &transaction,
                                  const HdPrivateNode &master,
                                  const uint8_t *seed, uint8_t *out,
                                  size_t *in_out_size) {
  if (in_out_size == nullptr) return ChainError::InvalidArgument;
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  if (out != nullptr) secure_zero(out, capacity);
  if (out == nullptr || transaction.payload_size == 0) {
    return ChainError::InvalidArgument;
  }

  ChainTransaction verified;
  ChainError error = chain_review_transaction(
      transaction.family, transaction.payload, transaction.payload_size, master,
      seed, transaction.address_index, &verified);
  if (error == ChainError::Ok &&
      (!review_equals(transaction.review, verified.review) ||
       !chain_constant_time_equal(transaction.digest, verified.digest, 32))) {
    error = ChainError::Malformed;
  }
  if (error != ChainError::Ok) {
    secure_zero(&verified, sizeof(verified));
    return error;
  }

  const char *network_id = chain_family_network_id(transaction.family);
  const NetworkProfile *network =
      network_id == nullptr ? nullptr : find_network_profile(network_id);
  if (network == nullptr) {
    secure_zero(&verified, sizeof(verified));
    return ChainError::Unsupported;
  }
  DerivedAddress derived;
  const WalletError derived_error = derive_address(
      master, seed, *network, 0, 0, transaction.address_index, &derived);
  if (derived_error != WalletError::Ok) {
    clear_derived_address(&derived);
    secure_zero(&verified, sizeof(verified));
    return ChainError::CryptoFailure;
  }

  // The adapter consumes capacity and replaces it with the produced length.
  *in_out_size = capacity;
  switch (transaction.family) {
    case ChainFamily::InternetComputer:
      error = icp_sign_payload(transaction.payload, transaction.payload_size,
                              derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Siacoin:
      error = sia_sign_payload(transaction.payload, transaction.payload_size,
                              derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Nem:
      error = nem_sign_payload(transaction.payload, transaction.payload_size,
                              derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Hedera:
      error = hedera_sign_payload(transaction.payload, transaction.payload_size,
                                  derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Cardano:
      error = cardano_sign_payload(transaction.payload, transaction.payload_size,
                                   seed, transaction.address_index, out, in_out_size);
      break;
    case ChainFamily::Sui:
      error = sui_sign_payload(transaction.payload, transaction.payload_size,
                               derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Filecoin:
      error = filecoin_sign_payload(transaction.payload, transaction.payload_size,
                                    derived.private_key, out, in_out_size);
      break;
    case ChainFamily::VeChain:
      error = vechain_sign_payload(transaction.payload, transaction.payload_size,
                                   derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Icon:
      error = icon_sign_payload(transaction.payload, transaction.payload_size,
                                derived.private_key, verified.review.sender,
                                out, in_out_size);
      break;
    case ChainFamily::Polkadot:
    case ChainFamily::Kusama:
      error = polkadot_sign_payload(transaction.family, transaction.payload,
                                    transaction.payload_size,
                                    derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Ergo:
      error = ergo_sign_payload(transaction.payload, transaction.payload_size,
                                derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Chia:
      error = chia_sign_payload(transaction.payload, transaction.payload_size,
                                derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Ton:
      error = ton_sign_payload(transaction.payload, transaction.payload_size,
                               derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Decred:
      error = dcr_sign_payload(transaction.payload, transaction.payload_size,
                               derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Ckb:
      error = ckb_sign_payload(transaction.payload, transaction.payload_size,
                               derived.private_key, out, in_out_size);
      break;
    case ChainFamily::Hive:
      error = hive_sign_payload(transaction.payload, transaction.payload_size,
                                derived.private_key, out, in_out_size);
      break;
    default:
      error = ChainError::Unsupported;
      break;
  }
  clear_derived_address(&derived);
  secure_zero(&verified, sizeof(verified));
  if (error != ChainError::Ok) {
    secure_zero(out, capacity);
    *in_out_size = 0;
  }
  return error;
}

bool run_chain_self_tests() {
  const bool ada = run_cardano_transaction_self_tests();
  const bool vet = run_vechain_self_tests();
  const bool icx = run_icon_self_tests();
  const bool dot = run_polkadot_self_tests();
  const bool ton = run_ton_self_tests();
  const bool sui = run_sui_self_tests();
  const bool fil = run_filecoin_self_tests();
  const bool dcr = run_decred_self_tests();
  const bool ckb = run_ckb_self_tests();
  const bool hive = run_hive_self_tests();
  const bool erg = run_ergo_self_tests();
  const bool bls = run_bls_g2_self_tests();
  const bool clvm = run_clvm_self_tests();
  const bool chia = run_chia_self_tests();
  ChainFamily family = ChainFamily::None;
  bool admission =
      chain_family_for_network("sui", &family) && family == ChainFamily::Sui &&
      chain_family_for_network("fil", &family) && family == ChainFamily::Filecoin &&
      chain_family_for_network("dcr", &family) && family == ChainFamily::Decred &&
      chain_family_for_network("ckb", &family) && family == ChainFamily::Ckb &&
      chain_family_for_network("hive", &family) && family == ChainFamily::Hive &&
      chain_family_for_network("erg", &family) && family == ChainFamily::Ergo &&
      chain_family_for_network("xch", &family) && family == ChainFamily::Chia;
#if defined(HEXWALLET_HOST_TEST) && defined(HEXWALLET_LEGACY_SUBSTRATE_TEST_ONLY)
  admission = admission && chain_family_for_network("dot", &family) &&
      chain_family_for_network("ksm", &family);
#else
  admission = admission && !chain_family_for_network("dot", &family) &&
      !chain_family_for_network("ksm", &family);
#endif
  return ada && vet && icx && dot && ton && sui && fil && dcr && ckb && hive &&
         erg && bls && clvm && chia && admission;
}

#if defined(HEXWALLET_HOST_TEST)
// Aggregate self-tests hide which family regressed; keep a labelled report for
// host builds so a failure is actionable.
void report_chain_self_tests() {
  const struct {
    const char *name;
    bool (*run)();
  } kTests[] = {
      {"cardano", run_cardano_transaction_self_tests},
      {"vechain", run_vechain_self_tests},
      {"icon", run_icon_self_tests},
      {"polkadot", run_polkadot_self_tests},
      {"ton", run_ton_self_tests},
      {"sui", run_sui_self_tests},
      {"filecoin", run_filecoin_self_tests},
      {"decred", run_decred_self_tests},
      {"ckb", run_ckb_self_tests},
      {"hive", run_hive_self_tests},
      {"ergo", run_ergo_self_tests},
      {"bls-g2", run_bls_g2_self_tests},
      {"clvm", run_clvm_self_tests},
      {"chia", run_chia_self_tests},
  };
  for (size_t i = 0; i < sizeof(kTests) / sizeof(kTests[0]); ++i) {
    ::printf("  chain.%s=%s\n", kTests[i].name,
             kTests[i].run() ? "pass" : "FAIL");
  }
}
#endif

}  // namespace hexwallet
