#include "WalletCustody.h"

#include "SecureElementPort.h"

#include <string.h>

namespace hexwallet {
namespace {

constexpr uint16_t kSecp256k1Ecdsa =
  SecureElementSecp256k1 | SecureElementEcdsa;

const SecureElementProfile kSoftwareOnly = { "mcu-only", SecureElementNone, false };
const SecureElementProfile kSe050 = {
  "NXP SE050C1H1",
  SecureElementSecp256k1 | SecureElementEcdsa | SecureElementSeedSeal,
  false,
};
const SecureElementProfile kSe051C2 = {
  "NXP SE051C2HQ1 (target only)",
  SecureElementSecp256k1 | SecureElementEcdsa | SecureElementEd25519 |
      SecureElementSeedSeal,
  false,
};

bool has_all(uint16_t capabilities, uint16_t required) {
  return (capabilities & required) == required;
}

}  // namespace

KeyScheme key_scheme_for(const NetworkProfile &network) {
  switch (network.encoding) {
    case AddressEncoding::KaspaBech32:
      return KeyScheme::KaspaSchnorr;
    case AddressEncoding::CryptoNote:
      return KeyScheme::CryptoNoteEdwards;
    case AddressEncoding::Ed25519Base58:
    case AddressEncoding::Aeternity:
    case AddressEncoding::Ed25519Base32:
    case AddressEncoding::Ed25519Blake2bBase58:
    case AddressEncoding::StellarStrKey:
    case AddressEncoding::NearImplicit:
    case AddressEncoding::Ss58Ed25519:
    case AddressEncoding::SuiEd25519:
    case AddressEncoding::AptosEd25519:
    case AddressEncoding::TonAddress:
    case AddressEncoding::HederaKeyAlias:
    case AddressEncoding::IcpPrincipal:
    case AddressEncoding::IcpLedgerAccount:
    case AddressEncoding::SiaV2:
      return KeyScheme::Ed25519Eddsa;
    case AddressEncoding::Ed25519Blake2b224Bech32:
      return KeyScheme::CardanoEd25519Bip32;
    case AddressEncoding::Blake2bBase58Ergo:
      return KeyScheme::ErgoSchnorr;
    case AddressEncoding::Nem:
      return KeyScheme::NemKeccakEd25519;
    case AddressEncoding::Bech32mBlsChia:
      return KeyScheme::Bls12381G1;
    case AddressEncoding::QrlXmss:
      return KeyScheme::XmssShake256;
    case AddressEncoding::QrlMlDsa:
      return KeyScheme::MlDsa87;
    case AddressEncoding::StarknetKey:
      return KeyScheme::StarkEcdsa;
    case AddressEncoding::P2pkh:
    case AddressEncoding::P2shP2wpkh:
    case AddressEncoding::P2wpkh:
    case AddressEncoding::Evm:
    case AddressEncoding::Tron:
    case AddressEncoding::ZcashTransparent:
    case AddressEncoding::CashAddr:
    case AddressEncoding::Bech32Cosmos:
    case AddressEncoding::Bech32Avalanche:
    case AddressEncoding::Blake2bBase32Filecoin:
    case AddressEncoding::Ripple:
    case AddressEncoding::VeChainAddress:
    case AddressEncoding::IconAddress:
    case AddressEncoding::DecredAddress:
    case AddressEncoding::CkbAddress:
    case AddressEncoding::GraphenePubkey:
      return KeyScheme::Secp256k1Ecdsa;
  }
  return KeyScheme::Unsupported;
}

CustodyPlan plan_key_custody(const NetworkProfile &network,
                             const SecureElementProfile &secure_element) {
  const KeyScheme scheme = key_scheme_for(network);
  // An exportable key profile cannot meet hardware custody requirements.
  const uint16_t caps = secure_element.private_key_export
      ? SecureElementNone : secure_element.capabilities;
  CustodyPlan plan = { scheme, false, false, true, true, "" };
  switch (scheme) {
    case KeyScheme::Secp256k1Ecdsa:
      plan.key_can_live_in_se = has_all(caps, kSecp256k1Ecdsa);
      plan.se_can_sign = has_all(caps, kSecp256k1Ecdsa);
      plan.mcu_must_hold_key = !plan.se_can_sign;
      plan.reason = plan.se_can_sign
        ? "target supports ECDSA; software derivation/import still exposes key in MCU RAM"
        : "no secp256k1 ECDSA backend; key stays in MCU RAM";
      break;
    case KeyScheme::KaspaSchnorr:
      // The curve is secp256k1, but Kaspa verifies BIP340 Schnorr signatures.
      plan.key_can_live_in_se = has_all(caps, SecureElementSecp256k1);
      plan.se_can_sign = has_all(caps, SecureElementSecp256k1 | SecureElementSchnorr);
      plan.mcu_must_hold_key = !plan.se_can_sign;
      plan.reason = plan.se_can_sign
        ? "secp256k1 Schnorr key held by the SE"
        : "SE has no BIP340 Schnorr engine; Kaspa keys stay in MCU RAM";
      break;
    case KeyScheme::Ed25519Eddsa:
      plan.key_can_live_in_se = has_all(caps, SecureElementEd25519);
      plan.se_can_sign = has_all(caps, SecureElementEd25519);
      plan.mcu_must_hold_key = !plan.se_can_sign;
      plan.reason = plan.se_can_sign
        ? "target supports standard Ed25519; software derivation/import still exposes key in MCU RAM"
        : "no Ed25519 applet capability; key stays in MCU RAM";
      break;
    case KeyScheme::CryptoNoteEdwards:
      plan.key_can_live_in_se = false;
      plan.se_can_sign = false;
      plan.mcu_must_hold_key = true;
      plan.reason = "Monero/Masari keys are Keccak-reduced Edwards scalars with subaddress algebra; no SE050 primitive exists";
      break;
    case KeyScheme::Bls12381G1:
      plan.key_can_live_in_se = false;
      plan.se_can_sign = false;
      plan.mcu_must_hold_key = true;
      plan.reason = "EIP-2333 BLS12-381 key generation and signing run in MCU RAM";
      break;
    case KeyScheme::XmssShake256:
      plan.key_can_live_in_se = has_all(caps, SecureElementXmss);
      plan.se_can_sign = has_all(caps, SecureElementXmss);
      plan.mcu_must_hold_key = !plan.se_can_sign;
      plan.reason = "QRL XMSS needs SHAKE-256, a Merkle tree and stateful leaf indices; the SE050 provides none of them";
      break;
    case KeyScheme::MlDsa87:
      plan.key_can_live_in_se = false;
      plan.se_can_sign = false;
      plan.mcu_must_hold_key = true;
      plan.reason = "ML-DSA-87 key expansion and signing need ~140 KB of MCU RAM; no SE primitive exists";
      break;
    case KeyScheme::CardanoEd25519Bip32:
      plan.reason = "Cardano uses expanded BIP32-Ed25519 kL/kR; standard SE Ed25519 seed signing is not interchangeable";
      break;
    case KeyScheme::ErgoSchnorr:
      plan.reason = "Ergo Sigma Schnorr is not ECDSA or BIP340; no validated SE applet signing primitive";
      break;
    case KeyScheme::NemKeccakEd25519:
      plan.reason = "NEM Keccak-Ed25519 is not standard Ed25519; no validated SE applet signing primitive";
      break;
    case KeyScheme::StarkEcdsa:
      plan.key_can_live_in_se = false;
      plan.se_can_sign = false;
      plan.mcu_must_hold_key = true;
      plan.reason = "Starknet signs on the Stark curve (2^251 + 17*2^192 + 1); the SE050/SE051 only hold NIST P-256 and secp256k1 keys";
    case KeyScheme::Unsupported:
      plan.reason = "unknown key scheme; hardware custody cannot be inferred from an address encoding";
      break;
  }
  return plan;
}

const SecureElementProfile &se050c1h1_profile() {
  return kSe050;
}

const SecureElementProfile &software_only_profile() {
  return kSoftwareOnly;
}
const SecureElementProfile &se051c2hq1_profile() {
  return kSe051C2;
}
const SecureElementProfile &target_secure_element_profile() {
  return kSe051C2;
}
const SecureElementProfile &active_secure_element_profile() {
  // SSS channel authentication does not change the wallet's key ownership.
  // WalletSession still returns plaintext seeds and every transaction signer
  // still accepts MCU private keys. Never promote that path to SE custody.
  return kSoftwareOnly;
}

void set_active_secure_element_profile(const SecureElementProfile *profile) {
  // No authenticated SE key-handle backend is implemented. A part capability
  // description must never be promoted into a claim of active key custody.
  (void)profile;
}

CustodyBlocker custody_gate_blocker(const CustodyGateState &state) {
  if (!state.backend_registered) return CustodyBlocker::BackendMissing;
  if (!state.channel_authenticated) return CustodyBlocker::ChannelNotAuthenticated;
  if (!state.user_authenticated) return CustodyBlocker::UserNotAuthenticated;
  if (!state.keys_non_exportable) return CustodyBlocker::KeysExportable;
  if (!state.wallet_uses_handles) return CustodyBlocker::WalletLayerNotConverted;
  return CustodyBlocker::None;
}

const char *custody_blocker_text(CustodyBlocker blocker) {
  switch (blocker) {
    case CustodyBlocker::None:
      return "ready";
    case CustodyBlocker::BackendMissing:
      return "no secure-element backend";
    case CustodyBlocker::ChannelNotAuthenticated:
      return "secure channel not authenticated";
    case CustodyBlocker::UserNotAuthenticated:
      return "user not authenticated";
    case CustodyBlocker::KeysExportable:
      return "keys not held by the secure element";
    case CustodyBlocker::WalletLayerNotConverted:
      return "wallet still derives and signs on the MCU";
  }
  return "unknown";
}

namespace {

CustodyWalletLayerQuery g_wallet_layer_query = nullptr;

}  // namespace

CustodyWalletLayerQuery custody_set_wallet_layer_query(
    CustodyWalletLayerQuery query) {
  const CustodyWalletLayerQuery previous = g_wallet_layer_query;
  g_wallet_layer_query = query;
  return previous;
}

CustodyGateState custody_gate_state() {
  CustodyGateState state = {};
  state.backend_registered = secure_element_name()[0] != '\0';
  state.channel_authenticated = secure_element_ready();
  state.user_authenticated = secure_element_user_authenticated();
  state.keys_non_exportable = secure_element_keys_non_exportable();
  // Asked of the wallet layer, not the card: a card holding keys does not make
  // the wallet use them.
  state.wallet_uses_handles =
    g_wallet_layer_query != nullptr && g_wallet_layer_query();
  return state;
}

bool secure_custody_backend_ready() {
  return custody_gate_blocker(custody_gate_state()) == CustodyBlocker::None;
}

namespace {

bool wallet_layer_ready() {
  return true;
}

}  // namespace

bool run_custody_self_tests() {
  const NetworkProfile *ethereum = find_network_profile("eth");
  const NetworkProfile *kaspa = find_network_profile("kas");
  const NetworkProfile *monero = find_network_profile("xmr");
  const NetworkProfile *qrl = find_network_profile("qrl");
  const NetworkProfile *solana = find_network_profile("sol");
  const NetworkProfile *chia = find_network_profile("xch");
  if (ethereum == nullptr || kaspa == nullptr || monero == nullptr ||
      qrl == nullptr || solana == nullptr || chia == nullptr) {
    return false;
  }
  const CustodyPlan eth = plan_key_custody(*ethereum, se050c1h1_profile());
  const CustodyPlan kas = plan_key_custody(*kaspa, se050c1h1_profile());
  const CustodyPlan xmr = plan_key_custody(*monero, se050c1h1_profile());
  const CustodyPlan qrl_plan = plan_key_custody(*qrl, se050c1h1_profile());
  const CustodyPlan sol = plan_key_custody(*solana, se050c1h1_profile());
  const CustodyPlan xch = plan_key_custody(*chia, se050c1h1_profile());
  const bool se050_matrix =
    eth.scheme == KeyScheme::Secp256k1Ecdsa && eth.key_can_live_in_se &&
    eth.se_can_sign && !eth.mcu_must_hold_key &&
    kas.scheme == KeyScheme::KaspaSchnorr && kas.key_can_live_in_se &&
    !kas.se_can_sign && kas.mcu_must_hold_key &&
    xmr.scheme == KeyScheme::CryptoNoteEdwards && !xmr.key_can_live_in_se &&
    xmr.mcu_must_hold_key &&
    qrl_plan.scheme == KeyScheme::XmssShake256 && !qrl_plan.se_can_sign &&
    qrl_plan.mcu_must_hold_key &&
    sol.scheme == KeyScheme::Ed25519Eddsa && !sol.se_can_sign &&
    sol.mcu_must_hold_key &&
    xch.scheme == KeyScheme::Bls12381G1 && xch.mcu_must_hold_key;
  const CustodyPlan software = plan_key_custody(*ethereum, software_only_profile());
  const bool software_matrix =
    !software.key_can_live_in_se && !software.se_can_sign &&
    software.mcu_must_hold_key && software.requires_seed_in_mcu;
  const bool active_default = active_secure_element_profile().capabilities ==
                              SecureElementNone;
  set_active_secure_element_profile(&se050c1h1_profile());
  const bool target_cannot_activate =
    !plan_key_custody(*ethereum, active_secure_element_profile()).se_can_sign;
  set_active_secure_element_profile(&se051c2hq1_profile());
  const CustodyPlan target_sol = plan_key_custody(*solana, se051c2hq1_profile());
  const bool target_ed25519 = target_sol.se_can_sign &&
      target_sol.requires_seed_in_mcu && !secure_custody_backend_ready() &&
      active_secure_element_profile().capabilities == SecureElementNone;
  set_active_secure_element_profile(nullptr);
  const bool active_reset =
    active_secure_element_profile().capabilities == SecureElementNone;

  // The gate is five facts ANDed in a fixed order. Each case below falsifies
  // exactly one fact, so no single integration change can open it alone.
  const CustodyGateState armed = {true, true, true, true, true};
  const bool gate_open_only_when_all =
    custody_gate_blocker(armed) == CustodyBlocker::None;
  const CustodyBlocker expected[] = {
    CustodyBlocker::BackendMissing, CustodyBlocker::ChannelNotAuthenticated,
    CustodyBlocker::UserNotAuthenticated, CustodyBlocker::KeysExportable,
    CustodyBlocker::WalletLayerNotConverted};
  bool gate_independent = true;
  for (size_t i = 0; i < 5; ++i) {
    CustodyGateState single = armed;
    bool *facts[5] = {&single.backend_registered, &single.channel_authenticated,
                      &single.user_authenticated, &single.keys_non_exportable,
                      &single.wallet_uses_handles};
    *facts[i] = false;
    gate_independent = custody_gate_blocker(single) == expected[i] &&
                       gate_independent;
  }
  // With two facts broken, the earlier one in the fix order wins: a status line
  // must never name a cause the caller cannot act on first.
  CustodyGateState card_and_wallet = armed;
  card_and_wallet.keys_non_exportable = false;
  card_and_wallet.wallet_uses_handles = false;
  CustodyGateState user_and_channel = armed;
  user_and_channel.user_authenticated = false;
  user_and_channel.channel_authenticated = false;
  gate_independent =
    custody_gate_blocker(card_and_wallet) == CustodyBlocker::KeysExportable &&
    custody_gate_blocker(user_and_channel) ==
        CustodyBlocker::ChannelNotAuthenticated &&
    gate_independent;
  for (CustodyBlocker blocker : expected) {
    const char *text = custody_blocker_text(blocker);
    gate_independent = text[0] != '\0' && strcmp(text, "unknown") != 0 &&
                       strcmp(text, "ready") != 0 && gate_independent;
  }
  const bool text_ready =
    strcmp(custody_blocker_text(CustodyBlocker::None), "ready") == 0;
  // Whatever this build's state is, the live gate must be closed today.
  const CustodyGateState live = custody_gate_state();
  const bool live_closed = !secure_custody_backend_ready() &&
                           custody_gate_blocker(live) != CustodyBlocker::None;
  // The wallet layer's answer is consulted, and it alone cannot open the gate.
  const CustodyWalletLayerQuery previous =
    custody_set_wallet_layer_query(&wallet_layer_ready);
  const bool query_consulted =
    custody_gate_state().wallet_uses_handles &&
    custody_gate_blocker(custody_gate_state()) == CustodyBlocker::BackendMissing;
  custody_set_wallet_layer_query(previous);
  const bool query_restored =
    custody_gate_state().wallet_uses_handles ==
    (previous != nullptr && previous());

  return se050_matrix && software_matrix && active_default &&
         target_cannot_activate && target_ed25519 && active_reset &&
         gate_open_only_when_all && gate_independent && text_ready &&
         live_closed && query_consulted && query_restored;
}

}  // namespace hexwallet
