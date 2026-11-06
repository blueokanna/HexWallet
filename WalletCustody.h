#ifndef HEXWALLET_CUSTODY_H
#define HEXWALLET_CUSTODY_H

#include <stdint.h>

#include "WalletNetworks.h"

namespace hexwallet {

// The custody plan answers one question per network: can the secure element
// hold the key and produce the signature this network needs, or must the MCU
// keep the private key in RAM? The requested NXP SE051C2HQ1 is planned around
// its ECDSA (secp256k1/NIST/Koblitz) engines; the Ed25519 capability below is
// the AN12973 target claim and is *unverified on hardware*, while no profile
// claims Schnorr, XMSS or CryptoNote derivation. No capability bit may be
// raised without an on-device test, because coin support cannot be inferred
// from "the SE supports ECC".
enum class KeyScheme : uint8_t {
  Secp256k1Ecdsa,    // BIP32 child secp256k1 + ECDSA (BTC/LTC/ETH/Cosmos/...)
  KaspaSchnorr,      // BIP32 child secp256k1 + BIP340 Schnorr (Kaspa)
  Ed25519Eddsa,      // standard seed-based Ed25519 (SOL/ALGO/XTZ/...)
  CryptoNoteEdwards, // Keccak-reduced Edwards25519 (XMR/ZEPH)
  Bls12381G1,        // EIP-2333 BLS12-381 G1 (XCH)
  XmssShake256,      // stateful hash-based XMSS (QRL)
  MlDsa87,           // FIPS 204 ML-DSA-87 signature over a 32-byte seed (QRL v2)
  CardanoEd25519Bip32, // expanded kL/kR keys; not a standard Ed25519 seed
  ErgoSchnorr,       // Ergo Sigma Schnorr; not ECDSA or BIP340
  NemKeccakEd25519,  // NEM Keccak variant; not RFC 8032 Ed25519
  StarkEcdsa,        // Stark curve (2^251+17*2^192+1) ECDSA over a BIP32 child
  TaprootSchnorr,    // BIP86 even-Y normalization + TapTweak + BIP340
  Unsupported,
};

enum SecureElementCapability : uint16_t {
  SecureElementNone = 0,
  SecureElementSecp256k1 = 1U << 0,
  SecureElementEcdsa = 1U << 1,
  SecureElementEd25519 = 1U << 2,
  SecureElementSchnorr = 1U << 3,
  SecureElementXmss = 1U << 4,
  SecureElementSeedSeal = 1U << 5,
};

struct SecureElementProfile {
  const char *name;
  uint16_t capabilities;
  bool private_key_export;
};

struct CustodyPlan {
  KeyScheme scheme;
  // The key object can live in the SE (generated there or imported through an
  // authenticated SCP03 channel) and the applet can keep it non-exportable.
  bool key_can_live_in_se;
  // The SE implements the exact signature algorithm the network verifies.
  bool se_can_sign;
  // Whether signing requires an MCU key under this hypothetical profile.
  // Even if false, the CURRENT software BIP32/SLIP10 import workflow still
  // exposes derived keys transiently in MCU RAM (requires_seed_in_mcu below).
  bool mcu_must_hold_key;
  // This repository has only MCU BIP32/SLIP10/EIP2333 derivation. Neither a
  // capability mask nor importing a child afterwards makes derivation secret.
  bool requires_seed_in_mcu;
  const char *reason;
};

KeyScheme key_scheme_for(const NetworkProfile &network);
CustodyPlan plan_key_custody(const NetworkProfile &network,
                             const SecureElementProfile &secure_element);

// Conservative SE050C1H1 *target* profile: the hardware can hold a secp256k1
// key and run ECDSA, and can seal a seed with an AES key.  Schnorr, XMSS,
// CryptoNote and BLS are not available; Ed25519 is not assumed until the
// applet integration is validated on hardware.  This profile is used by the
// historical planning tests only; it never activates a real signing backend.
const SecureElementProfile &se050c1h1_profile();
// AN12973 Table 3: SE051C2 supports ECDSA/Koblitz and standard Ed25519,
// plus AES sealing primitives. This is a TARGET capability plan, not proof
// that the connected device/app version/key policy implements our wallet.
const SecureElementProfile &se051c2hq1_profile();
const SecureElementProfile &target_secure_element_profile();
const SecureElementProfile &software_only_profile();

// Actual wallet integration is MCU-only. SCP03 authentication does not prove
// that derivation or transaction signing uses non-exportable SE objects.
const SecureElementProfile &active_secure_element_profile();
// Compatibility entry point; rejects all profile-only activation attempts.
void set_active_secure_element_profile(const SecureElementProfile *profile);
// End-to-end wallet custody gate: true only when every CustodyBlocker is
// cleared, i.e. the card holds the keys, the user is authenticated, and the
// wallet layer derives and signs through handles.
bool secure_custody_backend_ready();

// ---------------------------------------------------------------------------
// Custody gate
// ---------------------------------------------------------------------------
//
// SE custody is five separate facts, and the wallet only gets it when all five
// hold at once. Keeping them apart is the point: a single boolean that some
// integration path sets is exactly how "hardware wallet" claims turn into
// marketing. Each fact is observable from a different layer, so no one layer
// can open the gate alone:
//
//   backend_registered       SecureElementPort knows a backend
//   channel_authenticated    SCP03 session up (authenticates the host)
//   user_authenticated       PIN verified (authenticates the person)
//   keys_non_exportable      the backend can keep key material inside the card
//   wallet_uses_handles      WalletSession derives and signs through handles
//
// The last one is the wallet layer's answer, not the card's. It stays false
// until derivation, review and signing no longer take a plaintext seed or a
// plaintext private key on the MCU.
enum class CustodyBlocker : uint8_t {
  None = 0,
  BackendMissing,
  ChannelNotAuthenticated,
  UserNotAuthenticated,
  KeysExportable,
  WalletLayerNotConverted,
};

struct CustodyGateState {
  bool backend_registered;
  bool channel_authenticated;
  bool user_authenticated;
  bool keys_non_exportable;
  bool wallet_uses_handles;
};

// Pure, total, and ordered: the blocker returned is the first one a caller
// should fix. "None" is only possible when every fact is true.
CustodyBlocker custody_gate_blocker(const CustodyGateState &state);
// Fixed English text, suitable for a status line or a CLI diagnostic.
const char *custody_blocker_text(CustodyBlocker blocker);
// Snapshot of the live state. The card-side facts come from the registered
// backend; the wallet-side fact comes from whoever owns the wallet session.
CustodyGateState custody_gate_state();
// Installs the wallet layer's answer to "does derivation and signing run
// through card handles?" and returns the previous query, so a caller (a test)
// can restore it. WalletSession registers itself, so the fact is real state
// rather than a constant somebody flips during an integration. A null (or
// never-registered) query means "not converted", which is the safe default for
// a build that does not link the wallet session at all.
using CustodyWalletLayerQuery = bool (*)();
CustodyWalletLayerQuery custody_set_wallet_layer_query(
    CustodyWalletLayerQuery query);

bool run_custody_self_tests();

}  // namespace hexwallet

#endif
