#ifndef HEXWALLET_CUSTODY_H
#define HEXWALLET_CUSTODY_H

#include <stdint.h>

#include "WalletNetworks.h"

namespace hexwallet {

// The custody plan answers one question per network: can the secure element
// hold the key and produce the signature this network needs, or must the MCU
// keep the private key in RAM?  The NXP SE050 has an ECDSA engine for
// secp256k1 but no Schnorr, no XMSS/SHAKE-256 and no CryptoNote key
// derivation, so coin support cannot be inferred from "the SE supports ECC".
enum class KeyScheme : uint8_t {
  Secp256k1Ecdsa,    // BIP32 child secp256k1 + ECDSA (BTC/LTC/ETH/Cosmos/...)
  KaspaSchnorr,      // BIP32 child secp256k1 + BIP340 Schnorr (Kaspa)
  Ed25519Eddsa,      // SLIP-0010 ed25519 + EdDSA (SOL/ALGO/ADA/XTZ/QUBIC)
  CryptoNoteEdwards, // Keccak-reduced Edwards25519 (XMR/MSR)
  Bls12381G1,        // EIP-2333 BLS12-381 G1 (XCH)
  XmssShake256,      // stateful hash-based XMSS (QRL)
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
  // The MCU must keep the private key, because the SE cannot sign this scheme
  // or cannot hold a key the MCU is allowed to replace.
  bool mcu_must_hold_key;
  // BIP32/SLIP-0010/XMSS derivation itself runs on the MCU; the SE050 has no
  // BIP32 engine.  The seed is volatile RAM and zeroized after derivation.
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
// planning tests and by `wallet custody` once the board port registers the
// secure element.  Until then the active profile is MCU-only.
const SecureElementProfile &se050c1h1_profile();
const SecureElementProfile &software_only_profile();

// Active integration state.  Defaults to MCU-only; the board port calls the
// setter after the SE050 applet has been probed and authenticated.  Passing
// nullptr resets to MCU-only.
const SecureElementProfile &active_secure_element_profile();
void set_active_secure_element_profile(const SecureElementProfile *profile);

bool run_custody_self_tests();

}  // namespace hexwallet

#endif
