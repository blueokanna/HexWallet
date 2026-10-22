#ifndef HEXWALLET_NETWORKS_H
#define HEXWALLET_NETWORKS_H

#include <stddef.h>
#include <stdint.h>

#include "WalletAddresses.h"

namespace hexwallet
{

  // Address serialization family. Every branch in `derive_address` and in the
  // catalog capability logic keys off this enum; a network profile may only be
  // marked address-capable after its encoder has been verified against external
  // reference vectors.
  enum class AddressEncoding : uint8_t
  {
    P2pkh,                   // base58check with 1-byte p2pkh/p2sh versions (BTC, LTC, DOGE, DASH, BTG, RVN, VTC, AXE)
    P2shP2wpkh,              // base58check p2sh of witness program (BIP49)
    P2wpkh,                  // bech32 witness v0 (BIP84 / native segwit)
    Evm,                     // keccak-256 hex 0x... account
    Tron,                    // keccak-256 base58check with 0x41 version
    CryptoNote,              // Monero/Masari keccak-reduce standard address
    ZcashTransparent,        // 2-byte-version base58check t1/t3 (ZEC, FLUX transparent)
    CashAddr,                // CashAddr base32 with poly-mod checksum (BCH, XEC)
    Ed25519Base58,           // ed25519 pubkey base58 (SOL)
    Ed25519Base32,           // ed25519 pubkey + sha512/256 checksum, base32 no-pad (ALGO)
    Ed25519Blake2bBase58,    // tz1: base58check blake2b-160(ed25519 pubkey) (XTZ)
    Ed25519Blake2b224Bech32, // addr1: bech32 blake2b-224(payment) + blake2b-224(stake) (ADA)
    Bech32Cosmos,            // bech32 hash160(secp256k1) with chain hrp (CRO-native, SEI)
    Bech32Avalanche,         // "X-" bech32 0x00 + hash160(secp256k1) (AVAX X/P)
    KaspaBech32,             // custom bech32, x-only secp256k1 pubkey (KAS)
    QubicBase26,             // base26(sha3-256(ed25519 pubkey)) (QUBIC)
    Blake2bBase32Filecoin,   // base32(0x01 + blake2b-160(secp256k1 pubkey)) (FIL)
    Blake2bBase58Ergo,       // base58check(0x01 + blake2b-256(secp256k1 pubkey)) (ERG)
    Bech32mBlsChia,          // bech32m(blake3-tree-hash puzzle of BLS12-381 G1 key) (XCH)
    QrlXmss,                 // QRL: XMSS-SHAKE256 root committed by sha256 (QRL)
  };

  // BIP32-style derivation policy per network. `derive_address` selects the path
  // builder from this enum. Ed25519 networks use SLIP-0010 (hardened only);
  // Chia uses EIP-2333 Lamport/HKDF derivation from the BIP39 seed.
  enum class DerivationStyle : uint8_t
  {
    Bip44,            // m/purpose'/coin'/account'/change/index (secp256k1)
    AllHardenedBip44, // m/44'/coin'/account'/change'/index' (SLIP-0010 ed25519)
    SolanaBip44,      // m/44'/501'/account'/0'/index' (SLIP-0010 ed25519)
    CardanoBip1852,   // m/1852'/1815'/account'/role/index (SLIP-0010 ed25519, documented policy)
    ChiaEip2333,      // EIP-2333 master + [12381,8444,0,index]
    QrlXmss,          // BIP39 seed -> SHAKE-256 -> XMSS(sk_seed, pub_seed); no BIP32 path
  };

  struct NetworkProfile
  {
    const char *id;
    const char *symbol;
    const char *name;
    uint32_t slip44_coin_type;
    uint32_t derivation_coin_type;
    uint32_t bip_purpose;
    DerivationStyle derivation;
    AddressEncoding encoding;
    UtxoAddressProfile utxo;    // 1-byte-version UTXO parameters (P2pkh family)
    uint8_t account_version;    // TRON 0x41, CryptoNote network prefix
    uint32_t evm_chain_id;      // EVM networks; 0 otherwise
    uint16_t alt_p2pkh_version; // ZcashTransparent 2-byte p2pkh (t1)
    uint16_t alt_p2sh_version;  // ZcashTransparent 2-byte p2sh (t3)
    const char *alt_hrp;        // cashaddr prefix / cosmos hrp / avalanche hrp
    uint16_t cryptonote_integrated_prefix;
    uint16_t cryptonote_subaddress_prefix;
    bool explicit_only_derivation;
  };

  extern const NetworkProfile kNetworkProfiles[];
  extern const size_t kNetworkProfileCount;

  // Transaction signing policy.  Deliberately separate from NetworkProfile so an
  // address profile can never imply a signing capability: a network may be
  // signed only when it has an explicit row here.
  enum class SighashFamily : uint8_t
  {
    None = 0,    // no transaction signing
    Bitcoin,     // legacy sighash for P2PKH inputs, BIP143 for witness inputs
    ForkId,      // BIP143 preimage with SIGHASH_FORKID (0x41) plus fork id bits
    ZcashZip243, // Zcash Overwinter/Sapling v4 BLAKE2b-256 with branch id
  };

  struct NetworkSigningPolicy
  {
    const char *network_id;
    SighashFamily family;
    uint32_t fork_id;
  };

  extern const NetworkSigningPolicy kNetworkSigningPolicies[];
  extern const size_t kNetworkSigningPolicyCount;
  const NetworkSigningPolicy *find_network_signing_policy(const char *network_id);
  struct ZcashNetworkPolicy
  {
    const char *network_id;
    uint32_t branch_id;
  };

  extern const ZcashNetworkPolicy kZcashNetworkPolicies[];
  extern const size_t kZcashNetworkPolicyCount;
  const ZcashNetworkPolicy *find_zcash_network_policy(const char *network_id);

  const NetworkProfile *find_network_profile(const char *id);
  bool network_supports_token_accounts(const NetworkProfile &network);
  bool network_supports_eip1559(const NetworkProfile &network);
  bool run_network_profile_self_tests();

} // namespace hexwallet

#endif
